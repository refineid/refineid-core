// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The bootstrap answer a custodian in pairing mode serves on each
//! transport (RAPP v26.10.29 §4.2): the `pairing-offer` while it can admit
//! an attempt, and `pairing-busy` while it cannot.

use core::fmt;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{
    CPACE_KC2_SUITE, OFFER_ID_SIZE, OFFER_TTL_MS, OfferId, TransportCandidate, TransportProfile,
    WIRE_VERSION_V26_10_29, WireError, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor,
};

/// Upper bound on an encoded offer: the 509-byte ATT value capacity at the
/// minimum ATT MTU of 512 (RAPP v26.10.29 §4.2).
pub const MAX_OFFER_SIZE: usize = 509;

/// Least `retry_after_ms` a `pairing-busy` carries (RAPP v26.10.29 §4.2,
/// "PairingBusy Schema").
pub const PAIRING_BUSY_RETRY_AFTER_MIN_MS: u64 = 1;

/// Greatest `retry_after_ms` a `pairing-busy` carries (RAPP v26.10.29 §4.2,
/// "PairingBusy Schema").
pub const PAIRING_BUSY_RETRY_AFTER_MAX_MS: u64 = 5_000;

/// Fields of the `pairing-offer` schema.
const OFFER_FIELDS: [&str; 7] = [
    "scheme",
    "version",
    "offer_id",
    "suites",
    "profiles",
    "transports",
    "offer_ttl_ms",
];

/// Field that names the time a `pairing-busy` asks the requester to wait;
/// the `pairing-offer` schema has no field of that name, so its presence
/// tells a busy answer from an offer.
const RETRY_AFTER_FIELD: &str = "retry_after_ms";

/// Fields of the `pairing-busy` schema.
const BUSY_FIELDS: [&str; 3] = ["scheme", "version", RETRY_AFTER_FIELD];

/// The scheme name both bootstrap answers carry.
const SCHEME: &str = "rapp";

/// Validated `pairing-offer` per RAPP v26.10.29 §4.2.
///
/// Every transport entry is the registered entry of its profile, the entries
/// are sorted by profile with no duplicates, and `offer_id` is random.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingOffer {
    /// Random one-off offer identifier.
    pub offer_id: OfferId,
    /// Ordered supported cryptographic suites.
    pub suites: Vec<String>,
    /// Ordered offered credential-profile registry names.
    pub profiles: Vec<String>,
    /// Registered entries of the transports the offer is served on.
    pub transports: Vec<TransportCandidate>,
    /// Offer lifetime, fixed at [`OFFER_TTL_MS`].
    pub offer_ttl_ms: u64,
}

/// Monotonic lifetime of one in-memory pairing offer.
///
/// The timestamp origin is deliberately supplied by the platform so the same
/// core works across operating systems. It is meaningful only inside the
/// process that created or scanned the offer and is never serialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingOfferDeadline {
    started_at_ms: u64,
    expires_at_ms: u64,
}

impl PairingOfferDeadline {
    /// Construct the local deadline for a validated offer.
    ///
    /// # Errors
    /// [`PairingOfferError::DeadlineOverflow`] when the deadline arithmetic
    /// overflows.
    pub fn from_offer(offer: &PairingOffer, started_at_ms: u64) -> Result<Self, PairingOfferError> {
        let expires_at_ms = started_at_ms
            .checked_add(offer.offer_ttl_ms)
            .ok_or(PairingOfferError::DeadlineOverflow)?;
        Ok(Self {
            started_at_ms,
            expires_at_ms,
        })
    }

    /// Monotonic time at which the offer expires.
    #[must_use]
    pub const fn expires_at_ms(self) -> u64 {
        self.expires_at_ms
    }

    /// Whether the offer is still live on this monotonic clock.
    #[must_use]
    pub const fn is_live(self, now_ms: u64) -> bool {
        now_ms >= self.started_at_ms && now_ms < self.expires_at_ms
    }
}

impl PairingOffer {
    /// Create the custodian's offer from a CSPRNG-provided identifier, the
    /// offered credential profiles, and the transports it is served on.
    ///
    /// # Errors
    /// [`PairingOfferError`] when the offer fails structural or policy
    /// validation.
    pub fn create(
        offer_id: OfferId,
        profiles: Vec<String>,
        transports: &[TransportProfile],
    ) -> Result<Self, PairingOfferError> {
        let mut transports = transports.to_vec();
        transports.sort_unstable();
        transports.dedup();
        Self::reconstruct(
            offer_id,
            vec![CPACE_KC2_SUITE.to_owned()],
            profiles,
            transports
                .into_iter()
                .map(TransportProfile::offer_entry)
                .collect(),
            OFFER_TTL_MS,
        )
    }

    /// The offer entry of `profile`, when the offer is served on it.
    #[must_use]
    pub fn entry(&self, profile: TransportProfile) -> Option<&TransportCandidate> {
        self.transports
            .iter()
            .find(|candidate| candidate.profile == profile.name())
    }

    /// Construct and validate an offer from its parts.
    ///
    /// # Errors
    /// [`PairingOfferError`] when the offer fails structural or policy
    /// validation.
    pub fn reconstruct(
        offer_id: OfferId,
        suites: Vec<String>,
        profiles: Vec<String>,
        transports: Vec<TransportCandidate>,
        offer_ttl_ms: u64,
    ) -> Result<Self, PairingOfferError> {
        let offer = Self {
            offer_id,
            suites,
            profiles,
            transports,
            offer_ttl_ms,
        };
        offer.validate()?;
        Ok(offer)
    }

    /// Serialize the canonical pairing offer into deterministic CBOR.
    ///
    /// # Errors
    /// [`PairingOfferError`] on validation failure or if the encoded length
    /// exceeds the maximum permitted offer size.
    pub fn to_cbor(&self) -> Result<Vec<u8>, PairingOfferError> {
        self.validate()?;
        let encoded = encode_deterministic_cbor(&WireValue::Map(self.to_map()))?;
        if encoded.len() > MAX_OFFER_SIZE {
            return Err(PairingOfferError::Oversized { got: encoded.len() });
        }
        Ok(encoded)
    }

    /// Decode a deterministic-CBOR byte slice into a validated offer.
    ///
    /// # Errors
    /// [`PairingOfferError`] on a wrong scheme, unexpected fields, malformed
    /// payload, or failed structural or policy validation.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, PairingOfferError> {
        Self::from_map(decode_bootstrap_map(bytes)?)
    }

    /// Reconstruct an offer from its decoded map.
    fn from_map(mut map: BTreeMap<String, WireValue>) -> Result<Self, PairingOfferError> {
        take_header(&mut map, &OFFER_FIELDS)?;
        let offer_id = take_bytes(&mut map, "offer_id")?;
        let offer_id =
            OfferId::reconstruct(&offer_id).map_err(|_| PairingOfferError::WrongLength {
                field: "offer_id",
                expected: OFFER_ID_SIZE,
                got: offer_id.len(),
            })?;
        let suites = take_text_array(&mut map, "suites")?;
        let profiles = take_text_array(&mut map, "profiles")?;
        let transport_values = take_array(&mut map, "transports")?;
        let transports = transport_values
            .into_iter()
            .map(transport_from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let offer_ttl_ms = take_unsigned(&mut map, "offer_ttl_ms")?;
        Self::reconstruct(offer_id, suites, profiles, transports, offer_ttl_ms)
    }

    /// The offer, when it lists the transport `profile` it arrived over.
    fn served_over(self, profile: TransportProfile) -> Result<Self, PairingOfferError> {
        if self.entry(profile).is_none() {
            return Err(PairingOfferError::TransportNotOffered);
        }
        Ok(self)
    }

    /// Hash the deterministic offer per RAPP v26.10.29 §4.2.
    ///
    /// # Errors
    /// [`PairingOfferError`] when deterministic encoding fails.
    pub fn offer_hash(&self) -> Result<[u8; 32], PairingOfferError> {
        let encoded = self.to_cbor()?;
        Ok(Sha256::digest(&encoded).into())
    }

    fn validate(&self) -> Result<(), PairingOfferError> {
        if self.suites.is_empty() || self.profiles.is_empty() || self.transports.is_empty() {
            return Err(PairingOfferError::EmptyRequiredArray);
        }
        if !self.suites.iter().any(|suite| suite == CPACE_KC2_SUITE) {
            return Err(PairingOfferError::MandatorySuiteMissing);
        }
        if self.offer_ttl_ms != OFFER_TTL_MS {
            return Err(PairingOfferError::InvalidTtl {
                got: self.offer_ttl_ms,
            });
        }
        let mut previous: Option<TransportProfile> = None;
        for candidate in &self.transports {
            let profile = TransportProfile::parse(&candidate.profile)
                .ok_or(PairingOfferError::InvalidTransport)?;
            if *candidate != profile.offer_entry() {
                return Err(PairingOfferError::InvalidTransport);
            }
            if previous
                .is_some_and(|earlier| earlier.name().as_bytes() >= profile.name().as_bytes())
            {
                return Err(PairingOfferError::InvalidTransport);
            }
            previous = Some(profile);
        }
        Ok(())
    }

    fn to_map(&self) -> BTreeMap<String, WireValue> {
        BTreeMap::from([
            ("scheme".to_owned(), WireValue::Text(SCHEME.to_owned())),
            ("version".to_owned(), version_value()),
            (
                "offer_id".to_owned(),
                WireValue::Bytes(self.offer_id.as_bytes().to_vec()),
            ),
            (
                "suites".to_owned(),
                WireValue::Array(self.suites.iter().cloned().map(WireValue::Text).collect()),
            ),
            (
                "profiles".to_owned(),
                WireValue::Array(self.profiles.iter().cloned().map(WireValue::Text).collect()),
            ),
            (
                "transports".to_owned(),
                WireValue::Array(self.transports.iter().map(transport_to_value).collect()),
            ),
            (
                "offer_ttl_ms".to_owned(),
                WireValue::Unsigned(self.offer_ttl_ms),
            ),
        ])
    }
}

impl fmt::Debug for PairingOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingOffer")
            .field("offer_id", &self.offer_id)
            .field("suites", &self.suites)
            .field("profiles", &self.profiles)
            .field("transports", &self.transports)
            .field("offer_ttl_ms", &self.offer_ttl_ms)
            .finish()
    }
}

/// The `pairing-busy` a custodian in pairing mode answers while it cannot
/// admit an attempt (RAPP v26.10.29 §3.3 item 6, §4.2 "PairingBusy Schema"
/// and "Busy Refusal").
///
/// It carries only the time until the custodian can admit an attempt,
/// between [`PAIRING_BUSY_RETRY_AFTER_MIN_MS`] and
/// [`PAIRING_BUSY_RETRY_AFTER_MAX_MS`], and nothing of the code or the
/// offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingBusy {
    retry_after_ms: u64,
}

impl PairingBusy {
    /// A busy answer asking the requester to wait `retry_after_ms`.
    ///
    /// # Errors
    /// [`PairingOfferError::RetryAfterOutOfRange`] outside
    /// [`PAIRING_BUSY_RETRY_AFTER_MIN_MS`] to
    /// [`PAIRING_BUSY_RETRY_AFTER_MAX_MS`].
    pub const fn new(retry_after_ms: u64) -> Result<Self, PairingOfferError> {
        if retry_after_ms < PAIRING_BUSY_RETRY_AFTER_MIN_MS
            || retry_after_ms > PAIRING_BUSY_RETRY_AFTER_MAX_MS
        {
            return Err(PairingOfferError::RetryAfterOutOfRange {
                got: retry_after_ms,
            });
        }
        Ok(Self { retry_after_ms })
    }

    /// The custodian's busy answer for a wait of `wait_ms` until it can
    /// admit an attempt, held to the schema's range: a wait that has
    /// already passed asks for the least wait, a longer one for the
    /// greatest.
    #[must_use]
    pub const fn until_admissible(wait_ms: u64) -> Self {
        let retry_after_ms = if wait_ms < PAIRING_BUSY_RETRY_AFTER_MIN_MS {
            PAIRING_BUSY_RETRY_AFTER_MIN_MS
        } else if wait_ms > PAIRING_BUSY_RETRY_AFTER_MAX_MS {
            PAIRING_BUSY_RETRY_AFTER_MAX_MS
        } else {
            wait_ms
        };
        Self { retry_after_ms }
    }

    /// Milliseconds until the custodian can admit an attempt.
    #[must_use]
    pub const fn retry_after_ms(self) -> u64 {
        self.retry_after_ms
    }

    /// Serialize into deterministic CBOR.
    ///
    /// # Errors
    /// [`PairingOfferError::Wire`] when deterministic encoding fails.
    pub fn to_cbor(self) -> Result<Vec<u8>, PairingOfferError> {
        Ok(encode_deterministic_cbor(&WireValue::Map(BTreeMap::from(
            [
                ("scheme".to_owned(), WireValue::Text(SCHEME.to_owned())),
                ("version".to_owned(), version_value()),
                (
                    RETRY_AFTER_FIELD.to_owned(),
                    WireValue::Unsigned(self.retry_after_ms),
                ),
            ],
        )))?)
    }

    /// Decode a deterministic-CBOR `pairing-busy`.
    ///
    /// # Errors
    /// [`PairingOfferError`] on malformed CBOR, a wrong scheme or version,
    /// a missing or unknown field, or a `retry_after_ms` out of range.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, PairingOfferError> {
        Self::from_map(decode_bootstrap_map(bytes)?)
    }

    fn from_map(mut map: BTreeMap<String, WireValue>) -> Result<Self, PairingOfferError> {
        take_header(&mut map, &BUSY_FIELDS)?;
        Self::new(take_unsigned(&mut map, RETRY_AFTER_FIELD)?)
    }
}

/// What a requester reads from a custodian in pairing mode (RAPP v26.10.29
/// §4.2, Bootstrap Read Flow item 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapAnswer {
    /// The custodian can admit an attempt: its offer, listing the transport
    /// it arrived over.
    Offer(PairingOffer),
    /// The custodian cannot admit an attempt now.
    Busy(PairingBusy),
}

impl BootstrapAnswer {
    /// Decode the bootstrap bytes received over the transport `profile`. A
    /// map carrying `retry_after_ms` is a `pairing-busy`; any other is a
    /// `pairing-offer`, which must list `profile`.
    ///
    /// # Errors
    /// [`PairingOfferError`] when the answer decodes as neither.
    pub fn from_bootstrap(
        bytes: &[u8],
        profile: TransportProfile,
    ) -> Result<Self, PairingOfferError> {
        let map = decode_bootstrap_map(bytes)?;
        if map.contains_key(RETRY_AFTER_FIELD) {
            return PairingBusy::from_map(map).map(Self::Busy);
        }
        PairingOffer::from_map(map)?
            .served_over(profile)
            .map(Self::Offer)
    }
}

/// Structural or policy failure in a bootstrap answer: a `pairing-offer`
/// or a `pairing-busy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingOfferError {
    /// The answer does not carry the `rapp` scheme.
    WrongScheme,
    /// Offer version differs from the supported wire version.
    UnsupportedVersion,
    /// Field carries the wrong CBOR type.
    WrongType,
    /// Required field is absent.
    MissingField {
        /// Name of the absent field.
        field: &'static str,
    },
    /// Field outside the offer schema.
    UnknownField,
    /// Fixed-size field has the wrong length.
    WrongLength {
        /// Name of the mis-sized field.
        field: &'static str,
        /// Registered length in bytes.
        expected: usize,
        /// Received length in bytes.
        got: usize,
    },
    /// A required array is empty.
    EmptyRequiredArray,
    /// Offer omits the mandatory pairing suite.
    MandatorySuiteMissing,
    /// A transport entry is not the registered entry of a registered
    /// profile, or the entries are not sorted by profile without duplicates.
    InvalidTransport,
    /// The offer does not list the transport it was received over.
    TransportNotOffered,
    /// A `pairing-busy` wait outside [`PAIRING_BUSY_RETRY_AFTER_MIN_MS`] to
    /// [`PAIRING_BUSY_RETRY_AFTER_MAX_MS`].
    RetryAfterOutOfRange {
        /// Declared wait in milliseconds.
        got: u64,
    },
    /// Lifetime differs from [`OFFER_TTL_MS`].
    InvalidTtl {
        /// Declared lifetime in milliseconds.
        got: u64,
    },
    /// Local deadline arithmetic overflowed.
    DeadlineOverflow,
    /// Encoded offer exceeds [`MAX_OFFER_SIZE`].
    Oversized {
        /// Encoded length in bytes.
        got: usize,
    },
    /// Underlying deterministic-CBOR failure.
    Wire(WireError),
}

impl From<WireError> for PairingOfferError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl fmt::Display for PairingOfferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid RAPP pairing offer")
    }
}

impl core::error::Error for PairingOfferError {}

/// The bootstrap answers' version triple, `[26, 10, 29]`.
fn version_triple() -> Vec<WireValue> {
    vec![
        WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_29.0)),
        WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_29.1)),
        WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_29.2)),
    ]
}

fn version_value() -> WireValue {
    WireValue::Array(version_triple())
}

/// Decode bounded bootstrap bytes into their top-level map.
fn decode_bootstrap_map(bytes: &[u8]) -> Result<BTreeMap<String, WireValue>, PairingOfferError> {
    if bytes.len() > MAX_OFFER_SIZE {
        return Err(PairingOfferError::Oversized { got: bytes.len() });
    }
    let WireValue::Map(map) = decode_deterministic_cbor(bytes)? else {
        return Err(PairingOfferError::WrongType);
    };
    Ok(map)
}

/// Check that `map` has no field outside `fields`, and take and check the
/// scheme and version both bootstrap answers carry.
fn take_header(
    map: &mut BTreeMap<String, WireValue>,
    fields: &[&str],
) -> Result<(), PairingOfferError> {
    if map.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(PairingOfferError::UnknownField);
    }
    if take_text(map, "scheme")? != SCHEME {
        return Err(PairingOfferError::WrongScheme);
    }
    if take_array(map, "version")? != version_triple() {
        return Err(PairingOfferError::UnsupportedVersion);
    }
    Ok(())
}

fn transport_to_value(candidate: &TransportCandidate) -> WireValue {
    WireValue::Map(BTreeMap::from([
        (
            "profile".to_owned(),
            WireValue::Text(candidate.profile.clone()),
        ),
        (
            "candidate_id".to_owned(),
            WireValue::Text(candidate.candidate_id.clone()),
        ),
        (
            "parameters".to_owned(),
            WireValue::Map(candidate.parameters.clone()),
        ),
    ]))
}

fn transport_from_value(value: WireValue) -> Result<TransportCandidate, PairingOfferError> {
    let WireValue::Map(mut map) = value else {
        return Err(PairingOfferError::WrongType);
    };
    if map
        .keys()
        .any(|key| !["profile", "candidate_id", "parameters"].contains(&key.as_str()))
    {
        return Err(PairingOfferError::UnknownField);
    }
    let profile = take_text(&mut map, "profile")?;
    let candidate_id = take_text(&mut map, "candidate_id")?;
    let WireValue::Map(parameters) =
        map.remove("parameters")
            .ok_or(PairingOfferError::MissingField {
                field: "parameters",
            })?
    else {
        return Err(PairingOfferError::WrongType);
    };
    Ok(TransportCandidate {
        profile,
        candidate_id,
        parameters,
    })
}

fn take_text(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<String, PairingOfferError> {
    match map
        .remove(field)
        .ok_or(PairingOfferError::MissingField { field })?
    {
        WireValue::Text(value) => Ok(value),
        _ => Err(PairingOfferError::WrongType),
    }
}

fn take_bytes(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<u8>, PairingOfferError> {
    match map
        .remove(field)
        .ok_or(PairingOfferError::MissingField { field })?
    {
        WireValue::Bytes(value) => Ok(value),
        _ => Err(PairingOfferError::WrongType),
    }
}

fn take_array(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<WireValue>, PairingOfferError> {
    match map
        .remove(field)
        .ok_or(PairingOfferError::MissingField { field })?
    {
        WireValue::Array(value) => Ok(value),
        _ => Err(PairingOfferError::WrongType),
    }
}

fn take_text_array(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<String>, PairingOfferError> {
    take_array(map, field)?
        .into_iter()
        .map(|value| match value {
            WireValue::Text(value) => Ok(value),
            _ => Err(PairingOfferError::WrongType),
        })
        .collect()
}

fn take_unsigned(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<u64, PairingOfferError> {
    match map
        .remove(field)
        .ok_or(PairingOfferError::MissingField { field })?
    {
        WireValue::Unsigned(value) => Ok(value),
        _ => Err(PairingOfferError::WrongType),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        BootstrapAnswer, MAX_OFFER_SIZE, PAIRING_BUSY_RETRY_AFTER_MAX_MS,
        PAIRING_BUSY_RETRY_AFTER_MIN_MS, PairingBusy, PairingOffer, PairingOfferDeadline,
        PairingOfferError, RETRY_AFTER_FIELD, SCHEME, version_value,
    };
    use crate::{
        OfferId, ProfileName, TransportCandidate, TransportProfile, WIRE_VERSION_V26_10_29,
        WireValue, encode_deterministic_cbor,
    };

    fn profiles() -> Vec<String> {
        ProfileName::ALL
            .iter()
            .map(|profile| profile.as_str().to_owned())
            .collect()
    }

    fn offer(transports: &[TransportProfile]) -> PairingOffer {
        PairingOffer::create(OfferId::from_array([0x10; 32]), profiles(), transports)
            .expect("fixture is valid")
    }

    #[test]
    fn bootstrap_bytes_round_trip_over_each_listed_transport() {
        let offer = offer(&[TransportProfile::Stream, TransportProfile::Ble]);
        let bytes = offer.to_cbor().expect("CBOR encodes");
        for profile in [TransportProfile::Ble, TransportProfile::Stream] {
            assert_eq!(
                BootstrapAnswer::from_bootstrap(&bytes, profile).expect("bootstrap decodes"),
                BootstrapAnswer::Offer(offer.clone())
            );
        }
    }

    #[test]
    fn bootstrap_over_an_unlisted_transport_is_refused() {
        let bytes = offer(&[TransportProfile::Ble])
            .to_cbor()
            .expect("CBOR encodes");
        assert_eq!(
            BootstrapAnswer::from_bootstrap(&bytes, TransportProfile::Stream),
            Err(PairingOfferError::TransportNotOffered)
        );
    }

    /// A `pairing-busy` map with `retry_after_ms` replaced by `retry_after`,
    /// or removed when it is `None`.
    fn busy_map(retry_after: Option<WireValue>) -> BTreeMap<String, WireValue> {
        let mut map = BTreeMap::from([
            ("scheme".to_owned(), WireValue::Text(SCHEME.to_owned())),
            ("version".to_owned(), version_value()),
        ]);
        if let Some(value) = retry_after {
            map.insert(RETRY_AFTER_FIELD.to_owned(), value);
        }
        map
    }

    fn encode(map: BTreeMap<String, WireValue>) -> Vec<u8> {
        encode_deterministic_cbor(&WireValue::Map(map)).expect("CBOR encodes")
    }

    #[test]
    fn a_busy_answer_round_trips_over_either_transport() {
        for retry_after_ms in [
            PAIRING_BUSY_RETRY_AFTER_MIN_MS,
            PAIRING_BUSY_RETRY_AFTER_MAX_MS,
        ] {
            let busy = PairingBusy::new(retry_after_ms).expect("in range");
            let bytes = busy.to_cbor().expect("CBOR encodes");
            assert_eq!(PairingBusy::from_cbor(&bytes), Ok(busy));
            for profile in [TransportProfile::Ble, TransportProfile::Stream] {
                assert_eq!(
                    BootstrapAnswer::from_bootstrap(&bytes, profile),
                    Ok(BootstrapAnswer::Busy(busy))
                );
            }
        }
    }

    #[test]
    fn a_busy_wait_is_held_to_the_schema_range() {
        assert_eq!(
            PairingBusy::until_admissible(0).retry_after_ms(),
            PAIRING_BUSY_RETRY_AFTER_MIN_MS
        );
        assert_eq!(
            PairingBusy::until_admissible(PAIRING_BUSY_RETRY_AFTER_MAX_MS + 1).retry_after_ms(),
            PAIRING_BUSY_RETRY_AFTER_MAX_MS
        );
        assert_eq!(PairingBusy::until_admissible(250).retry_after_ms(), 250);
        assert_eq!(
            PairingBusy::new(0),
            Err(PairingOfferError::RetryAfterOutOfRange { got: 0 })
        );
    }

    #[test]
    fn malformed_busy_answers_are_refused() {
        let out_of_range = [
            PAIRING_BUSY_RETRY_AFTER_MIN_MS - 1,
            PAIRING_BUSY_RETRY_AFTER_MAX_MS + 1,
        ];
        for got in out_of_range {
            assert_eq!(
                BootstrapAnswer::from_bootstrap(
                    &encode(busy_map(Some(WireValue::Unsigned(got)))),
                    TransportProfile::Stream
                ),
                Err(PairingOfferError::RetryAfterOutOfRange { got })
            );
        }
        assert_eq!(
            PairingBusy::from_cbor(&encode(busy_map(None))),
            Err(PairingOfferError::MissingField {
                field: RETRY_AFTER_FIELD
            })
        );
        assert_eq!(
            BootstrapAnswer::from_bootstrap(
                &encode(busy_map(Some(WireValue::Text("soon".to_owned())))),
                TransportProfile::Stream
            ),
            Err(PairingOfferError::WrongType)
        );
        let mut wrong_version =
            busy_map(Some(WireValue::Unsigned(PAIRING_BUSY_RETRY_AFTER_MIN_MS)));
        wrong_version.insert(
            "version".to_owned(),
            WireValue::Array(vec![
                WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_29.0)),
                WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_29.1)),
                WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_29.2) + 1),
            ]),
        );
        assert_eq!(
            BootstrapAnswer::from_bootstrap(&encode(wrong_version), TransportProfile::Stream),
            Err(PairingOfferError::UnsupportedVersion)
        );
        let mut wrong_scheme = busy_map(Some(WireValue::Unsigned(PAIRING_BUSY_RETRY_AFTER_MIN_MS)));
        wrong_scheme.insert("scheme".to_owned(), WireValue::Text("rappx".to_owned()));
        assert_eq!(
            BootstrapAnswer::from_bootstrap(&encode(wrong_scheme), TransportProfile::Stream),
            Err(PairingOfferError::WrongScheme)
        );
        let mut extra = busy_map(Some(WireValue::Unsigned(PAIRING_BUSY_RETRY_AFTER_MIN_MS)));
        extra.insert("offer_id".to_owned(), WireValue::Bytes(vec![0x10; 32]));
        assert_eq!(
            BootstrapAnswer::from_bootstrap(&encode(extra), TransportProfile::Stream),
            Err(PairingOfferError::UnknownField),
            "an offer field in a busy answer is not an offer"
        );
    }

    #[test]
    fn an_offer_carrying_a_wait_is_refused() {
        let mut map = offer(&[TransportProfile::Stream]).to_map();
        map.insert(
            RETRY_AFTER_FIELD.to_owned(),
            WireValue::Unsigned(PAIRING_BUSY_RETRY_AFTER_MIN_MS),
        );
        assert_eq!(
            BootstrapAnswer::from_bootstrap(&encode(map), TransportProfile::Stream),
            Err(PairingOfferError::UnknownField)
        );
    }

    #[test]
    fn entries_are_sorted_by_profile() {
        let offer = offer(&[TransportProfile::Stream, TransportProfile::Ble]);
        assert_eq!(
            offer.transports,
            vec![
                TransportProfile::Ble.offer_entry(),
                TransportProfile::Stream.offer_entry()
            ]
        );
    }

    #[test]
    fn unsorted_or_unregistered_entries_are_refused() {
        let unsorted = PairingOffer::reconstruct(
            OfferId::from_array([1; 32]),
            vec![crate::CPACE_KC2_SUITE.to_owned()],
            profiles(),
            vec![
                TransportProfile::Stream.offer_entry(),
                TransportProfile::Ble.offer_entry(),
            ],
            crate::OFFER_TTL_MS,
        );
        assert_eq!(unsorted, Err(PairingOfferError::InvalidTransport));
        let mut altered = TransportProfile::Stream.offer_entry();
        altered.candidate_id = "stream-2".to_owned();
        let unregistered = PairingOffer::reconstruct(
            OfferId::from_array([1; 32]),
            vec![crate::CPACE_KC2_SUITE.to_owned()],
            profiles(),
            vec![altered],
            crate::OFFER_TTL_MS,
        );
        assert_eq!(unregistered, Err(PairingOfferError::InvalidTransport));
        let unknown = PairingOffer::reconstruct(
            OfferId::from_array([1; 32]),
            vec![crate::CPACE_KC2_SUITE.to_owned()],
            profiles(),
            vec![TransportCandidate {
                profile: "local-quic-v1".to_owned(),
                candidate_id: "candidate".to_owned(),
                parameters: std::collections::BTreeMap::new(),
            }],
            crate::OFFER_TTL_MS,
        );
        assert_eq!(unknown, Err(PairingOfferError::InvalidTransport));
    }

    #[test]
    fn offer_with_pairing_secret_is_strictly_rejected() {
        let mut map = offer(&[TransportProfile::Ble]).to_map();
        map.insert(
            "pairing_secret".to_owned(),
            WireValue::Bytes(vec![0x42; 32]),
        );
        let forbidden_cbor = encode_deterministic_cbor(&WireValue::Map(map)).expect("CBOR encodes");
        assert_eq!(
            PairingOffer::from_cbor(&forbidden_cbor),
            Err(PairingOfferError::UnknownField)
        );
    }

    #[test]
    fn offer_fits_one_att_value_with_both_transports() {
        let cbor = offer(&[TransportProfile::Ble, TransportProfile::Stream])
            .to_cbor()
            .expect("CBOR encodes");
        assert!(cbor.len() <= MAX_OFFER_SIZE, "{} bytes", cbor.len());
    }

    #[test]
    fn monotonic_deadline_is_live_only_inside_original_interval() {
        let deadline = PairingOfferDeadline::from_offer(&offer(&[TransportProfile::Ble]), 10_000)
            .expect("deadline does not overflow");

        assert!(!deadline.is_live(9_999));
        assert!(deadline.is_live(10_000));
        assert!(deadline.is_live(10_000 + crate::OFFER_TTL_MS - 1));
        assert!(!deadline.is_live(10_000 + crate::OFFER_TTL_MS));
    }

    #[test]
    fn monotonic_deadline_rejects_overflow() {
        assert!(
            PairingOfferDeadline::from_offer(&offer(&[TransportProfile::Ble]), u64::MAX).is_err()
        );
    }
}
