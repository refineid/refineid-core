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

//! The `pairing-offer` a custodian serves through the offer bootstrap of
//! each transport (RAPP v26.10.10 §4.2).

use core::fmt;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{
    CPACE_KC2_SUITE, OFFER_ID_SIZE, OFFER_TTL_MS, OfferId, TransportCandidate, TransportProfile,
    WIRE_VERSION_V26_10_10, WireError, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor,
};

/// Upper bound on an encoded offer: the 509-byte ATT value capacity at the
/// minimum ATT MTU of 512 (RAPP v26.10.10 §4.2).
pub const MAX_OFFER_SIZE: usize = 509;

/// Validated `pairing-offer` per RAPP v26.10.10 §4.2.
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
        if bytes.len() > MAX_OFFER_SIZE {
            return Err(PairingOfferError::Oversized { got: bytes.len() });
        }
        let value = decode_deterministic_cbor(bytes)?;
        let WireValue::Map(mut map) = value else {
            return Err(PairingOfferError::WrongType);
        };
        let expected = [
            "scheme",
            "version",
            "offer_id",
            "suites",
            "profiles",
            "transports",
            "offer_ttl_ms",
        ];
        if map.keys().any(|key| !expected.contains(&key.as_str())) {
            return Err(PairingOfferError::UnknownField);
        }
        if take_text(&mut map, "scheme")? != "rapp" {
            return Err(PairingOfferError::WrongScheme);
        }
        let version = take_array(&mut map, "version")?;
        if version
            != vec![
                WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_10.0)),
                WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_10.1)),
                WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_10.2)),
            ]
        {
            return Err(PairingOfferError::UnsupportedVersion);
        }
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

    /// Decode bootstrap bytes received over the transport `profile`, which
    /// the offer must list (RAPP v26.10.10 §4.2 step 3).
    ///
    /// # Errors
    /// [`PairingOfferError`] on any decode or validation failure, or
    /// [`PairingOfferError::TransportNotOffered`] when the offer does not
    /// list `profile`.
    pub fn from_bootstrap(
        bytes: &[u8],
        profile: TransportProfile,
    ) -> Result<Self, PairingOfferError> {
        let offer = Self::from_cbor(bytes)?;
        if offer.entry(profile).is_none() {
            return Err(PairingOfferError::TransportNotOffered);
        }
        Ok(offer)
    }

    /// Hash the deterministic offer per RAPP v26.10.10 §4.2.
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
            ("scheme".to_owned(), WireValue::Text("rapp".to_owned())),
            (
                "version".to_owned(),
                WireValue::Array(vec![
                    WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_10.0)),
                    WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_10.1)),
                    WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_10.2)),
                ]),
            ),
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

/// Structural or policy failure in a pairing offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingOfferError {
    /// The offer does not carry the `rapp` scheme.
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
    use super::{MAX_OFFER_SIZE, PairingOffer, PairingOfferDeadline, PairingOfferError};
    use crate::{
        OfferId, ProfileName, TransportCandidate, TransportProfile, WireValue,
        encode_deterministic_cbor,
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
                PairingOffer::from_bootstrap(&bytes, profile).expect("bootstrap decodes"),
                offer
            );
        }
    }

    #[test]
    fn bootstrap_over_an_unlisted_transport_is_refused() {
        let bytes = offer(&[TransportProfile::Ble])
            .to_cbor()
            .expect("CBOR encodes");
        assert_eq!(
            PairingOffer::from_bootstrap(&bytes, TransportProfile::Stream),
            Err(PairingOfferError::TransportNotOffered)
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
        assert!(deadline.is_live(69_999));
        assert!(!deadline.is_live(70_000));
    }

    #[test]
    fn monotonic_deadline_rejects_overflow() {
        assert!(
            PairingOfferDeadline::from_offer(&offer(&[TransportProfile::Ble]), u64::MAX).is_err()
        );
    }
}
