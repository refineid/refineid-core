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

//! Manual high-entropy pairing offer and QR URI.

use core::fmt;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    MANDATORY_PAIRING_SUITE, MAX_TRANSPORT_CANDIDATES, OFFER_ID_SIZE, OFFER_TTL_MAX_MS, OfferId,
    PairingSecret, TransportCandidate, VISIBLE_WIRE_VERSION, WireError, WireValue,
    decode_deterministic_cbor, encode_deterministic_cbor,
};

const MAX_OFFER_SIZE: usize = 1_024;
const PAIRING_SECRET_SIZE: usize = 32;
const URI_PREFIX: &str = "rapp:";

/// Validated logical pairing offer.
pub struct PairingOffer {
    /// Random one-off offer identifier.
    pub offer_id: OfferId,
    pairing_secret: PairingSecret,
    /// Ordered supported cryptographic suites.
    pub suites: Vec<String>,
    /// Ordered requested credential-profile registry names.
    pub profiles: Vec<String>,
    /// Public transport rendezvous candidates.
    pub transports: Vec<TransportCandidate>,
    /// Monotonic lifetime hint, independently clamped by both peers.
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

    /// Whether the offer is still live on this monotonic clock.
    #[must_use]
    pub const fn is_live(self, now_ms: u64) -> bool {
        now_ms >= self.started_at_ms && now_ms < self.expires_at_ms
    }
}

impl PairingOffer {
    /// Construct a fresh offer from CSPRNG-provided values.
    ///
    /// # Errors
    /// [`PairingOfferError`] when the offer fails structural or policy
    /// validation.
    pub fn reconstruct(
        offer_id: OfferId,
        pairing_secret: PairingSecret,
        suites: Vec<String>,
        profiles: Vec<String>,
        transports: Vec<TransportCandidate>,
        offer_ttl_ms: u64,
    ) -> Result<Self, PairingOfferError> {
        let offer = Self {
            offer_id,
            pairing_secret,
            suites,
            profiles,
            transports,
            offer_ttl_ms,
        };
        offer.validate()?;
        Ok(offer)
    }

    /// Borrow the one-use secret only for the pairing Noise handshake.
    #[must_use]
    pub const fn pairing_secret(&self) -> &PairingSecret {
        &self.pairing_secret
    }

    /// Hash the deterministic offer with the bearer secret removed.
    ///
    /// # Errors
    /// [`PairingOfferError::Wire`] when deterministic encoding fails.
    pub fn offer_hash(&self) -> Result<[u8; 32], PairingOfferError> {
        let encoded = encode_deterministic_cbor(&WireValue::Map(self.to_map(false)))?;
        Ok(Sha256::digest(encoded).into())
    }

    /// Encode the complete secret-bearing QR payload.
    ///
    /// # Errors
    /// [`PairingOfferError`] on an invalid offer or an encoding above the QR
    /// size limit.
    pub fn to_uri(&self) -> Result<PairingOfferUri, PairingOfferError> {
        self.validate()?;
        let encoded = encode_deterministic_cbor(&WireValue::Map(self.to_map(true)))?;
        if encoded.len() > MAX_OFFER_SIZE {
            return Err(PairingOfferError::Oversized { got: encoded.len() });
        }
        let mut uri = String::with_capacity(URI_PREFIX.len() + encoded.len() * 2);
        uri.push_str(URI_PREFIX);
        uri.push_str(&base64url_encode(&encoded));
        Ok(PairingOfferUri(uri))
    }

    /// Decode a scanned QR URI into a validated offer.
    ///
    /// # Errors
    /// [`PairingOfferError`] on a wrong scheme, malformed payload, or failed
    /// structural or policy validation.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "consumes the one-use secret-bearing URI so it is zeroized after decoding"
    )]
    pub fn from_uri(uri: PairingOfferUri) -> Result<Self, PairingOfferError> {
        let payload = uri
            .0
            .strip_prefix(URI_PREFIX)
            .ok_or(PairingOfferError::WrongScheme)?;
        let mut decoded = base64url_decode(payload)?;
        if decoded.len() > MAX_OFFER_SIZE {
            let got = decoded.len();
            decoded.zeroize();
            return Err(PairingOfferError::Oversized { got });
        }
        let value = decode_deterministic_cbor(&decoded)?;
        decoded.zeroize();
        let WireValue::Map(mut map) = value else {
            return Err(PairingOfferError::WrongType);
        };
        let expected = [
            "scheme",
            "version",
            "offer_id",
            "pairing_secret",
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
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.0)),
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.1)),
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.2)),
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
        let mut secret = take_bytes(&mut map, "pairing_secret")?;
        let secret_bytes: [u8; PAIRING_SECRET_SIZE] =
            secret
                .as_slice()
                .try_into()
                .map_err(|_| PairingOfferError::WrongLength {
                    field: "pairing_secret",
                    expected: PAIRING_SECRET_SIZE,
                    got: secret.len(),
                })?;
        secret.zeroize();
        let suites = take_text_array(&mut map, "suites")?;
        let profiles = take_text_array(&mut map, "profiles")?;
        let transport_values = take_array(&mut map, "transports")?;
        let transports = transport_values
            .into_iter()
            .map(transport_from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let offer_ttl_ms = take_unsigned(&mut map, "offer_ttl_ms")?;
        Self::reconstruct(
            offer_id,
            PairingSecret::from_random_bytes(secret_bytes),
            suites,
            profiles,
            transports,
            offer_ttl_ms,
        )
    }

    fn validate(&self) -> Result<(), PairingOfferError> {
        if self.suites.is_empty() || self.profiles.is_empty() || self.transports.is_empty() {
            return Err(PairingOfferError::EmptyRequiredArray);
        }
        if !self
            .suites
            .iter()
            .any(|suite| suite == MANDATORY_PAIRING_SUITE)
        {
            return Err(PairingOfferError::MandatorySuiteMissing);
        }
        if self.transports.len() > MAX_TRANSPORT_CANDIDATES {
            return Err(PairingOfferError::TooManyTransports {
                got: self.transports.len(),
            });
        }
        if self.offer_ttl_ms == 0 || self.offer_ttl_ms > OFFER_TTL_MAX_MS {
            return Err(PairingOfferError::InvalidTtl {
                got: self.offer_ttl_ms,
            });
        }
        if self
            .transports
            .iter()
            .any(|candidate| candidate.profile.is_empty() || candidate.candidate_id.is_empty())
        {
            return Err(PairingOfferError::InvalidTransport);
        }
        Ok(())
    }

    fn to_map(&self, include_secret: bool) -> BTreeMap<String, WireValue> {
        let mut map = BTreeMap::from([
            ("scheme".to_owned(), WireValue::Text("rapp".to_owned())),
            (
                "version".to_owned(),
                WireValue::Array(vec![
                    WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.0)),
                    WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.1)),
                    WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.2)),
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
        ]);
        if include_secret {
            map.insert(
                "pairing_secret".to_owned(),
                WireValue::Bytes(self.pairing_secret.expose().to_vec()),
            );
        }
        map
    }
}

impl fmt::Debug for PairingOffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingOffer")
            .field("offer_id", &self.offer_id)
            .field("pairing_secret", &"[redacted]")
            .field("suites", &self.suites)
            .field("profiles", &self.profiles)
            .field("transports", &self.transports)
            .field("offer_ttl_ms", &self.offer_ttl_ms)
            .finish()
    }
}

/// Secret-bearing `rapp:` URI intended only for immediate QR rendering.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingOfferUri(String);

impl PairingOfferUri {
    /// Reconstruct owned text received directly from a QR scanner.
    #[must_use]
    pub const fn from_scanned_text(text: String) -> Self {
        Self(text)
    }

    /// Borrow text for direct QR rendering or parsing.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PairingOfferUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingOfferUri([redacted])")
    }
}

/// Structural or policy failure in a pairing QR offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingOfferError {
    /// URI does not carry the offer scheme.
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
    /// Offer exceeds the transport-candidate limit.
    TooManyTransports {
        /// Declared candidate count.
        got: usize,
    },
    /// Transport candidate has an empty profile or candidate identifier.
    InvalidTransport,
    /// Lifetime is zero or exceeds the offer lifetime ceiling.
    InvalidTtl {
        /// Declared lifetime in milliseconds.
        got: u64,
    },
    /// Local deadline arithmetic overflowed.
    DeadlineOverflow,
    /// Encoded offer exceeds the QR size limit.
    Oversized {
        /// Encoded length in bytes.
        got: usize,
    },
    /// Payload is not unpadded base64url.
    InvalidBase64Url,
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

fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

fn base64url_decode(text: &str) -> Result<Vec<u8>, PairingOfferError> {
    if text.is_empty() || text.contains('=') || text.len() % 4 == 1 {
        return Err(PairingOfferError::InvalidBase64Url);
    }
    let values = text
        .bytes()
        .map(decode_base64url_byte)
        .collect::<Result<Vec<_>, _>>()?;
    let mut output = Vec::with_capacity(values.len() * 3 / 4);
    for chunk in values.chunks(4) {
        let first = chunk[0];
        let second = chunk[1];
        output.push((first << 2) | (second >> 4));
        if chunk.len() > 2 {
            let third = chunk[2];
            output.push((second << 4) | (third >> 2));
            if chunk.len() > 3 {
                output.push((third << 6) | chunk[3]);
            }
        }
    }
    Ok(output)
}

const fn decode_base64url_byte(byte: u8) -> Result<u8, PairingOfferError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(PairingOfferError::InvalidBase64Url),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{PairingOffer, PairingOfferDeadline};
    use crate::{MANDATORY_PAIRING_SUITE, OfferId, PairingSecret, TransportCandidate};

    #[test]
    fn offer_uri_round_trip_preserves_secret_and_hash() {
        let offer = PairingOffer::reconstruct(
            OfferId::from_array([1; 32]),
            PairingSecret::from_random_bytes([2; 32]),
            vec![MANDATORY_PAIRING_SUITE.to_owned()],
            vec!["fi.refineid.card-status.v1".to_owned()],
            vec![TransportCandidate {
                profile: "local-quic-v1".to_owned(),
                candidate_id: "candidate".to_owned(),
                parameters: BTreeMap::new(),
            }],
            60_000,
        )
        .expect("fixture is valid");
        let expected_hash = offer.offer_hash().expect("hash encodes");
        let decoded =
            PairingOffer::from_uri(offer.to_uri().expect("URI encodes")).expect("URI decodes");
        assert_eq!(decoded.offer_hash().expect("hash encodes"), expected_hash);
    }

    #[test]
    fn monotonic_deadline_is_live_only_inside_original_interval() {
        let offer = PairingOffer::reconstruct(
            OfferId::from_array([1; 32]),
            PairingSecret::from_random_bytes([2; 32]),
            vec![MANDATORY_PAIRING_SUITE.to_owned()],
            vec!["fi.refineid.card-status.v1".to_owned()],
            vec![TransportCandidate {
                profile: "local-quic-v1".to_owned(),
                candidate_id: "candidate".to_owned(),
                parameters: BTreeMap::new(),
            }],
            60_000,
        )
        .expect("fixture is valid");
        let deadline =
            PairingOfferDeadline::from_offer(&offer, 10_000).expect("deadline does not overflow");

        assert!(!deadline.is_live(9_999));
        assert!(deadline.is_live(10_000));
        assert!(deadline.is_live(69_999));
        assert!(!deadline.is_live(70_000));
    }

    #[test]
    fn monotonic_deadline_rejects_overflow() {
        let offer = PairingOffer::reconstruct(
            OfferId::from_array([1; 32]),
            PairingSecret::from_random_bytes([2; 32]),
            vec![MANDATORY_PAIRING_SUITE.to_owned()],
            vec!["fi.refineid.card-status.v1".to_owned()],
            vec![TransportCandidate {
                profile: "local-quic-v1".to_owned(),
                candidate_id: "candidate".to_owned(),
                parameters: BTreeMap::new(),
            }],
            60_000,
        )
        .expect("fixture is valid");

        assert!(PairingOfferDeadline::from_offer(&offer, u64::MAX).is_err());
    }
}
