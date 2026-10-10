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

//! The routing preamble every connection opens with, on both transport
//! profiles (RAPP v26.10.10 §2.2.1), and the stream profile's name.
//!
//! The stream profile (§2.2.2) carries RAPP frames over one reliable ordered
//! byte stream, each frame behind a 2-byte big-endian length. Socket I/O and
//! the length-prefix framing live in platform adapters, never here.

use super::{
    SESSION_ROUTING_SIZE, SessionRouting, TransportProfile, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor,
};

/// Registered transport profile name for the stream profile.
pub const STREAM_PROFILE: &str = "fi.refineid.stream.v1";

/// Preamble purpose naming a pairing attempt.
const PURPOSE_PAIRING: &str = "pairing";

/// Preamble purpose naming a session attempt for a stored pairing.
const PURPOSE_SESSION: &str = "session";

/// Upper bound on an encoded routing preamble frame. The accepting
/// endpoint rejects a longer preamble before parsing it.
pub const MAX_ROUTING_PREAMBLE_FRAME: usize = 64;

/// One plaintext routing preamble, the first frame the requester sends on
/// a fresh connection.
///
/// The preamble is unauthenticated routing metadata: it selects whether the
/// custodian serves its offer or opens a session, and enables nothing else.
/// A session preamble's routing value is fresh per dial and keyed by the
/// pairing's static agreement, so it names the pairing only to its custodian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPreamble {
    /// Connect to the custodian's currently active pairing offer.
    Pairing,
    /// Connect for a fresh session with the stored pairing that keyed this
    /// routing value.
    Session(SessionRouting),
}

impl RoutingPreamble {
    /// Encode the preamble frame payload for `profile`.
    ///
    /// # Errors
    /// [`PreambleError::Malformed`] when deterministic encoding fails.
    pub fn encode(&self, profile: TransportProfile) -> Result<Vec<u8>, PreambleError> {
        let (purpose, routing) = match self {
            Self::Pairing => (PURPOSE_PAIRING, Vec::new()),
            Self::Session(routing) => (PURPOSE_SESSION, routing.to_bytes().to_vec()),
        };
        encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(profile.preamble_domain().to_owned()),
            WireValue::Text(purpose.to_owned()),
            WireValue::Bytes(routing),
        ]))
        .map_err(|_| PreambleError::Malformed)
    }

    /// Decode and validate one preamble frame payload received on `profile`.
    ///
    /// Every failure is pre-authentication invalid input (§10.1, class 1):
    /// the caller closes the connection and changes no stored state.
    ///
    /// # Errors
    /// [`PreambleError`] on an oversized frame, a malformed preamble, another
    /// profile's domain, or an unregistered purpose.
    pub fn decode(profile: TransportProfile, bytes: &[u8]) -> Result<Self, PreambleError> {
        if bytes.len() > MAX_ROUTING_PREAMBLE_FRAME {
            return Err(PreambleError::Oversized);
        }
        let WireValue::Array(elements) =
            decode_deterministic_cbor(bytes).map_err(|_| PreambleError::Malformed)?
        else {
            return Err(PreambleError::Malformed);
        };
        let [
            WireValue::Text(domain),
            WireValue::Text(purpose),
            WireValue::Bytes(routing),
        ] = elements.as_slice()
        else {
            return Err(PreambleError::Malformed);
        };
        if domain != profile.preamble_domain() {
            return Err(PreambleError::Malformed);
        }
        match purpose.as_str() {
            PURPOSE_PAIRING => {
                if routing.is_empty() {
                    Ok(Self::Pairing)
                } else {
                    Err(PreambleError::Malformed)
                }
            }
            PURPOSE_SESSION => SessionRouting::from_bytes(routing)
                .filter(|_| routing.len() == SESSION_ROUTING_SIZE)
                .map(Self::Session)
                .ok_or(PreambleError::Malformed),
            _ => Err(PreambleError::UnknownPurpose),
        }
    }
}

/// Rejected routing preamble bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreambleError {
    /// Structure, domain, type, or routing length was not exactly as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_ROUTING_PREAMBLE_FRAME`].
    Oversized,
    /// Purpose string is not registered; the connection closes unanswered.
    UnknownPurpose,
}

impl core::fmt::Display for PreambleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for PreambleError {}

#[cfg(test)]
mod tests {
    use super::super::{RandomUnavailable, RoutingKey, X25519_KEY_SIZE};
    use super::*;

    const PRIVATE_BYTE: u8 = 0x11;
    const PEER_BYTE: u8 = 0x22;
    const PAIR_BYTE: u8 = 0x33;
    const NONCE_BYTE: u8 = 0x44;

    fn routing() -> SessionRouting {
        let peer = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(
            [PEER_BYTE; X25519_KEY_SIZE],
        )
        .to_bytes();
        RoutingKey::from_parts(
            super::super::PairId::from_array([PAIR_BYTE; super::super::PAIR_ID_SIZE]),
            &[PRIVATE_BYTE; X25519_KEY_SIZE],
            &peer,
        )
        .expect("key")
        .route(
            TransportProfile::Stream,
            |bytes| -> Result<(), RandomUnavailable> {
                bytes.fill(NONCE_BYTE);
                Ok(())
            },
        )
        .expect("route")
    }

    fn preamble(domain: &str, purpose: &str, routing: Vec<u8>) -> Vec<u8> {
        encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(domain.to_owned()),
            WireValue::Text(purpose.to_owned()),
            WireValue::Bytes(routing),
        ]))
        .expect("encode")
    }

    #[test]
    fn pairing_preamble_round_trips_on_both_profiles() {
        for profile in [TransportProfile::Ble, TransportProfile::Stream] {
            let encoded = RoutingPreamble::Pairing.encode(profile).expect("encode");
            assert!(encoded.len() <= MAX_ROUTING_PREAMBLE_FRAME);
            assert_eq!(
                RoutingPreamble::decode(profile, &encoded),
                Ok(RoutingPreamble::Pairing)
            );
        }
    }

    #[test]
    fn session_preamble_round_trips_within_the_frame_bound() {
        for profile in [TransportProfile::Ble, TransportProfile::Stream] {
            let encoded = RoutingPreamble::Session(routing())
                .encode(profile)
                .expect("encode");
            assert!(encoded.len() <= MAX_ROUTING_PREAMBLE_FRAME);
            assert_eq!(
                RoutingPreamble::decode(profile, &encoded),
                Ok(RoutingPreamble::Session(routing()))
            );
        }
    }

    #[test]
    fn another_profiles_domain_is_rejected() {
        let encoded = RoutingPreamble::Pairing
            .encode(TransportProfile::Ble)
            .expect("encode");
        assert_eq!(
            RoutingPreamble::decode(TransportProfile::Stream, &encoded),
            Err(PreambleError::Malformed)
        );
    }

    #[test]
    fn pairing_preamble_with_routing_bytes_is_rejected() {
        let encoded = preamble(
            TransportProfile::Stream.preamble_domain(),
            PURPOSE_PAIRING,
            routing().to_bytes().to_vec(),
        );
        assert_eq!(
            RoutingPreamble::decode(TransportProfile::Stream, &encoded),
            Err(PreambleError::Malformed)
        );
    }

    #[test]
    fn session_preamble_with_short_routing_is_rejected() {
        let mut short = routing().to_bytes().to_vec();
        short.pop();
        let encoded = preamble(
            TransportProfile::Stream.preamble_domain(),
            PURPOSE_SESSION,
            short,
        );
        assert_eq!(
            RoutingPreamble::decode(TransportProfile::Stream, &encoded),
            Err(PreambleError::Malformed)
        );
    }

    #[test]
    fn unknown_purpose_is_its_own_rejection() {
        let encoded = preamble(
            TransportProfile::Stream.preamble_domain(),
            "resume",
            Vec::new(),
        );
        assert_eq!(
            RoutingPreamble::decode(TransportProfile::Stream, &encoded),
            Err(PreambleError::UnknownPurpose)
        );
    }

    #[test]
    fn oversized_preamble_is_rejected_before_parsing() {
        let oversized = vec![0_u8; MAX_ROUTING_PREAMBLE_FRAME + 1];
        assert_eq!(
            RoutingPreamble::decode(TransportProfile::Stream, &oversized),
            Err(PreambleError::Oversized)
        );
    }
}
