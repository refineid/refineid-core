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

//! The `fi.refineid.stream.v1` transport profile's routing preamble.
//!
//! The stream profile (RAPP v26.10.9 §2.2.2) carries RAPP frames over one
//! reliable ordered byte stream, each frame behind a 2-byte big-endian
//! length. The custodian listens and the requester dials, for both pairing
//! and sessions, and the requester's first frame is the routing preamble
//! this module encodes (§2.2.1). Socket I/O and the length-prefix framing
//! live in platform adapters, never here.

use hmac::{
    Hmac,
    digest::{KeyInit, Mac},
};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::{RendezvousToken, WireValue, decode_deterministic_cbor, encode_deterministic_cbor};

/// Registered transport profile name for the stream profile.
pub const STREAM_PROFILE: &str = "fi.refineid.stream.v1";

/// Domain string opening every stream rendezvous preamble.
const STREAM_RENDEZVOUS_DOMAIN: &str = "RAPP-stream-v1";

/// Preamble purpose naming a pairing attempt.
const PURPOSE_PAIRING: &str = "pairing";

/// Preamble purpose naming a session attempt for a stored pairing.
const PURPOSE_SESSION: &str = "session";

/// HKDF-Expand info naming the discovery-hint key (hierarchy §4.3).
const DISCOVERY_HINT_INFO: &[u8] = b"RAPP-discovery-hint-v1";

/// Label opening the withdrawal-hint HMAC message, ahead of the epoch.
const WITHDRAWAL_HINT_LABEL: &[u8] = b"RAPP-withdrawal-v1";

/// The single-block counter byte of HKDF-Expand for a 32-byte output.
const HKDF_FIRST_BLOCK: u8 = 1;

/// Byte length of one published discovery hint.
pub const DISCOVERY_HINT_SIZE: usize = 8;

/// Length in seconds of one discovery-hint epoch.
pub const DISCOVERY_HINT_EPOCH_SECONDS: u64 = 900;

type HmacSha256 = Hmac<Sha256>;

/// The rotating discovery hint a custodian MAY publish for one stored
/// pairing in `epoch` = floor(unix time / 900) (hierarchy specification
/// §4.3).
///
/// `K_disc` is HKDF-Expand-SHA-256 with the 16-byte `rendezvous_token` as
/// PRK, info `"RAPP-discovery-hint-v1"`, and 32 output bytes, which is the
/// single block `HMAC-SHA-256(token, info || 0x01)`; the hint is the first 8
/// bytes of `HMAC-SHA-256(K_disc, epoch as 8-byte big-endian)`.
#[must_use]
pub fn discovery_hint(token: &RendezvousToken, epoch: u64) -> [u8; DISCOVERY_HINT_SIZE] {
    keyed_hint(token, &[], epoch)
}

/// The withdrawal hint a custodian publishes for one stored pairing when it
/// deliberately stops serving, in `epoch` = floor(unix time / 900)
/// (RAPP §4.5).
///
/// The key is the pairing's discovery-hint key `K_disc`; the hint is the
/// first 8 bytes of `HMAC-SHA-256(K_disc, "RAPP-withdrawal-v1" || epoch as
/// 8-byte big-endian)`. The label keeps it apart from the discovery hint,
/// whose message is the epoch alone.
#[must_use]
pub fn withdrawal_hint(token: &RendezvousToken, epoch: u64) -> [u8; DISCOVERY_HINT_SIZE] {
    keyed_hint(token, WITHDRAWAL_HINT_LABEL, epoch)
}

/// Whether `hint` is the withdrawal hint of `token` for `epoch` or an
/// adjacent epoch, the window a requester accepts (RAPP §4.5).
#[must_use]
pub fn withdrawal_hint_matches(
    token: &RendezvousToken,
    hint: &[u8; DISCOVERY_HINT_SIZE],
    epoch: u64,
) -> bool {
    [epoch.checked_sub(1), Some(epoch), epoch.checked_add(1)]
        .into_iter()
        .flatten()
        .fold(false, |matched, candidate| {
            matched | bool::from(withdrawal_hint(token, candidate).ct_eq(hint))
        })
}

/// First 8 bytes of `HMAC-SHA-256(K_disc, label || epoch_be64)`.
fn keyed_hint(token: &RendezvousToken, label: &[u8], epoch: u64) -> [u8; DISCOVERY_HINT_SIZE] {
    let mut expand = <HmacSha256 as KeyInit>::new_from_slice(token.as_bytes())
        .expect("HMAC accepts any key length");
    expand.update(DISCOVERY_HINT_INFO);
    expand.update(&[HKDF_FIRST_BLOCK]);
    let key = expand.finalize().into_bytes();
    let mut hint =
        <HmacSha256 as KeyInit>::new_from_slice(&key).expect("HMAC accepts any key length");
    hint.update(label);
    hint.update(&epoch.to_be_bytes());
    let digest = hint.finalize().into_bytes();
    let mut out = [0_u8; DISCOVERY_HINT_SIZE];
    out.copy_from_slice(&digest[..DISCOVERY_HINT_SIZE]);
    out
}

/// Upper bound on an encoded rendezvous preamble frame. The accepting
/// endpoint rejects a longer preamble before parsing it.
pub const MAX_STREAM_RENDEZVOUS_FRAME: usize = 64;

/// One plaintext routing preamble, the first frame the dialing requester
/// sends on a fresh stream connection.
///
/// The preamble is unauthenticated routing metadata, exactly like a relay
/// token: it selects whether the listening custodian serves its offer or
/// opens a session, and enables nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRendezvous {
    /// Connect to the listener's currently active pairing offer.
    Pairing,
    /// Connect for a fresh session with the stored pairing this token names.
    Session(RendezvousToken),
}

impl StreamRendezvous {
    /// Encode the preamble frame payload.
    ///
    /// # Errors
    /// [`StreamError::Malformed`] when deterministic encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let (purpose, token_bytes) = match self {
            Self::Pairing => (PURPOSE_PAIRING, Vec::new()),
            Self::Session(token) => (PURPOSE_SESSION, token.as_bytes().to_vec()),
        };
        encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            WireValue::Text(purpose.to_owned()),
            WireValue::Bytes(token_bytes),
        ]))
        .map_err(|_| StreamError::Malformed)
    }

    /// Decode and validate one received preamble frame payload.
    ///
    /// Every failure is pre-authentication invalid input (RAPP v26.10.9
    /// §10.1, class 1): the caller closes the connection and changes
    /// no stored state.
    ///
    /// # Errors
    /// [`StreamError`] on an oversized frame, a malformed preamble, or an
    /// unregistered purpose.
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_STREAM_RENDEZVOUS_FRAME {
            return Err(StreamError::Oversized);
        }
        let WireValue::Array(elements) =
            decode_deterministic_cbor(bytes).map_err(|_| StreamError::Malformed)?
        else {
            return Err(StreamError::Malformed);
        };
        let [
            WireValue::Text(domain),
            WireValue::Text(purpose),
            WireValue::Bytes(token_bytes),
        ] = elements.as_slice()
        else {
            return Err(StreamError::Malformed);
        };
        if domain != STREAM_RENDEZVOUS_DOMAIN {
            return Err(StreamError::Malformed);
        }
        match purpose.as_str() {
            PURPOSE_PAIRING => {
                if token_bytes.is_empty() {
                    Ok(Self::Pairing)
                } else {
                    Err(StreamError::Malformed)
                }
            }
            PURPOSE_SESSION => RendezvousToken::reconstruct(token_bytes)
                .map(Self::Session)
                .map_err(|_| StreamError::Malformed),
            _ => Err(StreamError::UnknownPurpose),
        }
    }
}

/// Rejected stream-profile bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// Structure, domain, type, or token length was not exactly as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_STREAM_RENDEZVOUS_FRAME`].
    Oversized,
    /// Purpose string is not registered; the connection closes unanswered.
    UnknownPurpose,
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for StreamError {}

#[cfg(test)]
mod tests {
    use super::super::RENDEZVOUS_TOKEN_SIZE;
    use super::*;

    fn token() -> RendezvousToken {
        RendezvousToken::from_array([0x5a; RENDEZVOUS_TOKEN_SIZE])
    }

    #[test]
    fn pairing_preamble_round_trips() {
        let encoded = StreamRendezvous::Pairing.encode().expect("encode");
        assert!(encoded.len() <= MAX_STREAM_RENDEZVOUS_FRAME);
        assert_eq!(
            StreamRendezvous::decode(&encoded).expect("decode"),
            StreamRendezvous::Pairing
        );
    }

    #[test]
    fn session_preamble_round_trips() {
        let encoded = StreamRendezvous::Session(token()).encode().expect("encode");
        assert!(encoded.len() <= MAX_STREAM_RENDEZVOUS_FRAME);
        assert_eq!(
            StreamRendezvous::decode(&encoded).expect("decode"),
            StreamRendezvous::Session(token())
        );
    }

    #[test]
    fn pairing_preamble_with_token_bytes_is_rejected() {
        let encoded = encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            WireValue::Text(PURPOSE_PAIRING.to_owned()),
            WireValue::Bytes(vec![0x01]),
        ]))
        .expect("encode");
        assert_eq!(
            StreamRendezvous::decode(&encoded),
            Err(StreamError::Malformed)
        );
    }

    #[test]
    fn session_preamble_with_short_token_is_rejected() {
        let encoded = encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            WireValue::Text(PURPOSE_SESSION.to_owned()),
            WireValue::Bytes(vec![0x01; RENDEZVOUS_TOKEN_SIZE - 1]),
        ]))
        .expect("encode");
        assert_eq!(
            StreamRendezvous::decode(&encoded),
            Err(StreamError::Malformed)
        );
    }

    #[test]
    fn unknown_purpose_is_its_own_rejection() {
        let encoded = encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            WireValue::Text("resume".to_owned()),
            WireValue::Bytes(Vec::new()),
        ]))
        .expect("encode");
        assert_eq!(
            StreamRendezvous::decode(&encoded),
            Err(StreamError::UnknownPurpose)
        );
    }

    #[test]
    fn wrong_domain_is_rejected() {
        let encoded = encode_deterministic_cbor(&WireValue::Array(vec![
            WireValue::Text("RAPP-relay-v1".to_owned()),
            WireValue::Text(PURPOSE_PAIRING.to_owned()),
            WireValue::Bytes(Vec::new()),
        ]))
        .expect("encode");
        assert_eq!(
            StreamRendezvous::decode(&encoded),
            Err(StreamError::Malformed)
        );
    }

    #[test]
    fn oversized_preamble_is_rejected_before_parsing() {
        let oversized = vec![0_u8; MAX_STREAM_RENDEZVOUS_FRAME + 1];
        assert_eq!(
            StreamRendezvous::decode(&oversized),
            Err(StreamError::Oversized)
        );
    }
}
