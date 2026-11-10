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

//! Compact JWE in the one shape the SCS transaction uses: direct
//! encryption with A256GCM under the transaction key agreed at `begin`
//! (DVV SCS specification v1.3; RFC 7516).
//!
//! The protected header is the additional authenticated data, the key
//! segment stays empty (direct encryption), the IV is 96 bits and the
//! tag 128, all base64url.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::base64;
use crate::error::TransactionError;
use crate::values;

/// The fixed protected header for `alg=dir`, `enc=A256GCM`, already
/// base64url.
const PROTECTED_HEADER: &str = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0";

/// Decrypt a compact JWE under `key`.
pub fn decrypt(
    compact: &[u8],
    key: &[u8; values::TRANSACTION_KEY_LENGTH],
) -> Result<Vec<u8>, TransactionError> {
    let text = core::str::from_utf8(compact)
        .map_err(|_| TransactionError::bad_request("JWE body is not UTF-8"))?;
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != values::JWE_SEGMENT_COUNT || !parts[1].is_empty() {
        return Err(TransactionError::bad_request(
            "execute transaction must be compact direct-encryption JWE",
        ));
    }
    let header_data = base64::decode_url(parts[0])
        .map_err(|_| TransactionError::bad_request("JWE must use alg=dir and enc=A256GCM"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_data)
        .map_err(|_| TransactionError::bad_request("JWE must use alg=dir and enc=A256GCM"))?;
    let direct = header.get("alg").and_then(serde_json::Value::as_str) == Some("dir")
        && header.get("enc").and_then(serde_json::Value::as_str) == Some("A256GCM");
    if !direct {
        return Err(TransactionError::bad_request(
            "JWE must use alg=dir and enc=A256GCM",
        ));
    }
    let initialization_vector = base64::decode_url(parts[values::JWE_INITIALIZATION_VECTOR_INDEX])
        .map_err(|_| TransactionError::bad_request("JWE IV must be 96 bits of base64url"))?;
    if initialization_vector.len() != values::JWE_INITIALIZATION_VECTOR_LENGTH {
        return Err(TransactionError::bad_request(
            "JWE IV must be 96 bits of base64url",
        ));
    }
    let ciphertext = base64::decode_url(parts[values::JWE_CIPHERTEXT_INDEX])
        .map_err(|_| TransactionError::bad_request("JWE ciphertext is not base64url"))?;
    let tag = base64::decode_url(parts[values::JWE_TAG_INDEX]).map_err(|_| {
        TransactionError::bad_request("JWE authentication tag must be 128 bits of base64url")
    })?;
    if tag.len() != values::JWE_TAG_LENGTH {
        return Err(TransactionError::bad_request(
            "JWE authentication tag must be 128 bits of base64url",
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| TransactionError::internal_error("open transaction envelope"))?;
    let nonce = Nonce::from_slice(&initialization_vector);
    let mut combined = ciphertext;
    combined.extend_from_slice(&tag);
    let payload = aes_gcm::aead::Payload {
        msg: &combined,
        aad: parts[0].as_bytes(),
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| TransactionError::forbidden("JWE authentication failed"))
}

/// Encrypt `plaintext` under `key` into a compact JWE.
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; values::TRANSACTION_KEY_LENGTH],
) -> Result<String, TransactionError> {
    let mut initialization_vector = [0_u8; values::JWE_INITIALIZATION_VECTOR_LENGTH];
    getrandom::fill(&mut initialization_vector)
        .map_err(|_| TransactionError::internal_error("encrypt transaction response"))?;
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| TransactionError::internal_error("encrypt transaction response"))?;
    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad: PROTECTED_HEADER.as_bytes(),
    };
    let sealed = cipher
        .encrypt(Nonce::from_slice(&initialization_vector), payload)
        .map_err(|_| TransactionError::internal_error("encrypt transaction response"))?;
    let split = sealed
        .len()
        .checked_sub(values::JWE_TAG_LENGTH)
        .ok_or_else(|| TransactionError::internal_error("encrypt transaction response"))?;
    let (ciphertext, tag) = sealed.split_at(split);
    Ok(PROTECTED_HEADER.to_owned()
        + ".."
        + &base64::encode_url(&initialization_vector)
        + "."
        + &base64::encode_url(ciphertext)
        + "."
        + &base64::encode_url(tag))
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};
    use crate::values;

    /// A fixed transaction key for the round-trip.
    const KEY: [u8; values::TRANSACTION_KEY_LENGTH] = *b"0123456789abcdef0123456789abcdef";

    /// Flips the key's first octet for the wrong-key refusal.
    const KEY_FLIP_MASK: u8 = 0x01;

    /// Encrypt then decrypt returns the plaintext.
    #[test]
    fn round_trip() {
        let sealed = encrypt(b"execute me", &KEY).expect("encrypts");
        assert_eq!(
            decrypt(sealed.as_bytes(), &KEY).as_deref(),
            Ok(b"execute me".as_slice())
        );
    }

    /// A tampered envelope is refused, and the wrong key with it.
    #[test]
    fn tampered_envelope_is_refused() {
        let sealed = encrypt(b"execute me", &KEY).expect("encrypts");
        let mut tampered = sealed.clone();
        tampered.push('A');
        assert!(decrypt(tampered.as_bytes(), &KEY).is_err());
        let mut wrong = KEY;
        wrong[0] ^= KEY_FLIP_MASK;
        assert!(decrypt(sealed.as_bytes(), &wrong).is_err());
    }

    /// Malformed envelopes name their defect.
    #[test]
    fn malformed_envelopes_are_refused() {
        assert!(decrypt(b"a.b.c", &KEY).is_err());
        assert!(decrypt(b"e30.e30.e30.e30.e30", &KEY).is_err());
    }
}
