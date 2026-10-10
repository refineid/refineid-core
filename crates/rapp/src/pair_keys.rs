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

//! Keys both endpoints of a pairing derive from its static X25519 agreement
//! (RAPP v26.10.10 §4.3).
//!
//! The agreement never crosses the wire, so a value keyed by it identifies
//! the pairing only to its two endpoints. Each use takes its own HKDF info
//! label.

use curve25519_dalek::{montgomery::MontgomeryPoint, traits::Identity};
use hmac::{
    Hmac,
    digest::{KeyInit, Mac},
};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{PairId, X25519_KEY_SIZE};

/// Byte length of every key derived from the static agreement.
pub const PAIR_KEY_SIZE: usize = 32;

/// The single-block counter byte of HKDF-Expand for a 32-byte output.
const HKDF_FIRST_BLOCK: u8 = 1;

type HmacSha256 = Hmac<Sha256>;

/// The static agreement is the identity point, so no key exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DegenerateAgreement;

impl core::fmt::Display for DegenerateAgreement {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("static agreement is the identity point")
    }
}

impl core::error::Error for DegenerateAgreement {}

/// `HKDF-SHA-256(salt = pair_id, IKM = X25519(local static private, peer
/// static public), info, L = 32)`.
///
/// # Errors
/// [`DegenerateAgreement`] when the agreement is the identity point.
pub fn derive_pair_key(
    pair_id: PairId,
    local_static_private: &[u8; X25519_KEY_SIZE],
    remote_static_public: &[u8; X25519_KEY_SIZE],
    info: &[u8],
) -> Result<Zeroizing<[u8; PAIR_KEY_SIZE]>, DegenerateAgreement> {
    let agreement = MontgomeryPoint(*remote_static_public).mul_clamped(*local_static_private);
    if agreement == MontgomeryPoint::identity() {
        return Err(DegenerateAgreement);
    }
    let shared = Zeroizing::new(agreement.0);
    let mut extract = <HmacSha256 as KeyInit>::new_from_slice(pair_id.as_bytes())
        .expect("HMAC accepts any key length");
    extract.update(shared.as_slice());
    let mut prk = Zeroizing::new([0_u8; PAIR_KEY_SIZE]);
    prk.copy_from_slice(&extract.finalize().into_bytes());
    let mut expand = <HmacSha256 as KeyInit>::new_from_slice(prk.as_slice())
        .expect("HMAC accepts any key length");
    expand.update(info);
    expand.update(&[HKDF_FIRST_BLOCK]);
    let mut key = Zeroizing::new([0_u8; PAIR_KEY_SIZE]);
    key.copy_from_slice(&expand.finalize().into_bytes());
    Ok(key)
}

/// `HMAC-SHA-256(key, message parts)`, the full 32-byte output.
pub fn mac(key: &[u8; PAIR_KEY_SIZE], parts: &[&[u8]]) -> [u8; PAIR_KEY_SIZE] {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
