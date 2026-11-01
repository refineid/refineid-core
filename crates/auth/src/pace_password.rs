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

//! The PACE password key of a PIN.
//!
//! The FINEID organizational cards authenticate the PACE channel with
//! PIN 1 or PIN 2 in place of the Card Access Number (FINEID S1 v4.0,
//! organizational cards, section 2.1). PACE never sends the password:
//! both sides derive `K_pi = KDF_pi(pi)` from it and the card encrypts
//! its nonce under that key (BSI TR-03110-3 sections 4.2 and A.2.3).
//! This module derives `K_pi` here, inside the crate that owns the
//! digits, so the PACE handshake receives the derived key and never the
//! PIN.
//!
//! The PIN's password encoding is its character string, each character
//! one ISO/IEC 8859-1 octet (BSI TR-03110-3 table 5 and appendix
//! D.2.1.4). The ASCII digits a validated PIN holds are their own
//! ISO/IEC 8859-1 octets, so the encoding is the validated digits as
//! they stand -- the same encoding the Card Access Number uses.

use core::fmt;

use sha2::{Digest as _, Sha256};
use zeroize::ZeroizeOnDrop;

use crate::credentials::{Pin1, Pin2};

/// Length of the PACE password key for an AES-256 mechanism: the whole
/// SHA-256 output (BSI TR-03110-3 section A.2.3.2).
pub const PACE_PASSWORD_KEY_LEN: usize = 32;

/// The 32-bit big-endian counter that selects the password key in the
/// PACE key-derivation function, `KDF_pi(pi) = KDF(f(pi), 3)` (BSI
/// TR-03110-3 section A.2.3).
const KDF_COUNTER_PASSWORD: u32 = 3;

/// `K_pi`, the AES-256 key a PACE handshake decrypts the card's nonce
/// with, derived from a PIN.
///
/// Secret custody: it determines the PIN by exhaustive search over the
/// digit space, so it is treated as the PIN itself. Not `Clone` or
/// `Copy`, zeroized on drop, redacted from every formatter, and produced
/// only by [`Pin1::pace_password_key`] and [`Pin2::pace_password_key`].
/// Its one consumer is the PACE handshake.
#[derive(ZeroizeOnDrop)]
pub struct PacePasswordKey([u8; PACE_PASSWORD_KEY_LEN]);

impl PacePasswordKey {
    /// `SHA-256(digits || 00000003)`, the key-derivation function of BSI
    /// TR-03110-3 section A.2.3 with the password counter, for an AES-256
    /// mechanism.
    fn derive(digits: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(digits);
        hasher.update(KDF_COUNTER_PASSWORD.to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Borrow the key bytes for the PACE nonce decryption.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PACE_PASSWORD_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for PacePasswordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PacePasswordKey([redacted])")
    }
}

impl Pin1 {
    /// The PACE password key for this PIN 1, for a PACE handshake that
    /// authenticates the channel with PIN 1.
    #[must_use]
    pub fn pace_password_key(&self) -> PacePasswordKey {
        PacePasswordKey::derive(self.digits())
    }
}

impl Pin2 {
    /// The PACE password key for this PIN 2, for a PACE handshake that
    /// authenticates the channel with PIN 2.
    #[must_use]
    pub fn pace_password_key(&self) -> PacePasswordKey {
        PacePasswordKey::derive(self.digits())
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::{KDF_COUNTER_PASSWORD, PacePasswordKey};
    use crate::credentials::{Pin1, Pin2, UnvalidatedSecret};

    /// A synthetic PIN.
    const PIN_TEXT: &[u8] = b"123456";
    /// A second synthetic PIN.
    const OTHER_PIN_TEXT: &[u8] = b"654321";

    fn pin1(text: &[u8]) -> Pin1 {
        Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(text.to_vec())).expect("valid PIN 1")
    }

    fn pin2(text: &[u8]) -> Pin2 {
        Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(text.to_vec())).expect("valid PIN 2")
    }

    #[test]
    fn the_key_is_sha256_of_the_digits_and_the_password_counter() {
        let mut preimage = PIN_TEXT.to_vec();
        preimage.extend_from_slice(&KDF_COUNTER_PASSWORD.to_be_bytes());
        let expected: [u8; super::PACE_PASSWORD_KEY_LEN] = Sha256::digest(&preimage).into();
        assert_eq!(pin1(PIN_TEXT).pace_password_key().as_bytes(), &expected);
    }

    #[test]
    fn both_roles_derive_the_same_key_from_the_same_digits() {
        assert_eq!(
            pin1(PIN_TEXT).pace_password_key().as_bytes(),
            pin2(PIN_TEXT).pace_password_key().as_bytes()
        );
        assert!(
            pin1(PIN_TEXT).pace_password_key().as_bytes()
                != pin1(OTHER_PIN_TEXT).pace_password_key().as_bytes()
        );
    }

    #[test]
    fn debug_is_redacted() {
        let key = pin1(PIN_TEXT).pace_password_key();
        assert_eq!(format!("{key:?}"), "PacePasswordKey([redacted])");
    }

    #[test]
    fn the_key_zeroizes_on_drop() {
        fn require_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        require_zeroize_on_drop::<PacePasswordKey>();
    }
}
