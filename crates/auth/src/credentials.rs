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

//! Refined PIN input types.
//!
//! Raw input exists only in [`UnvalidatedSecret`]. Consuming construction
//! validates the candidate and reconstructs a fixed-capacity, role-specific
//! value. The resulting types are not `Clone`, `Copy`, serializable, or
//! raw-debuggable.

use core::fmt;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::verify::PinSlot;

/// Shortest PIN either PIN role type accepts. The card in session is the
/// authority on its PIN lengths, and the signing and login paths do not
/// read them, so [`Pin1`] and [`Pin2`] accept every length a FINEID card
/// may list: down to the PIN 1 minimum of FINEID S4-1 v4.2 section 4.1.
pub const PIN_MIN_LENGTH: usize = 4;
/// Minimum PIN1 length from FINEID S4-1 v4.2 section 4.1; the fallback
/// when the card lists no PIN 1 length.
pub const FINEID_PIN1_MIN_LENGTH: usize = 4;
/// Minimum PIN2 length from FINEID S4-1 v4.2 section 4.1; the fallback
/// when the card lists no PIN 2 length.
pub const FINEID_PIN2_MIN_LENGTH: usize = 6;
/// Stored length for both PIN roles from FINEID S4-1 v4.2 section 4.1;
/// the longest PIN either PIN role type carries.
pub const PIN_MAX_LENGTH: usize = 12;
/// Minimum PUK length from FINEID S4-1 v4.2 section 8.1.5 (EF.AOD): the
/// unblocking password is eight to twelve digits. The 7-digit preset
/// activation PIN of FINEID S4-1 v4.2 section 4.6.2 is the factory value
/// of PIN 1 and PIN 2, not the PUK, and does not unblock a PIN.
pub const PUK_MIN_LENGTH: usize = 8;
/// Maximum PUK length: the stored (padded) block length from FINEID S4-1
/// v4.2 section 8.1.5, as for the PIN roles.
pub const PUK_MAX_LENGTH: usize = 12;

/// Explicitly unvalidated secret bytes at an input boundary.
///
/// This is the only public type in this module that owns a byte vector. It
/// exists to make the raw state visible in the type system and zeroizes its
/// allocation on every exit path. It must be consumed to obtain a PIN role.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnvalidatedSecret {
    bytes: Vec<u8>,
}

impl UnvalidatedSecret {
    /// Take ownership of bytes read from a secure input surface.
    #[must_use]
    pub fn from_owned_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl fmt::Debug for UnvalidatedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnvalidatedSecret([redacted])")
    }
}

/// Credential role being reconstructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRole {
    /// PIN protecting authentication-key signing and decipher operations.
    Pin1,
    /// Qualified-signature PIN.
    Pin2,
    /// PIN Unblocking Key: resets a blocked PIN's retry counter while
    /// setting a new value. It never authorises an operation, and it
    /// spends its own counter.
    Puk,
    /// Activation PIN of either FINEID S4-1 section 4.6 scheme.
    ActivationCode,
}

impl fmt::Display for CredentialRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pin1 => f.write_str("PIN1"),
            Self::Pin2 => f.write_str("PIN2"),
            Self::Puk => f.write_str("PUK"),
            Self::ActivationCode => f.write_str("ActivationCode"),
        }
    }
}

/// Structural reason that secret input was rejected.
///
/// The error reports shape only. It never contains candidate lengths, byte
/// offsets, rejected bytes, or any credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialInputError {
    /// No bytes were supplied.
    Empty {
        /// Role that was being reconstructed.
        role: CredentialRole,
    },
    /// Candidate length was outside the role's accepted range.
    WrongLength {
        /// Role that was being reconstructed.
        role: CredentialRole,
        /// Minimum accepted digit count.
        expected_min: usize,
        /// Maximum accepted digit count.
        expected_max: usize,
    },
    /// Candidate contained a non-ASCII-digit byte.
    NonDigit {
        /// Role that was being reconstructed.
        role: CredentialRole,
    },
}

#[derive(Zeroize)]
pub(crate) struct SecretDigits {
    bytes: [u8; PIN_MAX_LENGTH],
    length: u8,
}

impl SecretDigits {
    pub(crate) fn reconstruct(
        input: UnvalidatedSecret,
        role: CredentialRole,
        minimum: usize,
        maximum: usize,
    ) -> Result<Self, CredentialInputError> {
        if input.bytes.is_empty() {
            return Err(CredentialInputError::Empty { role });
        }
        if input.bytes.len() < minimum || input.bytes.len() > maximum {
            return Err(CredentialInputError::WrongLength {
                role,
                expected_min: minimum,
                expected_max: maximum,
            });
        }
        if input.bytes.iter().any(|byte| !byte.is_ascii_digit()) {
            return Err(CredentialInputError::NonDigit { role });
        }
        let length = match u8::try_from(input.bytes.len()) {
            Ok(length) => length,
            Err(_) => {
                return Err(CredentialInputError::WrongLength {
                    role,
                    expected_min: minimum,
                    expected_max: maximum,
                });
            }
        };

        let mut reconstructed = [0_u8; PIN_MAX_LENGTH];
        reconstructed[..input.bytes.len()].copy_from_slice(&input.bytes);
        Ok(Self {
            bytes: reconstructed,
            length,
        })
    }

    pub(crate) const fn digit_count(&self) -> usize {
        self.length as usize
    }

    pub(crate) fn secret_bytes(&self) -> &[u8] {
        &self.bytes[..self.digit_count()]
    }
}

/// Validated PIN1 value.
///
/// The type deliberately does not implement `Clone`, `Copy`, serialization,
/// or a raw-byte accessor. The PIN operations consume it through a
/// crate-private, zeroizing path. A host may hold a PIN1 the card accepted
/// only in process memory, until an invalidation event, as the credential
/// custody contract says.
#[derive(ZeroizeOnDrop)]
pub struct Pin1(SecretDigits);

impl Pin1 {
    /// Consume unvalidated input and reconstruct a PIN1.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInputError`] unless the input is
    /// [`PIN_MIN_LENGTH`] through [`PIN_MAX_LENGTH`] ASCII digits.
    pub fn reconstruct(input: UnvalidatedSecret) -> Result<Self, CredentialInputError> {
        SecretDigits::reconstruct(input, CredentialRole::Pin1, PIN_MIN_LENGTH, PIN_MAX_LENGTH)
            .map(Self)
    }

    /// Number of validated digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }

    /// Borrow the validated digits for the verification command builder.
    ///
    /// This is the crate-private path the PIN operations consume PIN1
    /// through: the digits never leave this crate as raw bytes, and no
    /// public `as_bytes` accessor exists.
    pub(crate) fn digits(&self) -> &[u8] {
        self.0.secret_bytes()
    }
}

impl fmt::Debug for Pin1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin1([redacted])")
    }
}

/// Validated PIN2 value.
///
/// PIN2 is entered for every signature, or once for a batch the holder
/// sees whole, and is never held between operations (credential custody
/// contract). The type deliberately does not implement `Clone`, `Copy`,
/// serialization, or a raw-byte accessor.
#[derive(ZeroizeOnDrop)]
pub struct Pin2(SecretDigits);

impl Pin2 {
    /// Consume unvalidated input and reconstruct a PIN2.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInputError`] unless the input is
    /// [`PIN_MIN_LENGTH`] through [`PIN_MAX_LENGTH`] ASCII digits.
    pub fn reconstruct(input: UnvalidatedSecret) -> Result<Self, CredentialInputError> {
        SecretDigits::reconstruct(input, CredentialRole::Pin2, PIN_MIN_LENGTH, PIN_MAX_LENGTH)
            .map(Self)
    }

    /// Number of validated digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }

    /// Borrow the validated digits for the verification command builder.
    ///
    /// This is the crate-private path the PIN operations consume PIN2
    /// through: the digits never leave this crate as raw bytes, and no
    /// public `as_bytes` accessor exists.
    pub(crate) fn digits(&self) -> &[u8] {
        self.0.secret_bytes()
    }
}

impl fmt::Debug for Pin2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin2([redacted])")
    }
}

mod sealed {
    /// Seals [`CachedPin`] so only this crate's PIN roles can implement it.
    pub trait Sealed {}
    impl Sealed for super::Pin1 {}
    impl Sealed for super::Pin2 {}
}

/// Length of a PIN rejection fingerprint: an HMAC-SHA-256 tag, 32 bytes.
pub const CACHE_FINGERPRINT_LEN: usize = 32;
/// Length of the per-process fingerprint key, 32 bytes (256 bits).
pub const CACHE_FINGERPRINT_KEY_LEN: usize = 32;

/// Domain-separation tag bound into the fingerprint preimage for PIN1.
const SLOT_TAG_PIN1: u8 = 1;
/// Domain-separation tag bound into the fingerprint preimage for PIN2.
const SLOT_TAG_PIN2: u8 = 2;

/// A PIN role whose card rejection a negative cache may remember.
///
/// Sealed: implemented only for [`Pin1`] and [`Pin2`]. The PUK is
/// deliberately excluded -- it authorises nothing, spends its own retry
/// counter, and has no cache path.
///
/// The one digit-facing method returns a keyed *fingerprint* -- an
/// HMAC-SHA-256 tag computed here, inside the crate that owns the digits.
/// The digits are absorbed into the MAC and never handed back; a caller
/// cannot recover them from the tag. So a negative cache can live in
/// another crate, keying by this fingerprint, without any raw-digit export
/// and with no public `as_bytes` on a PIN role.
pub trait CachedPin: sealed::Sealed {
    /// The slot this PIN targets.
    #[must_use]
    fn slot(&self) -> PinSlot;

    /// The keyed fingerprint of this PIN for the card identified by
    /// `serial_bytes`, under the process-local `key`. Domain-separated so no
    /// two `(serial, slot, pin)` triples share a tag.
    #[must_use]
    fn keyed_fingerprint(
        &self,
        serial_bytes: &[u8],
        key: &[u8; CACHE_FINGERPRINT_KEY_LEN],
    ) -> [u8; CACHE_FINGERPRINT_LEN];
}

impl CachedPin for Pin1 {
    fn slot(&self) -> PinSlot {
        PinSlot::Pin1
    }

    fn keyed_fingerprint(
        &self,
        serial_bytes: &[u8],
        key: &[u8; CACHE_FINGERPRINT_KEY_LEN],
    ) -> [u8; CACHE_FINGERPRINT_LEN] {
        pin_fingerprint(SLOT_TAG_PIN1, serial_bytes, self.digits(), key)
    }
}

impl CachedPin for Pin2 {
    fn slot(&self) -> PinSlot {
        PinSlot::Pin2
    }

    fn keyed_fingerprint(
        &self,
        serial_bytes: &[u8],
        key: &[u8; CACHE_FINGERPRINT_KEY_LEN],
    ) -> [u8; CACHE_FINGERPRINT_LEN] {
        pin_fingerprint(SLOT_TAG_PIN2, serial_bytes, self.digits(), key)
    }
}

/// HMAC-SHA-256 over a domain-separated preimage so that no two distinct
/// `(serial, slot, pin)` triples share a tag: the serial length as a
/// fixed-width big-endian integer, then the serial, a slot tag, the pin
/// length, and the pin digits. Fail-closed -- if the key is somehow
/// unusable, every value collapses to one tag and is refused after the
/// first rejection, never replayed to the card.
fn pin_fingerprint(
    slot_tag: u8,
    serial_bytes: &[u8],
    digits: &[u8],
    key: &[u8; CACHE_FINGERPRINT_KEY_LEN],
) -> [u8; CACHE_FINGERPRINT_LEN] {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return [0_u8; CACHE_FINGERPRINT_LEN];
    };
    let Ok(serial_len) = u32::try_from(serial_bytes.len()) else {
        return [0_u8; CACHE_FINGERPRINT_LEN];
    };
    let Ok(pin_len) = u8::try_from(digits.len()) else {
        return [0_u8; CACHE_FINGERPRINT_LEN];
    };
    mac.update(&serial_len.to_be_bytes());
    mac.update(serial_bytes);
    mac.update(&[slot_tag]);
    mac.update(&[pin_len]);
    mac.update(digits);
    mac.finalize().into_bytes().into()
}

/// Validated PUK value.
///
/// The PUK is not a PIN: it never authorises an operation on the user's
/// behalf. It resets a blocked PIN's retry counter while setting a new
/// value (RESET RETRY COUNTER, FINEID S1 v4.2 section 3.5.4). The PUK
/// spends its own retry counter, and exhausting it is terminal for the
/// card, so every operation that presents it applies the retry floor to
/// the PUK's counter, not the target PIN's. Like the PIN roles, this type is not `Clone`, `Copy`,
/// serializable, or raw-debuggable, and there is no cache path.
#[derive(ZeroizeOnDrop)]
pub struct Puk(SecretDigits);

impl Puk {
    /// Consume unvalidated input and reconstruct a PUK.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInputError`] unless the input is
    /// [`PUK_MIN_LENGTH`] through [`PUK_MAX_LENGTH`] ASCII digits.
    pub fn reconstruct(input: UnvalidatedSecret) -> Result<Self, CredentialInputError> {
        SecretDigits::reconstruct(input, CredentialRole::Puk, PUK_MIN_LENGTH, PUK_MAX_LENGTH)
            .map(Self)
    }

    /// Number of validated digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }

    /// Borrow the validated digits for the credential-command builder.
    ///
    /// This is the crate-private path the unblock operations consume the
    /// PUK through: the digits never leave this crate as raw bytes, and no
    /// public `as_bytes` accessor exists.
    pub(crate) fn digits(&self) -> &[u8] {
        self.0.secret_bytes()
    }
}

impl fmt::Debug for Puk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Puk([redacted])")
    }
}

impl fmt::Display for CredentialInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { role } => write!(f, "{role} cannot be empty"),
            Self::WrongLength {
                role,
                expected_min,
                expected_max,
            } => write!(
                f,
                "{role} must contain {expected_min}-{expected_max} digits"
            ),
            Self::NonDigit { role } => write!(f, "{role} must contain only ASCII digits"),
        }
    }
}

impl core::error::Error for CredentialInputError {}

#[cfg(test)]
mod tests {
    use super::{
        CredentialInputError, CredentialRole, FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH,
        PIN_MIN_LENGTH, PUK_MAX_LENGTH, PUK_MIN_LENGTH, Pin1, Pin2, Puk, UnvalidatedSecret,
    };
    use zeroize::Zeroize;
    const PIN1_TOO_SHORT_LENGTH: usize = PIN_MIN_LENGTH - 1;
    const PIN2_TOO_SHORT_LENGTH: usize = PIN_MIN_LENGTH - 1;
    const TOO_LONG_LENGTH: usize = PIN_MAX_LENGTH + 1;
    const PUK_TOO_SHORT_LENGTH: usize = PUK_MIN_LENGTH - 1;
    const PUK_TOO_LONG_LENGTH: usize = PUK_MAX_LENGTH + 1;

    fn input(bytes: &[u8]) -> UnvalidatedSecret {
        UnvalidatedSecret::from_owned_bytes(bytes.to_vec())
    }

    fn digits(length: usize) -> UnvalidatedSecret {
        UnvalidatedSecret::from_owned_bytes(vec![b'7'; length])
    }

    fn non_ascii_digits(length: usize) -> UnvalidatedSecret {
        let mut bytes = vec![b'7'; length];
        let last = bytes.last_mut().expect("fixture length is non-zero");
        *last = u8::MAX;
        UnvalidatedSecret::from_owned_bytes(bytes)
    }

    #[test]
    fn role_types_reconstruct_valid_input() {
        let pin1 = Pin1::reconstruct(input(b"1234")).expect("valid PIN1 fixture");
        let pin2 = Pin2::reconstruct(input(b"123456")).expect("valid PIN2 fixture");

        assert_eq!(pin1.digit_count(), PIN_MIN_LENGTH);
        assert_eq!(pin1.0.secret_bytes(), b"1234");
        assert_eq!(pin2.digit_count(), FINEID_PIN2_MIN_LENGTH);
        assert_eq!(pin2.0.secret_bytes(), b"123456");
    }

    #[test]
    fn pin2_accepts_lengths_below_the_fineid_minimum() {
        // The card is the authority on PIN 2's length; the role type
        // accepts every length from the PIN minimum.
        for length in PIN_MIN_LENGTH..FINEID_PIN2_MIN_LENGTH {
            let pin2 = Pin2::reconstruct(digits(length)).expect("valid PIN2 fixture");
            assert_eq!(pin2.digit_count(), length);
        }
    }

    #[test]
    fn pin1_boundary_lengths_are_enforced() {
        assert!(matches!(
            Pin1::reconstruct(input(b"")),
            Err(CredentialInputError::Empty {
                role: CredentialRole::Pin1,
            })
        ));
        assert!(matches!(
            Pin1::reconstruct(digits(PIN1_TOO_SHORT_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Pin1,
                expected_min: PIN_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
            })
        ));
        assert!(Pin1::reconstruct(digits(PIN_MIN_LENGTH)).is_ok());
        assert!(Pin1::reconstruct(digits(PIN_MAX_LENGTH)).is_ok());
        assert!(matches!(
            Pin1::reconstruct(digits(TOO_LONG_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Pin1,
                expected_min: PIN_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
            })
        ));
        assert!(matches!(
            Pin1::reconstruct(non_ascii_digits(PIN_MIN_LENGTH)),
            Err(CredentialInputError::NonDigit {
                role: CredentialRole::Pin1,
            })
        ));
    }

    #[test]
    fn pin2_boundary_lengths_are_enforced() {
        assert!(matches!(
            Pin2::reconstruct(input(b"")),
            Err(CredentialInputError::Empty {
                role: CredentialRole::Pin2,
            })
        ));
        assert!(matches!(
            Pin2::reconstruct(digits(PIN2_TOO_SHORT_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Pin2,
                expected_min: PIN_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
            })
        ));
        assert!(Pin2::reconstruct(digits(PIN_MIN_LENGTH)).is_ok());
        assert!(Pin2::reconstruct(digits(PIN_MAX_LENGTH)).is_ok());
        assert!(matches!(
            Pin2::reconstruct(digits(TOO_LONG_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Pin2,
                expected_min: PIN_MIN_LENGTH,
                expected_max: PIN_MAX_LENGTH,
            })
        ));
        assert!(matches!(
            Pin2::reconstruct(non_ascii_digits(PIN_MIN_LENGTH)),
            Err(CredentialInputError::NonDigit {
                role: CredentialRole::Pin2,
            })
        ));
    }

    #[test]
    fn puk_boundary_lengths_are_enforced() {
        assert!(matches!(
            Puk::reconstruct(input(b"")),
            Err(CredentialInputError::Empty {
                role: CredentialRole::Puk,
            })
        ));
        assert!(matches!(
            Puk::reconstruct(digits(PUK_TOO_SHORT_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Puk,
                expected_min: PUK_MIN_LENGTH,
                expected_max: PUK_MAX_LENGTH,
            })
        ));
        assert!(Puk::reconstruct(digits(PUK_MIN_LENGTH)).is_ok());
        assert!(Puk::reconstruct(digits(PUK_MAX_LENGTH)).is_ok());
        assert!(matches!(
            Puk::reconstruct(digits(PUK_TOO_LONG_LENGTH)),
            Err(CredentialInputError::WrongLength {
                role: CredentialRole::Puk,
                expected_min: PUK_MIN_LENGTH,
                expected_max: PUK_MAX_LENGTH,
            })
        ));
        assert!(matches!(
            Puk::reconstruct(non_ascii_digits(PUK_MIN_LENGTH)),
            Err(CredentialInputError::NonDigit {
                role: CredentialRole::Puk,
            })
        ));
        let puk = Puk::reconstruct(digits(PUK_MAX_LENGTH)).expect("valid PUK fixture");
        assert_eq!(puk.digit_count(), PUK_MAX_LENGTH);
        assert_eq!(format!("{puk:?}"), "Puk([redacted])");
    }

    #[test]
    fn errors_never_retain_the_rejected_byte() {
        let error =
            Pin1::reconstruct(input(b"12a4")).expect_err("fixture contains a non-digit byte");
        assert_eq!(
            error,
            CredentialInputError::NonDigit {
                role: CredentialRole::Pin1,
            }
        );
    }

    #[test]
    fn debug_is_always_redacted() {
        let raw = input(b"1234");
        assert_eq!(format!("{raw:?}"), "UnvalidatedSecret([redacted])");

        let pin1 = Pin1::reconstruct(input(b"1234")).expect("valid PIN1 fixture");
        assert_eq!(format!("{pin1:?}"), "Pin1([redacted])");

        let pin2 = Pin2::reconstruct(input(b"123456")).expect("valid PIN2 fixture");
        assert_eq!(format!("{pin2:?}"), "Pin2([redacted])");

        let wrong_len =
            Pin1::reconstruct(input(b"12")).expect_err("fixture is below minimum length");
        let expected_wrong_len = format!(
            "WrongLength {{ role: Pin1, expected_min: {PIN_MIN_LENGTH}, expected_max: {PIN_MAX_LENGTH} }}"
        );
        assert_eq!(format!("{wrong_len:?}"), expected_wrong_len);

        let non_digit =
            Pin1::reconstruct(input(b"12a4")).expect_err("fixture contains a non-digit byte");
        assert_eq!(format!("{non_digit:?}"), "NonDigit { role: Pin1 }");
    }

    #[test]
    fn display_is_always_shape_only() {
        let empty = Pin1::reconstruct(input(b"")).expect_err("fixture is empty");
        assert_eq!(empty.to_string(), "PIN1 cannot be empty");

        let wrong_len =
            Pin1::reconstruct(input(b"12")).expect_err("fixture is below minimum length");
        let expected_wrong_len =
            format!("PIN1 must contain {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digits");
        assert_eq!(wrong_len.to_string(), expected_wrong_len);

        let non_digit =
            Pin1::reconstruct(input(b"12a4")).expect_err("fixture contains a non-digit byte");
        assert_eq!(non_digit.to_string(), "PIN1 must contain only ASCII digits");
    }

    #[test]
    fn unvalidated_storage_is_zeroizable() {
        let mut raw = input(b"1234");
        raw.zeroize();
        assert!(raw.bytes.iter().all(|byte| *byte == 0));
    }
}
