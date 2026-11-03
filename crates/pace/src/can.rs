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

//! Refined Card Access Number input.
//!
//! A CAN is printed on the card, but it is sensitive access data because it
//! enables PACE access to the chip. Consuming construction checks the value
//! once; downstream code receives only the opaque, zeroizing [`Can`] type.
//!
//! A client may remember a CAN across sessions -- an operating-system
//! keystore under user consent is a legitimate home for this credential
//! class (see the credential-custody policy). Persistence happens upstream
//! of this border: the input surface that collected the digits stores its
//! own copy at collection time, and a keystore read is another input
//! surface whose bytes re-enter through [`UnvalidatedCan`]. A [`Can`]
//! never exports its value; past the border it flows only toward the PACE
//! handshake.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of ASCII digits in a FINEID Card Access Number for citizen cards.
///
/// ICAO Doc 9303 Part 5 section 3.2.3 specifies a six-digit numeric CAN.
pub const CAN_DIGITS: usize = 6;

/// Minimum number of ASCII digits in a FINEID Card Access Number (FINEID S1 v4.0).
pub const CAN_MIN_DIGITS: usize = 4;

/// Maximum number of ASCII digits in a FINEID Card Access Number (FINEID S1 v4.0).
pub const CAN_MAX_DIGITS: usize = 12;

/// Explicitly unvalidated, owned CAN text at an input boundary.
///
/// The wrapper must be created immediately after secure UI or terminal input.
/// It owns and zeroizes the original allocation on every exit path.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnvalidatedCan {
    text: String,
}

impl UnvalidatedCan {
    /// Take ownership of text read from an input surface.
    #[must_use]
    pub fn from_owned_text(text: String) -> Self {
        Self { text }
    }
}

impl fmt::Debug for UnvalidatedCan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnvalidatedCan([redacted])")
    }
}

/// A validated, opaque FINEID Card Access Number.
///
/// The type is deliberately non-clonable, non-copyable, zeroizing, and has no
/// public raw-value accessor. A future PACE command constructor will consume
/// it through a crate-private path.
#[derive(ZeroizeOnDrop)]
pub struct Can {
    bytes: [u8; CAN_MAX_DIGITS],
    len: u8,
}

impl fmt::Debug for Can {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Can([redacted])")
    }
}

/// Structural reason that candidate CAN input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanError {
    /// No bytes were supplied.
    Empty,
    /// The candidate did not contain between [`CAN_MIN_DIGITS`] and [`CAN_MAX_DIGITS`] bytes.
    WrongLength,
    /// The candidate contained a non-ASCII-digit byte.
    NonDigit,
}

impl Can {
    /// Consume unvalidated input and reconstruct it as a [`Can`].
    ///
    /// # Errors
    ///
    /// Returns [`CanError`] for empty, wrong-length, or non-digit input.
    pub fn reconstruct(input: UnvalidatedCan) -> Result<Self, CanError> {
        let bytes = input.text.as_bytes();
        if bytes.is_empty() {
            return Err(CanError::Empty);
        }
        if bytes.len() < CAN_MIN_DIGITS || bytes.len() > CAN_MAX_DIGITS {
            return Err(CanError::WrongLength);
        }
        if bytes.iter().any(|byte| !byte.is_ascii_digit()) {
            return Err(CanError::NonDigit);
        }

        let mut reconstructed = [0_u8; CAN_MAX_DIGITS];
        reconstructed[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: reconstructed,
            len: bytes.len() as u8,
        })
    }

    /// Number of validated CAN digits.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.len as usize
    }

    /// Borrow the validated digits for the PACE key-derivation step.
    ///
    /// This is the crate-private path the handshake consumes the CAN
    /// through: the value never leaves this crate as raw bytes, and no
    /// public `as_bytes` accessor exists.
    pub(crate) fn password_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl fmt::Display for CanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("CAN cannot be empty"),
            Self::WrongLength => {
                write!(
                    f,
                    "CAN must contain between {CAN_MIN_DIGITS} and {CAN_MAX_DIGITS} digits"
                )
            }
            Self::NonDigit => f.write_str("CAN must contain ASCII digits only"),
        }
    }
}

impl core::error::Error for CanError {}

#[cfg(test)]
mod tests {
    use super::{CAN_DIGITS, CAN_MAX_DIGITS, CAN_MIN_DIGITS, Can, CanError, UnvalidatedCan};

    fn input(text: &str) -> UnvalidatedCan {
        UnvalidatedCan::from_owned_text(text.to_owned())
    }

    #[test]
    fn valid_input_is_reconstructed_once() {
        let can = Can::reconstruct(input("123456")).expect("fixture is a valid CAN");
        assert_eq!(can.digit_count(), CAN_DIGITS);
        assert_eq!(can.password_bytes(), b"123456");
    }

    #[test]
    fn variable_lengths() {
        for valid in ["1234", "12345", "123456", "12345678", "123456789012"] {
            let can = Can::reconstruct(input(valid)).expect("valid CAN candidate");
            assert_eq!(can.digit_count(), valid.len());
            assert_eq!(can.password_bytes(), valid.as_bytes());
        }
    }

    #[test]
    fn structural_failures_are_typed() {
        assert!(matches!(Can::reconstruct(input("")), Err(CanError::Empty)));
        assert!(matches!(
            Can::reconstruct(input("123")),
            Err(CanError::WrongLength)
        ));
        assert!(matches!(
            Can::reconstruct(input("1234567890123")),
            Err(CanError::WrongLength)
        ));
        assert!(matches!(
            Can::reconstruct(input("12a456")),
            Err(CanError::NonDigit)
        ));
    }

    #[test]
    fn can_error_format_does_not_leak_candidate_length_or_offset() {
        let empty = CanError::Empty;
        assert_eq!(format!("{empty}"), "CAN cannot be empty");
        assert_eq!(format!("{empty:?}"), "Empty");

        let wrong_len = CanError::WrongLength;
        assert_eq!(
            format!("{wrong_len}"),
            format!("CAN must contain between {CAN_MIN_DIGITS} and {CAN_MAX_DIGITS} digits")
        );
        assert_eq!(format!("{wrong_len:?}"), "WrongLength");

        let non_digit = CanError::NonDigit;
        assert_eq!(format!("{non_digit}"), "CAN must contain ASCII digits only");
        assert_eq!(format!("{non_digit:?}"), "NonDigit");
    }

    #[test]
    fn every_six_digit_value_is_structurally_valid() {
        for text in ["000000", "000001", "100000", "012300", "010101"] {
            assert!(
                Can::reconstruct(input(text)).is_ok(),
                "valid six-digit candidate should be accepted"
            );
        }
    }

    #[test]
    fn debug_is_always_redacted() {
        let raw = input("123456");
        assert_eq!(format!("{raw:?}"), "UnvalidatedCan([redacted])");

        let can = Can::reconstruct(input("123456")).expect("fixture is a valid CAN");
        assert_eq!(format!("{can:?}"), "Can([redacted])");
    }
}
