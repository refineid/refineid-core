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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Secret-code newtype and validation for PKCS#11 sessions.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A syntactically valid FINEID PIN: 4-12 ASCII digits.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinBytes {
    bytes: [u8; Self::MAX_LENGTH],
    length: u8,
}

impl PinBytes {
    /// Shortest code accepted by any FINEID PIN role.
    pub const MIN_LENGTH: usize = 4;
    /// Longest code accepted by any FINEID PIN role.
    pub const MAX_LENGTH: usize = 12;

    /// Validate and take ownership of `bytes`.
    ///
    /// # Errors
    /// Returns [`PinRoleError`] unless `bytes` contains 4-12 ASCII digits.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, PinRoleError> {
        if let Err(error) = validate_digits(&bytes, Self::MIN_LENGTH, Self::MAX_LENGTH) {
            bytes.zeroize();
            return Err(error);
        }
        let Ok(length) = u8::try_from(bytes.len()) else {
            bytes.zeroize();
            return Err(PinRoleError::WrongLength {
                expected_min: Self::MIN_LENGTH,
                expected_max: Self::MAX_LENGTH,
            });
        };
        let mut storage = [0_u8; Self::MAX_LENGTH];
        storage[..bytes.len()].copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self {
            bytes: storage,
            length,
        })
    }

    /// Borrow the inner bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.digit_count()]
    }

    /// Number of ASCII digits in the code.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.length as usize
    }

    /// Validate that the PIN digits fall within min and max length bounds.
    ///
    /// # Errors
    /// Returns [`PinRoleError`] if the length is outside `[min, max]`.
    pub fn validate_digits(&self, min: usize, max: usize) -> Result<(), PinRoleError> {
        validate_digits(self.as_bytes(), min, max)
    }
}

impl TryFrom<Vec<u8>> for PinBytes {
    type Error = PinRoleError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl<const N: usize> TryFrom<[u8; N]> for PinBytes {
    type Error = PinRoleError;

    fn try_from(mut bytes: [u8; N]) -> Result<Self, Self::Error> {
        if let Err(error) = validate_digits(&bytes, Self::MIN_LENGTH, Self::MAX_LENGTH) {
            bytes.zeroize();
            return Err(error);
        }
        let Ok(length) = u8::try_from(N) else {
            bytes.zeroize();
            return Err(PinRoleError::WrongLength {
                expected_min: Self::MIN_LENGTH,
                expected_max: Self::MAX_LENGTH,
            });
        };
        let mut storage = [0_u8; Self::MAX_LENGTH];
        storage[..N].copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self {
            bytes: storage,
            length,
        })
    }
}

impl fmt::Debug for PinBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinBytes([redacted])")
    }
}

/// Structural reason that PIN input was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRoleError {
    /// No bytes were supplied.
    Empty,
    /// Candidate length was outside accepted range.
    WrongLength {
        /// Minimum accepted length in digits.
        expected_min: usize,
        /// Maximum accepted length in digits.
        expected_max: usize,
    },
    /// Candidate contained a non-ASCII-digit byte.
    NonDigit,
}

impl fmt::Display for PinRoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("PIN input is empty"),
            Self::WrongLength {
                expected_min,
                expected_max,
            } => write!(
                f,
                "PIN length outside expected range [{expected_min}, {expected_max}]"
            ),
            Self::NonDigit => f.write_str("PIN must contain only ASCII digits"),
        }
    }
}

impl core::error::Error for PinRoleError {}

fn validate_digits(bytes: &[u8], min: usize, max: usize) -> Result<(), PinRoleError> {
    if bytes.is_empty() {
        return Err(PinRoleError::Empty);
    }
    if bytes.len() < min || bytes.len() > max {
        return Err(PinRoleError::WrongLength {
            expected_min: min,
            expected_max: max,
        });
    }
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(PinRoleError::NonDigit);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_role_error_debug_does_not_leak_candidate_length_or_offset() {
        let err = validate_digits(b"12", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture is below minimum length");
        let expected_debug = format!(
            "WrongLength {{ expected_min: {}, expected_max: {} }}",
            PinBytes::MIN_LENGTH,
            PinBytes::MAX_LENGTH
        );
        assert_eq!(format!("{err:?}"), expected_debug);

        let err_non_digit = validate_digits(b"12a4", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture contains a non-digit byte");
        assert_eq!(format!("{err_non_digit:?}"), "NonDigit");
    }

    #[test]
    fn pin_role_error_display_is_always_shape_only() {
        let err_empty = validate_digits(b"", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture is empty");
        assert_eq!(err_empty.to_string(), "PIN input is empty");

        let err_wrong_len = validate_digits(b"12", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture is below minimum length");
        let expected_wrong_len = format!(
            "PIN length outside expected range [{}, {}]",
            PinBytes::MIN_LENGTH,
            PinBytes::MAX_LENGTH
        );
        assert_eq!(err_wrong_len.to_string(), expected_wrong_len);

        let err_non_digit = validate_digits(b"12a4", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture contains a non-digit byte");
        assert_eq!(
            err_non_digit.to_string(),
            "PIN must contain only ASCII digits"
        );
    }
}
