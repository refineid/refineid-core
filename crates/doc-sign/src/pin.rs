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

/// Local PIN policy rejection reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicyReason {
    /// PIN candidate length was outside accepted range.
    WrongLength {
        /// Minimum accepted length in digits.
        min: usize,
        /// Maximum accepted length in digits.
        max: usize,
    },
    /// PIN candidate contained a non-digit byte.
    NonDigit,
}

impl fmt::Display for PinPolicyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { min, max } => {
                write!(f, "PIN length outside accepted range [{min}, {max}]")
            }
            Self::NonDigit => f.write_str("PIN must contain only ASCII digits"),
        }
    }
}

impl core::error::Error for PinPolicyReason {}

/// Why a PIN entry produced no PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinEntryError {
    /// The holder ended the entry without a PIN.
    Cancelled,
    /// No entry could be offered: no terminal, no dialog.
    Unavailable,
    /// What was entered is not a PIN.
    NotAPin(PinRoleError),
}

impl fmt::Display for PinEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("PIN entry ended without a PIN"),
            Self::Unavailable => f.write_str("no PIN entry is available"),
            Self::NotAPin(reason) => write!(f, "PIN entry: {reason}"),
        }
    }
}

impl core::error::Error for PinEntryError {}

/// Which PIN a flow asks for (FINEID S1 v4.2 §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRole {
    /// PIN 1, which gates the authentication key.
    Pin1,
    /// PIN 2, which gates the qualified-signature key.
    Pin2,
}

/// Where a signing flow gets the PIN, at the moment it is needed:
/// after the card is found, checked and its retry counter served,
/// right before VERIFY.
pub trait PinSource {
    /// The PIN for `role`, asked for now unless the source already
    /// holds that PIN.
    ///
    /// # Errors
    /// [`PinEntryError`] when the entry produced no PIN.
    fn pin(&mut self, role: PinRole) -> Result<&PinBytes, PinEntryError>;

    /// The PIN [`Self::pin`] gave did not end in a signature -- the card
    /// refused it, the card changed, or the flow failed before or after
    /// VERIFY; a source that keeps it forgets it, so a later use asks
    /// again.
    fn forget(&mut self);
}

/// A [`PinSource`] that runs its prompt at first use and gives the
/// answer to every later use for the same [`PinRole`] until a use does
/// not end in a signature: a run signing several documents asks once
/// and presents the same PIN to each VERIFY. A request for the other
/// role forgets the held PIN and asks again. A failed prompt is not
/// remembered. The PIN is held in memory only and zeroizes when this
/// drops or is forgotten.
pub struct PromptedPin<F> {
    prompt: F,
    answer: Option<(PinRole, PinBytes)>,
}

impl<F> PromptedPin<F>
where
    F: FnMut(PinRole) -> Result<PinBytes, PinEntryError>,
{
    /// A source that asks `prompt` for a role's PIN when it is first
    /// needed.
    #[must_use]
    pub const fn new(prompt: F) -> Self {
        Self {
            prompt,
            answer: None,
        }
    }
}

impl<F> PinSource for PromptedPin<F>
where
    F: FnMut(PinRole) -> Result<PinBytes, PinEntryError>,
{
    fn pin(&mut self, role: PinRole) -> Result<&PinBytes, PinEntryError> {
        if self.answer.as_ref().is_none_or(|(held, _)| *held != role) {
            self.answer = None;
            self.answer = Some((role, (self.prompt)(role)?));
        }
        self.answer
            .as_ref()
            .map(|(_, pin)| pin)
            .ok_or(PinEntryError::Unavailable)
    }

    fn forget(&mut self) {
        self.answer = None;
    }
}

impl<F> fmt::Debug for PromptedPin<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PromptedPin([redacted])")
    }
}

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

    /// A synthetic PIN in the shape every PIN role accepts.
    const SYNTHETIC_PIN: &[u8] = b"123456";

    /// A boxed PIN prompt.
    type Prompt = Box<dyn FnMut(PinRole) -> Result<PinBytes, PinEntryError>>;

    fn counting() -> (PromptedPin<Prompt>, std::rc::Rc<core::cell::Cell<usize>>) {
        let asked = std::rc::Rc::new(core::cell::Cell::new(0));
        let counter = std::rc::Rc::clone(&asked);
        let source = PromptedPin::new(Box::new(move |_role| {
            counter.set(counter.get() + 1);
            PinBytes::new(SYNTHETIC_PIN.to_vec()).map_err(PinEntryError::NotAPin)
        }) as Prompt);
        (source, asked)
    }

    #[test]
    fn a_prompted_pin_asks_only_when_needed_and_then_once() {
        let (mut source, asked) = counting();
        assert_eq!(asked.get(), 0, "nothing asked before use");
        assert_eq!(
            source.pin(PinRole::Pin2).map(PinBytes::as_bytes),
            Ok(SYNTHETIC_PIN)
        );
        assert_eq!(
            source.pin(PinRole::Pin2).map(PinBytes::as_bytes),
            Ok(SYNTHETIC_PIN)
        );
        assert_eq!(asked.get(), 1, "asked once for every use");
    }

    #[test]
    fn a_forgotten_pin_is_asked_again() {
        let (mut source, asked) = counting();
        assert!(source.pin(PinRole::Pin2).is_ok());
        source.forget();
        assert!(source.pin(PinRole::Pin2).is_ok());
        assert_eq!(asked.get(), 2, "asked again after the card refused it");
    }

    #[test]
    fn a_held_pin_is_never_given_for_the_other_role() {
        let roles = std::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
        let seen = std::rc::Rc::clone(&roles);
        let mut source = PromptedPin::new(move |role| {
            seen.borrow_mut().push(role);
            PinBytes::new(SYNTHETIC_PIN.to_vec()).map_err(PinEntryError::NotAPin)
        });
        assert!(source.pin(PinRole::Pin2).is_ok());
        assert!(source.pin(PinRole::Pin1).is_ok());
        assert!(source.pin(PinRole::Pin1).is_ok());
        assert_eq!(
            *roles.borrow(),
            vec![PinRole::Pin2, PinRole::Pin1],
            "the other role is asked for, the same role is not"
        );
    }

    #[test]
    fn a_failed_prompt_is_not_remembered() {
        let mut attempts = 0;
        let mut source = PromptedPin::new(move |_role| {
            attempts += 1;
            if attempts == 1 {
                Err(PinEntryError::Cancelled)
            } else {
                PinBytes::new(SYNTHETIC_PIN.to_vec()).map_err(PinEntryError::NotAPin)
            }
        });
        assert_eq!(
            source.pin(PinRole::Pin2).err(),
            Some(PinEntryError::Cancelled)
        );
        assert_eq!(
            source.pin(PinRole::Pin2).map(PinBytes::as_bytes),
            Ok(SYNTHETIC_PIN)
        );
        assert_eq!(format!("{source:?}"), "PromptedPin([redacted])");
    }
}
