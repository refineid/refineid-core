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

//! ISO 7816-4 status word, decoded into the cases RefineID handles.
//!
//! The two trailing bytes SW1 and SW2 of every response identify how the
//! card processed the command; ISO 7816-4 section 5.1.3 lists the standard
//! values. Matching on the typed enum makes a missing case a compile-time
//! error and keeps raw comparisons out of protocol code. When a new
//! protocol layer matches on an additional status word, it gains a variant
//! here rather than a new raw literal. Unrecognised values land in
//! [`StatusWord::Other`] carrying the raw sixteen-bit value.

use core::fmt;

/// PIN or PUK retries-remaining counter, as carried by the low nibble of
/// SW2 in the counter status-word family.
///
/// ISO 7816-4 section 5.1.3 reserves the SW1-SW2 family `63 Cx` for a
/// counter from zero to fifteen provided by `x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinRetries(u8);

impl PinRetries {
    /// Largest counter value the four-bit field can carry.
    pub const MAX: u8 = 0x0F;

    /// Wrap a nibble-sized retries counter.
    ///
    /// Returns `None` above [`PinRetries::MAX`]: the value cannot have
    /// come from a counter status word.
    #[must_use]
    pub const fn from_nibble(n: u8) -> Option<Self> {
        if n > Self::MAX { None } else { Some(Self(n)) }
    }

    /// The raw counter value.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// `true` when the counter has reached zero. Cards typically emit
    /// [`StatusWord::AuthenticationBlocked`] alongside or instead of the
    /// zero-counter form, but a defensive check belongs here.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for PinRetries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Decoded ISO 7816-4 status word.
///
/// Construct via [`StatusWord::from_u16`] or [`StatusWord::from_bytes`];
/// query via the named variants or [`StatusWord::as_u16`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusWord {
    /// SW1-SW2 `69 83`: authentication method blocked. A PIN or PUK retry
    /// counter is exhausted and the credential is locked.
    AuthenticationBlocked,
    /// SW1-SW2 `63 00`: authentication or verification failed without a
    /// retry counter. Some cards emit this instead of the counter family
    /// when no per-secret counter exists.
    AuthenticationFailed,
    /// SW1-SW2 `62 82`: end of file or record reached before reading the
    /// requested number of bytes. The body up to the boundary is still
    /// valid; many callers treat this as non-fatal.
    EndOfFile,
    /// SW1-SW2 `6A 82`: file or application not found.
    FileNotFound,
    /// Any status word not modeled here. The raw value is carried
    /// verbatim so callers can surface it without losing information.
    Other(u16),
    /// SW1-SW2 `63 Cx`: PIN or PUK verification failed; `retries` carries
    /// the low nibble of SW2, the attempts remaining before the secret
    /// locks.
    PinIncorrect {
        /// Attempts remaining before the slot locks.
        retries: PinRetries,
    },
    /// SW1-SW2 `69 84`: referenced data invalidated. Typical after a PUK
    /// unblock that reset a PIN to a known weak default.
    ReferenceDataInvalidated,
    /// SW1-SW2 `6A 88`: referenced data not found; the key or PIN slot
    /// the command pointed at does not exist.
    ReferenceDataNotFound,
    /// SW1-SW2 `69 82`: security status not satisfied; a precondition
    /// such as a verified PIN was not met.
    SecurityNotSatisfied,
    /// SW1-SW2 `69 88`: secure-messaging data objects incorrect.
    SmDataObjectsIncorrect,
    /// SW1-SW2 `90 00`: normal processing, no further information.
    Success,
    /// SW1-SW2 `67 00`: wrong length; Lc or the body length does not
    /// match the command shape.
    WrongLength,
}

impl StatusWord {
    // Raw ISO 7816-4 status-word codes, each named exactly once so no
    // bare literal is compared or matched in the dispatch below. The
    // human meaning lives on the matching variant; these constants are
    // the single source of truth for the wire encoding.
    /// Wire value of [`StatusWord::Success`].
    const SW_SUCCESS: u16 = 0x9000;
    /// Wire value of [`StatusWord::EndOfFile`].
    const SW_END_OF_FILE: u16 = 0x6282;
    /// Wire value of [`StatusWord::AuthenticationFailed`].
    const SW_AUTHENTICATION_FAILED: u16 = 0x6300;
    /// Wire value of [`StatusWord::WrongLength`].
    const SW_WRONG_LENGTH: u16 = 0x6700;
    /// Wire value of [`StatusWord::SecurityNotSatisfied`].
    const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
    /// Wire value of [`StatusWord::AuthenticationBlocked`].
    const SW_AUTHENTICATION_BLOCKED: u16 = 0x6983;
    /// Wire value of [`StatusWord::ReferenceDataInvalidated`].
    const SW_REFERENCE_DATA_INVALIDATED: u16 = 0x6984;
    /// Wire value of [`StatusWord::SmDataObjectsIncorrect`].
    const SW_SM_DATA_OBJECTS_INCORRECT: u16 = 0x6988;
    /// Wire value of [`StatusWord::FileNotFound`].
    const SW_FILE_NOT_FOUND: u16 = 0x6A82;
    /// Wire value of [`StatusWord::ReferenceDataNotFound`].
    const SW_REFERENCE_DATA_NOT_FOUND: u16 = 0x6A88;
    /// Counter family prefix: a status word whose high twelve bits equal
    /// this prefix carries the remaining-retries count in the low nibble
    /// of SW2.
    const SW_PIN_COUNTER_PREFIX: u16 = 0x63C0;
    /// Mask selecting the high twelve bits, to test the counter family
    /// independently of the counter value.
    const SW_PIN_COUNTER_MASK: u16 = 0xFFF0;

    /// Re-encode to the raw sixteen-bit wire value. Inverse of
    /// [`StatusWord::from_u16`] for every variant; `Other` round-trips
    /// its carried value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::AuthenticationBlocked => Self::SW_AUTHENTICATION_BLOCKED,
            Self::AuthenticationFailed => Self::SW_AUTHENTICATION_FAILED,
            Self::EndOfFile => Self::SW_END_OF_FILE,
            Self::FileNotFound => Self::SW_FILE_NOT_FOUND,
            Self::Other(sw) => sw,
            Self::PinIncorrect { retries } => {
                let [sw1, prefix_sw2] = Self::SW_PIN_COUNTER_PREFIX.to_be_bytes();
                let sw2 = prefix_sw2 | (retries.get() & PinRetries::MAX);
                u16::from_be_bytes([sw1, sw2])
            }
            Self::ReferenceDataInvalidated => Self::SW_REFERENCE_DATA_INVALIDATED,
            Self::ReferenceDataNotFound => Self::SW_REFERENCE_DATA_NOT_FOUND,
            Self::SecurityNotSatisfied => Self::SW_SECURITY_NOT_SATISFIED,
            Self::SmDataObjectsIncorrect => Self::SW_SM_DATA_OBJECTS_INCORRECT,
            Self::Success => Self::SW_SUCCESS,
            Self::WrongLength => Self::SW_WRONG_LENGTH,
        }
    }

    /// Decode from the raw SW1, SW2 byte pair.
    #[must_use]
    pub const fn from_bytes(sw1: u8, sw2: u8) -> Self {
        Self::from_u16(u16::from_be_bytes([sw1, sw2]))
    }

    /// Decode a sixteen-bit status-word value.
    #[must_use]
    pub const fn from_u16(sw: u16) -> Self {
        match sw {
            Self::SW_SUCCESS => Self::Success,
            Self::SW_END_OF_FILE => Self::EndOfFile,
            Self::SW_AUTHENTICATION_FAILED => Self::AuthenticationFailed,
            Self::SW_WRONG_LENGTH => Self::WrongLength,
            Self::SW_SECURITY_NOT_SATISFIED => Self::SecurityNotSatisfied,
            Self::SW_AUTHENTICATION_BLOCKED => Self::AuthenticationBlocked,
            Self::SW_REFERENCE_DATA_INVALIDATED => Self::ReferenceDataInvalidated,
            Self::SW_SM_DATA_OBJECTS_INCORRECT => Self::SmDataObjectsIncorrect,
            Self::SW_FILE_NOT_FOUND => Self::FileNotFound,
            Self::SW_REFERENCE_DATA_NOT_FOUND => Self::ReferenceDataNotFound,
            counter if (counter & Self::SW_PIN_COUNTER_MASK) == Self::SW_PIN_COUNTER_PREFIX => {
                let sw2 = counter.to_be_bytes()[1];
                let nibble = sw2 & PinRetries::MAX;
                Self::PinIncorrect {
                    retries: PinRetries(nibble),
                }
            }
            other => Self::Other(other),
        }
    }

    /// `true` iff this is the success status word.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    /// Remaining PIN or PUK retries if this status word is the counter
    /// family; `None` for every other variant, including the no-counter
    /// failure and the already-blocked case.
    #[must_use]
    pub const fn pin_retries(self) -> Option<PinRetries> {
        match self {
            Self::PinIncorrect { retries } => Some(retries),
            Self::AuthenticationBlocked
            | Self::AuthenticationFailed
            | Self::EndOfFile
            | Self::FileNotFound
            | Self::Other(_)
            | Self::ReferenceDataInvalidated
            | Self::ReferenceDataNotFound
            | Self::SecurityNotSatisfied
            | Self::SmDataObjectsIncorrect
            | Self::Success
            | Self::WrongLength => None,
        }
    }
}

impl fmt::Display for StatusWord {
    /// Operator-friendly rendering: the raw hexadecimal value alongside
    /// the human label.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.as_u16();
        match *self {
            Self::AuthenticationBlocked => write!(f, "{raw:#06X} (AuthenticationBlocked)"),
            Self::AuthenticationFailed => write!(f, "{raw:#06X} (AuthenticationFailed)"),
            Self::EndOfFile => write!(f, "{raw:#06X} (EndOfFile)"),
            Self::FileNotFound => write!(f, "{raw:#06X} (FileNotFound)"),
            Self::Other(sw) => write!(f, "{sw:#06X} (Other)"),
            Self::PinIncorrect { retries } => {
                write!(f, "{raw:#06X} (PIN incorrect, {retries} retries left)")
            }
            Self::ReferenceDataInvalidated => write!(f, "{raw:#06X} (ReferenceDataInvalidated)"),
            Self::ReferenceDataNotFound => write!(f, "{raw:#06X} (ReferenceDataNotFound)"),
            Self::SecurityNotSatisfied => write!(f, "{raw:#06X} (SecurityNotSatisfied)"),
            Self::SmDataObjectsIncorrect => write!(f, "{raw:#06X} (SmDataObjectsIncorrect)"),
            Self::Success => write!(f, "{raw:#06X} (Success)"),
            Self::WrongLength => write!(f, "{raw:#06X} (WrongLength)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PinRetries, StatusWord};

    /// A status word outside the modeled set, for fall-through tests.
    const UNMODELED_SW: u16 = 0x6F00;
    /// Counter-family value with three retries remaining.
    const THREE_RETRIES_SW: u16 = 0x63C3;
    /// Retries carried by [`THREE_RETRIES_SW`].
    const THREE: u8 = 3;

    #[test]
    fn success_round_trips() {
        let sw = StatusWord::from_u16(StatusWord::SW_SUCCESS);
        assert!(matches!(sw, StatusWord::Success));
        assert!(sw.is_success());
        assert_eq!(sw.as_u16(), StatusWord::SW_SUCCESS);
    }

    #[test]
    fn pin_incorrect_carries_retries() {
        let sw = StatusWord::from_u16(THREE_RETRIES_SW);
        let three = PinRetries::from_nibble(THREE).expect("fixture fits the nibble");
        assert_eq!(sw, StatusWord::PinIncorrect { retries: three });
        assert_eq!(sw.pin_retries(), Some(three));
        assert_eq!(sw.as_u16(), THREE_RETRIES_SW);
        assert_eq!(three.get(), THREE);
        assert!(!three.is_exhausted());
    }

    #[test]
    fn zero_counter_is_distinct_from_authentication_blocked() {
        let sw = StatusWord::from_u16(StatusWord::SW_PIN_COUNTER_PREFIX);
        let zero = PinRetries::from_nibble(0).expect("zero fits the nibble");
        assert_eq!(sw, StatusWord::PinIncorrect { retries: zero });
        assert!(zero.is_exhausted());
        assert_eq!(
            StatusWord::from_u16(StatusWord::SW_AUTHENTICATION_BLOCKED),
            StatusWord::AuthenticationBlocked
        );
    }

    #[test]
    fn pin_retries_rejects_out_of_nibble_range() {
        assert!(PinRetries::from_nibble(PinRetries::MAX + 1).is_none());
        assert!(PinRetries::from_nibble(u8::MAX).is_none());
        assert_eq!(
            PinRetries::from_nibble(PinRetries::MAX).map(PinRetries::get),
            Some(PinRetries::MAX)
        );
    }

    #[test]
    fn from_bytes_matches_from_u16() {
        let [sw1, sw2] = StatusWord::SW_FILE_NOT_FOUND.to_be_bytes();
        assert_eq!(
            StatusWord::from_bytes(sw1, sw2),
            StatusWord::from_u16(StatusWord::SW_FILE_NOT_FOUND)
        );
        assert_eq!(StatusWord::from_bytes(sw1, sw2), StatusWord::FileNotFound);
    }

    #[test]
    fn unknown_sw_falls_through_to_other() {
        let sw = StatusWord::from_u16(UNMODELED_SW);
        assert_eq!(sw, StatusWord::Other(UNMODELED_SW));
        assert_eq!(sw.as_u16(), UNMODELED_SW);
        assert!(!sw.is_success());
        assert!(sw.pin_retries().is_none());
    }

    #[test]
    fn every_status_word_value_round_trips_through_u16() {
        for sw in 0..=u16::MAX {
            assert_eq!(StatusWord::from_u16(sw).as_u16(), sw);
        }
    }

    #[test]
    fn display_includes_raw_value_and_human_label() {
        let sw = StatusWord::Success;
        let rendered = format!("{sw}");
        let raw = format!("{:#06X}", sw.as_u16());
        assert!(rendered.contains(&raw));
        assert!(rendered.contains("(Success)"));

        let five = PinRetries::from_nibble(THREE).expect("fixture fits the nibble");
        let rendered = format!("{}", StatusWord::PinIncorrect { retries: five });
        assert!(rendered.contains("retries left"));
    }
}
