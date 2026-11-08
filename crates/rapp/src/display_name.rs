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

//! The name an endpoint gives itself (RAPP v26.11.8 section 4.3 item 3).

use core::fmt;

/// Most UTF-8 bytes a `display_name` or a `platform` carries (RAPP
/// v26.11.8 section 7.1, `display_name_max_bytes`).
pub const DISPLAY_NAME_MAX_BYTES: usize = 256;

/// The name an endpoint sends for itself in `pairing.hello`,
/// `session.ready` and `session.hello`, as the peer shows it and stores it
/// in the pair record (section 4.3 items 3 and 4). It is 1 to
/// [`DISPLAY_NAME_MAX_BYTES`] bytes of UTF-8 holding at least one
/// character that is not white space. A label for people: no pairing is
/// found, matched, replaced or revoked by it.
#[derive(Clone, PartialEq, Eq)]
pub struct DisplayName(String);

impl DisplayName {
    /// The name `text`, as an endpoint sends it or the peer received it.
    ///
    /// # Errors
    /// [`DisplayNameError`] when `text` is blank or longer than
    /// [`DISPLAY_NAME_MAX_BYTES`].
    pub fn parse(text: String) -> Result<Self, DisplayNameError> {
        check_label(&text)?;
        Ok(Self(text))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("DisplayName").field(&self.0).finish()
    }
}

impl From<DisplayName> for String {
    fn from(name: DisplayName) -> Self {
        name.0
    }
}

/// Why a name is not a display name, or a platform description is not one
/// (section 7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayNameError {
    /// The text is empty or holds white space alone.
    Blank,
    /// The text is longer than [`DISPLAY_NAME_MAX_BYTES`].
    TooLong,
}

impl fmt::Display for DisplayNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Blank => "the name is blank",
            Self::TooLong => "the name is longer than 256 bytes",
        })
    }
}

impl core::error::Error for DisplayNameError {}

/// The predicate `display_name` and `platform` share: 1 to
/// [`DISPLAY_NAME_MAX_BYTES`] bytes of UTF-8 holding a character that is
/// not white space (section 7.1).
pub(crate) fn check_label(text: &str) -> Result<(), DisplayNameError> {
    if text.len() > DISPLAY_NAME_MAX_BYTES {
        Err(DisplayNameError::TooLong)
    } else if text.trim().is_empty() {
        Err(DisplayNameError::Blank)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{DISPLAY_NAME_MAX_BYTES, DisplayName, DisplayNameError};

    #[test]
    fn the_bound_counts_bytes() {
        let at_bound = "a".repeat(DISPLAY_NAME_MAX_BYTES);
        assert!(DisplayName::parse(at_bound.clone()).is_ok());
        assert_eq!(
            DisplayName::parse(at_bound + "a"),
            Err(DisplayNameError::TooLong)
        );
        let two_byte_character = "\u{f6}";
        let half = DISPLAY_NAME_MAX_BYTES / two_byte_character.len();
        assert!(DisplayName::parse(two_byte_character.repeat(half)).is_ok());
        assert_eq!(
            DisplayName::parse(two_byte_character.repeat(half) + "a"),
            Err(DisplayNameError::TooLong)
        );
    }

    #[test]
    fn a_blank_name_is_refused() {
        for blank in ["", " ", " \t ", "\u{a0}"] {
            assert_eq!(
                DisplayName::parse(blank.to_owned()),
                Err(DisplayNameError::Blank),
                "{blank:?}"
            );
        }
        assert!(DisplayName::parse(" x ".to_owned()).is_ok());
    }
}
