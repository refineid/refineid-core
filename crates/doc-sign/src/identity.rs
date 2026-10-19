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

//! Minimal identity types for document signing and verification.

use core::fmt;
use core::ops::Deref;

pub use crate::email::EmailAddress;

#[cfg(feature = "pcsc")]
pub use refineid_pkcs15::{TokenSerial, render_token_serial};

/// Serial number of an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertSerial(Vec<u8>);

impl CertSerial {
    /// Wrap a byte iterator into a certificate serial number.
    #[must_use]
    pub fn from_bytes<I>(bytes: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        Self(bytes.into_iter().collect())
    }

    /// Borrow the raw integer content bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for CertSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Subject common name extracted from an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommonName(String);

impl CommonName {
    /// Wrap a string as a common name.
    #[must_use]
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Borrow the common name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for CommonName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CommonName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommonName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for CommonName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for CommonName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Construction error shared by free-text identity newtypes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeTextError {
    /// Input was zero bytes.
    Empty,
    /// Input exceeded the per-field byte budget.
    TooLong {
        /// Length of the rejected input in UTF-8 bytes.
        got: usize,
        /// The per-field byte cap that was breached.
        max: usize,
    },
}

impl fmt::Display for FreeTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("free-text value cannot be empty"),
            Self::TooLong { got, max } => {
                write!(f, "free-text length {got} bytes exceeds maximum {max}")
            }
        }
    }
}

impl core::error::Error for FreeTextError {}

/// Maximum byte length accepted by free-text newtypes (1024 bytes).
pub const FREE_TEXT_MAX_BYTES: usize = 1024;

struct FreeText<'a> {
    value: &'a str,
}

impl<'a> FreeText<'a> {
    const fn parse(value: &'a str) -> Result<Self, FreeTextError> {
        if value.is_empty() {
            return Err(FreeTextError::Empty);
        }
        if value.len() > FREE_TEXT_MAX_BYTES {
            return Err(FreeTextError::TooLong {
                got: value.len(),
                max: FREE_TEXT_MAX_BYTES,
            });
        }
        Ok(Self { value })
    }
}

struct LegacyUppercaseName<'a> {
    source: FreeText<'a>,
}

impl<'a> LegacyUppercaseName<'a> {
    const fn from_validated(source: FreeText<'a>) -> Self {
        Self { source }
    }

    fn parse(source: &'a str) -> Result<Self, FreeTextError> {
        Ok(Self {
            source: FreeText::parse(source)?,
        })
    }

    fn title_case_segments(&self) -> String {
        let s = self.source.value;
        let mut out = String::with_capacity(s.len());
        let mut at_segment_start = true;
        for c in s.chars() {
            if c.is_whitespace() || c == '-' {
                out.push(c);
                at_segment_start = true;
            } else if at_segment_start {
                for upper in c.to_uppercase() {
                    out.push(upper);
                }
                at_segment_start = false;
            } else {
                for lower in c.to_lowercase() {
                    out.push(lower);
                }
            }
        }
        out
    }
}

/// Personal name in its case-normalized title-case form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeName(String);

impl NativeName {
    /// Normalize an uppercase/mixed-case name slot to its native title-case form.
    pub fn from_legacy_uppercase(s: &str) -> Result<Self, FreeTextError> {
        let source = LegacyUppercaseName::parse(s)?;
        Ok(Self(source.title_case_segments()))
    }

    /// Borrow the title-cased native name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for NativeName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for NativeName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NativeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Subject surname extracted from an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Surname(String);

impl Surname {
    /// Construct a new validated `Surname`.
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the surname text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render this `Surname` as its case-normalized [`NativeName`].
    #[must_use]
    pub fn to_native(&self) -> NativeName {
        NativeName(
            LegacyUppercaseName::from_validated(FreeText { value: &self.0 }).title_case_segments(),
        )
    }
}

impl Deref for Surname {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Surname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Surname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// First given name extracted from an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirstName(String);

impl FirstName {
    /// Construct a new validated `FirstName`.
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the first name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render as case-normalized [`NativeName`].
    #[must_use]
    pub fn to_native(&self) -> NativeName {
        NativeName(
            LegacyUppercaseName::from_validated(FreeText { value: &self.0 }).title_case_segments(),
        )
    }
}

impl Deref for FirstName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for FirstName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FirstName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Second given name extracted from an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecondName(String);

impl SecondName {
    /// Construct a new validated `SecondName`.
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the second name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render as case-normalized [`NativeName`].
    #[must_use]
    pub fn to_native(&self) -> NativeName {
        NativeName(
            LegacyUppercaseName::from_validated(FreeText { value: &self.0 }).title_case_segments(),
        )
    }
}

impl Deref for SecondName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SecondName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecondName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Additional given name extracted from an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdditionalName(String);

impl AdditionalName {
    /// Construct a new validated `AdditionalName`.
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the additional name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render as case-normalized [`NativeName`].
    #[must_use]
    pub fn to_native(&self) -> NativeName {
        NativeName(
            LegacyUppercaseName::from_validated(FreeText { value: &self.0 }).title_case_segments(),
        )
    }
}

impl Deref for AdditionalName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AdditionalName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AdditionalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Given names structured into typed slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SplitGivenNames {
    /// First given name; `None` when the source attribute had no tokens.
    pub first: Option<FirstName>,
    /// Second given name when the source attribute had at least two tokens.
    pub second: Option<SecondName>,
    /// Third and subsequent given names, one per token in source order.
    pub additional: Vec<AdditionalName>,
}

/// Validated source text containing one or more given-name tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GivenNamesText(String);

impl GivenNamesText {
    /// Validate raw given-name text before splitting.
    pub fn new(value: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&value)?;
        Ok(Self(value))
    }

    /// Split into typed slots.
    #[must_use]
    pub fn split(&self) -> SplitGivenNames {
        let mut out = SplitGivenNames::default();
        let mut slot = 0_usize;
        for tok in self.0.split_whitespace() {
            if tok.is_empty() {
                continue;
            }
            let owned = tok.to_owned();
            match slot {
                0 => {
                    if let Ok(n) = FirstName::new(owned) {
                        out.first = Some(n);
                        slot = 1;
                    }
                }
                1 => {
                    if let Ok(n) = SecondName::new(owned) {
                        out.second = Some(n);
                        slot = 2;
                    }
                }
                _ => {
                    if let Ok(n) = AdditionalName::new(owned) {
                        out.additional.push(n);
                    }
                }
            }
        }
        out
    }
}

/// PEUIN / SATU identifier from a certificate's `serialNumber` DN attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Peuin([u8; 9]);

/// Construction errors emitted by `Peuin::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeuinError {
    /// Input was not exactly 9 bytes (8 digits + 1 checksum).
    WrongLength {
        /// Number of bytes given.
        got: usize,
    },
    /// One of positions 0..8 was not an ASCII digit.
    NonDigit {
        /// Byte offset where the non-digit was encountered.
        at: usize,
        /// The byte value.
        byte: u8,
    },
    /// Position 8 was not ASCII alphanumeric.
    BadChecksum {
        /// The byte value at position 8.
        byte: u8,
    },
}

impl fmt::Display for PeuinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { got } => write!(
                f,
                "PEUIN must be exactly 9 characters (8 digits + 1 checksum), got {got}"
            ),
            Self::NonDigit { at, byte } => write!(
                f,
                "PEUIN positions 0..8 must be ASCII digits; non-digit at offset {at}: {byte:#04x}"
            ),
            Self::BadChecksum { byte } => write!(
                f,
                "PEUIN checksum (position 8) must be ASCII alphanumeric; got {byte:#04x}"
            ),
        }
    }
}

impl core::error::Error for PeuinError {}

impl Peuin {
    /// Parse `s` as a PEUIN (9 ASCII bytes: 8 digits followed by 1 alphanumeric checksum).
    pub fn new(s: &str) -> Result<Self, PeuinError> {
        let bytes = s.as_bytes();
        if bytes.len() != 9 {
            return Err(PeuinError::WrongLength { got: bytes.len() });
        }
        let mut buf = [0_u8; 9];
        buf.copy_from_slice(bytes);
        for (i, &b) in buf.iter().take(8).enumerate() {
            if !b.is_ascii_digit() {
                return Err(PeuinError::NonDigit { at: i, byte: b });
            }
        }
        let checksum_byte = buf[8];
        if !checksum_byte.is_ascii_alphanumeric() {
            return Err(PeuinError::BadChecksum {
                byte: checksum_byte,
            });
        }
        Ok(Self(buf))
    }

    /// String view of the PEUIN. Always valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        #[expect(
            clippy::expect_used,
            reason = "Peuin::new accepts only ASCII alphanumerics, which are always valid UTF-8"
        )]
        core::str::from_utf8(&self.0).expect("Peuin bytes are ASCII by construction")
    }

    /// Borrow the underlying 9-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 9] {
        &self.0
    }
}

impl Deref for Peuin {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for Peuin {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Peuin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
