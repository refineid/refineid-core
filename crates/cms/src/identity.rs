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

//! Typed X.509 subject identity values and holder-line formatting.

use core::fmt;
use core::ops::Deref;

use crate::x509::Name;

/// Maximum byte length accepted by every free-text identity newtype.
pub const FREE_TEXT_MAX_BYTES: usize = 1024;

/// Total ASCII length of a Finnish PEUIN / SATU identifier (8 digits + 1
/// checksum).
pub const PEUIN_LEN: usize = 9;
/// Number of leading ASCII digit positions in a PEUIN.
const PEUIN_DIGITS_LEN: usize = 8;
/// Zero-based index of the alphanumeric checksum character in a PEUIN.
const PEUIN_CHECKSUM_INDEX: usize = 8;

/// Token slot index for the first given name during [`GivenNamesText::split`].
const GIVEN_NAME_SLOT_FIRST: usize = 0;
/// Token slot index for the second given name during [`GivenNamesText::split`].
const GIVEN_NAME_SLOT_SECOND: usize = 1;
/// Token slot index for third-and-further given names during
/// [`GivenNamesText::split`].
const GIVEN_NAME_SLOT_ADDITIONAL: usize = 2;

/// Separator joining the holder's name to the organization on the holder line.
const ORGANIZATION_SEPARATOR: &str = ", ";

/// Construction error shared by every free-text identity newtype.
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

/// Validated non-empty, length-bounded text slice.
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

/// Helper for normalizing legacy uppercase personal names into title case.
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
    /// Normalize an uppercase or mixed-case name slot to its native
    /// title-case form.
    ///
    /// # Errors
    /// [`FreeTextError`] if `s` is empty or exceeds [`FREE_TEXT_MAX_BYTES`].
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

impl PartialEq<str> for NativeName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for NativeName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// X.509 `commonName` attribute value (X.520 `cn`, OID `2.5.4.3`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommonName(String);

impl CommonName {
    /// Construct a validated `CommonName`.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
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

/// X.509 `surName` attribute value (X.520 `sn`, OID `2.5.4.4`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Surname(String);

impl Surname {
    /// Construct a validated `Surname`.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
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

impl PartialEq<str> for Surname {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Surname {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// X.509 `organizationName` attribute value (X.520 `o`, OID `2.5.4.10`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrganizationName(String);

impl OrganizationName {
    /// Construct a validated `OrganizationName`.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the organization-name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for OrganizationName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for OrganizationName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OrganizationName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for OrganizationName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for OrganizationName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// First given name extracted from X.520 `givenName` (OID `2.5.4.42`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirstName(String);

impl FirstName {
    /// Construct a validated `FirstName`.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the first-name text.
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

impl PartialEq<str> for FirstName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for FirstName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Second given name extracted from X.520 `givenName` (OID `2.5.4.42`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecondName(String);

impl SecondName {
    /// Construct a validated `SecondName`.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the second-name text.
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

impl PartialEq<str> for SecondName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for SecondName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Third-or-further given name extracted from X.520 `givenName` (OID `2.5.4.42`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdditionalName(String);

impl AdditionalName {
    /// Construct a validated `AdditionalName`.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds [`FREE_TEXT_MAX_BYTES`].
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the additional-name text.
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

impl PartialEq<str> for AdditionalName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for AdditionalName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
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
    ///
    /// # Errors
    /// [`FreeTextError`] if `value` is empty or exceeds [`FREE_TEXT_MAX_BYTES`].
    pub fn new(value: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&value)?;
        Ok(Self(value))
    }

    /// Split into typed slots.
    #[must_use]
    pub fn split(&self) -> SplitGivenNames {
        let mut out = SplitGivenNames::default();
        let mut slot = GIVEN_NAME_SLOT_FIRST;
        for tok in self.0.split_whitespace() {
            if tok.is_empty() {
                continue;
            }
            let owned = tok.to_owned();
            match slot {
                GIVEN_NAME_SLOT_FIRST => {
                    if let Ok(name) = FirstName::new(owned) {
                        out.first = Some(name);
                        slot = GIVEN_NAME_SLOT_SECOND;
                    }
                }
                GIVEN_NAME_SLOT_SECOND => {
                    if let Ok(name) = SecondName::new(owned) {
                        out.second = Some(name);
                        slot = GIVEN_NAME_SLOT_ADDITIONAL;
                    }
                }
                _ => {
                    if let Ok(name) = AdditionalName::new(owned) {
                        out.additional.push(name);
                    }
                }
            }
        }
        out
    }
}

/// Personal Electronic Unique Identification Number (DVV `SATU` / `FINUID`)
/// from a certificate's `serialNumber` DN attribute (OID `2.5.4.5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Peuin([u8; PEUIN_LEN]);

/// Construction errors emitted by [`Peuin::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeuinError {
    /// Input was not exactly [`PEUIN_LEN`] bytes (8 ASCII digits + 1 checksum).
    WrongLength {
        /// Number of bytes given.
        got: usize,
    },
    /// One of the leading digit positions was not an ASCII digit.
    NonDigit {
        /// Zero-based byte offset where the non-digit was encountered.
        at: usize,
        /// The offending byte value.
        byte: u8,
    },
    /// The checksum character at the final position was not ASCII alphanumeric.
    BadChecksum {
        /// The offending byte value at the checksum position.
        byte: u8,
    },
}

impl fmt::Display for PeuinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { got } => write!(
                f,
                "PEUIN must be exactly {PEUIN_LEN} characters ({PEUIN_DIGITS_LEN} digits + 1 checksum), got {got}"
            ),
            Self::NonDigit { at, byte } => write!(
                f,
                "PEUIN positions 0..{PEUIN_DIGITS_LEN} must be ASCII digits; non-digit at offset {at}: {byte:#04x}"
            ),
            Self::BadChecksum { byte } => write!(
                f,
                "PEUIN checksum (position {PEUIN_CHECKSUM_INDEX}) must be ASCII alphanumeric; got {byte:#04x}"
            ),
        }
    }
}

impl core::error::Error for PeuinError {}

impl Peuin {
    /// Parse `s` as a PEUIN: 9 ASCII bytes (8 digits followed by 1
    /// alphanumeric checksum character).
    ///
    /// Only the structural shape is enforced; the check character is not
    /// recomputed against the 8-digit body because the issuing certificate
    /// authority is authoritative for the identifier value.
    ///
    /// # Errors
    /// [`PeuinError`] for wrong length, non-digit body character, or
    /// non-alphanumeric checksum character.
    pub fn new(s: &str) -> Result<Self, PeuinError> {
        let bytes = s.as_bytes();
        if bytes.len() != PEUIN_LEN {
            return Err(PeuinError::WrongLength { got: bytes.len() });
        }
        let mut buf = [0_u8; PEUIN_LEN];
        buf.copy_from_slice(bytes);
        for (i, &b) in buf.iter().take(PEUIN_DIGITS_LEN).enumerate() {
            if !b.is_ascii_digit() {
                return Err(PeuinError::NonDigit { at: i, byte: b });
            }
        }
        let checksum_byte = buf[PEUIN_CHECKSUM_INDEX];
        if !checksum_byte.is_ascii_alphanumeric() {
            return Err(PeuinError::BadChecksum {
                byte: checksum_byte,
            });
        }
        Ok(Self(buf))
    }

    /// String view of the PEUIN. Always valid UTF-8.
    ///
    /// # Panics
    /// Never under valid construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).expect("Peuin bytes are ASCII by construction")
    }

    /// Borrow the underlying 9-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PEUIN_LEN] {
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

impl PartialEq<str> for Peuin {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Peuin {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Format the holder line a window shows: the holder's name followed by
/// the organization when the certificate names one. Returns the name
/// alone when there is no organization, and empty when there is no name.
#[must_use]
pub fn holder_line(person: String, organization: Option<&OrganizationName>) -> String {
    match organization {
        Some(organization) if !person.is_empty() => {
            format!("{person}{ORGANIZATION_SEPARATOR}{organization}")
        }
        _ => person,
    }
}

/// Cardholder identity attributes extracted from an X.509 certificate's
/// subject Distinguished Name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubjectIdentity {
    /// First given name split from X.520 `givenName` (OID `2.5.4.42`).
    pub first_name: Option<FirstName>,
    /// Second given name split from X.520 `givenName`.
    pub second_name: Option<SecondName>,
    /// Third-and-further given names split from X.520 `givenName`.
    pub additional_names: Vec<AdditionalName>,
    /// X.520 `surName` (OID `2.5.4.4`).
    pub surname: Option<Surname>,
    /// Personal Electronic Unique Identification Number (`serialNumber`
    /// DN attribute, OID `2.5.4.5`).
    pub peuin: Option<Peuin>,
    /// X.520 `organizationName` (OID `2.5.4.10`) from the certificate
    /// subject.
    pub organization: Option<OrganizationName>,
}

impl SubjectIdentity {
    /// Empty subject identity. Equivalent to [`Default::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Extract a [`SubjectIdentity`] from an X.509 [`Name`].
    #[must_use]
    pub fn from_name(subject: Name<'_>) -> Self {
        let given_names = subject.given_names();
        Self {
            first_name: given_names.first,
            second_name: given_names.second,
            additional_names: given_names.additional,
            surname: subject.surname(),
            peuin: subject.peuin(),
            organization: subject.organization_name(),
        }
    }

    /// Set [`first_name`](Self::first_name) and return `self`.
    #[must_use]
    pub fn with_first_name(mut self, value: FirstName) -> Self {
        self.first_name = Some(value);
        self
    }

    /// Set [`second_name`](Self::second_name) and return `self`.
    #[must_use]
    pub fn with_second_name(mut self, value: SecondName) -> Self {
        self.second_name = Some(value);
        self
    }

    /// Append one entry to [`additional_names`](Self::additional_names).
    #[must_use]
    pub fn with_additional_name(mut self, value: AdditionalName) -> Self {
        self.additional_names.push(value);
        self
    }

    /// Replace [`additional_names`](Self::additional_names) wholesale.
    #[must_use]
    pub fn with_additional_names(mut self, values: Vec<AdditionalName>) -> Self {
        self.additional_names = values;
        self
    }

    /// Set [`surname`](Self::surname) and return `self`.
    #[must_use]
    pub fn with_surname(mut self, value: Surname) -> Self {
        self.surname = Some(value);
        self
    }

    /// Set [`organization`](Self::organization) and return `self`.
    #[must_use]
    pub fn with_organization(mut self, value: OrganizationName) -> Self {
        self.organization = Some(value);
        self
    }

    /// Set [`peuin`](Self::peuin) and return `self`.
    #[must_use]
    pub const fn with_peuin(mut self, value: Peuin) -> Self {
        self.peuin = Some(value);
        self
    }

    /// Surname and given names, space-separated, `None` fields elided.
    #[must_use]
    pub fn person_string(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if let Some(s) = self.surname.as_deref()
            && !s.is_empty()
        {
            parts.push(s);
        }
        for given in self.iter_given_names() {
            if !given.is_empty() {
                parts.push(given);
            }
        }
        parts.join(" ")
    }

    /// The holder line a window shows: [`person_string`](Self::person_string)
    /// followed by the organization when present.
    #[must_use]
    pub fn holder_line(&self) -> String {
        holder_line(self.person_string(), self.organization.as_ref())
    }

    /// Iterate every given-name slot in canonical order: first, second,
    /// then each additional name.
    pub fn iter_given_names(&self) -> impl Iterator<Item = &str> {
        self.first_name
            .as_deref()
            .into_iter()
            .chain(self.second_name.as_deref())
            .chain(self.additional_names.iter().map(AsRef::as_ref))
    }

    /// `true` when every field is `None` / empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.first_name.is_none()
            && self.second_name.is_none()
            && self.additional_names.is_empty()
            && self.surname.is_none()
            && self.peuin.is_none()
            && self.organization.is_none()
    }
}

impl fmt::Display for SubjectIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut emit = |s: &str, f: &mut fmt::Formatter<'_>| -> fmt::Result {
            if s.is_empty() {
                return Ok(());
            }
            if !first {
                f.write_str(" ")?;
            }
            f.write_str(s)?;
            first = false;
            Ok(())
        };
        if let Some(s) = self.surname.as_deref() {
            emit(s, f)?;
        }
        for given in self.iter_given_names() {
            emit(given, f)?;
        }
        if let Some(s) = self.peuin.as_deref() {
            emit(s, f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CommonName, FREE_TEXT_MAX_BYTES, FirstName, FreeTextError, GivenNamesText, NativeName,
        OrganizationName, Peuin, PeuinError, SecondName, SubjectIdentity, Surname, holder_line,
    };

    const SAMPLE_SURNAME: &str = "SPECIMEN-TRAVEL";
    const SAMPLE_GIVEN: &str = "VILMA SOFIA";
    const SAMPLE_FIRST: &str = "VILMA";
    const SAMPLE_SECOND: &str = "SOFIA";
    const SAMPLE_PEUIN: &str = "12345678X";
    const SAMPLE_ORG: &str = "Testiorganisaatio Oy";
    const SHORT_PEUIN_LEN: usize = 7;
    const NON_DIGIT_OFFSET: usize = 2;

    fn sample_identity() -> SubjectIdentity {
        SubjectIdentity::new()
            .with_surname(Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"))
            .with_first_name(
                FirstName::new(SAMPLE_FIRST.to_owned()).expect("sample first name is valid"),
            )
            .with_second_name(
                SecondName::new(SAMPLE_SECOND.to_owned()).expect("sample second name is valid"),
            )
            .with_peuin(Peuin::new(SAMPLE_PEUIN).expect("sample PEUIN is valid"))
    }

    #[test]
    fn an_organization_card_holder_line_names_the_organization() {
        let id = sample_identity().with_organization(
            OrganizationName::new(SAMPLE_ORG.to_owned()).expect("sample organization is valid"),
        );
        assert_eq!(id.person_string(), "SPECIMEN-TRAVEL VILMA SOFIA");
        assert_eq!(
            id.holder_line(),
            "SPECIMEN-TRAVEL VILMA SOFIA, Testiorganisaatio Oy"
        );
    }

    #[test]
    fn a_citizen_card_holder_line_is_the_name_alone() {
        let id = sample_identity();
        assert_eq!(id.holder_line(), id.person_string());
    }

    #[test]
    fn an_organization_without_a_name_shows_nothing() {
        let org =
            OrganizationName::new(SAMPLE_ORG.to_owned()).expect("sample organization is valid");
        assert_eq!(holder_line(String::new(), Some(&org)), "");
        let id = SubjectIdentity::new().with_organization(org);
        assert_eq!(id.holder_line(), "");
    }

    #[test]
    fn display_renders_name_and_peuin_and_skips_none_fields() {
        assert_eq!(
            format!("{}", sample_identity()),
            format!("{SAMPLE_SURNAME} {SAMPLE_GIVEN} {SAMPLE_PEUIN}")
        );
        let empty = SubjectIdentity::default();
        assert_eq!(format!("{empty}"), "");
        assert!(empty.is_empty());
    }

    #[test]
    fn peuin_validates_shape_and_characters() {
        let alpha = Peuin::new("12345678X").expect("eight digits plus alpha checksum parses");
        assert_eq!(alpha.as_str(), "12345678X");
        assert_eq!(alpha, "12345678X");
        let digit = Peuin::new("123456789").expect("digit checksum parses");
        assert_eq!(format!("{digit}"), "123456789");
        assert!(matches!(
            Peuin::new("1234567"),
            Err(PeuinError::WrongLength {
                got: SHORT_PEUIN_LEN
            })
        ));
        assert!(matches!(
            Peuin::new("12X45678Y"),
            Err(PeuinError::NonDigit {
                at: NON_DIGIT_OFFSET,
                byte: b'X'
            })
        ));
        assert!(matches!(
            Peuin::new("12345678!"),
            Err(PeuinError::BadChecksum { byte: b'!' })
        ));
    }

    #[test]
    fn free_text_and_given_name_splitting_validate_bounds() {
        assert!(matches!(
            Surname::new(String::new()),
            Err(FreeTextError::Empty)
        ));
        assert!(matches!(
            CommonName::new(String::new()),
            Err(FreeTextError::Empty)
        ));
        let overlong = FREE_TEXT_MAX_BYTES + 1;
        let huge = "a".repeat(overlong);
        assert_eq!(
            Surname::new(huge),
            Err(FreeTextError::TooLong {
                got: overlong,
                max: FREE_TEXT_MAX_BYTES
            })
        );
        let split = GivenNamesText::new("ANNA MARIA ELENA".to_owned())
            .expect("valid given names")
            .split();
        assert_eq!(split.first.as_deref(), Some("ANNA"));
        assert_eq!(split.second.as_deref(), Some("MARIA"));
        assert_eq!(split.additional.len(), 1);
        assert_eq!(split.additional[0].as_str(), "ELENA");
    }

    #[test]
    fn native_name_title_cases_hyphenated_and_spaced_segments() {
        let native =
            NativeName::from_legacy_uppercase(SAMPLE_SURNAME).expect("title-casing succeeds");
        assert_eq!(native, "Specimen-Travel");
        let surname = Surname::new(SAMPLE_SURNAME.to_owned()).expect("valid surname");
        assert_eq!(surname.to_native(), "Specimen-Travel");
    }
}
