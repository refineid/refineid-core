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

//! ISO/IEC 7816-4 and ISO/IEC 7816-15 / PKCS#15 v1.1 directory parsers.
//!
//! A standards-compliant smart card publishes its application inventory
//! in EF.DIR (ISO/IEC 7816-4 section 8.2.1.2), its PKCS#15 object
//! directory files in EF.ODF (PKCS#15 v1.1 section 6.2), its
//! certificates in EF.CDF (section 6.6), its private keys in EF.PrKDF
//! (section 6.3), and its authentication objects in EF.AOD (section
//! 6.8). Parsing these structures at the card boundary lets higher
//! layers discover application AIDs, certificate paths, key references,
//! and PIN parameters directly from the card rather than hardcoding
//! card-generation layouts.
//!
//! Nothing in this module transmits APDUs; every type here sits at the
//! pure parsing border between a confirmed file read and card-profile
//! decisions.

use core::fmt;

use refineid_apdu::{Aid, FileId};
use refineid_ber::{
    BerTag, BerTlvAny, BitString, Boolean, Integer, OctetString, PrintableString, Sequence,
    Utf8String,
};

use crate::aod::PasswordObject;

/// EF.DIR, the ISO/IEC 7816-4 section 8.2.1.2 application directory
/// directly under the MF.
pub const EF_DIR_FID: FileId = FileId::from_u16(0x2F00);

/// EF.ODF, the ISO/IEC 7816-15 / PKCS#15 v1.1 section 5.5 Object
/// Directory File under a PKCS#15 application.
pub const EF_ODF_FID: FileId = FileId::from_u16(0x5031);

/// Application label published in EF.DIR tag 50 by Estonian eID cards
/// (GED24035).
pub const ESTONIAN_EID_APPLICATION_LABEL: &str = "Estonian eID";

/// Universal DER tag of a SEQUENCE (ITU-T X.690 table 1).
const TAG_SEQUENCE: u16 = <Sequence as BerTag>::TAG;
/// Universal DER tag of an OCTET STRING (ITU-T X.690 table 1).
const TAG_OCTET_STRING: u16 = <OctetString as BerTag>::TAG;
/// Universal DER tag of an INTEGER (ITU-T X.690 table 1).
const TAG_INTEGER: u16 = <Integer as BerTag>::TAG;
/// Universal DER tag of a BOOLEAN (ITU-T X.690 table 1).
const TAG_BOOLEAN: u16 = <Boolean as BerTag>::TAG;
/// Universal DER tag of a BIT STRING (ITU-T X.690 table 1).
const TAG_BIT_STRING: u16 = <BitString as BerTag>::TAG;
/// Universal DER tag of a `UTF8String` (ITU-T X.690 table 1).
const TAG_UTF8_STRING: u16 = <Utf8String as BerTag>::TAG;
/// Universal DER tag of a `PrintableString` (ITU-T X.690 table 1;
/// PKCS#15 v1.1 section 6.1.3).
const TAG_PRINTABLE_STRING: u16 = <PrintableString as BerTag>::TAG;

/// First byte of a DER SEQUENCE (ITU-T X.690 table 1).
const DER_SEQUENCE_TAG_OCTET: u8 = 0x30;
/// Bit 8 of a DER length octet announcing the long form (ITU-T X.690
/// section 8.1.3).
const LONG_FORM_MASK: u8 = 0x80;
/// Low seven bits of a long-form length octet carrying the length-octet
/// count.
const LENGTH_COUNT_MASK: u8 = 0x7F;
/// Indefinite-length marker forbidden by DER (ITU-T X.690 section 10.1).
const INDEFINITE_LENGTH: u8 = 0x80;
/// End-of-contents / zero padding octet (ITU-T X.690 section 8.1.5).
const END_OF_CONTENTS_OCTET: u8 = 0x00;
/// Padding octet FF permitted alongside 00 between or after BER-TLV
/// records in EF.DIR (ISO/IEC 7816-4 section 5.2.2.1).
const PADDING_FF_OCTET: u8 = 0xFF;
/// Maximum length octets a DER certificate file may carry here.
const MAXIMUM_DER_LENGTH_OCTETS: usize = 2;
/// Tag octet plus the first length octet of a DER SEQUENCE.
const TAG_AND_LENGTH_OCTETS: usize = 2;

/// Maximum DER INTEGER octets for an unsigned 32-bit PKCS#15 path
/// index or length: four magnitude octets plus one optional leading
/// zero octet.
const MAXIMUM_U32_INTEGER_OCTETS: usize = 5;

/// PKCS#15 v1.1 section 6.1.5: `Path.length [0] INTEGER` under
/// `IMPLICIT TAGS`.
const TAG_PATH_LENGTH: u16 = 0x80;

/// PKCS#15 v1.1 section 6.2: the context-specific constructed tags of
/// `PKCS15Objects` records inside EF.ODF.
const TAG_PRIVATE_KEYS: u8 = 0xA0;
const TAG_PUBLIC_KEYS: u8 = 0xA1;
const TAG_TRUSTED_PUBLIC_KEYS: u8 = 0xA2;
const TAG_SECRET_KEYS: u8 = 0xA3;
const TAG_CERTIFICATES: u8 = 0xA4;
const TAG_TRUSTED_CERTIFICATES: u8 = 0xA5;
const TAG_USEFUL_CERTIFICATES: u8 = 0xA6;
const TAG_DATA_OBJECTS: u8 = 0xA7;
const TAG_AUTH_OBJECTS: u8 = 0xA8;

/// PKCS#15 v1.1 section 6.1.7: the non-path `PathOrObjects` choices.
const TAG_OBJECTS: u8 = 0xA0;
const TAG_INDIRECT_PROTECTED: u8 = 0xA1;
const TAG_DIRECT_PROTECTED: u8 = 0xA2;

/// Class and constructed bits of a context-specific constructed tag.
const CONTEXT_CONSTRUCTED_MASK: u8 = 0xE0;
const CONTEXT_CONSTRUCTED_VALUE: u8 = 0xA0;

/// PKCS#15 v1.1 section 6.3.1: tagged non-RSA `PrivateKeyType` choices.
const TAG_PRIVATE_EC_KEY: u8 = 0xA0;
const TAG_PRIVATE_KEA_KEY: u8 = 0xA3;

/// PKCS#15 v1.1 section 6.6.1: tagged non-X.509 `CertificateType`
/// choices.
const TAG_X509_ATTRIBUTE_CERTIFICATE: u8 = 0xA0;
const TAG_CV_CERTIFICATE: u8 = 0xA5;

/// PKCS#15 v1.1 section 6.1.13: optional `subClassAttributes [0]`.
const TAG_SUB_CLASS_ATTRIBUTES: u16 = 0xA0;
/// PKCS#15 v1.1 section 6.1.13: required `typeAttributes [1]`.
const TAG_TYPE_ATTRIBUTES: u16 = 0xA1;

/// PKCS#15 v1.1 section 6.1.5: non-path `ObjectValue` choices.
const TAG_DIRECT_OBJECT_VALUE: u8 = 0xA0;
const TAG_INDIRECT_PROTECTED_OBJECT_VALUE: u8 = 0xA1;
const TAG_DIRECT_PROTECTED_OBJECT_VALUE: u8 = 0xA2;

/// PKCS#15 v1.1 sections 6.1.2, 6.3.1 and 6.6.1: maximum identifier and
/// label lengths.
pub(crate) const MAXIMUM_IDENTIFIER_OCTETS: usize = 255;
const MAXIMUM_LABEL_OCTETS: usize = 255;

/// PKCS#15 v1.1 section 6.1.9: a key reference is an INTEGER in 0..=255
/// (at most two octets in minimal DER, including a leading zero octet).
const MAXIMUM_REFERENCE_OCTETS: usize = 2;

/// High bit of a DER INTEGER's leading content octet (sign bit, ITU-T
/// X.690 section 8.3.1).
const INTEGER_SIGN_MASK: u8 = 0x80;
/// Bits per octet.
const OCTET_BITS: u32 = 8;
/// Maximum unused-bit count in a DER/BER BIT STRING (ITU-T X.690
/// section 8.6.2.2).
const MAXIMUM_BIT_STRING_UNUSED: u8 = 7;
/// Mask for bit 0 (the most-significant bit) in one BIT STRING octet.
const BIT_STRING_MSB_MASK: u8 = 0x80;
/// Least-significant bit base used to mask trailing unused BIT STRING
/// bits (ITU-T X.690 section 8.6.2.2).
const BIT_STRING_LSB_MASK: u8 = 0x01;

/// Bit positions in PKCS#15 v1.1 section 6.1.9 `KeyUsageFlags`.
const KEY_USAGE_DECRYPT_BIT: usize = 1;
const KEY_USAGE_SIGN_BIT: usize = 2;
const KEY_USAGE_DERIVE_BIT: usize = 8;
const KEY_USAGE_NON_REPUDIATION_BIT: usize = 9;

/// ISO/IEC 7816-4 table 100: EF.DIR application template (tag 61) and
/// its entries: AID (tag 4F), label (tag 50), and path (tag 51).
const TAG_APPLICATION_TEMPLATE: u16 = 0x61;
const TAG_APPLICATION_IDENTIFIER: u16 = 0x4F;
const TAG_APPLICATION_LABEL: u16 = 0x50;
const TAG_APPLICATION_PATH: u16 = 0x51;

/// Read bit `bit_index` from a validated BER BIT STRING content slice
/// (`[unused_bits, octets...]`, ITU-T X.690 section 8.6.2).
///
/// Returns `None` when the BIT STRING header itself is malformed:
/// empty content, `unused_bits > 7`, non-zero `unused_bits` with no
/// data octets, or non-zero trailing unused bits in the final octet
/// (ITU-T X.690 section 8.6.2.2).
pub(crate) fn validate_bit_string(content: &[u8]) -> Option<(u8, &[u8])> {
    let (&unused_bits, octets) = content.split_first()?;
    if unused_bits > MAXIMUM_BIT_STRING_UNUSED {
        return None;
    }
    if octets.is_empty() && unused_bits != 0 {
        return None;
    }
    if unused_bits != 0 {
        let &last = octets.last()?;
        let unused_mask = (BIT_STRING_LSB_MASK << unused_bits).wrapping_sub(BIT_STRING_LSB_MASK);
        if last & unused_mask != 0 {
            return None;
        }
    }
    Some((unused_bits, octets))
}

/// Bits per octet as `usize`, for BIT STRING bit indexing.
const BITS_PER_OCTET: usize = 8;

/// Whether `bit_index` is present and set inside a validated BIT STRING
/// `(unused_bits, octets)`.
pub(crate) fn bit_string_flag(unused_bits: u8, octets: &[u8], bit_index: usize) -> bool {
    let total_bits = octets
        .len()
        .saturating_mul(BITS_PER_OCTET)
        .saturating_sub(usize::from(unused_bits));
    if bit_index >= total_bits {
        return false;
    }
    let byte_index = bit_index / BITS_PER_OCTET;
    let bit_offset = bit_index % BITS_PER_OCTET;
    let Some(&octet) = octets.get(byte_index) else {
        return false;
    };
    let mask = BIT_STRING_MSB_MASK >> bit_offset;
    octet & mask != 0
}

/// Whether a read reached the end of the file the card reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEnd {
    /// The card reported the end of the file.
    Confirmed,
    /// The read stopped at a cap before the card reported end of file.
    Incomplete,
}

impl fmt::Display for FileEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Confirmed => f.write_str("complete"),
            Self::Incomplete => f.write_str("incomplete"),
        }
    }
}

/// A transparent file's octets paired with the card's end-of-file
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileContent {
    bytes: Vec<u8>,
    end: FileEnd,
}

impl FileContent {
    /// Wrap the octets a READ BINARY loop returned and its end report.
    #[must_use]
    pub const fn from_read(bytes: Vec<u8>, end: FileEnd) -> Self {
        Self { bytes, end }
    }

    /// Number of octets read.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the read returned no octets.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The octets the read returned.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper and return the raw octets.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Whether the card confirmed end of file.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        matches!(self.end, FileEnd::Confirmed)
    }

    /// The card's end report for this read.
    #[must_use]
    pub const fn end(&self) -> FileEnd {
        self.end
    }

    /// Apply an optional PKCS#15 `Path` byte window `(index, length)`.
    ///
    /// When `slice` is `None`, returns `Some(self)` unchanged. When
    /// `slice` is `Some(window)`, demands a confirmed read whose
    /// `index..index + length` range lies completely inside the file.
    #[must_use]
    pub fn apply_path_slice(self, slice: Option<PathSlice>) -> Option<Self> {
        let Some(window) = slice else {
            return Some(self);
        };
        if !self.is_confirmed() {
            return None;
        }
        let start = usize::try_from(window.index()).ok()?;
        let length = usize::try_from(window.length()).ok()?;
        let end = start.checked_add(length)?;
        let range = self.bytes.get(start..end)?;
        Some(Self::from_read(range.to_vec(), FileEnd::Confirmed))
    }
}

/// One certificate file proven to be a confirmed read of exactly one
/// complete DER SEQUENCE (ITU-T X.690 section 10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerCertificate {
    bytes: Vec<u8>,
}

/// Outcome of validating a certificate file read at the border.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateRead {
    /// Confirmed EOF and exactly one complete DER SEQUENCE.
    Complete(DerCertificate),
    /// The read stopped before the card confirmed end of file.
    Incomplete,
    /// The octets were not exactly one complete DER SEQUENCE.
    NotOneObject,
}

impl DerCertificate {
    /// Validate a certificate read: requires confirmed EOF and exact
    /// single-SEQUENCE DER framing with no trailing octets.
    #[must_use]
    pub fn of(content: FileContent) -> CertificateRead {
        if !content.is_confirmed() {
            return CertificateRead::Incomplete;
        }
        let bytes = content.bytes;
        match der_sequence_total(&bytes) {
            Some(total) if total == bytes.len() => CertificateRead::Complete(Self { bytes }),
            _ => CertificateRead::NotOneObject,
        }
    }

    /// Number of octets in the DER certificate.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false for a valid DER SEQUENCE; paired with [`Self::len`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow the complete DER octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the wrapper and take the complete DER octets.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Total octets of the single minimal-length DER SEQUENCE at the start
/// of `bytes`, or `None` on wrong tag, truncation, indefinite length,
/// non-minimal length, or overflow.
fn der_sequence_total(bytes: &[u8]) -> Option<usize> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != DER_SEQUENCE_TAG_OCTET {
        return None;
    }
    let (&first, after_first) = rest.split_first()?;
    if first < LONG_FORM_MASK {
        return TAG_AND_LENGTH_OCTETS.checked_add(usize::from(first));
    }
    if first == INDEFINITE_LENGTH {
        return None;
    }
    let count = usize::from(first & LENGTH_COUNT_MASK);
    if count > MAXIMUM_DER_LENGTH_OCTETS {
        return None;
    }
    let length_octets = after_first.get(..count)?;
    if length_octets.first() == Some(&END_OF_CONTENTS_OCTET) {
        return None;
    }
    let mut content = 0_usize;
    for octet in length_octets {
        content = content
            .checked_shl(OCTET_BITS)?
            .checked_add(usize::from(*octet))?;
    }
    if content < usize::from(LONG_FORM_MASK) {
        return None;
    }
    TAG_AND_LENGTH_OCTETS
        .checked_add(count)?
        .checked_add(content)
}

/// A non-empty application label carried in EF.DIR tag 50.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationLabel(String);

/// Construction error when an application label string is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyApplicationLabel;

impl fmt::Display for EmptyApplicationLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("application label cannot be empty")
    }
}

impl core::error::Error for EmptyApplicationLabel {}

impl ApplicationLabel {
    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ApplicationLabel {
    type Error = EmptyApplicationLabel;

    fn try_from(label: &str) -> Result<Self, Self::Error> {
        if label.is_empty() {
            Err(EmptyApplicationLabel)
        } else {
            Ok(Self(label.to_owned()))
        }
    }
}

/// One parsed application template from EF.DIR (ISO/IEC 7816-4 section
/// 8.2.1.2, table 100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationDirectoryEntry {
    label: Option<ApplicationLabel>,
    identifier: Aid,
    path: Option<Pkcs15Path>,
}

impl ApplicationDirectoryEntry {
    /// The display label (tag 50), when published.
    #[must_use]
    pub const fn label(&self) -> Option<&ApplicationLabel> {
        self.label.as_ref()
    }

    /// The application identifier (tag 4F), validated to ISO/IEC 7816-5
    /// bounds.
    #[must_use]
    pub const fn identifier(&self) -> &Aid {
        &self.identifier
    }

    /// The optional path (tag 51) published by the template.
    #[must_use]
    pub const fn path(&self) -> Option<&Pkcs15Path> {
        self.path.as_ref()
    }
}

/// Outcome of parsing an EF.DIR file read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationDirectoryRead {
    /// Confirmed EOF and every application template framed and
    /// validated.
    Parsed(ApplicationDirectory),
    /// The read stopped before the card confirmed end of file.
    Incomplete,
    /// The octets did not frame as valid EF.DIR application templates
    /// or carried an invalid AID, label, or path.
    Malformed,
}

/// Outcome of looking up an application label in EF.DIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryLookup {
    /// No entry carries the requested label.
    Absent,
    /// More than one entry carries the requested label.
    Ambiguous,
    /// Exactly one entry carries the requested label and names this
    /// AID.
    Identified(Aid),
}

/// EF.DIR: the card's application directory, parsed and validated at
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationDirectory {
    entries: Vec<ApplicationDirectoryEntry>,
}

impl ApplicationDirectory {
    /// Validate a confirmed EF.DIR read.
    #[must_use]
    pub fn of(content: FileContent) -> ApplicationDirectoryRead {
        let FileContent { bytes, end } = content;
        if !matches!(end, FileEnd::Confirmed) {
            return ApplicationDirectoryRead::Incomplete;
        }
        parse_application_directory(&bytes).map_or(ApplicationDirectoryRead::Malformed, |entries| {
            ApplicationDirectoryRead::Parsed(Self { entries })
        })
    }

    /// Every application template published by the card, in file order.
    #[must_use]
    pub fn entries(&self) -> &[ApplicationDirectoryEntry] {
        &self.entries
    }

    /// Look up the AID published under `label`. Multiple matching
    /// entries answer [`DirectoryLookup::Ambiguous`] instead of picking
    /// the first.
    #[must_use]
    pub fn identifier_labelled(&self, label: &ApplicationLabel) -> DirectoryLookup {
        let mut matching = self
            .entries
            .iter()
            .filter(|entry| entry.label.as_ref() == Some(label));
        let Some(first) = matching.next() else {
            return DirectoryLookup::Absent;
        };
        if matching.next().is_some() {
            return DirectoryLookup::Ambiguous;
        }
        DirectoryLookup::Identified(first.identifier.clone())
    }
}

/// Parse an EF.DIR body as tag 61 application templates, skipping 00
/// and FF padding octets between or after templates (ISO/IEC 7816-4
/// section 5.2.2.1).
fn parse_application_directory(bytes: &[u8]) -> Option<Vec<ApplicationDirectoryEntry>> {
    let mut entries = Vec::new();
    let mut rest = bytes;
    while let Some(&first) = rest.first() {
        if first == END_OF_CONTENTS_OCTET || first == PADDING_FF_OCTET {
            rest = rest.get(1..)?;
            continue;
        }
        let template = BerTlvAny::parse(rest).ok()?;
        if template.tag() != TAG_APPLICATION_TEMPLATE {
            return None;
        }
        entries.push(parse_application_template(template.value())?);
        rest = rest.get(template.size()..)?;
    }
    Some(entries)
}

/// Parse one tag 61 application template. Demands exactly one valid 4F
/// AID, at most one valid UTF-8 50 label, and at most one valid 51
/// path.
fn parse_application_template(template: &[u8]) -> Option<ApplicationDirectoryEntry> {
    let children = tlvs(template)?;
    let mut identifier: Option<Aid> = None;
    let mut label: Option<ApplicationLabel> = None;
    let mut path: Option<Pkcs15Path> = None;
    let mut saw_label = false;
    let mut saw_path = false;
    for child in children {
        if child.tag() == TAG_APPLICATION_IDENTIFIER {
            if identifier.is_some() {
                return None;
            }
            identifier = Some(Aid::from_slice(child.value()).ok()?);
        } else if child.tag() == TAG_APPLICATION_LABEL {
            if saw_label {
                return None;
            }
            saw_label = true;
            if !child.value().is_empty() {
                let text = core::str::from_utf8(child.value()).ok()?;
                label = Some(ApplicationLabel::try_from(text).ok()?);
            }
        } else if child.tag() == TAG_APPLICATION_PATH {
            if saw_path {
                return None;
            }
            saw_path = true;
            if !child.value().is_empty() {
                path = Some(pkcs15_path_from_octets(child.value(), None)?);
            }
        }
    }
    Some(ApplicationDirectoryEntry {
        label,
        identifier: identifier?,
        path,
    })
}

/// One object class EF.ODF can name (PKCS#15 v1.1 section 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectClass {
    /// Private keys (EF.PrKDF).
    PrivateKeys,
    /// Public keys (EF.PuKDF).
    PublicKeys,
    /// Trusted public keys (EF.PuKDF-trusted).
    TrustedPublicKeys,
    /// Secret keys (EF.SKDF).
    SecretKeys,
    /// End-entity certificates (EF.CDF).
    Certificates,
    /// Trusted CA certificates (EF.CDF-trusted).
    TrustedCertificates,
    /// Useful CA / intermediate certificates (EF.CDF-useful).
    UsefulCertificates,
    /// Data objects (EF.DODF).
    DataObjects,
    /// Authentication objects (EF.AOD).
    AuthObjects,
}

impl ObjectClass {
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            TAG_PRIVATE_KEYS => Some(Self::PrivateKeys),
            TAG_PUBLIC_KEYS => Some(Self::PublicKeys),
            TAG_TRUSTED_PUBLIC_KEYS => Some(Self::TrustedPublicKeys),
            TAG_SECRET_KEYS => Some(Self::SecretKeys),
            TAG_CERTIFICATES => Some(Self::Certificates),
            TAG_TRUSTED_CERTIFICATES => Some(Self::TrustedCertificates),
            TAG_USEFUL_CERTIFICATES => Some(Self::UsefulCertificates),
            TAG_DATA_OBJECTS => Some(Self::DataObjects),
            TAG_AUTH_OBJECTS => Some(Self::AuthObjects),
            _ => None,
        }
    }

    /// Human-readable label for diagnostics and errors.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PrivateKeys => "private keys",
            Self::PublicKeys => "public keys",
            Self::TrustedPublicKeys => "trusted public keys",
            Self::SecretKeys => "secret keys",
            Self::Certificates => "certificates",
            Self::TrustedCertificates => "trusted certificates",
            Self::UsefulCertificates => "useful certificates",
            Self::DataObjects => "data objects",
            Self::AuthObjects => "authentication objects",
        }
    }
}

/// Optional byte window `(index, length)` inside the target file of a
/// PKCS#15 `Path` (v1.1 section 6.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSlice {
    index: u32,
    length: u32,
}

impl PathSlice {
    /// Byte offset inside the target elementary file.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Byte count of the object slice inside the target elementary file.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }
}

/// A non-empty PKCS#15 `Path` (v1.1 section 6.1.5): ordered two-byte
/// file identifiers plus an optional `(index, length)` byte slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkcs15Path {
    steps: Vec<FileId>,
    file: FileId,
    slice: Option<PathSlice>,
}

impl Pkcs15Path {
    /// Every two-byte file identifier in path order. Non-empty by
    /// construction.
    #[must_use]
    pub fn steps(&self) -> &[FileId] {
        &self.steps
    }

    /// Leading directory identifiers before [`Self::file`], if any.
    #[must_use]
    pub fn parents(&self) -> &[FileId] {
        self.steps.split_last().map_or(&[], |(_, parents)| parents)
    }

    /// Trailing target file identifier.
    #[must_use]
    pub const fn file(&self) -> FileId {
        self.file
    }

    /// Whether the path starts at the Master File (`FileId::MF`).
    #[must_use]
    pub fn is_absolute_from_mf(&self) -> bool {
        self.steps.first() == Some(&FileId::MF)
    }

    /// Optional `(index, length)` byte window within [`Self::file`].
    #[must_use]
    pub const fn slice(&self) -> Option<PathSlice> {
        self.slice
    }
}

/// Where one EF.ODF record says its objects live (PKCS#15 v1.1 section
/// 6.1.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectDirectoryLocation {
    /// Plain directory file named by its full PKCS#15 path.
    File(Pkcs15Path),
    /// Objects encoded inline in the EF.ODF record itself.
    Inline,
    /// Objects enveloped / protected rather than stored in a plain
    /// directory file.
    Protected,
}

/// One EF.ODF record pairing an [`ObjectClass`] with its location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDirectoryEntry {
    class: ObjectClass,
    location: ObjectDirectoryLocation,
}

impl ObjectDirectoryEntry {
    /// The object class this record names.
    #[must_use]
    pub const fn class(&self) -> ObjectClass {
        self.class
    }

    /// Where this record places the class's objects.
    #[must_use]
    pub const fn location(&self) -> &ObjectDirectoryLocation {
        &self.location
    }
}

/// Outcome of parsing an EF.ODF file read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectDirectoryRead {
    /// Confirmed EOF and every record framed.
    Parsed(ObjectDirectory),
    /// The read stopped before the card confirmed end of file.
    Incomplete,
    /// The octets were not a valid record-oriented `PKCS15Objects`
    /// sequence.
    Malformed,
}

/// EF.ODF: the PKCS#15 Object Directory File, in card order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectDirectory {
    entries: Vec<ObjectDirectoryEntry>,
}

impl ObjectDirectory {
    /// Validate a confirmed EF.ODF read.
    #[must_use]
    pub fn of(content: FileContent) -> ObjectDirectoryRead {
        let FileContent { bytes, end } = content;
        if !matches!(end, FileEnd::Confirmed) {
            return ObjectDirectoryRead::Incomplete;
        }
        parse_object_directory(&bytes).map_or(ObjectDirectoryRead::Malformed, |entries| {
            ObjectDirectoryRead::Parsed(Self { entries })
        })
    }

    /// Every recognized record published in EF.ODF, in file order.
    #[must_use]
    pub fn entries(&self) -> &[ObjectDirectoryEntry] {
        &self.entries
    }

    /// Every plain file path published for `class`, in file order.
    ///
    /// Returns `None` if `class` has no entries or if any entry for
    /// `class` uses an inline or protected location that cannot be read
    /// as a plain directory file (so callers never silently miss
    /// records stored in an unreadable location).
    #[must_use]
    pub fn plain_file_paths(&self, class: ObjectClass) -> Option<Vec<&Pkcs15Path>> {
        let mut paths = Vec::new();
        for entry in &self.entries {
            if entry.class != class {
                continue;
            }
            match &entry.location {
                ObjectDirectoryLocation::File(path) => paths.push(path),
                ObjectDirectoryLocation::Inline | ObjectDirectoryLocation::Protected => {
                    return None;
                }
            }
        }
        (!paths.is_empty()).then_some(paths)
    }
}

fn parse_object_directory(bytes: &[u8]) -> Option<Vec<ObjectDirectoryEntry>> {
    let mut entries = Vec::new();
    let mut rest = bytes;
    while let Some(&first) = rest.first() {
        if first == END_OF_CONTENTS_OCTET || first == PADDING_FF_OCTET {
            if rest.iter().all(|&octet| octet == first) {
                break;
            }
            return None;
        }
        let record = BerTlvAny::parse(rest).ok()?;
        let tag = u8::try_from(record.tag()).ok()?;
        if tag & CONTEXT_CONSTRUCTED_MASK != CONTEXT_CONSTRUCTED_VALUE {
            return None;
        }
        if let Some(class) = ObjectClass::from_tag(tag) {
            entries.push(ObjectDirectoryEntry {
                class,
                location: parse_directory_location(record.value())?,
            });
        }
        rest = rest.get(record.size()..)?;
    }
    Some(entries)
}

fn parse_directory_location(value: &[u8]) -> Option<ObjectDirectoryLocation> {
    let choice = BerTlvAny::parse(value).ok()?;
    if choice.size() != value.len() {
        return None;
    }
    if choice.tag() == TAG_SEQUENCE {
        return parse_path(choice.value()).map(ObjectDirectoryLocation::File);
    }
    match u8::try_from(choice.tag()).ok()? {
        TAG_OBJECTS => Some(ObjectDirectoryLocation::Inline),
        TAG_INDIRECT_PROTECTED | TAG_DIRECT_PROTECTED => Some(ObjectDirectoryLocation::Protected),
        _ => None,
    }
}

fn parse_path(sequence: &[u8]) -> Option<Pkcs15Path> {
    let (octets, slice) = parse_path_fields(sequence)?;
    pkcs15_path_from_octets(octets, slice)
}

fn parse_path_fields(sequence: &[u8]) -> Option<(&[u8], Option<PathSlice>)> {
    let path = BerTlvAny::parse(sequence).ok()?;
    if path.tag() != TAG_OCTET_STRING {
        return None;
    }
    let octets = path.value();
    let mut rest = sequence.get(path.size()..)?;
    let slice = if rest.is_empty() {
        None
    } else {
        let index_tlv = BerTlvAny::parse(rest).ok()?;
        if index_tlv.tag() != TAG_INTEGER {
            return None;
        }
        let index = parse_non_negative_u32(index_tlv.value())?;
        rest = rest.get(index_tlv.size()..)?;
        let length_tlv = BerTlvAny::parse(rest).ok()?;
        if length_tlv.tag() != TAG_PATH_LENGTH {
            return None;
        }
        let length = parse_non_negative_u32(length_tlv.value())?;
        rest = rest.get(length_tlv.size()..)?;
        if !rest.is_empty() {
            return None;
        }
        Some(PathSlice { index, length })
    };
    Some((octets, slice))
}

fn parse_non_negative_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_U32_INTEGER_OCTETS {
        return None;
    }
    let first = *bytes.first()?;
    if first & INTEGER_SIGN_MASK != 0 {
        return None;
    }
    if bytes.len() > 1
        && first == END_OF_CONTENTS_OCTET
        && (*bytes.get(1)? & INTEGER_SIGN_MASK) == 0
    {
        return None;
    }
    let mut value = 0_u64;
    for &octet in bytes {
        value = value
            .checked_shl(OCTET_BITS)?
            .checked_add(u64::from(octet))?;
    }
    u32::try_from(value).ok()
}

fn pkcs15_path_from_octets(octets: &[u8], slice: Option<PathSlice>) -> Option<Pkcs15Path> {
    let (chunks, remainder) = octets.as_chunks::<{ FileId::LENGTH }>();
    if chunks.is_empty() || !remainder.is_empty() {
        return None;
    }
    let steps: Vec<FileId> = chunks.iter().copied().map(FileId::new).collect();
    let file = *steps.last()?;
    Some(Pkcs15Path { steps, file, slice })
}

/// One PKCS#15 `Identifier` OCTET STRING linking certificates, private
/// keys, and authentication objects (v1.1 section 6.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentifier(Vec<u8>);

impl ObjectIdentifier {
    /// Construct from octets within the PKCS#15 identifier length cap.
    pub(crate) fn of(bytes: Vec<u8>) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_IDENTIFIER_OCTETS {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// The identifier octets published by the card.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A UTF-8 object label published in `CommonObjectAttributes` (PKCS#15
/// v1.1 section 6.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectLabel(String);

impl ObjectLabel {
    fn of(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAXIMUM_LABEL_OCTETS {
            return None;
        }
        core::str::from_utf8(bytes)
            .ok()
            .map(|text| Self(text.to_owned()))
    }

    /// The label text published by the card.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The card-specific `keyReference` published in EF.PrKDF (PKCS#15 v1.1
/// section 6.1.9) and passed to MSE:SET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyReference(u8);

impl KeyReference {
    const fn of(value: u8) -> Self {
        Self(value)
    }

    /// The key-reference wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// MSE:SET key reference proven by PKCS#15 directory discovery to belong
/// to the card's unique non-repudiation (qualified-signature) private key.
///
/// Constructible only inside this crate from a validated
/// [`DiscoveredQualifiedSignatureProfile`], preventing authentication key
/// references from being passed to qualified-signature unlock APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualifiedKeyReference(KeyReference);

impl QualifiedKeyReference {
    pub(crate) const fn of(reference: KeyReference) -> Self {
        Self(reference)
    }

    /// The underlying PKCS#15 [`KeyReference`].
    #[must_use]
    pub const fn key_reference(self) -> KeyReference {
        self.0
    }

    /// The key-reference wire byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0.as_u8()
    }
}

/// Key-usage bits from `CommonKeyAttributes.usage` (PKCS#15 v1.1 section
/// 6.1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsageFlags {
    decrypt: bool,
    sign: bool,
    derive: bool,
    non_repudiation: bool,
}

impl KeyUsageFlags {
    fn parse_bit_string(content: &[u8]) -> Option<Self> {
        let (unused, octets) = validate_bit_string(content)?;
        Some(Self {
            decrypt: bit_string_flag(unused, octets, KEY_USAGE_DECRYPT_BIT),
            sign: bit_string_flag(unused, octets, KEY_USAGE_SIGN_BIT),
            derive: bit_string_flag(unused, octets, KEY_USAGE_DERIVE_BIT),
            non_repudiation: bit_string_flag(unused, octets, KEY_USAGE_NON_REPUDIATION_BIT),
        })
    }

    /// Bit 1 (`decrypt`).
    #[must_use]
    pub const fn decrypt(self) -> bool {
        self.decrypt
    }

    /// Bit 2 (`sign`).
    #[must_use]
    pub const fn sign(self) -> bool {
        self.sign
    }

    /// Bit 8 (`derive`).
    #[must_use]
    pub const fn derive(self) -> bool {
        self.derive
    }

    /// Bit 9 (`nonRepudiation`): distinguishes qualified / legal
    /// signature keys from authentication keys.
    #[must_use]
    pub const fn non_repudiation(self) -> bool {
        self.non_repudiation
    }

    /// Whether this key's declared usage marks it as an authentication
    /// signing key rather than a non-repudiation (qualified signature)
    /// key: `sign` set and `nonRepudiation` clear.
    #[must_use]
    pub const fn is_authentication(self) -> bool {
        self.sign && !self.non_repudiation
    }

    /// Whether this key's declared usage marks it as a qualified
    /// (non-repudiation) signature key: `nonRepudiation` set.
    #[must_use]
    pub const fn is_qualified_signature(self) -> bool {
        self.non_repudiation
    }
}

/// One certificate record from EF.CDF (PKCS#15 v1.1 section 6.6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDirectoryEntry {
    is_x509: bool,
    label: Option<ObjectLabel>,
    identifier: ObjectIdentifier,
    path: Option<Pkcs15Path>,
}

impl CertificateDirectoryEntry {
    /// Whether this record is an `x509Certificate` choice (universal
    /// SEQUENCE) rather than an attribute, PGP, WTLS, or CV
    /// certificate.
    #[must_use]
    pub const fn is_x509(&self) -> bool {
        self.is_x509
    }

    /// Display label from `CommonObjectAttributes`, when present.
    #[must_use]
    pub const fn label(&self) -> Option<&ObjectLabel> {
        self.label.as_ref()
    }

    /// Identifier shared with the certificate's private key.
    #[must_use]
    pub const fn identifier(&self) -> &ObjectIdentifier {
        &self.identifier
    }

    /// Full PKCS#15 path to the certificate file, when the value is a
    /// readable path.
    #[must_use]
    pub const fn path(&self) -> Option<&Pkcs15Path> {
        self.path.as_ref()
    }

    /// Trailing elementary file identifier, when the value is a
    /// readable path.
    #[must_use]
    pub fn file(&self) -> Option<FileId> {
        self.path.as_ref().map(Pkcs15Path::file)
    }
}

/// One private-key record from EF.PrKDF (PKCS#15 v1.1 section 6.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyDirectoryEntry {
    label: Option<ObjectLabel>,
    auth_id: Option<ObjectIdentifier>,
    identifier: ObjectIdentifier,
    usage: KeyUsageFlags,
    key_reference: Option<KeyReference>,
}

impl PrivateKeyDirectoryEntry {
    /// Display label from `CommonObjectAttributes`, when present.
    #[must_use]
    pub const fn label(&self) -> Option<&ObjectLabel> {
        self.label.as_ref()
    }

    /// `CommonObjectAttributes.authId`, linking this private key to the
    /// authentication object (PIN) in EF.AOD that protects it.
    #[must_use]
    pub const fn auth_id(&self) -> Option<&ObjectIdentifier> {
        self.auth_id.as_ref()
    }

    /// Identifier shared with the private key's certificate.
    #[must_use]
    pub const fn identifier(&self) -> &ObjectIdentifier {
        &self.identifier
    }

    /// Declared `KeyUsageFlags` from `CommonKeyAttributes`.
    #[must_use]
    pub const fn usage(&self) -> KeyUsageFlags {
        self.usage
    }

    /// MSE:SET key reference, when published.
    #[must_use]
    pub const fn key_reference(&self) -> Option<KeyReference> {
        self.key_reference
    }
}

/// Outcome of parsing an EF.CDF file read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateDirectoryRead {
    /// Confirmed EOF and every record framed.
    Parsed(CertificateDirectory),
    /// The read stopped before the card confirmed end of file.
    Incomplete,
    /// The octets were not a valid `CertificateType` record list.
    Malformed,
}

/// Outcome of parsing an EF.PrKDF file read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateKeyDirectoryRead {
    /// Confirmed EOF and every record framed.
    Parsed(PrivateKeyDirectory),
    /// The read stopped before the card confirmed end of file.
    Incomplete,
    /// The octets were not a valid `PrivateKeyType` record list.
    Malformed,
}

/// EF.CDF: the card's certificate directory, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDirectory {
    entries: Vec<CertificateDirectoryEntry>,
}

impl CertificateDirectory {
    /// Validate a confirmed EF.CDF read.
    #[must_use]
    pub fn of(content: FileContent) -> CertificateDirectoryRead {
        let FileContent { bytes, end } = content;
        if !matches!(end, FileEnd::Confirmed) {
            return CertificateDirectoryRead::Incomplete;
        }
        parse_certificate_directory(&bytes).map_or(CertificateDirectoryRead::Malformed, |entries| {
            CertificateDirectoryRead::Parsed(Self { entries })
        })
    }

    /// Combine entries from multiple EF.CDF files listed by EF.ODF.
    pub(crate) fn merge(directories: Vec<Self>) -> Self {
        let mut entries = Vec::new();
        for directory in directories {
            entries.extend(directory.entries);
        }
        Self { entries }
    }

    /// Every certificate entry published by the card, in file order.
    #[must_use]
    pub fn entries(&self) -> &[CertificateDirectoryEntry] {
        &self.entries
    }
}

/// EF.PrKDF: the card's private-key directory, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyDirectory {
    entries: Vec<PrivateKeyDirectoryEntry>,
}

impl PrivateKeyDirectory {
    /// Validate a confirmed EF.PrKDF read.
    #[must_use]
    pub fn of(content: FileContent) -> PrivateKeyDirectoryRead {
        let FileContent { bytes, end } = content;
        if !matches!(end, FileEnd::Confirmed) {
            return PrivateKeyDirectoryRead::Incomplete;
        }
        parse_private_key_directory(&bytes).map_or(PrivateKeyDirectoryRead::Malformed, |entries| {
            PrivateKeyDirectoryRead::Parsed(Self { entries })
        })
    }

    /// Combine entries from multiple EF.PrKDF files listed by EF.ODF.
    pub(crate) fn merge(directories: Vec<Self>) -> Self {
        let mut entries = Vec::new();
        for directory in directories {
            entries.extend(directory.entries);
        }
        Self { entries }
    }

    /// Every private-key entry published by the card, in file order.
    #[must_use]
    pub fn entries(&self) -> &[PrivateKeyDirectoryEntry] {
        &self.entries
    }
}

/// One certificate paired with the private key sharing its PKCS#15
/// `Identifier`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    certificate: CertificateDirectoryEntry,
    key: PrivateKeyDirectoryEntry,
}

impl Credential {
    /// The certificate directory entry.
    #[must_use]
    pub const fn certificate(&self) -> &CertificateDirectoryEntry {
        &self.certificate
    }

    /// The private-key directory entry.
    #[must_use]
    pub const fn key(&self) -> &PrivateKeyDirectoryEntry {
        &self.key
    }

    /// The identifier shared by certificate and private key.
    #[must_use]
    pub const fn identifier(&self) -> &ObjectIdentifier {
        self.certificate.identifier()
    }

    /// The certificate's readable PKCS#15 path, if published.
    #[must_use]
    pub const fn path(&self) -> Option<&Pkcs15Path> {
        self.certificate.path()
    }

    /// The certificate's trailing elementary file, if published.
    #[must_use]
    pub fn file(&self) -> Option<FileId> {
        self.certificate.file()
    }

    /// The MSE:SET key reference, if published.
    #[must_use]
    pub const fn key_reference(&self) -> Option<KeyReference> {
        self.key.key_reference()
    }
}

/// Why EF.CDF and EF.PrKDF could not be paired into unambiguous
/// credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPairingError {
    /// Two certificates share an identifier.
    DuplicateCertificate,
    /// Two private keys share an identifier.
    DuplicateKey,
    /// Two paired credentials claim the same MSE:SET key reference.
    DuplicateKeyReference,
}

impl fmt::Display for CredentialPairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DuplicateCertificate => "two certificates share an identifier",
            Self::DuplicateKey => "two private keys share an identifier",
            Self::DuplicateKeyReference => "two credentials share a key reference",
        })
    }
}

impl core::error::Error for CredentialPairingError {}

/// Result of selecting the authentication credential from a paired
/// [`CredentialDirectory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationCredentialLookup<'a> {
    /// No paired credential declares authentication key usage.
    Absent,
    /// More than one paired credential declares authentication key
    /// usage, so no unique authentication credential can be chosen.
    Ambiguous,
    /// Exactly one paired credential declares authentication key usage.
    Unique(&'a Credential),
}

/// Result of selecting the qualified-signature credential from a paired
/// [`CredentialDirectory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualifiedSignatureCredentialLookup<'a> {
    /// No paired credential declares non-repudiation key usage.
    Absent,
    /// More than one paired credential declares non-repudiation key
    /// usage, so no unique qualified-signature credential can be chosen.
    Ambiguous,
    /// Exactly one paired credential declares non-repudiation key usage.
    Unique(&'a Credential),
}

/// Credentials formed by pairing EF.CDF and EF.PrKDF by `Identifier`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDirectory {
    entries: Vec<Credential>,
}

impl CredentialDirectory {
    /// Pair every certificate with the private key sharing its
    /// identifier, ignoring unpaired certificates (such as CA
    /// certificates in EF.CDF) and unpaired keys while rejecting
    /// duplicate identifiers or colliding key references.
    ///
    /// # Errors
    /// [`CredentialPairingError`] when either directory repeats an
    /// identifier or two paired credentials claim the same key
    /// reference.
    pub fn of(
        certificates: &CertificateDirectory,
        keys: &PrivateKeyDirectory,
    ) -> Result<Self, CredentialPairingError> {
        for (index, key) in keys.entries().iter().enumerate() {
            if keys
                .entries()
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.identifier() == key.identifier())
            {
                return Err(CredentialPairingError::DuplicateKey);
            }
        }
        let mut entries = Vec::with_capacity(certificates.entries().len());
        for (index, certificate) in certificates.entries().iter().enumerate() {
            if certificates
                .entries()
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.identifier() == certificate.identifier())
            {
                return Err(CredentialPairingError::DuplicateCertificate);
            }
            if let Some(key) = keys
                .entries()
                .iter()
                .find(|key| key.identifier() == certificate.identifier())
            {
                entries.push(Credential {
                    certificate: certificate.clone(),
                    key: key.clone(),
                });
            }
        }
        for (index, credential) in entries.iter().enumerate() {
            let Some(reference) = credential.key_reference() else {
                continue;
            };
            if entries
                .iter()
                .skip(index.saturating_add(1))
                .any(|other| other.key_reference() == Some(reference))
            {
                return Err(CredentialPairingError::DuplicateKeyReference);
            }
        }
        Ok(Self { entries })
    }

    /// Every paired credential, in CDF order.
    #[must_use]
    pub fn entries(&self) -> &[Credential] {
        &self.entries
    }

    /// Find the single credential whose private key declares
    /// authentication usage (`sign` set, `nonRepudiation` clear).
    #[must_use]
    pub fn unique_authentication_credential(&self) -> AuthenticationCredentialLookup<'_> {
        let mut matching = self
            .entries
            .iter()
            .filter(|credential| credential.key().usage().is_authentication());
        let Some(first) = matching.next() else {
            return AuthenticationCredentialLookup::Absent;
        };
        if matching.next().is_some() {
            return AuthenticationCredentialLookup::Ambiguous;
        }
        AuthenticationCredentialLookup::Unique(first)
    }

    /// Find the single credential whose private key declares qualified
    /// signature usage (`nonRepudiation` set).
    #[must_use]
    pub fn unique_qualified_signature_credential(&self) -> QualifiedSignatureCredentialLookup<'_> {
        let mut matching = self
            .entries
            .iter()
            .filter(|credential| credential.key().usage().is_qualified_signature());
        let Some(first) = matching.next() else {
            return QualifiedSignatureCredentialLookup::Absent;
        };
        if matching.next().is_some() {
            return QualifiedSignatureCredentialLookup::Ambiguous;
        }
        QualifiedSignatureCredentialLookup::Unique(first)
    }
}

/// Complete ISO/IEC 7816-15 qualified-signature profile discovered
/// purely from a card's EF.ODF, EF.CDF, EF.PrKDF, and EF.AOD under a
/// given application AID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredQualifiedSignatureProfile {
    application_aid: Aid,
    sign_cert_path: Pkcs15Path,
    sign_key_reference: QualifiedKeyReference,
    aod_path: Pkcs15Path,
    pin2_auth_id: ObjectIdentifier,
    pin2: PasswordObject,
    puk: Option<PasswordObject>,
}

impl DiscoveredQualifiedSignatureProfile {
    pub(crate) const fn new(
        application_aid: Aid,
        sign_cert_path: Pkcs15Path,
        sign_key_reference: QualifiedKeyReference,
        aod_path: Pkcs15Path,
        pin2_auth_id: ObjectIdentifier,
        pin2: PasswordObject,
        puk: Option<PasswordObject>,
    ) -> Self {
        Self {
            application_aid,
            sign_cert_path,
            sign_key_reference,
            aod_path,
            pin2_auth_id,
            pin2,
            puk,
        }
    }

    /// Application identifier selected for this PKCS#15 profile.
    #[must_use]
    pub const fn application_aid(&self) -> &Aid {
        &self.application_aid
    }

    /// Full PKCS#15 path of the X.509 qualified-signature certificate.
    #[must_use]
    pub const fn sign_cert_path(&self) -> &Pkcs15Path {
        &self.sign_cert_path
    }

    /// MSE:SET key reference of the qualified-signature private key.
    #[must_use]
    pub const fn sign_key_reference(&self) -> QualifiedKeyReference {
        self.sign_key_reference
    }

    /// Full PKCS#15 path of the EF.AOD file that lists [`Self::pin2`].
    #[must_use]
    pub const fn aod_path(&self) -> &Pkcs15Path {
        &self.aod_path
    }

    /// PKCS#15 `authId` linking the qualified-signature key to
    /// [`Self::pin2`].
    #[must_use]
    pub const fn pin2_auth_id(&self) -> &ObjectIdentifier {
        &self.pin2_auth_id
    }

    /// Qualified-signature PIN 2 object parsed from EF.AOD.
    #[must_use]
    pub const fn pin2(&self) -> &PasswordObject {
        &self.pin2
    }

    /// Protecting PUK object parsed from EF.AOD, when linked by
    /// `CommonObjectAttributes.authId`.
    #[must_use]
    pub const fn puk(&self) -> Option<&PasswordObject> {
        self.puk.as_ref()
    }
}

/// Complete ISO/IEC 7816-15 authentication profile discovered purely
/// from a card's EF.ODF, EF.CDF, EF.PrKDF, and EF.AOD under a given
/// application AID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredAuthenticationProfile {
    application_aid: Aid,
    auth_cert_path: Pkcs15Path,
    auth_key_reference: KeyReference,
    aod_path: Pkcs15Path,
    pin1_auth_id: ObjectIdentifier,
    pin1: PasswordObject,
    puk: Option<PasswordObject>,
}

impl DiscoveredAuthenticationProfile {
    pub(crate) const fn new(
        application_aid: Aid,
        auth_cert_path: Pkcs15Path,
        auth_key_reference: KeyReference,
        aod_path: Pkcs15Path,
        pin1_auth_id: ObjectIdentifier,
        pin1: PasswordObject,
        puk: Option<PasswordObject>,
    ) -> Self {
        Self {
            application_aid,
            auth_cert_path,
            auth_key_reference,
            aod_path,
            pin1_auth_id,
            pin1,
            puk,
        }
    }

    /// Application identifier selected for this PKCS#15 profile.
    #[must_use]
    pub const fn application_aid(&self) -> &Aid {
        &self.application_aid
    }

    /// Full PKCS#15 path of the X.509 authentication certificate.
    #[must_use]
    pub const fn auth_cert_path(&self) -> &Pkcs15Path {
        &self.auth_cert_path
    }

    /// MSE:SET key reference of the authentication private key.
    #[must_use]
    pub const fn auth_key_reference(&self) -> KeyReference {
        self.auth_key_reference
    }

    /// Full PKCS#15 path of the EF.AOD file that lists [`Self::pin1`].
    #[must_use]
    pub const fn aod_path(&self) -> &Pkcs15Path {
        &self.aod_path
    }

    /// PKCS#15 `authId` linking the authentication key to [`Self::pin1`].
    #[must_use]
    pub const fn pin1_auth_id(&self) -> &ObjectIdentifier {
        &self.pin1_auth_id
    }

    /// Authentication PIN object parsed from EF.AOD.
    #[must_use]
    pub const fn pin1(&self) -> &PasswordObject {
        &self.pin1
    }

    /// Protecting PUK object parsed from EF.AOD, when linked by
    /// `CommonObjectAttributes.authId`.
    #[must_use]
    pub const fn puk(&self) -> Option<&PasswordObject> {
        self.puk.as_ref()
    }
}

/// Where an `ObjectValue` points as far as readable elementary files
/// are concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ObjectValueLocation {
    Path(Pkcs15Path),
    Empty,
    Other,
}

struct Pkcs15ObjectFields<'a> {
    common: &'a [u8],
    class: &'a [u8],
    type_attributes: &'a [u8],
}

pub(crate) struct CommonObjectAttributes {
    pub(crate) label: Option<ObjectLabel>,
    pub(crate) auth_id: Option<ObjectIdentifier>,
}

fn parse_certificate_directory(bytes: &[u8]) -> Option<Vec<CertificateDirectoryEntry>> {
    parse_record_list(bytes, is_certificate_type)?
        .into_iter()
        .map(|record| parse_certificate_entry(record.tag() == TAG_SEQUENCE, record.value()))
        .collect()
}

fn parse_private_key_directory(bytes: &[u8]) -> Option<Vec<PrivateKeyDirectoryEntry>> {
    parse_record_list(bytes, is_private_key_type)?
        .into_iter()
        .map(|record| parse_private_key_entry(record.value()))
        .collect()
}

fn parse_record_list(bytes: &[u8], accepts: fn(u8) -> bool) -> Option<Vec<BerTlvAny<'_>>> {
    let mut records = Vec::new();
    let mut rest = bytes;
    while let Some(&first) = rest.first() {
        if first == END_OF_CONTENTS_OCTET || first == PADDING_FF_OCTET {
            if rest.iter().all(|&octet| octet == first) {
                break;
            }
            return None;
        }
        let record = BerTlvAny::parse(rest).ok()?;
        let tag = u8::try_from(record.tag()).ok()?;
        if !accepts(tag) {
            return None;
        }
        records.push(record);
        rest = rest.get(record.size()..)?;
    }
    Some(records)
}

fn is_certificate_type(tag: u8) -> bool {
    tag == DER_SEQUENCE_TAG_OCTET
        || (TAG_X509_ATTRIBUTE_CERTIFICATE..=TAG_CV_CERTIFICATE).contains(&tag)
}

fn is_private_key_type(tag: u8) -> bool {
    tag == DER_SEQUENCE_TAG_OCTET || (TAG_PRIVATE_EC_KEY..=TAG_PRIVATE_KEA_KEY).contains(&tag)
}

fn parse_certificate_entry(is_x509: bool, body: &[u8]) -> Option<CertificateDirectoryEntry> {
    let fields = parse_pkcs15_object(body)?;
    let common = parse_common_object_attributes(fields.common)?;
    let identifier = parse_certificate_attributes(fields.class)?;
    let location = parse_object_value_field(fields.type_attributes)?;
    let path = match location {
        ObjectValueLocation::Path(path) => Some(path),
        ObjectValueLocation::Empty | ObjectValueLocation::Other => None,
    };
    Some(CertificateDirectoryEntry {
        is_x509,
        label: common.label,
        identifier,
        path,
    })
}

fn parse_private_key_entry(body: &[u8]) -> Option<PrivateKeyDirectoryEntry> {
    let fields = parse_pkcs15_object(body)?;
    let common = parse_common_object_attributes(fields.common)?;
    let (identifier, usage, key_reference) = parse_key_attributes(fields.class)?;
    parse_object_value_field(fields.type_attributes)?;
    Some(PrivateKeyDirectoryEntry {
        label: common.label,
        auth_id: common.auth_id,
        identifier,
        usage,
        key_reference,
    })
}

fn parse_pkcs15_object(body: &[u8]) -> Option<Pkcs15ObjectFields<'_>> {
    let mut fields = tlvs(body)?.into_iter();
    let common = fields.next()?;
    if common.tag() != TAG_SEQUENCE {
        return None;
    }
    let class = fields.next()?;
    if class.tag() != TAG_SEQUENCE {
        return None;
    }
    let mut type_attributes = fields.next()?;
    if type_attributes.tag() == TAG_SUB_CLASS_ATTRIBUTES {
        type_attributes = fields.next()?;
    }
    if type_attributes.tag() != TAG_TYPE_ATTRIBUTES || fields.next().is_some() {
        return None;
    }
    let attributes = BerTlvAny::parse(type_attributes.value()).ok()?;
    if attributes.size() != type_attributes.value().len() || attributes.tag() != TAG_SEQUENCE {
        return None;
    }
    Some(Pkcs15ObjectFields {
        common: common.value(),
        class: class.value(),
        type_attributes: attributes.value(),
    })
}

/// Parse `CommonObjectAttributes` (PKCS#15 v1.1 section 6.1.8):
/// optional `label` (`UTF8String`), optional `flags` (`BIT STRING`),
/// optional `authId` (`OCTET STRING`).
pub(crate) fn parse_common_object_attributes(value: &[u8]) -> Option<CommonObjectAttributes> {
    let mut fields = tlvs(value)?.into_iter().peekable();
    let label = match fields.next_if(|field| field.tag() == TAG_UTF8_STRING) {
        Some(field) => Some(ObjectLabel::of(field.value())?),
        None => None,
    };
    if let Some(flags) = fields.next_if(|field| field.tag() == TAG_BIT_STRING) {
        validate_bit_string(flags.value())?;
    }
    let auth_id = match fields.next_if(|field| field.tag() == TAG_OCTET_STRING) {
        Some(field) => Some(ObjectIdentifier::of(field.value().to_vec())?),
        None => None,
    };
    Some(CommonObjectAttributes { label, auth_id })
}

fn parse_certificate_attributes(value: &[u8]) -> Option<ObjectIdentifier> {
    let fields = tlvs(value)?;
    let identifier = fields.first()?;
    if identifier.tag() != TAG_OCTET_STRING {
        return None;
    }
    ObjectIdentifier::of(identifier.value().to_vec())
}

fn parse_key_attributes(
    value: &[u8],
) -> Option<(ObjectIdentifier, KeyUsageFlags, Option<KeyReference>)> {
    let mut fields = tlvs(value)?.into_iter().peekable();
    let identifier = fields.next()?;
    if identifier.tag() != TAG_OCTET_STRING {
        return None;
    }
    let usage_tlv = fields.next()?;
    if usage_tlv.tag() != TAG_BIT_STRING {
        return None;
    }
    let usage = KeyUsageFlags::parse_bit_string(usage_tlv.value())?;
    let _native = fields.next_if(|field| field.tag() == TAG_BOOLEAN);
    if let Some(access_flags) = fields.next_if(|field| field.tag() == TAG_BIT_STRING) {
        validate_bit_string(access_flags.value())?;
    }
    let key_reference = match fields.next_if(|field| field.tag() == TAG_INTEGER) {
        Some(field) => Some(parse_reference(field.value())?),
        None => None,
    };
    Some((
        ObjectIdentifier::of(identifier.value().to_vec())?,
        usage,
        key_reference,
    ))
}

fn parse_reference(bytes: &[u8]) -> Option<KeyReference> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_REFERENCE_OCTETS {
        return None;
    }
    if bytes.first()? & INTEGER_SIGN_MASK != 0 {
        return None;
    }
    let mut value = 0_u16;
    for octet in bytes {
        value = value
            .checked_shl(OCTET_BITS)?
            .checked_add(u16::from(*octet))?;
    }
    u8::try_from(value).ok().map(KeyReference::of)
}

fn parse_object_value_field(value: &[u8]) -> Option<ObjectValueLocation> {
    let fields = tlvs(value)?;
    parse_object_value(*fields.first()?)
}

fn parse_object_value(value: BerTlvAny<'_>) -> Option<ObjectValueLocation> {
    if value.tag() == TAG_SEQUENCE {
        let (octets, slice) = parse_path_fields(value.value())?;
        return if octets.is_empty() {
            if slice.is_some() {
                None
            } else {
                Some(ObjectValueLocation::Empty)
            }
        } else {
            pkcs15_path_from_octets(octets, slice).map(ObjectValueLocation::Path)
        };
    }
    if value.tag() == TAG_PRINTABLE_STRING {
        return Some(ObjectValueLocation::Other);
    }
    match u8::try_from(value.tag()).ok()? {
        TAG_DIRECT_OBJECT_VALUE
        | TAG_INDIRECT_PROTECTED_OBJECT_VALUE
        | TAG_DIRECT_PROTECTED_OBJECT_VALUE => Some(ObjectValueLocation::Other),
        _ => None,
    }
}

fn tlvs(value: &[u8]) -> Option<Vec<BerTlvAny<'_>>> {
    let mut rest = value;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let field = BerTlvAny::parse(rest).ok()?;
        rest = rest.get(field.size()..)?;
        fields.push(field);
    }
    Some(fields)
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{Aid, FileId};
    use refineid_ber::{BerEncoder, tlv, tlv2};

    use super::{
        ApplicationDirectory, ApplicationDirectoryRead, ApplicationLabel,
        AuthenticationCredentialLookup, CertificateDirectory, CertificateDirectoryRead,
        CertificateRead, CredentialDirectory, CredentialPairingError, DER_SEQUENCE_TAG_OCTET,
        DerCertificate, DirectoryLookup, END_OF_CONTENTS_OCTET, FileContent, FileEnd,
        INDEFINITE_LENGTH, KeyUsageFlags, ObjectClass, ObjectDirectory, ObjectDirectoryRead,
        PADDING_FF_OCTET, PrivateKeyDirectory, PrivateKeyDirectoryRead,
        QualifiedSignatureCredentialLookup, TAG_APPLICATION_IDENTIFIER, TAG_APPLICATION_LABEL,
        TAG_APPLICATION_PATH, TAG_APPLICATION_TEMPLATE, TAG_AUTH_OBJECTS, TAG_BIT_STRING,
        TAG_CERTIFICATES, TAG_DIRECT_OBJECT_VALUE, TAG_INTEGER, TAG_OBJECTS, TAG_OCTET_STRING,
        TAG_PATH_LENGTH, TAG_PRINTABLE_STRING, TAG_PRIVATE_EC_KEY, TAG_PRIVATE_KEYS, TAG_SEQUENCE,
        TAG_TYPE_ATTRIBUTES, TAG_UTF8_STRING, TAG_X509_ATTRIBUTE_CERTIFICATE,
    };

    const TEST_AID: &[u8] = b"test-aid-01";
    const OTHER_AID: &[u8] = b"other-aid";
    const SHORT_AID: &[u8] = b"test";
    const LONG_AID: &[u8] = b"test-aid-01-extra";
    const TEST_LABEL: &str = "test application";
    const OTHER_LABEL: &str = "another application";
    const NOT_UTF8: &[u8] = &[0xFF, 0xFE];
    const TAG_URL: u16 = 0x5F50;
    const TAG_DISCRETIONARY_DATA: u8 = 0x53;
    const LONG_VALUE_LEN: usize = 140;
    const FILLER_BYTE: u8 = 0xAA;
    const NON_ZERO_TRAILER: u8 = 0x01;
    const ODD_PATH_OCTETS: &[u8] = &[0x3F, 0x00, 0x50];
    const CERT_DF_FID: FileId = FileId::from_u16(0xADF1);
    const AUTH_CERT_FID: FileId = FileId::from_u16(0x3411);
    const SIGN_DF_FID: FileId = FileId::from_u16(0xADF2);
    const SIGN_CERT_FID: FileId = FileId::from_u16(0x3421);
    const ODF_CDF_FID: FileId = FileId::from_u16(0x5003);
    const ODF_PRKDF_FID: FileId = FileId::from_u16(0x5001);
    const ODF_AOD_FID: FileId = FileId::from_u16(0x5006);
    const AUTH_OBJECT_ID: u8 = 0x11;
    const SIGN_OBJECT_ID: u8 = 0x21;
    const PIN1_AUTH_ID: u8 = 0x01;
    const PIN2_AUTH_ID: u8 = 0x02;
    const AUTH_KEY_REF: u8 = 0x01;
    const SIGN_KEY_REF: u8 = 0x05;
    /// Observed Estonian eID auth key usage BIT STRING: 7 unused bits,
    /// sign (bit 2) and derive (bit 8) set, nonRepudiation (bit 9) clear.
    const AUTH_KEY_USAGE_BITSTRING: &[u8] = &[0x07, 0x20, 0x80];
    /// Observed Estonian eID signature key usage BIT STRING: 6 unused
    /// bits, nonRepudiation (bit 9) set, sign (bit 2) clear.
    const SIGN_KEY_USAGE_BITSTRING: &[u8] = &[0x06, 0x00, 0x40];
    const SLICE_INDEX: u8 = 4;
    const SLICE_LENGTH: u8 = 16;
    const SAMPLE_FILE_LEN: usize = 32;
    const TWO_ENTRIES: usize = 2;
    const LONG_FORM_ONE_OCTET_MARKER: u8 = 0x81;
    const LONG_FORM_TWO_OCTET_MARKER: u8 = 0x82;
    const LONG_FORM_THREE_OCTET_MARKER: u8 = 0x83;
    const SHORT_DER_CONTENT_LEN: u8 = 4;
    const TWO_OCTET_CERT_CONTENT_LEN: usize = 300;
    const COMMON_FLAGS_BITSTRING: &[u8] = &[0x06, 0xC0];

    fn tag1(value: u16) -> u8 {
        u8::try_from(value).expect("one-byte tag")
    }

    fn aid(bytes: &[u8]) -> Aid {
        Aid::from_slice(bytes).expect("valid test AID")
    }

    fn label(text: &str) -> ApplicationLabel {
        ApplicationLabel::try_from(text).expect("non-empty test label")
    }

    fn ef_dir_entry(text: &str, id: &[u8], path: Option<&[FileId]>) -> Vec<u8> {
        let mut inner = BerEncoder::default();
        inner
            .push_tlv(tag1(TAG_APPLICATION_IDENTIFIER), id)
            .expect("encodes");
        inner
            .push_tlv(tag1(TAG_APPLICATION_LABEL), text.as_bytes())
            .expect("encodes");
        if let Some(steps) = path {
            let mut raw = Vec::new();
            for fid in steps {
                raw.extend_from_slice(fid.as_bytes());
            }
            inner
                .push_tlv(tag1(TAG_APPLICATION_PATH), raw)
                .expect("encodes");
        }
        tlv(tag1(TAG_APPLICATION_TEMPLATE), inner.finish()).expect("encodes")
    }

    fn encode_path(steps: &[FileId], slice: Option<(u8, u8)>) -> Vec<u8> {
        let mut raw = Vec::new();
        for fid in steps {
            raw.extend_from_slice(fid.as_bytes());
        }
        let mut inner = BerEncoder::default();
        inner
            .push_tlv(tag1(TAG_OCTET_STRING), raw)
            .expect("encodes");
        if let Some((index, length)) = slice {
            inner.push_tlv(tag1(TAG_INTEGER), [index]).expect("encodes");
            inner
                .push_tlv(tag1(TAG_PATH_LENGTH), [length])
                .expect("encodes");
        }
        tlv(tag1(TAG_SEQUENCE), inner.finish()).expect("encodes")
    }

    fn encode_cdf_entry(
        outer_tag: u8,
        name: &str,
        id: u8,
        path: &[FileId],
        slice: Option<(u8, u8)>,
    ) -> Vec<u8> {
        let common = tlv(
            tag1(TAG_SEQUENCE),
            tlv(tag1(TAG_UTF8_STRING), name.as_bytes()).expect("encodes"),
        )
        .expect("encodes");
        let class = tlv(
            tag1(TAG_SEQUENCE),
            tlv(tag1(TAG_OCTET_STRING), [id]).expect("encodes"),
        )
        .expect("encodes");
        let attrs = tlv(tag1(TAG_SEQUENCE), encode_path(path, slice)).expect("encodes");
        let type_attrs = tlv(tag1(TAG_TYPE_ATTRIBUTES), attrs).expect("encodes");
        let mut body = common;
        body.extend_from_slice(&class);
        body.extend_from_slice(&type_attrs);
        tlv(outer_tag, body).expect("encodes")
    }

    fn encode_prkdf_entry(
        outer_tag: u8,
        name: &str,
        auth_id: Option<u8>,
        id: u8,
        usage: &[u8],
        key_ref: Option<u8>,
    ) -> Vec<u8> {
        let mut common_inner = BerEncoder::default();
        common_inner
            .push_tlv(tag1(TAG_UTF8_STRING), name.as_bytes())
            .expect("encodes");
        common_inner
            .push_tlv(tag1(TAG_BIT_STRING), COMMON_FLAGS_BITSTRING)
            .expect("encodes");
        if let Some(aid_byte) = auth_id {
            common_inner
                .push_tlv(tag1(TAG_OCTET_STRING), [aid_byte])
                .expect("encodes");
        }
        let common = tlv(tag1(TAG_SEQUENCE), common_inner.finish()).expect("encodes");

        let mut class_inner = BerEncoder::default();
        class_inner
            .push_tlv(tag1(TAG_OCTET_STRING), [id])
            .expect("encodes");
        class_inner
            .push_tlv(tag1(TAG_BIT_STRING), usage)
            .expect("encodes");
        if let Some(reference) = key_ref {
            class_inner
                .push_tlv(tag1(TAG_INTEGER), [reference])
                .expect("encodes");
        }
        let class = tlv(tag1(TAG_SEQUENCE), class_inner.finish()).expect("encodes");
        let empty_path = tlv(
            tag1(TAG_SEQUENCE),
            tlv(tag1(TAG_OCTET_STRING), []).expect("encodes"),
        )
        .expect("encodes");
        let attrs = tlv(tag1(TAG_SEQUENCE), empty_path).expect("encodes");
        let type_attrs = tlv(tag1(TAG_TYPE_ATTRIBUTES), attrs).expect("encodes");
        let mut body = common;
        body.extend_from_slice(&class);
        body.extend_from_slice(&type_attrs);
        tlv(outer_tag, body).expect("encodes")
    }

    #[test]
    fn ef_dir_parses_aid_label_path_multibyte_tags_and_padding() {
        let mut template = BerEncoder::default();
        template
            .push_tlv(tag1(TAG_APPLICATION_IDENTIFIER), TEST_AID)
            .expect("encodes");
        template
            .push_tlv(tag1(TAG_APPLICATION_LABEL), TEST_LABEL.as_bytes())
            .expect("encodes");
        template
            .push_tlv(tag1(TAG_APPLICATION_PATH), FileId::MF.as_bytes())
            .expect("encodes");
        let url_tlv = tlv2(TAG_URL, b"https://example.invalid").expect("encodes");
        let mut raw_template = template.finish();
        raw_template.extend_from_slice(&url_tlv);
        raw_template.extend_from_slice(
            &tlv(TAG_DISCRETIONARY_DATA, vec![FILLER_BYTE; LONG_VALUE_LEN]).expect("encodes"),
        );

        let mut file = vec![PADDING_FF_OCTET, END_OF_CONTENTS_OCTET];
        file.extend_from_slice(
            &tlv(tag1(TAG_APPLICATION_TEMPLATE), raw_template).expect("encodes"),
        );
        file.extend_from_slice(&ef_dir_entry(OTHER_LABEL, OTHER_AID, None));
        file.push(PADDING_FF_OCTET);

        let dir =
            match ApplicationDirectory::of(FileContent::from_read(file, FileEnd::Confirmed)) {
                ApplicationDirectoryRead::Parsed(dir) => Some(dir),
                ApplicationDirectoryRead::Incomplete | ApplicationDirectoryRead::Malformed => None,
            }
            .expect("valid EF.DIR must parse");
        assert_eq!(dir.entries().len(), TWO_ENTRIES);
        assert_eq!(
            dir.identifier_labelled(&label(TEST_LABEL)),
            DirectoryLookup::Identified(aid(TEST_AID))
        );
        assert_eq!(
            dir.entries()[0].path().map(super::Pkcs15Path::steps),
            Some([FileId::MF].as_slice())
        );
    }

    #[test]
    fn ef_dir_rejects_incomplete_ambiguous_bad_aid_bad_utf8_and_odd_path() {
        let valid = ef_dir_entry(TEST_LABEL, TEST_AID, None);
        assert_eq!(
            ApplicationDirectory::of(FileContent::from_read(valid.clone(), FileEnd::Incomplete)),
            ApplicationDirectoryRead::Incomplete
        );
        let mut dup = valid;
        dup.extend_from_slice(&ef_dir_entry(TEST_LABEL, OTHER_AID, None));
        let dir = match ApplicationDirectory::of(FileContent::from_read(dup, FileEnd::Confirmed)) {
            ApplicationDirectoryRead::Parsed(dir) => Some(dir),
            ApplicationDirectoryRead::Incomplete | ApplicationDirectoryRead::Malformed => None,
        }
        .expect("syntactically valid duplicate-label EF.DIR parses");
        assert_eq!(
            dir.identifier_labelled(&label(TEST_LABEL)),
            DirectoryLookup::Ambiguous
        );

        for bad in [
            ef_dir_entry(TEST_LABEL, SHORT_AID, None),
            ef_dir_entry(TEST_LABEL, LONG_AID, None),
            {
                let mut inner = BerEncoder::default();
                inner
                    .push_tlv(tag1(TAG_APPLICATION_IDENTIFIER), TEST_AID)
                    .expect("encodes");
                inner
                    .push_tlv(tag1(TAG_APPLICATION_LABEL), NOT_UTF8)
                    .expect("encodes");
                tlv(tag1(TAG_APPLICATION_TEMPLATE), inner.finish()).expect("encodes")
            },
            {
                let mut inner = BerEncoder::default();
                inner
                    .push_tlv(tag1(TAG_APPLICATION_IDENTIFIER), TEST_AID)
                    .expect("encodes");
                inner
                    .push_tlv(tag1(TAG_APPLICATION_PATH), ODD_PATH_OCTETS)
                    .expect("encodes");
                tlv(tag1(TAG_APPLICATION_TEMPLATE), inner.finish()).expect("encodes")
            },
        ] {
            assert_eq!(
                ApplicationDirectory::of(FileContent::from_read(bad, FileEnd::Confirmed)),
                ApplicationDirectoryRead::Malformed
            );
        }
    }

    #[test]
    fn der_certificate_requires_confirmed_eof_and_exact_minimal_der_sequence() {
        let short_cert = tlv(
            DER_SEQUENCE_TAG_OCTET,
            vec![FILLER_BYTE; usize::from(SHORT_DER_CONTENT_LEN)],
        )
        .expect("encodes");
        assert!(matches!(
            DerCertificate::of(FileContent::from_read(
                short_cert.clone(),
                FileEnd::Confirmed
            )),
            CertificateRead::Complete(_)
        ));
        assert_eq!(
            DerCertificate::of(FileContent::from_read(
                short_cert.clone(),
                FileEnd::Incomplete
            )),
            CertificateRead::Incomplete
        );

        let mut with_trailing = short_cert;
        with_trailing.push(END_OF_CONTENTS_OCTET);
        assert_eq!(
            DerCertificate::of(FileContent::from_read(with_trailing, FileEnd::Confirmed)),
            CertificateRead::NotOneObject
        );

        let long_cert = tlv(
            DER_SEQUENCE_TAG_OCTET,
            vec![FILLER_BYTE; TWO_OCTET_CERT_CONTENT_LEN],
        )
        .expect("encodes");
        assert!(matches!(
            DerCertificate::of(FileContent::from_read(long_cert, FileEnd::Confirmed)),
            CertificateRead::Complete(_)
        ));

        for invalid in [
            vec![
                DER_SEQUENCE_TAG_OCTET,
                INDEFINITE_LENGTH,
                END_OF_CONTENTS_OCTET,
                END_OF_CONTENTS_OCTET,
            ],
            vec![
                DER_SEQUENCE_TAG_OCTET,
                LONG_FORM_ONE_OCTET_MARKER,
                SHORT_DER_CONTENT_LEN,
                FILLER_BYTE,
                FILLER_BYTE,
                FILLER_BYTE,
                FILLER_BYTE,
            ],
            vec![
                DER_SEQUENCE_TAG_OCTET,
                LONG_FORM_TWO_OCTET_MARKER,
                END_OF_CONTENTS_OCTET,
                LONG_FORM_ONE_OCTET_MARKER,
            ],
            vec![
                DER_SEQUENCE_TAG_OCTET,
                LONG_FORM_THREE_OCTET_MARKER,
                NON_ZERO_TRAILER,
                END_OF_CONTENTS_OCTET,
                END_OF_CONTENTS_OCTET,
            ],
        ] {
            assert_eq!(
                DerCertificate::of(FileContent::from_read(invalid, FileEnd::Confirmed)),
                CertificateRead::NotOneObject
            );
        }
    }

    #[test]
    fn ef_odf_parses_paths_and_rejects_inline_when_plain_paths_demanded() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            &tlv(
                TAG_CERTIFICATES,
                encode_path(&[FileId::MF, ODF_CDF_FID], None),
            )
            .expect("encodes"),
        );
        bytes.extend_from_slice(
            &tlv(
                TAG_PRIVATE_KEYS,
                encode_path(&[FileId::MF, ODF_PRKDF_FID], None),
            )
            .expect("encodes"),
        );
        bytes.extend_from_slice(
            &tlv(
                TAG_AUTH_OBJECTS,
                encode_path(&[FileId::MF, ODF_AOD_FID], None),
            )
            .expect("encodes"),
        );
        bytes.extend_from_slice(
            &tlv(TAG_AUTH_OBJECTS, tlv(TAG_OBJECTS, []).expect("encodes")).expect("encodes"),
        );

        let odf = match ObjectDirectory::of(FileContent::from_read(bytes, FileEnd::Confirmed)) {
            ObjectDirectoryRead::Parsed(odf) => Some(odf),
            ObjectDirectoryRead::Incomplete | ObjectDirectoryRead::Malformed => None,
        }
        .expect("valid EF.ODF must parse");
        assert_eq!(
            odf.plain_file_paths(ObjectClass::Certificates)
                .expect("plain CDF path")[0]
                .file(),
            ODF_CDF_FID
        );
        assert_eq!(
            odf.plain_file_paths(ObjectClass::PrivateKeys)
                .expect("plain PrKDF path")[0]
                .file(),
            ODF_PRKDF_FID
        );
        assert!(
            odf.plain_file_paths(ObjectClass::AuthObjects).is_none(),
            "inline AuthObjects entry alongside File must refuse plain-only resolution"
        );
    }

    #[test]
    fn key_usage_and_credential_pairing_distinguish_auth_from_signature() {
        let auth_usage =
            KeyUsageFlags::parse_bit_string(AUTH_KEY_USAGE_BITSTRING).expect("valid BIT STRING");
        assert!(auth_usage.sign());
        assert!(auth_usage.derive());
        assert!(!auth_usage.non_repudiation());
        assert!(auth_usage.is_authentication());
        assert!(!auth_usage.is_qualified_signature());

        let sign_usage =
            KeyUsageFlags::parse_bit_string(SIGN_KEY_USAGE_BITSTRING).expect("valid BIT STRING");
        assert!(!sign_usage.sign());
        assert!(sign_usage.non_repudiation());
        assert!(!sign_usage.is_authentication());
        assert!(sign_usage.is_qualified_signature());

        let mut cdf_bytes = encode_cdf_entry(
            DER_SEQUENCE_TAG_OCTET,
            "authentication certificate",
            AUTH_OBJECT_ID,
            &[FileId::MF, CERT_DF_FID, AUTH_CERT_FID],
            Some((SLICE_INDEX, SLICE_LENGTH)),
        );
        cdf_bytes.extend_from_slice(&encode_cdf_entry(
            DER_SEQUENCE_TAG_OCTET,
            "signature certificate",
            SIGN_OBJECT_ID,
            &[FileId::MF, SIGN_DF_FID, SIGN_CERT_FID],
            None,
        ));

        let mut prkdf_bytes = encode_prkdf_entry(
            TAG_PRIVATE_EC_KEY,
            "authentication key",
            Some(PIN1_AUTH_ID),
            AUTH_OBJECT_ID,
            AUTH_KEY_USAGE_BITSTRING,
            Some(AUTH_KEY_REF),
        );
        prkdf_bytes.extend_from_slice(&encode_prkdf_entry(
            TAG_PRIVATE_EC_KEY,
            "signature key",
            Some(PIN2_AUTH_ID),
            SIGN_OBJECT_ID,
            SIGN_KEY_USAGE_BITSTRING,
            Some(SIGN_KEY_REF),
        ));

        let cdf =
            match CertificateDirectory::of(FileContent::from_read(cdf_bytes, FileEnd::Confirmed)) {
                CertificateDirectoryRead::Parsed(cdf) => Some(cdf),
                CertificateDirectoryRead::Incomplete | CertificateDirectoryRead::Malformed => None,
            }
            .expect("CDF parses");
        let prkdf = match PrivateKeyDirectory::of(FileContent::from_read(
            prkdf_bytes,
            FileEnd::Confirmed,
        )) {
            PrivateKeyDirectoryRead::Parsed(prkdf) => Some(prkdf),
            PrivateKeyDirectoryRead::Incomplete | PrivateKeyDirectoryRead::Malformed => None,
        }
        .expect("PrKDF parses");
        let paired = CredentialDirectory::of(&cdf, &prkdf).expect("credentials pair cleanly");
        let auth = match paired.unique_authentication_credential() {
            AuthenticationCredentialLookup::Unique(auth) => Some(auth),
            AuthenticationCredentialLookup::Absent | AuthenticationCredentialLookup::Ambiguous => {
                None
            }
        }
        .expect("must select unique authentication credential");
        assert_eq!(auth.identifier().as_bytes(), &[AUTH_OBJECT_ID]);
        assert!(auth.certificate().is_x509());
        assert_eq!(auth.file(), Some(AUTH_CERT_FID));
        assert_eq!(
            auth.key().auth_id().map(super::ObjectIdentifier::as_bytes),
            Some([PIN1_AUTH_ID].as_slice())
        );
        assert_eq!(
            auth.key_reference().map(super::KeyReference::as_u8),
            Some(AUTH_KEY_REF)
        );

        let sign = match paired.unique_qualified_signature_credential() {
            QualifiedSignatureCredentialLookup::Unique(sign) => Some(sign),
            QualifiedSignatureCredentialLookup::Absent
            | QualifiedSignatureCredentialLookup::Ambiguous => None,
        }
        .expect("must select unique qualified signature credential");
        assert_eq!(sign.identifier().as_bytes(), &[SIGN_OBJECT_ID]);
        assert!(sign.certificate().is_x509());
        assert_eq!(sign.file(), Some(SIGN_CERT_FID));
        assert_eq!(
            sign.key().auth_id().map(super::ObjectIdentifier::as_bytes),
            Some([PIN2_AUTH_ID].as_slice())
        );
        assert_eq!(
            sign.key_reference().map(super::KeyReference::as_u8),
            Some(SIGN_KEY_REF)
        );

        let sample = FileContent::from_read(vec![FILLER_BYTE; SAMPLE_FILE_LEN], FileEnd::Confirmed);
        let sliced = sample
            .apply_path_slice(auth.path().and_then(super::Pkcs15Path::slice))
            .expect("path slice applies");
        assert_eq!(sliced.len(), usize::from(SLICE_LENGTH));
    }

    #[test]
    fn credential_pairing_allows_orphans_and_refuses_duplicates() {
        const ORPHAN_CERT_ID: u8 = 0x31;
        const ORPHAN_KEY_ID: u8 = 0x32;
        const ORPHAN_KEY_REF: u8 = 0x09;
        const BAD_UNUSED_BITSTRING: &[u8] = &[0x06, 0x41];

        // Non-zero trailing unused BIT STRING bits are rejected per X.690 8.6.2.2.
        assert!(KeyUsageFlags::parse_bit_string(BAD_UNUSED_BITSTRING).is_none());

        let single_cdf = encode_cdf_entry(
            TAG_X509_ATTRIBUTE_CERTIFICATE,
            "attr cert",
            AUTH_OBJECT_ID,
            &[FileId::MF, AUTH_CERT_FID],
            None,
        );
        let cdf = match CertificateDirectory::of(FileContent::from_read(
            single_cdf,
            FileEnd::Confirmed,
        )) {
            CertificateDirectoryRead::Parsed(cdf) => Some(cdf),
            CertificateDirectoryRead::Incomplete | CertificateDirectoryRead::Malformed => None,
        }
        .expect("CDF parses");
        assert!(!cdf.entries()[0].is_x509());

        let prkdf =
            match PrivateKeyDirectory::of(FileContent::from_read(Vec::new(), FileEnd::Confirmed)) {
                PrivateKeyDirectoryRead::Parsed(prkdf) => Some(prkdf),
                PrivateKeyDirectoryRead::Incomplete | PrivateKeyDirectoryRead::Malformed => None,
            }
            .expect("empty PrKDF parses");
        let empty_paired =
            CredentialDirectory::of(&cdf, &prkdf).expect("unpaired certificate is ignored");
        assert!(empty_paired.entries().is_empty());
        assert_eq!(
            empty_paired.unique_authentication_credential(),
            AuthenticationCredentialLookup::Absent
        );
        assert_eq!(
            empty_paired.unique_qualified_signature_credential(),
            QualifiedSignatureCredentialLookup::Absent
        );

        // Orphan CA cert in CDF and extra orphan key in PrKDF alongside a valid auth credential,
        // plus trailing FF EEPROM padding.
        let mut mixed_cdf_bytes = encode_cdf_entry(
            DER_SEQUENCE_TAG_OCTET,
            "auth cert",
            AUTH_OBJECT_ID,
            &[FileId::MF, CERT_DF_FID, AUTH_CERT_FID],
            None,
        );
        mixed_cdf_bytes.extend_from_slice(&encode_cdf_entry(
            DER_SEQUENCE_TAG_OCTET,
            "orphan ca cert",
            ORPHAN_CERT_ID,
            &[FileId::MF, SIGN_CERT_FID],
            None,
        ));
        mixed_cdf_bytes.extend_from_slice(&[PADDING_FF_OCTET, PADDING_FF_OCTET]);
        let mixed_cdf = match CertificateDirectory::of(FileContent::from_read(
            mixed_cdf_bytes,
            FileEnd::Confirmed,
        )) {
            CertificateDirectoryRead::Parsed(cdf) => Some(cdf),
            CertificateDirectoryRead::Incomplete | CertificateDirectoryRead::Malformed => None,
        }
        .expect("CDF with trailing FF padding parses");

        let mut mixed_prkdf_bytes = encode_prkdf_entry(
            TAG_PRIVATE_EC_KEY,
            "auth key",
            Some(PIN1_AUTH_ID),
            AUTH_OBJECT_ID,
            AUTH_KEY_USAGE_BITSTRING,
            Some(AUTH_KEY_REF),
        );
        mixed_prkdf_bytes.extend_from_slice(&encode_prkdf_entry(
            TAG_PRIVATE_EC_KEY,
            "orphan extra key",
            Some(PIN2_AUTH_ID),
            ORPHAN_KEY_ID,
            SIGN_KEY_USAGE_BITSTRING,
            Some(ORPHAN_KEY_REF),
        ));
        mixed_prkdf_bytes.extend_from_slice(&[PADDING_FF_OCTET, PADDING_FF_OCTET]);
        let mixed_prkdf = match PrivateKeyDirectory::of(FileContent::from_read(
            mixed_prkdf_bytes,
            FileEnd::Confirmed,
        )) {
            PrivateKeyDirectoryRead::Parsed(prkdf) => Some(prkdf),
            PrivateKeyDirectoryRead::Incomplete | PrivateKeyDirectoryRead::Malformed => None,
        }
        .expect("PrKDF with trailing FF padding parses");

        let paired = CredentialDirectory::of(&mixed_cdf, &mixed_prkdf)
            .expect("orphans do not break pairing");
        assert_eq!(paired.entries().len(), 1);
        assert!(matches!(
            paired.unique_authentication_credential(),
            AuthenticationCredentialLookup::Unique(cred)
                if cred.key_reference().map(super::KeyReference::as_u8) == Some(AUTH_KEY_REF)
        ));

        // Duplicate certificate identifier is still rejected.
        let mut dup_cdf_bytes = encode_cdf_entry(
            DER_SEQUENCE_TAG_OCTET,
            "auth 1",
            AUTH_OBJECT_ID,
            &[FileId::MF, AUTH_CERT_FID],
            None,
        );
        dup_cdf_bytes.extend_from_slice(&encode_cdf_entry(
            DER_SEQUENCE_TAG_OCTET,
            "auth 2",
            AUTH_OBJECT_ID,
            &[FileId::MF, SIGN_CERT_FID],
            None,
        ));
        let dup_cdf = match CertificateDirectory::of(FileContent::from_read(
            dup_cdf_bytes,
            FileEnd::Confirmed,
        )) {
            CertificateDirectoryRead::Parsed(cdf) => Some(cdf),
            CertificateDirectoryRead::Incomplete | CertificateDirectoryRead::Malformed => None,
        }
        .expect("duplicate-ID CDF parses syntactically");
        assert_eq!(
            CredentialDirectory::of(&dup_cdf, &mixed_prkdf),
            Err(CredentialPairingError::DuplicateCertificate)
        );

        // Two paired nonRepudiation credentials resolve to Ambiguous rather than picking the first.
        const SECOND_SIGN_ID: u8 = 0x41;
        const SECOND_SIGN_KEY_REF: u8 = 0x06;
        let mut ambig_cdf_bytes = encode_cdf_entry(
            DER_SEQUENCE_TAG_OCTET,
            "sign 1",
            SIGN_OBJECT_ID,
            &[FileId::MF, SIGN_CERT_FID],
            None,
        );
        ambig_cdf_bytes.extend_from_slice(&encode_cdf_entry(
            DER_SEQUENCE_TAG_OCTET,
            "sign 2",
            SECOND_SIGN_ID,
            &[FileId::MF, AUTH_CERT_FID],
            None,
        ));
        let ambig_cdf = match CertificateDirectory::of(FileContent::from_read(
            ambig_cdf_bytes,
            FileEnd::Confirmed,
        )) {
            CertificateDirectoryRead::Parsed(cdf) => Some(cdf),
            CertificateDirectoryRead::Incomplete | CertificateDirectoryRead::Malformed => None,
        }
        .expect("ambiguous CDF parses");
        let mut ambig_prkdf_bytes = encode_prkdf_entry(
            TAG_PRIVATE_EC_KEY,
            "sign key 1",
            Some(PIN2_AUTH_ID),
            SIGN_OBJECT_ID,
            SIGN_KEY_USAGE_BITSTRING,
            Some(SIGN_KEY_REF),
        );
        ambig_prkdf_bytes.extend_from_slice(&encode_prkdf_entry(
            TAG_PRIVATE_EC_KEY,
            "sign key 2",
            Some(PIN2_AUTH_ID),
            SECOND_SIGN_ID,
            SIGN_KEY_USAGE_BITSTRING,
            Some(SECOND_SIGN_KEY_REF),
        ));
        let ambig_prkdf = match PrivateKeyDirectory::of(FileContent::from_read(
            ambig_prkdf_bytes,
            FileEnd::Confirmed,
        )) {
            PrivateKeyDirectoryRead::Parsed(prkdf) => Some(prkdf),
            PrivateKeyDirectoryRead::Incomplete | PrivateKeyDirectoryRead::Malformed => None,
        }
        .expect("ambiguous PrKDF parses");
        let ambig_paired = CredentialDirectory::of(&ambig_cdf, &ambig_prkdf)
            .expect("distinct sign credentials pair");
        assert_eq!(
            ambig_paired.unique_qualified_signature_credential(),
            QualifiedSignatureCredentialLookup::Ambiguous
        );

        // Non-padding data after FF padding is rejected.
        let mut bad_ff_odf = tlv(
            TAG_CERTIFICATES,
            encode_path(&[FileId::MF, ODF_CDF_FID], None),
        )
        .expect("encodes");
        bad_ff_odf.extend_from_slice(&[PADDING_FF_OCTET, NON_ZERO_TRAILER]);
        assert_eq!(
            ObjectDirectory::of(FileContent::from_read(bad_ff_odf, FileEnd::Confirmed)),
            ObjectDirectoryRead::Malformed
        );

        // Non-path ObjectValue forms parse cleanly as path() == None.
        let non_path_values = [
            tlv(tag1(TAG_PRINTABLE_STRING), b"https://example.invalid").expect("encodes"),
            tlv(TAG_DIRECT_OBJECT_VALUE, [FILLER_BYTE]).expect("encodes"),
        ];
        for raw_val in non_path_values {
            let common = tlv(tag1(TAG_SEQUENCE), []).expect("encodes");
            let class = tlv(
                tag1(TAG_SEQUENCE),
                tlv(tag1(TAG_OCTET_STRING), [AUTH_OBJECT_ID]).expect("encodes"),
            )
            .expect("encodes");
            let attrs = tlv(tag1(TAG_SEQUENCE), raw_val).expect("encodes");
            let type_attrs = tlv(tag1(TAG_TYPE_ATTRIBUTES), attrs).expect("encodes");
            let mut body = common;
            body.extend_from_slice(&class);
            body.extend_from_slice(&type_attrs);
            let record = tlv(DER_SEQUENCE_TAG_OCTET, body).expect("encodes");
            let parsed = match CertificateDirectory::of(FileContent::from_read(
                record,
                FileEnd::Confirmed,
            )) {
                CertificateDirectoryRead::Parsed(parsed) => Some(parsed),
                CertificateDirectoryRead::Incomplete | CertificateDirectoryRead::Malformed => None,
            }
            .expect("non-path CDF record parses");
            assert!(parsed.entries()[0].path().is_none());
        }
    }
}
