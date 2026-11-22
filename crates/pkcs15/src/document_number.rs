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

//! Estonian eID document-number parsing.
//!
//! The card body prints a document number that names the plastic
//! independently of the chip serial. EF.D003 carries it as one DER TLV,
//! readable without a PIN: the older card generations wrap the value in
//! a universal OCTET STRING (ID1 Developer Guide 2019, section 6.1),
//! Cosmo X in `[APPLICATION 26]` (GED24035, section 6.1).

use core::fmt;
use core::ops::Deref;

/// Tag of the document-number TLV on the older card generations: a
/// universal OCTET STRING (ID1 Developer Guide 2019, section 6.1).
const TAG_DOCUMENT_NUMBER_OCTET_STRING: u8 = 0x04;

/// Tag of the document-number TLV on Cosmo X: `[APPLICATION 26]`
/// primitive (GED24035, section 6.1).
const TAG_DOCUMENT_NUMBER_APPLICATION_26: u8 = 0x5A;

/// First octet of a short-form DER length (ITU-T X.690 section 8.1.3):
/// every document number fits it.
const SHORT_FORM_LENGTH_MAX: u8 = 0x7F;

/// Characters of the document-number format `XX9999999` every card in
/// the family prints (GED24035, section 9, PD7; ID1 Developer Guide
/// 2019, section 7).
pub const DOCUMENT_NUMBER_CHARS: usize = 9;

/// Leading characters that are uppercase ASCII letters.
const LETTER_PREFIX_CHARS: usize = 2;

/// A document number read from EF.D003.
///
/// The printed number names the plastic: two uppercase ASCII letters
/// followed by seven ASCII digits (GED24035, section 9, PD7). A value
/// exists only as the result of [`DocumentNumber::parse_tlv`] or
/// [`DocumentNumber::from_ascii`], so the shape is checked once at the
/// card border and downstream code may quote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentNumber(String);

impl DocumentNumber {
    /// Validating constructor: decode the EF.D003 TLV and check the
    /// document-number predicate.
    ///
    /// # Errors
    ///
    /// [`DocumentNumberError`] when the TLV is truncated, carries a tag
    /// or length form the card family does not use, or holds text that
    /// is not the printed `XX9999999` shape.
    pub fn parse_tlv(tlv: &[u8]) -> Result<Self, DocumentNumberError> {
        let (&tag, rest) = tlv.split_first().ok_or(DocumentNumberError::Truncated)?;
        let (&length_octet, content) = rest.split_first().ok_or(DocumentNumberError::Truncated)?;
        if tag != TAG_DOCUMENT_NUMBER_OCTET_STRING && tag != TAG_DOCUMENT_NUMBER_APPLICATION_26 {
            return Err(DocumentNumberError::UnexpectedTag);
        }
        if length_octet > SHORT_FORM_LENGTH_MAX {
            return Err(DocumentNumberError::LongFormLength);
        }
        let length = usize::from(length_octet);
        let value = content
            .get(..length)
            .ok_or(DocumentNumberError::Truncated)?;
        if content.len() != length {
            return Err(DocumentNumberError::LengthMismatch);
        }
        Self::from_ascii(value)
    }

    /// Validating constructor: check raw document-number bytes against
    /// the printed predicate. EF.5007 under DF.DD holds the value with
    /// no TLV wrapper (GED24035, section 6.1).
    ///
    /// # Errors
    ///
    /// [`DocumentNumberError::NotAscii`] when the bytes are not UTF-8,
    /// and [`DocumentNumberError::WrongShape`] when the text is not the
    /// printed `XX9999999` shape.
    pub fn from_ascii(value: &[u8]) -> Result<Self, DocumentNumberError> {
        let text = core::str::from_utf8(value).map_err(|_ignored| DocumentNumberError::NotAscii)?;
        if !has_printed_shape(text) {
            return Err(DocumentNumberError::WrongShape);
        }
        Ok(Self(text.to_owned()))
    }

    /// Borrow the printed document number.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for DocumentNumber {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for DocumentNumber {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DocumentNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `text` is the printed `XX9999999` shape: two uppercase ASCII
/// letters, then seven ASCII digits.
fn has_printed_shape(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == DOCUMENT_NUMBER_CHARS
        && bytes
            .get(..LETTER_PREFIX_CHARS)
            .is_some_and(|prefix| prefix.iter().all(u8::is_ascii_uppercase))
        && bytes
            .get(LETTER_PREFIX_CHARS..)
            .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit))
}

/// Why EF.D003 did not yield a document number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentNumberError {
    /// The TLV ends before its tag, length, or declared content.
    Truncated,
    /// The tag is neither the OCTET STRING nor the `[APPLICATION 26]`
    /// form the card family documents.
    UnexpectedTag,
    /// The length uses the long form, which a document number never
    /// needs.
    LongFormLength,
    /// Bytes follow the declared content inside the read object.
    LengthMismatch,
    /// The content is not valid UTF-8.
    NotAscii,
    /// The content is not the printed `XX9999999` shape.
    WrongShape,
}

impl fmt::Display for DocumentNumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("document number: truncated TLV"),
            Self::UnexpectedTag => f.write_str("document number: unexpected tag"),
            Self::LongFormLength => f.write_str("document number: long-form length"),
            Self::LengthMismatch => f.write_str("document number: trailing bytes"),
            Self::NotAscii => f.write_str("document number: not UTF-8"),
            Self::WrongShape => f.write_str("document number: not the printed shape"),
        }
    }
}

impl core::error::Error for DocumentNumberError {}

#[cfg(test)]
mod tests {
    use refineid_ber::{BerTag, OctetString, Sequence, tlv};

    use super::{
        DOCUMENT_NUMBER_CHARS, DocumentNumber, DocumentNumberError,
        TAG_DOCUMENT_NUMBER_APPLICATION_26, TAG_DOCUMENT_NUMBER_OCTET_STRING,
    };

    /// Synthetic printed document number: two letters and seven digits.
    const FIXTURE_DOCUMENT_NUMBER: &str = "AB1234567";

    fn octet_string_tlv(value: &[u8]) -> Vec<u8> {
        let tag = u8::try_from(<OctetString as BerTag>::TAG).expect("tag fits one octet");
        tlv(tag, value).expect("fixture encodes")
    }

    #[test]
    fn octet_string_form_parses_the_printed_number() {
        let number =
            DocumentNumber::parse_tlv(&octet_string_tlv(FIXTURE_DOCUMENT_NUMBER.as_bytes()))
                .expect("the documented form parses");
        assert_eq!(number.as_str(), FIXTURE_DOCUMENT_NUMBER);
        assert_eq!(number.as_str().len(), DOCUMENT_NUMBER_CHARS);
        assert_eq!(
            <OctetString as BerTag>::TAG,
            u16::from(TAG_DOCUMENT_NUMBER_OCTET_STRING)
        );
    }

    #[test]
    fn application_26_form_parses_the_printed_number() {
        let der = tlv(
            TAG_DOCUMENT_NUMBER_APPLICATION_26,
            FIXTURE_DOCUMENT_NUMBER.as_bytes(),
        )
        .expect("fixture encodes");
        let number = DocumentNumber::parse_tlv(&der).expect("the Cosmo X form parses");
        assert_eq!(number.as_str(), FIXTURE_DOCUMENT_NUMBER);
    }

    #[test]
    fn raw_ascii_form_parses_the_printed_number() {
        let number = DocumentNumber::from_ascii(FIXTURE_DOCUMENT_NUMBER.as_bytes())
            .expect("the plain ASCII form parses");
        assert_eq!(number.as_str(), FIXTURE_DOCUMENT_NUMBER);
        assert_eq!(
            DocumentNumber::from_ascii(b"UB001516"),
            Err(DocumentNumberError::WrongShape)
        );
    }

    #[test]
    fn a_foreign_tag_is_refused() {
        let der = tlv(
            u8::try_from(<Sequence as BerTag>::TAG).expect("tag fits"),
            FIXTURE_DOCUMENT_NUMBER.as_bytes(),
        )
        .expect("fixture encodes");
        assert_eq!(
            DocumentNumber::parse_tlv(&der),
            Err(DocumentNumberError::UnexpectedTag)
        );
    }

    #[test]
    fn a_truncated_or_overlong_object_is_refused() {
        let der = octet_string_tlv(FIXTURE_DOCUMENT_NUMBER.as_bytes());
        assert_eq!(
            DocumentNumber::parse_tlv(&der[..der.len() - 1]),
            Err(DocumentNumberError::Truncated)
        );
        let mut trailing = der;
        trailing.push(b' ');
        assert_eq!(
            DocumentNumber::parse_tlv(&trailing),
            Err(DocumentNumberError::LengthMismatch)
        );
        assert_eq!(
            DocumentNumber::parse_tlv(&[]),
            Err(DocumentNumberError::Truncated)
        );
        assert_eq!(
            DocumentNumber::parse_tlv(&[TAG_DOCUMENT_NUMBER_OCTET_STRING]),
            Err(DocumentNumberError::Truncated)
        );
    }

    #[test]
    fn a_long_form_length_is_refused() {
        let der = [
            TAG_DOCUMENT_NUMBER_OCTET_STRING,
            super::SHORT_FORM_LENGTH_MAX.wrapping_add(1),
            u8::try_from(FIXTURE_DOCUMENT_NUMBER.len()).expect("fits"),
        ];
        assert_eq!(
            DocumentNumber::parse_tlv(&der),
            Err(DocumentNumberError::LongFormLength)
        );
    }

    #[test]
    fn text_outside_the_printed_shape_is_refused() {
        for text in [
            "AB123456",
            "AB12345670",
            "ab1234567",
            "A11234567",
            "AB123456X",
            "",
        ] {
            let der = octet_string_tlv(text.as_bytes());
            assert_eq!(
                DocumentNumber::parse_tlv(&der),
                Err(DocumentNumberError::WrongShape),
                "{text:?} must not parse as a document number"
            );
        }
        /// A non-ASCII code point, outside the printed alphabet.
        const NON_ASCII: u32 = 0x00C4;
        let mut text = String::new();
        text.push(char::from_u32(NON_ASCII).expect("valid code point"));
        text.push_str("B0015161");
        assert_eq!(
            DocumentNumber::parse_tlv(&octet_string_tlv(text.as_bytes())),
            Err(DocumentNumberError::WrongShape)
        );
    }
}
