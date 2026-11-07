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

//! EF.TokenInfo parsing.

use refineid_ber::{
    BerError, BerTag, BerTlv, BerTlvIter, Integer, OctetString, PrintableString, Sequence,
    Utf8String,
};

use crate::token_serial::{TokenSerial, hex_encode};

/// Context tag zero: the implicit-tagged label field in PKCS#15
/// `TokenInfo`, the alternate location for the label string.
const TAG_TOKEN_INFO_LABEL_IMPLICIT: u16 = 0x80;

/// The sign bit of an INTEGER's leading content octet (ITU-T X.690
/// section 8.3.3).
const INTEGER_SIGN_BIT: u8 = 0x80;

/// The octets of the `u32` that holds `TokenInfo.version`.
const VERSION_OCTETS: usize = core::mem::size_of::<u32>();

/// Subset of PKCS#15 `TokenInfo` that card-status surfaces need, per
/// ISO/IEC 7816-15 section 8.2.
///
/// A value exists only as the result of [`TokenInfo::parse`]; the fields
/// are private, so the type cannot be built past that trust boundary.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    version: u32,
    serial_number_hex: Option<TokenSerial>,
    manufacturer_id: Option<String>,
    label: Option<String>,
}

impl TokenInfo {
    /// `TokenInfo.version`: the structure's mandatory integer version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// `TokenInfo.serialNumber` as a hex string, when present: the
    /// chip-side long serial, kept distinct from the plastic-printed and
    /// certificate serials by the typed form.
    #[must_use]
    pub fn serial_number_hex(&self) -> Option<&TokenSerial> {
        self.serial_number_hex.as_ref()
    }

    /// `TokenInfo.manufacturerID`, when present.
    #[must_use]
    pub fn manufacturer_id(&self) -> Option<&str> {
        self.manufacturer_id.as_deref()
    }

    /// `TokenInfo.label`, when present.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Validating constructor: parse raw EF.TokenInfo bytes into a typed
    /// `TokenInfo`. This is the trust boundary; the card hands raw bytes
    /// and construction and validation are one step.
    ///
    /// The decode is total, not best-effort. Every child of the outer
    /// SEQUENCE must BER-decode, so a malformed sub-object is a parse
    /// error rather than a silently absent field. The mandatory `version`
    /// must be present as an INTEGER. The optional fields are consumed by
    /// position and tag, so an absent optional never swallows the field
    /// that follows it. Fields of `TokenInfo` beyond the subset modelled
    /// here are left untouched.
    ///
    /// # Errors
    ///
    /// [`BerError`] when the outer SEQUENCE or any child does not decode,
    /// or when the mandatory `version` INTEGER is absent.
    pub fn parse(der: &[u8]) -> Result<Self, BerError> {
        let outer = BerTlv::<Sequence>::parse(der)?;
        let children = BerTlvIter::new(outer.value()).collect::<Result<Vec<_>, _>>()?;
        let mut next = 0;

        // version: mandatory INTEGER (ISO/IEC 7816-15 section 8.2).
        let version_tlv = children.get(next).ok_or(BerError::Truncated)?;
        if version_tlv.tag() != <Integer as BerTag>::TAG {
            return Err(BerError::UnexpectedTag {
                expected: <Integer as BerTag>::TAG,
                got: version_tlv.tag(),
            });
        }
        let version = unsigned_version(version_tlv.value())?;
        next += 1;

        // serialNumber: OPTIONAL OCTET STRING.
        let serial_number_hex = match children.get(next) {
            Some(tlv) if tlv.tag() == <OctetString as BerTag>::TAG => {
                next += 1;
                Some(TokenSerial::new(hex_encode(tlv.value())))
            }
            _ => None,
        };

        // manufacturerID: OPTIONAL Label (a UTF-8 or printable string).
        let manufacturer_id = match children.get(next) {
            Some(tlv) if is_label_string(tlv.tag()) => {
                next += 1;
                Some(String::from_utf8_lossy(tlv.value()).into_owned())
            }
            _ => None,
        };

        // label: OPTIONAL [0]-tagged Label, or a bare Label string.
        let label = match children.get(next) {
            Some(tlv)
                if tlv.tag() == TAG_TOKEN_INFO_LABEL_IMPLICIT || is_label_string(tlv.tag()) =>
            {
                Some(String::from_utf8_lossy(tlv.value()).into_owned())
            }
            _ => None,
        };

        Ok(Self {
            version,
            serial_number_hex,
            manufacturer_id,
            label,
        })
    }
}

/// The `TokenInfo.version` INTEGER content as a `u32`: one to four
/// octets with the sign bit clear (ITU-T X.690 section 8.3).
pub(crate) fn unsigned_version(content: &[u8]) -> Result<u32, BerError> {
    let negative = content
        .first()
        .is_some_and(|&leading| leading & INTEGER_SIGN_BIT != 0);
    if content.is_empty() || negative || content.len() > VERSION_OCTETS {
        return Err(BerError::IntegerOutOfRange);
    }
    Ok(content
        .iter()
        .fold(0, |version, &byte| (version << u8::BITS) | u32::from(byte)))
}

/// Whether `tag` is one of the universal string tags a PKCS#15 `Label`
/// uses.
fn is_label_string(tag: u16) -> bool {
    tag == <Utf8String as BerTag>::TAG || tag == <PrintableString as BerTag>::TAG
}

#[cfg(test)]
mod tests {
    use refineid_ber::{
        BerEncoder, BerError, BerTag, Integer, OctetString, Sequence, Utf8String, tlv,
    };

    use super::TokenInfo;
    use crate::token_serial::{derive_printed_serial, render_token_serial};

    /// Synthetic chip serial stored in the fixture token info.
    const FIXTURE_SERIAL_TEXT: &str = "DEMO0001AB1234567";
    /// Printed tail of the fixture serial.
    const FIXTURE_PRINTED_TAIL: &str = "AB1234567";
    /// Manufacturer string in the fixture.
    const FIXTURE_MANUFACTURER: &str = "Demo Manufacturer";
    /// Label string in the fixture.
    const FIXTURE_LABEL: &str = "Demo Card";
    /// Version integer in the fixture.
    const FIXTURE_VERSION: u32 = 1;
    /// A leading content octet that widens a version INTEGER past four
    /// octets without setting its sign bit.
    const FIXTURE_VERSION_OCTET: u8 = 1;

    fn universal_tag(tag: u16) -> u8 {
        u8::try_from(tag).expect("universal tags fit one byte")
    }

    fn fixture_token_info_der() -> Vec<u8> {
        let mut inner = BerEncoder::default();
        inner
            .push_tlv(
                universal_tag(<Integer as BerTag>::TAG),
                [u8::try_from(FIXTURE_VERSION).expect("fixture version fits one byte")],
            )
            .expect("fixture encodes");
        inner
            .push_tlv(
                universal_tag(<OctetString as BerTag>::TAG),
                FIXTURE_SERIAL_TEXT.as_bytes(),
            )
            .expect("fixture encodes");
        inner
            .push_tlv(
                universal_tag(<Utf8String as BerTag>::TAG),
                FIXTURE_MANUFACTURER.as_bytes(),
            )
            .expect("fixture encodes");
        inner
            .push_tlv(
                universal_tag(<Utf8String as BerTag>::TAG),
                FIXTURE_LABEL.as_bytes(),
            )
            .expect("fixture encodes");
        tlv(universal_tag(<Sequence as BerTag>::TAG), inner.finish()).expect("fixture encodes")
    }

    /// Encode a TokenInfo SEQUENCE carrying only its mandatory version.
    fn version_only_der() -> Vec<u8> {
        let mut inner = BerEncoder::default();
        inner
            .push_tlv(
                universal_tag(<Integer as BerTag>::TAG),
                [u8::try_from(FIXTURE_VERSION).expect("fixture version fits one byte")],
            )
            .expect("fixture encodes");
        tlv(universal_tag(<Sequence as BerTag>::TAG), inner.finish()).expect("fixture encodes")
    }

    #[test]
    fn parses_the_populated_fields() {
        let info = TokenInfo::parse(&fixture_token_info_der()).expect("fixture parses");
        assert_eq!(info.version(), FIXTURE_VERSION);
        assert_eq!(info.manufacturer_id(), Some(FIXTURE_MANUFACTURER));
        assert_eq!(info.label(), Some(FIXTURE_LABEL));

        let serial_hex = info
            .serial_number_hex()
            .cloned()
            .expect("fixture carries a serial");
        let rendered = render_token_serial(serial_hex);
        assert_eq!(rendered, FIXTURE_SERIAL_TEXT);
        let printed = derive_printed_serial(&rendered).expect("fixture shape derives");
        assert_eq!(printed.as_str(), FIXTURE_PRINTED_TAIL);
    }

    #[test]
    fn optional_fields_read_as_absent() {
        let info = TokenInfo::parse(&version_only_der()).expect("version-only sequence parses");
        assert_eq!(info.version(), FIXTURE_VERSION);
        assert!(info.serial_number_hex().is_none());
        assert!(info.manufacturer_id().is_none());
        assert!(info.label().is_none());
    }

    #[test]
    fn malformed_outer_structure_is_a_hard_error() {
        let not_a_sequence =
            tlv(universal_tag(<Integer as BerTag>::TAG), [1_u8]).expect("fixture encodes");
        assert!(TokenInfo::parse(&not_a_sequence).is_err());
        assert!(TokenInfo::parse(&[]).is_err());
    }

    /// A TokenInfo SEQUENCE whose version INTEGER carries `content`.
    fn version_der(content: &[u8]) -> Vec<u8> {
        let version = tlv(universal_tag(<Integer as BerTag>::TAG), content).expect("encodes");
        tlv(universal_tag(<Sequence as BerTag>::TAG), version).expect("fixture encodes")
    }

    #[test]
    fn the_widest_unsigned_version_is_accepted() {
        let info = TokenInfo::parse(&version_der(&i32::MAX.to_be_bytes()))
            .expect("a four-octet positive version parses");
        assert_eq!(i32::try_from(info.version()), Ok(i32::MAX));
    }

    #[test]
    fn a_version_wider_than_its_field_is_refused() {
        let mut five_octets = vec![FIXTURE_VERSION_OCTET];
        five_octets.extend_from_slice(&FIXTURE_VERSION.to_be_bytes());
        assert_eq!(
            TokenInfo::parse(&version_der(&five_octets)).map(|info| info.version()),
            Err(BerError::IntegerOutOfRange)
        );
    }

    #[test]
    fn a_version_without_content_octets_is_refused() {
        assert_eq!(
            TokenInfo::parse(&version_der(&[])).map(|info| info.version()),
            Err(BerError::IntegerOutOfRange)
        );
    }

    #[test]
    fn a_negative_version_is_refused() {
        assert_eq!(
            TokenInfo::parse(&version_der(&i8::MIN.to_be_bytes())).map(|info| info.version()),
            Err(BerError::IntegerOutOfRange)
        );
    }

    #[test]
    fn a_missing_mandatory_version_is_a_hard_error() {
        let empty = tlv(universal_tag(<Sequence as BerTag>::TAG), []).expect("fixture encodes");
        assert!(TokenInfo::parse(&empty).is_err());
    }
}
