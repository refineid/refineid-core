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

//! EF.AOD parsing: the length bounds of the card's password objects.
//!
//! EF.AOD (Authentication Object Directory) lists the card's
//! authentication objects as ISO/IEC 7816-15 `AuthenticationObjectChoice`
//! values (FINEID S4-1 v4.2 section 8.1.5; FINEID S4-2 v4.0 sections
//! 4.6.10 and 4.7.10). A password object carries `PasswordAttributes`:
//!
//! ```text
//! PasswordAttributes ::= SEQUENCE {
//!     pwdFlags      PasswordFlags,        -- BIT STRING
//!     pwdType       PasswordType,         -- ENUMERATED
//!     minLength     INTEGER,
//!     storedLength  INTEGER,
//!     maxLength     INTEGER OPTIONAL,
//!     pwdReference  [0] Reference DEFAULT 0,
//!     padChar       OCTET STRING OPTIONAL,
//!     ... }
//! ```
//!
//! What this software consults is the reference and the length range, so
//! a password object is deconstructed to exactly those: the reference the
//! card names it by, and the shortest and longest value it accepts. The
//! longest is `maxLength` when the card lists it, and `storedLength`
//! otherwise.

use core::fmt;

use refineid_apdu::FileId;
use refineid_ber::{BerError, BerTag, BerTlv, BerTlvAny, BerTlvIter, BitString, Integer, Sequence};

/// EF.AOD, the Authentication Object Directory, under the PKCS#15
/// application (FINEID S4-1 v4.2 section 8.1.5; FINEID S4-2 v4.0
/// sections 4.6.10 and 4.7.10).
pub const EF_AOD_FID: FileId = FileId::from_u16(0x4401);

/// The end-of-contents octet (ITU-T X.690 section 8.1.5). No PKCS#15
/// object starts with it, so at an object boundary it begins the file's
/// zero padding.
const END_OF_CONTENTS_OCTET: u8 = 0x00;

/// ASN.1 universal `ENUMERATED` (ITU-T X.680 section 20), the
/// `pwdType` encoding.
const ENUMERATED_TAG: u16 = 0x0A;

/// `typeAttributes [1]` of a PKCS#15 object, constructed: it wraps the
/// `PasswordAttributes` SEQUENCE.
const TYPE_ATTRIBUTES_TAG: u16 = 0xA1;

/// `pwdReference [0]`, an implicitly tagged INTEGER.
const PWD_REFERENCE_TAG: u16 = 0x80;

/// The `pwdReference` value when the card omits it (`DEFAULT 0`).
const PWD_REFERENCE_DEFAULT: u8 = 0;

/// `pwdType` `ascii-numeric(1)`: one byte per character, as FINEID cards
/// list their PINs and the PUK.
const PASSWORD_TYPE_ASCII_NUMERIC: u8 = 1;
/// `pwdType` `utf8(2)`: a digit is one byte, so the lengths count digits
/// as for `ascii-numeric`.
const PASSWORD_TYPE_UTF8: u8 = 2;

/// The shortest and longest value a credential accepts, in digits.
///
/// The predicate is `1 <= min <= max`: an empty credential has no
/// meaning and a range whose minimum exceeds its maximum admits nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordLengthRange {
    min: u8,
    max: u8,
}

impl PasswordLengthRange {
    /// A range from `min` to `max` digits, or `None` unless
    /// `1 <= min <= max`.
    #[must_use]
    pub const fn new(min: u8, max: u8) -> Option<Self> {
        if min == 0 || min > max {
            return None;
        }
        Some(Self { min, max })
    }

    /// Shortest accepted value, in digits.
    #[must_use]
    pub const fn min(self) -> usize {
        self.min as usize
    }

    /// Longest accepted value, in digits.
    #[must_use]
    pub const fn max(self) -> usize {
        self.max as usize
    }

    /// Whether a value of `digit_count` digits lies in the range.
    #[must_use]
    pub const fn contains(self, digit_count: usize) -> bool {
        digit_count >= self.min() && digit_count <= self.max()
    }

    /// The digit counts both ranges accept, or `None` when they share
    /// none.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Option<Self> {
        let min = if self.min > other.min {
            self.min
        } else {
            other.min
        };
        let max = if self.max < other.max {
            self.max
        } else {
            other.max
        };
        Self::new(min, max)
    }
}

/// One password object from EF.AOD: the reference the card names it by
/// and the length range it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordObject {
    reference: u8,
    lengths: PasswordLengthRange,
}

impl PasswordObject {
    /// `pwdReference` as the card lists it.
    #[must_use]
    pub const fn reference(&self) -> u8 {
        self.reference
    }

    /// The accepted length range: `minLength` to `maxLength`, or to
    /// `storedLength` when `maxLength` is absent.
    #[must_use]
    pub const fn lengths(&self) -> PasswordLengthRange {
        self.lengths
    }
}

/// The password objects EF.AOD lists, in file order.
///
/// A value exists only as the result of
/// [`AuthenticationObjects::parse`]. Objects of the other authentication
/// kinds (biometric templates, authentication keys, external
/// authentication) are not password objects and are not kept. A password
/// object is kept only when its lengths count digits (`ascii-numeric` or
/// `utf8`), its reference and lengths fit one octet, and its range
/// satisfies [`PasswordLengthRange::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationObjects {
    passwords: Vec<PasswordObject>,
}

/// Why EF.AOD bytes did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationObjectsError {
    /// A TLV did not frame.
    Ber(BerError),
    /// A password object lacks a mandatory element, or carries it under
    /// another tag; the label names the element.
    MissingElement(&'static str),
    /// Bytes other than zero follow the zero padding.
    DataAfterPadding,
}

impl fmt::Display for AuthenticationObjectsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ber(error) => write!(f, "EF.AOD: {error}"),
            Self::MissingElement(what) => write!(f, "EF.AOD: password object lacks {what}"),
            Self::DataAfterPadding => f.write_str("EF.AOD: data after the zero padding"),
        }
    }
}

impl core::error::Error for AuthenticationObjectsError {}

impl From<BerError> for AuthenticationObjectsError {
    fn from(error: BerError) -> Self {
        Self::Ber(error)
    }
}

impl AuthenticationObjects {
    /// The password objects, in file order.
    #[must_use]
    pub fn passwords(&self) -> &[PasswordObject] {
        &self.passwords
    }

    /// Parse the contents of EF.AOD.
    ///
    /// The file is a concatenation of authentication objects, optionally
    /// followed by zero padding to the file size. Every object must frame
    /// as BER, and every password object must carry its mandatory
    /// `PasswordAttributes` elements under their tags; any failure there
    /// rejects the whole file.
    ///
    /// # Errors
    ///
    /// [`AuthenticationObjectsError`] when a TLV does not frame, a
    /// password object lacks a mandatory element, or non-zero bytes follow
    /// the padding.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthenticationObjectsError> {
        let mut passwords = Vec::new();
        let mut rest = bytes;
        while let Some(&first) = rest.first() {
            if first == END_OF_CONTENTS_OCTET {
                if rest.iter().all(|&byte| byte == END_OF_CONTENTS_OCTET) {
                    break;
                }
                return Err(AuthenticationObjectsError::DataAfterPadding);
            }
            let object = BerTlvAny::parse(rest)?;
            rest = rest.get(object.size()..).unwrap_or(&[]);
            if object.tag() != <Sequence as BerTag>::TAG {
                continue;
            }
            if let Some(password) = password_object(object.value())? {
                passwords.push(password);
            }
        }
        Ok(Self { passwords })
    }
}

/// Decode one password object's content: the common and class
/// attributes, an optional subclass, and `typeAttributes [1]`.
fn password_object(content: &[u8]) -> Result<Option<PasswordObject>, AuthenticationObjectsError> {
    let children = BerTlvIter::new(content).collect::<Result<Vec<_>, _>>()?;
    let type_attributes = children
        .iter()
        .find(|child| child.tag() == TYPE_ATTRIBUTES_TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("typeAttributes"))?;
    let attributes = BerTlv::<Sequence>::parse(type_attributes.value())?;
    password_attributes(attributes.value())
}

/// Decode `PasswordAttributes` by position: flags, type, minimum and
/// stored length, then the optional maximum length and reference.
fn password_attributes(
    content: &[u8],
) -> Result<Option<PasswordObject>, AuthenticationObjectsError> {
    let fields = BerTlvIter::new(content).collect::<Result<Vec<_>, _>>()?;
    let mut fields = fields.iter().peekable();

    fields
        .next()
        .filter(|field| field.tag() == <BitString as BerTag>::TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("pwdFlags"))?;
    let password_type = fields
        .next()
        .filter(|field| field.tag() == ENUMERATED_TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("pwdType"))?;
    let min_length = fields
        .next()
        .filter(|field| field.tag() == <Integer as BerTag>::TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("minLength"))?;
    let stored_length = fields
        .next()
        .filter(|field| field.tag() == <Integer as BerTag>::TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("storedLength"))?;
    let max_length = fields.next_if(|field| field.tag() == <Integer as BerTag>::TAG);
    let reference = fields.next_if(|field| field.tag() == PWD_REFERENCE_TAG);

    if !matches!(
        unsigned_octet(password_type.value()),
        Some(PASSWORD_TYPE_ASCII_NUMERIC | PASSWORD_TYPE_UTF8)
    ) {
        return Ok(None);
    }
    let reference = match reference {
        Some(field) => unsigned_octet(field.value()),
        None => Some(PWD_REFERENCE_DEFAULT),
    };
    let min = unsigned_octet(min_length.value());
    let max = unsigned_octet(max_length.unwrap_or(stored_length).value());
    let (Some(reference), Some(min), Some(max)) = (reference, min, max) else {
        return Ok(None);
    };
    Ok(PasswordLengthRange::new(min, max).map(|lengths| PasswordObject { reference, lengths }))
}

/// An INTEGER or ENUMERATED content read as an unsigned magnitude that
/// fits one octet: leading zero octets are dropped, so both the DER form
/// of a reference with its high bit set (a zero octet, then the
/// reference) and the bare octet read as the reference. `None` for an
/// empty content or a magnitude above one octet.
fn unsigned_octet(content: &[u8]) -> Option<u8> {
    let first_significant = content
        .iter()
        .position(|&byte| byte != END_OF_CONTENTS_OCTET);
    match first_significant {
        None => content.first().copied(),
        Some(start) => match content.get(start..) {
            Some([only]) => Some(*only),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use refineid_ber::{BerEncoder, BerTag, BitString, Integer, OctetString, Sequence, Utf8String};

    use super::{
        AuthenticationObjects, AuthenticationObjectsError, END_OF_CONTENTS_OCTET, ENUMERATED_TAG,
        PASSWORD_TYPE_ASCII_NUMERIC, PWD_REFERENCE_DEFAULT, PWD_REFERENCE_TAG, PasswordLengthRange,
        TYPE_ATTRIBUTES_TAG,
    };

    /// FINEID S4-1 v4.2 section 8.1.5: PIN 1's reference, minimum and
    /// stored length on a citizen card.
    const CITIZEN_PIN1_REFERENCE: u8 = 17;
    const CITIZEN_PIN1_MIN: u8 = 4;
    /// PIN 2's reference and minimum length on a citizen card.
    const CITIZEN_PIN2_REFERENCE: u8 = 130;
    const CITIZEN_PIN2_MIN: u8 = 6;
    /// The PUK's reference and minimum length on a citizen card.
    const CITIZEN_PUK_REFERENCE: u8 = 131;
    const CITIZEN_PUK_MIN: u8 = 8;
    /// The stored length every citizen password object lists.
    const CITIZEN_STORED_LENGTH: u8 = 12;
    /// An organization card's PIN 1 object: reference, minimum, stored
    /// and maximum length.
    const ORGANIZATION_PIN1_REFERENCE: u8 = 3;
    const ORGANIZATION_PIN1_MIN: u8 = 4;
    const ORGANIZATION_PIN1_STORED: u8 = 12;
    const ORGANIZATION_PIN1_MAX: u8 = 8;
    /// `pwdType` `bcd(0)`: the lengths do not count digits one per byte.
    const PASSWORD_TYPE_BCD: u8 = 0;
    /// `pwdFlags` content of the fixtures: no unused bits, one flag
    /// octet; the flags are not consulted.
    const FLAGS_UNUSED_BITS: u8 = 0;
    const FLAGS_OCTET: u8 = 0;
    /// The authId of the fixture objects; not consulted.
    const AUTH_ID: u8 = 1;
    /// `padChar` of the fixture objects.
    const PAD_CHAR: u8 = 0;
    /// A context tag for an authentication object of another kind
    /// (`authKey`).
    const OTHER_AUTHENTICATION_KIND_TAG: u8 = 0xA1;
    /// Zero padding after the objects.
    const PADDING_LENGTH: usize = 16;
    /// A magnitude above one octet.
    const TWO_OCTET_LENGTH: u16 = 300;

    fn tag(value: u16) -> u8 {
        u8::try_from(value).expect("one-octet tag")
    }

    /// The minimal DER INTEGER content of `value`: a zero octet first
    /// when the high bit is set.
    fn integer(value: u8) -> Vec<u8> {
        if value.leading_zeros() == 0 {
            vec![END_OF_CONTENTS_OCTET, value]
        } else {
            vec![value]
        }
    }

    #[derive(Clone, Copy)]
    struct Fixture {
        password_type: u8,
        min: u8,
        stored: u8,
        max: Option<u8>,
        reference: Option<u8>,
    }

    impl Fixture {
        const fn citizen(reference: u8, min: u8) -> Self {
            Self {
                password_type: PASSWORD_TYPE_ASCII_NUMERIC,
                min,
                stored: CITIZEN_STORED_LENGTH,
                max: None,
                reference: Some(reference),
            }
        }
    }

    fn attributes(fixture: Fixture) -> Vec<u8> {
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(
                tag(<BitString as BerTag>::TAG),
                [FLAGS_UNUSED_BITS, FLAGS_OCTET],
            )
            .expect("encodes");
        fields
            .push_tlv(tag(ENUMERATED_TAG), [fixture.password_type])
            .expect("encodes");
        fields
            .push_tlv(tag(<Integer as BerTag>::TAG), integer(fixture.min))
            .expect("encodes");
        fields
            .push_tlv(tag(<Integer as BerTag>::TAG), integer(fixture.stored))
            .expect("encodes");
        if let Some(max) = fixture.max {
            fields
                .push_tlv(tag(<Integer as BerTag>::TAG), integer(max))
                .expect("encodes");
        }
        if let Some(reference) = fixture.reference {
            fields
                .push_tlv(tag(PWD_REFERENCE_TAG), integer(reference))
                .expect("encodes");
        }
        fields
            .push_tlv(tag(<OctetString as BerTag>::TAG), [PAD_CHAR])
            .expect("encodes");
        fields.finish()
    }

    fn object_around(attributes: &[u8]) -> Vec<u8> {
        let mut common = BerEncoder::default();
        common
            .push_tlv(tag(<Utf8String as BerTag>::TAG), b"perustunnusluku")
            .expect("encodes");
        let mut class = BerEncoder::default();
        class
            .push_tlv(tag(<OctetString as BerTag>::TAG), [AUTH_ID])
            .expect("encodes");
        let mut typed = BerEncoder::default();
        typed
            .push_tlv(tag(<Sequence as BerTag>::TAG), attributes)
            .expect("encodes");
        let mut object = BerEncoder::default();
        object
            .push_tlv(tag(<Sequence as BerTag>::TAG), common.finish())
            .expect("encodes");
        object
            .push_tlv(tag(<Sequence as BerTag>::TAG), class.finish())
            .expect("encodes");
        object
            .push_tlv(tag(TYPE_ATTRIBUTES_TAG), typed.finish())
            .expect("encodes");
        let mut outer = BerEncoder::default();
        outer
            .push_tlv(tag(<Sequence as BerTag>::TAG), object.finish())
            .expect("encodes");
        outer.finish()
    }

    fn file(fixtures: &[Fixture]) -> Vec<u8> {
        fixtures
            .iter()
            .flat_map(|fixture| object_around(&attributes(*fixture)))
            .collect()
    }

    fn range(min: u8, max: u8) -> PasswordLengthRange {
        PasswordLengthRange::new(min, max).expect("valid range")
    }

    #[test]
    fn the_citizen_layout_lists_three_password_objects() {
        let bytes = file(&[
            Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN),
            Fixture::citizen(CITIZEN_PIN2_REFERENCE, CITIZEN_PIN2_MIN),
            Fixture::citizen(CITIZEN_PUK_REFERENCE, CITIZEN_PUK_MIN),
        ]);
        let objects = AuthenticationObjects::parse(&bytes).expect("parses");
        let listed: Vec<_> = objects
            .passwords()
            .iter()
            .map(|object| (object.reference(), object.lengths()))
            .collect();
        assert_eq!(
            listed,
            [
                (
                    CITIZEN_PIN1_REFERENCE,
                    range(CITIZEN_PIN1_MIN, CITIZEN_STORED_LENGTH)
                ),
                (
                    CITIZEN_PIN2_REFERENCE,
                    range(CITIZEN_PIN2_MIN, CITIZEN_STORED_LENGTH)
                ),
                (
                    CITIZEN_PUK_REFERENCE,
                    range(CITIZEN_PUK_MIN, CITIZEN_STORED_LENGTH)
                ),
            ]
        );
    }

    #[test]
    fn max_length_wins_over_stored_length() {
        let bytes = file(&[Fixture {
            password_type: PASSWORD_TYPE_ASCII_NUMERIC,
            min: ORGANIZATION_PIN1_MIN,
            stored: ORGANIZATION_PIN1_STORED,
            max: Some(ORGANIZATION_PIN1_MAX),
            reference: Some(ORGANIZATION_PIN1_REFERENCE),
        }]);
        let objects = AuthenticationObjects::parse(&bytes).expect("parses");
        assert_eq!(objects.passwords().len(), 1);
        let object = objects.passwords()[0];
        assert_eq!(object.reference(), ORGANIZATION_PIN1_REFERENCE);
        assert_eq!(
            object.lengths(),
            range(ORGANIZATION_PIN1_MIN, ORGANIZATION_PIN1_MAX)
        );
    }

    #[test]
    fn an_absent_reference_reads_as_the_default() {
        let fixture = Fixture {
            reference: None,
            ..Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN)
        };
        let objects = AuthenticationObjects::parse(&file(&[fixture])).expect("parses");
        assert_eq!(objects.passwords()[0].reference(), PWD_REFERENCE_DEFAULT);
    }

    #[test]
    fn zero_padding_ends_the_file_and_other_bytes_after_it_reject_it() {
        let mut bytes = file(&[Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN)]);
        bytes.resize(bytes.len() + PADDING_LENGTH, END_OF_CONTENTS_OCTET);
        assert_eq!(
            AuthenticationObjects::parse(&bytes)
                .expect("parses")
                .passwords()
                .len(),
            1
        );
        bytes.push(CITIZEN_PIN1_MIN);
        assert_eq!(
            AuthenticationObjects::parse(&bytes),
            Err(AuthenticationObjectsError::DataAfterPadding)
        );
    }

    #[test]
    fn objects_of_other_kinds_and_other_length_units_are_not_kept() {
        let mut bytes = Vec::new();
        let mut other = BerEncoder::default();
        other
            .push_tlv(
                OTHER_AUTHENTICATION_KIND_TAG,
                attributes(Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN)),
            )
            .expect("encodes");
        bytes.extend(other.finish());
        bytes.extend(file(&[Fixture {
            password_type: PASSWORD_TYPE_BCD,
            ..Fixture::citizen(CITIZEN_PIN2_REFERENCE, CITIZEN_PIN2_MIN)
        }]));
        let objects = AuthenticationObjects::parse(&bytes).expect("parses");
        assert!(objects.passwords().is_empty());
    }

    #[test]
    fn an_object_whose_range_admits_nothing_is_not_kept() {
        let inverted = Fixture {
            min: CITIZEN_STORED_LENGTH,
            stored: CITIZEN_PIN1_MIN,
            ..Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN)
        };
        let zero_minimum = Fixture {
            min: 0,
            ..Fixture::citizen(CITIZEN_PIN2_REFERENCE, CITIZEN_PIN2_MIN)
        };
        let objects =
            AuthenticationObjects::parse(&file(&[inverted, zero_minimum])).expect("parses");
        assert!(objects.passwords().is_empty());
    }

    #[test]
    fn a_length_above_one_octet_is_not_kept() {
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(
                tag(<BitString as BerTag>::TAG),
                [FLAGS_UNUSED_BITS, FLAGS_OCTET],
            )
            .expect("encodes");
        fields
            .push_tlv(tag(ENUMERATED_TAG), [PASSWORD_TYPE_ASCII_NUMERIC])
            .expect("encodes");
        fields
            .push_tlv(tag(<Integer as BerTag>::TAG), integer(CITIZEN_PIN1_MIN))
            .expect("encodes");
        fields
            .push_tlv(
                tag(<Integer as BerTag>::TAG),
                TWO_OCTET_LENGTH.to_be_bytes(),
            )
            .expect("encodes");
        let objects =
            AuthenticationObjects::parse(&object_around(&fields.finish())).expect("parses");
        assert!(objects.passwords().is_empty());
    }

    #[test]
    fn a_password_object_missing_a_mandatory_element_rejects_the_file() {
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(
                tag(<BitString as BerTag>::TAG),
                [FLAGS_UNUSED_BITS, FLAGS_OCTET],
            )
            .expect("encodes");
        fields
            .push_tlv(tag(ENUMERATED_TAG), [PASSWORD_TYPE_ASCII_NUMERIC])
            .expect("encodes");
        fields
            .push_tlv(tag(<Integer as BerTag>::TAG), integer(CITIZEN_PIN1_MIN))
            .expect("encodes");
        assert_eq!(
            AuthenticationObjects::parse(&object_around(&fields.finish())),
            Err(AuthenticationObjectsError::MissingElement("storedLength"))
        );
    }

    #[test]
    fn every_truncation_is_rejected_or_drops_objects_without_panicking() {
        let bytes = file(&[
            Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN),
            Fixture::citizen(CITIZEN_PIN2_REFERENCE, CITIZEN_PIN2_MIN),
        ]);
        let full = AuthenticationObjects::parse(&bytes).expect("parses");
        for cut in 0..bytes.len() {
            if let Ok(parsed) = AuthenticationObjects::parse(&bytes[..cut]) {
                assert!(parsed.passwords().len() < full.passwords().len());
            }
        }
    }

    #[test]
    fn ranges_intersect_to_the_shared_digit_counts() {
        let card = range(CITIZEN_PIN1_MIN, ORGANIZATION_PIN1_MAX);
        let role = range(CITIZEN_PIN2_MIN, CITIZEN_STORED_LENGTH);
        assert_eq!(
            card.intersection(role),
            Some(range(CITIZEN_PIN2_MIN, ORGANIZATION_PIN1_MAX))
        );
        let below = range(CITIZEN_PIN1_MIN, CITIZEN_PIN1_MIN);
        assert_eq!(below.intersection(role), None);
        assert!(card.contains(CITIZEN_PIN1_MIN.into()));
        assert!(!card.contains(CITIZEN_STORED_LENGTH.into()));
        assert_eq!(PasswordLengthRange::new(0, CITIZEN_PIN1_MIN), None);
        assert_eq!(
            PasswordLengthRange::new(CITIZEN_PIN2_MIN, CITIZEN_PIN1_MIN),
            None
        );
    }
}
