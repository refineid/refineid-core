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

//! EF.AOD parsing: authentication-object links, flags, length bounds,
//! stored lengths, references, and pad octets.
//!
//! EF.AOD (Authentication Object Directory) lists the card's
//! authentication objects as ISO/IEC 7816-15 `AuthenticationObjectChoice`
//! values (PKCS#15 v1.1 section 6.8; FINEID S4-1 v4.2 section 8.1.5;
//! FINEID S4-2 v4.0 sections 4.6.10 and 4.7.10). A password object
//! carries `CommonObjectAttributes`, `CommonAuthenticationObjectAttributes`,
//! and `PasswordAttributes`:
//!
//! ```text
//! PasswordAttributes ::= SEQUENCE {
//!     pwdFlags      PasswordFlags,        -- BIT STRING
//!     pwdType       PasswordType,         -- ENUMERATED
//!     minLength     INTEGER,
//!     storedLength  INTEGER,
//!     maxLength     INTEGER OPTIONAL,
//!     pwdReference  [0] Reference DEFAULT 0,
//!     padChar       OCTET STRING (SIZE(1)) OPTIONAL,
//!     ... }
//! ```

use core::fmt;

use refineid_apdu::FileId;
use refineid_ber::{
    BerError, BerTag, BerTlv, BerTlvAny, BerTlvIter, BitString, Integer, OctetString, Sequence,
};

use crate::directory::{
    FileContent, FileEnd, ObjectIdentifier, bit_string_flag, parse_common_object_attributes,
    validate_bit_string,
};

/// EF.AOD, the Authentication Object Directory, under the FINEID
/// PKCS#15 application (FINEID S4-1 v4.2 section 8.1.5; FINEID S4-2
/// v4.0 sections 4.6.10 and 4.7.10). Other ISO/IEC 7816-15 cards
/// publish their EF.AOD path through EF.ODF.
pub const EF_AOD_FID: FileId = FileId::from_u16(0x4401);

/// The end-of-contents octet (ITU-T X.690 section 8.1.5). No PKCS#15
/// object starts with it, so at an object boundary it begins trailing
/// zero padding.
const END_OF_CONTENTS_OCTET: u8 = 0x00;

/// Erased-EEPROM trailing padding octet permitted at an object
/// boundary alongside 00 (ISO/IEC 7816-4 section 5.2.2.1).
const PADDING_FF_OCTET: u8 = 0xFF;

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

/// `pwdType` `ascii-numeric(1)`: one byte per character.
const PASSWORD_TYPE_ASCII_NUMERIC: u8 = 1;
/// `pwdType` `utf8(2)`: a digit is one byte, so lengths count digits as
/// for `ascii-numeric`.
const PASSWORD_TYPE_UTF8: u8 = 2;

/// Bit positions in ISO/IEC 7816-15 / PKCS#15 v1.1 section 6.8.1
/// `PasswordFlags`.
const PWD_FLAG_CASE_SENSITIVE_BIT: usize = 0;
const PWD_FLAG_LOCAL_BIT: usize = 1;
const PWD_FLAG_INITIALIZED_BIT: usize = 4;
const PWD_FLAG_NEEDS_PADDING_BIT: usize = 5;
const PWD_FLAG_UNBLOCKING_PASSWORD_BIT: usize = 6;
const PWD_FLAG_EXCHANGE_REF_DATA_BIT: usize = 11;

/// Decoded flags from `PasswordAttributes.pwdFlags` (PKCS#15 v1.1
/// section 6.8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordFlags {
    case_sensitive: bool,
    local: bool,
    initialized: bool,
    needs_padding: bool,
    unblocking_password: bool,
    exchange_ref_data: bool,
}

impl PasswordFlags {
    fn parse_bit_string(content: &[u8]) -> Option<Self> {
        let (unused, octets) = validate_bit_string(content)?;
        Some(Self {
            case_sensitive: bit_string_flag(unused, octets, PWD_FLAG_CASE_SENSITIVE_BIT),
            local: bit_string_flag(unused, octets, PWD_FLAG_LOCAL_BIT),
            initialized: bit_string_flag(unused, octets, PWD_FLAG_INITIALIZED_BIT),
            needs_padding: bit_string_flag(unused, octets, PWD_FLAG_NEEDS_PADDING_BIT),
            unblocking_password: bit_string_flag(unused, octets, PWD_FLAG_UNBLOCKING_PASSWORD_BIT),
            exchange_ref_data: bit_string_flag(unused, octets, PWD_FLAG_EXCHANGE_REF_DATA_BIT),
        })
    }

    /// Bit 0 (`case-sensitive`).
    #[must_use]
    pub const fn case_sensitive(self) -> bool {
        self.case_sensitive
    }

    /// Bit 1 (`local`).
    #[must_use]
    pub const fn local(self) -> bool {
        self.local
    }

    /// Bit 4 (`initialized`).
    #[must_use]
    pub const fn initialized(self) -> bool {
        self.initialized
    }

    /// Bit 5 (`needs-padding`): the card expects credentials to be
    /// right-padded to `storedLength` with `padChar`.
    #[must_use]
    pub const fn needs_padding(self) -> bool {
        self.needs_padding
    }

    /// Bit 6 (`unblockingPassword`): distinguishes a PUK from a PIN.
    #[must_use]
    pub const fn unblocking_password(self) -> bool {
        self.unblocking_password
    }

    /// Bit 11 (`exchangeRefData`).
    #[must_use]
    pub const fn exchange_ref_data(self) -> bool {
        self.exchange_ref_data
    }
}

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

/// One password object from EF.AOD: its `authId` links, flags, wire
/// reference, accepted digit-length range, stored length, and optional
/// pad octet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordObject {
    auth_id: Option<ObjectIdentifier>,
    protecting_auth_id: Option<ObjectIdentifier>,
    flags: PasswordFlags,
    reference: u8,
    lengths: PasswordLengthRange,
    stored_length: u8,
    pad_char: Option<u8>,
}

impl PasswordObject {
    /// `CommonAuthenticationObjectAttributes.authId`, when present:
    /// the identifier that private keys in EF.PrKDF reference in their
    /// `CommonObjectAttributes.authId`.
    #[must_use]
    pub const fn auth_id(&self) -> Option<&ObjectIdentifier> {
        self.auth_id.as_ref()
    }

    /// `CommonObjectAttributes.authId`, when present: the identifier of
    /// the authentication object (typically the PUK) that unblocks this
    /// password object.
    #[must_use]
    pub const fn protecting_auth_id(&self) -> Option<&ObjectIdentifier> {
        self.protecting_auth_id.as_ref()
    }

    /// Decoded `PasswordFlags` (`pwdFlags`).
    #[must_use]
    pub const fn flags(&self) -> PasswordFlags {
        self.flags
    }

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

    /// `storedLength`: the block width a padded card compares.
    #[must_use]
    pub const fn stored_length(&self) -> u8 {
        self.stored_length
    }

    /// `padChar`: the single padding octet published by the card, when
    /// present.
    #[must_use]
    pub const fn pad_char(&self) -> Option<u8> {
        self.pad_char
    }
}

/// Outcome of parsing an EF.AOD [`FileContent`] read at the border.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationObjectsRead {
    /// Confirmed EOF and every record decoded cleanly.
    Parsed(AuthenticationObjects),
    /// The read stopped before the card confirmed end of file.
    Incomplete,
    /// The octets did not decode as valid EF.AOD records.
    Malformed(AuthenticationObjectsError),
}

/// The password objects EF.AOD lists, in file order.
///
/// A value exists only as the result of [`AuthenticationObjects::parse`]
/// or [`AuthenticationObjects::of`]. Objects of other authentication
/// kinds (biometric templates, authentication keys, external
/// authentication) are not password objects and are not kept. A
/// password object is kept only when its lengths count digits
/// (`ascii-numeric` or `utf8`), its reference and lengths fit one
/// octet, and its range satisfies [`PasswordLengthRange::new`].
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
    /// A BIT STRING field (`pwdFlags` or common flags) carried invalid
    /// unused-bit encoding.
    MalformedBitString(&'static str),
    /// `padChar` was present with a length other than one octet
    /// (PKCS#15 v1.1 section 6.8.1 requires `OCTET STRING (SIZE(1))`).
    MalformedPadChar,
    /// An `authId` or `CommonObjectAttributes` element was malformed.
    MalformedAuthId,
    /// Non-padding octets follow trailing 00 or FF padding.
    DataAfterPadding,
}

impl fmt::Display for AuthenticationObjectsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ber(error) => write!(f, "EF.AOD: {error}"),
            Self::MissingElement(what) => write!(f, "EF.AOD: password object lacks {what}"),
            Self::MalformedBitString(what) => {
                write!(f, "EF.AOD: password object carries malformed {what}")
            }
            Self::MalformedPadChar => {
                f.write_str("EF.AOD: padChar must be a single-octet OCTET STRING")
            }
            Self::MalformedAuthId => {
                f.write_str("EF.AOD: malformed authentication object identifier")
            }
            Self::DataAfterPadding => f.write_str("EF.AOD: data after the trailing padding"),
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
    /// Validate a confirmed EF.AOD read at the border.
    #[must_use]
    pub fn of(content: FileContent) -> AuthenticationObjectsRead {
        if !matches!(content.end(), FileEnd::Confirmed) {
            return AuthenticationObjectsRead::Incomplete;
        }
        match Self::parse(content.as_bytes()) {
            Ok(parsed) => AuthenticationObjectsRead::Parsed(parsed),
            Err(error) => AuthenticationObjectsRead::Malformed(error),
        }
    }

    /// Combine password objects from multiple EF.AOD files listed by
    /// EF.ODF.
    pub(crate) fn merge(directories: Vec<Self>) -> Self {
        let mut passwords = Vec::new();
        for directory in directories {
            passwords.extend(directory.passwords);
        }
        Self { passwords }
    }

    /// The password objects, in file order.
    #[must_use]
    pub fn passwords(&self) -> &[PasswordObject] {
        &self.passwords
    }

    /// Whether the directory lists a password object under `reference`.
    #[must_use]
    pub fn lists_reference(&self, reference: u8) -> bool {
        self.passwords
            .iter()
            .any(|object| object.reference == reference)
    }

    /// Return the single password object whose
    /// `CommonAuthenticationObjectAttributes.authId` matches `auth_id`,
    /// or `None` when none or more than one matches.
    #[must_use]
    pub fn unique_by_auth_id(&self, auth_id: &ObjectIdentifier) -> Option<&PasswordObject> {
        let mut matching = self
            .passwords
            .iter()
            .filter(|object| object.auth_id.as_ref() == Some(auth_id));
        let first = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        Some(first)
    }

    /// Return the single password object with `pwdReference ==
    /// reference`, or `None` when none or more than one matches.
    #[must_use]
    pub fn unique_by_reference(&self, reference: u8) -> Option<&PasswordObject> {
        let mut matching = self
            .passwords
            .iter()
            .filter(|object| object.reference == reference);
        let first = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        Some(first)
    }

    /// Parse the contents of EF.AOD.
    ///
    /// The file is a concatenation of authentication objects, optionally
    /// followed by uniform 00 or FF padding to the file size. Every
    /// object must frame as BER, and every password object must carry
    /// its mandatory `PasswordAttributes` elements under their tags;
    /// any failure there rejects the whole file.
    ///
    /// # Errors
    ///
    /// [`AuthenticationObjectsError`] when a TLV does not frame, a
    /// password object lacks a mandatory element or carries a malformed
    /// field, or non-padding octets follow the trailing padding.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthenticationObjectsError> {
        let mut passwords = Vec::new();
        let mut rest = bytes;
        while let Some(&first) = rest.first() {
            if first == END_OF_CONTENTS_OCTET || first == PADDING_FF_OCTET {
                if rest.iter().all(|&byte| byte == first) {
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

/// Decode one password object's content: optional common and class
/// attribute sequences (carrying `protecting_auth_id` and `auth_id`),
/// optional subclass attributes, and required `typeAttributes [1]`.
fn password_object(content: &[u8]) -> Result<Option<PasswordObject>, AuthenticationObjectsError> {
    let children = BerTlvIter::new(content).collect::<Result<Vec<_>, _>>()?;
    let sequence_tag = <Sequence as BerTag>::TAG;
    let (protecting_auth_id, auth_id) = match (children.first(), children.get(1)) {
        (Some(common), Some(class))
            if common.tag() == sequence_tag && class.tag() == sequence_tag =>
        {
            let common_attrs = parse_common_object_attributes(common.value())
                .ok_or(AuthenticationObjectsError::MalformedAuthId)?;
            let class_auth_id = parse_common_auth_object_attributes(class.value())?;
            (common_attrs.auth_id, class_auth_id)
        }
        _ => (None, None),
    };
    let type_attributes = children
        .iter()
        .find(|child| child.tag() == TYPE_ATTRIBUTES_TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("typeAttributes"))?;
    let attributes = BerTlv::<Sequence>::parse(type_attributes.value())?;
    password_attributes(attributes.value(), auth_id, protecting_auth_id)
}

/// Parse `CommonAuthenticationObjectAttributes ::= SEQUENCE { authId
/// OCTET STRING }` (PKCS#15 v1.1 section 6.1.15).
fn parse_common_auth_object_attributes(
    content: &[u8],
) -> Result<Option<ObjectIdentifier>, AuthenticationObjectsError> {
    let children = BerTlvIter::new(content).collect::<Result<Vec<_>, _>>()?;
    let Some(first) = children.first() else {
        return Ok(None);
    };
    if first.tag() != <OctetString as BerTag>::TAG {
        return Err(AuthenticationObjectsError::MalformedAuthId);
    }
    ObjectIdentifier::of(first.value().to_vec())
        .map(Some)
        .ok_or(AuthenticationObjectsError::MalformedAuthId)
}

/// Decode `PasswordAttributes` by position: flags, type, minimum and
/// stored length, then optional maximum length, reference, and padChar.
fn password_attributes(
    content: &[u8],
    auth_id: Option<ObjectIdentifier>,
    protecting_auth_id: Option<ObjectIdentifier>,
) -> Result<Option<PasswordObject>, AuthenticationObjectsError> {
    let fields = BerTlvIter::new(content).collect::<Result<Vec<_>, _>>()?;
    let mut fields = fields.iter().peekable();

    let flags_tlv = fields
        .next()
        .filter(|field| field.tag() == <BitString as BerTag>::TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("pwdFlags"))?;
    let flags = PasswordFlags::parse_bit_string(flags_tlv.value())
        .ok_or(AuthenticationObjectsError::MalformedBitString("pwdFlags"))?;
    let password_type = fields
        .next()
        .filter(|field| field.tag() == ENUMERATED_TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("pwdType"))?;
    let min_length = fields
        .next()
        .filter(|field| field.tag() == <Integer as BerTag>::TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("minLength"))?;
    let stored_length_tlv = fields
        .next()
        .filter(|field| field.tag() == <Integer as BerTag>::TAG)
        .ok_or(AuthenticationObjectsError::MissingElement("storedLength"))?;
    let max_length = fields.next_if(|field| field.tag() == <Integer as BerTag>::TAG);
    let reference = fields.next_if(|field| field.tag() == PWD_REFERENCE_TAG);
    let pad_char = match fields.next_if(|field| field.tag() == <OctetString as BerTag>::TAG) {
        Some(field) => match field.value() {
            [octet] => Some(*octet),
            _ => return Err(AuthenticationObjectsError::MalformedPadChar),
        },
        None => None,
    };

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
    let stored_length = unsigned_octet(stored_length_tlv.value());
    let max = unsigned_octet(max_length.unwrap_or(stored_length_tlv).value());
    let (Some(reference), Some(min), Some(stored_length), Some(max)) =
        (reference, min, stored_length, max)
    else {
        return Ok(None);
    };
    Ok(
        PasswordLengthRange::new(min, max).map(|lengths| PasswordObject {
            auth_id,
            protecting_auth_id,
            flags,
            reference,
            lengths,
            stored_length,
            pad_char,
        }),
    )
}

/// An INTEGER or ENUMERATED content read as an unsigned magnitude that
/// fits one octet: leading zero octets are dropped, so both the DER
/// form of a reference with its high bit set (a zero octet, then the
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
        AuthenticationObjects, AuthenticationObjectsError, AuthenticationObjectsRead,
        END_OF_CONTENTS_OCTET, ENUMERATED_TAG, PASSWORD_TYPE_ASCII_NUMERIC, PWD_REFERENCE_DEFAULT,
        PWD_REFERENCE_TAG, PasswordLengthRange, TYPE_ATTRIBUTES_TAG,
    };
    use crate::directory::{FileContent, FileEnd, ObjectIdentifier};

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
    /// `pwdType` `bcd(0)`: lengths do not count digits one per byte.
    const PASSWORD_TYPE_BCD: u8 = 0;
    /// Default `pwdFlags` content for legacy-shape fixtures: no flags.
    const FLAGS_UNUSED_BITS: u8 = 0;
    const FLAGS_OCTET: u8 = 0;
    /// Estonian PIN1 `pwdFlags` observed on card: 4 unused bits,
    /// case-sensitive + local + initialized + needs-padding +
    /// exchangeRefData.
    const ESTONIAN_PIN1_FLAGS: &[u8] = &[0x04, 0xCC, 0x10];
    /// Estonian PUK `pwdFlags` observed on card: 1 unused bit,
    /// unblockingPassword + needs-padding set.
    const ESTONIAN_PUK_FLAGS: &[u8] = &[0x01, 0xFE];
    /// Common authId of PIN1 and protecting PUK in fixtures.
    const AUTH_ID_PIN1: u8 = 1;
    const AUTH_ID_PUK: u8 = 3;
    /// Default `padChar` in fixtures.
    const PAD_CHAR_ZERO: u8 = 0x00;
    /// Alternate `padChar` (e.g. IDEMIA / IAS-ECC style).
    const PAD_CHAR_FF: u8 = 0xFF;
    /// Context tag for an authentication object of another kind.
    const OTHER_AUTHENTICATION_KIND_TAG: u8 = 0xA1;
    /// Zero padding after the objects.
    const PADDING_LENGTH: usize = 16;
    /// A magnitude above one octet.
    const TWO_OCTET_LENGTH: u16 = 300;
    /// Malformed BIT STRING unused-bit count above 7.
    const INVALID_UNUSED_BITS: u8 = 8;
    /// Two-octet padChar, prohibited by PKCS#15 SIZE(1).
    const TWO_OCTET_PAD_CHAR: &[u8] = &[0x00, 0xFF];

    fn tag(value: u16) -> u8 {
        u8::try_from(value).expect("one-octet tag")
    }

    fn integer(value: u8) -> Vec<u8> {
        if value.leading_zeros() == 0 {
            vec![END_OF_CONTENTS_OCTET, value]
        } else {
            vec![value]
        }
    }

    #[derive(Clone, Copy)]
    struct Fixture {
        auth_id: u8,
        protecting_auth_id: Option<u8>,
        flags: &'static [u8],
        password_type: u8,
        min: u8,
        stored: u8,
        max: Option<u8>,
        reference: Option<u8>,
        pad_char: Option<&'static [u8]>,
    }

    const EMPTY_FLAGS: &[u8] = &[FLAGS_UNUSED_BITS, FLAGS_OCTET];
    const ZERO_PAD_SLICE: &[u8] = &[PAD_CHAR_ZERO];
    const FF_PAD_SLICE: &[u8] = &[PAD_CHAR_FF];

    impl Fixture {
        const fn citizen(reference: u8, min: u8) -> Self {
            Self {
                auth_id: AUTH_ID_PIN1,
                protecting_auth_id: None,
                flags: EMPTY_FLAGS,
                password_type: PASSWORD_TYPE_ASCII_NUMERIC,
                min,
                stored: CITIZEN_STORED_LENGTH,
                max: None,
                reference: Some(reference),
                pad_char: Some(ZERO_PAD_SLICE),
            }
        }
    }

    fn attributes(fixture: Fixture) -> Vec<u8> {
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(tag(<BitString as BerTag>::TAG), fixture.flags)
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
        if let Some(pad) = fixture.pad_char {
            fields
                .push_tlv(tag(<OctetString as BerTag>::TAG), pad)
                .expect("encodes");
        }
        fields.finish()
    }

    fn object_around(auth_id: u8, protecting_auth_id: Option<u8>, attributes: &[u8]) -> Vec<u8> {
        let mut common = BerEncoder::default();
        common
            .push_tlv(tag(<Utf8String as BerTag>::TAG), b"perustunnusluku")
            .expect("encodes");
        if let Some(protecting) = protecting_auth_id {
            common
                .push_tlv(tag(<OctetString as BerTag>::TAG), [protecting])
                .expect("encodes");
        }
        let mut class = BerEncoder::default();
        class
            .push_tlv(tag(<OctetString as BerTag>::TAG), [auth_id])
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
            .flat_map(|fixture| {
                object_around(
                    fixture.auth_id,
                    fixture.protecting_auth_id,
                    &attributes(*fixture),
                )
            })
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
    fn parses_flags_stored_length_pad_char_and_auth_id_graph() {
        let bytes = file(&[
            Fixture {
                auth_id: AUTH_ID_PIN1,
                protecting_auth_id: Some(AUTH_ID_PUK),
                flags: ESTONIAN_PIN1_FLAGS,
                pad_char: Some(FF_PAD_SLICE),
                ..Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN)
            },
            Fixture {
                auth_id: AUTH_ID_PUK,
                protecting_auth_id: None,
                flags: ESTONIAN_PUK_FLAGS,
                pad_char: Some(ZERO_PAD_SLICE),
                ..Fixture::citizen(CITIZEN_PUK_REFERENCE, CITIZEN_PUK_MIN)
            },
        ]);
        let objects = match AuthenticationObjects::of(FileContent::from_read(
            bytes.clone(),
            FileEnd::Confirmed,
        )) {
            AuthenticationObjectsRead::Parsed(objects) => Some(objects),
            AuthenticationObjectsRead::Incomplete | AuthenticationObjectsRead::Malformed(_) => None,
        }
        .expect("confirmed EF.AOD parses");
        assert_eq!(
            AuthenticationObjects::of(FileContent::from_read(bytes, FileEnd::Incomplete)),
            AuthenticationObjectsRead::Incomplete
        );

        let pin1_id = ObjectIdentifier::of(vec![AUTH_ID_PIN1]).expect("valid id");
        let pin1 = objects
            .unique_by_auth_id(&pin1_id)
            .expect("PIN1 found by authId");
        assert!(pin1.flags().needs_padding());
        assert!(pin1.flags().local());
        assert!(pin1.flags().exchange_ref_data());
        assert!(!pin1.flags().unblocking_password());
        assert_eq!(pin1.stored_length(), CITIZEN_STORED_LENGTH);
        assert_eq!(pin1.pad_char(), Some(PAD_CHAR_FF));

        let puk_id = pin1
            .protecting_auth_id()
            .expect("PIN1 names its protecting PUK authId");
        let puk = objects
            .unique_by_auth_id(puk_id)
            .expect("PUK found by protecting authId");
        assert!(puk.flags().needs_padding());
        assert!(puk.flags().unblocking_password());
        assert_eq!(puk.pad_char(), Some(PAD_CHAR_ZERO));
    }

    #[test]
    fn rejects_malformed_pad_char_and_malformed_pwd_flags() {
        let two_byte_pad = file(&[Fixture {
            pad_char: Some(TWO_OCTET_PAD_CHAR),
            ..Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN)
        }]);
        assert_eq!(
            AuthenticationObjects::parse(&two_byte_pad),
            Err(AuthenticationObjectsError::MalformedPadChar)
        );

        let empty_pad = file(&[Fixture {
            pad_char: Some(&[]),
            ..Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN)
        }]);
        assert_eq!(
            AuthenticationObjects::parse(&empty_pad),
            Err(AuthenticationObjectsError::MalformedPadChar)
        );

        let bad_flags_slice: &[u8] = &[INVALID_UNUSED_BITS, FLAGS_OCTET];
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(tag(<BitString as BerTag>::TAG), bad_flags_slice)
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
                integer(CITIZEN_STORED_LENGTH),
            )
            .expect("encodes");
        assert_eq!(
            AuthenticationObjects::parse(&object_around(AUTH_ID_PIN1, None, &fields.finish())),
            Err(AuthenticationObjectsError::MalformedBitString("pwdFlags"))
        );
    }

    #[test]
    fn a_reference_is_reported_from_the_listed_objects() {
        let bytes = file(&[
            Fixture::citizen(CITIZEN_PIN1_REFERENCE, CITIZEN_PIN1_MIN),
            Fixture::citizen(CITIZEN_PIN2_REFERENCE, CITIZEN_PIN2_MIN),
        ]);
        let objects = AuthenticationObjects::parse(&bytes).expect("parses");
        assert!(objects.lists_reference(CITIZEN_PIN1_REFERENCE));
        assert!(!objects.lists_reference(CITIZEN_PUK_REFERENCE));
        assert_eq!(
            objects
                .unique_by_reference(CITIZEN_PIN1_REFERENCE)
                .map(super::PasswordObject::reference),
            Some(CITIZEN_PIN1_REFERENCE)
        );
    }

    #[test]
    fn max_length_wins_over_stored_length() {
        let bytes = file(&[Fixture {
            auth_id: AUTH_ID_PIN1,
            protecting_auth_id: None,
            flags: EMPTY_FLAGS,
            password_type: PASSWORD_TYPE_ASCII_NUMERIC,
            min: ORGANIZATION_PIN1_MIN,
            stored: ORGANIZATION_PIN1_STORED,
            max: Some(ORGANIZATION_PIN1_MAX),
            reference: Some(ORGANIZATION_PIN1_REFERENCE),
            pad_char: None,
        }]);
        let objects = AuthenticationObjects::parse(&bytes).expect("parses");
        assert_eq!(objects.passwords().len(), 1);
        let object = &objects.passwords()[0];
        assert_eq!(object.reference(), ORGANIZATION_PIN1_REFERENCE);
        assert_eq!(object.stored_length(), ORGANIZATION_PIN1_STORED);
        assert_eq!(object.pad_char(), None);
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
            AuthenticationObjects::parse(&object_around(AUTH_ID_PIN1, None, &fields.finish()))
                .expect("parses");
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
            AuthenticationObjects::parse(&object_around(AUTH_ID_PIN1, None, &fields.finish())),
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
