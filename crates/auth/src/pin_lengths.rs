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

//! The PIN and PUK lengths the card in session accepts.
//!
//! The card's EF.AOD lists each password object's length range (FINEID
//! S4-1 v4.2 section 8.1.5; FINEID S4-2 v4.0 sections 4.6.10 and 4.7.10)
//! and is the authority. On a citizen card whose EF.AOD does not list a
//! credential, the PIN policy in that credential's PIN container is the
//! second source (FINEID S1 v4.2 section 3.15.3). A listed range is used
//! as the card lists it, within the lengths its role type can carry
//! ([`Pin1`] and [`Pin2`] 4-12 digits, [`Puk`] 8-12): a listed maximum
//! above that is taken as the role type's maximum, a listed minimum below
//! it as the role type's minimum. A credential neither source lists takes
//! the FINEID bounds (FINEID S4-1 v4.2 section 4.1: PIN 1 4-12 digits,
//! PIN 2 6-12, PUK 8-12).
//!
//! The lengths are read where PINs are set -- activation, change and
//! reset -- never on the signing or login paths.

use core::fmt;

use refineid_pkcs15::{AuthenticationObjects, PasswordLengthRange};

use crate::credentials::{
    CredentialRole, FINEID_PIN1_MIN_LENGTH, FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH, PIN_MIN_LENGTH,
    PUK_MAX_LENGTH, PUK_MIN_LENGTH, Pin1, Pin2, Puk,
};
use crate::verify::{PinReferenceScheme, PinSlot};

/// The ISO/IEC 7816-4 reference qualifier bit marking a specific (local)
/// reference; FINEID S1 v4.2 section 3.15.3 Table 19 sets it on local
/// PINs. A card may list a reference in EF.AOD with or without it.
const SPECIFIC_REFERENCE_BIT: u8 = 0x80;

/// Which card source a listed range came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardLengthSource {
    /// The password object in EF.AOD.
    AuthenticationObjectDirectory,
    /// The PIN policy in the citizen card's PIN container.
    PinPolicy,
}

/// What the card lists for one credential's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListedLength {
    /// The card lists this range.
    Listed {
        /// The range as the card lists it.
        range: PasswordLengthRange,
        /// Where the card lists it.
        source: CardLengthSource,
    },
    /// Neither source lists the credential, or its entry did not decode;
    /// the FINEID bounds apply.
    NotListed,
}

/// One credential's lengths: what the card lists, and what an entry is
/// checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialLengths {
    listed: ListedLength,
    accepted: Option<PasswordLengthRange>,
}

impl CredentialLengths {
    /// Take what the card lists within the role type's `capacity`, or
    /// the FINEID `fallback` when it lists nothing.
    fn new(
        listed: ListedLength,
        capacity: PasswordLengthRange,
        fallback: PasswordLengthRange,
    ) -> Self {
        let accepted = match listed {
            ListedLength::Listed { range, .. } => range.intersection(capacity),
            ListedLength::NotListed => Some(fallback),
        };
        Self { listed, accepted }
    }

    /// What the card lists.
    #[must_use]
    pub const fn listed(&self) -> ListedLength {
        self.listed
    }

    /// The lengths an entry may have: the card's range within the lengths
    /// the role type carries, or the FINEID bounds when the card lists
    /// nothing. `None` when the card's range shares no length with what
    /// the role type carries, and no entry is accepted.
    #[must_use]
    pub const fn accepted(&self) -> Option<PasswordLengthRange> {
        self.accepted
    }

    fn check(&self, role: CredentialRole, digit_count: usize) -> Result<(), PinLengthRefusal> {
        match self.accepted {
            Some(range) if range.contains(digit_count) => Ok(()),
            Some(range) => Err(PinLengthRefusal::OutsideAcceptedRange {
                role,
                accepted: range,
            }),
            None => Err(PinLengthRefusal::NoAcceptedLength { role }),
        }
    }
}

/// An entry whose length the card in session does not accept, refused
/// before any command carrying it is sent.
///
/// It names the role and the accepted range, never the entry's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinLengthRefusal {
    /// The entry's length is outside the accepted range.
    OutsideAcceptedRange {
        /// The credential the entry was for.
        role: CredentialRole,
        /// The lengths accepted for it.
        accepted: PasswordLengthRange,
    },
    /// The card's range shares no length with what the role type
    /// carries.
    NoAcceptedLength {
        /// The credential the entry was for.
        role: CredentialRole,
    },
}

impl fmt::Display for PinLengthRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutsideAcceptedRange { role, accepted } => write!(
                f,
                "{role} must contain {}-{} digits on this card",
                accepted.min(),
                accepted.max()
            ),
            Self::NoAcceptedLength { role } => {
                write!(f, "this card lists no {role} length that can be set")
            }
        }
    }
}

impl core::error::Error for PinLengthRefusal {}

/// The PIN 1, PIN 2 and PUK lengths of the card in session, under the
/// numbering they were mapped by.
///
/// Produced by [`crate::PinManageOps::read_card_pin_lengths`]; the
/// change, unblock and activation operations take it, address the card
/// under its numbering, and refuse an entry outside its ranges before any
/// command. It describes one card session; a new session reads it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardPinLengths {
    numbering: PinReferenceScheme,
    pin1: CredentialLengths,
    pin2: CredentialLengths,
    puk: CredentialLengths,
}

/// The lengths the PIN role types carry.
const PIN_CAPACITY: PasswordLengthRange = length_range(PIN_MIN_LENGTH, PIN_MAX_LENGTH);
/// The lengths the PUK role type carries.
const PUK_CAPACITY: PasswordLengthRange = length_range(PUK_MIN_LENGTH, PUK_MAX_LENGTH);
/// FINEID bounds of PIN 1, the fallback when the card lists none.
const FINEID_PIN1_BOUNDS: PasswordLengthRange =
    length_range(FINEID_PIN1_MIN_LENGTH, PIN_MAX_LENGTH);
/// FINEID bounds of PIN 2, the fallback when the card lists none.
const FINEID_PIN2_BOUNDS: PasswordLengthRange =
    length_range(FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH);
/// FINEID bounds of the PUK, the fallback when the card lists none.
const FINEID_PUK_BOUNDS: PasswordLengthRange = PUK_CAPACITY;

/// A length constant pair as a range, evaluated at compile time: bounds
/// that do not fit one octet or admit nothing fail the build.
const fn length_range(min: usize, max: usize) -> PasswordLengthRange {
    assert!(min <= u8::MAX as usize && max <= u8::MAX as usize);
    PasswordLengthRange::new(min as u8, max as u8).expect("the bounds admit a length")
}

/// Whether an EF.AOD reference names the credential VERIFY addresses as
/// `expected`, with or without the specific-reference bit.
const fn names(listed: u8, expected: u8) -> bool {
    listed | SPECIFIC_REFERENCE_BIT == expected | SPECIFIC_REFERENCE_BIT
}

/// The one EF.AOD range for `expected`, or nothing when the directory
/// lists no object for it or more than one.
fn directory_range(objects: &AuthenticationObjects, expected: u8) -> Option<PasswordLengthRange> {
    let mut matching = objects
        .passwords()
        .iter()
        .filter(|object| names(object.reference(), expected));
    let first = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    Some(first.lengths())
}

impl CardPinLengths {
    /// Lengths for a card that lists none: every credential takes its
    /// FINEID bounds.
    #[must_use]
    pub fn not_listed(numbering: PinReferenceScheme) -> Self {
        Self::from_listed(
            numbering,
            ListedLength::NotListed,
            ListedLength::NotListed,
            ListedLength::NotListed,
        )
    }

    fn from_listed(
        numbering: PinReferenceScheme,
        pin1: ListedLength,
        pin2: ListedLength,
        puk: ListedLength,
    ) -> Self {
        Self {
            numbering,
            pin1: CredentialLengths::new(pin1, PIN_CAPACITY, FINEID_PIN1_BOUNDS),
            pin2: CredentialLengths::new(pin2, PIN_CAPACITY, FINEID_PIN2_BOUNDS),
            puk: CredentialLengths::new(puk, PUK_CAPACITY, FINEID_PUK_BOUNDS),
        }
    }

    /// Map EF.AOD's password objects onto PIN 1, PIN 2 and the PUK by the
    /// references `numbering` gives them; objects under other references
    /// are not consulted. `policy` supplies the second source for a
    /// credential the directory does not list.
    pub(crate) fn from_card(
        numbering: PinReferenceScheme,
        objects: Option<&AuthenticationObjects>,
        mut policy: impl FnMut(u8) -> Option<PasswordLengthRange>,
    ) -> Self {
        let mut listed = |reference: u8| {
            let directory = objects.and_then(|objects| directory_range(objects, reference));
            if let Some(range) = directory {
                return ListedLength::Listed {
                    range,
                    source: CardLengthSource::AuthenticationObjectDirectory,
                };
            }
            match policy(reference) {
                Some(range) => ListedLength::Listed {
                    range,
                    source: CardLengthSource::PinPolicy,
                },
                None => ListedLength::NotListed,
            }
        };
        let pin1 = listed(numbering.reference(PinSlot::Pin1));
        let pin2 = listed(numbering.reference(PinSlot::Pin2));
        let puk = listed(numbering.puk_reference());
        Self::from_listed(numbering, pin1, pin2, puk)
    }

    /// The numbering the lengths were mapped by, and the operations
    /// taking them address the card under.
    #[must_use]
    pub const fn numbering(&self) -> PinReferenceScheme {
        self.numbering
    }

    /// PIN 1's lengths.
    #[must_use]
    pub const fn pin1(&self) -> CredentialLengths {
        self.pin1
    }

    /// PIN 2's lengths.
    #[must_use]
    pub const fn pin2(&self) -> CredentialLengths {
        self.pin2
    }

    /// The PUK's lengths.
    #[must_use]
    pub const fn puk(&self) -> CredentialLengths {
        self.puk
    }

    /// The lengths of the PIN in `slot`.
    #[must_use]
    pub const fn slot(&self, slot: PinSlot) -> CredentialLengths {
        match slot {
            PinSlot::Pin1 => self.pin1,
            PinSlot::Pin2 => self.pin2,
        }
    }

    /// Check a PIN 1 entry against PIN 1's accepted lengths.
    ///
    /// # Errors
    ///
    /// [`PinLengthRefusal`] when the card does not accept its length.
    pub fn check_pin1(&self, pin: &Pin1) -> Result<(), PinLengthRefusal> {
        self.pin1.check(CredentialRole::Pin1, pin.digit_count())
    }

    /// Check a PIN 2 entry against PIN 2's accepted lengths.
    ///
    /// # Errors
    ///
    /// [`PinLengthRefusal`] when the card does not accept its length.
    pub fn check_pin2(&self, pin: &Pin2) -> Result<(), PinLengthRefusal> {
        self.pin2.check(CredentialRole::Pin2, pin.digit_count())
    }

    /// Check a PUK entry against the PUK's accepted lengths.
    ///
    /// # Errors
    ///
    /// [`PinLengthRefusal`] when the card does not accept its length.
    pub fn check_puk(&self, puk: &Puk) -> Result<(), PinLengthRefusal> {
        self.puk.check(CredentialRole::Puk, puk.digit_count())
    }

    /// Check an activation entry presented in place of the PUK, or of the
    /// PIN in `slot` when `slot` is given.
    pub(crate) fn check_activation_entry(
        &self,
        presented_as: Option<PinSlot>,
        digit_count: usize,
    ) -> Result<(), PinLengthRefusal> {
        let lengths = match presented_as {
            Some(slot) => self.slot(slot),
            None => self.puk,
        };
        lengths.check(CredentialRole::ActivationCode, digit_count)
    }
}

#[cfg(test)]
mod tests {
    use refineid_apdu::iso7816::{ReadBinary, SelectFile};
    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
        TransportOutcome,
    };
    use refineid_ber::{BerEncoder, BerTag, BitString, Integer, OctetString, Sequence};
    use refineid_pkcs15::{AuthenticationObjects, PasswordLengthRange};

    use crate::activation::{
        ActivationCode, ActivationScheme, GET_DATA_INS, PIN_CONTAINER_REF_TAG,
        PIN_CONTAINER_TEMPLATE_TAG, PIN_POLICY_LEN, PIN_POLICY_MAX_LENGTH_OFFSET,
        PIN_POLICY_MIN_LENGTH_OFFSET, PIN_POLICY_TAG,
    };
    use crate::manage::{ManageOutcome, PinManageOps};
    use crate::verify::{AuthError, PinSlot, VERIFY_INS};

    use super::{
        CardLengthSource, CardPinLengths, ListedLength, PinLengthRefusal, SPECIFIC_REFERENCE_BIT,
    };
    use crate::credentials::{
        CredentialRole, FINEID_PIN1_MIN_LENGTH, FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH,
        PIN_MIN_LENGTH, PUK_MAX_LENGTH, PUK_MIN_LENGTH, Pin1, Pin2, Puk, UnvalidatedSecret,
    };
    use crate::verify::{
        PIN1_REFERENCE, PIN1_REFERENCE_ORGANIZATIONAL, PIN2_REFERENCE,
        PIN2_REFERENCE_ORGANIZATIONAL, PUK_REFERENCE, PUK_REFERENCE_ORGANIZATIONAL,
        PinReferenceScheme,
    };

    /// `pwdType` `ascii-numeric(1)` (ISO/IEC 7816-15).
    const ASCII_NUMERIC: u8 = 1;
    /// ASN.1 universal `ENUMERATED`.
    const ENUMERATED_TAG: u8 = 0x0A;
    /// `typeAttributes [1]`, constructed.
    const TYPE_ATTRIBUTES_TAG: u8 = 0xA1;
    /// `pwdReference [0]`.
    const PWD_REFERENCE_TAG: u8 = 0x80;
    /// `pwdFlags` content: no unused bits, then one flag octet with no
    /// flag set; the flags are not consulted.
    const FLAGS_UNUSED_BITS: u8 = 0;
    const FLAGS_OCTET: u8 = 0;
    /// The stored length FINEID password objects list.
    const STORED_LENGTH: u8 = 12;
    /// An older organization card's PIN 1 maximum.
    const OLDER_ORGANIZATION_MAX: u8 = 8;
    /// The Cosmo X organization card's PIN 1 minimum and maximum.
    const ORGANIZATION_PIN1_MIN: u8 = 4;
    const ORGANIZATION_PIN1_MAX: u8 = 12;
    /// A card-listed PIN 2 minimum below the role type's.
    const SHORT_PIN2_MIN: u8 = 4;
    /// A card-listed range below the PIN role types' minimum.
    const BELOW_CAPACITY_MIN: u8 = 2;
    const BELOW_CAPACITY_MAX: u8 = 3;
    /// A card-listed maximum above the role types' capacity.
    const LONG_MAX: u8 = 16;
    /// A reference no FINEID numbering uses.
    const UNKNOWN_REFERENCE: u8 = 0x15;
    /// Citizen password-object minimums (FINEID S4-1 v4.2 section 8.1.5).
    const CITIZEN_PIN1_MIN: u8 = 4;
    const CITIZEN_PIN2_MIN: u8 = 6;
    const CITIZEN_PUK_MIN: u8 = 8;

    fn integer(value: u8) -> Vec<u8> {
        if value.leading_zeros() == 0 {
            vec![0, value]
        } else {
            vec![value]
        }
    }

    fn object(reference: u8, min: u8, stored: u8, max: Option<u8>) -> Vec<u8> {
        let integer_tag = u8::try_from(<Integer as BerTag>::TAG).expect("one octet");
        let sequence_tag = u8::try_from(<Sequence as BerTag>::TAG).expect("one octet");
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(
                u8::try_from(<BitString as BerTag>::TAG).expect("one octet"),
                [FLAGS_UNUSED_BITS, FLAGS_OCTET],
            )
            .expect("encodes");
        fields
            .push_tlv(ENUMERATED_TAG, [ASCII_NUMERIC])
            .expect("encodes");
        fields.push_tlv(integer_tag, integer(min)).expect("encodes");
        fields
            .push_tlv(integer_tag, integer(stored))
            .expect("encodes");
        if let Some(max) = max {
            fields.push_tlv(integer_tag, integer(max)).expect("encodes");
        }
        fields
            .push_tlv(PWD_REFERENCE_TAG, integer(reference))
            .expect("encodes");
        let mut typed = BerEncoder::default();
        typed
            .push_tlv(sequence_tag, fields.finish())
            .expect("encodes");
        let mut class = BerEncoder::default();
        class
            .push_tlv(
                u8::try_from(<OctetString as BerTag>::TAG).expect("one octet"),
                [reference],
            )
            .expect("encodes");
        let mut body = BerEncoder::default();
        body.push_tlv(sequence_tag, []).expect("encodes");
        body.push_tlv(sequence_tag, class.finish())
            .expect("encodes");
        body.push_tlv(TYPE_ATTRIBUTES_TAG, typed.finish())
            .expect("encodes");
        let mut outer = BerEncoder::default();
        outer
            .push_tlv(sequence_tag, body.finish())
            .expect("encodes");
        outer.finish()
    }

    fn directory(objects: &[Vec<u8>]) -> AuthenticationObjects {
        AuthenticationObjects::parse(&objects.concat()).expect("fixture parses")
    }

    fn range(min: u8, max: u8) -> PasswordLengthRange {
        PasswordLengthRange::new(min, max).expect("valid range")
    }

    fn from_directory(
        numbering: PinReferenceScheme,
        objects: &AuthenticationObjects,
    ) -> CardPinLengths {
        CardPinLengths::from_card(numbering, Some(objects), |_| None)
    }

    fn listed_from_directory(range: PasswordLengthRange) -> ListedLength {
        ListedLength::Listed {
            range,
            source: CardLengthSource::AuthenticationObjectDirectory,
        }
    }

    fn citizen_directory() -> AuthenticationObjects {
        directory(&[
            object(PIN1_REFERENCE, CITIZEN_PIN1_MIN, STORED_LENGTH, None),
            object(PIN2_REFERENCE, CITIZEN_PIN2_MIN, STORED_LENGTH, None),
            object(PUK_REFERENCE, CITIZEN_PUK_MIN, STORED_LENGTH, None),
        ])
    }

    fn secret(length: usize) -> UnvalidatedSecret {
        UnvalidatedSecret::from_owned_bytes(vec![b'5'; length])
    }

    #[test]
    fn the_citizen_directory_maps_by_the_citizen_references() {
        let lengths = from_directory(PinReferenceScheme::Citizen, &citizen_directory());
        assert_eq!(lengths.numbering(), PinReferenceScheme::Citizen);
        assert_eq!(
            lengths.pin1().listed(),
            listed_from_directory(range(CITIZEN_PIN1_MIN, STORED_LENGTH))
        );
        assert_eq!(
            lengths.pin2().listed(),
            listed_from_directory(range(CITIZEN_PIN2_MIN, STORED_LENGTH))
        );
        assert_eq!(
            lengths.puk().listed(),
            listed_from_directory(range(CITIZEN_PUK_MIN, STORED_LENGTH))
        );
        assert_eq!(
            lengths.pin2().accepted(),
            Some(range(CITIZEN_PIN2_MIN, STORED_LENGTH))
        );
    }

    #[test]
    fn the_organization_directory_maps_by_the_organization_references() {
        let objects = directory(&[
            object(
                PIN1_REFERENCE_ORGANIZATIONAL,
                ORGANIZATION_PIN1_MIN,
                STORED_LENGTH,
                Some(ORGANIZATION_PIN1_MAX),
            ),
            object(
                PIN2_REFERENCE_ORGANIZATIONAL | SPECIFIC_REFERENCE_BIT,
                CITIZEN_PIN2_MIN,
                STORED_LENGTH,
                Some(OLDER_ORGANIZATION_MAX),
            ),
            object(
                PUK_REFERENCE_ORGANIZATIONAL,
                CITIZEN_PUK_MIN,
                STORED_LENGTH,
                None,
            ),
        ]);
        let lengths = from_directory(PinReferenceScheme::Organizational, &objects);
        assert_eq!(
            lengths.pin1().accepted(),
            Some(range(ORGANIZATION_PIN1_MIN, ORGANIZATION_PIN1_MAX))
        );
        // The local form of the reference names the same PIN, and the
        // card's narrower maximum is the authority.
        assert_eq!(
            lengths.pin2().accepted(),
            Some(range(CITIZEN_PIN2_MIN, OLDER_ORGANIZATION_MAX))
        );
        assert_eq!(
            lengths.puk().accepted(),
            Some(range(CITIZEN_PUK_MIN, STORED_LENGTH))
        );
        // Under the citizen numbering none of these objects is consulted.
        let citizen = from_directory(PinReferenceScheme::Citizen, &objects);
        assert_eq!(citizen.pin1().listed(), ListedLength::NotListed);
        assert_eq!(citizen.pin2().listed(), ListedLength::NotListed);
    }

    #[test]
    fn unknown_references_are_not_consulted() {
        let objects = directory(&[object(
            UNKNOWN_REFERENCE,
            OLDER_ORGANIZATION_MAX,
            OLDER_ORGANIZATION_MAX,
            None,
        )]);
        for numbering in [
            PinReferenceScheme::Citizen,
            PinReferenceScheme::Organizational,
        ] {
            assert_eq!(
                from_directory(numbering, &objects),
                CardPinLengths::not_listed(numbering)
            );
        }
    }

    #[test]
    fn a_reference_listed_twice_is_not_listed() {
        let objects = directory(&[
            object(PIN1_REFERENCE, CITIZEN_PIN1_MIN, STORED_LENGTH, None),
            object(
                PIN1_REFERENCE | SPECIFIC_REFERENCE_BIT,
                CITIZEN_PIN2_MIN,
                STORED_LENGTH,
                None,
            ),
        ]);
        let lengths = from_directory(PinReferenceScheme::Citizen, &objects);
        assert_eq!(lengths.pin1().listed(), ListedLength::NotListed);
    }

    #[test]
    fn not_listed_falls_back_to_the_fineid_bounds() {
        let lengths = CardPinLengths::not_listed(PinReferenceScheme::Organizational);
        let fallback = |min: usize, max: usize| {
            PasswordLengthRange::new(
                u8::try_from(min).expect("fits"),
                u8::try_from(max).expect("fits"),
            )
        };
        assert_eq!(
            lengths.pin1().accepted(),
            fallback(FINEID_PIN1_MIN_LENGTH, PIN_MAX_LENGTH)
        );
        assert_eq!(
            lengths.pin2().accepted(),
            fallback(FINEID_PIN2_MIN_LENGTH, PIN_MAX_LENGTH)
        );
        assert_eq!(
            lengths.puk().accepted(),
            fallback(PUK_MIN_LENGTH, PUK_MAX_LENGTH)
        );
    }

    #[test]
    fn the_pin_policy_lists_what_the_directory_does_not() {
        let objects = directory(&[object(
            PIN1_REFERENCE,
            CITIZEN_PIN1_MIN,
            STORED_LENGTH,
            None,
        )]);
        let mut asked = Vec::new();
        let lengths =
            CardPinLengths::from_card(PinReferenceScheme::Citizen, Some(&objects), |reference| {
                asked.push(reference);
                (reference == PIN2_REFERENCE)
                    .then(|| range(CITIZEN_PIN2_MIN, OLDER_ORGANIZATION_MAX))
            });
        assert_eq!(asked, [PIN2_REFERENCE, PUK_REFERENCE]);
        assert_eq!(
            lengths.pin2().listed(),
            ListedLength::Listed {
                range: range(CITIZEN_PIN2_MIN, OLDER_ORGANIZATION_MAX),
                source: CardLengthSource::PinPolicy,
            }
        );
        assert_eq!(lengths.puk().listed(), ListedLength::NotListed);
    }

    #[test]
    fn a_listed_range_is_used_as_listed_within_the_role_capacity() {
        let objects = directory(&[
            object(PIN1_REFERENCE, BELOW_CAPACITY_MIN, LONG_MAX, None),
            object(PIN2_REFERENCE, SHORT_PIN2_MIN, STORED_LENGTH, None),
        ]);
        let lengths = from_directory(PinReferenceScheme::Citizen, &objects);
        // Listed beyond what the role type carries: reported as listed,
        // used as the role type's minimum and maximum.
        assert_eq!(
            lengths.pin1().listed(),
            listed_from_directory(range(BELOW_CAPACITY_MIN, LONG_MAX))
        );
        assert_eq!(
            lengths.pin1().accepted(),
            Some(range(CITIZEN_PIN1_MIN, STORED_LENGTH))
        );
        // A PIN 2 minimum below the FINEID bound is the card's to set.
        assert_eq!(
            lengths.pin2().accepted(),
            Some(range(SHORT_PIN2_MIN, STORED_LENGTH))
        );
        let short = Pin2::reconstruct(secret(usize::from(SHORT_PIN2_MIN))).expect("valid PIN 2");
        assert_eq!(lengths.check_pin2(&short), Ok(()));
    }

    #[test]
    fn checks_refuse_outside_the_accepted_range_without_the_entry_length() {
        let objects = directory(&[object(
            PIN1_REFERENCE,
            CITIZEN_PIN1_MIN,
            STORED_LENGTH,
            Some(OLDER_ORGANIZATION_MAX),
        )]);
        let lengths = from_directory(PinReferenceScheme::Citizen, &objects);
        let accepted = range(CITIZEN_PIN1_MIN, OLDER_ORGANIZATION_MAX);
        let long = Pin1::reconstruct(secret(PIN_MAX_LENGTH)).expect("valid PIN 1");
        let refusal = lengths
            .check_pin1(&long)
            .expect_err("above the card maximum");
        assert_eq!(
            refusal,
            PinLengthRefusal::OutsideAcceptedRange {
                role: CredentialRole::Pin1,
                accepted,
            }
        );
        assert_eq!(
            refusal.to_string(),
            format!(
                "PIN1 must contain {}-{} digits on this card",
                accepted.min(),
                accepted.max()
            )
        );
        let fits = Pin1::reconstruct(secret(usize::from(OLDER_ORGANIZATION_MAX))).expect("valid");
        assert_eq!(lengths.check_pin1(&fits), Ok(()));
        let pin2 = Pin2::reconstruct(secret(PIN_MAX_LENGTH)).expect("valid PIN 2");
        assert_eq!(lengths.check_pin2(&pin2), Ok(()));
        let puk = Puk::reconstruct(secret(PUK_MAX_LENGTH)).expect("valid PUK");
        assert_eq!(lengths.check_puk(&puk), Ok(()));
    }

    #[test]
    fn a_card_range_sharing_no_length_with_the_role_type_accepts_nothing() {
        let objects = directory(&[object(
            PIN2_REFERENCE,
            BELOW_CAPACITY_MIN,
            BELOW_CAPACITY_MAX,
            None,
        )]);
        let lengths = from_directory(PinReferenceScheme::Citizen, &objects);
        assert_eq!(lengths.pin2().accepted(), None);
        let pin2 = Pin2::reconstruct(secret(FINEID_PIN2_MIN_LENGTH)).expect("valid PIN 2");
        assert_eq!(
            lengths.check_pin2(&pin2),
            Err(PinLengthRefusal::NoAcceptedLength {
                role: CredentialRole::Pin2
            })
        );
    }

    #[test]
    fn an_unreadable_directory_lists_nothing() {
        let lengths = CardPinLengths::from_card(PinReferenceScheme::Citizen, None, |_| None);
        assert_eq!(
            lengths,
            CardPinLengths::not_listed(PinReferenceScheme::Citizen)
        );
    }

    /// A card simulation for the session tests: SELECT succeeds when the
    /// card has an EF.AOD, READ BINARY serves it, GET DATA serves the
    /// PIN policy of the references listed, the counter-safe probes
    /// resolve the numbering, and credential commands succeed.
    struct SimulatedCard {
        numbering: PinReferenceScheme,
        aod: Option<Vec<u8>>,
        policies: Vec<(u8, PasswordLengthRange)>,
        get_data_references: Vec<u8>,
        credential_commands: usize,
        plain_commands: usize,
    }

    impl SimulatedCard {
        fn new(numbering: PinReferenceScheme, aod: Option<Vec<u8>>) -> Self {
            Self {
                numbering,
                aod,
                policies: Vec::new(),
                get_data_references: Vec::new(),
                credential_commands: 0,
                plain_commands: 0,
            }
        }

        fn policy_body(reference: u8, lengths: PasswordLengthRange) -> Vec<u8> {
            let mut policy = vec![0_u8; PIN_POLICY_LEN];
            policy[PIN_POLICY_MIN_LENGTH_OFFSET] = u8::try_from(lengths.min()).expect("fits");
            policy[PIN_POLICY_MAX_LENGTH_OFFSET] = u8::try_from(lengths.max()).expect("fits");
            let mut inner = BerEncoder::default();
            inner
                .push_tlv(PIN_CONTAINER_REF_TAG, [reference])
                .expect("encodes");
            inner
                .push_tlv_tag2(PIN_POLICY_TAG, policy)
                .expect("encodes");
            let mut outer = BerEncoder::default();
            outer
                .push_tlv(PIN_CONTAINER_TEMPLATE_TAG, inner.finish())
                .expect("encodes");
            outer.finish()
        }
    }

    const INS_INDEX: usize = 1;
    const P1_INDEX: usize = 2;
    const P2_INDEX: usize = 3;
    /// Wire offset of the GET DATA PIN reference: header, Lc, template
    /// tag and length, reference tag and length.
    const GET_DATA_REFERENCE_INDEX: usize = 9;
    /// Wire offset of READ BINARY's Le in a case 2 command.
    const READ_LE_INDEX: usize = 4;
    /// Retry count of a pristine credential.
    const PRISTINE: u8 = 5;
    /// A cut inside the first password object.
    const TRUNCATED_LENGTH: usize = 7;

    fn reply(body: Vec<u8>, sw: StatusWord) -> TransportOutcome {
        let [sw1, sw2] = sw.as_u16().to_be_bytes();
        TransportOutcome::Response(ResponseApdu { body, sw1, sw2 })
    }

    impl CardTransport for SimulatedCard {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.plain_commands += 1;
            let wire = command.as_bytes();
            match wire[INS_INDEX] {
                SelectFile::INS => Ok(reply(
                    Vec::new(),
                    if self.aod.is_some() {
                        StatusWord::Success
                    } else {
                        StatusWord::FileNotFound
                    },
                )),
                ReadBinary::INS => {
                    let aod = self.aod.as_deref().unwrap_or_default();
                    let offset = usize::from(u16::from_be_bytes([wire[P1_INDEX], wire[P2_INDEX]]));
                    let want = usize::from(wire[READ_LE_INDEX]);
                    let end = aod.len().min(offset + want);
                    Ok(reply(
                        aod.get(offset..end).unwrap_or_default().to_vec(),
                        StatusWord::Success,
                    ))
                }
                GET_DATA_INS => {
                    let reference = wire[GET_DATA_REFERENCE_INDEX];
                    self.get_data_references.push(reference);
                    let policy = self
                        .policies
                        .iter()
                        .find(|(listed, _)| *listed == reference)
                        .map(|(_, lengths)| Self::policy_body(reference, *lengths));
                    Ok(match policy {
                        Some(body) => reply(body, StatusWord::Success),
                        None => reply(Vec::new(), StatusWord::FileNotFound),
                    })
                }
                VERIFY_INS => {
                    let p2 = wire[P2_INDEX];
                    let known = p2 == self.numbering.reference(PinSlot::Pin1)
                        || p2 == self.numbering.reference(PinSlot::Pin2)
                        || p2 == self.numbering.puk_reference();
                    Ok(reply(
                        Vec::new(),
                        if known {
                            StatusWord::PinIncorrect {
                                retries: PinRetries::from_nibble(PRISTINE).expect("nibble"),
                            }
                        } else {
                            StatusWord::ReferenceDataNotFound
                        },
                    ))
                }
                _ => Ok(reply(Vec::new(), StatusWord::FileNotFound)),
            }
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.credential_commands += 1;
            Ok(reply(Vec::new(), StatusWord::Success))
        }
    }

    fn citizen_aod() -> Vec<u8> {
        [
            object(PIN1_REFERENCE, CITIZEN_PIN1_MIN, STORED_LENGTH, None),
            object(PIN2_REFERENCE, CITIZEN_PIN2_MIN, STORED_LENGTH, None),
            object(PUK_REFERENCE, CITIZEN_PUK_MIN, STORED_LENGTH, None),
        ]
        .concat()
    }

    #[test]
    fn a_citizen_session_reads_the_directory_and_asks_no_pin_container() {
        let mut card = SimulatedCard::new(PinReferenceScheme::Citizen, Some(citizen_aod()));
        let lengths = card.read_card_pin_lengths().expect("reads");
        assert_eq!(
            lengths,
            from_directory(PinReferenceScheme::Citizen, &citizen_directory())
        );
        assert!(card.get_data_references.is_empty());
        assert_eq!(card.credential_commands, 0);
    }

    #[test]
    fn an_organization_session_maps_the_cosmo_x_directory_and_asks_no_pin_container() {
        let aod = object(
            PIN1_REFERENCE_ORGANIZATIONAL,
            ORGANIZATION_PIN1_MIN,
            STORED_LENGTH,
            Some(ORGANIZATION_PIN1_MAX),
        );
        let mut card = SimulatedCard::new(PinReferenceScheme::Organizational, Some(aod));
        let lengths = card.read_card_pin_lengths().expect("reads");
        assert_eq!(lengths.numbering(), PinReferenceScheme::Organizational);
        assert_eq!(
            lengths.pin1().listed(),
            listed_from_directory(range(ORGANIZATION_PIN1_MIN, ORGANIZATION_PIN1_MAX))
        );
        assert_eq!(lengths.pin2().listed(), ListedLength::NotListed);
        assert!(card.get_data_references.is_empty());
    }

    #[test]
    fn a_citizen_card_without_a_directory_falls_back_to_its_pin_policy() {
        let mut card = SimulatedCard::new(PinReferenceScheme::Citizen, None);
        card.policies.push((
            PIN2_REFERENCE,
            range(CITIZEN_PIN2_MIN, OLDER_ORGANIZATION_MAX),
        ));
        let lengths = card.read_card_pin_lengths().expect("reads");
        assert_eq!(
            card.get_data_references,
            [PIN1_REFERENCE, PIN2_REFERENCE, PUK_REFERENCE]
        );
        assert_eq!(lengths.pin1().listed(), ListedLength::NotListed);
        assert_eq!(
            lengths.pin2().listed(),
            ListedLength::Listed {
                range: range(CITIZEN_PIN2_MIN, OLDER_ORGANIZATION_MAX),
                source: CardLengthSource::PinPolicy,
            }
        );
        assert_eq!(lengths.puk().listed(), ListedLength::NotListed);
    }

    #[test]
    fn a_truncated_directory_lists_nothing() {
        let mut aod = citizen_aod();
        aod.truncate(TRUNCATED_LENGTH);
        let mut card = SimulatedCard::new(PinReferenceScheme::Organizational, Some(aod));
        let lengths = card.read_card_pin_lengths().expect("reads");
        assert_eq!(
            lengths,
            CardPinLengths::not_listed(PinReferenceScheme::Organizational)
        );
    }

    /// A card that lists PIN 1 and PIN 2 up to the older organization
    /// maximum and the PUK from its stored length.
    fn narrow_lengths(numbering: PinReferenceScheme) -> CardPinLengths {
        let objects = directory(&[
            object(
                numbering.reference(PinSlot::Pin1),
                CITIZEN_PIN1_MIN,
                STORED_LENGTH,
                Some(OLDER_ORGANIZATION_MAX),
            ),
            object(
                numbering.reference(PinSlot::Pin2),
                CITIZEN_PIN2_MIN,
                STORED_LENGTH,
                Some(OLDER_ORGANIZATION_MAX),
            ),
            object(
                numbering.puk_reference(),
                STORED_LENGTH,
                STORED_LENGTH,
                None,
            ),
        ]);
        from_directory(numbering, &objects)
    }

    fn pin1(length: usize) -> Pin1 {
        Pin1::reconstruct(secret(length)).expect("valid PIN 1")
    }

    fn pin2(length: usize) -> Pin2 {
        Pin2::reconstruct(secret(length)).expect("valid PIN 2")
    }

    fn puk(length: usize) -> Puk {
        Puk::reconstruct(secret(length)).expect("valid PUK")
    }

    fn is_length_refusal<T>(result: Result<T, AuthError<String>>, role: CredentialRole) -> bool {
        matches!(
            result,
            Err(AuthError::PinLength(
                PinLengthRefusal::OutsideAcceptedRange { role: refused, .. }
            )) if refused == role
        )
    }

    const NUMBERINGS: &[PinReferenceScheme] = &[
        PinReferenceScheme::Citizen,
        PinReferenceScheme::Organizational,
    ];

    #[test]
    fn change_refuses_an_entry_outside_the_card_range_before_any_command() {
        for &numbering in NUMBERINGS {
            let lengths = narrow_lengths(numbering);
            let fits = usize::from(OLDER_ORGANIZATION_MAX);
            let mut card = SimulatedCard::new(numbering, None);
            let refused = card.change_pin1(&lengths, pin1(fits), pin1(PIN_MAX_LENGTH));
            assert!(is_length_refusal(refused, CredentialRole::Pin1));
            let refused = card.change_pin2(&lengths, pin2(PIN_MAX_LENGTH), pin2(fits));
            assert!(is_length_refusal(refused, CredentialRole::Pin2));
            assert_eq!(card.plain_commands + card.credential_commands, 0);

            let changed = card
                .change_pin1(&lengths, pin1(fits), pin1(PIN_MIN_LENGTH))
                .expect("accepted lengths reach the card");
            assert_eq!(changed, ManageOutcome::Ok);
            assert_eq!(card.credential_commands, 1);
        }
    }

    #[test]
    fn unblock_refuses_an_entry_outside_the_card_range_before_any_command() {
        for &numbering in NUMBERINGS {
            let lengths = narrow_lengths(numbering);
            let mut card = SimulatedCard::new(numbering, None);
            let refused = card.unblock_pin1(&lengths, puk(PUK_MIN_LENGTH), pin1(PIN_MIN_LENGTH));
            assert!(is_length_refusal(refused, CredentialRole::Puk));
            let refused = card.unblock_pin2(&lengths, puk(PUK_MAX_LENGTH), pin2(PIN_MAX_LENGTH));
            assert!(is_length_refusal(refused, CredentialRole::Pin2));
            assert_eq!(card.plain_commands + card.credential_commands, 0);

            let unblocked = card
                .unblock_pin2(&lengths, puk(PUK_MAX_LENGTH), pin2(FINEID_PIN2_MIN_LENGTH))
                .expect("accepted lengths reach the card");
            assert_eq!(unblocked, ManageOutcome::Ok);
        }
    }

    #[test]
    fn activation_refuses_an_entry_outside_the_card_range_before_any_command() {
        let lengths = narrow_lengths(PinReferenceScheme::Organizational);
        let code = |scheme: ActivationScheme| {
            ActivationCode::reconstruct(secret(scheme.activation_entry_digit_count()), scheme)
                .expect("valid activation PIN")
        };
        let mut card = SimulatedCard::new(PinReferenceScheme::Organizational, None);
        // The 8-digit activation PIN stands in for a PUK the card lists
        // from twelve digits.
        let refused = card.activate_card(
            &lengths,
            code(ActivationScheme::ActivationCodeIsPuk),
            Some(pin1(PIN_MIN_LENGTH)),
            None,
        );
        assert!(is_length_refusal(refused, CredentialRole::ActivationCode));
        let not_listed = CardPinLengths::not_listed(PinReferenceScheme::Organizational);
        let refused = card.activate_card(
            &lengths,
            code(ActivationScheme::PresetActivationPin),
            None,
            Some(pin2(PIN_MAX_LENGTH)),
        );
        assert!(is_length_refusal(refused, CredentialRole::Pin2));
        assert_eq!(card.plain_commands + card.credential_commands, 0);

        let narrow_pin2 = directory(&[object(
            PIN2_REFERENCE_ORGANIZATIONAL,
            CITIZEN_PIN2_MIN,
            STORED_LENGTH,
            Some(CITIZEN_PIN2_MIN),
        )]);
        let preset_refused = from_directory(PinReferenceScheme::Organizational, &narrow_pin2);
        let refused = card.activate_card(
            &preset_refused,
            code(ActivationScheme::PresetActivationPin),
            None,
            Some(pin2(FINEID_PIN2_MIN_LENGTH)),
        );
        assert!(is_length_refusal(refused, CredentialRole::ActivationCode));
        assert_eq!(card.plain_commands + card.credential_commands, 0);

        assert!(
            card.activate_card(
                &not_listed,
                code(ActivationScheme::ActivationCodeIsPuk),
                Some(pin1(PIN_MIN_LENGTH)),
                Some(pin2(FINEID_PIN2_MIN_LENGTH)),
            )
            .is_ok()
        );
    }

    /// A transport whose session fails.
    struct FailingCard;

    impl CardTransport for FailingCard {
        type Error = String;

        fn transmit(&mut self, _command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            Err(String::from("card removed"))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err(String::from("card removed"))
        }
    }

    #[test]
    fn a_failed_session_is_an_error_not_an_empty_listing() {
        let result = FailingCard.read_card_pin_lengths_with_scheme(PinReferenceScheme::Citizen);
        assert!(matches!(result, Err(AuthError::Transport(_))));
    }
}
