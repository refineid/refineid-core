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

//! EF.CardAccess: the PACE suites a card publishes before any channel
//! exists.
//!
//! The file sits in the master file, is readable always, and holds the
//! DER-encoded `SecurityInfos` (BSI TR-03110-3 section A.1.2.1 and table
//! 2). The terminal picks its PACE mechanism and domain parameters from
//! the `PACEInfo` entries there (section A.1.1.1). The file is
//! unprotected, and domain parameters a terminal has not verified can
//! leak the password (section A.2.1.3), so only the standardized domain
//! parameters of table 4 that this crate implements are admitted.
//!
//! The citizen cards publish generic and chip-authentication mapping
//! over brainpoolP384r1 (FINEID S4-1 v4.2 section 3.2); the
//! organizational cards publish generic and integrated mapping over NIST
//! P-256 and P-384 (FINEID S4-2 v4.0 section 6).

use refineid_apdu::{CardTransport, FileId};
use refineid_ber::{BerTlv, BerTlvAny, BerTlvIter, Integer, Oid, Sequence, Set};
use refineid_pkcs15::Pkcs15Ops as _;

use crate::handshake::PaceError;

/// File identifier of EF.CardAccess in the master file (BSI TR-03110-3
/// table 2).
pub const EF_CARD_ACCESS_FID: u16 = 0x011C;

/// Length of a PACE protocol object-identifier body, in bytes.
const PACE_PROTOCOL_OID_LEN: usize = 10;

/// DER object identifier body for `id-PACE-ECDH-GM-AES-CBC-CMAC-256`
/// (OID 0.4.0.127.0.7.2.2.4.2.4, BSI TR-03110-3 section A.1.1.1), without
/// the tag and length octets.
pub(crate) const PACE_ECDH_GM_AES_256_OID: [u8; PACE_PROTOCOL_OID_LEN] =
    [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];

/// DER object identifier body for `id-PACE-ECDH-IM-AES-CBC-CMAC-256`
/// (OID 0.4.0.127.0.7.2.2.4.4.4, BSI TR-03110-3 section A.1.1.1), without
/// the tag and length octets.
pub(crate) const PACE_ECDH_IM_AES_256_OID: [u8; PACE_PROTOCOL_OID_LEN] =
    [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04];

/// The `PACEInfo` version this crate implements; version 1 is
/// deprecated (BSI TR-03110-3 section A.1.1.1).
pub(crate) const PACE_INFO_VERSION: u8 = 2;

/// Standardized domain parameter identifier of NIST P-256 (BSI
/// TR-03110-3 table 4).
const PARAMETER_ID_NIST_P256: u8 = 12;
/// Standardized domain parameter identifier of NIST P-384 (BSI
/// TR-03110-3 table 4).
const PARAMETER_ID_NIST_P384: u8 = 15;
/// Standardized domain parameter identifier of brainpoolP384r1 (BSI
/// TR-03110-3 table 4).
const PARAMETER_ID_BRAINPOOL_P384_R1: u8 = 16;

/// The sign bit of the first content octet of a DER INTEGER (ITU-T
/// X.690 section 8.3.3).
const INTEGER_SIGN_BIT: u8 = 0x80;
/// The leading octet a DER INTEGER carries only to clear the sign bit
/// of the octet after it (ITU-T X.690 section 8.3.2).
const INTEGER_PAD_OCTET: u8 = 0x00;
/// The leading octet a DER INTEGER carries only to set the sign bit of
/// the octet after it (ITU-T X.690 section 8.3.2).
const INTEGER_SIGN_EXTENSION_OCTET: u8 = 0xFF;

/// How a PACE mechanism maps the card nonce to the session generator
/// (ICAO Doc 9303 Part 11 section 4.4.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaceMapping {
    /// Generic mapping: an anonymous Diffie-Hellman key agreement,
    /// `G' = s * G + H` (section 4.4.3.3.1).
    Generic,
    /// Integrated mapping: a pseudo-random point derived from the nonce
    /// (section 4.4.3.3.2). Published by the organizational cards; the
    /// handshake here runs generic mapping.
    Integrated,
}

/// A standardized PACE domain parameter this crate implements (BSI
/// TR-03110-3 table 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaceDomain {
    /// NIST P-256 (`secp256r1`), identifier 12.
    NistP256,
    /// NIST P-384 (`secp384r1`), identifier 15.
    NistP384,
    /// brainpoolP384r1 (RFC 5639 section 3.6), identifier 16.
    BrainpoolP384r1,
}

impl PaceDomain {
    /// The domains in the order the handshake prefers them: the 384-bit
    /// curves first, NIST P-384 ahead of brainpoolP384r1, then P-256.
    const PREFERENCE: &[Self] = &[Self::NistP384, Self::BrainpoolP384r1, Self::NistP256];

    /// The standardized domain parameter identifier, as `MSE:Set AT`
    /// names it (BSI TR-03110-3 section B.14.1).
    #[must_use]
    pub const fn parameter_id(self) -> u8 {
        match self {
            Self::NistP256 => PARAMETER_ID_NIST_P256,
            Self::NistP384 => PARAMETER_ID_NIST_P384,
            Self::BrainpoolP384r1 => PARAMETER_ID_BRAINPOOL_P384_R1,
        }
    }

    const fn from_parameter_id(id: u8) -> Option<Self> {
        match id {
            PARAMETER_ID_NIST_P256 => Some(Self::NistP256),
            PARAMETER_ID_NIST_P384 => Some(Self::NistP384),
            PARAMETER_ID_BRAINPOOL_P384_R1 => Some(Self::BrainpoolP384r1),
            _ => None,
        }
    }
}

/// One PACE suite the card publishes, of the two this crate parses:
/// `id-PACE-ECDH-GM-AES-CBC-CMAC-256` or
/// `id-PACE-ECDH-IM-AES-CBC-CMAC-256`, `PACEInfo` version 2, over a
/// standardized domain parameter from [`PaceDomain`]. The handshake runs
/// the generic-mapping suites; [`CardAccess::generic_mapping_suite`]
/// names the one it runs.
///
/// Exists only through [`CardAccess::parse`], so a value is proof that
/// the card listed the suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaceInfo {
    mapping: PaceMapping,
    domain: PaceDomain,
}

impl PaceInfo {
    /// The mapping the suite names.
    #[must_use]
    pub const fn mapping(self) -> PaceMapping {
        self.mapping
    }

    /// The domain parameter the suite names.
    #[must_use]
    pub const fn domain(self) -> PaceDomain {
        self.domain
    }

    /// The protocol object-identifier body `MSE:Set AT` and the
    /// authentication token carry (BSI TR-03110-3 sections A.2.4 and
    /// B.14.1).
    pub(crate) const fn protocol_oid(self) -> &'static [u8; PACE_PROTOCOL_OID_LEN] {
        match self.mapping {
            PaceMapping::Generic => &PACE_ECDH_GM_AES_256_OID,
            PaceMapping::Integrated => &PACE_ECDH_IM_AES_256_OID,
        }
    }

    /// Reconstruct a `PACEInfo` from a `SecurityInfo` whose protocol
    /// object identifier is `protocol` and whose remaining fields are
    /// `fields` (BSI TR-03110-3 section A.1.1.1):
    ///
    /// ```text
    /// PACEInfo ::= SEQUENCE {
    ///   protocol    OBJECT IDENTIFIER,
    ///   version     INTEGER,
    ///   parameterId INTEGER OPTIONAL
    /// }
    /// ```
    ///
    /// `Ok(None)` for an entry that is well formed but not a suite this
    /// crate implements: another protocol, another PACE mechanism, a
    /// version other than 2, or a domain parameter that is explicit
    /// (no `parameterId`) or not in [`PaceDomain`].
    fn from_security_info(
        protocol: &[u8],
        mut fields: BerTlvIter<'_>,
    ) -> Result<Option<Self>, CardAccessError> {
        let mapping = if protocol == PACE_ECDH_GM_AES_256_OID {
            PaceMapping::Generic
        } else if protocol == PACE_ECDH_IM_AES_256_OID {
            PaceMapping::Integrated
        } else {
            return Ok(None);
        };
        let version = match fields.next() {
            Some(field) => {
                small_unsigned(field.map_err(|_framing| CardAccessError::MalformedPaceInfo)?)?
            }
            None => return Err(CardAccessError::MalformedPaceInfo),
        };
        let parameter_id = match fields.next() {
            Some(field) => Some(small_unsigned(
                field.map_err(|_framing| CardAccessError::MalformedPaceInfo)?,
            )?),
            None => None,
        };
        if fields.next().is_some() {
            return Err(CardAccessError::MalformedPaceInfo);
        }
        if version != Some(PACE_INFO_VERSION) {
            return Ok(None);
        }
        let Some(Some(parameter_id)) = parameter_id else {
            return Ok(None);
        };
        Ok(PaceDomain::from_parameter_id(parameter_id).map(|domain| Self { mapping, domain }))
    }
}

/// Decode a `PACEInfo` INTEGER field. `Some(value)` for a value from
/// zero to the largest octet, `None` for a negative or larger value,
/// which names no field value this crate implements.
///
/// # Errors
///
/// [`CardAccessError::MalformedPaceInfo`] when the field is not an
/// INTEGER, or not in the minimal DER encoding (ITU-T X.690 sections
/// 8.3.1 and 8.3.2).
fn small_unsigned(field: BerTlvAny<'_>) -> Result<Option<u8>, CardAccessError> {
    let integer = field
        .expect::<Integer>()
        .map_err(|_tag| CardAccessError::MalformedPaceInfo)?;
    match integer.value() {
        [] => Err(CardAccessError::MalformedPaceInfo),
        [only] if only & INTEGER_SIGN_BIT == 0 => Ok(Some(*only)),
        [_negative] => Ok(None),
        [INTEGER_PAD_OCTET, second, ..] if second & INTEGER_SIGN_BIT == 0 => {
            Err(CardAccessError::MalformedPaceInfo)
        }
        [INTEGER_SIGN_EXTENSION_OCTET, second, ..] if second & INTEGER_SIGN_BIT != 0 => {
            Err(CardAccessError::MalformedPaceInfo)
        }
        [INTEGER_PAD_OCTET, second] => Ok(Some(*second)),
        [_first, _second, ..] => Ok(None),
    }
}

/// The bytes of EF.CardAccess as read from the card, before parsing.
///
/// The one input border of [`CardAccess`]; transit only, consumed by
/// [`CardAccess::parse`].
#[derive(Debug)]
pub struct UnvalidatedCardAccess {
    bytes: Vec<u8>,
}

impl UnvalidatedCardAccess {
    /// Take ownership of the bytes a READ BINARY of EF.CardAccess
    /// returned.
    #[must_use]
    pub const fn from_card_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

/// Why EF.CardAccess did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardAccessError {
    /// The file is not one DER `SET OF SecurityInfo` and nothing else:
    /// a BER framing failure, another outer tag, or bytes after the set.
    NotSecurityInfos,
    /// An element of the set is not a `SEQUENCE` that starts with its
    /// protocol object identifier (BSI TR-03110-3 section A.1).
    MalformedSecurityInfo,
    /// A `PACEInfo` of a suite this crate implements does not have the
    /// version and optional parameter identifier, as minimal DER
    /// INTEGERs, and nothing else (BSI TR-03110-3 section A.1.1.1).
    MalformedPaceInfo,
}

impl core::fmt::Display for CardAccessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotSecurityInfos => f.write_str("EF.CardAccess is not a set of SecurityInfos"),
            Self::MalformedSecurityInfo => {
                f.write_str("EF.CardAccess holds a malformed SecurityInfo")
            }
            Self::MalformedPaceInfo => f.write_str("EF.CardAccess holds a malformed PACEInfo"),
        }
    }
}

impl core::error::Error for CardAccessError {}

/// The [`PaceInfo`] suites EF.CardAccess lists, in the order the card
/// lists them.
///
/// Other `SecurityInfo` entries -- other protocols, other PACE
/// mechanisms such as chip-authentication mapping, other versions,
/// explicit or unimplemented domain parameters -- are not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardAccess {
    pace: Vec<PaceInfo>,
}

impl CardAccess {
    /// Parse EF.CardAccess: one DER `SET OF SecurityInfo` (BSI
    /// TR-03110-3 sections A.1 and A.1.2.1), each `SecurityInfo` a
    /// `SEQUENCE` that starts with its protocol object identifier.
    ///
    /// # Errors
    ///
    /// [`CardAccessError`] naming the first structural failure.
    pub fn parse(input: UnvalidatedCardAccess) -> Result<Self, CardAccessError> {
        let bytes = input.bytes.as_slice();
        let set =
            BerTlv::<Set>::parse(bytes).map_err(|_framing| CardAccessError::NotSecurityInfos)?;
        if set.size() != bytes.len() {
            return Err(CardAccessError::NotSecurityInfos);
        }
        let mut pace = Vec::new();
        for element in set.iter_children() {
            let info = element
                .and_then(BerTlvAny::expect::<Sequence>)
                .map_err(|_framing| CardAccessError::MalformedSecurityInfo)?;
            let mut fields = info.iter_children();
            let protocol = fields
                .next()
                .ok_or(CardAccessError::MalformedSecurityInfo)?
                .and_then(BerTlvAny::expect::<Oid>)
                .map_err(|_framing| CardAccessError::MalformedSecurityInfo)?;
            if let Some(suite) = PaceInfo::from_security_info(protocol.value(), fields)? {
                pace.push(suite);
            }
        }
        Ok(Self { pace })
    }

    /// Every parsed suite the card lists, integrated mapping included.
    #[must_use]
    pub fn pace_infos(&self) -> &[PaceInfo] {
        &self.pace
    }

    /// The generic-mapping suite the handshake runs: the listed one over
    /// the most preferred domain parameter, NIST P-384, then
    /// brainpoolP384r1, then NIST P-256. `None` when the card lists no
    /// generic-mapping suite over any of them.
    #[must_use]
    pub fn generic_mapping_suite(&self) -> Option<PaceInfo> {
        PaceDomain::PREFERENCE.iter().find_map(|&domain| {
            self.pace
                .iter()
                .copied()
                .find(|info| info.mapping == PaceMapping::Generic && info.domain == domain)
        })
    }
}

/// Read and parse EF.CardAccess from the card's master file.
///
/// Selects EF.CardAccess by its file identifier and reads exactly its
/// one DER object. The card must be at master-file level, where PACE
/// itself starts.
///
/// # Errors
///
/// [`PaceError::CardAccessRead`] when the selection or the read fails,
/// [`PaceError::CardAccess`] when the bytes do not parse.
pub fn read_card_access<T: CardTransport>(
    transport: &mut T,
) -> Result<CardAccess, PaceError<T::Error>> {
    transport
        .select_ef(FileId::from_u16(EF_CARD_ACCESS_FID))
        .map_err(PaceError::CardAccessRead)?;
    let bytes = transport
        .read_binary_der_object("EF.CardAccess")
        .map_err(PaceError::CardAccessRead)?;
    CardAccess::parse(UnvalidatedCardAccess::from_card_bytes(bytes)).map_err(PaceError::CardAccess)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        CardAccess, CardAccessError, INTEGER_PAD_OCTET, INTEGER_SIGN_BIT,
        INTEGER_SIGN_EXTENSION_OCTET, PACE_ECDH_GM_AES_256_OID, PACE_ECDH_IM_AES_256_OID,
        PACE_INFO_VERSION, PaceDomain, PaceInfo, PaceMapping, UnvalidatedCardAccess,
    };
    use refineid_ber::{BerEncoder, BerTag, Integer, Oid, Sequence, Set};

    /// A one-byte tag of a universal-class ASN.1 type.
    fn tag(marker: u16) -> u8 {
        u8::try_from(marker).expect("universal tags fit one octet")
    }

    /// DER object identifier body for
    /// `id-PACE-ECDH-CAM-AES-CBC-CMAC-256` (OID 0.4.0.127.0.7.2.2.4.6.4,
    /// BSI TR-03110-3 section A.1.1.1), the citizen card's second entry.
    const PACE_ECDH_CAM_AES_256_OID: [u8; super::PACE_PROTOCOL_OID_LEN] =
        [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x04];

    /// A deprecated `PACEInfo` version.
    const PACE_INFO_VERSION_ONE: u8 = 1;
    /// A table 4 identifier this crate does not implement:
    /// brainpoolP256r1.
    const PARAMETER_ID_BRAINPOOL_P256_R1: u8 = 13;

    /// A `PACEInfo` SEQUENCE: the protocol, the version, and the
    /// optional parameter identifier, each assembled from named tags.
    pub(crate) fn pace_info(protocol: &[u8], version: u8, parameter_id: Option<u8>) -> Vec<u8> {
        let mut fields = BerEncoder::default();
        fields.push_tlv(tag(Oid::TAG), protocol).expect("encodes");
        fields
            .push_tlv(tag(Integer::TAG), [version])
            .expect("encodes");
        if let Some(id) = parameter_id {
            fields.push_tlv(tag(Integer::TAG), [id]).expect("encodes");
        }
        refineid_ber::tlv(tag(Sequence::TAG), fields.finish()).expect("encodes")
    }

    /// EF.CardAccess: the SET of the given `SecurityInfo` encodings.
    pub(crate) fn card_access_file(infos: &[Vec<u8>]) -> Vec<u8> {
        refineid_ber::tlv(tag(Set::TAG), infos.concat()).expect("encodes")
    }

    /// The organizational card's EF.CardAccess: generic and integrated
    /// mapping over NIST P-256 and NIST P-384 (FINEID S4-2 v4.0 section
    /// 6).
    pub(crate) fn organizational_card_access() -> Vec<u8> {
        card_access_file(&[
            pace_info(
                &PACE_ECDH_GM_AES_256_OID,
                PACE_INFO_VERSION,
                Some(PaceDomain::NistP256.parameter_id()),
            ),
            pace_info(
                &PACE_ECDH_GM_AES_256_OID,
                PACE_INFO_VERSION,
                Some(PaceDomain::NistP384.parameter_id()),
            ),
            pace_info(
                &PACE_ECDH_IM_AES_256_OID,
                PACE_INFO_VERSION,
                Some(PaceDomain::NistP256.parameter_id()),
            ),
            pace_info(
                &PACE_ECDH_IM_AES_256_OID,
                PACE_INFO_VERSION,
                Some(PaceDomain::NistP384.parameter_id()),
            ),
        ])
    }

    /// The citizen card's EF.CardAccess: generic and chip-authentication
    /// mapping over brainpoolP384r1 (FINEID S4-1 v4.2 section 3.2).
    pub(crate) fn citizen_card_access() -> Vec<u8> {
        card_access_file(&[
            pace_info(
                &PACE_ECDH_GM_AES_256_OID,
                PACE_INFO_VERSION,
                Some(PaceDomain::BrainpoolP384r1.parameter_id()),
            ),
            pace_info(
                &PACE_ECDH_CAM_AES_256_OID,
                PACE_INFO_VERSION,
                Some(PaceDomain::BrainpoolP384r1.parameter_id()),
            ),
        ])
    }

    fn parse(bytes: Vec<u8>) -> Result<CardAccess, CardAccessError> {
        CardAccess::parse(UnvalidatedCardAccess::from_card_bytes(bytes))
    }

    #[test]
    fn the_organizational_set_parses_to_four_suites_and_picks_p384() {
        let access = parse(organizational_card_access()).expect("parses");
        let suites: Vec<(PaceMapping, PaceDomain)> = access
            .pace_infos()
            .iter()
            .map(|info| (info.mapping(), info.domain()))
            .collect();
        assert_eq!(
            suites,
            vec![
                (PaceMapping::Generic, PaceDomain::NistP256),
                (PaceMapping::Generic, PaceDomain::NistP384),
                (PaceMapping::Integrated, PaceDomain::NistP256),
                (PaceMapping::Integrated, PaceDomain::NistP384),
            ]
        );
        assert_eq!(
            access.generic_mapping_suite(),
            Some(PaceInfo {
                mapping: PaceMapping::Generic,
                domain: PaceDomain::NistP384
            })
        );
    }

    #[test]
    fn the_organizational_file_is_eighty_two_bytes() {
        /// The size of the organizational card's EF.CardAccess as read.
        const ORGANIZATIONAL_FILE_LEN: usize = 82;
        assert_eq!(organizational_card_access().len(), ORGANIZATIONAL_FILE_LEN);
    }

    #[test]
    fn the_citizen_set_keeps_generic_mapping_and_skips_chip_authentication_mapping() {
        let access = parse(citizen_card_access()).expect("parses");
        let expected = PaceInfo {
            mapping: PaceMapping::Generic,
            domain: PaceDomain::BrainpoolP384r1,
        };
        assert_eq!(access.pace_infos(), &[expected]);
        assert_eq!(access.generic_mapping_suite(), Some(expected));
    }

    #[test]
    fn p256_alone_is_picked_when_nothing_stronger_is_listed() {
        let access = parse(card_access_file(&[pace_info(
            &PACE_ECDH_GM_AES_256_OID,
            PACE_INFO_VERSION,
            Some(PaceDomain::NistP256.parameter_id()),
        )]))
        .expect("parses");
        assert_eq!(
            access.generic_mapping_suite().map(PaceInfo::domain),
            Some(PaceDomain::NistP256)
        );
    }

    #[test]
    fn integrated_mapping_alone_offers_no_generic_suite() {
        let access = parse(card_access_file(&[pace_info(
            &PACE_ECDH_IM_AES_256_OID,
            PACE_INFO_VERSION,
            Some(PaceDomain::NistP384.parameter_id()),
        )]))
        .expect("parses");
        assert_eq!(access.generic_mapping_suite(), None);
    }

    #[test]
    fn unimplemented_entries_are_skipped() {
        let access = parse(card_access_file(&[
            pace_info(
                &PACE_ECDH_GM_AES_256_OID,
                PACE_INFO_VERSION_ONE,
                Some(PaceDomain::NistP384.parameter_id()),
            ),
            pace_info(&PACE_ECDH_GM_AES_256_OID, PACE_INFO_VERSION, None),
            pace_info(
                &PACE_ECDH_GM_AES_256_OID,
                PACE_INFO_VERSION,
                Some(PARAMETER_ID_BRAINPOOL_P256_R1),
            ),
        ]))
        .expect("parses");
        assert!(access.pace_infos().is_empty());
        assert_eq!(access.generic_mapping_suite(), None);
    }

    #[test]
    fn trailing_bytes_after_the_set_are_refused() {
        let mut bytes = citizen_card_access();
        bytes.push(INTEGER_PAD_OCTET);
        assert_eq!(parse(bytes), Err(CardAccessError::NotSecurityInfos));
    }

    #[test]
    fn another_outer_tag_is_refused() {
        let sequence =
            refineid_ber::tlv(tag(Sequence::TAG), citizen_card_access()).expect("encodes");
        assert_eq!(parse(sequence), Err(CardAccessError::NotSecurityInfos));
        assert_eq!(parse(Vec::new()), Err(CardAccessError::NotSecurityInfos));
    }

    #[test]
    fn a_security_info_that_is_not_a_sequence_is_refused() {
        let oid = refineid_ber::tlv(tag(Oid::TAG), PACE_ECDH_GM_AES_256_OID).expect("encodes");
        assert_eq!(
            parse(card_access_file(&[oid])),
            Err(CardAccessError::MalformedSecurityInfo)
        );
        let empty = refineid_ber::tlv(tag(Sequence::TAG), []).expect("encodes");
        assert_eq!(
            parse(card_access_file(&[empty])),
            Err(CardAccessError::MalformedSecurityInfo)
        );
    }

    #[test]
    fn a_pace_info_without_a_version_or_with_extra_fields_is_refused() {
        let protocol_only = refineid_ber::tlv(
            tag(Sequence::TAG),
            refineid_ber::tlv(tag(Oid::TAG), PACE_ECDH_GM_AES_256_OID).expect("encodes"),
        )
        .expect("encodes");
        assert_eq!(
            parse(card_access_file(&[protocol_only])),
            Err(CardAccessError::MalformedPaceInfo)
        );

        let mut extra = BerEncoder::default();
        extra
            .push_tlv(tag(Oid::TAG), PACE_ECDH_GM_AES_256_OID)
            .expect("encodes");
        extra
            .push_tlv(tag(Integer::TAG), [PACE_INFO_VERSION])
            .expect("encodes");
        extra
            .push_tlv(tag(Integer::TAG), [PaceDomain::NistP384.parameter_id()])
            .expect("encodes");
        extra
            .push_tlv(tag(Integer::TAG), [PACE_INFO_VERSION])
            .expect("encodes");
        let extra = refineid_ber::tlv(tag(Sequence::TAG), extra.finish()).expect("encodes");
        assert_eq!(
            parse(card_access_file(&[extra])),
            Err(CardAccessError::MalformedPaceInfo)
        );
    }

    #[test]
    fn a_non_minimal_integer_is_refused() {
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(tag(Oid::TAG), PACE_ECDH_GM_AES_256_OID)
            .expect("encodes");
        fields
            .push_tlv(tag(Integer::TAG), [INTEGER_PAD_OCTET, PACE_INFO_VERSION])
            .expect("encodes");
        let info = refineid_ber::tlv(tag(Sequence::TAG), fields.finish()).expect("encodes");
        assert_eq!(
            parse(card_access_file(&[info])),
            Err(CardAccessError::MalformedPaceInfo)
        );
    }

    #[test]
    fn a_non_minimal_negative_integer_is_refused() {
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(tag(Oid::TAG), PACE_ECDH_GM_AES_256_OID)
            .expect("encodes");
        fields
            .push_tlv(
                tag(Integer::TAG),
                [INTEGER_SIGN_EXTENSION_OCTET, INTEGER_SIGN_BIT],
            )
            .expect("encodes");
        let info = refineid_ber::tlv(tag(Sequence::TAG), fields.finish()).expect("encodes");
        assert_eq!(
            parse(card_access_file(&[info])),
            Err(CardAccessError::MalformedPaceInfo)
        );
    }

    #[test]
    fn a_padded_large_parameter_id_names_no_domain() {
        let mut fields = BerEncoder::default();
        fields
            .push_tlv(tag(Oid::TAG), PACE_ECDH_GM_AES_256_OID)
            .expect("encodes");
        fields
            .push_tlv(tag(Integer::TAG), [PACE_INFO_VERSION])
            .expect("encodes");
        fields
            .push_tlv(tag(Integer::TAG), [INTEGER_PAD_OCTET, INTEGER_SIGN_BIT])
            .expect("encodes");
        let info = refineid_ber::tlv(tag(Sequence::TAG), fields.finish()).expect("encodes");
        let access = parse(card_access_file(&[info])).expect("parses");
        assert!(access.pace_infos().is_empty());
    }
}
