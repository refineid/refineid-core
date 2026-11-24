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

//! FINEID card identity: types, classification by ATR/ATS, and the
//! canonical strings refineid emits for each card.
//!
//! The models and their ATR/ATS values come from DVV's technology note
//! on ATR bytes.

use core::fmt;

use crate::{Atr, HistoricalDataObject};

/// Byte width of FINEID pre-issuing data (compact-TLV tag 6, FINEID
/// S4-1 §3.3.1).
pub const FINEID_PRE_ISSUING_LEN: usize = 5;

/// Maximum ATS length per ISO 14443-4.
pub const ATS_MAX_LEN: usize = 254;

/// FINEID pre-issuing family-name marker (byte 1) on observed
/// `MultiApp` cards (FINEID S4-1 §3.3.1).
const FINEID_PRE_ISSUING_FAMILY: u8 = 0xB0;
/// FINEID pre-issuing product-name marker (byte 2).
const FINEID_PRE_ISSUING_PRODUCT: u8 = 0x85;
/// Pre-issuing OS-version marker (byte 3) for `MultiApp` v5.0 (Thales).
const FINEID_OS_VERSION_THALES_V5_0: u8 = 0x05;
/// Pre-issuing OS-version marker (byte 3) for `MultiApp` v4.2 (Gemalto).
const FINEID_OS_VERSION_GEMALTO_V4_2: u8 = 0x04;

/// Thales `MultiApp` v5.0 (FINEID S4-1 v4.0), chip-revision v1.0.0,
/// contact ATR from DVV's ATR/ATS technote v1.0 (2024-08-12).
const THALES_MULTIAPP_V5_0_REV_1_0_CONTACT_ATR: &[u8] = &[
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x00, 0x11, 0x12, 0x24,
    0x60, 0x82, 0x90, 0x00,
];

/// Thales `MultiApp` v5.0 (FINEID S4-1 v4.0), chip-revision v2.0.0,
/// contact ATR field-observed 2026-05-24 on a freshly-issued production
/// card.
const THALES_MULTIAPP_V5_0_REV_2_0_CONTACT_ATR: &[u8] = &[
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x10, 0x24, 0x12, 0x24,
    0x60, 0x82, 0x90, 0x00,
];

/// Gemalto `MultiApp` v4.2 (FINEID S4-1 v3.1) contact ATR from DVV's
/// ATR/ATS technote v1.0 (2024-08-12).
const GEMALTO_MULTIAPP_V4_2_CONTACT_ATR: &[u8] = &[
    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x04, 0x02, 0x1B, 0x12, 0x00,
    0xF6, 0x82, 0x90, 0x00,
];

/// Idemia Cosmo X contact ATR from DVV's technology note on ATR bytes
/// (v1.0, 2024-08-12), section "Idemia Cosmo X".
const IDEMIA_COSMO_X_CONTACT_ATR: &[u8] = &[
    0x3B, 0xDD, 0x96, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x00, 0x31, 0xB8, 0x64, 0x04, 0x29, 0xEC, 0xC1,
    0x73, 0x94, 0x01, 0x80, 0x83, 0x49,
];

/// Thales `MultiApp` v5.0 contactless ATS from DVV's ATR/ATS technote.
const THALES_MULTIAPP_V5_0_CONTACTLESS_ATS: &[u8] = &[
    0x14, 0x78, 0x77, 0x95, 0x02, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x00, 0x11, 0x12, 0x24,
    0x60, 0x82, 0x90, 0x00,
];

/// Gemalto `MultiApp` v4.2 contactless ATS from DVV's ATR/ATS technote.
const GEMALTO_MULTIAPP_V4_2_CONTACTLESS_ATS: &[u8] = &[
    0x14, 0x78, 0x77, 0x95, 0x02, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x04, 0x02, 0x1B, 0x12, 0x00,
    0xF6, 0x82, 0x90, 0x00,
];

/// Idemia Cosmo X contactless ATR/ATS sequence published verbatim in
/// DVV's technology note on ATR bytes (v1.0, 2024-08-12), section
/// "Idemia Cosmo X". Unlike the `MultiApp` entries (which are raw
/// ISO 14443-4 `TL`-prefixed ATS byte sequences), DVV's note records
/// the 17-byte PC/SC contactless ATR form for Cosmo X.
const IDEMIA_COSMO_X_CONTACTLESS_ATS: &[u8] = &[
    0x3B, 0x89, 0x80, 0x01, 0x00, 0x31, 0xB8, 0x64, 0x04, 0x29, 0xEC, 0xC1, 0x73, 0x94, 0x01, 0x80,
    0x83,
];

/// Known contact ATRs for [`FineidCardModel::ThalesMultiAppV5_0`].
const THALES_MULTIAPP_V5_0_CONTACT_ATRS: &[&[u8]] = &[
    THALES_MULTIAPP_V5_0_REV_1_0_CONTACT_ATR,
    THALES_MULTIAPP_V5_0_REV_2_0_CONTACT_ATR,
];

/// Known contact ATRs for [`FineidCardModel::GemaltoMultiAppV4_2`].
const GEMALTO_MULTIAPP_V4_2_CONTACT_ATRS: &[&[u8]] = &[GEMALTO_MULTIAPP_V4_2_CONTACT_ATR];

/// Known contact ATRs for [`FineidCardModel::IdemiaCosmoX`].
const IDEMIA_COSMO_X_CONTACT_ATRS: &[&[u8]] = &[IDEMIA_COSMO_X_CONTACT_ATR];

/// Known contactless ATSs for [`FineidCardModel::ThalesMultiAppV5_0`].
const THALES_MULTIAPP_V5_0_CONTACTLESS_ATSS: &[&[u8]] = &[THALES_MULTIAPP_V5_0_CONTACTLESS_ATS];

/// Known contactless ATSs for [`FineidCardModel::GemaltoMultiAppV4_2`].
const GEMALTO_MULTIAPP_V4_2_CONTACTLESS_ATSS: &[&[u8]] = &[GEMALTO_MULTIAPP_V4_2_CONTACTLESS_ATS];

/// Known contactless ATSs for [`FineidCardModel::IdemiaCosmoX`].
const IDEMIA_COSMO_X_CONTACTLESS_ATSS: &[&[u8]] = &[IDEMIA_COSMO_X_CONTACTLESS_ATS];

/// FINEID interpretation of the ISO 7816-4 pre-issuing data
/// (compact-TLV tag 6), per FINEID S4-1 §3.3.1.
///
/// ISO 7816-4 leaves the pre-issuing interior to the card
/// manufacturer/personalizer; the generic layer keeps it as opaque
/// bytes ([`HistoricalDataObject::PreIssuingData`]). This is the
/// FINEID layer's reading: a 5-byte block naming the product family
/// and versions. The field names follow FINEID's *contact*-interface
/// gloss (§3.3.1); FINEID's contactless table (§3.3.2) labels the
/// same five bytes more coarsely as "hardmask identification", so
/// treat the finer names as FINEID's intent, not an ISO guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FineidPreIssuingData {
    /// Byte 1 -- family name marker (`B0h` on observed FINEID cards).
    pub family_name: u8,
    /// Byte 2 -- product name marker (`85h`).
    pub product_name: u8,
    /// Byte 3 -- OS version. Distinguishes the generation:
    /// `05h` = `MultiApp` v5.0 (Thales), `04h` = v4.2 (Gemalto).
    pub os_version: u8,
    /// Byte 4 -- program version.
    pub program_version: u8,
    /// Byte 5 -- chip identifier (varies by chip revision).
    pub chip_id: u8,
}

impl FineidPreIssuingData {
    /// Build from the five pre-issuing value bytes.
    #[must_use]
    pub const fn from_array(bytes: [u8; FINEID_PRE_ISSUING_LEN]) -> Self {
        let [
            family_name,
            product_name,
            os_version,
            program_version,
            chip_id,
        ] = bytes;
        Self {
            family_name,
            product_name,
            os_version,
            program_version,
            chip_id,
        }
    }

    /// The FINEID pre-issuing data (compact-TLV tag 6, 5 bytes), if
    /// present and well-formed.
    ///
    /// Reads the generic ISO [`HistoricalDataObject::PreIssuingData`]
    /// and applies the FINEID §3.3.1 interpretation. `None` when the
    /// historical bytes carry no 5-byte pre-issuing object (e.g. a
    /// non-FINEID card).
    #[must_use]
    pub fn from_atr(atr: &Atr) -> Option<Self> {
        atr.historical_bytes()
            .data_objects()
            .into_iter()
            .find_map(|object| {
                let HistoricalDataObject::PreIssuingData(bytes) = object else {
                    return None;
                };
                match bytes.as_slice() {
                    &[b0, b1, b2, b3, b4] => Some(Self::from_array([b0, b1, b2, b3, b4])),
                    _ => None,
                }
            })
    }
}

/// Answer-To-Select bytes from a contactless (ISO 14443-4) session.
///
/// ATS is not bounded by the ATR length window; ISO 14443-4 allows up
/// to [`ATS_MAX_LEN`] bytes. We still enforce a minimum so an empty
/// value cannot masquerade as a successful ATS read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ats(Vec<u8>);

/// Error returned by [`Ats::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtsError {
    /// Input was zero bytes (ISO 14443-4 requires at least one byte).
    Empty,
    /// Input exceeded the ISO 14443-4 cap ([`ATS_MAX_LEN`] bytes).
    TooLong {
        /// Length of the rejected input in bytes.
        got: usize,
    },
}

impl fmt::Display for AtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("ATS cannot be empty"),
            Self::TooLong { got } => write!(
                f,
                "ATS too long: got {got} bytes, ISO 14443-4 caps at {ATS_MAX_LEN}"
            ),
        }
    }
}

impl core::error::Error for AtsError {}

impl Ats {
    /// Wrap a byte sequence as an ATS.
    ///
    /// # Errors
    /// Returns [`AtsError::Empty`] for zero-length input,
    /// [`AtsError::TooLong`] for more than [`ATS_MAX_LEN`] bytes.
    pub fn new<B: AsRef<[u8]>>(bytes: B) -> Result<Self, AtsError> {
        let slice = bytes.as_ref();
        if slice.is_empty() {
            return Err(AtsError::Empty);
        }
        if slice.len() > ATS_MAX_LEN {
            return Err(AtsError::TooLong { got: slice.len() });
        }
        Ok(Self(slice.to_vec()))
    }

    /// Borrow the underlying ATS byte sequence (TL + per-protocol
    /// interface bytes + historical bytes).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Ats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

/// DVV's category label for a certificate card.
///
/// The labels here are the strings DVV uses in the ATR/ATS technology
/// note, minus the trailing "card" / "cards" plural.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CardType {
    /// DVV's "Citizen eID" category.
    CitizenEid,
    /// DVV's "Social welfare and organizational" category.
    SocialWelfareAndOrganizational,
    /// DVV's "Health care and organizational" category.
    HealthCareAndOrganizational,
}

impl CardType {
    /// The DVV-published literal string used on the wire.
    #[must_use]
    pub const fn as_dvv_label(self) -> &'static str {
        match self {
            Self::CitizenEid => "Citizen eID",
            Self::SocialWelfareAndOrganizational => "Social welfare and organizational",
            Self::HealthCareAndOrganizational => "Health care and organizational",
        }
    }
}

impl fmt::Display for CardType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_dvv_label())
    }
}

/// Vendor of the smart-card hardware as DVV publishes it.
///
/// "Gemalto" became "Thales" after the 2019 acquisition; both labels
/// appear in DVV's current ATR/ATS table because pre-acquisition
/// Gemalto cards are still in the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CardVendor {
    /// Thales (post-2019 Gemalto acquisition).
    Thales,
    /// Gemalto (pre-2019 acquisition); preserved as a distinct
    /// variant so older-card identification stays exact.
    Gemalto,
    /// Idemia.
    Idemia,
}

impl CardVendor {
    /// DVV-published literal string used on the wire.
    #[must_use]
    pub const fn as_dvv_label(self) -> &'static str {
        match self {
            Self::Thales => "Thales",
            Self::Gemalto => "Gemalto",
            Self::Idemia => "Idemia",
        }
    }
}

impl fmt::Display for CardVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_dvv_label())
    }
}

/// The set of FINEID card models refineid currently recognises.
///
/// Strictly the in-scope subset of DVV's ATR/ATS note: the models whose
/// cards are within their validity window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FineidCardModel {
    /// Thales `MultiApp` v5.0 -- Citizen eID, FINEID S4-1 v4.0.
    /// In production 2023-03-13 -> .
    ThalesMultiAppV5_0,
    /// Gemalto `MultiApp` v4.2 -- Citizen eID, FINEID S4-1 v3.1.
    /// In production 2021-01-11 - 2023-03-12.
    GemaltoMultiAppV4_2,
    /// Idemia Cosmo X -- Social welfare and organizational, FINEID
    /// S1 v5.0.
    IdemiaCosmoX,
}

impl FineidCardModel {
    /// All in-scope models, in no particular order.
    #[must_use]
    pub const fn all_known() -> &'static [Self] {
        &[
            Self::ThalesMultiAppV5_0,
            Self::GemaltoMultiAppV4_2,
            Self::IdemiaCosmoX,
        ]
    }

    /// Classify an ATR to a known FINEID card model.
    ///
    /// Field-driven (FINEID S4-1 §3.3.1): reads the typed pre-issuing
    /// data's family / product / OS-version markers rather than
    /// matching the whole ATR against fixed byte tables, falling back
    /// to exact contact-ATR matching for models without FINEID
    /// pre-issuing data (such as [`Self::IdemiaCosmoX`]).
    ///
    /// # Errors
    /// [`CardClassificationError::UnknownOrUnsupportedAtr`] when the
    /// ATR carries no recognised FINEID pre-issuing data or exact
    /// contact ATR.
    pub fn from_atr(atr: &Atr) -> Result<Self, CardClassificationError> {
        FineidPreIssuingData::from_atr(atr)
            .and_then(Self::from_pre_issuing)
            .or_else(|| Self::from_exact_atr(&atr.to_wire_bytes()))
            .ok_or_else(|| CardClassificationError::UnknownOrUnsupportedAtr {
                observed: atr.clone(),
            })
    }

    /// Identify a model whose ATR carries no FINEID pre-issuing data
    /// by its full contact ATR, as DVV's note lists it.
    #[must_use]
    pub fn from_exact_atr(atr: &[u8]) -> Option<Self> {
        Self::IdemiaCosmoX
            .contact_atr_byte_sets()
            .contains(&atr)
            .then_some(Self::IdemiaCosmoX)
    }

    /// Identify the model from the FINEID pre-issuing data markers
    /// (FINEID S4-1 §3.3.1): the family/product bytes confirm a
    /// FINEID `MultiApp` card, and the OS-version byte selects the
    /// generation. `None` when the markers match no in-scope model
    /// (e.g. the expired v3.0 generation, OS version `03h`).
    #[must_use]
    pub const fn from_pre_issuing(pre: FineidPreIssuingData) -> Option<Self> {
        if pre.family_name != FINEID_PRE_ISSUING_FAMILY
            || pre.product_name != FINEID_PRE_ISSUING_PRODUCT
        {
            return None;
        }
        match pre.os_version {
            FINEID_OS_VERSION_THALES_V5_0 => Some(Self::ThalesMultiAppV5_0),
            FINEID_OS_VERSION_GEMALTO_V4_2 => Some(Self::GemaltoMultiAppV4_2),
            _ => None,
        }
    }

    /// DVV's category label for this model.
    #[must_use]
    pub const fn card_type(self) -> CardType {
        match self {
            Self::ThalesMultiAppV5_0 | Self::GemaltoMultiAppV4_2 => CardType::CitizenEid,
            Self::IdemiaCosmoX => CardType::SocialWelfareAndOrganizational,
        }
    }

    /// Vendor whose name DVV publishes for this model.
    #[must_use]
    pub const fn vendor(self) -> CardVendor {
        match self {
            Self::ThalesMultiAppV5_0 => CardVendor::Thales,
            Self::GemaltoMultiAppV4_2 => CardVendor::Gemalto,
            Self::IdemiaCosmoX => CardVendor::Idemia,
        }
    }

    /// Vendor's product family name (`"MultiApp"` or `"Cosmo"`).
    #[must_use]
    pub const fn vendor_product(self) -> &'static str {
        match self {
            Self::ThalesMultiAppV5_0 | Self::GemaltoMultiAppV4_2 => "MultiApp",
            Self::IdemiaCosmoX => "Cosmo",
        }
    }

    /// Vendor's product version, bare (`"5.0"`, `"4.2"`, `"X"`).
    #[must_use]
    pub const fn vendor_product_version(self) -> &'static str {
        match self {
            Self::ThalesMultiAppV5_0 => "5.0",
            Self::GemaltoMultiAppV4_2 => "4.2",
            Self::IdemiaCosmoX => "X",
        }
    }

    /// FINEID specification document this model implements
    /// (DVV canonical identifier, e.g. `"S4-1"` or `"S1"`).
    #[must_use]
    pub const fn fineid_specification(self) -> &'static str {
        match self {
            Self::ThalesMultiAppV5_0 | Self::GemaltoMultiAppV4_2 => "S4-1",
            Self::IdemiaCosmoX => "S1",
        }
    }

    /// Version of the FINEID specification document. Bare, no leading `"v"`.
    #[must_use]
    pub const fn fineid_specification_version(self) -> &'static str {
        match self {
            Self::ThalesMultiAppV5_0 => "4.0",
            Self::GemaltoMultiAppV4_2 => "3.1",
            Self::IdemiaCosmoX => "5.0",
        }
    }

    /// Contact-interface ATR byte sequences this model is known to emit.
    #[must_use]
    pub const fn contact_atr_byte_sets(self) -> &'static [&'static [u8]] {
        match self {
            Self::ThalesMultiAppV5_0 => THALES_MULTIAPP_V5_0_CONTACT_ATRS,
            Self::GemaltoMultiAppV4_2 => GEMALTO_MULTIAPP_V4_2_CONTACT_ATRS,
            Self::IdemiaCosmoX => IDEMIA_COSMO_X_CONTACT_ATRS,
        }
    }

    /// Contactless-interface ATS byte sequences this model is known to emit.
    #[must_use]
    pub const fn contactless_ats_byte_sets(self) -> &'static [&'static [u8]] {
        match self {
            Self::ThalesMultiAppV5_0 => THALES_MULTIAPP_V5_0_CONTACTLESS_ATSS,
            Self::GemaltoMultiAppV4_2 => GEMALTO_MULTIAPP_V4_2_CONTACTLESS_ATSS,
            Self::IdemiaCosmoX => IDEMIA_COSMO_X_CONTACTLESS_ATSS,
        }
    }
}

/// Error returned by [`FineidCardModel::from_atr`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardClassificationError {
    /// Observed ATR did not match any FINEID card model in
    /// [`FineidCardModel::all_known`]. Expired DVV card models land
    /// here, as does any non-FINEID smartcard.
    UnknownOrUnsupportedAtr {
        /// The ATR bytes that did not classify.
        observed: Atr,
    },
}

impl fmt::Display for CardClassificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOrUnsupportedAtr { observed } => write!(
                f,
                "card ATR `{observed}` does not match any in-scope FINEID card model"
            ),
        }
    }
}

impl core::error::Error for CardClassificationError {}

#[cfg(test)]
mod tests {
    use super::{
        ATS_MAX_LEN, Ats, AtsError, CardClassificationError, CardType, CardVendor,
        FINEID_OS_VERSION_THALES_V5_0, FINEID_PRE_ISSUING_FAMILY, FINEID_PRE_ISSUING_PRODUCT,
        FineidCardModel, FineidPreIssuingData, THALES_MULTIAPP_V5_0_REV_1_0_CONTACT_ATR,
    };
    use crate::{ATR_MAX_LEN, ATR_MIN_LEN, Atr};

    /// Thales v5.0 rev 1.0.0 expected program-version byte.
    const REV_1_0_PROGRAM_VERSION: u8 = 0x00;
    /// Thales v5.0 rev 1.0.0 expected chip-id byte.
    const REV_1_0_CHIP_ID: u8 = 0x11;

    /// Synthetic Thales v5.0 ATR with an unenumerated chip revision
    /// (program version FEh, chip id A5h) to verify generation-stable
    /// classification.
    const SYNTHETIC_THALES_V5_0_NEW_REV_ATR: &[u8] = &[
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0xFE, 0xA5, 0x12,
        0x24, 0x60, 0x82, 0x90, 0x00,
    ];

    /// Expired Gemalto `MultiApp` v3.0 (FINEID S4-1 v3.0, OS version
    /// 03h) contact ATR; out of scope and must be rejected.
    const EXPIRED_GEMALTO_V3_0_ATR: &[u8] = &[
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x03, 0x00, 0xEF, 0x12,
        0x00, 0xF6, 0x82, 0x90, 0x00,
    ];

    /// FINEID-shaped compact-TLV ATR carrying non-FINEID family/product
    /// markers (`AAh BBh` instead of `B0h 85h`).
    const NON_FINEID_MARKERS_ATR: &[u8] = &[
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xAA, 0xBB, 0x05, 0x00, 0x11, 0x12,
        0x24, 0x60, 0x82, 0x90, 0x00,
    ];

    #[test]
    fn fineid_pre_issuing_extracts_named_fields() {
        let atr = Atr::new(THALES_MULTIAPP_V5_0_REV_1_0_CONTACT_ATR)
            .expect("Thales v5.0 ATR fixture parses");
        let pre = FineidPreIssuingData::from_atr(&atr).expect("pre-issuing present");
        assert_eq!(
            pre,
            FineidPreIssuingData {
                family_name: FINEID_PRE_ISSUING_FAMILY,
                product_name: FINEID_PRE_ISSUING_PRODUCT,
                os_version: FINEID_OS_VERSION_THALES_V5_0,
                program_version: REV_1_0_PROGRAM_VERSION,
                chip_id: REV_1_0_CHIP_ID,
            }
        );
    }

    #[test]
    fn classify_is_generation_stable_across_chip_revisions() {
        let atr = Atr::new(SYNTHETIC_THALES_V5_0_NEW_REV_ATR)
            .expect("unknown-chip-revision ATR fixture parses");
        assert_eq!(
            FineidCardModel::from_atr(&atr),
            Ok(FineidCardModel::ThalesMultiAppV5_0)
        );
    }

    #[test]
    fn classify_rejects_expired_v3_0_generation() {
        let atr = Atr::new(EXPIRED_GEMALTO_V3_0_ATR).expect("Gemalto v3.0 ATR fixture parses");
        assert_eq!(
            FineidCardModel::from_atr(&atr),
            Err(CardClassificationError::UnknownOrUnsupportedAtr { observed: atr })
        );
    }

    #[test]
    fn classify_rejects_non_fineid_markers() {
        let atr = Atr::new(NON_FINEID_MARKERS_ATR).expect("non-FINEID-marker ATR fixture parses");
        assert!(FineidPreIssuingData::from_atr(&atr).is_some());
        assert!(matches!(
            FineidCardModel::from_atr(&atr),
            Err(CardClassificationError::UnknownOrUnsupportedAtr { .. })
        ));
    }

    #[test]
    fn ats_rejects_empty() {
        assert_eq!(Ats::new([]), Err(AtsError::Empty));
    }

    #[test]
    fn ats_rejects_too_long() {
        let overlong = ATS_MAX_LEN + 1;
        let v = vec![0_u8; overlong];
        assert_eq!(Ats::new(v), Err(AtsError::TooLong { got: overlong }));
    }

    #[test]
    fn every_known_thales_multiapp_v5_atr_classifies() {
        for bytes in FineidCardModel::ThalesMultiAppV5_0.contact_atr_byte_sets() {
            let atr = Atr::new(*bytes).expect("known Thales v5.0 ATR parses");
            assert_eq!(
                FineidCardModel::from_atr(&atr).expect("known Thales v5.0 ATR classifies"),
                FineidCardModel::ThalesMultiAppV5_0,
                "ATR {atr} should classify as Thales MultiApp v5.0"
            );
        }
    }

    #[test]
    fn dvv_gemalto_multiapp_v4_2_atr_classifies() {
        for bytes in FineidCardModel::GemaltoMultiAppV4_2.contact_atr_byte_sets() {
            let atr = Atr::new(*bytes).expect("known Gemalto v4.2 ATR parses");
            assert_eq!(
                FineidCardModel::from_atr(&atr).expect("known Gemalto v4.2 ATR classifies"),
                FineidCardModel::GemaltoMultiAppV4_2
            );
        }
    }

    #[test]
    fn idemia_cosmo_x_atr_classifies() {
        for bytes in FineidCardModel::IdemiaCosmoX.contact_atr_byte_sets() {
            let atr = Atr::new(*bytes).expect("Idemia Cosmo X ATR parses");
            assert_eq!(
                FineidCardModel::from_atr(&atr).expect("Idemia Cosmo X ATR classifies"),
                FineidCardModel::IdemiaCosmoX
            );
        }
        let m = FineidCardModel::IdemiaCosmoX;
        assert_eq!(m.card_type(), CardType::SocialWelfareAndOrganizational);
        assert_eq!(m.vendor().as_dvv_label(), "Idemia");
        assert_eq!(m.vendor_product(), "Cosmo");
        assert_eq!(m.vendor_product_version(), "X");
        assert_eq!(m.fineid_specification(), "S1");
        assert_eq!(m.fineid_specification_version(), "5.0");
    }

    #[test]
    fn wire_strings_thales_multiapp_v5() {
        let m = FineidCardModel::ThalesMultiAppV5_0;
        assert_eq!(m.card_type().as_dvv_label(), "Citizen eID");
        assert_eq!(m.vendor().as_dvv_label(), "Thales");
        assert_eq!(m.vendor_product(), "MultiApp");
        assert_eq!(m.vendor_product_version(), "5.0");
        assert_eq!(m.fineid_specification(), "S4-1");
        assert_eq!(m.fineid_specification_version(), "4.0");
    }

    #[test]
    fn wire_strings_gemalto_multiapp_v4_2() {
        let m = FineidCardModel::GemaltoMultiAppV4_2;
        assert_eq!(m.card_type().as_dvv_label(), "Citizen eID");
        assert_eq!(m.vendor().as_dvv_label(), "Gemalto");
        assert_eq!(m.vendor_product(), "MultiApp");
        assert_eq!(m.vendor_product_version(), "4.2");
        assert_eq!(m.fineid_specification(), "S4-1");
        assert_eq!(m.fineid_specification_version(), "3.1");
    }

    #[test]
    fn card_type_all_dvv_labels() {
        assert_eq!(CardType::CitizenEid.as_dvv_label(), "Citizen eID");
        assert_eq!(
            CardType::SocialWelfareAndOrganizational.as_dvv_label(),
            "Social welfare and organizational"
        );
        assert_eq!(
            CardType::HealthCareAndOrganizational.as_dvv_label(),
            "Health care and organizational"
        );
    }

    #[test]
    fn card_vendor_all_dvv_labels() {
        assert_eq!(CardVendor::Thales.as_dvv_label(), "Thales");
        assert_eq!(CardVendor::Gemalto.as_dvv_label(), "Gemalto");
        assert_eq!(CardVendor::Idemia.as_dvv_label(), "Idemia");
    }

    #[test]
    fn all_known_lists_every_model() {
        for model in [
            FineidCardModel::ThalesMultiAppV5_0,
            FineidCardModel::GemaltoMultiAppV4_2,
            FineidCardModel::IdemiaCosmoX,
        ] {
            assert!(FineidCardModel::all_known().contains(&model));
        }
    }

    #[test]
    fn dvv_contact_atrs_and_contactless_atss_are_in_spec_bounds() {
        for &m in FineidCardModel::all_known() {
            for bytes in m.contact_atr_byte_sets() {
                let n = bytes.len();
                assert!(
                    (ATR_MIN_LEN..=ATR_MAX_LEN).contains(&n),
                    "{m:?} ATR length {n} out of ISO 7816-3 window"
                );
            }
            for bytes in m.contactless_ats_byte_sets() {
                let ats = Ats::new(*bytes).expect("recorded ATS is within ISO 14443-4 bounds");
                assert_eq!(ats.as_bytes(), *bytes);
            }
        }
    }
}
