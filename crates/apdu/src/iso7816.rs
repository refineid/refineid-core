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

//! Typed ISO 7816-4 command builders shared across protocol crates.
//!
//! Each struct represents one specific command shape that RefineID
//! issues; serialisation happens once, at the `into_apdu` boundary, and
//! after that point the bytes are an opaque [`CommandApdu`]. This module
//! hosts only generic commands that more than one protocol issues;
//! protocol-specific commands live beside their protocol crate.

use core::fmt;

use crate::command::{APDU_HEADER_LEN, ApduClass, CommandApdu, LC_LEN, LE_LEN};
use crate::primitives::{Aid, FileId, Sfi};

/// SELECT by application identifier without response data, per FINEID S1
/// v4.2 section 3.1 and ISO 7816-4 section 8.2.1.2: a case-3 command
/// whose data field is the AID and whose P2 suppresses the file control
/// information.
#[derive(Debug, Clone)]
pub struct SelectByAidNoFci {
    /// Application identifier; the [`Aid`] newtype enforces the ISO
    /// 7816-5 length range.
    pub aid: Aid,
}

impl SelectByAidNoFci {
    /// Class byte: plain command.
    pub const CLA: u8 = 0x00;
    /// SELECT instruction byte.
    pub const INS: u8 = 0xA4;
    /// P1: select by application identifier.
    pub const P1: u8 = 0x04;
    /// P2: first or only occurrence, no file control information
    /// returned.
    pub const P2: u8 = 0x0C;

    /// Serialise into the wire APDU. The AID length is bounded by
    /// [`Aid::new`], so the Lc byte cannot truncate.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let aid_bytes = self.aid.as_bytes();
        let mut out = Vec::with_capacity(APDU_HEADER_LEN + LC_LEN + aid_bytes.len());
        out.extend_from_slice(&[Self::CLA, Self::INS, Self::P1, Self::P2]);
        out.push(u8::try_from(aid_bytes.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(aid_bytes);
        CommandApdu::from_wire(out)
    }
}

/// SELECT by two-byte file identifier under the current DF without
/// response data: a case-3 command. This is the FINEID wire shape proven
/// across platforms; requesting no response data keeps the command out of
/// case-4 handling differences between reader stacks.
#[derive(Debug, Clone, Copy)]
pub struct SelectEfNoFci {
    /// File identifier of the EF to select.
    pub fid: FileId,
}

impl SelectEfNoFci {
    /// Class byte: plain command.
    pub const CLA: u8 = 0x00;
    /// SELECT instruction byte.
    pub const INS: u8 = 0xA4;
    /// P1: select an EF by file identifier under the current DF.
    pub const P1: u8 = 0x02;
    /// P2: return no file control information.
    pub const P2: u8 = 0x0C;
    /// Lc byte: [`FileId::LENGTH`] as the data-field length.
    pub const LC: u8 = 2;

    /// Serialise into the wire APDU.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let fid = self.fid.as_bytes();
        let mut out = Vec::with_capacity(APDU_HEADER_LEN + LC_LEN + FileId::LENGTH);
        out.extend_from_slice(&[Self::CLA, Self::INS, Self::P1, Self::P2, Self::LC]);
        out.extend_from_slice(fid);
        CommandApdu::from_wire(out)
    }
}

/// Absolute path from the MF, per FINEID S1 v4.2 section 3.2.2: file
/// identifiers from the immediate MF children down to the target,
/// without the MF prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsolutePath {
    /// Ordered DF and EF identifiers from the MF down to the target.
    fids: Vec<FileId>,
}

/// Construction errors for [`AbsolutePath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsolutePathError {
    /// The list was empty; the spec expresses MF selection as the
    /// empty-data form of the by-file-identifier target instead.
    Empty,
    /// The path starts with the MF identifier, which the wire form
    /// omits.
    StartsWithMf,
    /// The path exceeds [`AbsolutePath::MAX_FIDS`] identifiers and would
    /// overflow the short-form data field.
    TooLong {
        /// Rejected identifier count.
        got: usize,
    },
}

impl fmt::Display for AbsolutePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("absolute path cannot be empty"),
            Self::StartsWithMf => {
                f.write_str("absolute path must omit the MF prefix per the wire form")
            }
            Self::TooLong { got } => write!(
                f,
                "absolute path of {got} identifiers exceeds the short-form maximum of {}",
                AbsolutePath::MAX_FIDS
            ),
        }
    }
}

impl core::error::Error for AbsolutePathError {}

impl AbsolutePath {
    /// Largest identifier count whose wire form fits the short-form data
    /// field.
    pub const MAX_FIDS: usize = 127;

    /// Build a path from a non-empty identifier sequence.
    ///
    /// # Errors
    ///
    /// [`AbsolutePathError`] when the list is empty, starts with the MF
    /// identifier, or exceeds [`AbsolutePath::MAX_FIDS`] entries.
    pub fn new(fids: Vec<FileId>) -> Result<Self, AbsolutePathError> {
        if fids.is_empty() {
            return Err(AbsolutePathError::Empty);
        }
        if fids.first() == Some(&FileId::MF) {
            return Err(AbsolutePathError::StartsWithMf);
        }
        if fids.len() > Self::MAX_FIDS {
            return Err(AbsolutePathError::TooLong { got: fids.len() });
        }
        Ok(Self { fids })
    }

    /// Borrow the identifier sequence.
    #[must_use]
    pub fn as_fids(&self) -> &[FileId] {
        &self.fids
    }
}

/// SELECT FILE target, per FINEID S1 v4.2 section 3.2.2. Each variant
/// encodes one P1 mode together with the data-field shape that mode
/// requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectFileTarget {
    /// Select EF, DF, or MF by file identifier; `None` selects the MF
    /// through the empty-data form.
    AnyByFileId(Option<FileId>),
    /// Select an EF by file identifier under the current DF.
    EfUnderCurrentDf(FileId),
    /// Select a DF or MF by name; the name is an application identifier.
    ByName(Aid),
    /// Select by absolute path from the MF, without the MF prefix.
    AbsolutePath(AbsolutePath),
}

impl SelectFileTarget {
    /// P1 for [`SelectFileTarget::AnyByFileId`].
    const P1_ANY_BY_FILE_ID: u8 = 0x00;
    /// P1 for [`SelectFileTarget::EfUnderCurrentDf`].
    const P1_EF_UNDER_CURRENT_DF: u8 = 0x02;
    /// P1 for [`SelectFileTarget::ByName`].
    const P1_BY_NAME: u8 = 0x04;
    /// P1 for [`SelectFileTarget::AbsolutePath`].
    const P1_ABSOLUTE_PATH: u8 = 0x08;

    /// P1 wire byte for this target.
    #[must_use]
    pub const fn as_p1(&self) -> u8 {
        match self {
            Self::AnyByFileId(_) => Self::P1_ANY_BY_FILE_ID,
            Self::EfUnderCurrentDf(_) => Self::P1_EF_UNDER_CURRENT_DF,
            Self::ByName(_) => Self::P1_BY_NAME,
            Self::AbsolutePath(_) => Self::P1_ABSOLUTE_PATH,
        }
    }

    /// Length of the data field for this target.
    #[must_use]
    pub fn data_len(&self) -> usize {
        match self {
            Self::AnyByFileId(None) => 0,
            Self::AnyByFileId(Some(_)) | Self::EfUnderCurrentDf(_) => FileId::LENGTH,
            Self::ByName(aid) => aid.len(),
            Self::AbsolutePath(path) => path.as_fids().len().saturating_mul(FileId::LENGTH),
        }
    }

    /// Append the data-field bytes for this target.
    fn append_data(&self, out: &mut Vec<u8>) {
        match self {
            Self::AnyByFileId(None) => {}
            Self::AnyByFileId(Some(fid)) | Self::EfUnderCurrentDf(fid) => {
                out.extend_from_slice(fid.as_bytes());
            }
            Self::ByName(aid) => out.extend_from_slice(aid.as_bytes()),
            Self::AbsolutePath(path) => {
                for fid in path.as_fids() {
                    out.extend_from_slice(fid.as_bytes());
                }
            }
        }
    }
}

/// SELECT FILE response selector, per FINEID S1 v4.2 section 3.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectFileResponseMode {
    /// The card returns the file control information template.
    Fci,
    /// The card returns the file control parameter template.
    Fcp,
    /// The card returns no response data.
    None,
}

impl SelectFileResponseMode {
    /// P2 for [`SelectFileResponseMode::Fci`].
    const P2_FCI: u8 = 0x00;
    /// P2 for [`SelectFileResponseMode::Fcp`].
    const P2_FCP: u8 = 0x04;
    /// P2 for [`SelectFileResponseMode::None`].
    const P2_NONE: u8 = 0x0C;

    /// P2 wire byte for this mode.
    #[must_use]
    pub const fn as_p2(self) -> u8 {
        match self {
            Self::Fci => Self::P2_FCI,
            Self::Fcp => Self::P2_FCP,
            Self::None => Self::P2_NONE,
        }
    }
}

/// SELECT FILE, per FINEID S1 v4.2 section 3.2: select a DF or an EF.
/// The P1 modes and P2 modes are reified as [`SelectFileTarget`] and
/// [`SelectFileResponseMode`]; the wire bytes follow mechanically from
/// the typed inputs. Lc and data are emitted only when the target
/// carries bytes; Le is emitted only when the response mode expects a
/// body.
#[derive(Debug, Clone)]
pub struct SelectFile {
    /// Class byte: plain or secure messaging.
    pub class: ApduClass,
    /// P1 selector and matching data shape.
    pub target: SelectFileTarget,
    /// P2 selector: which response template the card returns.
    pub response_mode: SelectFileResponseMode,
}

impl SelectFile {
    /// SELECT instruction byte.
    pub const INS: u8 = 0xA4;
    /// Le byte requesting any length, emitted when a response is
    /// expected.
    pub const LE_ANY: u8 = 0x00;

    /// Serialise into the wire APDU. The target invariants bound the
    /// data field within the short form, so the Lc byte cannot truncate.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let data_len = self.target.data_len();
        let mut out = Vec::with_capacity(APDU_HEADER_LEN + LC_LEN + data_len + LE_LEN);
        out.push(self.class.as_byte());
        out.push(Self::INS);
        out.push(self.target.as_p1());
        out.push(self.response_mode.as_p2());
        if data_len > 0 {
            out.push(u8::try_from(data_len).unwrap_or(u8::MAX));
            self.target.append_data(&mut out);
        }
        if matches!(
            self.response_mode,
            SelectFileResponseMode::Fci | SelectFileResponseMode::Fcp
        ) {
            out.push(Self::LE_ANY);
        }
        CommandApdu::from_wire(out)
    }
}

/// GET RESPONSE, per FINEID S1 v4.2 section 3.3: fetch response data the
/// card holds after signalling chained-response availability.
#[derive(Debug, Clone, Copy)]
pub struct GetResponse {
    /// Class byte.
    pub class: ApduClass,
    /// Maximum response bytes expected; zero means any length.
    pub le: u8,
}

impl GetResponse {
    /// GET RESPONSE instruction byte.
    pub const INS: u8 = 0xC0;
    /// P1: reserved.
    pub const P1: u8 = 0x00;
    /// P2: reserved.
    pub const P2: u8 = 0x00;

    /// Serialise into the wire APDU: a five-byte case-2 command whose
    /// builder opts into the single wrong-Le correction.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        CommandApdu::from_wire(vec![
            self.class.as_byte(),
            Self::INS,
            Self::P1,
            Self::P2,
            self.le,
        ])
        .allow_wrong_le_retry()
    }
}

/// Direct-selection byte offset for READ BINARY, per the FINEID S1 v4.2
/// section 3.4.2 coding table: the offset flag bit of P1 clear and the
/// remaining fifteen bits addressing into the currently selected EF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectOffset15(u16);

/// Construction error for [`DirectOffset15`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectOffset15Error {
    /// Offset above the fifteen-bit cap.
    OutOfRange {
        /// The offending offset value.
        got: u16,
    },
}

impl fmt::Display for DirectOffset15Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { got } => write!(
                f,
                "READ BINARY direct offset {got} exceeds the fifteen-bit cap {}",
                DirectOffset15::MAX
            ),
        }
    }
}

impl core::error::Error for DirectOffset15Error {}

impl DirectOffset15 {
    /// Maximum fifteen-bit offset value.
    pub const MAX: u16 = 0x7FFF;

    /// Wrap an offset, validating it fits in fifteen bits so the typed
    /// value can never round-trip into the SFI-form encoding.
    ///
    /// # Errors
    ///
    /// [`DirectOffset15Error::OutOfRange`] above [`DirectOffset15::MAX`].
    pub const fn try_new(offset: u16) -> Result<Self, DirectOffset15Error> {
        if offset > Self::MAX {
            return Err(DirectOffset15Error::OutOfRange { got: offset });
        }
        Ok(Self(offset))
    }

    /// The underlying offset value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// P1 byte: the high octet of the offset, with the mode bit clear by
    /// the constructor invariant.
    #[must_use]
    pub const fn as_p1(self) -> u8 {
        let [hi, _lo] = self.0.to_be_bytes();
        hi
    }

    /// P2 byte: the low octet of the offset.
    #[must_use]
    pub const fn as_p2(self) -> u8 {
        let [_hi, lo] = self.0.to_be_bytes();
        lo
    }
}

/// READ BINARY offset selector, per the FINEID S1 v4.2 section 3.4.2
/// coding table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadBinaryOffset {
    /// Direct-selection form: reads the currently selected EF at a
    /// fifteen-bit byte offset.
    Direct(DirectOffset15),
    /// SFI form: P1 carries the short file identifier and P2 an
    /// eight-bit offset; the card selects the EF as part of the read.
    BySfi {
        /// Short file identifier; the [`Sfi`] newtype enforces the
        /// range.
        sfi: Sfi,
        /// Byte offset within the EF identified by `sfi`.
        offset: u8,
    },
}

impl ReadBinaryOffset {
    /// P1 wire byte for this selector.
    #[must_use]
    pub const fn as_p1(self) -> u8 {
        match self {
            Self::Direct(offset) => offset.as_p1(),
            Self::BySfi { sfi, .. } => sfi.as_p1_short_form(),
        }
    }

    /// P2 wire byte for this selector.
    #[must_use]
    pub const fn as_p2(self) -> u8 {
        match self {
            Self::Direct(offset) => offset.as_p2(),
            Self::BySfi { offset, .. } => offset,
        }
    }
}

/// READ BINARY, per FINEID S1 v4.2 section 3.4: read all or part of a
/// transparent EF. A five-byte case-2 command; the builder opts into the
/// single wrong-Le correction because the read is replay-safe.
#[derive(Debug, Clone, Copy)]
pub struct ReadBinary {
    /// Class byte.
    pub class: ApduClass,
    /// P1 and P2 selector per the coding table.
    pub offset: ReadBinaryOffset,
    /// Le: bytes to read; zero means until end of file, up to the
    /// short-form maximum.
    pub le: u8,
}

impl ReadBinary {
    /// READ BINARY instruction byte.
    pub const INS: u8 = 0xB0;

    /// Serialise into the wire APDU.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        CommandApdu::from_wire(vec![
            self.class.as_byte(),
            Self::INS,
            self.offset.as_p1(),
            self.offset.as_p2(),
            self.le,
        ])
        .allow_wrong_le_retry()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AbsolutePath, AbsolutePathError, DirectOffset15, DirectOffset15Error, GetResponse,
        ReadBinary, ReadBinaryOffset, SelectByAidNoFci, SelectEfNoFci, SelectFile,
        SelectFileResponseMode, SelectFileTarget,
    };
    use crate::command::{APDU_HEADER_LEN, ApduClass, LC_LEN, LE_LEN};
    use crate::primitives::{Aid, FileId, Sfi};

    /// Synthetic seven-byte AID for wire tests; the ASCII value has no
    /// protocol meaning, only a valid length.
    const TEST_AID: &[u8] = b"testaid";
    /// Expected wire for SELECT by AID without response data over
    /// [`TEST_AID`], assembled from the builder's named header bytes:
    /// header, Lc, then the AID (FINEID S1 v4.2 section 3.1).
    fn expected_select_aid_wire() -> Vec<u8> {
        let mut wire = vec![
            SelectByAidNoFci::CLA,
            SelectByAidNoFci::INS,
            SelectByAidNoFci::P1,
            SelectByAidNoFci::P2,
        ];
        wire.push(u8::try_from(TEST_AID.len()).expect("fixture AID fits the short form"));
        wire.extend_from_slice(TEST_AID);
        wire
    }

    /// Synthetic file identifier for wire tests.
    const TEST_FID: FileId = FileId::from_u16(0x5031);
    /// Expected wire for SELECT EF without response data over
    /// [`TEST_FID`]: header, Lc, then the identifier.
    fn expected_select_ef_wire() -> Vec<u8> {
        let mut wire = vec![
            SelectEfNoFci::CLA,
            SelectEfNoFci::INS,
            SelectEfNoFci::P1,
            SelectEfNoFci::P2,
            SelectEfNoFci::LC,
        ];
        wire.extend_from_slice(TEST_FID.as_bytes());
        wire
    }

    /// Le fixture for GET RESPONSE and READ BINARY wire tests.
    const TEST_LE: u8 = 0x80;
    /// Expected wire for a plain GET RESPONSE with [`TEST_LE`] (FINEID S1
    /// v4.2 section 3.3.2).
    fn expected_get_response_wire() -> Vec<u8> {
        vec![
            ApduClass::Plain.as_byte(),
            GetResponse::INS,
            GetResponse::P1,
            GetResponse::P2,
            TEST_LE,
        ]
    }

    /// Direct offset fixture for READ BINARY wire tests.
    const TEST_OFFSET: u16 = 0x1234;
    /// Expected wire for a plain direct-offset READ BINARY at
    /// [`TEST_OFFSET`] with [`TEST_LE`] (FINEID S1 v4.2 section 3.4.2):
    /// the offset rides big-endian in P1-P2.
    fn expected_read_binary_wire() -> Vec<u8> {
        let [offset_high, offset_low] = TEST_OFFSET.to_be_bytes();
        vec![
            ApduClass::Plain.as_byte(),
            ReadBinary::INS,
            offset_high,
            offset_low,
            TEST_LE,
        ]
    }

    /// SFI fixture for the SFI-form READ BINARY test.
    const TEST_SFI: u8 = 5;
    /// EF-internal offset fixture for the SFI-form READ BINARY test.
    const TEST_SFI_OFFSET: u8 = 16;
    /// Expected wire for a plain SFI-form READ BINARY of [`TEST_SFI`] at
    /// [`TEST_SFI_OFFSET`] with [`TEST_LE`]: P1 carries the SFI-selection
    /// flag over the identifier.
    fn expected_read_binary_sfi_wire() -> Vec<u8> {
        vec![
            ApduClass::Plain.as_byte(),
            ReadBinary::INS,
            SFI_MODE_BIT | TEST_SFI,
            TEST_SFI_OFFSET,
            TEST_LE,
        ]
    }

    /// P1 mode bit distinguishing SFI form from direct form.
    const SFI_MODE_BIT: u8 = 0x80;

    /// Corrected Le for wrong-Le correction tests.
    const CORRECTED_LE: u8 = 0x2C;

    /// One identifier above the absolute-path cap.
    const OVER_PATH_CAP: usize = AbsolutePath::MAX_FIDS + 1;

    fn test_aid() -> Aid {
        Aid::from_slice(TEST_AID).expect("fixture AID length is valid")
    }

    #[test]
    fn select_by_aid_matches_the_specified_wire() {
        let apdu = SelectByAidNoFci { aid: test_aid() }.into_apdu();
        assert_eq!(apdu.as_bytes(), expected_select_aid_wire().as_slice());
        assert!(
            apdu.corrected_wrong_le(CORRECTED_LE).is_none(),
            "a case-3 SELECT never opts into wrong-Le correction"
        );
    }

    #[test]
    fn select_ef_matches_the_specified_wire() {
        let apdu = SelectEfNoFci { fid: TEST_FID }.into_apdu();
        assert_eq!(apdu.as_bytes(), expected_select_ef_wire().as_slice());
    }

    #[test]
    fn get_response_matches_the_specified_wire_and_permits_one_correction() {
        let apdu = GetResponse {
            class: ApduClass::Plain,
            le: TEST_LE,
        }
        .into_apdu();
        assert_eq!(apdu.as_bytes(), expected_get_response_wire().as_slice());

        let corrected = apdu
            .corrected_wrong_le(CORRECTED_LE)
            .expect("the read builder opts into one correction");
        assert_eq!(
            corrected.as_bytes().last().copied(),
            Some(CORRECTED_LE),
            "the corrected command carries the card-reported Le"
        );
        assert!(corrected.corrected_wrong_le(TEST_LE).is_none());
    }

    #[test]
    fn read_binary_direct_matches_the_specified_wire() {
        let offset = DirectOffset15::try_new(TEST_OFFSET).expect("fixture offset is in range");
        let apdu = ReadBinary {
            class: ApduClass::Plain,
            offset: ReadBinaryOffset::Direct(offset),
            le: TEST_LE,
        }
        .into_apdu();
        assert_eq!(apdu.as_bytes(), expected_read_binary_wire().as_slice());
        assert_eq!(ReadBinaryOffset::Direct(offset).as_p1() & SFI_MODE_BIT, 0);
        assert!(apdu.corrected_wrong_le(CORRECTED_LE).is_some());
    }

    #[test]
    fn read_binary_by_sfi_matches_the_specified_wire() {
        let sfi = Sfi::new(TEST_SFI).expect("fixture SFI is in range");
        let offset = ReadBinaryOffset::BySfi {
            sfi,
            offset: TEST_SFI_OFFSET,
        };
        let apdu = ReadBinary {
            class: ApduClass::Plain,
            offset,
            le: TEST_LE,
        }
        .into_apdu();
        assert_eq!(apdu.as_bytes(), expected_read_binary_sfi_wire().as_slice());
        assert_eq!(offset.as_p1() & SFI_MODE_BIT, SFI_MODE_BIT);
    }

    /// Expected SELECT FILE wire derived from the typed symbols, so the
    /// matrix test and the serialiser share one source of truth for each
    /// spec value; the fixed-wire constants above lock the byte
    /// encodings independently.
    fn expected_select_file_wire(
        class: ApduClass,
        target: &SelectFileTarget,
        response_mode: SelectFileResponseMode,
    ) -> Vec<u8> {
        let data_len = target.data_len();
        let mut out = Vec::with_capacity(APDU_HEADER_LEN + LC_LEN + data_len + LE_LEN);
        out.push(class.as_byte());
        out.push(SelectFile::INS);
        out.push(target.as_p1());
        out.push(response_mode.as_p2());
        if data_len > 0 {
            out.push(u8::try_from(data_len).expect("target data fits the short form"));
            target.append_data(&mut out);
        }
        if matches!(
            response_mode,
            SelectFileResponseMode::Fci | SelectFileResponseMode::Fcp
        ) {
            out.push(SelectFile::LE_ANY);
        }
        out
    }

    #[test]
    fn select_file_covers_every_target_and_response_mode() {
        let targets = [
            SelectFileTarget::AnyByFileId(None),
            SelectFileTarget::AnyByFileId(Some(FileId::MF)),
            SelectFileTarget::EfUnderCurrentDf(TEST_FID),
            SelectFileTarget::ByName(test_aid()),
            SelectFileTarget::AbsolutePath(
                AbsolutePath::new(vec![TEST_FID]).expect("fixture path is valid"),
            ),
        ];
        let modes = [
            SelectFileResponseMode::Fci,
            SelectFileResponseMode::Fcp,
            SelectFileResponseMode::None,
        ];
        for target in &targets {
            for mode in modes {
                let apdu = SelectFile {
                    class: ApduClass::Plain,
                    target: target.clone(),
                    response_mode: mode,
                }
                .into_apdu();
                assert_eq!(
                    apdu.as_bytes(),
                    expected_select_file_wire(ApduClass::Plain, target, mode).as_slice()
                );
            }
        }
    }

    #[test]
    fn select_file_empty_data_form_is_header_only() {
        let apdu = SelectFile {
            class: ApduClass::Plain,
            target: SelectFileTarget::AnyByFileId(None),
            response_mode: SelectFileResponseMode::None,
        }
        .into_apdu();
        assert_eq!(apdu.as_bytes().len(), APDU_HEADER_LEN);
    }

    #[test]
    fn absolute_path_boundaries_are_enforced() {
        assert_eq!(AbsolutePath::new(vec![]), Err(AbsolutePathError::Empty));
        assert_eq!(
            AbsolutePath::new(vec![FileId::MF, TEST_FID]),
            Err(AbsolutePathError::StartsWithMf)
        );
        assert!(AbsolutePath::new(vec![TEST_FID; AbsolutePath::MAX_FIDS]).is_ok());
        assert_eq!(
            AbsolutePath::new(vec![TEST_FID; OVER_PATH_CAP]),
            Err(AbsolutePathError::TooLong { got: OVER_PATH_CAP })
        );
    }

    #[test]
    fn direct_offset_boundaries_are_enforced() {
        assert!(DirectOffset15::try_new(0).is_ok());
        let max = DirectOffset15::try_new(DirectOffset15::MAX).expect("cap value is accepted");
        assert_eq!(max.as_u16(), DirectOffset15::MAX);
        const ABOVE_CAP: u16 = DirectOffset15::MAX + 1;
        assert_eq!(
            DirectOffset15::try_new(ABOVE_CAP),
            Err(DirectOffset15Error::OutOfRange { got: ABOVE_CAP })
        );
    }
}
