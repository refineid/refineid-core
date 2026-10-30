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

//! Binary reading of eMRTD elementary files.

use core::cmp::min;

use refineid_apdu::iso7816::{DirectOffset15, ReadBinary, ReadBinaryOffset};
use refineid_apdu::{ApduClass, CardTransport, CommandApdu, CommandHeader, TransportOutcome};

use crate::error::EmrtdError;
use crate::sfi::Sfi;

const INS_READ_BINARY: u8 = 0xB0;
const PARAMETER_ZERO: u8 = 0x00;
const HEADER_PROBE_LENGTH: u8 = 0x04;
/// Bytes requested per READ BINARY chunk: the largest span whose
/// secure-messaging response still fits one short-APDU response, so
/// protected reads never fragment.
const READ_CHUNK_MAX_LENGTH: u8 = 0xDF;
const SW_END_OF_FILE_REACHED: u16 = 0x6282;

const MULTI_BYTE_TAG_FLAG: u8 = 0x1F;
const HIGH_BIT_SET_FLAG: u8 = 0x80;
const LONG_FORM_LENGTH_FLAG: u8 = 0x80;
const LENGTH_COUNT_MASK: u8 = 0x7F;
const MIN_HEADER_BYTES_FOR_LENGTH: usize = 2;
/// Most length octets a long-form outer length may carry here (X.690
/// section 8.1.3.5); two octets already reach past
/// [`MAX_EMRTD_FILE_BYTES`].
const MAX_LENGTH_OCTETS: usize = 2;
/// Largest elementary file this reader assembles: every byte lies within
/// the fifteen-bit direct-offset range of the even-INS READ BINARY.
/// Offsets above [`DirectOffset15::MAX`] need the odd-INS READ BINARY with
/// an offset data object (ICAO Doc 9303 Part 10), which this reader does
/// not issue. An announced length above the ceiling is refused before any
/// chunk is read.
pub const MAX_EMRTD_FILE_BYTES: usize = DirectOffset15::MAX as usize + 1;

/// Reads an entire elementary file by its Short File Identifier.
///
/// The header probe selects the file by SFI; every following chunk reads
/// by direct offset, which addresses at most [`DirectOffset15::MAX`]
/// (FINEID S1 v4.2 section 3.4.2).
///
/// # Errors
///
/// Returns an [`EmrtdError`] on transport faults or if reading is rejected
/// by the card; [`EmrtdError::MalformedData`] when the probe answers more
/// bytes than requested, the outer length does not decode, the file
/// exceeds [`MAX_EMRTD_FILE_BYTES`], or a chunk answers more bytes than
/// requested.
pub fn read_emrtd_file<T: CardTransport + ?Sized>(
    transport: &mut T,
    sfi: Sfi,
) -> Result<Vec<u8>, EmrtdError<T::Error>> {
    let header_cmd = CommandApdu::case_2(
        CommandHeader {
            class: ApduClass::Plain,
            instruction: INS_READ_BINARY,
            p1: sfi.p1_for_read_binary(),
            p2: PARAMETER_ZERO,
        },
        HEADER_PROBE_LENGTH,
    );

    let header = match transport
        .transmit(&header_cmd)
        .map_err(EmrtdError::Transport)?
    {
        TransportOutcome::Response(response) => {
            if !response.is_ok() && response.status_word().as_u16() != SW_END_OF_FILE_REACHED {
                return Err(EmrtdError::Status {
                    operation: "READ BINARY by SFI header probe",
                    sw: response.status_word(),
                });
            }
            response.body
        }
        non_response => return Err(EmrtdError::from(non_response)),
    };

    if header.is_empty() {
        return Err(EmrtdError::EmptyFile);
    }
    if header.len() > usize::from(HEADER_PROBE_LENGTH) {
        return Err(EmrtdError::MalformedData);
    }
    if header.len() < MIN_HEADER_BYTES_FOR_LENGTH {
        return Ok(header);
    }

    let total_expected_length =
        decode_outer_total_length(&header).ok_or(EmrtdError::MalformedData)?;
    let mut buffer = header;
    buffer.truncate(total_expected_length);

    while buffer.len() < total_expected_length {
        let remaining = total_expected_length - buffer.len();
        let want = u8::try_from(min(usize::from(READ_CHUNK_MAX_LENGTH), remaining))
            .map_err(|_| EmrtdError::MalformedData)?;
        let offset = u16::try_from(buffer.len())
            .ok()
            .and_then(|offset| DirectOffset15::try_new(offset).ok())
            .ok_or(EmrtdError::MalformedData)?;

        let chunk_cmd = ReadBinary {
            class: ApduClass::Plain,
            offset: ReadBinaryOffset::Direct(offset),
            le: want,
        }
        .into_apdu();

        let outcome = transport
            .transmit(&chunk_cmd)
            .map_err(EmrtdError::Transport)?;
        let chunk_response = match outcome {
            TransportOutcome::Response(response) => response,
            non_response => return Err(EmrtdError::from(non_response)),
        };

        let sw = chunk_response.status_word().as_u16();
        if !chunk_response.is_ok() && sw != SW_END_OF_FILE_REACHED {
            return Err(EmrtdError::Status {
                operation: "READ BINARY by offset chunk",
                sw: chunk_response.status_word(),
            });
        }
        if chunk_response.body.is_empty() {
            break;
        }

        if chunk_response.body.len() > usize::from(want) {
            return Err(EmrtdError::MalformedData);
        }
        buffer.extend_from_slice(&chunk_response.body);

        if sw == SW_END_OF_FILE_REACHED {
            break;
        }
    }

    Ok(buffer)
}

/// Decodes the total length of an outer BER-TLV object -- tag, length
/// octets and content -- from its initial header bytes (X.690 section
/// 8.1).
///
/// `None` when the header is truncated before the length is complete,
/// the long form is indefinite or carries more than two length octets,
/// or the total exceeds [`MAX_EMRTD_FILE_BYTES`].
#[must_use]
pub fn decode_outer_total_length(header: &[u8]) -> Option<usize> {
    let (&first_tag_byte, rest) = header.split_first()?;
    let mut index = 1_usize;
    if first_tag_byte & MULTI_BYTE_TAG_FLAG == MULTI_BYTE_TAG_FLAG {
        let continuation = rest
            .iter()
            .take_while(|byte| **byte & HIGH_BIT_SET_FLAG != 0)
            .count();
        index = index.checked_add(continuation)?.checked_add(1)?;
    }
    let length_first_byte = *header.get(index)?;
    index = index.checked_add(1)?;
    let content_length = if length_first_byte < LONG_FORM_LENGTH_FLAG {
        usize::from(length_first_byte)
    } else {
        let count = usize::from(length_first_byte & LENGTH_COUNT_MASK);
        if count == 0 || count > MAX_LENGTH_OCTETS {
            return None;
        }
        let octets = header.get(index..index.checked_add(count)?)?;
        index = index.checked_add(count)?;
        octets.iter().try_fold(0_usize, |value, &octet| {
            value
                .checked_shl(u8::BITS)
                .and_then(|shifted| shifted.checked_add(usize::from(octet)))
        })?
    };
    let total = index.checked_add(content_length)?;
    (total <= MAX_EMRTD_FILE_BYTES).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::{
        HEADER_PROBE_LENGTH, HIGH_BIT_SET_FLAG, INS_READ_BINARY, LONG_FORM_LENGTH_FLAG,
        MAX_EMRTD_FILE_BYTES, MULTI_BYTE_TAG_FLAG, PARAMETER_ZERO, decode_outer_total_length,
        read_emrtd_file,
    };
    use crate::error::EmrtdError;
    use crate::sfi::SFI_EF_DG2;
    use refineid_apdu::iso7816::DirectOffset15;
    use refineid_apdu::{
        ApduClass, CardTransport, CommandApdu, CredentialCommand, ResponseApdu, StatusWord,
        TransportOutcome,
    };

    /// EF.DG2 outer tag (ICAO Doc 9303 Part 10, data group tags).
    const TAG_DG2: u8 = 0x75;
    /// Content length of the short-form fixture.
    const SHORT_CONTENT: u8 = 16;
    /// Content length of the two-octet long-form fixture.
    const LONG_CONTENT: u16 = 256;
    /// Bytes of a single-byte tag.
    const TAG_LEN: usize = 1;
    /// Bytes of a short-form length.
    const SHORT_LENGTH_LEN: usize = 1;
    /// Length octets in a two-octet long form.
    const TWO_LENGTH_OCTETS: u8 = 2;
    /// Length octets in a three-octet long form, one above the cap.
    const THREE_LENGTH_OCTETS: u8 = 3;
    /// Bytes of a single-byte tag followed by a two-octet long form.
    const LONG_HEADER_LEN: usize = 4;
    /// Bytes a misbehaving card answers to the four-byte header probe.
    const OVER_LONG_PROBE: usize = 10;
    /// Extra bytes a misbehaving card appends to a chunk.
    const CHUNK_OVERRUN: usize = 1;
    /// Bytes stored in the elementary file after its outer TLV.
    const TRAILING_PADDING: usize = 2;
    /// Bit of P1 that selects the SFI form of READ BINARY (FINEID S1 v4.2
    /// section 3.4.2).
    const P1_SFI_FORM_BIT: u8 = 0x80;
    /// Bytes of a case 2 short command: header and Le.
    const CASE_2_LEN: usize = 5;
    /// A synthetic file byte.
    const FILLER: u8 = b'x';

    fn long_form(count: u8) -> u8 {
        LONG_FORM_LENGTH_FLAG | count
    }

    #[test]
    fn decodes_short_and_extended_lengths() {
        let short = [TAG_DG2, SHORT_CONTENT];
        assert_eq!(
            decode_outer_total_length(&short),
            Some(TAG_LEN + SHORT_LENGTH_LEN + usize::from(SHORT_CONTENT))
        );
        let mut long = vec![TAG_DG2, long_form(TWO_LENGTH_OCTETS)];
        long.extend_from_slice(&LONG_CONTENT.to_be_bytes());
        assert_eq!(
            decode_outer_total_length(&long),
            Some(long.len() + usize::from(LONG_CONTENT))
        );
    }

    #[test]
    fn decodes_a_multi_byte_tag() {
        let header = [
            MULTI_BYTE_TAG_FLAG,
            HIGH_BIT_SET_FLAG,
            TAG_DG2,
            SHORT_CONTENT,
        ];
        assert_eq!(
            decode_outer_total_length(&header),
            Some(header.len() + usize::from(SHORT_CONTENT))
        );
    }

    #[test]
    fn rejects_length_of_length_above_two_octets() {
        let mut header = vec![TAG_DG2, long_form(THREE_LENGTH_OCTETS)];
        header.extend(core::iter::repeat_n(
            PARAMETER_ZERO,
            usize::from(THREE_LENGTH_OCTETS),
        ));
        assert_eq!(decode_outer_total_length(&header), None);
    }

    #[test]
    fn rejects_an_indefinite_length() {
        assert_eq!(
            decode_outer_total_length(&[TAG_DG2, LONG_FORM_LENGTH_FLAG]),
            None
        );
    }

    #[test]
    fn ceiling_is_the_direct_offset_reach() {
        assert_eq!(MAX_EMRTD_FILE_BYTES, usize::from(DirectOffset15::MAX) + 1);
        let at_ceiling = header_announcing(MAX_EMRTD_FILE_BYTES - LONG_HEADER_LEN);
        assert_eq!(
            decode_outer_total_length(&at_ceiling),
            Some(MAX_EMRTD_FILE_BYTES)
        );
        let above = header_announcing(MAX_EMRTD_FILE_BYTES - LONG_HEADER_LEN + 1);
        assert_eq!(decode_outer_total_length(&above), None);
    }

    #[test]
    fn rejects_truncated_long_form() {
        let mut header = vec![TAG_DG2, long_form(TWO_LENGTH_OCTETS)];
        header.push(LONG_CONTENT.to_be_bytes()[0]);
        assert_eq!(decode_outer_total_length(&header), None);
        assert_eq!(decode_outer_total_length(&[TAG_DG2]), None);
        assert_eq!(decode_outer_total_length(&[]), None);
    }

    /// A card serving one transparent file by SFI: a strict READ BINARY
    /// peer that refuses any command other than the SFI probe of EF.DG2
    /// followed by direct-offset chunks, and answers each with exactly the
    /// requested bytes unless an overrun is configured.
    struct ScriptedFile {
        file: Vec<u8>,
        probe_overrun: Option<usize>,
        chunk_overrun: usize,
        p1_bytes: Vec<u8>,
    }

    impl ScriptedFile {
        fn new(file: Vec<u8>) -> Self {
            Self {
                file,
                probe_overrun: None,
                chunk_overrun: 0,
                p1_bytes: Vec::new(),
            }
        }

        fn success(body: Vec<u8>) -> TransportOutcome {
            let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
            TransportOutcome::Response(ResponseApdu { body, sw1, sw2 })
        }

        fn serve(&self, offset: usize, length: usize) -> Vec<u8> {
            self.file
                .iter()
                .copied()
                .skip(offset)
                .take(length)
                .collect()
        }
    }

    impl CardTransport for ScriptedFile {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let &[cla, ins, p1, p2, le] = command.as_bytes() else {
                return Err(format!(
                    "not a {CASE_2_LEN}-byte case 2 command: {} bytes",
                    command.as_bytes().len()
                ));
            };
            if cla != ApduClass::Plain.as_byte() || ins != INS_READ_BINARY {
                return Err("not a plain READ BINARY".to_owned());
            }
            let le = usize::from(le);
            let first = self.p1_bytes.is_empty();
            self.p1_bytes.push(p1);
            if first {
                if p1 != SFI_EF_DG2.p1_for_read_binary()
                    || p2 != PARAMETER_ZERO
                    || le != usize::from(HEADER_PROBE_LENGTH)
                {
                    return Err("the first command is not the EF.DG2 SFI probe".to_owned());
                }
                let served = self.probe_overrun.unwrap_or(le);
                return Ok(Self::success(self.serve(0, served)));
            }
            if p1 & P1_SFI_FORM_BIT != 0 || le == 0 {
                return Err("a chunk is not a direct-offset read with Le".to_owned());
            }
            let offset = usize::from(u16::from_be_bytes([p1, p2]));
            Ok(Self::success(self.serve(offset, le + self.chunk_overrun)))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("the reader issues no credential command".to_owned())
        }
    }

    /// A DG2 tag and two-octet long form announcing `content` bytes.
    fn header_announcing(content: usize) -> Vec<u8> {
        let content = u16::try_from(content).expect("fits two length octets");
        let mut header = vec![TAG_DG2, long_form(TWO_LENGTH_OCTETS)];
        header.extend_from_slice(&content.to_be_bytes());
        header
    }

    /// A DG2-tagged file whose two-octet long form announces `content`
    /// bytes, filled with [`FILLER`].
    fn file_with_content(content: usize) -> Vec<u8> {
        let mut file = header_announcing(content);
        file.extend(core::iter::repeat_n(FILLER, content));
        file
    }

    #[test]
    fn reads_a_whole_file_in_chunks() {
        let file = file_with_content(usize::from(LONG_CONTENT));
        let mut card = ScriptedFile::new(file.clone());
        let read = read_emrtd_file(&mut card, SFI_EF_DG2).expect("the file reads");
        assert_eq!(read, file);
    }

    #[test]
    fn over_long_probe_response_is_malformed_data() {
        let mut card = ScriptedFile::new(file_with_content(usize::from(LONG_CONTENT)));
        card.probe_overrun = Some(OVER_LONG_PROBE);
        assert_eq!(
            read_emrtd_file(&mut card, SFI_EF_DG2),
            Err(EmrtdError::MalformedData)
        );
    }

    #[test]
    fn chunk_longer_than_requested_is_malformed_data() {
        let mut card = ScriptedFile::new(file_with_content(usize::from(LONG_CONTENT)));
        card.chunk_overrun = CHUNK_OVERRUN;
        assert_eq!(
            read_emrtd_file(&mut card, SFI_EF_DG2),
            Err(EmrtdError::MalformedData)
        );
    }

    #[test]
    fn probe_beyond_a_short_object_is_cut_to_the_object() {
        let object = [TAG_DG2, PARAMETER_ZERO];
        let mut file = object.to_vec();
        file.extend(core::iter::repeat_n(FILLER, TRAILING_PADDING));
        let mut card = ScriptedFile::new(file);
        let read = read_emrtd_file(&mut card, SFI_EF_DG2).expect("the object reads");
        assert_eq!(read, object);
        assert_eq!(card.p1_bytes.len(), 1);
    }

    #[test]
    fn file_at_the_ceiling_reads_by_direct_offset() {
        let file = file_with_content(MAX_EMRTD_FILE_BYTES - LONG_HEADER_LEN);
        let mut card = ScriptedFile::new(file.clone());
        let read = read_emrtd_file(&mut card, SFI_EF_DG2).expect("the file reads");
        assert_eq!(read, file);
        let chunks = card.p1_bytes.get(1..).expect("the probe was sent");
        assert!(!chunks.is_empty());
        assert!(chunks.iter().all(|p1| p1 & P1_SFI_FORM_BIT == 0));
    }

    #[test]
    fn file_above_the_ceiling_is_refused_before_any_chunk() {
        let mut card = ScriptedFile::new(header_announcing(
            MAX_EMRTD_FILE_BYTES - LONG_HEADER_LEN + 1,
        ));
        assert_eq!(
            read_emrtd_file(&mut card, SFI_EF_DG2),
            Err(EmrtdError::MalformedData)
        );
        assert_eq!(card.p1_bytes.len(), 1);
    }
}
