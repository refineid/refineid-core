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
const BITS_PER_BYTE: usize = 8;
const BYTE_MASK: usize = 0xFF;
const MIN_HEADER_BYTES_FOR_LENGTH: usize = 2;

/// Reads an entire elementary file by its Short File Identifier.
///
/// # Errors
///
/// Returns an [`EmrtdError`] on transport faults or if reading is rejected by the card.
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
    if header.len() < MIN_HEADER_BYTES_FOR_LENGTH {
        return Ok(header);
    }

    let total_expected_length = decode_outer_total_length(&header);
    let mut buffer = header;

    while buffer.len() < total_expected_length {
        let remaining = total_expected_length - buffer.len();
        let want = min(usize::from(READ_CHUNK_MAX_LENGTH), remaining) as u8;
        let offset = buffer.len() as u16;

        let chunk_cmd = CommandApdu::case_2(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: INS_READ_BINARY,
                p1: ((offset >> BITS_PER_BYTE) as usize & BYTE_MASK) as u8,
                p2: (offset as usize & BYTE_MASK) as u8,
            },
            want,
        );

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

        buffer.extend_from_slice(&chunk_response.body);

        if sw == SW_END_OF_FILE_REACHED {
            break;
        }
    }

    Ok(buffer)
}

/// Decodes the total expected length of an outer ASN.1 TLV object from its initial header bytes.
#[must_use]
pub fn decode_outer_total_length(header: &[u8]) -> usize {
    if header.is_empty() {
        return 0;
    }
    let mut index = 0;
    let first_tag_byte = header[index];
    index += 1;
    if first_tag_byte & MULTI_BYTE_TAG_FLAG == MULTI_BYTE_TAG_FLAG {
        while index < header.len() && (header[index] & HIGH_BIT_SET_FLAG != 0) {
            index += 1;
        }
        if index < header.len() {
            index += 1;
        }
    }
    let tag_len = index;
    if index >= header.len() {
        return header.len();
    }
    let length_first_byte = header[index];
    index += 1;

    let (length_bytes_count, content_length) = if length_first_byte < LONG_FORM_LENGTH_FLAG {
        (1usize, length_first_byte as usize)
    } else {
        let count = (length_first_byte & LENGTH_COUNT_MASK) as usize;
        let mut value: usize = 0;
        for sub_index in 0..count {
            if index + sub_index >= header.len() {
                return header.len();
            }
            value = (value << BITS_PER_BYTE) | (header[index + sub_index] as usize);
        }
        (1 + count, value)
    };

    tag_len + length_bytes_count + content_length
}

#[cfg(test)]
mod tests {
    use super::decode_outer_total_length;

    const SHORT_HEADER_LEN: usize = 2;
    const SHORT_FORM_HEADER: [u8; SHORT_HEADER_LEN] = [0x75, 0x10];
    const SHORT_FORM_TOTAL: usize = 18;
    const EXTENDED_HEADER_LEN: usize = 4;
    const EXTENDED_FORM_HEADER: [u8; EXTENDED_HEADER_LEN] = [0x75, 0x82, 0x01, 0x00];
    const EXTENDED_FORM_TOTAL: usize = 260;

    #[test]
    fn decodes_short_and_extended_lengths() {
        assert_eq!(
            decode_outer_total_length(&SHORT_FORM_HEADER),
            SHORT_FORM_TOTAL
        );
        assert_eq!(
            decode_outer_total_length(&EXTENDED_FORM_HEADER),
            EXTENDED_FORM_TOTAL
        );
    }
}
