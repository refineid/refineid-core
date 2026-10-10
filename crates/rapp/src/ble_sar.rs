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

//! The RAPP BLE segmentation and reassembly framing (RAPP v26.10.9 §5.3).
//!
//! Every message on the Channel Characteristic travels as one or more
//! fragments, each a 6-byte header (total length, chunk sequence, flags,
//! reserved) followed by payload. [`segment`] sends; [`BleSarReassembler`]
//! receives. Neither touches a radio.

use core::fmt;

use zeroize::Zeroize;

/// Bytes in one fragment header.
pub const BLE_SAR_HEADER_SIZE: usize = 6;
/// The smallest negotiated ATT MTU the profile accepts.
pub const BLE_MINIMUM_ATT_MTU: usize = 512;
/// The fewest payload bytes a FIRST or CONT fragment may carry.
pub const BLE_SAR_MINIMUM_NON_FINAL_PAYLOAD: usize = 64;
/// The first chunk sequence that is out of bounds.
pub const BLE_SAR_SEQUENCE_LIMIT: usize = 1_024;
/// The longest message the 16-bit total length expresses.
pub const BLE_SAR_MAXIMUM_MESSAGE: usize = u16::MAX as usize;
/// How long a frame may take to reassemble after its FIRST fragment.
pub const BLE_SAR_REASSEMBLY_TIMEOUT_MS: u64 = 5_000;

/// The hard cap on any attribute value (Bluetooth Core v5.4, Vol 3, Part F,
/// §3.2.9).
const ATTRIBUTE_VALUE_LIMIT: usize = 512;
/// Bytes the ATT PDU header takes from the MTU.
const ATT_HEADER_SIZE: usize = 3;

const OFFSET_TOTAL: usize = 0;
const OFFSET_SEQUENCE: usize = 2;
const OFFSET_FLAGS: usize = 4;
const OFFSET_RESERVED: usize = 5;

const FLAG_FIRST: u8 = 1 << 0;
const FLAG_CONT: u8 = 1 << 1;
const FLAG_LAST: u8 = 1 << 2;
const FLAG_SINGLE: u8 = FLAG_FIRST | FLAG_LAST;
/// Bits 0 to 2; bits 3 to 7 are reserved.
const FLAGS_DEFINED: u8 = FLAG_FIRST | FLAG_CONT | FLAG_LAST;

/// A fragment or message the SAR layer refuses.
///
/// Every receive failure is unrecoverable: the reassembly buffer is
/// zeroized and the connection must be dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BleSarError {
    /// The negotiated ATT MTU is below the profile minimum of 512 bytes.
    AttMtuTooSmall,
    /// A fragment carries no payload.
    EmptyFragment,
    /// A FIRST fragment already carries the whole declared total.
    FirstFragmentNotShorterThanTotal,
    /// A FIRST fragment carries fewer than 64 bytes.
    FirstFragmentTooShort,
    /// A fragment carries more payload than the capacity allows.
    FragmentOverCapacity,
    /// Fewer bytes than one SAR header.
    HeaderTruncated,
    /// The flags are not FIRST, CONT, LAST, or SINGLE.
    IllegalFlags,
    /// FIRST or SINGLE arrived while a frame was being reassembled.
    IllegalTransition,
    /// LAST arrived before the declared total was reached.
    IncompleteAtLast,
    /// The payload capacity cannot carry a non-final fragment.
    InvalidCapacity,
    /// The message is empty or longer than the 16-bit total length allows.
    InvalidMessageLength,
    /// A CONT fragment carries fewer than 64 bytes.
    NonFinalFragmentTooShort,
    /// The fragment would take the frame past its declared total.
    Overflow,
    /// The frame did not complete within 5.0 seconds of its FIRST fragment.
    ReassemblyTimeout,
    /// The reserved byte or reserved flag bits are not zero.
    ReservedBitsSet,
    /// The chunk sequence is not the next expected one.
    SequenceMismatch,
    /// The chunk sequence is 1024 or above.
    SequenceOutOfBounds,
    /// A SINGLE fragment's payload differs from its declared total.
    SingleLengthMismatch,
    /// The declared total differs from the one the frame latched.
    TotalLengthChanged,
    /// A frame does not begin with FIRST or SINGLE at sequence zero.
    UnexpectedInitialFragment,
    /// The declared total frame length is zero.
    ZeroTotalLength,
}

impl fmt::Display for BleSarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for BleSarError {}

/// The uniform fragment payload capacity,
/// `min(negotiated_att_mtu - 3, 512) - 6`, also bounded by any smaller value
/// limit the platform reports.
///
/// # Errors
/// [`BleSarError::AttMtuTooSmall`] below an MTU of 512, and
/// [`BleSarError::InvalidCapacity`] when the platform limit leaves no room
/// for a non-final fragment.
pub fn payload_capacity(
    negotiated_att_mtu: usize,
    platform_value_limit: Option<usize>,
) -> Result<usize, BleSarError> {
    if negotiated_att_mtu < BLE_MINIMUM_ATT_MTU {
        return Err(BleSarError::AttMtuTooSmall);
    }
    let mut value_limit = (negotiated_att_mtu - ATT_HEADER_SIZE).min(ATTRIBUTE_VALUE_LIMIT);
    if let Some(limit) = platform_value_limit {
        value_limit = value_limit.min(limit);
    }
    let capacity = value_limit
        .checked_sub(BLE_SAR_HEADER_SIZE)
        .ok_or(BleSarError::InvalidCapacity)?;
    if capacity < BLE_SAR_MINIMUM_NON_FINAL_PAYLOAD {
        return Err(BleSarError::InvalidCapacity);
    }
    Ok(capacity)
}

/// Split one message into the fragments that carry it, in order.
///
/// A message that fits one fragment travels as SINGLE; a longer one as
/// FIRST, CONT ... and LAST, each non-final fragment filled to capacity.
///
/// # Errors
/// [`BleSarError::InvalidCapacity`] for a capacity outside the profile's
/// range, and [`BleSarError::InvalidMessageLength`] for an empty message or
/// one longer than 65,535 bytes.
pub fn segment(message: &[u8], capacity: usize) -> Result<Vec<Vec<u8>>, BleSarError> {
    if !(BLE_SAR_MINIMUM_NON_FINAL_PAYLOAD..=ATTRIBUTE_VALUE_LIMIT - BLE_SAR_HEADER_SIZE)
        .contains(&capacity)
    {
        return Err(BleSarError::InvalidCapacity);
    }
    if message.is_empty() || message.len() > BLE_SAR_MAXIMUM_MESSAGE {
        return Err(BleSarError::InvalidMessageLength);
    }
    if message.len() <= capacity {
        return Ok(vec![fragment(message.len(), 0, FLAG_SINGLE, message)]);
    }
    let chunks: Vec<&[u8]> = message.chunks(capacity).collect();
    let last = chunks.len() - 1;
    Ok(chunks
        .iter()
        .enumerate()
        .map(|(sequence, payload)| {
            let flags = match sequence {
                0 => FLAG_FIRST,
                index if index == last => FLAG_LAST,
                _ => FLAG_CONT,
            };
            fragment(message.len(), sequence, flags, payload)
        })
        .collect())
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "segment bounds the total by 65,535 and the sequence by the chunk count of such a total"
)]
fn fragment(total: usize, sequence: usize, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BLE_SAR_HEADER_SIZE + payload.len());
    bytes.extend_from_slice(&(total as u16).to_be_bytes());
    bytes.extend_from_slice(&(sequence as u16).to_be_bytes());
    bytes.push(flags);
    bytes.push(0);
    bytes.extend_from_slice(payload);
    bytes
}

fn field(fragment: &[u8], offset: usize) -> usize {
    usize::from(u16::from_be_bytes([fragment[offset], fragment[offset + 1]]))
}

struct Header {
    total: usize,
    sequence: usize,
    flags: u8,
}

/// The normative SAR receive state machine for one connection and one
/// direction.
///
/// Fragments must be handed over in arrival order. Any refused fragment
/// zeroizes the buffer and returns the machine to idle; the caller then
/// drops the connection. The clock is the caller's monotonic milliseconds.
#[derive(Default)]
pub struct BleSarReassembler {
    expected_sequence: usize,
    expected_total: usize,
    buffer: Vec<u8>,
    deadline: Option<u64>,
}

impl fmt::Debug for BleSarReassembler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BleSarReassembler")
            .field("expected_sequence", &self.expected_sequence)
            .field("expected_total", &self.expected_total)
            .finish_non_exhaustive()
    }
}

impl Drop for BleSarReassembler {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl BleSarReassembler {
    /// A machine waiting for the first fragment of a frame.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether no frame is being reassembled.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.expected_sequence == 0 && self.buffer.is_empty()
    }

    /// Consume one fragment.
    ///
    /// Returns the complete message once its last fragment arrives, or
    /// `None` while more fragments are expected.
    ///
    /// # Errors
    /// [`BleSarError`] for any fragment the specification refuses; the
    /// machine is then idle and zeroized.
    pub fn receive(
        &mut self,
        fragment: &[u8],
        capacity: usize,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, BleSarError> {
        let outcome = self.accept(fragment, capacity, now_ms);
        if outcome.is_err() {
            self.reset();
        }
        outcome
    }

    /// Refuse a frame whose 5.0-second reassembly timer has run out.
    ///
    /// # Errors
    /// [`BleSarError::ReassemblyTimeout`] when a frame is in progress and
    /// its deadline has passed; the machine is then idle.
    pub fn check_timer(&mut self, now_ms: u64) -> Result<(), BleSarError> {
        match self.deadline {
            Some(deadline) if now_ms >= deadline => {
                self.reset();
                Err(BleSarError::ReassemblyTimeout)
            }
            _ => Ok(()),
        }
    }

    /// Zeroize any partial frame and return to idle.
    pub fn reset(&mut self) {
        self.buffer.zeroize();
        self.buffer.clear();
        self.expected_sequence = 0;
        self.expected_total = 0;
        self.deadline = None;
    }

    fn header(fragment: &[u8], capacity: usize) -> Result<Header, BleSarError> {
        if fragment.len() < BLE_SAR_HEADER_SIZE {
            return Err(BleSarError::HeaderTruncated);
        }
        let flags = fragment[OFFSET_FLAGS];
        if fragment[OFFSET_RESERVED] != 0 {
            return Err(BleSarError::ReservedBitsSet);
        }
        if ![FLAG_FIRST, FLAG_CONT, FLAG_LAST, FLAG_SINGLE].contains(&flags) {
            return Err(if flags & !FLAGS_DEFINED == 0 {
                BleSarError::IllegalFlags
            } else {
                BleSarError::ReservedBitsSet
            });
        }
        let payload_len = fragment.len() - BLE_SAR_HEADER_SIZE;
        if payload_len == 0 {
            return Err(BleSarError::EmptyFragment);
        }
        if payload_len > capacity {
            return Err(BleSarError::FragmentOverCapacity);
        }
        let sequence = field(fragment, OFFSET_SEQUENCE);
        if sequence >= BLE_SAR_SEQUENCE_LIMIT {
            return Err(BleSarError::SequenceOutOfBounds);
        }
        let total = field(fragment, OFFSET_TOTAL);
        if total == 0 {
            return Err(BleSarError::ZeroTotalLength);
        }
        Ok(Header {
            total,
            sequence,
            flags,
        })
    }

    fn accept(
        &mut self,
        fragment: &[u8],
        capacity: usize,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, BleSarError> {
        self.check_timer(now_ms)?;
        let header = Self::header(fragment, capacity)?;
        let payload = &fragment[BLE_SAR_HEADER_SIZE..];
        if self.is_idle() {
            self.begin(&header, payload, now_ms)
        } else {
            self.continue_frame(&header, payload)
        }
    }

    fn begin(
        &mut self,
        header: &Header,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, BleSarError> {
        if !(header.flags == FLAG_FIRST || header.flags == FLAG_SINGLE) || header.sequence != 0 {
            return Err(BleSarError::UnexpectedInitialFragment);
        }
        if header.flags == FLAG_SINGLE {
            if header.total != payload.len() {
                return Err(BleSarError::SingleLengthMismatch);
            }
            return Ok(Some(payload.to_vec()));
        }
        if payload.len() < BLE_SAR_MINIMUM_NON_FINAL_PAYLOAD {
            return Err(BleSarError::FirstFragmentTooShort);
        }
        if payload.len() >= header.total {
            return Err(BleSarError::FirstFragmentNotShorterThanTotal);
        }
        self.expected_total = header.total;
        self.buffer.reserve(header.total);
        self.buffer.extend_from_slice(payload);
        self.expected_sequence = 1;
        self.deadline = Some(now_ms.saturating_add(BLE_SAR_REASSEMBLY_TIMEOUT_MS));
        Ok(None)
    }

    fn continue_frame(
        &mut self,
        header: &Header,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, BleSarError> {
        let is_last = header.flags == FLAG_LAST;
        if !is_last && header.flags != FLAG_CONT {
            return Err(BleSarError::IllegalTransition);
        }
        if header.total != self.expected_total {
            return Err(BleSarError::TotalLengthChanged);
        }
        if header.sequence != self.expected_sequence {
            return Err(BleSarError::SequenceMismatch);
        }
        if !is_last && payload.len() < BLE_SAR_MINIMUM_NON_FINAL_PAYLOAD {
            return Err(BleSarError::NonFinalFragmentTooShort);
        }
        if self.buffer.len() + payload.len() > self.expected_total {
            return Err(BleSarError::Overflow);
        }
        self.buffer.extend_from_slice(payload);
        if !is_last {
            self.expected_sequence += 1;
            return Ok(None);
        }
        if self.buffer.len() != self.expected_total {
            return Err(BleSarError::IncompleteAtLast);
        }
        let message = self.buffer.clone();
        self.reset();
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::{BleSarError, BleSarReassembler, payload_capacity, segment};

    #[test]
    fn segmenting_then_reassembling_returns_the_message() {
        let capacity = payload_capacity(517, None).expect("capacity");
        let message: Vec<u8> = (0..1_500_u16).map(|value| value.to_le_bytes()[0]).collect();
        let mut reassembler = BleSarReassembler::new();
        let mut delivered = None;
        for fragment in segment(&message, capacity).expect("segment") {
            delivered = reassembler
                .receive(&fragment, capacity, 0)
                .expect("fragment accepted");
        }
        assert_eq!(delivered, Some(message));
        assert!(reassembler.is_idle());
    }

    #[test]
    fn a_refused_fragment_leaves_the_machine_idle() {
        let mut reassembler = BleSarReassembler::new();
        assert_eq!(
            reassembler.receive(&[0, 1, 0, 0, 2, 0, 9], 503, 0),
            Err(BleSarError::UnexpectedInitialFragment)
        );
        assert!(reassembler.is_idle());
    }
}
