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

//! CCID bulk and interrupt message encoding and decoding.
//!
//! Defined by USB-IF Smart Card CCID Specification Revision 1.1 §6.1, §6.2, and §6.3.

use crate::error::CcidError;
use alloc::vec::Vec;

/// Standard CCID 10-byte bulk message header size.
pub const CCID_HEADER_SIZE: usize = 10;
/// Maximum allowed response payload size (extended APDU response + SW1/SW2).
pub const MAX_RESPONSE_PAYLOAD_SIZE: usize = 65_538;

/// Byte offset of message type in CCID header.
pub const MESSAGE_TYPE_OFFSET: usize = 0;
/// Byte offset of payload length (4 bytes LE) in CCID header.
pub const LENGTH_OFFSET: usize = 1;
/// Byte offset of slot number in CCID header.
pub const SLOT_OFFSET: usize = 5;
/// Byte offset of sequence number in CCID header.
pub const SEQUENCE_OFFSET: usize = 6;
/// Byte offset of status / parameter byte in CCID header.
pub const STATUS_OFFSET: usize = 7;
/// Byte offset of error code in CCID header.
pub const ERROR_OFFSET: usize = 8;
/// Byte offset of response parameter (chain/clock/protocol) in CCID header.
pub const RESPONSE_PARAMETER_OFFSET: usize = 9;

// --- CCID Message Types (Bulk-OUT: Host -> Reader) ---

/// Set parameters command (`PC_to_RDR_SetParameters`).
pub const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
/// Power on card command (`PC_to_RDR_IccPowerOn`).
pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
/// Power off card command (`PC_to_RDR_IccPowerOff`).
pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
/// Get slot status command (`PC_to_RDR_GetSlotStatus`).
pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
/// Abort command (`PC_to_RDR_Abort`).
pub const PC_TO_RDR_ABORT: u8 = 0x67;
/// Get parameters command (`PC_to_RDR_GetParameters`).
pub const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6C;
/// Transfer block command (`PC_to_RDR_XfrBlock`).
pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;

// --- CCID Message Types (Bulk-IN: Reader -> Host) ---

/// Data block reply (`RDR_to_PC_DataBlock`).
pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
/// Slot status reply (`RDR_to_PC_SlotStatus`).
pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
/// Parameters reply (`RDR_to_PC_Parameters`).
pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;

// --- CCID Message Types (Interrupt-IN: Reader -> Host) ---

/// Slot status change notification (`RDR_to_PC_NotifySlotChange`).
pub const RDR_TO_PC_NOTIFY_SLOT_CHANGE: u8 = 0x50;
/// Hardware error notification (`RDR_to_PC_HardwareError`).
pub const RDR_TO_PC_HARDWARE_ERROR: u8 = 0x51;

// --- Status field masks and bits ---

/// Card status: card present and powered/active.
pub const CARD_STATUS_ACTIVE: u8 = 0;
/// Card status: card present but inactive/unpowered.
pub const CARD_STATUS_INACTIVE: u8 = 1;
/// Card status: no smart card present in slot.
pub const CARD_STATUS_NOT_PRESENT: u8 = 2;

/// Command status: command succeeded.
pub const COMMAND_STATUS_SUCCEEDED: u8 = 0;
/// Command status: command failed.
pub const COMMAND_STATUS_FAILED: u8 = 1;
/// Command status: time extension requested.
pub const COMMAND_STATUS_TIME_EXTENSION: u8 = 2;
/// Bit shift for command status in bStatus byte.
pub const COMMAND_STATUS_SHIFT: usize = 6;

/// Mask for reserved bits (bits 2..5) in bStatus byte.
pub const RESERVED_STATUS_MASK: u8 = 0x3C;
/// 2-bit field mask.
pub const FIELD_MASK: u8 = 0x03;

/// Voltage selection: automatic.
pub const AUTOMATIC_VOLTAGE_SELECTION: u8 = 0;
/// Voltage selection: 5.0V.
pub const VOLTAGE_5_0V: u8 = 1;
/// Voltage selection: 3.0V.
pub const VOLTAGE_3_0V: u8 = 2;
/// Voltage selection: 1.8V.
pub const VOLTAGE_1_8V: u8 = 3;

/// Chain parameter: complete message.
pub const CHAIN_COMPLETE: u8 = 0;
/// Chain parameter: begin of message.
pub const CHAIN_BEGIN: u8 = 1;
/// Chain parameter: end of message.
pub const CHAIN_END: u8 = 2;
/// Chain parameter: continuation of message.
pub const CHAIN_CONTINUE: u8 = 3;
/// Chain parameter: command continuation expected.
pub const CHAIN_COMMAND_CONTINUATION_EXPECTED: u8 = 0x10;

/// Clock running.
pub const CLOCK_RUNNING: u8 = 0;
/// Clock stopped low.
pub const CLOCK_STOPPED_LOW: u8 = 1;
/// Clock stopped high.
pub const CLOCK_STOPPED_HIGH: u8 = 2;
/// Clock stopped unknown state.
pub const CLOCK_STOPPED_UNKNOWN: u8 = 3;

/// Default T=0 Fi/Di parameter (0x11 = 372 clock cycles/etu).
pub const DEFAULT_T0_FIDI: u8 = 0x11;
/// Default T=0 waiting integer (WI = 10).
pub const DEFAULT_T0_WAITING_INTEGER: u8 = 0x0A;
/// T=0 parameter block length (5 bytes).
pub const T0_PARAMETER_LENGTH: usize = 5;
/// Inverse convention bit in T=0 convention byte.
pub const T0_INVERSE_CONVENTION: u8 = 0x02;

/// Card presence status in slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardStatus {
    /// Card is present and active (powered).
    Active,
    /// Card is present but inactive.
    Inactive,
    /// No card present in slot.
    NotPresent,
}

/// Clock status reported by reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockStatus {
    /// Clock is running.
    Running,
    /// Clock stopped in low state.
    StoppedLow,
    /// Clock stopped in high state.
    StoppedHigh,
    /// Clock stopped in unknown state.
    StoppedUnknown,
}

/// Message chaining parameter reported by reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainParameter {
    /// Single complete message.
    Complete,
    /// First block of multi-block chain.
    Begin,
    /// Final block of multi-block chain.
    End,
    /// Intermediate block of multi-block chain.
    Continue,
    /// Command continuation expected.
    CommandContinuationExpected,
}

/// Decoded successful or failure CCID response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcidResponse {
    /// Data block reply with card payload (e.g. ATR or R-APDU).
    DataBlock {
        /// Card power status.
        card_status: CardStatus,
        /// Message chain parameter.
        chain_parameter: ChainParameter,
        /// Received payload bytes.
        payload: Vec<u8>,
    },
    /// Slot status reply without payload.
    SlotStatus {
        /// Card power status.
        card_status: CardStatus,
        /// Card clock status.
        clock_status: ClockStatus,
    },
    /// Parameters reply with protocol information.
    Parameters {
        /// Card power status.
        card_status: CardStatus,
        /// Active protocol number (0 for T=0, 1 for T=1).
        protocol_num: u8,
        /// Parameter payload bytes.
        payload: Vec<u8>,
    },
    /// Command failed with error code.
    CommandFailure {
        /// Card power status.
        card_status: CardStatus,
        /// Signed error code.
        error_code: i8,
    },
    /// Time extension requested by reader.
    TimeExtension {
        /// Card power status.
        card_status: CardStatus,
        /// Waiting time multiplier.
        multiplier: u8,
    },
}

impl CcidResponse {
    /// Returns the card status for this response.
    #[must_use]
    pub const fn card_status(&self) -> CardStatus {
        match self {
            Self::DataBlock { card_status, .. }
            | Self::SlotStatus { card_status, .. }
            | Self::Parameters { card_status, .. }
            | Self::CommandFailure { card_status, .. }
            | Self::TimeExtension { card_status, .. } => *card_status,
        }
    }
}

/// Decoded interrupt slot change notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotChangeNotification {
    /// Per-slot presence indicator: `slot_presence[i]` is true if slot `i` has a card present.
    pub slot_presence: Vec<bool>,
    /// Per-slot change indicator: `slot_changed[i]` is true if slot `i` presence changed.
    pub slot_changed: Vec<bool>,
}

impl SlotChangeNotification {
    /// Check if a specific slot has a card present.
    #[must_use]
    pub fn is_card_present(&self, slot: u8) -> bool {
        self.slot_presence
            .get(slot as usize)
            .copied()
            .unwrap_or(false)
    }

    /// Check if a specific slot had its presence changed.
    #[must_use]
    pub fn has_slot_changed(&self, slot: u8) -> bool {
        self.slot_changed
            .get(slot as usize)
            .copied()
            .unwrap_or(false)
    }
}

// --- Encoding functions ---

/// Encode a 10-byte `PC_to_RDR_IccPowerOn` message.
#[must_use]
pub fn encode_icc_power_on(slot: u8, seq: u8, voltage_selection: u8) -> [u8; CCID_HEADER_SIZE] {
    let mut buf = [0_u8; CCID_HEADER_SIZE];
    buf[MESSAGE_TYPE_OFFSET] = PC_TO_RDR_ICC_POWER_ON;
    buf[SLOT_OFFSET] = slot;
    buf[SEQUENCE_OFFSET] = seq;
    buf[STATUS_OFFSET] = voltage_selection;
    buf
}

/// Encode a 10-byte `PC_to_RDR_IccPowerOff` message.
#[must_use]
pub fn encode_icc_power_off(slot: u8, seq: u8) -> [u8; CCID_HEADER_SIZE] {
    let mut buf = [0_u8; CCID_HEADER_SIZE];
    buf[MESSAGE_TYPE_OFFSET] = PC_TO_RDR_ICC_POWER_OFF;
    buf[SLOT_OFFSET] = slot;
    buf[SEQUENCE_OFFSET] = seq;
    buf
}

/// Encode a 10-byte `PC_to_RDR_GetSlotStatus` message.
#[must_use]
pub fn encode_get_slot_status(slot: u8, seq: u8) -> [u8; CCID_HEADER_SIZE] {
    let mut buf = [0_u8; CCID_HEADER_SIZE];
    buf[MESSAGE_TYPE_OFFSET] = PC_TO_RDR_GET_SLOT_STATUS;
    buf[SLOT_OFFSET] = slot;
    buf[SEQUENCE_OFFSET] = seq;
    buf
}

/// Encode a `PC_to_RDR_XfrBlock` message with payload.
#[must_use]
pub fn encode_xfr_block(
    slot: u8,
    seq: u8,
    b_wi: u8,
    w_level_parameter: u16,
    block: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CCID_HEADER_SIZE + block.len());
    out.push(PC_TO_RDR_XFR_BLOCK);
    out.extend_from_slice(&(block.len() as u32).to_le_bytes());
    out.push(slot);
    out.push(seq);
    out.push(b_wi);
    out.extend_from_slice(&w_level_parameter.to_le_bytes());
    out.extend_from_slice(block);
    out
}

/// Encode a 10-byte `PC_to_RDR_GetParameters` message.
#[must_use]
pub fn encode_get_parameters(slot: u8, seq: u8) -> [u8; CCID_HEADER_SIZE] {
    let mut buf = [0_u8; CCID_HEADER_SIZE];
    buf[MESSAGE_TYPE_OFFSET] = PC_TO_RDR_GET_PARAMETERS;
    buf[SLOT_OFFSET] = slot;
    buf[SEQUENCE_OFFSET] = seq;
    buf
}

/// Encode a 15-byte `PC_to_RDR_SetParameters` message for protocol T=0.
#[must_use]
pub fn encode_set_parameters_t0(
    slot: u8,
    seq: u8,
    fi_di: u8,
    guard_time: u8,
    waiting_integer: u8,
    clock_stop: u8,
    inverse_convention: bool,
) -> [u8; CCID_HEADER_SIZE + T0_PARAMETER_LENGTH] {
    let mut buf = [0_u8; CCID_HEADER_SIZE + T0_PARAMETER_LENGTH];
    buf[MESSAGE_TYPE_OFFSET] = PC_TO_RDR_SET_PARAMETERS;
    buf[LENGTH_OFFSET..LENGTH_OFFSET + 4]
        .copy_from_slice(&(T0_PARAMETER_LENGTH as u32).to_le_bytes());
    buf[SLOT_OFFSET] = slot;
    buf[SEQUENCE_OFFSET] = seq;
    buf[STATUS_OFFSET] = 0; // bProtocolNum = 0 (T=0)
    buf[CCID_HEADER_SIZE] = fi_di;
    buf[CCID_HEADER_SIZE + 1] = if inverse_convention {
        T0_INVERSE_CONVENTION
    } else {
        0
    };
    buf[CCID_HEADER_SIZE + 2] = guard_time;
    buf[CCID_HEADER_SIZE + 3] = waiting_integer;
    buf[CCID_HEADER_SIZE + 4] = clock_stop;
    buf
}

/// Encode a 10-byte `PC_to_RDR_Abort` message.
#[must_use]
pub fn encode_abort(slot: u8, seq: u8) -> [u8; CCID_HEADER_SIZE] {
    let mut buf = [0_u8; CCID_HEADER_SIZE];
    buf[MESSAGE_TYPE_OFFSET] = PC_TO_RDR_ABORT;
    buf[SLOT_OFFSET] = slot;
    buf[SEQUENCE_OFFSET] = seq;
    buf
}

// --- Decoding functions ---

/// Decode a CCID response frame received on Bulk-IN.
///
/// # Errors
/// Returns `CcidError` if the header is truncated, lengths do not match,
/// or reserved bits/types violate the specification.
pub fn decode_response(
    frame: &[u8],
    expected_msg_type: u8,
    expected_slot: u8,
    expected_seq: u8,
) -> Result<CcidResponse, CcidError> {
    if frame.len() < CCID_HEADER_SIZE {
        return Err(CcidError::TruncatedHeader);
    }

    let declared_length = u32::from_le_bytes([
        frame[LENGTH_OFFSET],
        frame[LENGTH_OFFSET + 1],
        frame[LENGTH_OFFSET + 2],
        frame[LENGTH_OFFSET + 3],
    ]) as usize;

    if declared_length > MAX_RESPONSE_PAYLOAD_SIZE {
        return Err(CcidError::ResponseLengthOutOfRange);
    }

    let expected_total_size = CCID_HEADER_SIZE
        .checked_add(declared_length)
        .ok_or(CcidError::ResponseLengthOutOfRange)?;

    if frame.len() != expected_total_size {
        return Err(CcidError::LengthMismatch);
    }

    let actual_msg_type = frame[MESSAGE_TYPE_OFFSET];
    if actual_msg_type != expected_msg_type {
        return Err(CcidError::UnexpectedMessageType {
            expected: expected_msg_type,
            actual: actual_msg_type,
        });
    }

    let actual_slot = frame[SLOT_OFFSET];
    if actual_slot != expected_slot {
        return Err(CcidError::UnexpectedSlot {
            expected: expected_slot,
            actual: actual_slot,
        });
    }

    let actual_seq = frame[SEQUENCE_OFFSET];
    if actual_seq != expected_seq {
        return Err(CcidError::UnexpectedSequence {
            expected: expected_seq,
            actual: actual_seq,
        });
    }

    if expected_msg_type == RDR_TO_PC_SLOT_STATUS && declared_length != 0 {
        return Err(CcidError::UnexpectedPayload);
    }

    let status = frame[STATUS_OFFSET];
    if (status & RESERVED_STATUS_MASK) != 0 {
        return Err(CcidError::ReservedStatusBits);
    }

    let card_status = match status & FIELD_MASK {
        CARD_STATUS_ACTIVE => CardStatus::Active,
        CARD_STATUS_INACTIVE => CardStatus::Inactive,
        CARD_STATUS_NOT_PRESENT => CardStatus::NotPresent,
        _ => return Err(CcidError::ReservedCardStatus),
    };

    let command_status = (status >> COMMAND_STATUS_SHIFT) & FIELD_MASK;
    let error_byte = frame[ERROR_OFFSET];

    match command_status {
        COMMAND_STATUS_SUCCEEDED => match expected_msg_type {
            RDR_TO_PC_SLOT_STATUS => {
                let clock_param = frame[RESPONSE_PARAMETER_OFFSET];
                let clock_status = match clock_param {
                    CLOCK_RUNNING => ClockStatus::Running,
                    CLOCK_STOPPED_LOW => ClockStatus::StoppedLow,
                    CLOCK_STOPPED_HIGH => ClockStatus::StoppedHigh,
                    CLOCK_STOPPED_UNKNOWN => ClockStatus::StoppedUnknown,
                    _ => return Err(CcidError::InvalidClockStatus),
                };
                Ok(CcidResponse::SlotStatus {
                    card_status,
                    clock_status,
                })
            }
            RDR_TO_PC_DATA_BLOCK => {
                let chain_param = frame[RESPONSE_PARAMETER_OFFSET];
                let chain_parameter = match chain_param {
                    CHAIN_COMPLETE => ChainParameter::Complete,
                    CHAIN_BEGIN => ChainParameter::Begin,
                    CHAIN_END => ChainParameter::End,
                    CHAIN_CONTINUE => ChainParameter::Continue,
                    CHAIN_COMMAND_CONTINUATION_EXPECTED => {
                        ChainParameter::CommandContinuationExpected
                    }
                    _ => return Err(CcidError::InvalidChainParameter),
                };
                let payload = frame[CCID_HEADER_SIZE..].to_vec();
                Ok(CcidResponse::DataBlock {
                    card_status,
                    chain_parameter,
                    payload,
                })
            }
            RDR_TO_PC_PARAMETERS => {
                let protocol_num = frame[RESPONSE_PARAMETER_OFFSET];
                let payload = frame[CCID_HEADER_SIZE..].to_vec();
                match protocol_num {
                    0 if payload.len() == 5 => Ok(CcidResponse::Parameters {
                        card_status,
                        protocol_num,
                        payload,
                    }),
                    1 if payload.len() == 7 => Ok(CcidResponse::Parameters {
                        card_status,
                        protocol_num,
                        payload,
                    }),
                    _ => Err(CcidError::ProtocolDesync(
                        "invalid CCID parameters protocol or length".into(),
                    )),
                }
            }
            _ => Err(CcidError::UnexpectedMessageType {
                expected: expected_msg_type,
                actual: actual_msg_type,
            }),
        },
        COMMAND_STATUS_FAILED => Ok(CcidResponse::CommandFailure {
            card_status,
            error_code: error_byte as i8,
        }),
        COMMAND_STATUS_TIME_EXTENSION => Ok(CcidResponse::TimeExtension {
            card_status,
            multiplier: error_byte,
        }),
        _ => Err(CcidError::ReservedCommandStatus),
    }
}

/// Decode an Interrupt-IN `RDR_to_PC_NotifySlotChange` packet.
///
/// Per CCID §6.3.1, the packet starts with byte 0x50, followed by pairs of bits
/// for each slot: bit 2n = ICC present, bit 2n+1 = ICC presence changed.
///
/// # Errors
/// Returns `CcidError` if the packet is too short or not a slot change notification.
pub fn decode_interrupt_slot_change(
    frame: &[u8],
    max_slot_index: u8,
) -> Result<SlotChangeNotification, CcidError> {
    if frame.is_empty() {
        return Err(CcidError::TruncatedHeader);
    }
    if frame[0] != RDR_TO_PC_NOTIFY_SLOT_CHANGE {
        return Err(CcidError::UnexpectedMessageType {
            expected: RDR_TO_PC_NOTIFY_SLOT_CHANGE,
            actual: frame[0],
        });
    }

    let slot_count = (max_slot_index as usize) + 1;
    let required_bytes = 1 + (slot_count.saturating_add(3) / 4);
    if frame.len() < required_bytes {
        return Err(CcidError::LengthMismatch);
    }

    let mut slot_presence = Vec::with_capacity(slot_count);
    let mut slot_changed = Vec::with_capacity(slot_count);

    for slot_idx in 0..slot_count {
        let byte_offset = 1 + (slot_idx / 4);
        let bit_offset = (slot_idx % 4) * 2;
        let byte_val = frame[byte_offset];

        let present = ((byte_val >> bit_offset) & 0x01) != 0;
        let changed = ((byte_val >> (bit_offset + 1)) & 0x01) != 0;

        slot_presence.push(present);
        slot_changed.push(changed);
    }

    Ok(SlotChangeNotification {
        slot_presence,
        slot_changed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_power_on_message() {
        let msg = encode_icc_power_on(0, 1, VOLTAGE_5_0V);
        assert_eq!(msg[0], PC_TO_RDR_ICC_POWER_ON);
        assert_eq!(&msg[1..5], &[0, 0, 0, 0]);
        assert_eq!(msg[5], 0); // slot
        assert_eq!(msg[6], 1); // seq
        assert_eq!(msg[7], VOLTAGE_5_0V);
        assert_eq!(&msg[8..10], &[0, 0]);
    }

    #[test]
    fn encode_power_off_message() {
        let msg = encode_icc_power_off(1, 42);
        assert_eq!(msg[0], PC_TO_RDR_ICC_POWER_OFF);
        assert_eq!(msg[5], 1);
        assert_eq!(msg[6], 42);
    }

    #[test]
    fn encode_get_slot_status_message() {
        let msg = encode_get_slot_status(2, 7);
        assert_eq!(msg[0], PC_TO_RDR_GET_SLOT_STATUS);
        assert_eq!(msg[5], 2);
        assert_eq!(msg[6], 7);
    }

    #[test]
    fn encode_xfr_block_message() {
        let payload = [0x00, 0xA4, 0x04, 0x00, 0x00];
        let msg = encode_xfr_block(0, 5, 10, 0x0102, &payload);
        assert_eq!(msg[0], PC_TO_RDR_XFR_BLOCK);
        let len = u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, payload.len());
        assert_eq!(msg[5], 0);
        assert_eq!(msg[6], 5);
        assert_eq!(msg[7], 10);
        assert_eq!(&msg[8..10], &[0x02, 0x01]);
        assert_eq!(&msg[10..], &payload);
    }

    #[test]
    fn encode_set_parameters_t0_message() {
        let msg = encode_set_parameters_t0(0, 3, 0x11, 0, 10, 0, false);
        assert_eq!(msg[0], PC_TO_RDR_SET_PARAMETERS);
        assert_eq!(&msg[1..5], &[5, 0, 0, 0]); // 5 bytes payload
        assert_eq!(msg[5], 0);
        assert_eq!(msg[6], 3);
        assert_eq!(msg[7], 0); // bProtocolNum = 0
        assert_eq!(msg[10], 0x11);
        assert_eq!(msg[11], 0);
        assert_eq!(msg[12], 0);
        assert_eq!(msg[13], 10);
        assert_eq!(msg[14], 0);
    }

    #[test]
    fn encode_abort_message() {
        let msg = encode_abort(0, 99);
        assert_eq!(msg[0], PC_TO_RDR_ABORT);
        assert_eq!(msg[5], 0);
        assert_eq!(msg[6], 99);
    }

    fn build_response_frame(
        msg_type: u8,
        slot: u8,
        seq: u8,
        status: u8,
        error: u8,
        param: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut f = Vec::with_capacity(10 + payload.len());
        f.push(msg_type);
        f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        f.push(slot);
        f.push(seq);
        f.push(status);
        f.push(error);
        f.push(param);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn decode_data_block_success() {
        let atr = [0x3B, 0x7F, 0x18, 0x00];
        let frame = build_response_frame(
            RDR_TO_PC_DATA_BLOCK,
            0,
            1,
            CARD_STATUS_ACTIVE,
            0,
            CHAIN_COMPLETE,
            &atr,
        );

        let resp =
            decode_response(&frame, RDR_TO_PC_DATA_BLOCK, 0, 1).expect("valid data block response");

        match resp {
            CcidResponse::DataBlock {
                card_status,
                chain_parameter,
                payload,
            } => {
                assert_eq!(card_status, CardStatus::Active);
                assert_eq!(chain_parameter, ChainParameter::Complete);
                assert_eq!(&payload, &atr);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn decode_slot_status_success() {
        let frame = build_response_frame(
            RDR_TO_PC_SLOT_STATUS,
            0,
            2,
            CARD_STATUS_ACTIVE,
            0,
            CLOCK_RUNNING,
            &[],
        );

        let resp = decode_response(&frame, RDR_TO_PC_SLOT_STATUS, 0, 2).expect("valid slot status");

        match resp {
            CcidResponse::SlotStatus {
                card_status,
                clock_status,
            } => {
                assert_eq!(card_status, CardStatus::Active);
                assert_eq!(clock_status, ClockStatus::Running);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn decode_command_failure() {
        let status = (COMMAND_STATUS_FAILED << COMMAND_STATUS_SHIFT) | CARD_STATUS_ACTIVE;
        let error_code = -5_i8 as u8;
        let frame = build_response_frame(RDR_TO_PC_DATA_BLOCK, 0, 3, status, error_code, 0, &[]);

        let resp =
            decode_response(&frame, RDR_TO_PC_DATA_BLOCK, 0, 3).expect("decoded command failure");

        match resp {
            CcidResponse::CommandFailure {
                card_status,
                error_code,
            } => {
                assert_eq!(card_status, CardStatus::Active);
                assert_eq!(error_code, -5);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn decode_time_extension() {
        let status = (COMMAND_STATUS_TIME_EXTENSION << COMMAND_STATUS_SHIFT) | CARD_STATUS_ACTIVE;
        let multiplier = 4_u8;
        let frame = build_response_frame(RDR_TO_PC_DATA_BLOCK, 0, 4, status, multiplier, 0, &[]);

        let resp =
            decode_response(&frame, RDR_TO_PC_DATA_BLOCK, 0, 4).expect("decoded time extension");

        match resp {
            CcidResponse::TimeExtension {
                card_status,
                multiplier: m,
            } => {
                assert_eq!(card_status, CardStatus::Active);
                assert_eq!(m, 4);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let short = [0x80, 0x00, 0x00];
        assert_eq!(
            decode_response(&short, RDR_TO_PC_DATA_BLOCK, 0, 0),
            Err(CcidError::TruncatedHeader)
        );
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let mut frame = build_response_frame(
            RDR_TO_PC_DATA_BLOCK,
            0,
            1,
            CARD_STATUS_ACTIVE,
            0,
            0,
            &[0x01, 0x02],
        );
        // Truncate payload
        frame.pop();
        assert_eq!(
            decode_response(&frame, RDR_TO_PC_DATA_BLOCK, 0, 1),
            Err(CcidError::LengthMismatch)
        );
    }

    #[test]
    fn decode_rejects_unexpected_message_type() {
        let frame =
            build_response_frame(RDR_TO_PC_SLOT_STATUS, 0, 1, CARD_STATUS_ACTIVE, 0, 0, &[]);
        assert_eq!(
            decode_response(&frame, RDR_TO_PC_DATA_BLOCK, 0, 1),
            Err(CcidError::UnexpectedMessageType {
                expected: RDR_TO_PC_DATA_BLOCK,
                actual: RDR_TO_PC_SLOT_STATUS,
            })
        );
    }

    #[test]
    fn decode_rejects_unexpected_slot() {
        let frame = build_response_frame(RDR_TO_PC_DATA_BLOCK, 1, 5, CARD_STATUS_ACTIVE, 0, 0, &[]);
        assert_eq!(
            decode_response(&frame, RDR_TO_PC_DATA_BLOCK, 0, 5),
            Err(CcidError::UnexpectedSlot {
                expected: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_rejects_unexpected_sequence() {
        let frame = build_response_frame(RDR_TO_PC_DATA_BLOCK, 0, 2, CARD_STATUS_ACTIVE, 0, 0, &[]);
        assert_eq!(
            decode_response(&frame, RDR_TO_PC_DATA_BLOCK, 0, 1),
            Err(CcidError::UnexpectedSequence {
                expected: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn decode_rejects_reserved_status_bits() {
        // Reserved bits 2..5 set
        let status = RESERVED_STATUS_MASK | CARD_STATUS_ACTIVE;
        let frame = build_response_frame(RDR_TO_PC_DATA_BLOCK, 0, 1, status, 0, 0, &[]);
        assert_eq!(
            decode_response(&frame, RDR_TO_PC_DATA_BLOCK, 0, 1),
            Err(CcidError::ReservedStatusBits)
        );
    }

    #[test]
    fn decode_interrupt_slot_change_single_slot() {
        // Slot 0 present (bit 0 = 1), changed (bit 1 = 1) -> 0x03
        let packet = [RDR_TO_PC_NOTIFY_SLOT_CHANGE, 0x03];
        let notif =
            decode_interrupt_slot_change(&packet, 0).expect("valid single slot notification");
        assert!(notif.is_card_present(0));
        assert!(notif.has_slot_changed(0));
    }

    #[test]
    fn decode_interrupt_slot_change_multi_slot() {
        // Slot 0: present (1), not changed (0) -> bits 0..1 = 01b
        // Slot 1: not present (0), changed (1) -> bits 2..3 = 10b (card removed!)
        // Byte 1 = 0b1001 = 0x09
        let packet = [RDR_TO_PC_NOTIFY_SLOT_CHANGE, 0x09];
        let notif =
            decode_interrupt_slot_change(&packet, 1).expect("valid multi slot notification");
        assert!(notif.is_card_present(0));
        assert!(!notif.has_slot_changed(0));
        assert!(!notif.is_card_present(1));
        assert!(notif.has_slot_changed(1));
    }
}
