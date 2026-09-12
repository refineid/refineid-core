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

//! Error types for CCID descriptor parsing, wire codec, and state machine operations.

use alloc::string::String;
use core::fmt;

/// Errors arising from CCID operations.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CcidError {
    /// Descriptor header was truncated.
    TruncatedDescriptorHeader,
    /// Descriptor declared length was less than minimum header size.
    InvalidDescriptorLength,
    /// Descriptor declared length exceeds the buffer length.
    TruncatedDescriptor,
    /// USB interface descriptor was shorter than the standard 9 bytes.
    InvalidInterfaceDescriptor,
    /// CCID functional descriptor (type 0x21) was not found for target interface.
    MissingCcidDescriptor,
    /// CCID functional descriptor was shorter than 54 bytes.
    CcidDescriptorTooShort,
    /// Unsupported exchange level (e.g. character-level exchange).
    UnsupportedExchangeLevel,
    /// Invalid or multiple exchange level bits set.
    InvalidExchangeLevel,
    /// Conflicting automatic parameter negotiation flags.
    InvalidApduConfiguration,
    /// Declared message length exceeds the maximum CCID specification bound.
    MessageLengthOutOfRange,
    /// Declared message length cannot carry even one transfer block.
    TransferMessageBoundTooSmall,
    /// CCID response header was shorter than 10 bytes.
    TruncatedHeader,
    /// Declared response payload length exceeds maximum.
    ResponseLengthOutOfRange,
    /// Declared response length does not match actual received frame length.
    LengthMismatch,
    /// Response message type does not match expected response type.
    UnexpectedMessageType {
        /// Expected CCID response message type.
        expected: u8,
        /// Received CCID response message type.
        actual: u8,
    },
    /// Response slot number does not match command slot.
    UnexpectedSlot {
        /// Expected slot.
        expected: u8,
        /// Received slot.
        actual: u8,
    },
    /// Response sequence number does not match command sequence.
    UnexpectedSequence {
        /// Expected sequence.
        expected: u8,
        /// Received sequence.
        actual: u8,
    },
    /// Reserved bits in status byte are non-zero.
    ReservedStatusBits,
    /// Reserved card status bits in status byte.
    ReservedCardStatus,
    /// Reserved command status bits in status byte.
    ReservedCommandStatus,
    /// Slot status response contained an unexpected payload.
    UnexpectedPayload,
    /// Invalid clock status in response parameter byte.
    InvalidClockStatus,
    /// Invalid chain parameter in response parameter byte.
    InvalidChainParameter,
    /// Command failure reported by reader firmware.
    CommandFailed {
        /// Signed 8-bit error code from CCID response.
        error_code: i8,
    },
    /// Time extension requested by reader firmware.
    TimeExtension {
        /// Waiting time multiplier.
        multiplier: u8,
    },
    /// Physical USB I/O failure.
    Io(String),
    /// Protocol or session desynchronization.
    ProtocolDesync(String),
    /// Operation timed out.
    Timeout,
    /// Operation cancelled.
    Cancelled,
    /// Card was removed.
    CardRemoved,
}

impl fmt::Display for CcidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedDescriptorHeader => write!(f, "USB descriptor header is truncated"),
            Self::InvalidDescriptorLength => write!(f, "USB descriptor length is invalid"),
            Self::TruncatedDescriptor => write!(f, "USB descriptor exceeds received byte count"),
            Self::InvalidInterfaceDescriptor => write!(f, "USB interface descriptor is too short"),
            Self::MissingCcidDescriptor => write!(f, "CCID functional descriptor was not found"),
            Self::CcidDescriptorTooShort => write!(f, "CCID functional descriptor is too short"),
            Self::UnsupportedExchangeLevel => write!(f, "CCID exchange level is not supported"),
            Self::InvalidExchangeLevel => write!(f, "CCID declares multiple exchange levels"),
            Self::InvalidApduConfiguration => {
                write!(f, "CCID declares conflicting automatic parameter handling")
            }
            Self::MessageLengthOutOfRange => {
                write!(f, "CCID maximum message length exceeds specification bound")
            }
            Self::TransferMessageBoundTooSmall => {
                write!(
                    f,
                    "CCID maximum message length cannot carry one transfer block"
                )
            }
            Self::TruncatedHeader => write!(f, "CCID response header is truncated"),
            Self::ResponseLengthOutOfRange => {
                write!(f, "CCID response length exceeds specification maximum")
            }
            Self::LengthMismatch => {
                write!(f, "CCID response length does not match received byte count")
            }
            Self::UnexpectedMessageType { expected, actual } => {
                write!(
                    f,
                    "CCID response type mismatch: expected {expected:#04x}, got {actual:#04x}"
                )
            }
            Self::UnexpectedSlot { expected, actual } => {
                write!(
                    f,
                    "CCID response slot mismatch: expected {expected}, got {actual}"
                )
            }
            Self::UnexpectedSequence { expected, actual } => {
                write!(
                    f,
                    "CCID response sequence mismatch: expected {expected}, got {actual}"
                )
            }
            Self::ReservedStatusBits => write!(f, "CCID response sets reserved status bits"),
            Self::ReservedCardStatus => write!(f, "CCID response uses reserved card status"),
            Self::ReservedCommandStatus => write!(f, "CCID response uses reserved command status"),
            Self::UnexpectedPayload => {
                write!(f, "CCID slot-status response contains unexpected payload")
            }
            Self::InvalidClockStatus => write!(f, "CCID response uses undefined clock status"),
            Self::InvalidChainParameter => {
                write!(f, "CCID response uses undefined chain parameter")
            }
            Self::CommandFailed { error_code } => {
                write!(f, "CCID command failed with error code {error_code}")
            }
            Self::TimeExtension { multiplier } => {
                write!(f, "CCID time extension requested: {multiplier}")
            }
            Self::Io(msg) => write!(f, "CCID USB I/O failure: {msg}"),
            Self::ProtocolDesync(msg) => write!(f, "CCID protocol desync: {msg}"),
            Self::Timeout => write!(f, "CCID operation timed out"),
            Self::Cancelled => write!(f, "CCID operation cancelled"),
            Self::CardRemoved => write!(f, "Smart card was removed from reader"),
        }
    }
}

impl core::error::Error for CcidError {}

impl refineid_apdu::TransportErrorExt for CcidError {
    fn kind(&self) -> refineid_apdu::TransportErrorKind {
        match self {
            Self::CardRemoved => refineid_apdu::TransportErrorKind::NoCard,
            Self::Timeout => refineid_apdu::TransportErrorKind::TimeoutUnknownState,
            Self::ProtocolDesync(_) => refineid_apdu::TransportErrorKind::ProtocolDesync,
            _ => refineid_apdu::TransportErrorKind::Backend,
        }
    }
}
