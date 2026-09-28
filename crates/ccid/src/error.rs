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

use core::fmt;

/// Detailed reasons for USB physical I/O failures.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CcidIoError {
    /// Connection to the USB device or endpoint was lost.
    ConnectionLost,
    /// USB device was disconnected.
    DeviceDisconnected,
    /// Short Bulk-OUT write.
    ShortWrite {
        /// Expected byte count.
        expected: usize,
        /// Actual transferred byte count.
        transferred: usize,
    },
    /// Bulk-IN read underflow or mock queue exhausted.
    BulkInUnderflow,
    /// Synthetic test harness failure.
    SyntheticFailure,
}

impl fmt::Display for CcidIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionLost => write!(f, "USB CCID connection lost"),
            Self::DeviceDisconnected => write!(f, "USB CCID device disconnected"),
            Self::ShortWrite {
                expected,
                transferred,
            } => {
                write!(
                    f,
                    "short Bulk-OUT write: expected {expected} bytes, transferred {transferred}"
                )
            }
            Self::BulkInUnderflow => write!(f, "Bulk-IN read underflow"),
            Self::SyntheticFailure => write!(f, "synthetic test failure"),
        }
    }
}

/// Specific failure modes when parsing CCID descriptors.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CcidDescriptorError {
    /// Invalid CCID functional descriptor type byte (expected 0x21).
    InvalidFunctionalDescriptorType {
        /// Received descriptor type byte.
        actual: u8,
    },
}

impl fmt::Display for CcidDescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFunctionalDescriptorType { actual } => {
                write!(
                    f,
                    "invalid CCID functional descriptor type: expected {:#04x}, got {actual:#04x}",
                    crate::descriptor::CCID_FUNCTIONAL_DESCRIPTOR_TYPE
                )
            }
        }
    }
}

/// Specific protocol desynchronization failure modes.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CcidProtocolDesync {
    /// Slot encountered an unrecovered error; abort recovery required.
    SlotRecoveryRequired,
    /// Another operation is already pending on the slot.
    OperationAlreadyPending,
    /// CCID parameters response has invalid protocol or length.
    InvalidParametersLength {
        /// Active protocol indicator (0 = T=0, 1 = T=1).
        protocol: u8,
        /// Payload byte length.
        length: usize,
    },
    /// Chain Begin block received while chain is already open.
    ChainBeginAlreadyOpen,
    /// Chain Continue block received without a preceding Begin.
    ChainContinueWithoutBegin,
    /// Chain End block received without a preceding Begin.
    ChainEndWithoutBegin,
    /// Chain Complete block received while chain is already open.
    ChainCompleteWhileOpen,
    /// Unexpected CCID command continuation requested by reader.
    UnexpectedCommandContinuation,
    /// PowerOn operation did not return ATR data.
    PowerOnMissingAtr,
    /// Reset operation did not return ATR data.
    ResetMissingAtr,
    /// Abort operation returned an unexpected outcome.
    UnexpectedAbortOutcome,
    /// CCID engine terminated operation without completing.
    TerminatedWithoutCompletion,
    /// Iteration limit exceeded during 61xx GET RESPONSE chaining.
    ChainingIterationLimitExceeded,
    /// 61xx GET RESPONSE chain exceeded maximum buffer capacity.
    ChainExceededCapacity,
    /// Card signaled 61xx but returned zero payload bytes (stalled chain).
    StalledChain,
    /// Repeated 6Cxx wrong-Le status words encountered during chaining.
    RepeatedWrongLe,
}

impl fmt::Display for CcidProtocolDesync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotRecoveryRequired => write!(f, "slot timed out; abort recovery required"),
            Self::OperationAlreadyPending => write!(f, "another operation is already pending"),
            Self::InvalidParametersLength { protocol, length } => {
                write!(
                    f,
                    "invalid CCID parameters length for protocol {protocol}: {length} bytes"
                )
            }
            Self::ChainBeginAlreadyOpen => {
                write!(f, "Chain Begin received while chain already open")
            }
            Self::ChainContinueWithoutBegin => {
                write!(f, "Chain Continue received without preceding Begin")
            }
            Self::ChainEndWithoutBegin => {
                write!(f, "Chain End received without preceding Begin")
            }
            Self::ChainCompleteWhileOpen => {
                write!(f, "Chain Complete received while chain open")
            }
            Self::UnexpectedCommandContinuation => {
                write!(f, "unexpected CCID command continuation request")
            }
            Self::PowerOnMissingAtr => write!(f, "PowerOn operation did not return ATR data"),
            Self::ResetMissingAtr => write!(f, "Reset did not return ATR data"),
            Self::UnexpectedAbortOutcome => write!(f, "abort returned unexpected outcome"),
            Self::TerminatedWithoutCompletion => {
                write!(f, "CCID engine terminated operation without completion")
            }
            Self::ChainingIterationLimitExceeded => {
                write!(f, "61xx GET RESPONSE chaining iteration limit exceeded")
            }
            Self::ChainExceededCapacity => {
                write!(f, "61xx GET RESPONSE chain exceeded buffer capacity")
            }
            Self::StalledChain => {
                write!(
                    f,
                    "card signalled 61xx but returned no bytes (stalled chain)"
                )
            }
            Self::RepeatedWrongLe => {
                write!(f, "repeated 6Cxx wrong-Le during 61xx chaining")
            }
        }
    }
}

/// Errors arising from CCID operations.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
    Io(CcidIoError),
    /// Protocol or session desynchronization.
    ProtocolDesync(CcidProtocolDesync),
    /// Operation timed out.
    Timeout,
    /// Operation cancelled.
    Cancelled,
    /// Card was removed.
    CardRemoved,
    /// Invalid CCID descriptor structure or field.
    InvalidCcidDescriptor(CcidDescriptorError),
    /// APDU payload exceeds maximum buffer length supported by reader.
    ApduTooLong,
    /// Smart card protocol is unsupported by the exchange level.
    UnsupportedProtocol,
    /// Card Answer to Reset (ATR) is invalid.
    Atr(refineid_atr::AtrError),
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
            Self::Io(err) => write!(f, "CCID USB I/O failure: {err}"),
            Self::ProtocolDesync(err) => write!(f, "CCID protocol desync: {err}"),
            Self::Timeout => write!(f, "CCID operation timed out"),
            Self::Cancelled => write!(f, "CCID operation cancelled"),
            Self::CardRemoved => write!(f, "Smart card was removed from reader"),
            Self::InvalidCcidDescriptor(err) => write!(f, "Invalid CCID descriptor: {err}"),
            Self::ApduTooLong => {
                write!(
                    f,
                    "APDU payload exceeds maximum buffer length supported by reader"
                )
            }
            Self::UnsupportedProtocol => {
                write!(f, "Card protocol is unsupported by CCID exchange level")
            }
            Self::Atr(e) => write!(f, "Invalid ATR: {e}"),
        }
    }
}

impl core::error::Error for CcidError {}

impl From<refineid_atr::AtrError> for CcidError {
    fn from(e: refineid_atr::AtrError) -> Self {
        Self::Atr(e)
    }
}

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
