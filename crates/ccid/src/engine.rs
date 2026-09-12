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

//! Pure deterministic CCID state machine engine.
//!
//! Separated completely from physical I/O, threads, and OS handles.
//! Accepts explicit events and monotonic time, returning discrete actions and deadlines.

use crate::codec::{
    CCID_HEADER_SIZE, RDR_TO_PC_DATA_BLOCK, RDR_TO_PC_PARAMETERS, RDR_TO_PC_SLOT_STATUS,
    decode_interrupt_slot_change, decode_response, encode_abort, encode_get_parameters,
    encode_get_slot_status, encode_icc_power_off, encode_icc_power_on, encode_set_parameters_t0,
    encode_xfr_block,
};
use crate::descriptor::{CcidExchangeLevel, CcidFunctionalDescriptor};
use crate::error::CcidError;
use alloc::vec::Vec;

/// Opaque identifier for a logical operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationId(pub u64);

/// Opaque identifier for a deadline timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeadlineId(pub u64);

/// Monotonic timestamp in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct MonotonicTime(pub u64);

/// Explicit deadline specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    /// Timer identifier.
    pub id: DeadlineId,
    /// Absolute monotonic expiration timestamp.
    pub expires_at: MonotonicTime,
}

/// Logical operation requested by the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Cold or warm reset / power on the card slot.
    PowerOn {
        /// Voltage selection (0 = automatic).
        voltage: u8,
    },
    /// Cut power to the card slot.
    PowerOff,
    /// Query card presence and slot status.
    GetSlotStatus,
    /// Read active slot parameters (T=0 / T=1 parameters).
    GetParameters,
    /// Configure T=0 parameters.
    SetParametersT0 {
        /// Fi/Di transmission factor.
        fi_di: u8,
        /// Guard time.
        guard_time: u8,
        /// Waiting integer.
        waiting_integer: u8,
        /// Clock stop parameter.
        clock_stop: u8,
        /// Inverse convention indicator.
        inverse_convention: bool,
    },
    /// Transfer an APDU or TPDU block to the card.
    TransferBlock {
        /// Waiting integer / block waiting integer.
        b_wi: u8,
        /// Level parameter.
        w_level_parameter: u16,
        /// Command payload bytes.
        data: Vec<u8>,
    },
    /// Abort an ongoing or stalled command.
    Abort,
}

/// Outcome of a completed logical operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationResult {
    /// Power on succeeded, returning ATR bytes.
    PowerOn(Vec<u8>),
    /// Power off succeeded.
    PowerOff,
    /// Slot status retrieved.
    SlotStatus {
        /// Card status (active, inactive, not present).
        card_present: bool,
    },
    /// Active parameters retrieved.
    Parameters(Vec<u8>),
    /// Set parameters succeeded.
    ParametersSet,
    /// Transfer block succeeded, returning response payload (R-APDU).
    TransferBlock(Vec<u8>),
    /// Abort completed.
    Aborted,
}

/// I/O completion report from the platform USB executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoCompletion {
    /// Bulk-IN read completed with received bytes.
    BulkIn(Vec<u8>),
    /// Bulk-OUT write completed with transferred byte count.
    BulkOut {
        /// Number of bytes actually transferred.
        transferred: usize,
    },
    /// Control transfer completed.
    Control,
    /// Hardware I/O failed.
    Failure(CcidError),
}

/// Input event presented to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputEvent {
    /// Start a new logical operation.
    Start {
        /// Operation identifier.
        id: OperationId,
        /// Operation to perform.
        op: Operation,
    },
    /// Low-level USB transfer completion.
    IoCompleted(IoCompletion),
    /// Interrupt-IN packet received from reader.
    InterruptReceived(Vec<u8>),
    /// Deadline expired.
    DeadlineExpired(DeadlineId),
    /// Cancel a running operation.
    Cancel(OperationId),
    /// USB device connection was lost or disconnected.
    ConnectionLost,
}

/// Discrete action produced by the state machine for the platform executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Submit raw bytes to Bulk-OUT endpoint.
    SubmitBulkOut {
        /// Sequence number for correlation.
        seq: u8,
        /// Message packet.
        data: Vec<u8>,
    },
    /// Submit read to Bulk-IN endpoint.
    SubmitBulkIn {
        /// Buffer capacity needed.
        buffer_size: usize,
    },
    /// Submit a standard USB Control transfer (e.g. for CCID ABORT §5.3.1).
    SubmitControl {
        /// bmRequestType
        request_type: u8,
        /// bRequest
        request: u8,
        /// wValue
        value: u16,
        /// wIndex (interface number)
        index: u16,
        /// Control payload data.
        data: Vec<u8>,
    },
    /// Complete a logical operation.
    Complete {
        /// Operation identifier.
        id: OperationId,
        /// Result or error.
        result: Result<OperationResult, CcidError>,
    },
    /// Publish card presence change to application.
    PublishSlotChange {
        /// Card slot number.
        slot: u8,
        /// Whether card is present.
        card_present: bool,
        /// Incrementing card generation counter.
        card_gen: u64,
    },
    /// Cancel active USB transfers.
    CancelTransfers,
}

/// Complete output transition from an engine step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    /// Ordered actions to execute.
    pub actions: Vec<Action>,
    /// Optional next deadline to arm.
    pub next_deadline: Option<Deadline>,
}

impl Transition {
    /// Construct a transition with a single action.
    #[must_use]
    pub fn single(action: Action) -> Self {
        Self {
            actions: alloc::vec![action],
            next_deadline: None,
        }
    }

    /// Construct an empty transition.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            actions: Vec::new(),
            next_deadline: None,
        }
    }
}

/// Pure deterministic CCID protocol engine for a single CCID slot.
#[derive(Debug)]
pub struct CcidEngine {
    /// Hardware interface index.
    pub interface_number: u8,
    /// Physical CCID slot index (`bSlot`).
    pub b_slot: u8,
    /// Monotonically increasing card generation (bumped on card removal/replacement).
    pub card_gen: u64,
    /// Monotonically increasing connection generation.
    pub connection_gen: u64,
    /// Next CCID sequence number (0..=255).
    pub next_seq: u8,
    /// Whether a card is currently physically present in the slot.
    pub card_present: bool,
    /// Whether the card has completed ATR power-on activation.
    pub activated: bool,
    /// Whether the underlying USB CCID device connection is alive.
    pub connected: bool,
    /// Whether a timeout or desync occurred requiring slot abort recovery.
    pub needs_recovery: bool,
    /// Negotiated exchange level from descriptor.
    pub exchange_level: CcidExchangeLevel,
    /// Maximum CCID message length.
    pub max_message_length: usize,
    /// Maximum slot index for multi-slot notifications.
    pub max_slot_index: u8,

    // Internal state tracking
    pending_op: Option<(OperationId, Operation)>,
    expected_response_type: u8,
    expected_seq: u8,
    expected_bulk_out_len: usize,
    active_deadline_id: u64,
    current_deadline: Option<Deadline>,
    default_timeout_ms: u64,
    chain_buffer: Vec<u8>,
}

impl CcidEngine {
    /// Create a new CCID engine instance from a validated functional descriptor.
    #[must_use]
    pub fn new(
        interface_number: u8,
        b_slot: u8,
        connection_gen: u64,
        descriptor: &CcidFunctionalDescriptor,
    ) -> Self {
        Self {
            interface_number,
            b_slot,
            card_gen: 1,
            connection_gen,
            next_seq: 0,
            card_present: false,
            activated: false,
            connected: true,
            needs_recovery: false,
            exchange_level: descriptor.exchange_level,
            max_message_length: descriptor.maximum_message_length,
            max_slot_index: descriptor.max_slot_index,
            pending_op: None,
            expected_response_type: 0,
            expected_seq: 0,
            expected_bulk_out_len: 0,
            active_deadline_id: 0,
            current_deadline: None,
            default_timeout_ms: 5000,
            chain_buffer: Vec::new(),
        }
    }

    /// Allocate the next sequence number.
    fn allocate_seq(&mut self) -> u8 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    /// Primary state transition driver.
    pub fn step(&mut self, now: MonotonicTime, event: InputEvent) -> Transition {
        let mut actions = Vec::new();
        let mut next_deadline = None;

        match event {
            InputEvent::InterruptReceived(raw_bytes) => {
                if let Ok(notification) =
                    decode_interrupt_slot_change(&raw_bytes, self.max_slot_index)
                {
                    let present = notification.is_card_present(self.b_slot);
                    let changed = notification.has_slot_changed(self.b_slot);

                    if changed || present != self.card_present {
                        self.card_present = present;
                        self.card_gen = self.card_gen.wrapping_add(1);

                        if changed || !present {
                            self.activated = false;
                            if let Some((op_id, _)) = self.pending_op.take() {
                                self.current_deadline = None;
                                actions.push(Action::CancelTransfers);
                                actions.push(Action::Complete {
                                    id: op_id,
                                    result: Err(CcidError::CardRemoved),
                                });
                            }
                        }

                        actions.push(Action::PublishSlotChange {
                            slot: self.b_slot,
                            card_present: present,
                            card_gen: self.card_gen,
                        });
                    }
                }
            }

            InputEvent::Start { id, op } => {
                if !self.connected {
                    actions.push(Action::Complete {
                        id,
                        result: Err(CcidError::Io("USB CCID connection lost".into())),
                    });
                    return Transition {
                        actions,
                        next_deadline: None,
                    };
                }

                if self.needs_recovery && !matches!(op, Operation::Abort) {
                    actions.push(Action::Complete {
                        id,
                        result: Err(CcidError::ProtocolDesync(
                            "slot timed out; abort recovery required".into(),
                        )),
                    });
                    return Transition {
                        actions,
                        next_deadline: None,
                    };
                }

                if self.pending_op.is_some() {
                    actions.push(Action::Complete {
                        id,
                        result: Err(CcidError::ProtocolDesync(
                            "another operation is already pending".into(),
                        )),
                    });
                    return Transition {
                        actions,
                        next_deadline: None,
                    };
                }

                if let Operation::TransferBlock { ref data, .. } = op
                    && data.len() > self.max_message_length
                {
                    actions.push(Action::Complete {
                        id,
                        result: Err(CcidError::ApduTooLong(data.len())),
                    });
                    return Transition {
                        actions,
                        next_deadline: None,
                    };
                }

                if matches!(op, Operation::Abort) {
                    self.needs_recovery = false;
                }

                self.chain_buffer.clear();
                let seq = self.allocate_seq();
                self.expected_seq = seq;
                self.pending_op = Some((id, op.clone()));

                let (encoded, expected_resp) = match op {
                    Operation::PowerOn { voltage } => (
                        encode_icc_power_on(self.b_slot, seq, voltage).to_vec(),
                        RDR_TO_PC_DATA_BLOCK,
                    ),
                    Operation::PowerOff => (
                        encode_icc_power_off(self.b_slot, seq).to_vec(),
                        RDR_TO_PC_SLOT_STATUS,
                    ),
                    Operation::GetSlotStatus => (
                        encode_get_slot_status(self.b_slot, seq).to_vec(),
                        RDR_TO_PC_SLOT_STATUS,
                    ),
                    Operation::GetParameters => (
                        encode_get_parameters(self.b_slot, seq).to_vec(),
                        RDR_TO_PC_PARAMETERS,
                    ),
                    Operation::SetParametersT0 {
                        fi_di,
                        guard_time,
                        waiting_integer,
                        clock_stop,
                        inverse_convention,
                    } => (
                        encode_set_parameters_t0(
                            self.b_slot,
                            seq,
                            fi_di,
                            guard_time,
                            waiting_integer,
                            clock_stop,
                            inverse_convention,
                        )
                        .to_vec(),
                        RDR_TO_PC_PARAMETERS,
                    ),
                    Operation::TransferBlock {
                        b_wi,
                        w_level_parameter,
                        data,
                    } => (
                        encode_xfr_block(self.b_slot, seq, b_wi, w_level_parameter, &data),
                        RDR_TO_PC_DATA_BLOCK,
                    ),
                    Operation::Abort => (
                        encode_abort(self.b_slot, seq).to_vec(),
                        RDR_TO_PC_SLOT_STATUS,
                    ),
                };

                self.expected_response_type = expected_resp;
                self.expected_bulk_out_len = encoded.len();

                self.active_deadline_id = self.active_deadline_id.wrapping_add(1);
                let dl = Deadline {
                    id: DeadlineId(self.active_deadline_id),
                    expires_at: MonotonicTime(now.0 + self.default_timeout_ms),
                };
                self.current_deadline = Some(dl);
                next_deadline = Some(dl);

                actions.push(Action::SubmitBulkOut { seq, data: encoded });
            }

            InputEvent::IoCompleted(IoCompletion::BulkOut { transferred }) => {
                if transferred != self.expected_bulk_out_len {
                    if let Some((op_id, _)) = self.pending_op.take() {
                        self.current_deadline = None;
                        actions.push(Action::CancelTransfers);
                        actions.push(Action::Complete {
                            id: op_id,
                            result: Err(CcidError::Io("short Bulk-OUT write".into())),
                        });
                    }
                } else {
                    actions.push(Action::SubmitBulkIn {
                        buffer_size: self.max_message_length.max(CCID_HEADER_SIZE),
                    });
                }
            }

            InputEvent::IoCompleted(IoCompletion::BulkIn(frame)) => {
                if let Some((op_id, op)) = self.pending_op.take() {
                    match decode_response(
                        &frame,
                        self.expected_response_type,
                        self.b_slot,
                        self.expected_seq,
                    ) {
                        Ok(crate::codec::CcidResponse::TimeExtension { multiplier, .. }) => {
                            self.pending_op = Some((op_id, op));
                            let extension_ms = (multiplier as u64) * 1000;
                            self.active_deadline_id = self.active_deadline_id.wrapping_add(1);
                            let dl = Deadline {
                                id: DeadlineId(self.active_deadline_id),
                                expires_at: MonotonicTime(now.0 + extension_ms),
                            };
                            self.current_deadline = Some(dl);
                            next_deadline = Some(dl);
                            actions.push(Action::SubmitBulkIn {
                                buffer_size: self.max_message_length.max(CCID_HEADER_SIZE),
                            });
                        }
                        Ok(crate::codec::CcidResponse::DataBlock {
                            card_status,
                            chain_parameter,
                            payload,
                        }) => {
                            if card_status == crate::codec::CardStatus::NotPresent {
                                self.card_present = false;
                                self.activated = false;
                                self.card_gen = self.card_gen.wrapping_add(1);
                                self.current_deadline = None;
                                actions.push(Action::Complete {
                                    id: op_id,
                                    result: Err(CcidError::CardRemoved),
                                });
                            } else {
                                match chain_parameter {
                                    crate::codec::ChainParameter::Begin
                                    | crate::codec::ChainParameter::Continue => {
                                        self.chain_buffer.extend_from_slice(&payload);
                                        self.pending_op = Some((op_id, op));
                                        actions.push(Action::SubmitBulkIn {
                                            buffer_size: self
                                                .max_message_length
                                                .max(CCID_HEADER_SIZE),
                                        });
                                    }
                                    crate::codec::ChainParameter::End
                                    | crate::codec::ChainParameter::Complete => {
                                        let mut combined = core::mem::take(&mut self.chain_buffer);
                                        combined.extend_from_slice(&payload);
                                        let result = match op {
                                            Operation::PowerOn { .. } => {
                                                self.activated = true;
                                                self.card_present = true;
                                                Ok(OperationResult::PowerOn(combined))
                                            }
                                            Operation::TransferBlock { .. } => {
                                                Ok(OperationResult::TransferBlock(combined))
                                            }
                                            _ => Ok(OperationResult::PowerOn(combined)),
                                        };
                                        self.current_deadline = None;
                                        actions.push(Action::Complete { id: op_id, result });
                                    }
                                    crate::codec::ChainParameter::CommandContinuationExpected => {
                                        self.current_deadline = None;
                                        actions.push(Action::Complete {
                                            id: op_id,
                                            result: Err(CcidError::ProtocolDesync(
                                                "unexpected CCID command continuation request"
                                                    .into(),
                                            )),
                                        });
                                    }
                                }
                            }
                        }
                        Ok(crate::codec::CcidResponse::SlotStatus { card_status, .. }) => {
                            let present = card_status == crate::codec::CardStatus::Active
                                || card_status == crate::codec::CardStatus::Inactive;
                            if !present && self.card_present {
                                self.activated = false;
                                self.card_gen = self.card_gen.wrapping_add(1);
                            }
                            self.card_present = present;
                            self.current_deadline = None;
                            let result = match op {
                                Operation::PowerOff => {
                                    self.activated = false;
                                    Ok(OperationResult::PowerOff)
                                }
                                Operation::Abort => Ok(OperationResult::Aborted),
                                _ => Ok(OperationResult::SlotStatus {
                                    card_present: present,
                                }),
                            };
                            actions.push(Action::Complete { id: op_id, result });
                        }
                        Ok(crate::codec::CcidResponse::Parameters {
                            card_status,
                            payload,
                            ..
                        }) => {
                            if card_status == crate::codec::CardStatus::NotPresent {
                                self.card_present = false;
                                self.activated = false;
                                self.card_gen = self.card_gen.wrapping_add(1);
                            }
                            self.current_deadline = None;
                            let result = match op {
                                Operation::SetParametersT0 { .. } => {
                                    Ok(OperationResult::ParametersSet)
                                }
                                _ => Ok(OperationResult::Parameters(payload)),
                            };
                            actions.push(Action::Complete { id: op_id, result });
                        }
                        Ok(crate::codec::CcidResponse::CommandFailure {
                            card_status,
                            error_code,
                        }) => {
                            if card_status == crate::codec::CardStatus::NotPresent {
                                self.card_present = false;
                                self.activated = false;
                                self.card_gen = self.card_gen.wrapping_add(1);
                            }
                            self.current_deadline = None;
                            actions.push(Action::Complete {
                                id: op_id,
                                result: Err(CcidError::CommandFailed { error_code }),
                            });
                        }
                        Err(e) => {
                            self.current_deadline = None;
                            actions.push(Action::Complete {
                                id: op_id,
                                result: Err(e),
                            });
                        }
                    }
                }
            }

            InputEvent::IoCompleted(IoCompletion::Control) => {}

            InputEvent::IoCompleted(IoCompletion::Failure(e)) => {
                if let Some((op_id, _)) = self.pending_op.take() {
                    self.current_deadline = None;
                    actions.push(Action::Complete {
                        id: op_id,
                        result: Err(e),
                    });
                }
            }

            InputEvent::DeadlineExpired(id) => {
                if let Some(dl) = self.current_deadline
                    && dl.id == id
                    && now.0 >= dl.expires_at.0
                    && let Some((op_id, _)) = self.pending_op.take()
                {
                    self.needs_recovery = true;
                    self.current_deadline = None;
                    actions.push(Action::CancelTransfers);
                    actions.push(Action::Complete {
                        id: op_id,
                        result: Err(CcidError::Timeout),
                    });
                }
            }

            InputEvent::Cancel(op_id) => {
                if self.pending_op.as_ref().is_some_and(|(id, _)| *id == op_id) {
                    self.pending_op = None;
                    self.current_deadline = None;
                    actions.push(Action::CancelTransfers);
                    actions.push(Action::Complete {
                        id: op_id,
                        result: Err(CcidError::Cancelled),
                    });
                }
            }

            InputEvent::ConnectionLost => {
                self.connected = false;
                self.card_present = false;
                self.activated = false;
                self.current_deadline = None;
                if let Some((op_id, _)) = self.pending_op.take() {
                    actions.push(Action::Complete {
                        id: op_id,
                        result: Err(CcidError::Io("device disconnected".into())),
                    });
                }
            }
        }

        if next_deadline.is_none() && self.pending_op.is_some() {
            next_deadline = self.current_deadline;
        }

        Transition {
            actions,
            next_deadline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{
        CARD_STATUS_ACTIVE, CHAIN_COMPLETE, COMMAND_STATUS_TIME_EXTENSION,
        RDR_TO_PC_NOTIFY_SLOT_CHANGE,
    };
    use crate::descriptor::{AUTOMATIC_ACTIVATION, SHORT_APDU_EXCHANGE};

    fn make_test_descriptor() -> CcidFunctionalDescriptor {
        CcidFunctionalDescriptor {
            exchange_level: CcidExchangeLevel::ShortApdu,
            maximum_message_length: 271,
            max_slot_index: 0,
            features: SHORT_APDU_EXCHANGE | AUTOMATIC_ACTIVATION,
            protocols: 3,
        }
    }

    fn make_test_data_block_response(seq: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.push(RDR_TO_PC_DATA_BLOCK);
        f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        f.push(0); // slot
        f.push(seq);
        f.push(CARD_STATUS_ACTIVE);
        f.push(0); // error
        f.push(CHAIN_COMPLETE);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn power_on_success_lifecycle() {
        let desc = make_test_descriptor();
        let mut engine = CcidEngine::new(0, 0, 1, &desc);
        assert!(!engine.card_present);
        assert!(!engine.activated);

        let op_id = OperationId(1);
        let t1 = engine.step(
            MonotonicTime(100),
            InputEvent::Start {
                id: op_id,
                op: Operation::PowerOn { voltage: 0 },
            },
        );

        assert_eq!(t1.actions.len(), 1);
        assert!(matches!(
            t1.actions[0],
            Action::SubmitBulkOut { seq: 0, .. }
        ));
        assert!(t1.next_deadline.is_some());

        let t_out = engine.step(
            MonotonicTime(110),
            InputEvent::IoCompleted(IoCompletion::BulkOut { transferred: 10 }),
        );
        assert_eq!(t_out.actions.len(), 1);
        assert!(matches!(t_out.actions[0], Action::SubmitBulkIn { .. }));

        let atr = [0x3B, 0x80, 0x00];
        let resp_bytes = make_test_data_block_response(0, &atr);

        let t2 = engine.step(
            MonotonicTime(120),
            InputEvent::IoCompleted(IoCompletion::BulkIn(resp_bytes)),
        );

        assert_eq!(t2.actions.len(), 1);
        match &t2.actions[0] {
            Action::Complete { id, result } => {
                assert_eq!(*id, op_id);
                assert_eq!(result, &Ok(OperationResult::PowerOn(atr.to_vec())));
            }
            _ => panic!("expected Complete action"),
        }

        assert!(engine.card_present);
        assert!(engine.activated);
    }

    #[test]
    fn transfer_block_success() {
        let desc = make_test_descriptor();
        let mut engine = CcidEngine::new(0, 0, 1, &desc);

        let op_id = OperationId(2);
        let apdu = [0x00, 0xA4, 0x04, 0x00, 0x00];
        let _ = engine.step(
            MonotonicTime(200),
            InputEvent::Start {
                id: op_id,
                op: Operation::TransferBlock {
                    b_wi: 0,
                    w_level_parameter: 0,
                    data: apdu.to_vec(),
                },
            },
        );

        let rapdu = [0x90, 0x00];
        let resp_bytes = make_test_data_block_response(0, &rapdu);

        let t_out = engine.step(
            MonotonicTime(210),
            InputEvent::IoCompleted(IoCompletion::BulkOut { transferred: 15 }),
        );
        assert_eq!(t_out.actions.len(), 1);
        assert!(matches!(t_out.actions[0], Action::SubmitBulkIn { .. }));

        let t = engine.step(
            MonotonicTime(220),
            InputEvent::IoCompleted(IoCompletion::BulkIn(resp_bytes)),
        );

        assert_eq!(t.actions.len(), 1);
        match &t.actions[0] {
            Action::Complete { id, result } => {
                assert_eq!(*id, op_id);
                assert_eq!(result, &Ok(OperationResult::TransferBlock(rapdu.to_vec())));
            }
            _ => panic!("expected Complete action"),
        }
    }

    #[test]
    fn time_extension_rearms_deadline_and_submits_bulkin() {
        let desc = make_test_descriptor();
        let mut engine = CcidEngine::new(0, 0, 1, &desc);

        let op_id = OperationId(3);
        let _ = engine.step(
            MonotonicTime(300),
            InputEvent::Start {
                id: op_id,
                op: Operation::TransferBlock {
                    b_wi: 0,
                    w_level_parameter: 0,
                    data: vec![0x00, 0x84, 0x00, 0x00, 0x08],
                },
            },
        );

        let _ = engine.step(
            MonotonicTime(310),
            InputEvent::IoCompleted(IoCompletion::BulkOut { transferred: 15 }),
        );

        // Frame reporting time extension: multiplier = 3
        let mut time_ext_frame = Vec::new();
        time_ext_frame.push(RDR_TO_PC_DATA_BLOCK);
        time_ext_frame.extend_from_slice(&0_u32.to_le_bytes());
        time_ext_frame.push(0); // slot
        time_ext_frame.push(0); // seq
        time_ext_frame.push((COMMAND_STATUS_TIME_EXTENSION << 6) | CARD_STATUS_ACTIVE);
        time_ext_frame.push(3); // multiplier
        time_ext_frame.push(0);

        let t1 = engine.step(
            MonotonicTime(350),
            InputEvent::IoCompleted(IoCompletion::BulkIn(time_ext_frame)),
        );

        // Should produce a new SubmitBulkIn and extended deadline (3000ms from 350 = 3350)
        assert_eq!(t1.actions.len(), 1);
        assert!(matches!(t1.actions[0], Action::SubmitBulkIn { .. }));
        assert_eq!(t1.next_deadline.expect("new deadline").expires_at.0, 3350);

        // Then real data block arrives
        let rapdu = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x90, 0x00];
        let resp_bytes = make_test_data_block_response(0, &rapdu);

        let t2 = engine.step(
            MonotonicTime(400),
            InputEvent::IoCompleted(IoCompletion::BulkIn(resp_bytes)),
        );

        assert_eq!(t2.actions.len(), 1);
        match &t2.actions[0] {
            Action::Complete { id, result } => {
                assert_eq!(*id, op_id);
                assert_eq!(result, &Ok(OperationResult::TransferBlock(rapdu.to_vec())));
            }
            _ => panic!("expected Complete action"),
        }
    }

    #[test]
    fn interrupt_card_removal_during_pending_op_causes_immediate_revocation() {
        let desc = make_test_descriptor();
        let mut engine = CcidEngine::new(0, 0, 1, &desc);
        engine.card_present = true;
        engine.activated = true;
        let initial_gen = engine.card_gen;

        let op_id = OperationId(4);
        let _ = engine.step(
            MonotonicTime(500),
            InputEvent::Start {
                id: op_id,
                op: Operation::TransferBlock {
                    b_wi: 0,
                    w_level_parameter: 0,
                    data: vec![0x00, 0x20, 0x00, 0x80],
                },
            },
        );

        // Slot 0: not present (0), changed (1) -> 0x02
        let interrupt = [RDR_TO_PC_NOTIFY_SLOT_CHANGE, 0x02];
        let t = engine.step(
            MonotonicTime(510),
            InputEvent::InterruptReceived(interrupt.to_vec()),
        );

        assert!(!engine.card_present);
        assert!(!engine.activated);
        assert_eq!(engine.card_gen, initial_gen + 1);

        // Operation immediately completed with CardRemoved and slot change published
        assert_eq!(t.actions.len(), 3);
        assert_eq!(t.actions[0], Action::CancelTransfers);
        match &t.actions[1] {
            Action::Complete { id, result } => {
                assert_eq!(*id, op_id);
                assert_eq!(result, &Err(CcidError::CardRemoved));
            }
            _ => panic!("expected Complete action"),
        }
        match &t.actions[2] {
            Action::PublishSlotChange {
                card_present,
                card_gen,
                ..
            } => {
                assert!(!card_present);
                assert_eq!(*card_gen, initial_gen + 1);
            }
            _ => panic!("expected PublishSlotChange action"),
        }
    }

    #[test]
    fn reject_concurrent_operation() {
        let desc = make_test_descriptor();
        let mut engine = CcidEngine::new(0, 0, 1, &desc);

        let op1 = OperationId(10);
        let _ = engine.step(
            MonotonicTime(600),
            InputEvent::Start {
                id: op1,
                op: Operation::PowerOn { voltage: 0 },
            },
        );

        let op2 = OperationId(11);
        let t = engine.step(
            MonotonicTime(610),
            InputEvent::Start {
                id: op2,
                op: Operation::GetSlotStatus,
            },
        );

        assert_eq!(t.actions.len(), 1);
        match &t.actions[0] {
            Action::Complete { id, result } => {
                assert_eq!(*id, op2);
                assert!(matches!(result, Err(CcidError::ProtocolDesync(_))));
            }
            _ => panic!("expected Complete action"),
        }
    }

    #[test]
    fn deadline_expiration_cancels_transfers_and_aborts_op() {
        let desc = make_test_descriptor();
        let mut engine = CcidEngine::new(0, 0, 1, &desc);

        let op_id = OperationId(20);
        let t1 = engine.step(
            MonotonicTime(700),
            InputEvent::Start {
                id: op_id,
                op: Operation::GetSlotStatus,
            },
        );

        let deadline_id = t1.next_deadline.expect("deadline armed").id;

        let t2 = engine.step(
            MonotonicTime(5701),
            InputEvent::DeadlineExpired(deadline_id),
        );

        assert_eq!(t2.actions.len(), 2);
        assert_eq!(t2.actions[0], Action::CancelTransfers);
        match &t2.actions[1] {
            Action::Complete { id, result } => {
                assert_eq!(*id, op_id);
                assert_eq!(result, &Err(CcidError::Timeout));
            }
            _ => panic!("expected Complete action"),
        }
    }

    #[test]
    fn cancel_event_aborts_operation() {
        let desc = make_test_descriptor();
        let mut engine = CcidEngine::new(0, 0, 1, &desc);

        let op_id = OperationId(30);
        let _ = engine.step(
            MonotonicTime(800),
            InputEvent::Start {
                id: op_id,
                op: Operation::GetSlotStatus,
            },
        );

        let t = engine.step(MonotonicTime(850), InputEvent::Cancel(op_id));

        assert_eq!(t.actions.len(), 2);
        assert_eq!(t.actions[0], Action::CancelTransfers);
        match &t.actions[1] {
            Action::Complete { id, result } => {
                assert_eq!(*id, op_id);
                assert_eq!(result, &Err(CcidError::Cancelled));
            }
            _ => panic!("expected Complete action"),
        }
    }

    #[test]
    fn connection_lost_clears_state_and_aborts_op() {
        let desc = make_test_descriptor();
        let mut engine = CcidEngine::new(0, 0, 1, &desc);
        engine.card_present = true;
        engine.activated = true;

        let op_id = OperationId(40);
        let _ = engine.step(
            MonotonicTime(900),
            InputEvent::Start {
                id: op_id,
                op: Operation::PowerOff,
            },
        );

        let t = engine.step(MonotonicTime(910), InputEvent::ConnectionLost);

        assert!(!engine.card_present);
        assert!(!engine.activated);
        assert_eq!(t.actions.len(), 1);
        match &t.actions[0] {
            Action::Complete { id, result } => {
                assert_eq!(*id, op_id);
                assert!(matches!(result, Err(CcidError::Io(_))));
            }
            _ => panic!("expected Complete action"),
        }
    }
}
