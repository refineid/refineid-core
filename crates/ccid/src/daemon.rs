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

//! Asynchronous CCID background event daemon and notification poller (§6.3).
//!
//! Provides reactive slot status monitoring, translating USB Interrupt-IN
//! notifications (`RDR_to_PC_NotifySlotChange` and `RDR_to_PC_HardwareError`)
//! and fallback slot status queries into structured [`CcidSlotEvent`] instances.

use alloc::vec::Vec;

use crate::codec::{
    CardStatus, ClockStatus, RDR_TO_PC_HARDWARE_ERROR, RDR_TO_PC_NOTIFY_SLOT_CHANGE,
    decode_interrupt_hardware_error, decode_interrupt_slot_change,
};
use crate::error::CcidError;
use crate::transport::UsbHostTransport;

/// First slot index.
const FIRST_SLOT_INDEX: u8 = 0;
/// Default buffer size for reading Interrupt-IN packets (64 bytes).
const INTERRUPT_BUFFER_SIZE: usize = 64;

/// Events emitted by the CCID background daemon and event poller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CcidSlotEvent {
    /// Card was inserted into reader slot.
    CardInserted {
        /// Zero-based slot index.
        slot: u8,
    },
    /// Card was removed from reader slot.
    CardRemoved {
        /// Zero-based slot index.
        slot: u8,
    },
    /// Slot status changed (e.g. clock stopped or changed).
    StatusChanged {
        /// Zero-based slot index.
        slot: u8,
        /// Current card presence / power status.
        card_status: CardStatus,
        /// Current clock status.
        clock_status: ClockStatus,
    },
    /// Reader hardware error notification received via interrupt endpoint.
    HardwareError {
        /// Zero-based slot index.
        slot: u8,
        /// Hardware error code reported by reader.
        error_code: u8,
    },
}

/// Tracked state of a reader slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotState {
    /// Whether a card is physically present in the slot.
    pub card_present: bool,
    /// Current card power / activation status.
    pub card_status: CardStatus,
    /// Current clock status.
    pub clock_status: ClockStatus,
}

impl Default for SlotState {
    fn default() -> Self {
        Self {
            card_present: false,
            card_status: CardStatus::NotPresent,
            clock_status: ClockStatus::Running,
        }
    }
}

/// Reactive CCID slot event poller.
///
/// Translates raw Interrupt-IN notifications and periodic slot status queries
/// into high-level [`CcidSlotEvent`] events while maintaining per-slot state.
#[derive(Debug, Clone)]
pub struct CcidEventPoller {
    slot_states: Vec<SlotState>,
    max_slot_index: u8,
}

impl CcidEventPoller {
    /// Construct a new event poller tracking up to `max_slot_index` (0-indexed).
    #[must_use]
    pub fn new(max_slot_index: u8) -> Self {
        let count = usize::from(max_slot_index).saturating_add(1);
        Self {
            slot_states: alloc::vec![SlotState::default(); count],
            max_slot_index,
        }
    }

    /// Retrieve the current tracked state of a slot.
    #[must_use]
    pub fn slot_state(&self, slot: u8) -> Option<&SlotState> {
        self.slot_states.get(usize::from(slot))
    }

    /// Maximum slot index monitored by this poller.
    #[must_use]
    pub const fn max_slot_index(&self) -> u8 {
        self.max_slot_index
    }

    /// Process a raw Interrupt-IN notification frame.
    ///
    /// # Errors
    /// Returns `CcidError` if the interrupt packet is malformed or invalid.
    pub fn process_interrupt(&mut self, frame: &[u8]) -> Result<Vec<CcidSlotEvent>, CcidError> {
        if frame.is_empty() {
            return Err(CcidError::TruncatedHeader);
        }
        let msg_type = frame[0];
        let mut events = Vec::new();

        if msg_type == RDR_TO_PC_HARDWARE_ERROR {
            let hw_err = decode_interrupt_hardware_error(frame)?;
            events.push(CcidSlotEvent::HardwareError {
                slot: hw_err.slot,
                error_code: hw_err.hardware_error_code,
            });
            return Ok(events);
        }

        if msg_type == RDR_TO_PC_NOTIFY_SLOT_CHANGE {
            let notification = decode_interrupt_slot_change(frame, self.max_slot_index)?;
            for slot_idx in FIRST_SLOT_INDEX..=self.max_slot_index {
                let is_present = notification.is_card_present(slot_idx);
                let changed = notification.has_slot_changed(slot_idx);
                let idx = usize::from(slot_idx);
                let Some(state) = self.slot_states.get_mut(idx) else {
                    continue;
                };
                if changed || state.card_present != is_present {
                    let prev_present = state.card_present;
                    state.card_present = is_present;
                    state.card_status = if is_present {
                        CardStatus::Inactive
                    } else {
                        CardStatus::NotPresent
                    };
                    if is_present && !prev_present {
                        events.push(CcidSlotEvent::CardInserted { slot: slot_idx });
                    } else if !is_present && prev_present {
                        events.push(CcidSlotEvent::CardRemoved { slot: slot_idx });
                    } else {
                        events.push(CcidSlotEvent::StatusChanged {
                            slot: slot_idx,
                            card_status: state.card_status,
                            clock_status: state.clock_status,
                        });
                    }
                }
            }
            return Ok(events);
        }

        Err(CcidError::UnexpectedMessageType {
            expected: RDR_TO_PC_NOTIFY_SLOT_CHANGE,
            actual: msg_type,
        })
    }

    /// Process a slot status snapshot (e.g. from a periodic or fallback `PC_to_RDR_GetSlotStatus`).
    pub fn process_slot_status(
        &mut self,
        slot: u8,
        card_status: CardStatus,
        clock_status: ClockStatus,
    ) -> Option<CcidSlotEvent> {
        if slot > self.max_slot_index {
            return None;
        }
        let idx = usize::from(slot);
        let state = self.slot_states.get_mut(idx)?;
        let is_present = card_status == CardStatus::Active || card_status == CardStatus::Inactive;
        let prev_present = state.card_present;
        let prev_status = state.card_status;
        let prev_clock = state.clock_status;

        state.card_present = is_present;
        state.card_status = card_status;
        state.clock_status = clock_status;

        if is_present && !prev_present {
            Some(CcidSlotEvent::CardInserted { slot })
        } else if !is_present && prev_present {
            Some(CcidSlotEvent::CardRemoved { slot })
        } else if prev_status != card_status || prev_clock != clock_status {
            Some(CcidSlotEvent::StatusChanged {
                slot,
                card_status,
                clock_status,
            })
        } else {
            None
        }
    }
}

/// Background daemon managing CCID reader events and slot tracking.
///
/// Provides cooperative interrupt-driven polling designed to be driven by
/// an asynchronous runtime task or an OS background worker thread.
pub struct CcidDaemon<H: UsbHostTransport> {
    transport: H,
    poller: CcidEventPoller,
    interrupt_endpoint: Option<u8>,
}

impl<H: UsbHostTransport> CcidDaemon<H> {
    /// Construct a new daemon with host transport, optional interrupt endpoint, and max slot index.
    #[must_use]
    pub fn new(transport: H, interrupt_endpoint: Option<u8>, max_slot_index: u8) -> Self {
        Self {
            transport,
            poller: CcidEventPoller::new(max_slot_index),
            interrupt_endpoint,
        }
    }

    /// Reference to the underlying host transport.
    pub fn transport(&self) -> &H {
        &self.transport
    }

    /// Mutable reference to the underlying host transport.
    pub fn transport_mut(&mut self) -> &mut H {
        &mut self.transport
    }

    /// Reference to the event poller.
    #[must_use]
    pub const fn poller(&self) -> &CcidEventPoller {
        &self.poller
    }

    /// Mutable reference to the event poller.
    pub fn poller_mut(&mut self) -> &mut CcidEventPoller {
        &mut self.poller
    }

    /// Poll the Interrupt-IN endpoint for slot change notifications.
    ///
    /// # Errors
    /// Returns `CcidError` on USB transmission failure or malformed packets.
    pub fn poll_interrupt(&mut self, timeout_ms: u32) -> Result<Vec<CcidSlotEvent>, CcidError> {
        let Some(endpoint) = self.interrupt_endpoint else {
            return Ok(Vec::new());
        };
        let mut buffer = [0_u8; INTERRUPT_BUFFER_SIZE];
        let bytes_read = self.transport.bulk_in(endpoint, &mut buffer, timeout_ms)?;
        if bytes_read == 0 {
            return Ok(Vec::new());
        }
        if bytes_read > buffer.len() {
            return Err(CcidError::LengthMismatch);
        }
        self.poller.process_interrupt(&buffer[..bytes_read])
    }
}
