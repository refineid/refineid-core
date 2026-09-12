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

//! USB Chip Card Interface Device (CCID) protocol stack and transport engine for ReFineID.
//!
//! Provides:
//! - [`descriptor`]: USB CCID Functional Descriptor parser (§5.1) validating exchange levels,
//!   message bounds, and multi-slot capabilities.
//! - [`codec`]: 10-byte bulk message encoders and decoders (§6.1, §6.2), slot change interrupt
//!   parsers (§6.3), and parameter structures.
//! - [`engine`]: Pure deterministic CCID state machine engine ([`CcidEngine`]) separated
//!   completely from OS threads and physical USB handles.
//! - [`transport`]: Synchronous smart card transport adapter ([`CcidCardTransport`]) implementing
//!   [`refineid_apdu::CardTransport`] over a platform [`UsbHostTransport`].

#![forbid(unsafe_code)]

extern crate alloc;

pub mod codec;
pub mod descriptor;
pub mod engine;
pub mod error;
pub mod transport;

pub use codec::{CardStatus, CcidResponse, ChainParameter, ClockStatus, SlotChangeNotification};
pub use descriptor::{CcidExchangeLevel, CcidFunctionalDescriptor};
pub use engine::{
    Action, CcidEngine, Deadline, DeadlineId, InputEvent, IoCompletion, MonotonicTime, Operation,
    OperationId, OperationResult, Transition,
};
pub use error::CcidError;
pub use transport::{CardProtocol, CcidCardTransport, UsbHostTransport};
