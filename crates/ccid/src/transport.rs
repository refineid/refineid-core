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

//! CCID card transport adapter implementing [`refineid_apdu::CardTransport`].
//!
//! Connects the deterministic [`CcidEngine`] with a platform-provided
//! [`UsbHostTransport`] (e.g. Android USB Host API, libusb, or mock).
//! Handles:
//! - T=0 / T=1 APDU and TPDU preparation.
//! - ISO 7816-4 `SW=61xx` `GET RESPONSE` chaining.
//! - ISO 7816-4 `SW=6Cxx` wrong-Le single retry on eligible read commands.
//! - Single-shot credential transmission with zeroized scratch buffers.
//! - USB CCID Class-Specific Abort (§5.3.1) on timeout or cancel.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use refineid_apdu::iso7816::GetResponse;
use refineid_apdu::{
    ApduClass, CardTransport, CommandApdu, CredentialCommand, ResponseApdu, TransportOutcome,
};
use refineid_atr::Atr;
use zeroize::Zeroize;

use crate::codec::{AUTOMATIC_VOLTAGE_SELECTION, DEFAULT_T0_FIDI, DEFAULT_T0_WAITING_INTEGER};
use crate::descriptor::{CcidExchangeLevel, CcidFunctionalDescriptor};
use crate::engine::{
    Action, CcidEngine, InputEvent, IoCompletion, MonotonicTime, Operation, OperationId,
    OperationResult,
};
use crate::error::CcidError;

/// Receive-buffer size ceiling for response concatenation (64 KiB).
const EXTENDED_RESPONSE_DATA_MAX_BYTES: usize = 1 << 16;
/// ISO 7816-3/4 status word indicating more bytes available via `GET RESPONSE`.
const SW1_BYTES_AVAILABLE: u8 = 0x61;
/// ISO 7816-4 status word indicating wrong Le length.
const SW1_WRONG_LE: u8 = 0x6C;

/// USB Host Transport interface implemented by platform drivers (Android USB Host, libusb, etc.).
pub trait UsbHostTransport {
    /// Send data to Bulk-OUT endpoint.
    ///
    /// # Errors
    /// Returns `CcidError` on USB transmission failure or timeout.
    fn bulk_out(&mut self, endpoint: u8, data: &[u8], timeout_ms: u32) -> Result<usize, CcidError>;

    /// Receive data from Bulk-IN endpoint.
    ///
    /// # Errors
    /// Returns `CcidError` on USB reception failure or timeout.
    fn bulk_in(
        &mut self,
        endpoint: u8,
        buffer: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, CcidError>;

    /// Execute USB control transfer (e.g. for CCID ABORT §5.3.1).
    ///
    /// # Errors
    /// Returns `CcidError` on USB control transfer failure.
    fn control_transfer(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, CcidError>;
}

/// Smart card communication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardProtocol {
    /// ISO/IEC 7816-3 T=0 (character / half-duplex byte transmission).
    T0,
    /// ISO/IEC 7816-3 T=1 (half-duplex block transmission).
    T1,
}

impl CardProtocol {
    /// Deduce protocol from parsed ATR.
    #[must_use]
    pub fn from_atr(atr: &Atr) -> Self {
        if atr.supports_non_t0_protocol() {
            Self::T1
        } else {
            Self::T0
        }
    }
}

/// Convert one short ISO 7816 case-4 command into the case-3 command
/// CCID / PC-SC drivers expect for T=0. The card then announces the response
/// with 61xx, which continues with GET RESPONSE.
fn t0_case3_from_short_case4(apdu: &[u8]) -> Option<Vec<u8>> {
    const HEADER_AND_LC_BYTES: usize = 5;
    const TRAILING_LE_BYTES: usize = 1;

    let lc = usize::from(*apdu.get(4)?);
    if lc == 0 {
        return None;
    }
    let case4_len = HEADER_AND_LC_BYTES
        .checked_add(lc)?
        .checked_add(TRAILING_LE_BYTES)?;
    if apdu.len() != case4_len {
        return None;
    }
    Some(apdu[..apdu.len() - 1].to_vec())
}

/// Prepare outgoing command bytes according to card protocol and CCID exchange level.
fn prepare_command_bytes(
    apdu: &[u8],
    protocol: CardProtocol,
    exchange_level: CcidExchangeLevel,
) -> Result<Vec<u8>, CcidError> {
    if protocol == CardProtocol::T1 && exchange_level == CcidExchangeLevel::Tpdu {
        return Err(CcidError::UnsupportedProtocol);
    }
    if protocol == CardProtocol::T0
        && exchange_level == CcidExchangeLevel::Tpdu
        && let Some(case3) = t0_case3_from_short_case4(apdu)
    {
        return Ok(case3);
    }
    Ok(apdu.to_vec())
}

/// Smart card transport adapter over USB CCID.
pub struct CcidCardTransport<H: UsbHostTransport> {
    host: H,
    engine: CcidEngine,
    bulk_out_endpoint: u8,
    bulk_in_endpoint: u8,
    atr: Vec<u8>,
    protocol: CardProtocol,
    next_op_id: u64,
    timeout_ms: u32,
}

impl<H: UsbHostTransport> CcidCardTransport<H> {
    /// Connect to a smart card in a CCID reader slot and power on to receive the ATR.
    ///
    /// # Errors
    /// Returns `CcidError` if the power-on or slot activation fails.
    pub fn connect(
        host: H,
        descriptor: &CcidFunctionalDescriptor,
        interface_number: u8,
        b_slot: u8,
        bulk_out_endpoint: u8,
        bulk_in_endpoint: u8,
    ) -> Result<Self, CcidError> {
        let engine = CcidEngine::new(interface_number, b_slot, 1, descriptor);
        let mut transport = Self {
            host,
            engine,
            bulk_out_endpoint,
            bulk_in_endpoint,
            atr: Vec::new(),
            protocol: CardProtocol::T0,
            next_op_id: 1,
            timeout_ms: 5000,
        };

        let res = transport.execute_op(Operation::PowerOn {
            voltage: AUTOMATIC_VOLTAGE_SELECTION,
        })?;

        match res {
            OperationResult::PowerOn(atr_bytes) => {
                let parsed = Atr::new(&atr_bytes)?;
                transport.protocol = CardProtocol::from_atr(&parsed);
                transport.atr = atr_bytes;

                if !descriptor.automatic_parameter_configuration()
                    && transport.protocol == CardProtocol::T0
                {
                    let _ = transport.execute_op(Operation::SetParametersT0 {
                        fi_di: DEFAULT_T0_FIDI,
                        guard_time: 0,
                        waiting_integer: DEFAULT_T0_WAITING_INTEGER,
                        clock_stop: 0,
                        inverse_convention: false,
                    });
                }

                Ok(transport)
            }
            _ => Err(CcidError::ProtocolDesync(
                "PowerOn operation did not return ATR data".into(),
            )),
        }
    }

    /// Construct a CCID transport from an existing activated session.
    #[must_use]
    pub fn from_existing(
        host: H,
        engine: CcidEngine,
        bulk_out_endpoint: u8,
        bulk_in_endpoint: u8,
        atr: Vec<u8>,
        protocol: CardProtocol,
    ) -> Self {
        Self {
            host,
            engine,
            bulk_out_endpoint,
            bulk_in_endpoint,
            atr,
            protocol,
            next_op_id: 1,
            timeout_ms: 5000,
        }
    }

    /// Borrow the raw ATR bytes.
    #[must_use]
    pub fn atr_bytes(&self) -> &[u8] {
        &self.atr
    }

    /// Parsed ATR.
    ///
    /// # Errors
    /// Returns `AtrError` if the ATR structure is invalid.
    pub fn atr(&self) -> Result<Atr, refineid_atr::AtrError> {
        Atr::new(&self.atr)
    }

    /// Smart card communication protocol.
    #[must_use]
    pub const fn protocol(&self) -> CardProtocol {
        self.protocol
    }

    /// Configured timeout in milliseconds.
    #[must_use]
    pub const fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }

    /// Set transport operation timeout in milliseconds.
    pub fn set_timeout_ms(&mut self, timeout_ms: u32) {
        self.timeout_ms = timeout_ms;
    }

    /// Reference to underlying USB host transport.
    pub fn host(&self) -> &H {
        &self.host
    }

    /// Mutable reference to underlying USB host transport.
    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Reference to underlying CCID protocol engine.
    #[must_use]
    pub const fn engine(&self) -> &CcidEngine {
        &self.engine
    }

    /// Mutable reference to underlying CCID protocol engine.
    pub fn engine_mut(&mut self) -> &mut CcidEngine {
        &mut self.engine
    }

    /// Reset the smart card, returning its fresh ATR.
    ///
    /// # Errors
    /// Returns `CcidError` if the card power cycle fails.
    pub fn reset(&mut self) -> Result<Vec<u8>, CcidError> {
        let _ = self.execute_op(Operation::PowerOff);
        let res = self.execute_op(Operation::PowerOn {
            voltage: AUTOMATIC_VOLTAGE_SELECTION,
        })?;
        match res {
            OperationResult::PowerOn(atr_bytes) => {
                if let Ok(parsed) = Atr::new(&atr_bytes) {
                    self.protocol = CardProtocol::from_atr(&parsed);
                }
                self.atr = atr_bytes.clone();
                Ok(atr_bytes)
            }
            _ => Err(CcidError::ProtocolDesync(
                "Reset did not return ATR data".into(),
            )),
        }
    }

    /// Abort an ongoing or stalled CCID slot operation per USB-IF CCID §5.3.1.
    ///
    /// # Errors
    /// Returns `CcidError` if the abort control transfer or slot status exchange fails.
    pub fn abort(&mut self) -> Result<(), CcidError> {
        let slot = self.engine.b_slot;
        let seq = self.engine.next_seq;
        let value = (u16::from(seq) << 8) | u16::from(slot);
        let index = u16::from(self.engine.interface_number);

        let mut empty_data = [];
        self.host
            .control_transfer(0x21, 0x01, value, index, &mut empty_data, self.timeout_ms)?;

        let res = self.execute_op(Operation::Abort)?;
        match res {
            OperationResult::Aborted | OperationResult::SlotStatus { .. } => Ok(()),
            _ => Err(CcidError::ProtocolDesync(
                "abort returned unexpected outcome".into(),
            )),
        }
    }

    /// Synchronously execute a logical operation through the deterministic CCID engine.
    ///
    /// # Errors
    /// Returns `CcidError` on I/O, protocol, or reader firmware failure.
    pub fn execute_op(&mut self, op: Operation) -> Result<OperationResult, CcidError> {
        let op_id = OperationId(self.next_op_id);
        self.next_op_id = self.next_op_id.wrapping_add(1);

        let now = MonotonicTime(0);
        let transition = self.engine.step(now, InputEvent::Start { id: op_id, op });

        let mut queue = VecDeque::new();
        for action in transition.actions {
            queue.push_back(action);
        }

        while let Some(action) = queue.pop_front() {
            match action {
                Action::SubmitBulkOut { mut data, .. } => {
                    let res = self
                        .host
                        .bulk_out(self.bulk_out_endpoint, &data, self.timeout_ms);
                    data.zeroize();
                    let ev = match res {
                        Ok(transferred) => {
                            InputEvent::IoCompleted(IoCompletion::BulkOut { transferred })
                        }
                        Err(e) => InputEvent::IoCompleted(IoCompletion::Failure(e)),
                    };
                    let next = self.engine.step(now, ev);
                    for a in next.actions {
                        queue.push_back(a);
                    }
                }
                Action::SubmitBulkIn { buffer_size } => {
                    let mut buf = alloc::vec![0_u8; buffer_size];
                    let res = self
                        .host
                        .bulk_in(self.bulk_in_endpoint, &mut buf, self.timeout_ms);
                    let ev = match res {
                        Ok(len) => {
                            buf.truncate(len);
                            InputEvent::IoCompleted(IoCompletion::BulkIn(buf))
                        }
                        Err(e) => InputEvent::IoCompleted(IoCompletion::Failure(e)),
                    };
                    let next = self.engine.step(now, ev);
                    for a in next.actions {
                        queue.push_back(a);
                    }
                }
                Action::SubmitControl {
                    request_type,
                    request,
                    value,
                    index,
                    mut data,
                } => {
                    let res = self.host.control_transfer(
                        request_type,
                        request,
                        value,
                        index,
                        &mut data,
                        self.timeout_ms,
                    );
                    let ev = match res {
                        Ok(_) => InputEvent::IoCompleted(IoCompletion::Control),
                        Err(e) => InputEvent::IoCompleted(IoCompletion::Failure(e)),
                    };
                    let next = self.engine.step(now, ev);
                    for a in next.actions {
                        queue.push_back(a);
                    }
                }
                Action::CancelTransfers => {
                    queue.clear();
                }
                Action::Complete { id, result } => {
                    if id == op_id {
                        queue.clear();
                        return result;
                    }
                }
                Action::PublishSlotChange { .. } => {}
            }
        }

        Err(CcidError::ProtocolDesync(
            "CCID engine terminated operation without completion".into(),
        ))
    }

    /// Drive one logical APDU exchange, handling `SW=61xx` `GET RESPONSE` chaining.
    fn run_exchange(&mut self, apdu_bytes: &[u8]) -> Result<TransportOutcome, CcidError> {
        let op = Operation::TransferBlock {
            b_wi: 0,
            w_level_parameter: 0,
            data: apdu_bytes.to_vec(),
        };
        let raw_resp = match self.execute_op(op) {
            Ok(OperationResult::TransferBlock(data)) => data,
            Ok(_) => return Ok(TransportOutcome::ProtocolDesync),
            Err(CcidError::CardRemoved) => return Ok(TransportOutcome::NoCard),
            Err(CcidError::Timeout) => return Ok(TransportOutcome::TimeoutUnknownState),
            Err(e) => return Err(e),
        };

        let Some((body, sw_bytes)) = raw_resp.split_last_chunk::<2>() else {
            return Ok(TransportOutcome::ProtocolDesync);
        };
        let [sw1, sw2] = *sw_bytes;

        if sw1 == SW1_BYTES_AVAILABLE {
            let mut combined = body.to_vec();
            let mut next_le = sw2;
            let mut chained_sw1;
            let mut chained_sw2;
            loop {
                let get_resp = GetResponse {
                    class: ApduClass::Plain,
                    le: next_le,
                }
                .into_apdu();
                let get_resp_bytes = prepare_command_bytes(
                    get_resp.as_bytes(),
                    self.protocol,
                    self.engine.exchange_level,
                )?;
                let chain_op = Operation::TransferBlock {
                    b_wi: 0,
                    w_level_parameter: 0,
                    data: get_resp_bytes,
                };
                let chain_raw = match self.execute_op(chain_op) {
                    Ok(OperationResult::TransferBlock(data)) => data,
                    Ok(_) => return Ok(TransportOutcome::ProtocolDesync),
                    Err(CcidError::CardRemoved) => return Ok(TransportOutcome::NoCard),
                    Err(CcidError::Timeout) => return Ok(TransportOutcome::TimeoutUnknownState),
                    Err(e) => return Err(e),
                };
                let Some((chain_body, chain_sw)) = chain_raw.split_last_chunk::<2>() else {
                    return Ok(TransportOutcome::ProtocolDesync);
                };
                let progressed = !chain_body.is_empty();
                let next_len = combined.len().saturating_add(chain_body.len());
                if next_len > EXTENDED_RESPONSE_DATA_MAX_BYTES {
                    return Err(CcidError::ProtocolDesync(
                        "61xx GET RESPONSE chain exceeded 64 KiB".into(),
                    ));
                }
                combined.extend_from_slice(chain_body);
                chained_sw1 = chain_sw[0];
                chained_sw2 = chain_sw[1];
                if chained_sw1 == SW1_BYTES_AVAILABLE {
                    if !progressed {
                        return Err(CcidError::ProtocolDesync(
                            "card signalled 61xx but returned no bytes (stalled chain)".into(),
                        ));
                    }
                    next_le = chained_sw2;
                    continue;
                }
                if chained_sw1 == SW1_WRONG_LE {
                    next_le = chained_sw2;
                    continue;
                }
                break;
            }
            return Ok(TransportOutcome::Response(ResponseApdu {
                body: combined,
                sw1: chained_sw1,
                sw2: chained_sw2,
            }));
        }

        Ok(TransportOutcome::Response(ResponseApdu {
            body: body.to_vec(),
            sw1,
            sw2,
        }))
    }
}

impl<H: UsbHostTransport> CardTransport for CcidCardTransport<H> {
    type Error = CcidError;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let prepared = prepare_command_bytes(
            command.as_bytes(),
            self.protocol,
            self.engine.exchange_level,
        )?;
        let outcome = self.run_exchange(&prepared)?;

        // Wrong-Le single retry on opted-in case-2 commands:
        if let TransportOutcome::Response(ref resp) = outcome
            && resp.sw1 == SW1_WRONG_LE
            && let Some(corrected) = command.corrected_wrong_le(resp.sw2)
        {
            let retry_bytes = prepare_command_bytes(
                corrected.as_bytes(),
                self.protocol,
                self.engine.exchange_level,
            )?;
            return self.run_exchange(&retry_bytes);
        }

        Ok(outcome)
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        command.expose_wire(|wire| {
            let mut prepared =
                prepare_command_bytes(wire, self.protocol, self.engine.exchange_level)?;
            let outcome = self.run_exchange(&prepared);
            prepared.zeroize();
            outcome
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{
        CARD_STATUS_ACTIVE, CHAIN_COMPLETE, PC_TO_RDR_ABORT, PC_TO_RDR_ICC_POWER_ON,
        PC_TO_RDR_XFR_BLOCK, RDR_TO_PC_DATA_BLOCK, RDR_TO_PC_SLOT_STATUS,
    };
    use crate::descriptor::{
        AUTOMATIC_ACTIVATION, AUTOMATIC_PARAMETER_CONFIGURATION, SHORT_APDU_EXCHANGE, TPDU_EXCHANGE,
    };
    use refineid_apdu::command::{
        ApduClass, CommandApdu, CommandHeader, CredentialBody, CredentialCommand,
        UnvalidatedCredentialBlock,
    };

    struct MockUsbHost {
        bulk_out_records: Vec<Vec<u8>>,
        bulk_in_replies: VecDeque<Result<Vec<u8>, CcidError>>,
        control_transfers: Vec<(u8, u8, u16, u16)>,
    }

    impl MockUsbHost {
        fn new() -> Self {
            Self {
                bulk_out_records: Vec::new(),
                bulk_in_replies: VecDeque::new(),
                control_transfers: Vec::new(),
            }
        }

        fn push_reply(&mut self, reply: Result<Vec<u8>, CcidError>) {
            self.bulk_in_replies.push_back(reply);
        }
    }

    impl UsbHostTransport for MockUsbHost {
        fn bulk_out(
            &mut self,
            _endpoint: u8,
            data: &[u8],
            _timeout_ms: u32,
        ) -> Result<usize, CcidError> {
            self.bulk_out_records.push(data.to_vec());
            Ok(data.len())
        }

        fn bulk_in(
            &mut self,
            _endpoint: u8,
            buffer: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<usize, CcidError> {
            match self.bulk_in_replies.pop_front() {
                Some(Ok(reply)) => {
                    let len = reply.len().min(buffer.len());
                    buffer[..len].copy_from_slice(&reply[..len]);
                    Ok(len)
                }
                Some(Err(e)) => Err(e),
                None => Err(CcidError::Io("mock bulk_in underflow".into())),
            }
        }

        fn control_transfer(
            &mut self,
            request_type: u8,
            request: u8,
            value: u16,
            index: u16,
            _data: &mut [u8],
            _timeout_ms: u32,
        ) -> Result<usize, CcidError> {
            self.control_transfers
                .push((request_type, request, value, index));
            Ok(0)
        }
    }

    fn test_descriptor() -> CcidFunctionalDescriptor {
        CcidFunctionalDescriptor {
            exchange_level: CcidExchangeLevel::ShortApdu,
            maximum_message_length: 271,
            max_slot_index: 0,
            features: SHORT_APDU_EXCHANGE
                | AUTOMATIC_ACTIVATION
                | AUTOMATIC_PARAMETER_CONFIGURATION,
            protocols: 3,
        }
    }

    fn tpdu_descriptor() -> CcidFunctionalDescriptor {
        CcidFunctionalDescriptor {
            exchange_level: CcidExchangeLevel::Tpdu,
            maximum_message_length: 271,
            max_slot_index: 0,
            features: TPDU_EXCHANGE | AUTOMATIC_ACTIVATION | AUTOMATIC_PARAMETER_CONFIGURATION,
            protocols: 3,
        }
    }

    fn mock_data_block_response(seq: u8, payload: &[u8]) -> Vec<u8> {
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

    fn mock_slot_status_response(seq: u8) -> Vec<u8> {
        let mut f = Vec::new();
        f.push(RDR_TO_PC_SLOT_STATUS);
        f.extend_from_slice(&0_u32.to_le_bytes());
        f.push(0); // slot
        f.push(seq);
        f.push(CARD_STATUS_ACTIVE);
        f.push(0); // error
        f.push(0); // clock running
        f
    }

    fn test_header() -> CommandHeader {
        CommandHeader {
            class: ApduClass::Plain,
            instruction: 0xEE,
            p1: 0x01,
            p2: 0x02,
        }
    }

    #[test]
    fn connect_initializes_transport_with_atr() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00]; // T=0 ATR
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        assert_eq!(transport.atr_bytes(), &atr);
        assert_eq!(transport.protocol(), CardProtocol::T0);
        assert_eq!(transport.host().bulk_out_records.len(), 1);
        assert_eq!(
            transport.host().bulk_out_records[0][0],
            PC_TO_RDR_ICC_POWER_ON
        );
    }

    #[test]
    fn transmit_success() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        let cmd = CommandApdu::case_2(test_header(), 0x08);
        let rapdu = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x90, 0x00];
        // Next seq for XfrBlock is 1
        transport
            .host_mut()
            .push_reply(Ok(mock_data_block_response(1, &rapdu)));

        let outcome = transport.transmit(&cmd).expect("transmit succeeds");
        let resp = outcome.into_response().expect("real response");
        assert!(resp.is_ok());
        assert_eq!(resp.body, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn transmit_t0_case4_strips_trailing_le() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = tpdu_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        let data = [0xAA, 0xBB];
        let cmd = CommandApdu::case_4(test_header(), &data, 0x10).expect("valid case 4");
        transport
            .host_mut()
            .push_reply(Ok(mock_data_block_response(1, &[0x90, 0x00])));

        let outcome = transport.transmit(&cmd).expect("transmit succeeds");
        let resp = outcome.into_response().expect("real response");
        assert!(resp.is_ok());

        // Verify sent block payload: Case 3 format (header + Lc=2 + 2 data bytes = 7 bytes, no Le)
        let sent = &transport.host().bulk_out_records[1];
        assert_eq!(sent[0], PC_TO_RDR_XFR_BLOCK);
        let payload_len = u32::from_le_bytes([sent[1], sent[2], sent[3], sent[4]]) as usize;
        assert_eq!(payload_len, 7);
        assert_eq!(&sent[10..], &[0x00, 0xEE, 0x01, 0x02, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn transmit_handles_61xx_chaining() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        let cmd = CommandApdu::case_2(test_header(), 0x05);
        // Reply 1: 2 bytes of body + 61 03 (3 more bytes available via GET RESPONSE)
        transport
            .host_mut()
            .push_reply(Ok(mock_data_block_response(1, &[0x10, 0x20, 0x61, 0x03])));
        // Reply 2: remaining 3 bytes + 90 00
        transport.host_mut().push_reply(Ok(mock_data_block_response(
            2,
            &[0x30, 0x40, 0x50, 0x90, 0x00],
        )));

        let outcome = transport.transmit(&cmd).expect("transmit succeeds");
        let resp = outcome.into_response().expect("real response");
        assert!(resp.is_ok());
        assert_eq!(resp.body, &[0x10, 0x20, 0x30, 0x40, 0x50]);

        // Verify that second command was GET RESPONSE with Le=3: [0x00, 0xC0, 0x00, 0x00, 0x03]
        let sent2 = &transport.host().bulk_out_records[2];
        assert_eq!(&sent2[10..], &[0x00, 0xC0, 0x00, 0x00, 0x03]);
    }

    #[test]
    fn transmit_handles_6cxx_wrong_le_single_retry() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        let cmd = GetResponse {
            class: ApduClass::Plain,
            le: 0x02,
        }
        .into_apdu();
        // Reply 1: 6C 04 (wrong Le, correct is 4)
        transport
            .host_mut()
            .push_reply(Ok(mock_data_block_response(1, &[0x6C, 0x04])));
        // Reply 2: 4 bytes + 90 00
        transport.host_mut().push_reply(Ok(mock_data_block_response(
            2,
            &[0x01, 0x02, 0x03, 0x04, 0x90, 0x00],
        )));

        let outcome = transport.transmit(&cmd).expect("transmit succeeds");
        let resp = outcome.into_response().expect("real response");
        assert!(resp.is_ok());
        assert_eq!(resp.body, &[1, 2, 3, 4]);

        // Verify that retry command was issued with Le=4
        let sent2 = &transport.host().bulk_out_records[2];
        assert_eq!(&sent2[10..], &[0x00, 0xC0, 0x00, 0x00, 0x04]);
    }

    #[test]
    fn transmit_credential_sends_once_without_retry() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        let octets = [0x01, 0x02, 0x03, 0x04];
        let mut block = UnvalidatedCredentialBlock::zeroed();
        block.buffer()[..octets.len()].copy_from_slice(&octets);
        block.set_filled(octets.len());
        let body = CredentialBody::from_block(block).expect("valid block");
        let cmd = CredentialCommand::assemble(test_header(), body);

        // Even if card returns 6C 08, credential command must NOT retry!
        transport
            .host_mut()
            .push_reply(Ok(mock_data_block_response(1, &[0x6C, 0x08])));

        let outcome = transport
            .transmit_credential(cmd)
            .expect("credential transmit completed");
        let resp = outcome.into_response().expect("real response");
        assert_eq!(resp.sw1, 0x6C);
        assert_eq!(resp.sw2, 0x08);

        // Only 1 transmit was made after connect
        assert_eq!(transport.host().bulk_out_records.len(), 2);
    }

    #[test]
    fn card_removed_maps_to_no_card_outcome() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        transport.host_mut().push_reply(Err(CcidError::CardRemoved));
        let cmd = CommandApdu::case_2(test_header(), 0x02);
        let outcome = transport.transmit(&cmd).expect("handled card removal");
        assert_eq!(outcome, TransportOutcome::NoCard);
    }

    #[test]
    fn timeout_maps_to_timeout_unknown_state() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        transport.host_mut().push_reply(Err(CcidError::Timeout));
        let cmd = CommandApdu::case_2(test_header(), 0x02);
        let outcome = transport.transmit(&cmd).expect("handled timeout");
        assert_eq!(outcome, TransportOutcome::TimeoutUnknownState);
    }

    #[test]
    fn abort_executes_control_and_bulk_abort() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        transport
            .host_mut()
            .push_reply(Ok(mock_slot_status_response(1)));
        transport.abort().expect("abort succeeds");

        assert_eq!(transport.host().control_transfers.len(), 1);
        assert_eq!(transport.host().control_transfers[0].0, 0x21); // CLASS | INTERFACE
        assert_eq!(transport.host().control_transfers[0].1, 0x01); // ABORT
        let last_out = transport
            .host()
            .bulk_out_records
            .last()
            .expect("has bulk out record");
        assert_eq!(last_out[0], PC_TO_RDR_ABORT);
    }

    #[test]
    fn reset_power_cycles_card() {
        let mut host = MockUsbHost::new();
        let atr = [0x3B, 0x80, 0x00];
        host.push_reply(Ok(mock_data_block_response(0, &atr)));

        let desc = test_descriptor();
        let mut transport =
            CcidCardTransport::connect(host, &desc, 0, 0, 0x02, 0x82).expect("connect succeeds");

        // PowerOff returns SlotStatus (seq 1), PowerOn returns DataBlock (seq 2)
        let fresh_atr = [0x3B, 0x01, 0x42];
        transport
            .host_mut()
            .push_reply(Ok(mock_slot_status_response(1)));
        transport
            .host_mut()
            .push_reply(Ok(mock_data_block_response(2, &fresh_atr)));

        let new_atr = transport.reset().expect("reset succeeds");
        assert_eq!(new_atr, fresh_atr);
        assert_eq!(transport.atr_bytes(), &fresh_atr);
    }
}
