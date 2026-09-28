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

//! Isolated synthetic review probes. Assertions describe required behavior.

use refineid_apdu::{ApduClass, CardTransport, CommandApdu, CommandHeader};
use refineid_ccid::codec::{
    CARD_STATUS_ACTIVE, CARD_STATUS_NOT_PRESENT, CCID_HEADER_SIZE, CHAIN_BEGIN, CHAIN_COMPLETE,
    CLOCK_RUNNING, CLOCK_STOPPED_LOW, PC_TO_RDR_ICC_POWER_OFF, PC_TO_RDR_SECURE,
    RDR_TO_PC_DATA_BLOCK, RDR_TO_PC_NOTIFY_SLOT_CHANGE, RDR_TO_PC_PARAMETERS,
    RDR_TO_PC_SLOT_STATUS, decode_response,
};
use refineid_ccid::descriptor::{
    AUTOMATIC_PARAMETER_CONFIGURATION, AUTOMATIC_PPS, CCID_FUNCTIONAL_DESCRIPTOR_LENGTH,
    CcidExchangeLevel, CcidFunctionalDescriptor, DESCRIPTOR_TYPE_OFFSET, FEATURES_OFFSET,
    MAX_BUSY_SLOTS_OFFSET, MAXIMUM_MESSAGE_LENGTH_OFFSET, MINIMUM_SHORT_APDU_MESSAGE_LENGTH,
    PIN_SUPPORT_OFFSET, PIN_SUPPORT_VERIFY, SHORT_APDU_EXCHANGE, USB_INTERFACE_DESCRIPTOR_TYPE,
};
use refineid_ccid::engine::{W_LEVEL_BEGIN, W_LEVEL_END, W_LEVEL_NONE};
use refineid_ccid::{
    Action, CardProtocol, CcidCardTransport, CcidEngine, CcidError, CcidIoError, InputEvent,
    IoCompletion, MonotonicTime, Operation, OperationId, OperationResult, Transition,
    UsbHostTransport,
};
use std::collections::VecDeque;
use zeroize::Zeroizing;

const ZERO: u8 = 0;
const ONE: u8 = 1;
const TWO: u8 = 2;
const DWORD_SIZE: usize = 4;
const OP_A: OperationId = OperationId(1);
const OP_B: OperationId = OperationId(2);
const GENERATION: u64 = 1;
const NOW: MonotonicTime = MonotonicTime(100);
const LATER: MonotonicTime = MonotonicTime(101);
const SW_OK: u8 = 0x90;
const SYNTHETIC_INS: u8 = 0xEE;
const TEST_LE: u8 = 8;
const CHANGED_PRESENT: u8 = 3;
const CLASS_INTERFACE_OUT: u8 = 0x21;
const ABORT_REQUEST: u8 = 0x01;
const BULK_OUT: u8 = 0x02;
const BULK_IN: u8 = 0x82;
const TS_DIRECT: u8 = 0x3B;
const TD_FOLLOWS: u8 = 0x80;
const UNKNOWN_PROTOCOL: u8 = 0x7F;
const BYTE_STEP: usize = 1;
const SW_MORE: u8 = 0x61;
const SW_WRONG_LE: u8 = 0x6C;
const EXTENDED_PAYLOAD_LEN: usize = 300;
const SYNTHETIC_ERROR_CODE: u8 = 0x42;
const DUMMY_VID: u16 = 0xFFFF;
const DUMMY_PID: u16 = 0x0001;
const INSERTION_BITS: u8 = 0x03;
const REMOVAL_BITS: u8 = 0x02;
const CONTINUATION_EXPECTED: u8 = 0x10;
const W_LEVEL_OFFSET_START: usize = 8;
const W_LEVEL_OFFSET_END: usize = 10;
const PIN_VERIFY_INS: u8 = 0x20;
const TEST_POLL_TIMEOUT_MS: u32 = 100;

fn descriptor(level: CcidExchangeLevel) -> CcidFunctionalDescriptor {
    descriptor_with_pin_support(level, ZERO)
}

fn descriptor_with_pin_support(
    level: CcidExchangeLevel,
    pin_support: u8,
) -> CcidFunctionalDescriptor {
    let level_bits = match level {
        CcidExchangeLevel::Character => refineid_ccid::descriptor::CHARACTER_EXCHANGE,
        CcidExchangeLevel::Tpdu => refineid_ccid::descriptor::TPDU_EXCHANGE,
        CcidExchangeLevel::ShortApdu => refineid_ccid::descriptor::SHORT_APDU_EXCHANGE,
        CcidExchangeLevel::ShortAndExtendedApdu => {
            refineid_ccid::descriptor::SHORT_AND_EXTENDED_APDU_EXCHANGE
        }
    };
    let mut d = [ZERO; 54];
    d[0] = 54;
    d[1] = 0x21;
    d[2] = 0x10;
    d[3] = 0x01;
    d[5] = 0x07;
    d[6..10].copy_from_slice(&(u32::from(ONE | TWO)).to_le_bytes());
    d[10..14].copy_from_slice(&4800_u32.to_le_bytes());
    d[14..18].copy_from_slice(&4800_u32.to_le_bytes());
    d[19..23].copy_from_slice(&10752_u32.to_le_bytes());
    d[23..27].copy_from_slice(&344064_u32.to_le_bytes());
    d[28..32].copy_from_slice(&254_u32.to_le_bytes());
    let features = level_bits | AUTOMATIC_PARAMETER_CONFIGURATION | AUTOMATIC_PPS;
    d[FEATURES_OFFSET..FEATURES_OFFSET + DWORD_SIZE].copy_from_slice(&features.to_le_bytes());
    let max_len = MINIMUM_SHORT_APDU_MESSAGE_LENGTH as u32;
    d[MAXIMUM_MESSAGE_LENGTH_OFFSET..MAXIMUM_MESSAGE_LENGTH_OFFSET + DWORD_SIZE]
        .copy_from_slice(&max_len.to_le_bytes());
    d[PIN_SUPPORT_OFFSET] = pin_support;
    d[MAX_BUSY_SLOTS_OFFSET] = ONE;
    CcidFunctionalDescriptor::parse_functional_descriptor(&d).expect("valid test descriptor")
}

fn engine(level: CcidExchangeLevel) -> CcidEngine {
    let mut e = CcidEngine::new(ZERO, ZERO, GENERATION, &descriptor(level));
    e.set_activated(true);
    e
}

fn start(e: &mut CcidEngine, op: Operation) -> Transition {
    e.step(NOW, InputEvent::Start { id: OP_A, op })
}

fn frame(kind: u8, seq: u8, status: u8, parameter: u8, data: &[u8]) -> Vec<u8> {
    let mut f = vec![kind];
    let length = u32::try_from(data.len()).expect("synthetic frame length");
    f.extend_from_slice(&length.to_le_bytes());
    f.extend_from_slice(&[ZERO, seq, status, ZERO, parameter]);
    f.extend_from_slice(data);
    f
}

fn data_frame(seq: u8, data: &[u8]) -> Vec<u8> {
    frame(
        RDR_TO_PC_DATA_BLOCK,
        seq,
        CARD_STATUS_ACTIVE,
        CHAIN_COMPLETE,
        data,
    )
}

fn completed_ok(t: &Transition) -> bool {
    t.actions
        .iter()
        .any(|a| matches!(a, Action::Complete { result: Ok(_), .. }))
}

#[test]
fn cancel_other_operation_preserves_pending_operation() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    start(&mut e, Operation::PowerOn { voltage: ZERO });
    e.step(LATER, InputEvent::Cancel(OP_B));
    let t = e.step(
        LATER,
        InputEvent::IoCompleted(IoCompletion::BulkIn(data_frame(ZERO, &[TS_DIRECT, ZERO]))),
    );
    assert!(completed_ok(&t));
}

#[test]
fn bulk_out_ack_preserves_current_deadline() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let t = start(&mut e, Operation::GetSlotStatus);
    let ack = e.step(
        LATER,
        InputEvent::IoCompleted(IoCompletion::BulkOut {
            transferred: CCID_HEADER_SIZE,
        }),
    );
    assert_eq!(ack.next_deadline, t.next_deadline);
}

#[test]
fn changed_present_revokes_activation_and_pending_operation() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    start(&mut e, Operation::GetSlotStatus);
    let t = e.step(
        LATER,
        InputEvent::InterruptReceived(vec![RDR_TO_PC_NOTIFY_SLOT_CHANGE, CHANGED_PRESENT]),
    );
    assert!(!e.is_activated());
    assert!(
        t.actions
            .iter()
            .any(|a| matches!(a, Action::Complete { result: Err(_), .. }))
    );
}

#[test]
fn disconnected_engine_refuses_new_usb_work() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    e.step(NOW, InputEvent::ConnectionLost);
    let t = start(&mut e, Operation::GetSlotStatus);
    assert!(
        !t.actions
            .iter()
            .any(|a| matches!(a, Action::SubmitBulkOut { .. }))
    );
}

#[test]
fn timeout_requires_recovery_before_next_command() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let t = start(&mut e, Operation::GetSlotStatus);
    let d = t.next_deadline.expect("deadline");
    e.step(d.expires_at, InputEvent::DeadlineExpired(d.id));
    let t = e.step(
        d.expires_at,
        InputEvent::Start {
            id: OP_B,
            op: Operation::GetSlotStatus,
        },
    );
    assert!(
        !t.actions
            .iter()
            .any(|a| matches!(a, Action::SubmitBulkOut { .. }))
    );
}

#[test]
fn bulk_status_absence_revokes_activation_and_generation() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let generation = e.card_gen();
    start(&mut e, Operation::GetSlotStatus);
    let f = frame(
        RDR_TO_PC_SLOT_STATUS,
        ZERO,
        CARD_STATUS_NOT_PRESENT,
        CLOCK_STOPPED_LOW,
        &[],
    );
    e.step(LATER, InputEvent::IoCompleted(IoCompletion::BulkIn(f)));
    assert!(!e.is_activated() && e.card_gen() != generation);
}

#[test]
fn short_write_cannot_complete_successfully() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    start(&mut e, Operation::GetSlotStatus);
    e.step(
        LATER,
        InputEvent::IoCompleted(IoCompletion::BulkOut {
            transferred: usize::from(ZERO),
        }),
    );
    let f = frame(
        RDR_TO_PC_SLOT_STATUS,
        ZERO,
        CARD_STATUS_ACTIVE,
        CLOCK_RUNNING,
        &[],
    );
    let t = e.step(LATER, InputEvent::IoCompleted(IoCompletion::BulkIn(f)));
    assert!(!completed_ok(&t));
}

#[test]
fn ccid_chain_begin_is_not_a_complete_apdu() {
    let mut e = engine(CcidExchangeLevel::ShortAndExtendedApdu);
    start(
        &mut e,
        Operation::TransferBlock {
            b_wi: ZERO,
            w_level_parameter: u16::from(ZERO),
            data: Zeroizing::new(b"synthetic".to_vec()),
        },
    );
    let f = frame(
        RDR_TO_PC_DATA_BLOCK,
        ZERO,
        CARD_STATUS_ACTIVE,
        CHAIN_BEGIN,
        &[SW_OK, ZERO],
    );
    let t = e.step(LATER, InputEvent::IoCompleted(IoCompletion::BulkIn(f)));
    assert!(!completed_ok(&t));
}

#[test]
fn oversized_block_is_not_sent_to_reader() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let data = Zeroizing::new(vec![ZERO; e.max_payload_length() + BYTE_STEP]);
    let t = start(
        &mut e,
        Operation::TransferBlock {
            b_wi: ZERO,
            w_level_parameter: u16::from(ZERO),
            data,
        },
    );
    assert!(
        !t.actions
            .iter()
            .any(|a| matches!(a, Action::SubmitBulkOut { .. }))
    );
}

#[test]
fn parameters_require_a_known_protocol_and_structure() {
    let f = frame(
        RDR_TO_PC_PARAMETERS,
        ZERO,
        CARD_STATUS_ACTIVE,
        UNKNOWN_PROTOCOL,
        &[],
    );
    assert!(decode_response(&f, RDR_TO_PC_PARAMETERS, ZERO, ZERO).is_err());
}

#[derive(Default)]
struct Host {
    writes: Vec<Vec<u8>>,
    replies: VecDeque<Result<Vec<u8>, CcidError>>,
    controls: Vec<(u8, u8, u16, u16)>,
    reject_control: bool,
    reject_write: bool,
    reads: usize,
}

impl UsbHostTransport for Host {
    fn bulk_out(&mut self, _: u8, data: &[u8], _: u32) -> Result<usize, CcidError> {
        if self.reject_write {
            return Err(CcidError::Io(CcidIoError::SyntheticFailure));
        }
        self.writes.push(data.to_vec());
        Ok(data.len())
    }
    fn bulk_in(&mut self, _: u8, buffer: &mut [u8], _: u32) -> Result<usize, CcidError> {
        self.reads += BYTE_STEP;
        let f = self
            .replies
            .pop_front()
            .ok_or(CcidError::Io(CcidIoError::SyntheticFailure))??;
        let dest = buffer.get_mut(..f.len()).ok_or(CcidError::LengthMismatch)?;
        dest.copy_from_slice(&f);
        Ok(f.len())
    }
    fn control_transfer(
        &mut self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        _: &mut [u8],
        _: u32,
    ) -> Result<usize, CcidError> {
        self.controls.push((kind, request, value, index));
        if self.reject_control {
            Err(CcidError::Io(CcidIoError::SyntheticFailure))
        } else {
            Ok(usize::from(ZERO))
        }
    }
}

type SharedWrites = std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>;
type SharedReplies = std::sync::Arc<std::sync::Mutex<VecDeque<Result<Vec<u8>, CcidError>>>>;

#[derive(Clone, Default)]
struct SharedHost {
    writes: SharedWrites,
    replies: SharedReplies,
}

impl UsbHostTransport for SharedHost {
    fn bulk_out(&mut self, _: u8, data: &[u8], _: u32) -> Result<usize, CcidError> {
        let mut guard = self.writes.lock().expect("writes mutex lock");
        guard.push(data.to_vec());
        Ok(data.len())
    }
    fn bulk_in(&mut self, _: u8, buffer: &mut [u8], _: u32) -> Result<usize, CcidError> {
        let mut guard = self.replies.lock().expect("replies mutex lock");
        let f = guard
            .pop_front()
            .ok_or(CcidError::Io(CcidIoError::SyntheticFailure))??;
        let dest = buffer.get_mut(..f.len()).ok_or(CcidError::LengthMismatch)?;
        dest.copy_from_slice(&f);
        Ok(f.len())
    }
    fn control_transfer(
        &mut self,
        _: u8,
        _: u8,
        _: u16,
        _: u16,
        _: &mut [u8],
        _: u32,
    ) -> Result<usize, CcidError> {
        Ok(usize::from(ZERO))
    }
}

fn transport(
    host: Host,
    level: CcidExchangeLevel,
    protocol: CardProtocol,
) -> CcidCardTransport<Host> {
    let desc = descriptor(level);
    let atr = refineid_atr::Atr::new([TS_DIRECT, ZERO]).expect("valid test atr");
    CcidCardTransport::from_existing(host, engine(level), desc, BULK_OUT, BULK_IN, atr, protocol)
}

fn header() -> CommandHeader {
    CommandHeader {
        class: ApduClass::Plain,
        instruction: SYNTHETIC_INS,
        p1: ZERO,
        p2: ZERO,
    }
}

#[test]
fn abort_uses_abort_request_number() {
    let mut h = Host::default();
    h.replies.push_back(Ok(frame(
        RDR_TO_PC_SLOT_STATUS,
        ZERO,
        CARD_STATUS_ACTIVE,
        CLOCK_RUNNING,
        &[],
    )));
    let mut t = transport(h, CcidExchangeLevel::ShortApdu, CardProtocol::T0);
    t.abort().expect("scripted abort");
    let control = t
        .host()
        .controls
        .first()
        .expect("recorded control transfer");
    assert_eq!(control.0, CLASS_INTERFACE_OUT);
    assert_eq!(control.1, ABORT_REQUEST);
    let control_seq = (control.2 >> 8) as u8;
    let bulk_abort = t.host().writes.first().expect("recorded bulk abort");
    assert_eq!(bulk_abort[0], refineid_ccid::codec::PC_TO_RDR_ABORT);
    assert_eq!(bulk_abort[6], control_seq); // Exact pairing test: wValue.seq == bulkAbort.bSeq per CCID §5.3.1
}

#[test]
fn abort_propagates_control_failure() {
    let mut h = Host {
        reject_control: true,
        ..Host::default()
    };
    h.replies.push_back(Ok(frame(
        RDR_TO_PC_SLOT_STATUS,
        ZERO,
        CARD_STATUS_ACTIVE,
        CLOCK_RUNNING,
        &[],
    )));
    let mut t = transport(h, CcidExchangeLevel::ShortApdu, CardProtocol::T0);
    assert!(t.abort().is_err());
}

#[test]
fn failed_write_does_not_issue_queued_read() {
    let h = Host {
        reject_write: true,
        ..Host::default()
    };
    let mut t = transport(h, CcidExchangeLevel::ShortApdu, CardProtocol::T0);
    let _ = t.execute_op(Operation::GetSlotStatus);
    assert_eq!(t.host().reads, usize::from(ZERO));
}

#[test]
fn malformed_atr_prevents_connection() {
    let mut h = Host::default();
    h.replies
        .push_back(Ok(data_frame(ZERO, &[TS_DIRECT, TD_FOLLOWS, ONE])));
    assert!(
        CcidCardTransport::connect(
            h,
            &descriptor(CcidExchangeLevel::ShortApdu),
            ZERO,
            ZERO,
            BULK_OUT,
            BULK_IN
        )
        .is_err()
    );
}

#[test]
fn malformed_atr_on_reset_fails_and_revokes_activation() {
    let mut h = Host::default();
    h.replies.push_back(Ok(frame(
        RDR_TO_PC_SLOT_STATUS,
        ZERO,
        CARD_STATUS_ACTIVE,
        CLOCK_RUNNING,
        &[],
    )));
    h.replies
        .push_back(Ok(data_frame(ONE, &[TS_DIRECT, TD_FOLLOWS, ONE])));
    let mut t = transport(h, CcidExchangeLevel::ShortApdu, CardProtocol::T0);
    assert!(t.reset().is_err());
    assert!(!t.engine().is_activated());
}

#[test]
fn t0_apdu_reader_receives_complete_case_four() {
    let mut h = Host::default();
    h.replies.push_back(Ok(data_frame(ZERO, &[SW_OK, ZERO])));
    let mut t = transport(h, CcidExchangeLevel::ShortApdu, CardProtocol::T0);
    let command =
        CommandApdu::case_4(header(), b"synthetic", TEST_LE).expect("synthetic case four");
    t.transmit(&command).expect("scripted response");
    let sent = t
        .host()
        .writes
        .first()
        .expect("write")
        .get(CCID_HEADER_SIZE..)
        .expect("payload");
    assert!(sent == command.as_bytes());
}

#[test]
fn t0_tpdu_case_one_stays_four_bytes_at_ccid_boundary() {
    let mut h = Host::default();
    h.replies.push_back(Ok(data_frame(ZERO, &[SW_OK, ZERO])));
    let mut t = transport(h, CcidExchangeLevel::Tpdu, CardProtocol::T0);
    let command = CommandApdu::case_1(header());
    t.transmit(&command).expect("scripted response");
    let sent = t
        .host()
        .writes
        .first()
        .expect("write")
        .get(CCID_HEADER_SIZE..)
        .expect("payload");
    assert!(sent == command.as_bytes());
}

#[test]
fn descriptor_cannot_be_an_unrelated_usb_type() {
    let mut d = vec![ZERO; CCID_FUNCTIONAL_DESCRIPTOR_LENGTH];
    let length = u8::try_from(CCID_FUNCTIONAL_DESCRIPTOR_LENGTH).expect("descriptor size");
    *d.first_mut().expect("header") = length;
    *d.get_mut(DESCRIPTOR_TYPE_OFFSET).expect("type") = USB_INTERFACE_DESCRIPTOR_TYPE;
    for (i, b) in SHORT_APDU_EXCHANGE.to_le_bytes().into_iter().enumerate() {
        *d.get_mut(FEATURES_OFFSET + i).expect("features") = b;
    }
    let maximum = u32::try_from(MINIMUM_SHORT_APDU_MESSAGE_LENGTH).expect("maximum");
    for (i, b) in maximum.to_le_bytes().into_iter().enumerate() {
        *d.get_mut(MAXIMUM_MESSAGE_LENGTH_OFFSET + i)
            .expect("maximum") = b;
    }
    assert!(CcidFunctionalDescriptor::parse_functional_descriptor(&d).is_err());
}

#[test]
fn wrong_le_for_followup_does_not_replay_original_read_binary() {
    use refineid_apdu::iso7816::{DirectOffset15, GetResponse, ReadBinary, ReadBinaryOffset};
    let command = ReadBinary {
        class: ApduClass::Plain,
        offset: ReadBinaryOffset::Direct(DirectOffset15::try_new(u16::from(ZERO)).expect("offset")),
        le: TEST_LE,
    }
    .into_apdu();
    let mut h = Host::default();
    h.replies
        .push_back(Ok(data_frame(ZERO, &[ONE, SW_MORE, TWO])));
    h.replies
        .push_back(Ok(data_frame(ONE, &[SW_WRONG_LE, ONE])));
    h.replies
        .push_back(Ok(data_frame(TWO, &[TWO, SW_OK, ZERO])));
    let mut t = transport(h, CcidExchangeLevel::ShortApdu, CardProtocol::T0);
    let _ = t.transmit(&command);
    let sent = t
        .host()
        .writes
        .last()
        .expect("write")
        .get(CCID_HEADER_SIZE..)
        .expect("payload");
    let expected = GetResponse {
        class: ApduClass::Plain,
        le: ONE,
    }
    .into_apdu();
    assert!(sent == expected.as_bytes());
}

#[test]
fn t1_tpdu_requires_lowering_or_explicit_rejection() {
    let mut h = Host::default();
    h.replies.push_back(Ok(data_frame(ZERO, &[SW_OK, ZERO])));
    let mut t = transport(h, CcidExchangeLevel::Tpdu, CardProtocol::T1);
    let command = CommandApdu::case_2(header(), TEST_LE);
    let result = t.transmit(&command);
    if let Some(sent) = t.host().writes.first() {
        let payload = sent.get(CCID_HEADER_SIZE..).expect("payload");
        assert!(payload != command.as_bytes());
    } else {
        assert!(result.is_err());
    }
}

#[test]
fn timer_event_cannot_expire_operation_early() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let t = start(&mut e, Operation::GetSlotStatus);
    let deadline = t.next_deadline.expect("deadline");
    let t = e.step(LATER, InputEvent::DeadlineExpired(deadline.id));
    assert!(
        !t.actions
            .iter()
            .any(|a| matches!(a, Action::Complete { .. }))
    );
}

#[test]
fn short_bulk_out_write_requires_recovery() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let _ = start(&mut e, Operation::GetSlotStatus);
    let transition = e.step(
        NOW,
        InputEvent::IoCompleted(IoCompletion::BulkOut {
            transferred: usize::from(ZERO),
        }),
    );
    assert!(e.needs_recovery());
    assert!(
        transition
            .actions
            .iter()
            .any(|a| matches!(a, Action::Complete { .. }))
    );
}

#[test]
fn malformed_response_requires_recovery() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let _ = start(&mut e, Operation::GetSlotStatus);
    let _ = e.step(
        NOW,
        InputEvent::IoCompleted(IoCompletion::BulkIn(vec![ZERO; 5])),
    );
    assert!(e.needs_recovery());
}

#[test]
fn invalid_chain_transition_requires_recovery() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let _ = start(
        &mut e,
        Operation::TransferBlock {
            b_wi: ZERO,
            w_level_parameter: W_LEVEL_NONE,
            data: Zeroizing::new(vec![]),
        },
    );
    let transition = e.step(
        NOW,
        InputEvent::IoCompleted(IoCompletion::BulkIn(frame(
            RDR_TO_PC_DATA_BLOCK,
            ZERO,
            CARD_STATUS_ACTIVE,
            TWO, // Chain End without preceding Begin
            &[SW_OK, ZERO],
        ))),
    );
    assert!(e.needs_recovery());
    assert!(transition.actions.iter().any(|a| matches!(
        a,
        Action::Complete {
            result: Err(CcidError::ProtocolDesync(_)),
            ..
        }
    )));
}

#[test]
fn pso_decipher_response_debug_redacted() {
    let result = OperationResult::TransferBlock(vec![0x42; 32]);
    let debug_str = format!("{result:?}");
    assert!(debug_str.contains("[redacted]"));
    assert!(!debug_str.contains("42"));

    let io = IoCompletion::BulkIn(vec![0x42; 32]);
    let io_debug = format!("{io:?}");
    assert!(io_debug.contains("[redacted]"));
    assert!(!io_debug.contains("42"));
}

#[test]
fn atr2_classified_as_t0_despite_global_interface_bytes() {
    let atr2_bytes = [0x3B, 0x75, 0x13, 0x00, 0x00, 0x9C, 0x02, 0x02, 0x01, 0x02];
    if let Ok(parsed) = refineid_atr::Atr::new(atr2_bytes) {
        assert_eq!(CardProtocol::from_atr(&parsed), CardProtocol::T0);
    }
}

#[test]
fn connect_rejects_out_of_range_slot() {
    let desc = descriptor(CcidExchangeLevel::ShortApdu);
    let h = Host::default();
    let err = CcidCardTransport::connect(h, &desc, ZERO, ONE, BULK_OUT, BULK_IN).err();
    assert_eq!(
        err,
        Some(CcidError::UnexpectedSlot {
            expected: ZERO,
            actual: ONE,
        })
    );
}

#[test]
fn outgoing_extended_apdu_chaining_via_wlevelparameter() {
    let mut e = engine(CcidExchangeLevel::ShortAndExtendedApdu);
    let large_payload = vec![SYNTHETIC_INS; EXTENDED_PAYLOAD_LEN];
    let op = Operation::TransferBlock {
        b_wi: ZERO,
        w_level_parameter: W_LEVEL_NONE,
        data: Zeroizing::new(large_payload),
    };
    let t1 = start(&mut e, op);
    let (seq1, first_out) = t1
        .actions
        .iter()
        .find_map(|a| match a {
            Action::SubmitBulkOut { seq, data } => Some((*seq, data.clone())),
            _ => None,
        })
        .expect("first chunk bulk out");
    let level_bytes: [u8; 2] = first_out
        .get(W_LEVEL_OFFSET_START..W_LEVEL_OFFSET_END)
        .and_then(|slice| slice.try_into().ok())
        .expect("wLevelParameter slice");
    let w_level = u16::from_le_bytes(level_bytes);
    assert_eq!(w_level, W_LEVEL_BEGIN);

    let t2 = e.step(
        NOW,
        InputEvent::IoCompleted(IoCompletion::BulkOut {
            transferred: first_out.len(),
        }),
    );
    assert!(
        t2.actions
            .iter()
            .any(|a| matches!(a, Action::SubmitBulkIn { .. }))
    );

    let cont_resp = frame(RDR_TO_PC_DATA_BLOCK, seq1, ZERO, CONTINUATION_EXPECTED, &[]);
    let t3 = e.step(
        NOW,
        InputEvent::IoCompleted(IoCompletion::BulkIn(cont_resp)),
    );

    let (seq2, second_out) = t3
        .actions
        .iter()
        .find_map(|a| match a {
            Action::SubmitBulkOut { seq, data } => Some((*seq, data.clone())),
            _ => None,
        })
        .expect("second chunk bulk out");
    let level_bytes2: [u8; 2] = second_out
        .get(W_LEVEL_OFFSET_START..W_LEVEL_OFFSET_END)
        .and_then(|slice| slice.try_into().ok())
        .expect("wLevelParameter slice");
    let w_level2 = u16::from_le_bytes(level_bytes2);
    assert_eq!(w_level2, W_LEVEL_END);

    let _ = e.step(
        NOW,
        InputEvent::IoCompleted(IoCompletion::BulkOut {
            transferred: second_out.len(),
        }),
    );
    let ok_resp = frame(RDR_TO_PC_DATA_BLOCK, seq2, ZERO, ZERO, &[SW_OK, ZERO]);
    let t4 = e.step(NOW, InputEvent::IoCompleted(IoCompletion::BulkIn(ok_resp)));
    assert!(t4.actions.iter().any(|a| matches!(
        a,
        Action::Complete {
            result: Ok(OperationResult::TransferBlock(_)),
            ..
        }
    )));
}

#[test]
fn secure_pin_operation_and_debug_redaction() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let pin_template = vec![ZERO, PIN_VERIFY_INS, ZERO, ONE, ZERO];
    let op = Operation::Secure {
        b_wi: ZERO,
        w_level_parameter: W_LEVEL_NONE,
        data: Zeroizing::new(pin_template),
    };
    let op_debug = format!("{op:?}");
    assert!(op_debug.contains("[redacted]"));
    assert!(!op_debug.contains("32"));

    let t = start(&mut e, op);
    let (seq, bulk_out) = t
        .actions
        .iter()
        .find_map(|a| match a {
            Action::SubmitBulkOut { seq, data } => Some((*seq, data.clone())),
            _ => None,
        })
        .expect("bulk out");
    assert_eq!(bulk_out.first().copied(), Some(PC_TO_RDR_SECURE));

    let _ = e.step(
        NOW,
        InputEvent::IoCompleted(IoCompletion::BulkOut {
            transferred: bulk_out.len(),
        }),
    );
    let resp = frame(RDR_TO_PC_DATA_BLOCK, seq, ZERO, ZERO, &[SW_OK, ZERO]);
    let t_complete = e.step(NOW, InputEvent::IoCompleted(IoCompletion::BulkIn(resp)));

    let completed_op = t_complete
        .actions
        .iter()
        .find_map(|a| match a {
            Action::Complete {
                result: Ok(res), ..
            } => Some(res.clone()),
            _ => None,
        })
        .expect("complete");
    let res_debug = format!("{completed_op:?}");
    assert!(res_debug.contains("[redacted]"));
    assert!(matches!(completed_op, OperationResult::Secure(_)));
}

#[test]
fn secure_direct_requires_pin_support_capability() {
    let h = Host::default();
    let mut t = transport(h, CcidExchangeLevel::ShortApdu, CardProtocol::T0);
    let pin_template = [ZERO, PIN_VERIFY_INS, ZERO, ONE, ZERO];
    let err = t.secure_direct(&pin_template).err();
    assert_eq!(err, Some(CcidError::UnsupportedProtocol));
}

#[test]
fn secure_direct_succeeds_with_pin_support() {
    let mut h = Host::default();
    h.replies.push_back(Ok(data_frame(ZERO, &[SW_OK, ZERO])));
    let desc = descriptor_with_pin_support(CcidExchangeLevel::ShortApdu, PIN_SUPPORT_VERIFY);
    let mut e = CcidEngine::new(ZERO, ZERO, GENERATION, &desc);
    e.set_activated(true);
    let atr = refineid_atr::Atr::new([TS_DIRECT, ZERO]).expect("valid test atr");
    let mut t =
        CcidCardTransport::from_existing(h, e, desc, BULK_OUT, BULK_IN, atr, CardProtocol::T0);
    let pin_template = [ZERO, PIN_VERIFY_INS, ZERO, ONE, ZERO];
    let res = t
        .secure_direct(&pin_template)
        .expect("secure direct response");
    assert_eq!(res.sw1, SW_OK);
    assert_eq!(res.sw2, ZERO);
    assert!(res.body.is_empty());
}

#[test]
fn oversized_secure_operation_rejected() {
    let mut e = engine(CcidExchangeLevel::ShortApdu);
    let oversized_data = Zeroizing::new(vec![ZERO; e.max_payload_length() + BYTE_STEP]);
    let op = Operation::Secure {
        b_wi: ZERO,
        w_level_parameter: W_LEVEL_NONE,
        data: oversized_data,
    };
    let t = start(&mut e, op);
    assert!(t.actions.iter().any(|a| matches!(
        a,
        Action::Complete {
            result: Err(CcidError::ApduTooLong),
            ..
        }
    )));
}

#[test]
fn character_exchange_level_support() {
    let desc = descriptor(CcidExchangeLevel::Character);
    assert_eq!(desc.exchange_level(), CcidExchangeLevel::Character);

    let mut h = Host::default();
    h.replies.push_back(Ok(data_frame(ZERO, &[SW_OK, ZERO])));
    let mut t = transport(h, CcidExchangeLevel::Character, CardProtocol::T0);
    let command = CommandApdu::case_4(header(), &[ONE, TWO], TEST_LE).expect("case 4");
    let res = t.transmit(&command);
    assert!(res.is_ok());

    let h2 = Host::default();
    let mut t2 = transport(h2, CcidExchangeLevel::Character, CardProtocol::T1);
    let res2 = t2.transmit(&command);
    assert_eq!(res2.err(), Some(CcidError::UnsupportedProtocol));
}

#[test]
fn structured_error_variants_and_display() {
    let io_err = CcidError::Io(refineid_ccid::CcidIoError::DeviceDisconnected);
    assert_eq!(
        format!("{io_err}"),
        "CCID USB I/O failure: USB CCID device disconnected"
    );

    let proto_err = CcidError::ProtocolDesync(refineid_ccid::CcidProtocolDesync::PowerOnMissingAtr);
    assert_eq!(
        format!("{proto_err}"),
        "CCID protocol desync: PowerOn operation did not return ATR data"
    );

    let desc_err = CcidError::InvalidCcidDescriptor(
        refineid_ccid::CcidDescriptorError::InvalidFunctionalDescriptorType {
            actual: SYNTHETIC_ERROR_CODE,
        },
    );
    assert_eq!(
        format!("{desc_err}"),
        "Invalid CCID descriptor: invalid CCID functional descriptor type: expected 0x21, got 0x42"
    );
}

#[test]
fn transport_disconnect_and_drop_lifecycle() {
    let mut h = Host::default();
    h.replies
        .push_back(Ok(data_frame(ZERO, &[TS_DIRECT, ZERO])));
    h.replies
        .push_back(Ok(frame(RDR_TO_PC_SLOT_STATUS, ONE, ZERO, ZERO, &[])));
    let desc = descriptor(CcidExchangeLevel::ShortApdu);
    let mut t =
        CcidCardTransport::connect(h, &desc, ZERO, ZERO, BULK_OUT, BULK_IN).expect("connect");
    assert!(t.engine().is_activated());

    t.disconnect().expect("disconnect");
    assert!(!t.engine().is_activated());
}

#[test]
fn transport_drop_while_activated_powers_off_card() {
    let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let replies = std::sync::Arc::new(std::sync::Mutex::new(VecDeque::new()));
    replies
        .lock()
        .expect("replies lock")
        .push_back(Ok(data_frame(ZERO, &[TS_DIRECT, ZERO])));
    replies.lock().expect("replies lock").push_back(Ok(frame(
        RDR_TO_PC_SLOT_STATUS,
        ONE,
        ZERO,
        ZERO,
        &[],
    )));

    let host = SharedHost {
        writes: writes.clone(),
        replies,
    };
    let desc = descriptor(CcidExchangeLevel::ShortApdu);
    {
        let t = CcidCardTransport::connect(host, &desc, ZERO, ZERO, BULK_OUT, BULK_IN)
            .expect("connect");
        assert!(t.engine().is_activated());
    }

    let recorded = writes.lock().expect("writes lock");
    let last_write = recorded.last().expect("recorded power-off write on drop");
    assert_eq!(last_write.first().copied(), Some(PC_TO_RDR_ICC_POWER_OFF));
}

#[test]
fn daemon_event_poller_and_notifications() {
    use refineid_ccid::codec::{
        CardStatus, ClockStatus, RDR_TO_PC_HARDWARE_ERROR, RDR_TO_PC_NOTIFY_SLOT_CHANGE,
    };
    use refineid_ccid::daemon::{CcidDaemon, CcidEventPoller, CcidSlotEvent};

    let mut poller = CcidEventPoller::new(ZERO);
    let slot_change_packet = [RDR_TO_PC_NOTIFY_SLOT_CHANGE, INSERTION_BITS];
    let events = poller
        .process_interrupt(&slot_change_packet)
        .expect("process interrupt");
    assert_eq!(events, vec![CcidSlotEvent::CardInserted { slot: ZERO }]);
    assert!(poller.slot_state(ZERO).expect("slot state").card_present);
    assert_eq!(
        poller.slot_state(ZERO).expect("slot state").card_status,
        CardStatus::Inactive
    );

    let slot_remove_packet = [RDR_TO_PC_NOTIFY_SLOT_CHANGE, REMOVAL_BITS];
    let events2 = poller
        .process_interrupt(&slot_remove_packet)
        .expect("process interrupt");
    assert_eq!(events2, vec![CcidSlotEvent::CardRemoved { slot: ZERO }]);
    assert!(!poller.slot_state(ZERO).expect("slot state").card_present);

    let hw_err_packet = [RDR_TO_PC_HARDWARE_ERROR, ZERO, ONE, SYNTHETIC_ERROR_CODE];
    let events3 = poller
        .process_interrupt(&hw_err_packet)
        .expect("process hw err");
    assert_eq!(
        events3,
        vec![CcidSlotEvent::HardwareError {
            slot: ZERO,
            error_code: SYNTHETIC_ERROR_CODE,
        }]
    );

    let event4 = poller.process_slot_status(ZERO, CardStatus::Active, ClockStatus::Running);
    assert_eq!(event4, Some(CcidSlotEvent::CardInserted { slot: ZERO }));

    let mut h = Host::default();
    h.replies.push_back(Ok(slot_change_packet.to_vec()));
    let mut daemon = CcidDaemon::new(h, Some(BULK_IN), ZERO);
    let daemon_events = daemon
        .poll_interrupt(TEST_POLL_TIMEOUT_MS)
        .expect("poll interrupt");
    assert_eq!(
        daemon_events,
        vec![CcidSlotEvent::CardInserted { slot: ZERO }]
    );
}

#[test]
fn hotplug_monitoring_mock_and_platform() {
    use refineid_ccid::hotplug::{
        MockHotplugMonitor, PlatformHotplugMonitor, UsbDeviceId, UsbHotplugEvent, UsbHotplugMonitor,
    };

    let mut mock = MockHotplugMonitor::new();
    let dev = UsbDeviceId {
        vendor_id: DUMMY_VID,
        product_id: DUMMY_PID,
        bus_number: ONE,
        device_address: TWO,
        device_path: Some("/dev/bus/usb/001/002".into()),
    };
    mock.push_event(UsbHotplugEvent::DeviceArrived(dev.clone()));
    let events = mock.poll_events().expect("poll mock");
    assert_eq!(events, vec![UsbHotplugEvent::DeviceArrived(dev.clone())]);

    let mut platform = PlatformHotplugMonitor::new();
    assert_eq!(
        platform.register_arrival(dev.clone()),
        Some(UsbHotplugEvent::DeviceArrived(dev.clone()))
    );
    assert_eq!(platform.register_arrival(dev.clone()), None);
    assert_eq!(platform.active_devices().len(), usize::from(ONE));
    assert_eq!(
        platform.register_removal(&dev),
        Some(UsbHotplugEvent::DeviceRemoved(dev))
    );
    assert_eq!(platform.active_devices().len(), usize::from(ZERO));
}
