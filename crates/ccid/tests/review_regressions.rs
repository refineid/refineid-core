//! Isolated synthetic review probes. Assertions describe required behavior.
use refineid_apdu::{ApduClass, CardTransport, CommandApdu, CommandHeader};
use refineid_ccid::codec::*;
use refineid_ccid::descriptor::*;
use refineid_ccid::*;
use std::collections::VecDeque;

const ZERO: u8 = 0;
const ONE: u8 = 1;
const TWO: u8 = 2;
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

fn descriptor(level: CcidExchangeLevel) -> CcidFunctionalDescriptor {
    CcidFunctionalDescriptor {
        exchange_level: level,
        maximum_message_length: MINIMUM_SHORT_APDU_MESSAGE_LENGTH,
        max_slot_index: ZERO,
        features: AUTOMATIC_PARAMETER_CONFIGURATION | AUTOMATIC_PPS,
        protocols: u32::from(ONE | TWO),
    }
}

fn engine(level: CcidExchangeLevel) -> CcidEngine {
    let mut e = CcidEngine::new(ZERO, ZERO, GENERATION, &descriptor(level));
    e.card_present = true;
    e.activated = true;
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
    assert!(!e.activated);
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
    let generation = e.card_gen;
    start(&mut e, Operation::GetSlotStatus);
    let f = frame(
        RDR_TO_PC_SLOT_STATUS,
        ZERO,
        CARD_STATUS_NOT_PRESENT,
        CLOCK_STOPPED_LOW,
        &[],
    );
    e.step(LATER, InputEvent::IoCompleted(IoCompletion::BulkIn(f)));
    assert!(!e.activated && e.card_gen != generation);
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
            data: b"synthetic".to_vec(),
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
    let data = vec![ZERO; e.max_message_length + BYTE_STEP];
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
    controls: Vec<(u8, u8)>,
    reject_control: bool,
    reject_write: bool,
    reads: usize,
}

impl UsbHostTransport for Host {
    fn bulk_out(&mut self, _: u8, data: &[u8], _: u32) -> Result<usize, CcidError> {
        if self.reject_write {
            return Err(CcidError::Io("synthetic write failure".into()));
        }
        self.writes.push(data.to_vec());
        Ok(data.len())
    }
    fn bulk_in(&mut self, _: u8, buffer: &mut [u8], _: u32) -> Result<usize, CcidError> {
        self.reads += BYTE_STEP;
        let f = self
            .replies
            .pop_front()
            .ok_or_else(|| CcidError::Io("synthetic script exhausted".into()))??;
        let dest = buffer.get_mut(..f.len()).ok_or(CcidError::LengthMismatch)?;
        dest.copy_from_slice(&f);
        Ok(f.len())
    }
    fn control_transfer(
        &mut self,
        kind: u8,
        request: u8,
        _: u16,
        _: u16,
        _: &mut [u8],
        _: u32,
    ) -> Result<usize, CcidError> {
        self.controls.push((kind, request));
        if self.reject_control {
            Err(CcidError::Io("synthetic control failure".into()))
        } else {
            Ok(usize::from(ZERO))
        }
    }
}

fn transport(
    host: Host,
    level: CcidExchangeLevel,
    protocol: CardProtocol,
) -> CcidCardTransport<Host> {
    CcidCardTransport::from_existing(
        host,
        engine(level),
        BULK_OUT,
        BULK_IN,
        vec![TS_DIRECT, ZERO],
        protocol,
    )
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
    assert_eq!(
        t.host().controls.first(),
        Some(&(CLASS_INTERFACE_OUT, ABORT_REQUEST))
    );
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
