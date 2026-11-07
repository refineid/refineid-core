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

//! PIN management on channels PACE opened with the PUK and with PIN 1,
//! and the PIN 2 presentation on a channel PACE opened with PIN 2,
//! over the real handshake and secure-messaging layer against the
//! synthetic organizational card. The card side recovers every protected
//! command, so the tests pin the plain wire the card received, assembled
//! from the serializer's own named constants.

use refineid_apdu::{ApduClass, PinRetries, ResponseApdu, StatusWord};
use refineid_auth::manage::{
    CHANGE_P1_CURRENT_THEN_NEW, CHANGE_REFERENCE_DATA_INS, RESET_P1_NEW_ONLY,
    RESET_RETRY_COUNTER_INS,
};
use refineid_auth::verify::{VERIFY_INS, VERIFY_P1};
use refineid_auth::{
    AuthError, CardPinLengths, ChannelProof, FlooredCredential, ManageOutcome, Pin1,
    Pin1PaceChannel as _, Pin1PaceChannelOps as _, Pin2, Pin2PaceChannel as _,
    Pin2PaceChannelOps as _, PinReferenceScheme, PinSlot, PinStatus, Puk, PukPaceChannel as _,
    PukPaceChannelOps as _, RetryFloorRefusal, UnvalidatedSecret, VerifyOutcome,
};

use crate::testkit::{OrganizationalCard, organizational_card_access};
use crate::{OpenedByPin1, OpenedByPin2, OpenedByPuk, SmTransport, run_pace};

/// A synthetic PUK, eight ASCII digits.
const SYNTHETIC_PUK: &[u8] = b"31415926";
/// A synthetic PIN 1, the one PACE opened the PIN 1 channel with.
const SYNTHETIC_PIN1: &[u8] = b"2718";
/// A synthetic new PIN 1.
const NEW_PIN1: &[u8] = b"161803";
/// A synthetic new PIN 2.
const NEW_PIN2: &[u8] = b"141421";
/// A synthetic PIN 2, the one PACE opened the PIN 2 channel with.
const SYNTHETIC_PIN2: &[u8] = b"173205";
/// A PIN's initial tries on the organizational card (FINEID S4-2 v4.0
/// section 4.3).
const PIN_INITIAL_TRIES: u8 = 5;
/// A PIN 2 the role type carries but shorter than the FINEID PIN 2
/// minimum a card that lists no length is held to (FINEID S4-1 v4.2
/// section 4.1).
const SHORT_PIN2: &[u8] = b"1234";
/// The PUK's initial tries on the organizational card (FINEID S4-2 v4.0
/// section 4.3.2).
const PUK_INITIAL_TRIES: u8 = 5;
/// The lowest count the floor serves.
const TRIES_AT_FLOOR: u8 = 3;
/// Just below the floor.
const TRIES_BELOW_FLOOR: u8 = 2;
/// A status word outside the modeled set, an answer whose effect on the
/// counter is unknown.
const UNMODELED_SW: u16 = 0x6F00;

fn digits(text: &[u8]) -> UnvalidatedSecret {
    UnvalidatedSecret::from_owned_bytes(text.to_vec())
}

fn puk() -> Puk {
    Puk::reconstruct(digits(SYNTHETIC_PUK)).expect("valid PUK fixture")
}

fn pin1(text: &[u8]) -> Pin1 {
    Pin1::reconstruct(digits(text)).expect("valid PIN 1 fixture")
}

fn pin2(text: &[u8]) -> Pin2 {
    Pin2::reconstruct(digits(text)).expect("valid PIN 2 fixture")
}

fn lengths() -> CardPinLengths {
    CardPinLengths::not_listed(PinReferenceScheme::Organizational)
}

fn answer(status: StatusWord) -> ResponseApdu {
    let [sw1, sw2] = status.as_u16().to_be_bytes();
    ResponseApdu {
        body: Vec::new(),
        sw1,
        sw2,
    }
}

fn tries(count: u8) -> PinRetries {
    PinRetries::from_nibble(count).expect("a nibble")
}

fn counter(count: u8) -> StatusWord {
    StatusWord::PinIncorrect {
        retries: tries(count),
    }
}

/// A plain credential command as the card recovers it: header, Lc, data.
fn plain(instruction: u8, p1: u8, p2: u8, data: &[&[u8]]) -> Vec<u8> {
    let body: Vec<u8> = data.concat();
    let mut wire = vec![
        ApduClass::Plain.as_byte(),
        instruction,
        p1,
        p2,
        u8::try_from(body.len()).expect("short"),
    ];
    wire.extend_from_slice(&body);
    wire
}

fn reset_wire(slot: PinSlot, new: &[u8]) -> Vec<u8> {
    plain(
        RESET_RETRY_COUNTER_INS,
        RESET_P1_NEW_ONLY,
        PinReferenceScheme::Organizational.reference(slot),
        &[new],
    )
}

fn verify_puk_wire() -> Vec<u8> {
    plain(
        VERIFY_INS,
        VERIFY_P1,
        PinReferenceScheme::Organizational.puk_reference(),
        &[SYNTHETIC_PUK],
    )
}

fn puk_channel_answering(
    mse: StatusWord,
    answers: Vec<ResponseApdu>,
) -> SmTransport<OrganizationalCard, OpenedByPuk> {
    let mut card = OrganizationalCard::new(
        PinReferenceScheme::Organizational.puk_reference(),
        SYNTHETIC_PUK,
        answers,
    )
    .answering_mse_with(mse);
    let session = run_pace(&mut card, &organizational_card_access(), &puk())
        .expect("the synthetic card accepts the PUK");
    SmTransport::new(card, session)
}

fn puk_channel(answers: Vec<ResponseApdu>) -> SmTransport<OrganizationalCard, OpenedByPuk> {
    puk_channel_answering(StatusWord::Success, answers)
}

fn pin1_channel_answering(
    mse: StatusWord,
    answers: Vec<ResponseApdu>,
) -> SmTransport<OrganizationalCard, OpenedByPin1> {
    let mut card = OrganizationalCard::new(
        PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
        SYNTHETIC_PIN1,
        answers,
    )
    .answering_mse_with(mse);
    let session = run_pace(
        &mut card,
        &organizational_card_access(),
        &pin1(SYNTHETIC_PIN1),
    )
    .expect("the synthetic card accepts PIN 1");
    SmTransport::new(card, session)
}

fn pin2_channel_answering(
    mse: StatusWord,
    answers: Vec<ResponseApdu>,
) -> SmTransport<OrganizationalCard, OpenedByPin2> {
    let mut card = OrganizationalCard::new(
        PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
        SYNTHETIC_PIN2,
        answers,
    )
    .answering_mse_with(mse);
    let session = run_pace(
        &mut card,
        &organizational_card_access(),
        &pin2(SYNTHETIC_PIN2),
    )
    .expect("the synthetic card accepts PIN 2");
    SmTransport::new(card, session)
}

fn verify_pin2_wire() -> Vec<u8> {
    plain(
        VERIFY_INS,
        VERIFY_P1,
        PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
        &[SYNTHETIC_PIN2],
    )
}

#[test]
fn a_pin2_channel_starts_from_the_mse_answer() {
    let channel = pin2_channel_answering(StatusWord::Success, Vec::new());
    assert_eq!(
        channel.pin2_counter(),
        PinStatus::Remaining(tries(PIN_INITIAL_TRIES))
    );
    let channel = pin2_channel_answering(counter(TRIES_AT_FLOOR), Vec::new());
    assert_eq!(
        channel.pin2_counter(),
        PinStatus::Remaining(tries(TRIES_AT_FLOOR))
    );
}

#[test]
fn presenting_pin2_again_sends_the_verify_alone_and_an_accepted_one_leaves_pin2_verified() {
    let mut channel =
        pin2_channel_answering(counter(TRIES_AT_FLOOR), vec![answer(StatusWord::Success)]);
    let outcome = channel
        .verify_pin2_after_pin2_pace(pin2(SYNTHETIC_PIN2))
        .expect("served at the floor");
    assert_eq!(outcome, VerifyOutcome::Ok);
    assert_eq!(channel.pin2_counter(), PinStatus::Verified);
    let card = channel.into_inner();
    assert_eq!(
        card.protected_commands(),
        [verify_pin2_wire()],
        "the VERIFY alone: no counter-safe probe over the channel"
    );
    assert_eq!(card.credential_commands(), 1);
}

#[test]
fn a_refused_pin2_lowers_the_record_and_the_floor_then_refuses_with_nothing_sent() {
    let mut channel = pin2_channel_answering(
        counter(TRIES_AT_FLOOR),
        vec![answer(counter(TRIES_BELOW_FLOOR))],
    );
    let outcome = channel
        .verify_pin2_after_pin2_pace(pin2(SYNTHETIC_PIN2))
        .expect("sent");
    assert_eq!(
        outcome,
        VerifyOutcome::WrongPin {
            retries_left: tries(TRIES_BELOW_FLOOR)
        }
    );
    assert_eq!(
        channel.pin2_counter(),
        PinStatus::Remaining(tries(TRIES_BELOW_FLOOR))
    );
    let refused = channel.verify_pin2_after_pin2_pace(pin2(SYNTHETIC_PIN2));
    assert!(matches!(
        refused,
        Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
            credential: FlooredCredential::Pin2,
            remaining,
        })) if remaining.get() == TRIES_BELOW_FLOOR
    ));
    let card = channel.into_inner();
    assert_eq!(card.protected_commands(), [verify_pin2_wire()]);
}

#[test]
fn a_blocked_answer_to_pin2_ends_presentations_on_the_channel_at_the_card_s_word() {
    // The record reads blocked, which the floor serves: the card is the
    // one to refuse, and spends nothing doing so.
    let mut channel = pin2_channel_answering(
        counter(TRIES_AT_FLOOR),
        vec![
            answer(StatusWord::AuthenticationBlocked),
            answer(StatusWord::AuthenticationBlocked),
        ],
    );
    let first = channel
        .verify_pin2_after_pin2_pace(pin2(SYNTHETIC_PIN2))
        .expect("sent");
    assert_eq!(first, VerifyOutcome::Locked);
    assert_eq!(channel.pin2_counter(), PinStatus::Locked);
    let second = channel
        .verify_pin2_after_pin2_pace(pin2(SYNTHETIC_PIN2))
        .expect("the card answers for itself");
    assert_eq!(second, VerifyOutcome::Locked);
}

#[test]
fn a_puk_channel_starts_from_the_puk_s_initial_tries() {
    let channel = puk_channel(Vec::new());
    assert_eq!(
        channel.puk_counter(),
        PinStatus::Remaining(tries(PUK_INITIAL_TRIES))
    );
}

#[test]
fn the_handshake_proof_resets_each_pin_with_only_the_new_pin_and_no_puk() {
    let mut channel = puk_channel(vec![
        answer(StatusWord::Success),
        answer(StatusWord::Success),
    ]);
    let pin1_outcome = channel
        .reset_pin1_after_puk_pace(&lengths(), pin1(NEW_PIN1), ChannelProof::PaceHandshake)
        .expect("sent");
    let pin2_outcome = channel
        .reset_pin2_after_puk_pace(&lengths(), pin2(NEW_PIN2), ChannelProof::PaceHandshake)
        .expect("sent");
    assert_eq!(pin1_outcome, ManageOutcome::Ok);
    assert_eq!(pin2_outcome, ManageOutcome::Ok);
    let card = channel.into_inner();
    assert_eq!(
        card.protected_commands(),
        [
            reset_wire(PinSlot::Pin1, NEW_PIN1),
            reset_wire(PinSlot::Pin2, NEW_PIN2)
        ]
    );
    assert_eq!(card.credential_commands(), card.protected_commands().len());
}

#[test]
fn a_reset_the_card_does_not_authorise_leaves_the_puk_record_alone() {
    let mut channel = puk_channel(vec![answer(StatusWord::SecurityNotSatisfied)]);
    let outcome = channel
        .reset_pin1_after_puk_pace(&lengths(), pin1(NEW_PIN1), ChannelProof::PaceHandshake)
        .expect("sent");
    assert_eq!(
        outcome,
        ManageOutcome::Other(StatusWord::SecurityNotSatisfied)
    );
    assert_eq!(
        channel.puk_counter(),
        PinStatus::Remaining(tries(PUK_INITIAL_TRIES))
    );
}

#[test]
fn presenting_the_puk_again_verifies_it_inside_the_channel_before_the_reset() {
    let mut channel = puk_channel(vec![
        answer(StatusWord::Success),
        answer(StatusWord::Success),
    ]);
    let outcome = channel
        .reset_pin2_after_puk_pace(
            &lengths(),
            pin2(NEW_PIN2),
            ChannelProof::PresentAgain(puk()),
        )
        .expect("sent");
    assert_eq!(outcome, ManageOutcome::Ok);
    let card = channel.into_inner();
    assert_eq!(
        card.protected_commands(),
        [verify_puk_wire(), reset_wire(PinSlot::Pin2, NEW_PIN2)]
    );
}

#[test]
fn a_refused_puk_sends_no_reset_and_the_floor_then_refuses_it_with_nothing_sent() {
    let mut channel = puk_channel(vec![answer(counter(TRIES_BELOW_FLOOR))]);
    let outcome = channel
        .reset_pin1_after_puk_pace(
            &lengths(),
            pin1(NEW_PIN1),
            ChannelProof::PresentAgain(puk()),
        )
        .expect("sent");
    assert_eq!(
        outcome,
        ManageOutcome::WrongCredential {
            retries_left: tries(TRIES_BELOW_FLOOR)
        }
    );
    assert_eq!(
        channel.puk_counter(),
        PinStatus::Remaining(tries(TRIES_BELOW_FLOOR))
    );
    let refused = channel.reset_pin1_after_puk_pace(
        &lengths(),
        pin1(NEW_PIN1),
        ChannelProof::PresentAgain(puk()),
    );
    assert!(matches!(
        refused,
        Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
            credential: FlooredCredential::Puk,
            remaining,
        })) if remaining.get() == TRIES_BELOW_FLOOR
    ));
    let card = channel.into_inner();
    assert_eq!(card.protected_commands(), [verify_puk_wire()]);
}

#[test]
fn a_channel_opened_at_three_puk_tries_serves_one_presentation_at_the_floor() {
    let mut channel = puk_channel_answering(
        counter(TRIES_AT_FLOOR),
        vec![answer(StatusWord::Success), answer(StatusWord::Success)],
    );
    assert_eq!(
        channel.puk_counter(),
        PinStatus::Remaining(tries(TRIES_AT_FLOOR))
    );
    let outcome = channel
        .reset_pin1_after_puk_pace(
            &lengths(),
            pin1(NEW_PIN1),
            ChannelProof::PresentAgain(puk()),
        )
        .expect("served at the floor");
    assert_eq!(outcome, ManageOutcome::Ok);
}

#[test]
fn an_unknown_answer_to_the_puk_ends_presentations_on_the_channel() {
    let mut channel = puk_channel(vec![answer(StatusWord::from_u16(UNMODELED_SW))]);
    let outcome = channel
        .reset_pin1_after_puk_pace(
            &lengths(),
            pin1(NEW_PIN1),
            ChannelProof::PresentAgain(puk()),
        )
        .expect("sent");
    assert_eq!(
        outcome,
        ManageOutcome::Other(StatusWord::from_u16(UNMODELED_SW))
    );
    let refused = channel.reset_pin1_after_puk_pace(
        &lengths(),
        pin1(NEW_PIN1),
        ChannelProof::PresentAgain(puk()),
    );
    assert!(matches!(
        refused,
        Err(AuthError::RetryFloor(
            RetryFloorRefusal::CounterUnreadable {
                credential: FlooredCredential::Puk
            }
        ))
    ));
}

#[test]
fn a_new_pin_the_card_does_not_accept_is_refused_before_any_command() {
    let mut channel = puk_channel(Vec::new());
    let refused = channel.reset_pin2_after_puk_pace(
        &lengths(),
        pin2(SHORT_PIN2),
        ChannelProof::PaceHandshake,
    );
    assert!(matches!(refused, Err(AuthError::PinLength(_))));
    assert!(channel.into_inner().protected_commands().is_empty());
}

#[test]
fn the_handshake_proof_changes_pin1_with_a_reset_carrying_only_the_new_pin() {
    let mut channel =
        pin1_channel_answering(StatusWord::Success, vec![answer(StatusWord::Success)]);
    let outcome = channel
        .change_pin1_after_pin1_pace(&lengths(), pin1(NEW_PIN1), ChannelProof::PaceHandshake)
        .expect("sent");
    assert_eq!(outcome, ManageOutcome::Ok);
    assert_eq!(
        channel.into_inner().protected_commands(),
        [reset_wire(PinSlot::Pin1, NEW_PIN1)]
    );
}

#[test]
fn presenting_pin1_again_changes_it_with_the_current_and_the_new_pin() {
    let mut channel = pin1_channel_answering(
        StatusWord::Success,
        vec![answer(counter(TRIES_BELOW_FLOOR))],
    );
    let outcome = channel
        .change_pin1_after_pin1_pace(
            &lengths(),
            pin1(NEW_PIN1),
            ChannelProof::PresentAgain(pin1(SYNTHETIC_PIN1)),
        )
        .expect("sent");
    assert_eq!(
        outcome,
        ManageOutcome::WrongCredential {
            retries_left: tries(TRIES_BELOW_FLOOR)
        }
    );
    assert_eq!(
        channel.pin1_counter(),
        PinStatus::Remaining(tries(TRIES_BELOW_FLOOR))
    );
    let refused = channel.change_pin1_after_pin1_pace(
        &lengths(),
        pin1(NEW_PIN1),
        ChannelProof::PresentAgain(pin1(SYNTHETIC_PIN1)),
    );
    assert!(matches!(
        refused,
        Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
            credential: FlooredCredential::Pin1,
            ..
        }))
    ));
    assert_eq!(
        channel.into_inner().protected_commands(),
        [plain(
            CHANGE_REFERENCE_DATA_INS,
            CHANGE_P1_CURRENT_THEN_NEW,
            PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
            &[SYNTHETIC_PIN1, NEW_PIN1],
        )]
    );
}

#[test]
fn the_puk_record_survives_a_channel_rebuild() {
    let mut channel = puk_channel(vec![answer(counter(TRIES_BELOW_FLOOR))]);
    let _ = channel.reset_pin1_after_puk_pace(
        &lengths(),
        pin1(NEW_PIN1),
        ChannelProof::PresentAgain(puk()),
    );
    let (card, session) = channel.into_parts();
    let channel = SmTransport::new(card, session);
    assert_eq!(
        channel.puk_counter(),
        PinStatus::Remaining(tries(TRIES_BELOW_FLOOR))
    );
}

#[test]
fn an_accepted_pin1_change_sends_current_and_new_and_keeps_the_record() {
    let mut channel =
        pin1_channel_answering(StatusWord::Success, vec![answer(StatusWord::Success)]);
    let before = channel.pin1_counter();
    let outcome = channel
        .change_pin1_after_pin1_pace(
            &lengths(),
            pin1(NEW_PIN1),
            ChannelProof::PresentAgain(pin1(SYNTHETIC_PIN1)),
        )
        .expect("sent");
    assert_eq!(outcome, ManageOutcome::Ok);
    assert_eq!(channel.pin1_counter(), before);
    assert_eq!(
        channel.into_inner().protected_commands(),
        [plain(
            CHANGE_REFERENCE_DATA_INS,
            CHANGE_P1_CURRENT_THEN_NEW,
            PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
            &[SYNTHETIC_PIN1, NEW_PIN1],
        )]
    );
}
