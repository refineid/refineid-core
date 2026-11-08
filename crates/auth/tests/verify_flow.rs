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

//! Scripted-transport tests for the VERIFY flow.
//!
//! These exercise the public API through a recording transport and assert
//! behaviour and command structure; the exact byte layout of the wire is
//! pinned by the crate's unit tests, where the framing constants are in
//! scope by name.

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
    TransportOutcome,
};
use refineid_auth::{
    AuthError, FlooredCredential, PIN_STORED_LENGTH, PIN1_REFERENCE, PIN1_REFERENCE_ORGANIZATIONAL,
    PIN2_REFERENCE, Pin1, Pin2, PinOps, PinReferenceScheme, PinSlot, PinStatus, RetryFloorRefusal,
    UnvalidatedSecret, VerifyOutcome,
};

/// A valid PIN1 fixture.
const PIN1_DIGITS: &[u8] = b"1234";
/// A valid PIN2 fixture.
const PIN2_DIGITS: &[u8] = b"654321";
/// A retry count returned on a wrong PIN; also the highest count the
/// retry floor refuses.
const TWO_RETRIES: u8 = 2;
/// A retry count the retry floor serves.
const FIVE_RETRIES: u8 = 5;
/// Wire index of the P2 reference byte.
const P2_INDEX: usize = 3;
/// Length of a header-only VERIFY command: class, instruction, P1, P2.
const HEADER_LENGTH: usize = 4;
/// Wire offset of the command data field: past the header and the Lc byte.
const DATA_OFFSET: usize = 5;

fn pin1() -> Pin1 {
    Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(PIN1_DIGITS.to_vec()))
        .expect("valid PIN1 fixture")
}

fn pin2() -> Pin2 {
    Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(PIN2_DIGITS.to_vec()))
        .expect("valid PIN2 fixture")
}

fn response(sw: StatusWord) -> ResponseApdu {
    let [sw1, sw2] = sw.as_u16().to_be_bytes();
    ResponseApdu {
        body: vec![],
        sw1,
        sw2,
    }
}

/// A transport that records what it was handed and answers the plain
/// path (the counter-safe probe) with `probe_sw` and the credential path
/// with `credential_sw`. A credential command's wire is captured through
/// the consuming exposure so the test can assert the command structure.
struct Recorder {
    plain_wire: Option<Vec<u8>>,
    credential_wire: Option<Vec<u8>>,
    probe_sw: StatusWord,
    credential_sw: StatusWord,
}

impl Recorder {
    /// A card answering every exchange with `sw`.
    fn new(sw: StatusWord) -> Self {
        Self::answering(sw, sw)
    }

    fn answering(probe_sw: StatusWord, credential_sw: StatusWord) -> Self {
        Self {
            plain_wire: None,
            credential_wire: None,
            probe_sw,
            credential_sw,
        }
    }
}

impl CardTransport for Recorder {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        self.plain_wire = Some(command.as_bytes().to_vec());
        Ok(TransportOutcome::Response(response(self.probe_sw)))
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        self.credential_wire = Some(command.expose_wire(<[u8]>::to_vec));
        Ok(TransportOutcome::Response(response(self.credential_sw)))
    }
}

fn counter(count: u8) -> StatusWord {
    StatusWord::PinIncorrect {
        retries: PinRetries::from_nibble(count).expect("fits a nibble"),
    }
}

#[test]
fn verify_pin1_ships_the_padded_block_as_a_credential_command() {
    let mut transport = Recorder::new(StatusWord::Success);
    let outcome = transport
        .verify_pin1_with_scheme(PinReferenceScheme::Citizen, pin1())
        .expect("scripted verify succeeds");
    assert_eq!(outcome, VerifyOutcome::Ok);
    let wire = transport
        .credential_wire
        .expect("the PIN must travel through the credential path");
    assert_eq!(wire.get(P2_INDEX).copied(), Some(PIN1_REFERENCE));
    // The citizen data field is the digits right-padded to the stored length.
    let data = &wire[DATA_OFFSET..];
    assert_eq!(data.len(), PIN_STORED_LENGTH);
    assert_eq!(&data[..PIN1_DIGITS.len()], PIN1_DIGITS);
    let probe = transport
        .plain_wire
        .expect("the VERIFY reads the counter first");
    assert_eq!(
        probe.len(),
        HEADER_LENGTH,
        "the only plain command is the counter-safe probe, with no data"
    );
    assert_eq!(probe.get(P2_INDEX).copied(), Some(PIN1_REFERENCE));
}

#[test]
fn a_verify_at_two_tries_left_is_refused_with_no_digits_on_the_wire() {
    let mut transport = Recorder::answering(counter(TWO_RETRIES), StatusWord::Success);
    let refused = transport.verify_pin1_with_scheme(PinReferenceScheme::Citizen, pin1());
    assert!(matches!(
        refused,
        Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
            credential: FlooredCredential::Pin1,
            ..
        }))
    ));
    assert!(
        transport.credential_wire.is_none(),
        "no VERIFY carried digits"
    );
    assert_eq!(
        transport.plain_wire.map(|wire| wire.len()),
        Some(HEADER_LENGTH),
        "only the counter-safe probe was sent"
    );
}

#[test]
fn verify_pin2_targets_the_qualified_signature_reference() {
    let mut transport = Recorder::new(StatusWord::Success);
    transport
        .verify_pin2_with_scheme(PinReferenceScheme::Citizen, pin2())
        .expect("scripted verify succeeds");
    let wire = transport
        .credential_wire
        .expect("credential command was sent");
    assert_eq!(wire.get(P2_INDEX).copied(), Some(PIN2_REFERENCE));
    let distinct_references = PIN2_REFERENCE != PIN1_REFERENCE;
    assert!(distinct_references);
}

#[test]
fn organizational_verify_sends_the_typed_length_block_under_the_org_reference() {
    let mut transport = Recorder::new(StatusWord::Success);
    transport
        .verify_pin1_with_scheme(PinReferenceScheme::Organizational, pin1())
        .expect("scripted verify succeeds");
    let wire = transport
        .credential_wire
        .expect("credential command was sent");
    assert_eq!(
        wire.get(P2_INDEX).copied(),
        Some(PIN1_REFERENCE_ORGANIZATIONAL)
    );
    // The organizational data field is the bare typed digits: no padding.
    let data = &wire[DATA_OFFSET..];
    assert_eq!(data, PIN1_DIGITS);
}

#[test]
fn resolution_picks_organizational_when_citizen_is_not_found() {
    // The card answers reference-not-found under the citizen numbering,
    // then a real retry state, one the floor serves, under the
    // organizational numbering.
    let mut transport = SchemeAware {
        citizen_probe: StatusWord::ReferenceDataNotFound,
        organizational_probe: counter(FIVE_RETRIES),
        credential_wire: None,
    };
    let scheme = transport
        .resolve_pin_reference_scheme()
        .expect("resolution succeeds");
    assert_eq!(scheme, PinReferenceScheme::Organizational);

    transport
        .verify_pin1_with_scheme(scheme, pin1())
        .expect("scripted verify succeeds");
    let wire = transport.credential_wire.expect("credential command sent");
    assert_eq!(
        wire.get(P2_INDEX).copied(),
        Some(PIN1_REFERENCE_ORGANIZATIONAL)
    );
}

#[test]
fn a_wrong_pin_reports_the_remaining_retries() {
    let two = PinRetries::from_nibble(TWO_RETRIES).expect("fits a nibble");
    let mut transport = Recorder::answering(counter(FIVE_RETRIES), counter(TWO_RETRIES));
    let outcome = transport
        .verify_pin1(pin1())
        .expect("scripted verify completes");
    assert_eq!(outcome, VerifyOutcome::WrongPin { retries_left: two });
}

#[test]
fn a_blocked_slot_reports_locked() {
    let mut transport = Recorder::new(StatusWord::AuthenticationBlocked);
    let outcome = transport
        .verify_pin1(pin1())
        .expect("scripted verify completes");
    assert_eq!(outcome, VerifyOutcome::Locked);
}

#[test]
fn the_status_probe_uses_the_plain_path_and_sends_no_data() {
    let mut transport = Recorder::new(StatusWord::Success);
    let status = transport
        .pin_status(PinSlot::Pin1)
        .expect("scripted probe succeeds");
    assert_eq!(status, PinStatus::Verified);
    let wire = transport.plain_wire.expect("a plain command was sent");
    assert_eq!(wire.len(), HEADER_LENGTH, "the probe carries no data field");
    assert_eq!(wire.get(P2_INDEX).copied(), Some(PIN1_REFERENCE));
    assert!(
        transport.credential_wire.is_none(),
        "the counter-safe probe carries no credential"
    );
}

/// A transport that answers the counter-safe probe differently under the
/// citizen and organizational references, so resolution can be driven,
/// and records the credential command it is later handed.
struct SchemeAware {
    citizen_probe: StatusWord,
    organizational_probe: StatusWord,
    credential_wire: Option<Vec<u8>>,
}

impl CardTransport for SchemeAware {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let reference = command.as_bytes().get(P2_INDEX).copied();
        let sw = if reference == Some(PIN1_REFERENCE) {
            self.citizen_probe
        } else {
            self.organizational_probe
        };
        Ok(TransportOutcome::Response(response(sw)))
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        self.credential_wire = Some(command.expose_wire(<[u8]>::to_vec));
        Ok(TransportOutcome::Response(response(StatusWord::Success)))
    }
}
