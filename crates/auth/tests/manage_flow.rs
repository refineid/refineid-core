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

//! Scripted-transport tests for the change and unblock flows through the
//! public, scheme-resolving entry points.

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
    TransportOutcome,
};
use refineid_auth::{
    ActivationCode, ActivationScheme, AuthError, FlooredCredential, ManageOutcome, PIN1_REFERENCE,
    PIN1_REFERENCE_ORGANIZATIONAL, PIN2_REFERENCE, PIN2_REFERENCE_ORGANIZATIONAL, PUK_REFERENCE,
    PUK_REFERENCE_ORGANIZATIONAL, Pin1, Pin2, PinManageOps, Puk, RetryFloorRefusal,
    UnvalidatedSecret,
};

/// Wire index of the P2 reference byte.
const P2_INDEX: usize = 3;
/// A retry count returned on a wrong credential.
const TWO_RETRIES: u8 = 2;
/// Retry count of a pristine credential.
const RETRIES_PRISTINE: u8 = 5;
/// Lowest retry count the floor serves.
const RETRIES_FLOOR: u8 = 3;
/// Retry count one wrong try from lockout.
const RETRIES_LOCKDOWN_IMMINENT: u8 = 1;
/// Credential commands the organizational unblock sends: a VERIFY then
/// a RESET.
const ORG_UNBLOCK_COMMAND_COUNT: usize = 2;
/// Credential commands an activation of both blocked PINs sends: one
/// RESET RETRY COUNTER per PIN.
const ACTIVATION_COMMAND_COUNT: usize = 2;
/// A valid PUK fixture, eight digits.
const PUK_DIGITS: &[u8] = b"12345678";

fn counter(count: u8) -> StatusWord {
    StatusWord::PinIncorrect {
        retries: PinRetries::from_nibble(count).expect("fits a nibble"),
    }
}

fn response(sw: StatusWord) -> ResponseApdu {
    let [sw1, sw2] = sw.as_u16().to_be_bytes();
    ResponseApdu {
        body: vec![],
        sw1,
        sw2,
    }
}

fn pin1(digits: &[u8]) -> Pin1 {
    Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(digits.to_vec()))
        .expect("valid PIN1 fixture")
}

fn pin2(digits: &[u8]) -> Pin2 {
    Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(digits.to_vec()))
        .expect("valid PIN2 fixture")
}

fn activation_code(digits: &[u8]) -> ActivationCode {
    ActivationCode::reconstruct(
        UnvalidatedSecret::from_owned_bytes(digits.to_vec()),
        ActivationScheme::ActivationCodeIsPuk,
    )
    .expect("valid activation-code fixture")
}

fn puk(digits: &[u8]) -> Puk {
    Puk::reconstruct(UnvalidatedSecret::from_owned_bytes(digits.to_vec()))
        .expect("valid PUK fixture")
}

/// A transport that answers the counter-safe probes by P2 -- so a
/// session resolves its numbering and reads the PUK's counter -- then
/// records the credential commands it is handed and answers each from a
/// scripted queue.
struct ResolvingRecorder {
    citizen_probe: StatusWord,
    organizational_probe: StatusWord,
    puk_probe: StatusWord,
    responses: Vec<StatusWord>,
    cursor: usize,
    commands: Vec<Vec<u8>>,
}

impl CardTransport for ResolvingRecorder {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let sw = match command.as_bytes().get(P2_INDEX).copied() {
            Some(PIN1_REFERENCE | PIN2_REFERENCE) => self.citizen_probe,
            Some(PUK_REFERENCE | PUK_REFERENCE_ORGANIZATIONAL) => self.puk_probe,
            _ => self.organizational_probe,
        };
        Ok(TransportOutcome::Response(response(sw)))
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        self.commands.push(command.expose_wire(<[u8]>::to_vec));
        let sw = *self
            .responses
            .get(self.cursor)
            .ok_or_else(|| format!("script exhausted at command {}", self.cursor))?;
        self.cursor += 1;
        Ok(TransportOutcome::Response(response(sw)))
    }
}

#[test]
fn change_pin1_resolves_the_citizen_numbering_then_updates() {
    // The citizen probe answers a real state, so resolution settles on
    // the citizen numbering without a second probe.
    let mut transport = ResolvingRecorder {
        citizen_probe: StatusWord::Success,
        organizational_probe: StatusWord::ReferenceDataNotFound,
        puk_probe: counter(RETRIES_PRISTINE),
        responses: vec![StatusWord::Success],
        cursor: 0,
        commands: vec![],
    };
    let outcome = transport
        .change_pin1(pin1(b"1234"), pin1(b"5678"))
        .expect("scripted change succeeds");
    assert_eq!(outcome, ManageOutcome::Ok);
    assert_eq!(transport.commands.len(), 1);
    assert_eq!(
        transport.commands[0].get(P2_INDEX).copied(),
        Some(PIN1_REFERENCE)
    );
}

#[test]
fn unblock_pin1_resolves_organizational_then_sends_the_two_command_flow() {
    // The citizen probe answers reference-not-found, so resolution
    // re-probes and settles on the organizational numbering.
    let two = PinRetries::from_nibble(TWO_RETRIES).expect("fits a nibble");
    let mut transport = ResolvingRecorder {
        citizen_probe: StatusWord::ReferenceDataNotFound,
        organizational_probe: StatusWord::PinIncorrect { retries: two },
        puk_probe: counter(RETRIES_FLOOR),
        responses: vec![StatusWord::Success, StatusWord::Success],
        cursor: 0,
        commands: vec![],
    };
    let outcome = transport
        .unblock_pin1(puk(PUK_DIGITS), pin1(b"5678"))
        .expect("scripted unblock succeeds");
    assert_eq!(outcome, ManageOutcome::Ok);
    assert_eq!(transport.commands.len(), ORG_UNBLOCK_COMMAND_COUNT);
    // First the PUK is verified under the organizational PUK reference,
    // then the reset targets the organizational PIN1 reference.
    assert_eq!(
        transport.commands[0].get(P2_INDEX).copied(),
        Some(PUK_REFERENCE_ORGANIZATIONAL)
    );
    assert_eq!(
        transport.commands[1].get(P2_INDEX).copied(),
        Some(PIN1_REFERENCE_ORGANIZATIONAL)
    );
}

#[test]
fn unblock_refuses_a_puk_below_the_floor_whatever_the_pin_counter() {
    // PIN 1 has five tries left; the PUK has one. Nothing carrying the
    // PUK goes out.
    let mut transport = ResolvingRecorder {
        citizen_probe: counter(RETRIES_PRISTINE),
        organizational_probe: StatusWord::ReferenceDataNotFound,
        puk_probe: counter(RETRIES_LOCKDOWN_IMMINENT),
        responses: vec![StatusWord::Success],
        cursor: 0,
        commands: vec![],
    };
    let refused = transport.unblock_pin1(puk(PUK_DIGITS), pin1(b"5678"));
    assert!(matches!(
        refused,
        Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
            credential: FlooredCredential::Puk,
            ..
        }))
    ));
    assert!(transport.commands.is_empty());
}

#[test]
fn unblock_serves_a_blocked_pin_while_the_puk_counter_is_at_the_floor() {
    let mut transport = ResolvingRecorder {
        citizen_probe: StatusWord::AuthenticationBlocked,
        organizational_probe: StatusWord::ReferenceDataNotFound,
        puk_probe: counter(RETRIES_FLOOR),
        responses: vec![StatusWord::Success],
        cursor: 0,
        commands: vec![],
    };
    let outcome = transport
        .unblock_pin2(puk(PUK_DIGITS), pin2(b"567890"))
        .expect("the PUK counter is at the floor");
    assert_eq!(outcome, ManageOutcome::Ok);
    assert_eq!(transport.commands.len(), 1);
}

#[test]
fn activation_with_the_code_as_puk_follows_the_puk_floor() {
    let activate = |puk_probe| {
        let mut transport = ResolvingRecorder {
            citizen_probe: StatusWord::AuthenticationBlocked,
            organizational_probe: StatusWord::ReferenceDataNotFound,
            puk_probe,
            responses: vec![StatusWord::Success, StatusWord::Success],
            cursor: 0,
            commands: vec![],
        };
        let result = transport.activate_card(
            activation_code(PUK_DIGITS),
            Some(pin1(b"5678")),
            Some(pin2(b"567890")),
        );
        (result, transport.commands.len())
    };

    let (served, sent) = activate(counter(RETRIES_FLOOR));
    let report = served.expect("the PUK counter is at the floor");
    assert_eq!(report.pin1, Some(ManageOutcome::Ok));
    assert_eq!(report.pin2, Some(ManageOutcome::Ok));
    assert_eq!(sent, ACTIVATION_COMMAND_COUNT);

    for probe in [
        counter(TWO_RETRIES),
        counter(RETRIES_LOCKDOWN_IMMINENT),
        StatusWord::AuthenticationBlocked,
    ] {
        let (refused, sent) = activate(probe);
        assert!(matches!(
            refused,
            Err(AuthError::RetryFloor(refusal))
                if refusal.credential() == FlooredCredential::Puk
        ));
        assert_eq!(sent, 0);
    }
}

/// An authentication certificate validity start before 13 January 2026.
const VALID_FROM_BEFORE_CUTOVER: i64 = 1_700_000_000;
/// An authentication certificate validity start after 13 January 2026.
const VALID_FROM_AFTER_CUTOVER: i64 = 1_800_000_000;
/// Retry count of a PIN blocked at the factory and reported as a counter.
const RETRIES_EXHAUSTED: u8 = 0;
/// Credential commands an organizational activation of both PINs sends:
/// a PUK VERIFY then a RESET RETRY COUNTER per PIN.
const ORG_ACTIVATION_COMMAND_COUNT: usize = 4;

/// An organization card fresh from the factory: the citizen reference is
/// not found, the organizational PINs answer an exhausted counter, and
/// the PIN container does not answer the citizen-numbered GET DATA.
fn factory_organization_card() -> ResolvingRecorder {
    ResolvingRecorder {
        citizen_probe: StatusWord::ReferenceDataNotFound,
        organizational_probe: counter(RETRIES_EXHAUSTED),
        puk_probe: counter(RETRIES_PRISTINE),
        responses: vec![StatusWord::Success; ORG_ACTIVATION_COMMAND_COUNT],
        cursor: 0,
        commands: vec![],
    }
}

#[test]
fn health_of_an_organization_card_is_the_puk_scheme_whatever_the_date() {
    for validity_start in [
        Some(VALID_FROM_BEFORE_CUTOVER),
        Some(VALID_FROM_AFTER_CUTOVER),
        None,
    ] {
        let report = factory_organization_card()
            .probe_credential_health(validity_start)
            .expect("scripted probe completes");
        assert_eq!(
            report.activation_scheme,
            Some(ActivationScheme::ActivationCodeIsPuk)
        );
        let needs = report.activation_needs.expect("a scheme was decided");
        assert!(needs.pin1 && needs.pin2);
    }
}

#[test]
fn health_of_a_citizen_card_follows_the_validity_start() {
    let citizen_card = || ResolvingRecorder {
        citizen_probe: StatusWord::AuthenticationBlocked,
        organizational_probe: StatusWord::ReferenceDataNotFound,
        puk_probe: counter(RETRIES_PRISTINE),
        responses: vec![],
        cursor: 0,
        commands: vec![],
    };
    let before = citizen_card()
        .probe_credential_health(Some(VALID_FROM_BEFORE_CUTOVER))
        .expect("scripted probe completes");
    assert_eq!(
        before.activation_scheme,
        Some(ActivationScheme::ActivationCodeIsPuk)
    );
    let needs = before.activation_needs.expect("a scheme was decided");
    assert!(needs.pin1 && needs.pin2);

    // Section 4.6.2 with the flag unreadable makes no activation decision,
    // whatever the counter says.
    let after = citizen_card()
        .probe_credential_health(Some(VALID_FROM_AFTER_CUTOVER))
        .expect("scripted probe completes");
    assert_eq!(
        after.activation_scheme,
        Some(ActivationScheme::PresetActivationPin)
    );
    let needs = after.activation_needs.expect("a scheme was decided");
    assert!(!needs.any());

    let unread = citizen_card()
        .probe_credential_health(None)
        .expect("scripted probe completes");
    assert_eq!(unread.activation_scheme, None);
    assert_eq!(unread.activation_needs, None);
}

#[test]
fn organization_card_activation_resets_each_pin_under_the_organizational_numbering() {
    let mut transport = factory_organization_card();
    let report = transport
        .activate_card(
            activation_code(PUK_DIGITS),
            Some(pin1(b"5678")),
            Some(pin2(b"567890")),
        )
        .expect("the PUK counter is pristine");
    assert_eq!(report.scheme, ActivationScheme::ActivationCodeIsPuk);
    assert_eq!(report.pin1, Some(ManageOutcome::Ok));
    assert_eq!(report.pin2, Some(ManageOutcome::Ok));
    let references: Vec<Option<u8>> = transport
        .commands
        .iter()
        .map(|wire| wire.get(P2_INDEX).copied())
        .collect();
    assert_eq!(
        references,
        [
            Some(PUK_REFERENCE_ORGANIZATIONAL),
            Some(PIN1_REFERENCE_ORGANIZATIONAL),
            Some(PUK_REFERENCE_ORGANIZATIONAL),
            Some(PIN2_REFERENCE_ORGANIZATIONAL),
        ]
    );
}

/// A PIN at the longest length either role accepts.
const LONGEST_DIGITS: &[u8] = b"135792468024";
/// Wire offset of the data field: past the header and the Lc byte.
const DATA_OFFSET: usize = 5;

#[test]
fn organization_card_activation_sets_twelve_digit_pins_unpadded() {
    let mut transport = factory_organization_card();
    let report = transport
        .activate_card(
            activation_code(PUK_DIGITS),
            Some(pin1(LONGEST_DIGITS)),
            Some(pin2(LONGEST_DIGITS)),
        )
        .expect("the PUK counter is pristine");
    assert_eq!(report.pin1, Some(ManageOutcome::Ok));
    assert_eq!(report.pin2, Some(ManageOutcome::Ok));
    let resets: Vec<(Option<u8>, &[u8])> = transport
        .commands
        .iter()
        .filter(|wire| {
            matches!(
                wire.get(P2_INDEX).copied(),
                Some(PIN1_REFERENCE_ORGANIZATIONAL | PIN2_REFERENCE_ORGANIZATIONAL)
            )
        })
        .map(|wire| (wire.get(P2_INDEX).copied(), &wire[DATA_OFFSET..]))
        .collect();
    assert_eq!(
        resets,
        [
            (Some(PIN1_REFERENCE_ORGANIZATIONAL), LONGEST_DIGITS),
            (Some(PIN2_REFERENCE_ORGANIZATIONAL), LONGEST_DIGITS),
        ]
    );
}
