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

//! Public-entry tests for the PACE handshake.
//!
//! The full four-round handshake and its live behaviour are validated on
//! hardware per the admission checklist; these tests read EF.CardAccess
//! through the public reader, drive the public entry point through its
//! first exchange and confirm the error surface, which needs no card.

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, ResponseApdu, StatusWord, TransportOutcome,
};
use refineid_ber::{BerEncoder, BerTag, Integer, Oid, Sequence, Set};
use refineid_pace::{
    Can, CardAccess, PaceDomain, PaceError, PaceMapping, UnvalidatedCan, read_card_access, run_pace,
};

/// A valid six-digit Card Access Number fixture.
const CAN_TEXT: &str = "123456";
/// Instruction byte the opening command carries.
const MSE_INS: u8 = 0x22;
/// Instruction byte of SELECT (ISO/IEC 7816-4 section 11.1.1).
const SELECT_INS: u8 = 0xA4;
/// Instruction byte of READ BINARY (ISO/IEC 7816-4 section 11.2.3).
const READ_BINARY_INS: u8 = 0xB0;
/// Offset of the instruction byte in a command.
const INS_OFFSET: usize = 1;
/// The `PACEInfo` version the cards publish (BSI TR-03110-3 section
/// A.1.1.1).
const PACE_INFO_VERSION: u8 = 2;
/// Length of a PACE protocol object-identifier body, in bytes.
const PACE_PROTOCOL_OID_LEN: usize = 10;
/// DER object identifier body for `id-PACE-ECDH-GM-AES-CBC-CMAC-256`
/// (OID 0.4.0.127.0.7.2.2.4.2.4, BSI TR-03110-3 section A.1.1.1).
const PACE_ECDH_GM_AES_256_OID: [u8; PACE_PROTOCOL_OID_LEN] =
    [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];

fn fixture_can() -> Can {
    Can::reconstruct(UnvalidatedCan::from_owned_text(CAN_TEXT.to_owned()))
        .expect("fixture is a valid CAN")
}

fn tag(marker: u16) -> u8 {
    u8::try_from(marker).expect("universal tags fit one octet")
}

/// A citizen-card EF.CardAccess: one generic-mapping entry over
/// brainpoolP384r1.
fn citizen_card_access_bytes() -> Vec<u8> {
    let mut fields = BerEncoder::default();
    fields
        .push_tlv(tag(Oid::TAG), PACE_ECDH_GM_AES_256_OID)
        .expect("encodes");
    fields
        .push_tlv(tag(Integer::TAG), [PACE_INFO_VERSION])
        .expect("encodes");
    fields
        .push_tlv(
            tag(Integer::TAG),
            [PaceDomain::BrainpoolP384r1.parameter_id()],
        )
        .expect("encodes");
    let info = refineid_ber::tlv(tag(Sequence::TAG), fields.finish()).expect("encodes");
    refineid_ber::tlv(tag(Set::TAG), info).expect("encodes")
}

fn status_response(sw: StatusWord) -> TransportOutcome {
    body_response(Vec::new(), sw)
}

fn body_response(body: Vec<u8>, sw: StatusWord) -> TransportOutcome {
    let [sw1, sw2] = sw.as_u16().to_be_bytes();
    TransportOutcome::Response(ResponseApdu { body, sw1, sw2 })
}

/// A transport that serves EF.CardAccess to SELECT and READ BINARY and
/// answers the first other command with a fixed outcome.
struct ScriptedCard {
    file: Vec<u8>,
    outcome: Option<TransportOutcome>,
    saw_mse: bool,
}

impl CardTransport for ScriptedCard {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        match command.as_bytes().get(INS_OFFSET).copied() {
            Some(SELECT_INS) => Ok(status_response(StatusWord::Success)),
            Some(READ_BINARY_INS) => Ok(body_response(self.file.clone(), StatusWord::Success)),
            Some(MSE_INS) => {
                self.saw_mse = true;
                self.outcome
                    .take()
                    .ok_or_else(|| "no further scripted outcome".to_owned())
            }
            _ => Err("no further scripted outcome".to_owned()),
        }
    }

    fn transmit_credential(
        &mut self,
        _command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        Err("the handshake issues no credential command".to_owned())
    }
}

fn scripted(outcome: TransportOutcome) -> (ScriptedCard, CardAccess) {
    let mut card = ScriptedCard {
        file: citizen_card_access_bytes(),
        outcome: Some(outcome),
        saw_mse: false,
    };
    let card_access = read_card_access(&mut card).expect("EF.CardAccess reads");
    (card, card_access)
}

#[test]
fn card_access_reads_and_names_the_generic_suite() {
    let (_card, card_access) = scripted(status_response(StatusWord::Success));
    let suite = card_access
        .generic_mapping_suite()
        .expect("a generic-mapping suite");
    assert_eq!(suite.mapping(), PaceMapping::Generic);
    assert_eq!(suite.domain(), PaceDomain::BrainpoolP384r1);
}

#[test]
fn opening_status_word_failure_names_the_stage() {
    let (mut card, card_access) = scripted(status_response(StatusWord::SecurityNotSatisfied));
    let can = fixture_can();
    let error = run_pace(&mut card, &card_access, &can).expect_err("a rejected opening fails");
    assert!(card.saw_mse, "the opening MSE:Set AT must be issued");
    assert!(matches!(
        error,
        PaceError::Status("MSE:Set AT", StatusWord::SecurityNotSatisfied)
    ));
}

#[test]
fn transport_state_transition_surfaces_as_an_outcome() {
    let (mut card, card_access) = scripted(TransportOutcome::NoCard);
    let can = fixture_can();
    let error = run_pace(&mut card, &card_access, &can).expect_err("a lost card fails");
    assert!(matches!(
        error,
        PaceError::Outcome(TransportOutcome::NoCard)
    ));
}
