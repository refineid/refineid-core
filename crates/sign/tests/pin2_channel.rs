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

//! The qualified key on a secure channel PIN 2 opened, over the real
//! PACE handshake and the real secure-messaging layer against the
//! synthetic organizational card of `refineid-pace`'s test kit.
//!
//! The expected plain wire is assembled from the crate's own typed
//! command builders; the card side recovers every protected command, so
//! the tests pin what the card received -- and that no VERIFY was among
//! it.

use refineid_apdu::iso7816::{
    SelectByAidNoFci, SelectFile, SelectFileResponseMode, SelectFileTarget,
};
use refineid_apdu::{Aid, ApduClass, FileId, ResponseApdu, StatusWord};
use refineid_auth::verify::VERIFY_INS;
use refineid_auth::{Pin2, PinReferenceScheme, PinSlot, UnvalidatedSecret};
use refineid_pace::testkit::{OrganizationalCard, organizational_card_access};
use refineid_pace::{OpenedByPin2, Pin2PresentationSpent, SmTransport, run_pace};
use refineid_pkcs15::ESIGN_AID;
use refineid_sign::commands::{
    ExternalHashValue, MseSet, PsoComputeDigitalSignature, SHA256_LEN, SignatureAlgRef,
    expected_length_le,
};
use refineid_sign::{
    KeyRef, Pin2ChannelError, Pin2ChannelSignOps as _, RSA_3072_SIG_BYTES, SignOps as _, SignScheme,
};

/// A synthetic PIN 2, ASCII digits within the organizational bounds.
const SYNTHETIC_PIN2: &[u8] = b"246813";
/// Digest filler byte for the fixtures.
const DIGEST_FILL: u8 = 0x5A;
/// Signature filler byte for the fixtures.
const SIG_FILL: u8 = 0xC3;
/// Index of the instruction byte in a plain command (ISO/IEC 7816-4
/// section 5.1).
const INS_INDEX: usize = 1;

fn pin2() -> Pin2 {
    Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(SYNTHETIC_PIN2.to_vec()))
        .expect("valid PIN 2 fixture")
}

fn success(body: Vec<u8>) -> ResponseApdu {
    let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
    ResponseApdu { body, sw1, sw2 }
}

fn select_mf_wire() -> Vec<u8> {
    SelectFile {
        class: ApduClass::Plain,
        target: SelectFileTarget::AnyByFileId(Some(FileId::MF)),
        response_mode: SelectFileResponseMode::None,
    }
    .into_apdu()
    .as_bytes()
    .to_vec()
}

fn select_esign_by_name_wire() -> Vec<u8> {
    SelectByAidNoFci {
        aid: Aid::from_slice(ESIGN_AID).expect("the published name is an AID"),
    }
    .into_apdu()
    .as_bytes()
    .to_vec()
}

fn qualified_mse_wire(alg: SignatureAlgRef) -> Vec<u8> {
    MseSet {
        alg_ref: alg,
        key_ref: KeyRef::Sign.reference(SignScheme::Organizational),
    }
    .into_apdu()
    .expect("MSE:Set encodes")
    .as_bytes()
    .to_vec()
}

fn pso_cds_inline_wire(hash: ExternalHashValue, le: u8) -> Vec<u8> {
    PsoComputeDigitalSignature
        .into_apdu_with_digest(hash, le)
        .expect("inline PSO:CDS encodes")
        .as_bytes()
        .to_vec()
}

/// Open a channel with PACE under PIN 2 against a card that answers the
/// protected commands with `answers`.
fn pin2_channel(answers: Vec<ResponseApdu>) -> SmTransport<OrganizationalCard, OpenedByPin2> {
    let mut card = OrganizationalCard::new(
        PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
        SYNTHETIC_PIN2,
        answers,
    );
    let pin = pin2();
    let session = run_pace(&mut card, &organizational_card_access(), &pin)
        .expect("the synthetic card accepts PIN 2");
    SmTransport::new(card, session)
}

fn no_verify(commands: &[Vec<u8>]) -> bool {
    commands
        .iter()
        .all(|command| command.get(INS_INDEX) != Some(&VERIFY_INS))
}

#[test]
fn a_pin2_channel_enters_esign_and_signs_inline_with_no_verify_on_the_wire() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut channel = pin2_channel(vec![
        success(vec![]),
        success(vec![]),
        success(vec![]),
        success(signature.clone()),
    ]);

    let result = channel
        .qualified_key_after_pin2_pace()
        .expect("the PIN 2 channel unlocks the qualified key")
        .sign_prehashed_sha256_rsa(digest)
        .expect("the synthetic card signs");
    assert_eq!(result.as_bytes(), signature.as_slice());

    let card = channel.into_inner();
    let le = expected_length_le(RSA_3072_SIG_BYTES);
    assert_eq!(
        card.protected_commands(),
        &[
            select_mf_wire(),
            select_esign_by_name_wire(),
            qualified_mse_wire(SignatureAlgRef::SHA256_RSA_PKCS1),
            pso_cds_inline_wire(ExternalHashValue::Sha256(digest), le),
        ],
        "SELECT MF, SELECT DF.ESIGN by name, MSE:Set and one inline PSO:CDS"
    );
    assert!(no_verify(card.protected_commands()));
    assert_eq!(card.credential_commands(), 0, "no PIN crossed the channel");
    assert_eq!(card.answers_left(), 0);
}

#[test]
fn the_presentation_is_spent_once_and_stays_spent_across_a_rebuild() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let mut channel = pin2_channel(vec![
        success(vec![]),
        success(vec![]),
        success(vec![]),
        success(vec![SIG_FILL; RSA_3072_SIG_BYTES]),
    ]);
    channel
        .qualified_key_after_pin2_pace()
        .expect("first key")
        .sign_prehashed_sha256_rsa(digest)
        .expect("first signature");

    let error = channel
        .qualified_key_after_pin2_pace()
        .expect_err("a second key needs a fresh presentation");
    assert!(matches!(
        error,
        Pin2ChannelError::PresentationSpent(Pin2PresentationSpent)
    ));

    let (card, session) = channel.into_parts();
    let mut channel = SmTransport::new(card, session);
    let error = channel
        .qualified_key_after_pin2_pace()
        .expect_err("the rebuilt channel carries the spent presentation");
    assert!(matches!(error, Pin2ChannelError::PresentationSpent(_)));

    let card = channel.into_inner();
    assert_eq!(
        card.protected_commands().len(),
        SIGNATURE_COMMANDS,
        "a spent presentation sends nothing"
    );
}

/// SELECT MF, SELECT DF.ESIGN, MSE:Set and PSO:CDS.
const SIGNATURE_COMMANDS: usize = 4;

#[test]
fn a_second_signature_on_the_channel_takes_a_protected_verify() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut channel = pin2_channel(vec![
        success(vec![]),
        success(vec![]),
        success(vec![]),
        success(signature.clone()),
        success(vec![]),
        success(vec![]),
        success(vec![]),
        success(vec![]),
        success(signature),
    ]);
    channel
        .qualified_key_after_pin2_pace()
        .expect("first key")
        .sign_prehashed_sha256_rsa(digest)
        .expect("first signature");
    channel
        .unlock_qualified_key(SignScheme::Organizational, pin2())
        .expect("the second key verifies PIN 2 on the channel")
        .sign_prehashed_sha256_rsa(digest)
        .expect("second signature");

    let card = channel.into_inner();
    assert_eq!(card.credential_commands(), 1, "one protected VERIFY");
    assert_eq!(card.answers_left(), 0);
}
