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

//! Scripted-transport tests for the signing choreography.
//!
//! The scripted expectations are assembled from the crate's own typed
//! command builders, so the test pins the *choreography* - which commands
//! the chain issues and in what order - while the exact byte layout of
//! each command is pinned by the command builders' unit tests.

use refineid_apdu::iso7816::{
    SelectByAidNoFci, SelectFile, SelectFileResponseMode, SelectFileTarget,
};
use refineid_apdu::{
    Aid, ApduClass, CardTransport, CommandApdu, CommandHeader, CredentialCommand, FileId,
    PinRetries, ResponseApdu, StatusWord, TransportOutcome,
};
use refineid_auth::verify::{VERIFY_INS, VERIFY_P1};
use refineid_auth::{
    AuthError, FlooredCredential, PIN_STORED_LENGTH, Pin2, PinReferenceScheme, PinSlot,
    RetryFloorRefusal, UnvalidatedSecret, VerifyOutcome,
};
use refineid_pkcs15::{DF_ESIGN_FID, ESIGN_AID, Pkcs15Error};
use refineid_sign::commands::{
    DecipherAlgRef, ExternalHashValue, MseSet, MseSetCt, PsoComputeDigitalSignature, PsoDecipher,
    PsoHashExternal, SHA256_LEN, SHA384_LEN, SHA512_LEN, SignatureAlgRef, expected_length_le,
};
use refineid_sign::{
    ECDSA_P256_SIG_BYTES, ECDSA_P384_SIG_BYTES, ESTONIAN_QUALIFIED_KEY_REF, KEY_REF_AUTH,
    KEY_REF_SIGN, KeyRef, ORG_QUALIFIED_KEY_REF, QualifiedSignSession, QualifiedUnlockError,
    RSA_3072_SIG_BYTES, RsaCryptogram, SignError, SignOps, SignScheme,
};

/// Digest filler byte for the fixtures.
const DIGEST_FILL: u8 = 0x5A;
/// Signature filler byte for the fixtures.
const SIG_FILL: u8 = 0xC3;
/// The counter a refused VERIFY reports.
const TRIES_AFTER_WRONG: u8 = 4;
/// The counter of a pristine PIN 2, which the retry floor serves.
const TRIES_PRISTINE: u8 = 5;
/// The counter of a pristine Estonian PIN 2, which the retry floor serves.
const ESTONIAN_TRIES_PRISTINE: u8 = 3;
/// The lowest counter the retry floor serves (two tries left).
const ESTONIAN_TRIES_FLOOR: u8 = 2;
/// The highest counter the retry floor refuses (the last try).
const TRIES_BELOW_FLOOR: u8 = 1;
/// GET DATA instruction byte (ISO 7816-4 / GED24035_015 section 8.3.4).
const GET_DATA_INS: u8 = 0xCB;
/// GET DATA P1/P2/Le bytes for the PIN-container query.
const GET_DATA_P1: u8 = 0x00;
const GET_DATA_P2: u8 = 0xFF;
const GET_DATA_LE: u8 = 0x00;
const PIN_CONTAINER_TEMPLATE_TAG: u8 = 0xA0;
const PIN_CONTAINER_TEMPLATE_LEN: u8 = 3;
const PIN_CONTAINER_REF_TAG: u8 = 0x83;
const PIN_CONTAINER_REF_LEN: u8 = 1;
const PIN_CHANGED_TAG_HIGH: u8 = 0xDF;
const PIN_CHANGED_TAG_LOW: u8 = 0x2F;
const PIN_CHANGED_LEN: u8 = 1;
const PIN_CHANGED_FLAG_UNCHANGED: u8 = 0x00;
const PIN_CHANGED_FLAG_CHANGED: u8 = 0x01;
const GET_DATA_LC: u8 = 5;
/// SELECT P1 for a child DF under the current DF, the fallback the
/// directory walk tries second (FINEID S1 v4.2 section 3.2.2).
const SELECT_CHILD_DF_P1: u8 = 0x01;

fn success(body: Vec<u8>) -> ResponseApdu {
    let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
    ResponseApdu { body, sw1, sw2 }
}

fn mse_wire(scheme: SignScheme, alg: SignatureAlgRef, key: KeyRef) -> Vec<u8> {
    MseSet {
        alg_ref: alg,
        key_ref: key
            .reference(scheme)
            .expect("supported key under signing scheme"),
    }
    .into_apdu()
    .expect("MSE:Set encodes")
    .as_bytes()
    .to_vec()
}

fn pso_hash_wire(hash: ExternalHashValue) -> Vec<u8> {
    PsoHashExternal { hash }
        .into_apdu()
        .expect("PSO:HASH encodes")
        .as_bytes()
        .to_vec()
}

fn pso_cds_empty_wire(le: u8) -> Vec<u8> {
    PsoComputeDigitalSignature.into_apdu(le).as_bytes().to_vec()
}

fn pso_cds_inline_wire(hash: ExternalHashValue, le: u8) -> Vec<u8> {
    PsoComputeDigitalSignature
        .into_apdu_with_digest(hash, le)
        .expect("inline PSO:CDS encodes")
        .as_bytes()
        .to_vec()
}

/// The expected-length Le for an RSA-3072 signature: it exceeds the short
/// form, so the maximum encoding.
fn rsa_le() -> u8 {
    expected_length_le(RSA_3072_SIG_BYTES)
}

/// The expected-length Le for a P-384 ECDSA signature: it fits the short
/// form, so its exact length.
fn ecdsa_le() -> u8 {
    expected_length_le(ECDSA_P384_SIG_BYTES)
}

/// The expected-length Le for a P-256 ECDSA signature: it fits the short
/// form, so its exact length.
fn ecdsa_p256_le() -> u8 {
    expected_length_le(ECDSA_P256_SIG_BYTES)
}

/// Which transport path a scripted command must arrive on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Path {
    /// The plain path: every signing and selection command.
    Plain,
    /// The credential path: VERIFY carrying the PIN.
    Credential,
}

/// A transport that checks each command, and the path it arrives on,
/// against a scripted expectation and returns the paired response.
#[derive(Debug)]
struct Scripted {
    steps: Vec<(Path, Vec<u8>, ResponseApdu)>,
    cursor: usize,
}

impl Scripted {
    /// A script of plain-path commands only.
    fn new(steps: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
        Self::with_paths(
            steps
                .into_iter()
                .map(|(wire, response)| (Path::Plain, wire, response))
                .collect(),
        )
    }

    fn with_paths(steps: Vec<(Path, Vec<u8>, ResponseApdu)>) -> Self {
        Self { steps, cursor: 0 }
    }

    fn drained(&self) -> bool {
        self.cursor == self.steps.len()
    }

    fn answer(&mut self, path: Path, wire: &[u8]) -> Result<TransportOutcome, String> {
        let (expected_path, expected, response) = self
            .steps
            .get(self.cursor)
            .ok_or_else(|| format!("script exhausted at step {}", self.cursor))?;
        if *expected_path != path || expected != wire {
            return Err(format!("unexpected command at step {}", self.cursor));
        }
        self.cursor += 1;
        Ok(TransportOutcome::Response(response.clone()))
    }
}

impl CardTransport for Scripted {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        self.answer(Path::Plain, command.as_bytes())
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        let wire = command.expose_wire(<[u8]>::to_vec);
        self.answer(Path::Credential, &wire)
    }
}

/// A synthetic PIN 2 in the shape both numberings accept.
const SYNTHETIC_PIN2: &[u8] = b"135790";

fn pin2() -> Pin2 {
    Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(SYNTHETIC_PIN2.to_vec()))
        .expect("valid PIN 2 fixture")
}

/// SELECT MF by its file identifier, the first variant the directory
/// walk tries.
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

/// SELECT DF.ESIGN by its published name.
fn select_esign_by_name_wire() -> Vec<u8> {
    SelectByAidNoFci {
        aid: Aid::from_slice(ESIGN_AID).expect("the published name is an AID"),
    }
    .into_apdu()
    .as_bytes()
    .to_vec()
}

/// The counter-safe probe of PIN 2 under `scheme`: a VERIFY header with
/// no data field, which every VERIFY carrying PIN 2 sends first.
fn probe_pin2_wire(scheme: PinReferenceScheme) -> Vec<u8> {
    vec![
        ApduClass::Plain.as_byte(),
        VERIFY_INS,
        VERIFY_P1,
        scheme.reference(PinSlot::Pin2),
    ]
}

/// The probe's answer at `tries` left, a count the retry floor serves.
fn probe_served(tries: u8) -> ResponseApdu {
    status(StatusWord::PinIncorrect {
        retries: PinRetries::from_nibble(tries).expect("counter value"),
    })
}

/// VERIFY PIN 2 under `scheme`: the organizational card is sent the bare
/// digits, citizen and Estonian cards the block padded to the stored length.
fn verify_pin2_wire(scheme: PinReferenceScheme) -> Vec<u8> {
    let mut body = SYNTHETIC_PIN2.to_vec();
    if matches!(
        scheme,
        PinReferenceScheme::Citizen | PinReferenceScheme::Estonian
    ) {
        body.resize(PIN_STORED_LENGTH, scheme.pad().octet());
    }
    let mut wire = vec![
        ApduClass::Plain.as_byte(),
        VERIFY_INS,
        VERIFY_P1,
        scheme.reference(PinSlot::Pin2),
        u8::try_from(body.len()).expect("a PIN block fits a short Lc"),
    ];
    wire.extend_from_slice(&body);
    wire
}

fn status(sw: StatusWord) -> ResponseApdu {
    let [sw1, sw2] = sw.as_u16().to_be_bytes();
    ResponseApdu {
        body: vec![],
        sw1,
        sw2,
    }
}

#[test]
fn citizen_rsa_sha256_drives_the_three_command_chain() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA256_RSA_PKCS1,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha256(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(rsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha256_rsa(digest)
        .expect("scripted RSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), RSA_3072_SIG_BYTES);
    assert!(transport.drained());
}

#[test]
fn citizen_rsa_sha384_drives_the_three_command_chain() {
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA384_RSA_PKCS1,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha384(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(rsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha384_rsa(digest)
        .expect("scripted SHA-384 RSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), RSA_3072_SIG_BYTES);
    assert!(transport.drained());
}

#[test]
fn citizen_rsa_sha512_drives_the_three_command_chain() {
    let digest = [DIGEST_FILL; SHA512_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA512_RSA_PKCS1,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha512(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(rsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha512_rsa(digest)
        .expect("scripted SHA-512 RSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), RSA_3072_SIG_BYTES);
    assert!(transport.drained());
}

#[test]
fn citizen_qualified_ecdsa_p384_verifies_pin2_in_place_and_signs_over_the_loaded_hash() {
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    // No SELECT: the citizen card is sent PIN 2 in the context the caller
    // selected, then the three-command chain under the citizen key
    // reference.
    let mse = mse_wire(
        SignScheme::Citizen,
        SignatureAlgRef::SHA384_ECDSA,
        KeyRef::Sign,
    );
    assert_eq!(mse.last().copied(), Some(KEY_REF_SIGN));
    let mut transport = Scripted::with_paths(vec![
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Citizen),
            probe_served(TRIES_PRISTINE),
        ),
        (
            Path::Credential,
            verify_pin2_wire(PinReferenceScheme::Citizen),
            success(vec![]),
        ),
        (Path::Plain, mse, success(vec![])),
        (
            Path::Plain,
            pso_hash_wire(ExternalHashValue::Sha384(digest)),
            success(vec![]),
        ),
        (
            Path::Plain,
            pso_cds_empty_wire(ecdsa_le()),
            success(signature.clone()),
        ),
    ]);

    let result = transport
        .unlock_qualified_key(SignScheme::Citizen, pin2())
        .expect("scripted PIN 2 is accepted")
        .sign_prehashed_sha384_ecdsa(digest)
        .expect("scripted ECDSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(transport.drained());
}

#[test]
fn citizen_ecdsa_p384_sha256_uses_the_negotiated_hash_reference() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA256_ECDSA,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha256(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(ecdsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha256_ecdsa(digest)
        .expect("scripted SHA-256 ECDSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(transport.drained());
}

/// The organizational qualified sequence up to the signature: SELECT MF,
/// SELECT DF.ESIGN by name, the counter-safe probe of PIN 2, VERIFY
/// PIN 2 under the organizational reference there, and MSE:Set naming
/// the DF.ESIGN-local key.
fn organizational_unlock_steps(alg: SignatureAlgRef) -> Vec<(Path, Vec<u8>, ResponseApdu)> {
    let mse = mse_wire(SignScheme::Organizational, alg, KeyRef::Sign);
    // The organizational qualified key is named by its local reference,
    // the last byte of the MSE:Set control-reference body.
    assert_eq!(mse.last().copied(), Some(ORG_QUALIFIED_KEY_REF));
    vec![
        (Path::Plain, select_mf_wire(), success(vec![])),
        (Path::Plain, select_esign_by_name_wire(), success(vec![])),
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Organizational),
            probe_served(TRIES_PRISTINE),
        ),
        (
            Path::Credential,
            verify_pin2_wire(PinReferenceScheme::Organizational),
            success(vec![]),
        ),
        (Path::Plain, mse, success(vec![])),
    ]
}

#[test]
fn organizational_qualified_rsa_enters_esign_verifies_pin2_and_signs_inline() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut steps = organizational_unlock_steps(SignatureAlgRef::SHA256_RSA_PKCS1);
    steps.push((
        Path::Plain,
        pso_cds_inline_wire(ExternalHashValue::Sha256(digest), rsa_le()),
        success(signature.clone()),
    ));
    let mut transport = Scripted::with_paths(steps);

    let result = transport
        .unlock_qualified_key(SignScheme::Organizational, pin2())
        .expect("scripted PIN 2 is accepted in DF.ESIGN")
        .sign_prehashed_sha256_rsa(digest)
        .expect("scripted organizational RSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(
        transport.drained(),
        "SELECT MF, SELECT DF.ESIGN, the probe, VERIFY, MSE:Set and one PSO:CDS, nothing else"
    );
}

#[test]
fn organizational_qualified_ecdsa_skips_pso_hash_and_carries_the_digest_inline() {
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mut steps = organizational_unlock_steps(SignatureAlgRef::SHA384_ECDSA);
    steps.push((
        Path::Plain,
        pso_cds_inline_wire(ExternalHashValue::Sha384(digest), ecdsa_le()),
        success(signature.clone()),
    ));
    let mut transport = Scripted::with_paths(steps);

    let result = transport
        .unlock_qualified_key(SignScheme::Organizational, pin2())
        .expect("scripted PIN 2 is accepted in DF.ESIGN")
        .sign_prehashed_sha384_ecdsa(digest)
        .expect("scripted organizational sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(transport.drained());
}

#[test]
fn organizational_authentication_key_signs_inline_without_entering_esign() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mse = mse_wire(
        SignScheme::Organizational,
        SignatureAlgRef::SHA256_RSA_PSS,
        KeyRef::Auth,
    );
    assert_eq!(mse.last().copied(), Some(KEY_REF_AUTH));
    let mut transport = Scripted::new(vec![
        (mse, success(vec![])),
        (
            pso_cds_inline_wire(ExternalHashValue::Sha256(digest), rsa_le()),
            success(signature.clone()),
        ),
    ]);

    let result = transport
        .authentication_key(SignScheme::Organizational)
        .sign_prehashed_sha256_rsa_pss(digest)
        .expect("scripted organizational authentication sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(transport.drained());
}

#[test]
fn a_refused_esign_directory_sends_no_pin2() {
    let not_found = status(StatusWord::FileNotFound);
    // Every DF.ESIGN variant is refused: by name, then the two file-
    // identifier forms. The script ends there, so a VERIFY would fail it.
    let child_df = CommandApdu::case_3(
        CommandHeader {
            class: ApduClass::Plain,
            instruction: SelectFile::INS,
            p1: SELECT_CHILD_DF_P1,
            p2: SelectFileResponseMode::None.as_p2(),
        },
        DF_ESIGN_FID.as_bytes(),
    )
    .expect("child-DF SELECT encodes");
    let any_file = SelectFile {
        class: ApduClass::Plain,
        target: SelectFileTarget::AnyByFileId(Some(DF_ESIGN_FID)),
        response_mode: SelectFileResponseMode::None,
    }
    .into_apdu();
    let mut transport = Scripted::new(vec![
        (select_mf_wire(), success(vec![])),
        (select_esign_by_name_wire(), not_found.clone()),
        (child_df.as_bytes().to_vec(), not_found.clone()),
        (any_file.as_bytes().to_vec(), not_found),
    ]);

    let error = transport
        .unlock_qualified_key(SignScheme::Organizational, pin2())
        .expect_err("no DF.ESIGN, no PIN 2");
    assert!(matches!(
        error,
        QualifiedUnlockError::Directory(Pkcs15Error::Status(StatusWord::FileNotFound))
    ));
    assert!(transport.drained());
}

#[test]
fn a_refused_pin2_yields_no_key() {
    let wrong = StatusWord::PinIncorrect {
        retries: PinRetries::from_nibble(TRIES_AFTER_WRONG).expect("counter value"),
    };
    let mut transport = Scripted::with_paths(vec![
        (Path::Plain, select_mf_wire(), success(vec![])),
        (Path::Plain, select_esign_by_name_wire(), success(vec![])),
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Organizational),
            probe_served(TRIES_PRISTINE),
        ),
        (
            Path::Credential,
            verify_pin2_wire(PinReferenceScheme::Organizational),
            status(wrong),
        ),
    ]);

    let error = transport
        .unlock_qualified_key(SignScheme::Organizational, pin2())
        .expect_err("a refused PIN 2 unlocks nothing");
    assert!(matches!(
        error,
        QualifiedUnlockError::PinRefused(VerifyOutcome::WrongPin { .. })
    ));
    assert!(transport.drained(), "no MSE:Set after a refused PIN 2");
}

#[test]
fn a_pin2_at_one_try_left_is_refused_after_the_probe_and_never_sent() {
    // The script ends at the probe: a VERIFY carrying PIN 2 would fail it.
    let mut transport = Scripted::with_paths(vec![
        (Path::Plain, select_mf_wire(), success(vec![])),
        (Path::Plain, select_esign_by_name_wire(), success(vec![])),
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Organizational),
            probe_served(TRIES_BELOW_FLOOR),
        ),
    ]);

    let error = transport
        .unlock_qualified_key(SignScheme::Organizational, pin2())
        .expect_err("the retry floor refuses PIN 2");
    assert!(matches!(
        error,
        QualifiedUnlockError::Verify(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
            credential: FlooredCredential::Pin2,
            ..
        }))
    ));
    assert!(transport.drained(), "nothing after the probe");
}

#[test]
fn citizen_rsa_pss_signs_over_the_loaded_hash_under_the_pss_reference() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA256_RSA_PSS,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha256(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(rsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha256_rsa_pss(digest)
        .expect("scripted PSS sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), RSA_3072_SIG_BYTES);
    assert!(transport.drained());
}

#[test]
fn citizen_rsa_pss_sha384_uses_the_matching_hash_and_pss_reference() {
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA384_RSA_PSS,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha384(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(rsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha384_rsa_pss(digest)
        .expect("scripted SHA-384 PSS sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), RSA_3072_SIG_BYTES);
    assert!(transport.drained());
}

#[test]
fn citizen_rsa_pss_sha512_uses_the_matching_hash_and_pss_reference() {
    let digest = [DIGEST_FILL; SHA512_LEN];
    let signature = vec![SIG_FILL; RSA_3072_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA512_RSA_PSS,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha512(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(rsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha512_rsa_pss(digest)
        .expect("scripted SHA-512 PSS sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), RSA_3072_SIG_BYTES);
    assert!(transport.drained());
}

#[test]
fn rsa_decipher_sets_the_confidentiality_template_and_chains_the_cryptogram() {
    // A modulus-wide cryptogram; with the padding indicator it exceeds the
    // short form and must chain.
    let cryptogram =
        RsaCryptogram::from_bytes(vec![DIGEST_FILL; RSA_3072_SIG_BYTES]).expect("modulus-wide");
    let plaintext = b"recovered content".to_vec();
    // A body on a non-final chained response is not part of the recovered
    // plaintext; only the final command's response carries it.
    let interim = b"interim block".to_vec();

    let mse = MseSetCt {
        alg_ref: DecipherAlgRef::RSA_PKCS1,
        key_ref: KeyRef::Auth
            .reference(SignScheme::Citizen)
            .expect("citizen auth key has a reference"),
    }
    .into_apdu()
    .expect("MSE:Set CT encodes")
    .as_bytes()
    .to_vec();
    let chain = PsoDecipher {
        cryptogram: &cryptogram,
    }
    .into_chain()
    .expect("cryptogram chains");
    assert!(chain.len() > 1, "a modulus-wide cryptogram chains");

    let mut steps = vec![(mse, success(vec![]))];
    let last_index = chain.len() - 1;
    for (index, command) in chain.iter().enumerate() {
        let response = if index == last_index {
            success(plaintext.clone())
        } else {
            success(interim.clone())
        };
        steps.push((command.as_bytes().to_vec(), response));
    }
    let mut transport = Scripted::new(steps);

    let result = transport
        .decipher_rsa(
            SignScheme::Citizen,
            KeyRef::Auth,
            DecipherAlgRef::RSA_PKCS1,
            &cryptogram,
        )
        .expect("scripted decipher succeeds");
    assert_eq!(result.as_bytes(), plaintext.as_slice());
    assert!(transport.drained());
}

#[test]
fn an_unexpected_signature_length_is_rejected() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    // The card returns a short signature: an RSA key that is not
    // RSA-3072, or a misconfiguration.
    let short = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA256_RSA_PKCS1,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha256(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(rsa_le()), success(short)),
    ]);

    let error = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha256_rsa(digest)
        .expect_err("a short signature is rejected");
    assert!(matches!(
        error,
        SignError::UnexpectedSignatureLength {
            got: ECDSA_P384_SIG_BYTES,
            expected: RSA_3072_SIG_BYTES,
        }
    ));
}

#[test]
fn a_status_word_failure_names_the_stage() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let [sw1, sw2] = StatusWord::SecurityNotSatisfied.as_u16().to_be_bytes();
    let rejected = ResponseApdu {
        body: vec![],
        sw1,
        sw2,
    };
    let mut transport = Scripted::new(vec![(
        mse_wire(
            SignScheme::Citizen,
            SignatureAlgRef::SHA256_RSA_PKCS1,
            KeyRef::Auth,
        ),
        rejected,
    )]);

    let error = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha256_rsa(digest)
        .expect_err("a rejected MSE fails");
    assert!(matches!(
        error,
        SignError::Status("MSE:Set", StatusWord::SecurityNotSatisfied)
    ));
}

fn get_data_pin2_wire(scheme: PinReferenceScheme) -> Vec<u8> {
    vec![
        ApduClass::Plain.as_byte(),
        GET_DATA_INS,
        GET_DATA_P1,
        GET_DATA_P2,
        GET_DATA_LC,
        PIN_CONTAINER_TEMPLATE_TAG,
        PIN_CONTAINER_TEMPLATE_LEN,
        PIN_CONTAINER_REF_TAG,
        PIN_CONTAINER_REF_LEN,
        scheme.reference(PinSlot::Pin2),
        GET_DATA_LE,
    ]
}

fn df2f_body(changed: bool) -> Vec<u8> {
    vec![
        PIN_CHANGED_TAG_HIGH,
        PIN_CHANGED_TAG_LOW,
        PIN_CHANGED_LEN,
        if changed {
            PIN_CHANGED_FLAG_CHANGED
        } else {
            PIN_CHANGED_FLAG_UNCHANGED
        },
    ]
}

#[test]
fn estonian_scheme_preserves_numbering_and_default_qualified_key_reference() {
    let scheme = SignScheme::from(PinReferenceScheme::Estonian);
    assert_eq!(scheme, SignScheme::Estonian);
    assert_eq!(scheme.pin_numbering(), PinReferenceScheme::Estonian);
    assert_eq!(KeyRef::Auth.reference(scheme), Some(KEY_REF_AUTH));
    assert_eq!(
        KeyRef::Sign.reference(scheme),
        Some(ESTONIAN_QUALIFIED_KEY_REF)
    );
}

#[test]
fn estonian_authentication_key_signs_p384_over_pso_hash_and_pso_cds() {
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mse = mse_wire(
        SignScheme::Estonian,
        SignatureAlgRef::SHA384_ECDSA,
        KeyRef::Auth,
    );
    assert_eq!(mse.last().copied(), Some(KEY_REF_AUTH));
    let mut transport = Scripted::new(vec![
        (mse, success(vec![])),
        (
            pso_hash_wire(ExternalHashValue::Sha384(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(ecdsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .authentication_key(SignScheme::Estonian)
        .sign_prehashed_sha384_ecdsa(digest)
        .expect("scripted Estonian authentication sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(transport.drained());
}

#[test]
fn estonian_qualified_unlock_blocks_unchanged_pin2_and_signs_once_changed_while_decipher_fails_closed()
 {
    // Unchanged initial PIN 2 (DF 2F == 00) refuses before VERIFY PIN 2.
    let mut blocked_transport = Scripted::with_paths(vec![
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Estonian),
            probe_served(ESTONIAN_TRIES_PRISTINE),
        ),
        (
            Path::Plain,
            get_data_pin2_wire(PinReferenceScheme::Estonian),
            success(df2f_body(false)),
        ),
    ]);
    let unlock_err = blocked_transport
        .unlock_qualified_key(SignScheme::Estonian, pin2())
        .expect_err("Estonian unchanged initial PIN 2 must refuse before VERIFY");
    assert!(matches!(
        unlock_err,
        QualifiedUnlockError::Pin2ChangeRequired
    ));
    assert!(
        blocked_transport.drained(),
        "zero VERIFY PIN 2 APDUs transmitted"
    );

    // Changed PIN 2 (DF 2F == 01) verifies PIN 2 at both 3 and 2 tries left and signs over PSO:HASH + PSO:CDS.
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    for tries in [ESTONIAN_TRIES_PRISTINE, ESTONIAN_TRIES_FLOOR] {
        let mut sign_transport = Scripted::with_paths(vec![
            (
                Path::Plain,
                probe_pin2_wire(PinReferenceScheme::Estonian),
                probe_served(tries),
            ),
            (
                Path::Plain,
                get_data_pin2_wire(PinReferenceScheme::Estonian),
                success(df2f_body(true)),
            ),
            (
                Path::Credential,
                verify_pin2_wire(PinReferenceScheme::Estonian),
                success(vec![]),
            ),
            (
                Path::Plain,
                mse_wire(
                    SignScheme::Estonian,
                    SignatureAlgRef::SHA384_ECDSA,
                    KeyRef::Sign,
                ),
                success(vec![]),
            ),
            (
                Path::Plain,
                pso_hash_wire(ExternalHashValue::Sha384(digest)),
                success(vec![]),
            ),
            (
                Path::Plain,
                pso_cds_empty_wire(ecdsa_le()),
                success(signature.clone()),
            ),
        ]);
        let sig = sign_transport
            .unlock_qualified_key(SignScheme::Estonian, pin2())
            .expect("Estonian changed PIN 2 unlocks qualified key")
            .sign_prehashed_sha384_ecdsa(digest)
            .expect("Estonian qualified ECDSA sign succeeds");
        assert_eq!(sig.as_bytes(), signature.as_slice());
        assert!(sign_transport.drained());
    }

    let cryptogram =
        RsaCryptogram::from_bytes(vec![DIGEST_FILL; RSA_3072_SIG_BYTES]).expect("modulus-wide");
    let mut decipher_transport = Scripted::new(vec![]);
    let decipher_err = decipher_transport
        .decipher_rsa(
            SignScheme::Estonian,
            KeyRef::Sign,
            DecipherAlgRef::RSA_PKCS1,
            &cryptogram,
        )
        .expect_err("Estonian qualified key does not support RSA decipher");
    assert!(matches!(
        decipher_err,
        SignError::UnsupportedKey {
            scheme: SignScheme::Estonian,
            key: KeyRef::Sign,
        }
    ));
    assert!(decipher_transport.drained(), "zero APDUs transmitted");
}

/// Expected raw `r || s` byte width of a P-256 ECDSA signature, pinned
/// independently of [`ECDSA_P256_SIG_BYTES`] in the wire test.
const EXPECTED_P256_SIG_LEN: usize = 64;
/// Expected short-form `Le` byte for a 64-byte P-256 ECDSA signature.
const EXPECTED_P256_LE: u8 = 0x40;

#[test]
fn citizen_ecdsa_p256_sha256_requests_p256_length_and_checks_signature_width() {
    assert_eq!(ECDSA_P256_SIG_BYTES, EXPECTED_P256_SIG_LEN);
    assert_eq!(ecdsa_p256_le(), EXPECTED_P256_LE);

    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; EXPECTED_P256_SIG_LEN];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA256_ECDSA,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha256(digest)),
            success(vec![]),
        ),
        (
            pso_cds_empty_wire(EXPECTED_P256_LE),
            success(signature.clone()),
        ),
    ]);

    let result = transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha256_ecdsa_p256(digest)
        .expect("scripted P-256 ECDSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), EXPECTED_P256_SIG_LEN);
    assert!(transport.drained());

    let wrong_len = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mut wrong_len_transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA256_ECDSA,
                KeyRef::Auth,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha256(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(EXPECTED_P256_LE), success(wrong_len)),
    ]);
    let error = wrong_len_transport
        .authentication_key(SignScheme::Citizen)
        .sign_prehashed_sha256_ecdsa_p256(digest)
        .expect_err("wrong-length P-256 signature is rejected");
    assert!(matches!(
        error,
        SignError::UnexpectedSignatureLength {
            got: ECDSA_P384_SIG_BYTES,
            expected: EXPECTED_P256_SIG_LEN,
        }
    ));
}

#[test]
fn qualified_sign_session_drives_citizen_organizational_cancel_and_refuses_estonian() {
    let digest = [DIGEST_FILL; SHA256_LEN];
    let signature = vec![SIG_FILL; EXPECTED_P256_SIG_LEN];

    let mut org_steps = organizational_unlock_steps(SignatureAlgRef::SHA256_ECDSA);
    org_steps.push((
        Path::Plain,
        pso_cds_inline_wire(ExternalHashValue::Sha256(digest), EXPECTED_P256_LE),
        success(signature.clone()),
    ));
    let org_transport = Scripted::with_paths(org_steps);
    let org_session = QualifiedSignSession::open(org_transport, SignScheme::Organizational, pin2())
        .expect("organizational PIN 2 verification succeeds");
    assert_eq!(org_session.scheme(), SignScheme::Organizational);
    let (org_transport, org_sig) =
        org_session.sign_once(|key| key.sign_prehashed_sha256_ecdsa_p256(digest));
    assert_eq!(
        org_sig
            .expect("split organizational qualified sign succeeds")
            .as_bytes(),
        signature.as_slice()
    );
    assert!(org_transport.drained());

    let citizen_transport = Scripted::with_paths(vec![
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Citizen),
            probe_served(TRIES_PRISTINE),
        ),
        (
            Path::Credential,
            verify_pin2_wire(PinReferenceScheme::Citizen),
            success(vec![]),
        ),
        (
            Path::Plain,
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA256_ECDSA,
                KeyRef::Sign,
            ),
            success(vec![]),
        ),
        (
            Path::Plain,
            pso_hash_wire(ExternalHashValue::Sha256(digest)),
            success(vec![]),
        ),
        (
            Path::Plain,
            pso_cds_empty_wire(EXPECTED_P256_LE),
            success(signature.clone()),
        ),
    ]);
    let citizen_session =
        QualifiedSignSession::open(citizen_transport, SignScheme::Citizen, pin2())
            .expect("citizen PIN 2 verification succeeds");
    assert_eq!(citizen_session.scheme(), SignScheme::Citizen);
    let (citizen_transport, citizen_sig) =
        citizen_session.sign_once(|key| key.sign_prehashed_sha256_ecdsa_p256(digest));
    assert_eq!(
        citizen_sig
            .expect("split citizen qualified sign succeeds")
            .as_bytes(),
        signature.as_slice()
    );
    assert!(citizen_transport.drained());

    let cancelled_transport = Scripted::with_paths(vec![
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Citizen),
            probe_served(TRIES_PRISTINE),
        ),
        (
            Path::Credential,
            verify_pin2_wire(PinReferenceScheme::Citizen),
            success(vec![]),
        ),
    ]);
    let cancelled_session =
        QualifiedSignSession::open(cancelled_transport, SignScheme::Citizen, pin2())
            .expect("citizen PIN 2 verification succeeds before cancel");
    let returned = cancelled_session.into_transport();
    assert!(returned.drained(), "cancel sends no signing APDUs");

    let estonian_blocked_transport = Scripted::with_paths(vec![
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Estonian),
            probe_served(ESTONIAN_TRIES_PRISTINE),
        ),
        (
            Path::Plain,
            get_data_pin2_wire(PinReferenceScheme::Estonian),
            success(df2f_body(false)),
        ),
    ]);
    let (returned, err) =
        QualifiedSignSession::open(estonian_blocked_transport, SignScheme::Estonian, pin2())
            .expect_err("Estonian unchanged initial PIN 2 refuses session open");
    assert!(matches!(err, QualifiedUnlockError::Pin2ChangeRequired));
    assert!(returned.drained(), "no VERIFY PIN 2 sent");

    let estonian_signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let estonian_digest = [DIGEST_FILL; SHA384_LEN];
    let estonian_transport = Scripted::with_paths(vec![
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Estonian),
            probe_served(ESTONIAN_TRIES_PRISTINE),
        ),
        (
            Path::Plain,
            get_data_pin2_wire(PinReferenceScheme::Estonian),
            success(df2f_body(true)),
        ),
        (
            Path::Credential,
            verify_pin2_wire(PinReferenceScheme::Estonian),
            success(vec![]),
        ),
        (
            Path::Plain,
            mse_wire(
                SignScheme::Estonian,
                SignatureAlgRef::SHA384_ECDSA,
                KeyRef::Sign,
            ),
            success(vec![]),
        ),
        (
            Path::Plain,
            pso_hash_wire(ExternalHashValue::Sha384(estonian_digest)),
            success(vec![]),
        ),
        (
            Path::Plain,
            pso_cds_empty_wire(ecdsa_le()),
            success(estonian_signature.clone()),
        ),
    ]);
    let estonian_session =
        QualifiedSignSession::open(estonian_transport, SignScheme::Estonian, pin2())
            .expect("Estonian changed PIN 2 opens qualified session");
    let (estonian_transport, estonian_sig) =
        estonian_session.sign_once(|key| key.sign_prehashed_sha384_ecdsa(estonian_digest));
    assert_eq!(
        estonian_sig
            .expect("split Estonian qualified sign succeeds")
            .as_bytes(),
        estonian_signature.as_slice()
    );
    assert!(estonian_transport.drained());

    let wrong = StatusWord::PinIncorrect {
        retries: PinRetries::from_nibble(TRIES_AFTER_WRONG).expect("counter value"),
    };
    let refused_transport = Scripted::with_paths(vec![
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Citizen),
            probe_served(TRIES_PRISTINE),
        ),
        (
            Path::Credential,
            verify_pin2_wire(PinReferenceScheme::Citizen),
            status(wrong),
        ),
    ]);
    let (returned, err) =
        QualifiedSignSession::open(refused_transport, SignScheme::Citizen, pin2())
            .expect_err("refused PIN 2 returns the transport without opening a session");
    assert!(matches!(
        err,
        QualifiedUnlockError::PinRefused(VerifyOutcome::WrongPin { .. })
    ));
    assert!(returned.drained(), "no signing APDU after refused PIN 2");
}

#[test]
fn estonian_rekeyed_qualified_reference_gates_df2f_and_drives_mse_set() {
    use refineid_apdu::iso7816::{
        AbsolutePath, DirectOffset15, ReadBinary, ReadBinaryOffset, SelectEfNoFci,
    };
    use refineid_pkcs15::{EF_ODF_FID, PKCS15_AID, Pkcs15Ops as _};

    const REKEYED_SIGN_KEY_REF: u8 = 0x07;
    const READ_CHUNK_LEN: u8 = 0xDF;
    const CDF_FID: FileId = FileId::from_u16(0x5103);
    const PRKDF_FID: FileId = FileId::from_u16(0x5101);
    const AOD_FID: FileId = FileId::from_u16(0x5106);

    const ODF_DER: &[u8] = &[
        0xA4, 0x08, 0x30, 0x06, 0x04, 0x04, 0x3F, 0x00, 0x51, 0x03, // Certificates -> MF/5103
        0xA0, 0x08, 0x30, 0x06, 0x04, 0x04, 0x3F, 0x00, 0x51, 0x01, // PrivateKeys -> MF/5101
        0xA8, 0x08, 0x30, 0x06, 0x04, 0x04, 0x3F, 0x00, 0x51, 0x06, // AuthObjects -> MF/5106
    ];
    const CDF_DER: &[u8] = &[
        0x30, 0x15, 0x30, 0x00, 0x30, 0x03, 0x04, 0x01, 0x22, 0xA1, 0x0C, 0x30, 0x0A, 0x30, 0x08,
        0x04, 0x06, 0x3F, 0x00, 0xAD, 0xF2, 0x34, 0x21,
    ];
    const PRKDF_DER: &[u8] = &[
        0xA0,
        0x1A,
        0x30,
        0x03,
        0x04,
        0x01,
        0x02,
        0x30,
        0x0B,
        0x04,
        0x01,
        0x22,
        0x03,
        0x03,
        0x06,
        0x00,
        0x40,
        0x02,
        0x01,
        REKEYED_SIGN_KEY_REF,
        0xA1,
        0x06,
        0x30,
        0x04,
        0x30,
        0x02,
        0x04,
        0x00,
    ];
    const AOD_DER: &[u8] = &[
        0x30, 0x20, 0x30, 0x00, 0x30, 0x03, 0x04, 0x01, 0x02, 0xA1, 0x17, 0x30, 0x15, 0x03, 0x03,
        0x04, 0xCC, 0x10, 0x0A, 0x01, 0x01, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0C, 0x80, 0x02, 0x00,
        0x82, 0x04, 0x01, 0x00,
    ];

    let aid = Aid::from_slice(PKCS15_AID).expect("standard PKCS#15 AID");
    let select_app = SelectByAidNoFci { aid: aid.clone() }
        .into_apdu()
        .as_bytes()
        .to_vec();
    let select_ef = |fid: FileId| SelectEfNoFci { fid }.into_apdu().as_bytes().to_vec();
    let select_abs = |fid: FileId| {
        SelectFile {
            class: ApduClass::Plain,
            target: SelectFileTarget::AbsolutePath(AbsolutePath::new(vec![fid]).expect("path")),
            response_mode: SelectFileResponseMode::None,
        }
        .into_apdu()
        .as_bytes()
        .to_vec()
    };
    let read_zero = ReadBinary {
        class: ApduClass::Plain,
        offset: ReadBinaryOffset::Direct(DirectOffset15::try_new(0).expect("zero offset")),
        le: READ_CHUNK_LEN,
    }
    .into_apdu()
    .as_bytes()
    .to_vec();
    let eof_resp = |body: &[u8]| {
        let [sw1, sw2] = StatusWord::EndOfFile.as_u16().to_be_bytes();
        ResponseApdu {
            body: body.to_vec(),
            sw1,
            sw2,
        }
    };

    let mut discovery_transport = Scripted::new(vec![
        (select_app.clone(), success(vec![])),
        (select_ef(EF_ODF_FID), success(vec![])),
        (read_zero.clone(), eof_resp(ODF_DER)),
        (select_abs(CDF_FID), success(vec![])),
        (read_zero.clone(), eof_resp(CDF_DER)),
        (select_abs(PRKDF_FID), success(vec![])),
        (read_zero.clone(), eof_resp(PRKDF_DER)),
        (select_abs(AOD_FID), success(vec![])),
        (read_zero, eof_resp(AOD_DER)),
        (select_app, success(vec![])),
    ]);
    let profile = discovery_transport
        .discover_qualified_signature_profile(&aid)
        .expect("discovers re-keyed qualified profile");
    assert!(discovery_transport.drained());
    let qualified_ref = profile.sign_key_reference();
    assert_eq!(qualified_ref.as_u8(), REKEYED_SIGN_KEY_REF);

    // Unchanged initial PIN 2 is blocked by *_with_reference before VERIFY.
    let mut blocked = Scripted::with_paths(vec![
        (
            Path::Plain,
            probe_pin2_wire(PinReferenceScheme::Estonian),
            probe_served(ESTONIAN_TRIES_PRISTINE),
        ),
        (
            Path::Plain,
            get_data_pin2_wire(PinReferenceScheme::Estonian),
            success(df2f_body(false)),
        ),
    ]);
    let err = blocked
        .unlock_qualified_key_with_reference(SignScheme::Estonian, qualified_ref, pin2())
        .expect_err("unchanged initial PIN 2 refuses unlock_qualified_key_with_reference");
    assert!(matches!(err, QualifiedUnlockError::Pin2ChangeRequired));
    assert!(blocked.drained());

    // Changed PIN 2 passes the discovered key reference to MSE:Set in both direct and split-session APIs.
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let rekeyed_mse = MseSet {
        alg_ref: SignatureAlgRef::SHA384_ECDSA,
        key_ref: REKEYED_SIGN_KEY_REF,
    }
    .into_apdu()
    .expect("MSE encodes")
    .as_bytes()
    .to_vec();

    let sign_steps = || {
        vec![
            (
                Path::Plain,
                probe_pin2_wire(PinReferenceScheme::Estonian),
                probe_served(ESTONIAN_TRIES_FLOOR),
            ),
            (
                Path::Plain,
                get_data_pin2_wire(PinReferenceScheme::Estonian),
                success(df2f_body(true)),
            ),
            (
                Path::Credential,
                verify_pin2_wire(PinReferenceScheme::Estonian),
                success(vec![]),
            ),
            (Path::Plain, rekeyed_mse.clone(), success(vec![])),
            (
                Path::Plain,
                pso_hash_wire(ExternalHashValue::Sha384(digest)),
                success(vec![]),
            ),
            (
                Path::Plain,
                pso_cds_empty_wire(ecdsa_le()),
                success(signature.clone()),
            ),
        ]
    };

    let mut direct = Scripted::with_paths(sign_steps());
    let direct_sig = direct
        .unlock_qualified_key_with_reference(SignScheme::Estonian, qualified_ref, pin2())
        .expect("re-keyed direct unlock succeeds")
        .sign_prehashed_sha384_ecdsa(digest)
        .expect("re-keyed direct sign succeeds");
    assert_eq!(direct_sig.as_bytes(), signature.as_slice());
    assert!(direct.drained());

    let split_transport = Scripted::with_paths(sign_steps());
    let session = QualifiedSignSession::open_with_reference(
        split_transport,
        SignScheme::Estonian,
        qualified_ref,
        pin2(),
    )
    .expect("re-keyed split session opens");
    let (split_transport, split_sig) =
        session.sign_once(|key| key.sign_prehashed_sha384_ecdsa(digest));
    assert_eq!(
        split_sig.expect("re-keyed split sign succeeds").as_bytes(),
        signature.as_slice()
    );
    assert!(split_transport.drained());
}
