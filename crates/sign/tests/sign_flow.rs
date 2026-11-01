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
use refineid_auth::verify::{PIN_PAD_BYTE, VERIFY_INS, VERIFY_P1};
use refineid_auth::{
    PIN_STORED_LENGTH, Pin2, PinReferenceScheme, PinSlot, UnvalidatedSecret, VerifyOutcome,
};
use refineid_pkcs15::{DF_ESIGN_FID, ESIGN_AID, Pkcs15Error};
use refineid_sign::commands::{
    DecipherAlgRef, ExternalHashValue, MseSet, MseSetCt, PsoComputeDigitalSignature, PsoDecipher,
    PsoHashExternal, SHA256_LEN, SHA384_LEN, SHA512_LEN, SignatureAlgRef, expected_length_le,
};
use refineid_sign::{
    ECDSA_P384_SIG_BYTES, KEY_REF_AUTH, KEY_REF_SIGN, KeyRef, ORG_QUALIFIED_KEY_REF,
    QualifiedUnlockError, RSA_3072_SIG_BYTES, RsaCryptogram, SignError, SignOps, SignScheme,
};

/// Digest filler byte for the fixtures.
const DIGEST_FILL: u8 = 0x5A;
/// Signature filler byte for the fixtures.
const SIG_FILL: u8 = 0xC3;
/// The counter a refused VERIFY reports.
const TRIES_AFTER_WRONG: u8 = 4;
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
        key_ref: key.reference(scheme),
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

/// VERIFY PIN 2 under `scheme`: the organizational card is sent the bare
/// digits, the citizen card the block padded to the stored length.
fn verify_pin2_wire(scheme: PinReferenceScheme) -> Vec<u8> {
    let mut body = SYNTHETIC_PIN2.to_vec();
    if scheme == PinReferenceScheme::Citizen {
        body.resize(PIN_STORED_LENGTH, PIN_PAD_BYTE);
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
/// SELECT DF.ESIGN by name, VERIFY PIN 2 under the organizational
/// reference there, and MSE:Set naming the DF.ESIGN-local key.
fn organizational_unlock_steps(alg: SignatureAlgRef) -> Vec<(Path, Vec<u8>, ResponseApdu)> {
    let mse = mse_wire(SignScheme::Organizational, alg, KeyRef::Sign);
    // The organizational qualified key is named by its local reference,
    // the last byte of the MSE:Set control-reference body.
    assert_eq!(mse.last().copied(), Some(ORG_QUALIFIED_KEY_REF));
    vec![
        (Path::Plain, select_mf_wire(), success(vec![])),
        (Path::Plain, select_esign_by_name_wire(), success(vec![])),
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
        "SELECT MF, SELECT DF.ESIGN, VERIFY, MSE:Set and one PSO:CDS, nothing else"
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
        key_ref: KeyRef::Auth.reference(SignScheme::Citizen),
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
