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

use refineid_apdu::{
    CardTransport, CommandApdu, CredentialCommand, ResponseApdu, StatusWord, TransportOutcome,
};
use refineid_sign::commands::{
    DecipherAlgRef, ExternalHashValue, MseSet, MseSetCt, PsoComputeDigitalSignature, PsoDecipher,
    PsoHashExternal, SHA256_LEN, SHA384_LEN, SHA512_LEN, SignatureAlgRef, expected_length_le,
};
use refineid_sign::{
    ECDSA_P384_SIG_BYTES, KeyRef, ORG_QUALIFIED_KEY_REF, RSA_3072_SIG_BYTES, RsaCryptogram,
    SignError, SignOps, SignScheme,
};

/// Digest filler byte for the fixtures.
const DIGEST_FILL: u8 = 0x5A;
/// Signature filler byte for the fixtures.
const SIG_FILL: u8 = 0xC3;

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

/// A transport that checks each command against a scripted expectation
/// and returns the paired response.
struct Scripted {
    steps: Vec<(Vec<u8>, ResponseApdu)>,
    cursor: usize,
}

impl Scripted {
    fn new(steps: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
        Self { steps, cursor: 0 }
    }

    fn drained(&self) -> bool {
        self.cursor == self.steps.len()
    }
}

impl CardTransport for Scripted {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let (expected, response) = self
            .steps
            .get(self.cursor)
            .ok_or_else(|| format!("script exhausted at step {}", self.cursor))?;
        if expected != command.as_bytes() {
            return Err(format!("unexpected command at step {}", self.cursor));
        }
        self.cursor += 1;
        Ok(TransportOutcome::Response(response.clone()))
    }

    fn transmit_credential(
        &mut self,
        _command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        Err("signing issues no credential command".to_owned())
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
        .sign_prehashed_sha256_rsa(SignScheme::Citizen, KeyRef::Auth, digest)
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
        .sign_prehashed_sha384_rsa(SignScheme::Citizen, KeyRef::Auth, digest)
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
        .sign_prehashed_sha512_rsa(SignScheme::Citizen, KeyRef::Auth, digest)
        .expect("scripted SHA-512 RSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert_eq!(result.len(), RSA_3072_SIG_BYTES);
    assert!(transport.drained());
}

#[test]
fn citizen_ecdsa_p384_signs_over_the_loaded_hash() {
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mut transport = Scripted::new(vec![
        (
            mse_wire(
                SignScheme::Citizen,
                SignatureAlgRef::SHA384_ECDSA,
                KeyRef::Sign,
            ),
            success(vec![]),
        ),
        (
            pso_hash_wire(ExternalHashValue::Sha384(digest)),
            success(vec![]),
        ),
        (pso_cds_empty_wire(ecdsa_le()), success(signature.clone())),
    ]);

    let result = transport
        .sign_prehashed_sha384_ecdsa(SignScheme::Citizen, KeyRef::Sign, digest)
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
        .sign_prehashed_sha256_ecdsa(SignScheme::Citizen, KeyRef::Auth, digest)
        .expect("scripted SHA-256 ECDSA sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(transport.drained());
}

#[test]
fn organizational_sign_skips_pso_hash_and_carries_the_digest_inline() {
    let digest = [DIGEST_FILL; SHA384_LEN];
    let signature = vec![SIG_FILL; ECDSA_P384_SIG_BYTES];
    let mse = mse_wire(
        SignScheme::Organizational,
        SignatureAlgRef::SHA384_ECDSA,
        KeyRef::Sign,
    );
    // The organizational qualified key is named by its local reference,
    // the last byte of the MSE:Set control-reference body.
    assert_eq!(mse.last().copied(), Some(ORG_QUALIFIED_KEY_REF));
    let mut transport = Scripted::new(vec![
        (mse, success(vec![])),
        (
            pso_cds_inline_wire(ExternalHashValue::Sha384(digest), ecdsa_le()),
            success(signature.clone()),
        ),
    ]);

    let result = transport
        .sign_prehashed_sha384_ecdsa(SignScheme::Organizational, KeyRef::Sign, digest)
        .expect("scripted organizational sign succeeds");
    assert_eq!(result.as_bytes(), signature.as_slice());
    assert!(
        transport.drained(),
        "the organizational chain issues exactly MSE:Set and PSO:CDS"
    );
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
        .sign_prehashed_sha256_rsa_pss(SignScheme::Citizen, KeyRef::Auth, digest)
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
        .sign_prehashed_sha384_rsa_pss(SignScheme::Citizen, KeyRef::Auth, digest)
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
        .sign_prehashed_sha512_rsa_pss(SignScheme::Citizen, KeyRef::Auth, digest)
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
        .sign_prehashed_sha256_rsa(SignScheme::Citizen, KeyRef::Auth, digest)
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
        .sign_prehashed_sha256_rsa(SignScheme::Citizen, KeyRef::Auth, digest)
        .expect_err("a rejected MSE fails");
    assert!(matches!(
        error,
        SignError::Status("MSE:Set", StatusWord::SecurityNotSatisfied)
    ));
}
