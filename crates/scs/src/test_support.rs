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

//! Test doubles: a scripted signing backend and minted P-256
//! certificates, so the protocol tests run without hardware.

use std::sync::Mutex;

use crate::backend::{BackendFailure, SignRequest, SigningBackend};
use crate::purpose::{KeyAlgorithm, SignPurpose};

/// A canned SCS signing backend: fixed chain and signature, optional
/// scripted refusal, and a record of what was asked.
pub(crate) struct ScriptedBackend {
    chain: Vec<Vec<u8>>,
    algorithm: KeyAlgorithm,
    signature: Vec<u8>,
    refusal: Option<BackendFailure>,
    signed: Mutex<Vec<SignRequest>>,
}

impl ScriptedBackend {
    /// A backend answering `signature` for every sign.
    pub(crate) fn answering(
        chain: Vec<Vec<u8>>,
        algorithm: KeyAlgorithm,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            chain,
            algorithm,
            signature,
            refusal: None,
            signed: Mutex::new(Vec::new()),
        }
    }

    /// A backend refusing every sign with `refusal`.
    pub(crate) fn refusing(refusal: BackendFailure) -> Self {
        Self {
            chain: Vec::new(),
            algorithm: KeyAlgorithm::Rsa,
            signature: Vec::new(),
            refusal: Some(refusal),
            signed: Mutex::new(Vec::new()),
        }
    }

    /// A backend serving `chain` but refusing every sign.
    pub(crate) fn refusing_sign(chain: Vec<Vec<u8>>, refusal: BackendFailure) -> Self {
        Self {
            chain,
            algorithm: KeyAlgorithm::Rsa,
            signature: Vec::new(),
            refusal: Some(refusal),
            signed: Mutex::new(Vec::new()),
        }
    }

    /// What the backend was asked to sign, in order.
    pub(crate) fn signed(&self) -> Vec<SignRequest> {
        self.signed
            .lock()
            .map(|held| held.clone())
            .unwrap_or_default()
    }
}

impl SigningBackend for ScriptedBackend {
    fn certificate_chain(&self, _purpose: SignPurpose) -> Vec<Vec<u8>> {
        self.chain.clone()
    }

    fn key_algorithm(&self, _purpose: SignPurpose) -> KeyAlgorithm {
        self.algorithm
    }

    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, BackendFailure> {
        if let Some(refusal) = &self.refusal {
            return Err(refusal.clone());
        }
        if let Ok(mut held) = self.signed.lock() {
            held.push(request);
        }
        Ok(self.signature.clone())
    }
}

/// Fill octet of the deterministic test signing key.
const TEST_KEY_FILL: u8 = 0x01;

/// Length of a P-256 secret, in bytes.
const SECRET_LENGTH: usize = 32;

/// X.509 version 3, zero-based.
const VERSION_THREE: u8 = 2;

/// The test certificate's serial number.
const SERIAL_ONE: u8 = 1;

/// A minted test certificate and its signing key.
pub(crate) struct TestCertificate {
    /// The DER certificate.
    pub(crate) der: Vec<u8>,
    /// The P-256 signing key.
    pub(crate) key: p256::ecdsa::SigningKey,
}

/// Mint a minimal self-signed P-256 certificate valid across a
/// window that includes every test run.
pub(crate) fn mint_certificate() -> TestCertificate {
    mint_certificate_window("200101000000Z", "400101000000Z")
}

/// Mint a minimal self-signed P-256 certificate across the given
/// UTCTime strings.
pub(crate) fn mint_certificate_window(not_before: &str, not_after: &str) -> TestCertificate {
    use p256::ecdsa::signature::Signer as _;
    let key = p256::ecdsa::SigningKey::from_slice(&[TEST_KEY_FILL; SECRET_LENGTH])
        .expect("fixed test key parses");
    let name = crate::der::sequence(&[&crate::der::set(&[&crate::der::sequence(&[
        &crate::der::oid(refineid_cms::oid::known::COMMON_NAME.as_bytes()).expect("oid"),
        &crate::der::utf8_string(b"scs-test").expect("name"),
    ])
    .expect("attribute")])
    .expect("set")])
    .expect("name");
    let algorithm = crate::der::sequence(&[&crate::der::oid(
        refineid_cms::oid::known::ECDSA_WITH_SHA256.as_bytes(),
    )
    .expect("oid")])
    .expect("algorithm");
    let validity = crate::der::sequence(&[
        &crate::der::tagged(crate::time::UTC_TIME_TAG, not_before.as_bytes()).expect("time"),
        &crate::der::tagged(crate::time::UTC_TIME_TAG, not_after.as_bytes()).expect("time"),
    ])
    .expect("validity");
    let spki = {
        let point = key.verifying_key().to_sec1_point(false);
        let algorithm = crate::der::sequence(&[
            &crate::der::oid(refineid_cms::oid::known::EC_PUBLIC_KEY.as_bytes()).expect("oid"),
            &crate::der::oid(refineid_cms::oid::known::SECP256R1.as_bytes()).expect("oid"),
        ])
        .expect("algorithm");
        let bits = crate::der::bit_string(point.as_bytes()).expect("bits");
        crate::der::sequence(&[&algorithm, &bits]).expect("spki")
    };
    let tbs = crate::der::sequence(&[
        &crate::der::tagged(
            crate::der::TAG_CONTEXT_ZERO,
            &crate::der::integer(VERSION_THREE).expect("version"),
        )
        .expect("explicit version"),
        &crate::der::integer(SERIAL_ONE).expect("serial"),
        &algorithm,
        &name,
        &validity,
        &name,
        &spki,
    ])
    .expect("tbs");
    let signature: p256::ecdsa::Signature = key.sign(&tbs);
    let signature_der = signature.to_der();
    let bits = crate::der::bit_string(signature_der.as_bytes()).expect("bits");
    let der = crate::der::sequence(&[&tbs, &algorithm, &bits]).expect("certificate");
    TestCertificate { der, key }
}

/// Mint a compact ES256 JWS over `payload` with `key`.
pub(crate) fn mint_jws(key: &p256::ecdsa::SigningKey, payload: &serde_json::Value) -> String {
    use p256::ecdsa::signature::Signer as _;
    let header = crate::base64::encode_url(br#"{"alg":"ES256"}"#);
    let body = crate::base64::encode_url(&serde_json::to_vec(payload).expect("payload encodes"));
    let signing_input = header + "." + &body;
    let signature: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
    signing_input + "." + &crate::base64::encode_url(signature.to_bytes().as_slice())
}
