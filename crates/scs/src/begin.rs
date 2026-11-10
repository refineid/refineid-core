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

//! The stateless work of the `begin` step.
//!
//! JWS verification, key agreement, and the card-signed response JWT
//! (DVV SCS specification v1.3 sec.2.7.2). The manager owns only the
//! pending slot; everything else happens here.

use std::time::SystemTime;

use elliptic_curve::NonZeroScalar;
use elliptic_curve::sec1::ToSec1Point as _;
use p256::NistP256;
use refineid_digest::HashAlg;
use zeroize::Zeroizing;

use crate::backend::{SignRequest, SigningBackend};
use crate::base64;
use crate::codec;
use crate::document::{
    BeginDocument, BeginResponseDocument, JoseHeaderDocument, ResponseHeaderDocument,
};
use crate::error::TransactionError;
use crate::purpose::{KeyAlgorithm, SignPurpose};
use crate::transaction::AgreedTransaction;
use crate::values;

/// One completed begin: the compact response JWT and the agreed state
/// the manager should hold for `execute`.
pub(crate) struct Outcome {
    /// The signed compact response JWT.
    pub(crate) response: String,
    /// The agreed transaction awaiting `execute`.
    pub(crate) state: AgreedTransaction,
}

/// Run the whole begin step over already-split JWS segments.
pub(crate) fn perform(
    segments: &[&str],
    origin: &str,
    now: SystemTime,
    backend: &dyn SigningBackend,
) -> Result<Outcome, TransactionError> {
    let Ok([header_segment, payload_segment, signature_segment]): Result<
        [&str; values::JWS_SEGMENT_COUNT],
        _,
    > = segments.try_into() else {
        return Err(TransactionError::bad_request(
            "begin transaction must be a compact JWS",
        ));
    };
    let header: JoseHeaderDocument =
        codec::decode_segment(header_segment, "JWS header", JoseHeaderDocument::decode)?;
    let payload: BeginDocument =
        codec::decode_segment(payload_segment, "JWS payload", BeginDocument::decode)?;
    if payload.version != values::VERSION {
        return Err(TransactionError::bad_request(format!(
            "unsupported transaction version {}",
            payload.version
        )));
    }
    let certificate = base64::decode(&payload.server_cert)
        .map_err(|_| TransactionError::bad_request("serverCert is not base64"))?;
    let signature = base64::decode_url(signature_segment)
        .map_err(|_| TransactionError::bad_request("JWS signature is not base64url"))?;
    let signing_input = header_segment.to_owned() + "." + payload_segment;
    if let Some(refusal) = crate::jws::refusal(
        &header.alg,
        &certificate,
        signing_input.as_bytes(),
        &signature,
        now,
    ) {
        return Err(refusal);
    }
    agreed(&payload, origin, backend)
}

/// The key-agreement half, after JWS verification.
fn agreed(
    payload: &BeginDocument,
    origin: &str,
    backend: &dyn SigningBackend,
) -> Result<Outcome, TransactionError> {
    let purpose = codec::purpose_of_selector(payload.selector.as_ref())?;
    let chain: Vec<String> = backend
        .certificate_chain(purpose)
        .iter()
        .map(|certificate| base64::encode(certificate))
        .collect();
    if chain.is_empty() {
        return Err(TransactionError::internal_error(
            "signing backend returned no end-user certificate",
        ));
    }
    if let Some(refusal) = codec::selector_refusal(payload, backend.key_algorithm(purpose)) {
        return Err(refusal);
    }
    let server_public = server_key(payload)?;
    let ephemeral = draw_scalar()?;
    let shared = elliptic_curve::ecdh::diffie_hellman(&*ephemeral, server_public.as_affine());
    let mut key = Zeroizing::new([0_u8; values::TRANSACTION_KEY_LENGTH]);
    key.copy_from_slice(shared.raw_secret_bytes().as_slice());
    let ephemeral_public = p256::PublicKey::from_secret_scalar(&ephemeral);
    let response = BeginResponseDocument {
        chain,
        reason_code: values::REASON_OK,
        reason_text: "Transaction started".to_owned(),
        status: "ok".to_owned(),
        transaction: base64::encode(&public_key_der(&ephemeral_public)?),
        version: values::VERSION.to_owned(),
    };
    let state = AgreedTransaction {
        key,
        origin: origin.to_owned(),
        purpose,
        server_key: payload.server_key.clone(),
    };
    signed(&response, purpose, backend, state)
}

/// The service's P-256 agreement key, parsed from its DER SPKI.
fn server_key(payload: &BeginDocument) -> Result<p256::PublicKey, TransactionError> {
    let server_key_der = base64::decode(&payload.server_key)
        .map_err(|_| TransactionError::bad_request("serverKey is not a P-256 SPKI"))?;
    codec::p256_spki_key(&server_key_der)
        .map_err(|()| TransactionError::bad_request("serverKey is not a P-256 SPKI"))
}

/// Draw an ephemeral scalar by rejection sampling: a draw is kept
/// only when its big-endian value is a canonical, nonzero scalar.
fn draw_scalar() -> Result<Zeroizing<NonZeroScalar<NistP256>>, TransactionError> {
    loop {
        let mut buffer = Zeroizing::new(elliptic_curve::FieldBytes::<NistP256>::default());
        getrandom::fill(&mut buffer)
            .map_err(|_| TransactionError::internal_error("transaction key agreement failed"))?;
        if let Some(scalar) = NonZeroScalar::<NistP256>::from_repr(*buffer).into_option() {
            return Ok(Zeroizing::new(scalar));
        }
    }
}

/// The ephemeral key as DER SPKI.
fn public_key_der(public: &p256::PublicKey) -> Result<Vec<u8>, TransactionError> {
    let coordinates = public.to_sec1_point(false);
    let algorithm = crate::der::sequence(&[
        &crate::der::oid(refineid_cms::oid::known::EC_PUBLIC_KEY.as_bytes())
            .map_err(|()| TransactionError::internal_error("serialize transaction response"))?,
        &crate::der::oid(refineid_cms::oid::known::SECP256R1.as_bytes())
            .map_err(|()| TransactionError::internal_error("serialize transaction response"))?,
    ])
    .map_err(|()| TransactionError::internal_error("serialize transaction response"))?;
    let key_bits = crate::der::bit_string(coordinates.as_bytes())
        .map_err(|()| TransactionError::internal_error("serialize transaction response"))?;
    crate::der::sequence(&[&algorithm, &key_bits])
        .map_err(|()| TransactionError::internal_error("serialize transaction response"))
}

/// Sign the response JWT with the card.
///
/// The JWS algorithm follows the card key: RS256 over SHA-256 for an
/// RSA key, ES384 over SHA-384 for the P-384 key -- the digest each
/// card's qualified key actually serves (RFC 7518 section 3.1; the raw
/// `r || s` card signature is already the ES384 JWS form).
fn signed(
    response: &BeginResponseDocument,
    purpose: SignPurpose,
    backend: &dyn SigningBackend,
    state: AgreedTransaction,
) -> Result<Outcome, TransactionError> {
    let (algorithm, hash) = match backend.key_algorithm(purpose) {
        KeyAlgorithm::Ecdsa => ("ES384", HashAlg::Sha384),
        KeyAlgorithm::Rsa => ("RS256", HashAlg::Sha256),
    };
    let header = ResponseHeaderDocument {
        alg: algorithm.to_owned(),
        kid: codec::key_identifier(&response.chain),
        typ: "JWT".to_owned(),
    };
    let encoded_header = codec::encode_segment(&header.encode())?;
    let encoded_payload = codec::encode_segment(&response.encode())?;
    let signing_input = encoded_header + "." + &encoded_payload;
    let signature = backend
        .sign(SignRequest {
            purpose,
            hash,
            data: signing_input.as_bytes().to_vec(),
            origin: Some(state.origin.clone()),
        })
        .map_err(TransactionError::wrapping)?;
    Ok(Outcome {
        response: signing_input + "." + &base64::encode_url(&signature),
        state,
    })
}
