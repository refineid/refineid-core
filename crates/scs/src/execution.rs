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

//! The `execute` step's validation, signing, and response rules (DVV
//! SCS specification v1.3 sec.2.7.3), split from the transaction
//! manager so each half stays readable.

use std::time::SystemTime;

use refineid_digest::HashAlg;

use crate::backend::{SignRequest, SigningBackend};
use crate::base64;
use crate::document::ExecuteDocument;
use crate::document::ExecuteResponseDocument;
use crate::error::TransactionError;
use crate::hash;
use crate::jwe;
use crate::purpose::SignPurpose;
use crate::transaction::AgreedTransaction;
use crate::values;

/// Run one decrypted `execute` payload to its encrypted answer.
pub(crate) fn respond(
    payload: &ExecuteDocument,
    state: &AgreedTransaction,
    backend: &dyn SigningBackend,
    now: SystemTime,
) -> Result<String, TransactionError> {
    let key_algorithm = backend.key_algorithm(state.purpose);
    if let Some(refused) = refusal(payload, state.purpose, key_algorithm) {
        return Err(refused);
    }
    let Some(hash) = hash::hash_named(&payload.hash_algorithm) else {
        return Err(TransactionError::internal_error(
            "refused hash algorithm reached signing",
        ));
    };
    let content = base64::decode(&payload.content)
        .map_err(|_| TransactionError::bad_request("execute content is not base64"))?;
    let now_unix = crate::time::system_unix(now)
        .map_err(|_| TransactionError::internal_error("read the system clock"))?;
    let produced = signature(
        &content,
        payload,
        hash,
        key_algorithm,
        state,
        backend,
        now_unix,
    )?;
    let effective_algorithm = payload.signature_algorithm.clone().unwrap_or_else(|| {
        match key_algorithm {
            crate::purpose::KeyAlgorithm::Ecdsa => "ECDSA",
            crate::purpose::KeyAlgorithm::Rsa => "RSA",
        }
        .to_owned()
    });
    let response = ExecuteResponseDocument {
        chain: backend
            .certificate_chain(state.purpose)
            .iter()
            .map(|certificate| base64::encode(certificate))
            .collect(),
        reason_code: values::REASON_OK,
        reason_text: "Signature generated".to_owned(),
        signature: base64::encode(&produced),
        signature_algorithm: payload.hash_algorithm.clone() + "with" + &effective_algorithm,
        signature_type: payload.signature_type.clone(),
        status: "ok".to_owned(),
        version: values::VERSION.to_owned(),
    };
    let plaintext = serde_json::to_vec(&response.encode())
        .map_err(|_| TransactionError::internal_error("serialize execute response"))?;
    jwe::encrypt(&plaintext, &state.key)
}

/// Why the decrypted `execute` payload is refused, or `None`.
pub(crate) fn refusal(
    payload: &ExecuteDocument,
    purpose: SignPurpose,
    key_algorithm: crate::purpose::KeyAlgorithm,
) -> Option<TransactionError> {
    if payload.version != values::VERSION {
        return Some(TransactionError::bad_request(format!(
            "unsupported transaction version {}",
            payload.version
        )));
    }
    if hash::hash_named(&payload.hash_algorithm).is_none() {
        return Some(TransactionError::not_implemented(format!(
            "unsupported hash algorithm {}",
            payload.hash_algorithm
        )));
    }
    match &payload.signature_algorithm {
        None => {}
        Some(name) if name == "RSA" || name == "ECDSA" => {
            let serves = matches!(
                (key_algorithm, name.as_str()),
                (crate::purpose::KeyAlgorithm::Rsa, "RSA")
                    | (crate::purpose::KeyAlgorithm::Ecdsa, "ECDSA")
            );
            if !serves {
                return Some(TransactionError::bad_request(format!(
                    "signature algorithm {name} does not match the card key"
                )));
            }
        }
        Some(other) => {
            return Some(TransactionError::not_implemented(format!(
                "unsupported signature algorithm {other}"
            )));
        }
    }
    if payload.signature_type != "signature" && payload.signature_type != "cms-pades" {
        return Some(TransactionError::not_implemented(format!(
            "unsupported signature type {}",
            payload.signature_type
        )));
    }
    if purpose == SignPurpose::Authentication && payload.signature_type != "signature" {
        return Some(TransactionError::bad_request(
            "authentication requests use only the signature type",
        ));
    }
    match payload.content_type.as_str() {
        "data" => {}
        "digest" if purpose == SignPurpose::Authentication => {
            return Some(TransactionError::bad_request(
                "authentication requests cannot use digest content",
            ));
        }
        "digest" if payload.signature_type == "cms-pades" => {}
        "digest" => {
            return Some(TransactionError::not_implemented(
                "pre-hashed raw card signing is not implemented",
            ));
        }
        other => {
            return Some(TransactionError::bad_request(format!(
                "unsupported content type {other}"
            )));
        }
    }
    None
}

/// Produce the signature bytes for one validated `execute`.
fn signature(
    content: &[u8],
    payload: &ExecuteDocument,
    hash: HashAlg,
    key_algorithm: crate::purpose::KeyAlgorithm,
    state: &AgreedTransaction,
    backend: &dyn SigningBackend,
    now_unix: i64,
) -> Result<Vec<u8>, TransactionError> {
    let purpose = state.purpose;
    let data: Vec<u8> = if purpose == SignPurpose::Authentication {
        bound_challenge(&payload.content, &state.server_key, &state.origin)?
    } else {
        content.to_vec()
    };
    if payload.signature_type != "cms-pades" {
        let raw = backend
            .sign(SignRequest {
                purpose,
                hash,
                data,
                origin: Some(state.origin.clone()),
            })
            .map_err(TransactionError::wrapping)?;
        return ecdsa_adjust(raw, key_algorithm);
    }
    let prepared = crate::cms::prepare(
        &data,
        &backend.certificate_chain(purpose),
        hash,
        key_algorithm,
        now_unix,
    )?;
    let card_signature = backend
        .sign(SignRequest {
            purpose,
            hash,
            data: prepared.signed_attributes().to_vec(),
            origin: Some(state.origin.clone()),
        })
        .map_err(TransactionError::wrapping)?;
    prepared.signed_data(&card_signature)
}

/// The card's raw signature in the response form: ECDSA signs as
/// X9.62 DER, RSA as returned (v1.3 sec.2.6.1).
fn ecdsa_adjust(
    raw: Vec<u8>,
    key_algorithm: crate::purpose::KeyAlgorithm,
) -> Result<Vec<u8>, TransactionError> {
    if key_algorithm != crate::purpose::KeyAlgorithm::Ecdsa {
        return Ok(raw);
    }
    crate::codec::ecdsa_signature_der(&raw)
        .map_err(|()| TransactionError::internal_error("encode ECDSA signature"))
}

/// The transaction form of the origin-bound challenge: the caller
/// sends `origin;nonce`, and the SCS appends `;serverKey` from the
/// agreement it actually made before the card signs (v1.3 sec.2.1).
/// Answers the bytes to sign.
fn bound_challenge(
    content: &str,
    server_key: &str,
    origin: &str,
) -> Result<Vec<u8>, TransactionError> {
    let not_utf8 = || TransactionError::bad_request("authentication challenge must be UTF-8");
    let raw = match base64::decode(content) {
        Ok(raw) => raw,
        Err(_) => return Err(not_utf8()),
    };
    let challenge = match core::str::from_utf8(&raw) {
        Ok(text) => text,
        Err(_) => return Err(not_utf8()),
    };
    if raw.len() > values::CHALLENGE_MAXIMUM_LENGTH {
        return Err(TransactionError::bad_request(format!(
            "challenge longer than {} octets",
            values::CHALLENGE_MAXIMUM_LENGTH
        )));
    }
    let Some((challenge_origin, nonce)) = challenge.split_once(';') else {
        return Err(TransactionError::bad_request(
            "challenge missing ; separator (expected origin;nonce)",
        ));
    };
    if nonce.contains(';') {
        return Err(TransactionError::bad_request(
            "authentication challenge must be origin;nonce",
        ));
    }
    if challenge_origin != origin {
        return Err(TransactionError::forbidden(
            "transaction authentication challenge is not bound to Origin and serverKey",
        ));
    }
    if nonce.len() < values::NONCE_MINIMUM_LENGTH {
        return Err(TransactionError::bad_request(format!(
            "authentication challenge nonce is shorter than {} octets",
            values::NONCE_MINIMUM_LENGTH
        )));
    }
    let mut bound = challenge.as_bytes().to_vec();
    bound.push(b';');
    bound.extend_from_slice(server_key.as_bytes());
    Ok(bound)
}
