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
) -> Result<String, TransactionError> {
    if let Some(refused) = refusal(payload, state.purpose, &state.server_key, &state.origin) {
        return Err(refused);
    }
    let Some(hash) = hash::hash_named(&payload.hash_algorithm) else {
        return Err(TransactionError::internal_error(
            "refused hash algorithm reached signing",
        ));
    };
    let content = base64::decode(&payload.content)
        .map_err(|_| TransactionError::bad_request("execute content is not base64"))?;
    let produced = signature(&content, &payload.signature_type, hash, state, backend)?;
    let response = ExecuteResponseDocument {
        chain: backend
            .certificate_chain(state.purpose)
            .iter()
            .map(|certificate| base64::encode(certificate))
            .collect(),
        reason_code: values::REASON_OK,
        reason_text: "Signature generated".to_owned(),
        signature: base64::encode(&produced),
        signature_algorithm: payload.hash_algorithm.clone() + "with" + &payload.signature_algorithm,
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
    server_key: &str,
    origin: &str,
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
    if payload.signature_algorithm != "RSA" && payload.signature_algorithm != "ECDSA" {
        return Some(TransactionError::not_implemented(format!(
            "unsupported signature algorithm {}",
            payload.signature_algorithm
        )));
    }
    if payload.signature_type != "signature" && payload.signature_type != "cms-pades" {
        return Some(TransactionError::not_implemented(format!(
            "unsupported signature type {}",
            payload.signature_type
        )));
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
    if purpose != SignPurpose::Authentication {
        return None;
    }
    challenge_refusal(&payload.content, server_key, origin)
}

/// Produce the signature bytes for one validated `execute`.
fn signature(
    content: &[u8],
    signature_type: &str,
    hash: HashAlg,
    state: &AgreedTransaction,
    backend: &dyn SigningBackend,
) -> Result<Vec<u8>, TransactionError> {
    let purpose = state.purpose;
    if signature_type != "cms-pades" {
        return backend
            .sign(SignRequest {
                purpose,
                hash,
                data: content.to_vec(),
                origin: Some(state.origin.clone()),
            })
            .map_err(TransactionError::wrapping);
    }
    let prepared = crate::cms::prepare(
        content,
        &backend.certificate_chain(purpose),
        hash::scs_name(hash),
    )?;
    let card_signature = backend
        .sign(SignRequest {
            purpose,
            hash,
            data: prepared.signed_attributes().to_vec(),
            origin: Some(state.origin.clone()),
        })
        .map_err(TransactionError::wrapping)?;
    Ok(prepared.signed_data(&card_signature))
}

/// The transaction form of the origin-bound challenge: the content
/// must be `origin;nonce;serverKey`, binding the sign to both the
/// caller and the key agreement (v1.3 sec.2.7.3).
fn challenge_refusal(content: &str, server_key: &str, origin: &str) -> Option<TransactionError> {
    let not_utf8 = || TransactionError::bad_request("authentication challenge must be UTF-8");
    let raw = match base64::decode(content) {
        Ok(raw) => raw,
        Err(_) => return Some(not_utf8()),
    };
    let challenge = match core::str::from_utf8(&raw) {
        Ok(text) => text,
        Err(_) => return Some(not_utf8()),
    };
    let prefix = origin.to_owned() + ";";
    let suffix = ";".to_owned() + server_key;
    if !challenge.starts_with(&prefix) || !challenge.ends_with(&suffix) {
        return Some(TransactionError::forbidden(
            "transaction authentication challenge is not bound to Origin and serverKey",
        ));
    }
    let nonce = &challenge[prefix.len()..challenge.len() - suffix.len()];
    if nonce.chars().count() < values::NONCE_MINIMUM_LENGTH {
        return Some(TransactionError::bad_request(format!(
            "authentication challenge nonce is shorter than {} octets",
            values::NONCE_MINIMUM_LENGTH
        )));
    }
    None
}
