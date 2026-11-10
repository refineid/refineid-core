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

//! Route one assembled SCS request to its handler and build the full
//! HTTP response bytes.
//!
//! The surface is the DVV SCS specification v1.3: `GET /version`,
//! `POST /sign` (JSON, or the JWT transaction flow selected by its
//! content type), and the CORS preflight. Sign outcomes always ride in
//! an HTTP 200 whose JSON reason triple carries the result (v1.3
//! sec.3); only an unknown route answers 404.

use std::time::SystemTime;

use refineid_digest::HashAlg;

use crate::backend::{SignRequest, SigningBackend};
use crate::base64;
use crate::challenge;
use crate::document::{SignRequestDocument, SignResponseDocument, VersionDocument};
use crate::error::TransactionError;
use crate::http;
use crate::transaction::TransactionManager;
use crate::values;

/// Dispatch one request and answer the response bytes.
pub fn dispatch(
    request: &http::Request,
    body: &[u8],
    now: SystemTime,
    backend: &dyn SigningBackend,
    transactions: &TransactionManager,
) -> Vec<u8> {
    if request.method == "OPTIONS" {
        return http::preflight(request.origin.as_deref());
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/version") => http::json(
            values::HTTP_OK,
            &encoded(&VersionDocument::current().encode()),
            request.origin.as_deref(),
        ),
        ("POST", "/sign") => sign(request, body, now, backend, transactions),
        _ => http::text(
            values::HTTP_NOT_FOUND,
            "Not Found",
            request.origin.as_deref(),
        ),
    }
}

/// Encode one response document with stable key order.
fn encoded(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

/// A failed sign, as the specification's always-200 JSON form.
fn sign_error(reason_code: u16, reason_text: &str, origin: Option<&str>) -> Vec<u8> {
    http::json(
        values::HTTP_OK,
        &encoded(&SignResponseDocument::failed(reason_code, reason_text.to_owned()).encode()),
        origin,
    )
}

/// Handle `POST /sign`: the JWT transaction branch by content type,
/// otherwise the JSON form.
fn sign(
    request: &http::Request,
    body: &[u8],
    now: SystemTime,
    backend: &dyn SigningBackend,
    transactions: &TransactionManager,
) -> Vec<u8> {
    if request
        .content_type
        .as_deref()
        .is_some_and(|content_type| content_type.contains("application/jwt"))
    {
        return sign_transaction(request, body, now, backend, transactions);
    }
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => {
            return sign_error(
                values::REASON_BAD_REQUEST,
                "Bad request: invalid JSON",
                request.origin.as_deref(),
            );
        }
    };
    let document = match SignRequestDocument::decode(&value) {
        Ok(document) => document,
        Err(()) => {
            return sign_error(
                values::REASON_BAD_REQUEST,
                "Bad request: invalid JSON",
                request.origin.as_deref(),
            );
        }
    };
    sign_json(&document, request.origin.as_deref(), backend)
}

/// The JWT transaction branch: a compact JWS begins, a compact JWE
/// executes; the dot count tells them apart.
fn sign_transaction(
    request: &http::Request,
    body: &[u8],
    now: SystemTime,
    backend: &dyn SigningBackend,
    transactions: &TransactionManager,
) -> Vec<u8> {
    let separators = body.iter().filter(|byte| **byte == DOT).count();
    let outcome = if separators == values::JWS_SEGMENT_COUNT - 1 {
        transactions.begin(body, request.origin.as_deref(), now, backend)
    } else if separators == values::JWE_SEGMENT_COUNT - 1 {
        transactions.execute(body, request.origin.as_deref(), backend)
    } else {
        return sign_error(
            values::REASON_BAD_REQUEST,
            "Bad request: JWT body is not compact JWS or JWE",
            request.origin.as_deref(),
        );
    };
    match outcome {
        Ok(compact) => http::jwt(&compact, request.origin.as_deref()),
        Err(error) => sign_error(error.code, &error.message, request.origin.as_deref()),
    }
}

/// The compact-segment separator.
const DOT: u8 = b'.';

/// The JSON `/sign` form: card-side hashing of `data` content, with
/// the origin-bound challenge enforced for the authentication key.
fn sign_json(
    document: &SignRequestDocument,
    origin: Option<&str>,
    backend: &dyn SigningBackend,
) -> Vec<u8> {
    let raw = match base64::decode(&document.content) {
        Ok(raw) => raw,
        Err(_) => {
            return sign_error(
                values::REASON_BAD_REQUEST,
                "Bad request: content not base64",
                origin,
            );
        }
    };
    if document.content_type == "digest" {
        return sign_error(
            values::REASON_NOT_IMPLEMENTED,
            "Not Implemented: the card hashes content itself; use contentType \"data\"",
            origin,
        );
    }
    if document.content_type != "data" {
        return sign_error(
            values::REASON_BAD_REQUEST,
            &format!(
                "Bad request: unsupported contentType {}",
                document.content_type
            ),
            origin,
        );
    }
    let purpose = document.purpose();
    if purpose == crate::purpose::SignPurpose::Authentication
        && let Some(refusal) = challenge::refusal(&raw, origin)
    {
        return sign_error(
            values::REASON_FORBIDDEN,
            &("Forbidden: ".to_owned() + &refusal),
            origin,
        );
    }
    let signature = backend.sign(SignRequest {
        purpose,
        hash: HashAlg::Sha256,
        data: raw,
        origin: origin.map(str::to_owned),
    });
    match signature {
        Ok(signature) => {
            let response = SignResponseDocument::ok(
                base64::encode(&signature),
                backend.key_algorithm(purpose).scs_name(HashAlg::Sha256),
                backend
                    .certificate_chain(purpose)
                    .iter()
                    .map(|certificate| base64::encode(certificate))
                    .collect(),
            );
            http::json(values::HTTP_OK, &encoded(&response.encode()), origin)
        }
        Err(failure) => {
            let wrapped = TransactionError::wrapping(failure);
            sign_error(wrapped.code, &wrapped.message, origin)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::dispatch;
    use crate::backend::BackendFailure;
    use crate::base64;
    use crate::http::Request;
    use crate::purpose::{KeyAlgorithm, SignPurpose};
    use crate::test_support::{ScriptedBackend, mint_certificate};
    use crate::transaction::TransactionManager;
    use crate::values;
    use std::time::{Duration, UNIX_EPOCH};

    /// Unix seconds of 2023-11-14T22:13:20Z, inside every test window.
    const TEST_NOW_SECONDS: u64 = 1_700_000_000;

    /// The test origin.
    const ORIGIN: &str = "https://example.com";

    /// A request for `method` and `path`.
    fn request(method: &str, path: &str, content_type: Option<&str>) -> Request {
        Request {
            method: method.to_owned(),
            path: path.to_owned(),
            origin: Some(ORIGIN.to_owned()),
            content_type: content_type.map(str::to_owned),
            body_length: 0,
        }
    }

    /// A backend answering a fixed signature for the minted chain.
    fn backend() -> ScriptedBackend {
        let minted = mint_certificate();
        ScriptedBackend::answering(
            [minted.der].into(),
            KeyAlgorithm::Rsa,
            b"card-signature".to_vec(),
        )
    }

    /// The response body as text.
    fn body_text(response: &[u8]) -> &str {
        let text = core::str::from_utf8(response).expect("ascii");
        text.split("\r\n\r\n").nth(1).expect("body")
    }

    /// The version document names the served surface.
    #[test]
    fn version_answers() {
        let backend = backend();
        let manager = TransactionManager::new();
        let response = dispatch(
            &request("GET", "/version", None),
            b"",
            UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS),
            &backend,
            &manager,
        );
        let text = core::str::from_utf8(&response).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text:?}");
        assert!(
            body_text(&response).contains("\"version\":\"1.3\""),
            "{text:?}"
        );
    }

    /// Unknown routes answer 404; anything answers its preflight.
    #[test]
    fn unknown_route_and_preflight() {
        let backend = backend();
        let manager = TransactionManager::new();
        let now = UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS);
        let missing = dispatch(
            &request("GET", "/elsewhere", None),
            b"",
            now,
            &backend,
            &manager,
        );
        let text = core::str::from_utf8(&missing).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"), "{text:?}");
        let preflight = dispatch(
            &request("OPTIONS", "/sign", None),
            b"",
            now,
            &backend,
            &manager,
        );
        let text = core::str::from_utf8(&preflight).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text:?}");
        assert!(
            text.contains("Access-Control-Allow-Methods: GET, POST\r\n"),
            "{text:?}"
        );
    }

    /// A well-formed authentication challenge signs.
    #[test]
    fn json_sign_answers() {
        let backend = backend();
        let manager = TransactionManager::new();
        let nonce = "n".repeat(values::NONCE_MINIMUM_LENGTH);
        let body = format!(
            "{{\"content\":\"{}\",\"contentType\":\"data\"}}",
            base64::encode(format!("{ORIGIN};{nonce}").as_bytes())
        );
        let response = dispatch(
            &request("POST", "/sign", Some("application/json")),
            body.as_bytes(),
            UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS),
            &backend,
            &manager,
        );
        let text = core::str::from_utf8(&response).expect("ascii");
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text:?}");
        let body = body_text(&response);
        assert!(body.contains("\"status\":\"ok\""), "{body:?}");
        assert!(
            body.contains("\"signatureAlgorithm\":\"SHA256withRSA\""),
            "{body:?}"
        );
        assert_eq!(backend.signed().len(), 1);
        assert_eq!(
            backend.signed().remove(0).purpose,
            SignPurpose::Authentication
        );
    }

    /// Malformed JSON signs fail in the always-200 reason form.
    #[test]
    fn json_sign_refusals_ride_in_200() {
        let backend = backend();
        let manager = TransactionManager::new();
        let now = UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS);
        for (body, reason) in [
            ("not json", "\"reasonCode\":400"),
            (
                "{\"content\":\"!!!\",\"contentType\":\"data\"}",
                "\"reasonCode\":400",
            ),
            (
                "{\"content\":\"eA==\",\"contentType\":\"digest\"}",
                "\"reasonCode\":501",
            ),
            (
                "{\"content\":\"eA==\",\"contentType\":\"smoke\"}",
                "\"reasonCode\":400",
            ),
            (
                "{\"content\":\"eA==\",\"contentType\":\"data\"}",
                "\"reasonCode\":403",
            ),
        ] {
            let response = dispatch(
                &request("POST", "/sign", Some("application/json")),
                body.as_bytes(),
                now,
                &backend,
                &manager,
            );
            let text = core::str::from_utf8(&response).expect("ascii");
            assert!(
                text.starts_with("HTTP/1.1 200 OK\r\n"),
                "{body:?} answered {text:?}"
            );
            assert!(
                body_text(&response).contains(reason),
                "{body:?} lacks {reason}"
            );
        }
        assert!(backend.signed().is_empty());
    }

    /// A backend refusal maps to its reason code.
    #[test]
    fn backend_refusal_maps() {
        let backend =
            ScriptedBackend::refusing(BackendFailure::CredentialRefused("no card".to_owned()));
        let manager = TransactionManager::new();
        let body = format!(
            "{{\"content\":\"{}\",\"contentType\":\"data\",\"selector\":{{\"keyusages\":[\"nonRepudiation\"]}}}}",
            base64::encode(b"qualified document"),
        );
        let response = dispatch(
            &request("POST", "/sign", Some("application/json")),
            body.as_bytes(),
            UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS),
            &backend,
            &manager,
        );
        let body = body_text(&response);
        assert!(body.contains("\"reasonCode\":401"), "{body:?}");
        assert!(body.contains("Unauthorized: no card"), "{body:?}");
    }

    /// A JWT body that is neither JWS nor JWE is refused.
    #[test]
    fn jwt_branch_counts_dots() {
        let backend = backend();
        let manager = TransactionManager::new();
        let now = UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS);
        let response = dispatch(
            &request("POST", "/sign", Some("application/jwt")),
            b"one",
            now,
            &backend,
            &manager,
        );
        assert!(
            body_text(&response).contains("JWT body is not compact JWS or JWE"),
            "{response:?}"
        );
        // Five segments selects execute, which finds no transaction.
        let response = dispatch(
            &request("POST", "/sign", Some("application/jwt")),
            b"a.b.c.d.e",
            now,
            &backend,
            &manager,
        );
        assert!(
            body_text(&response).contains("no active transaction"),
            "{response:?}"
        );
    }
}
