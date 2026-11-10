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
use crate::hash;
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
    if request
        .origin
        .as_deref()
        .is_none_or(|origin| !origin.starts_with("https://"))
    {
        return sign_error(
            values::REASON_FORBIDDEN,
            "Forbidden: sign Origin must use HTTPS",
            request.origin.as_deref(),
        );
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
    sign_json(
        &document,
        request.origin.as_deref(),
        now,
        backend,
        transactions,
    )
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
        transactions.execute(body, request.origin.as_deref(), now, backend)
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

/// The JSON `/sign` form: the raw subset of the advertised
/// surface, with the origin-bound challenge enforced for the
/// authentication key.
///
/// The JSON path serves `data` content as a raw signature under the
/// requested digest; digests, CMS forms, and other signature types
/// live on the transaction path, and asking for them here is refused
/// rather than silently substituted. The flight is reserved across
/// the sign: the specification allows one active signature creation
/// request at a time (v1.3 sec.2.1). The dispatcher gates Origin
/// before calling.
fn sign_json(
    document: &SignRequestDocument,
    origin: Option<&str>,
    now: SystemTime,
    backend: &dyn SigningBackend,
    transactions: &TransactionManager,
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
    let hash = match &document.hash_algorithm {
        None => HashAlg::Sha256,
        Some(name) => match hash::hash_named(name) {
            Some(hash) => hash,
            None => {
                return sign_error(
                    values::REASON_NOT_IMPLEMENTED,
                    &format!("Not Implemented: unsupported hash algorithm {name}"),
                    origin,
                );
            }
        },
    };
    if let Some(name) = &document.signature_type
        && name != "signature"
    {
        return sign_error(
            values::REASON_NOT_IMPLEMENTED,
            &format!("Not Implemented: signature type {name} is served on the transaction path"),
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
    let _flight = match transactions.reserve_sign(now) {
        Ok(flight) => flight,
        Err(error) => return sign_error(error.code, &error.message, origin),
    };
    let signature = backend.sign(SignRequest {
        purpose,
        hash,
        data: raw,
        origin: origin.map(str::to_owned),
    });
    match signature {
        Ok(signature) => {
            let signature = match ecdsa_adjust(signature, backend.key_algorithm(purpose)) {
                Ok(signature) => signature,
                Err(error) => return sign_error(error.code, &error.message, origin),
            };
            let response = SignResponseDocument::ok(
                base64::encode(&signature),
                backend.key_algorithm(purpose).scs_name(hash),
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
        request_with_origin(method, path, Some(ORIGIN), content_type)
    }

    /// A request with an explicit origin.
    fn request_with_origin(
        method: &str,
        path: &str,
        origin: Option<&str>,
        content_type: Option<&str>,
    ) -> Request {
        Request {
            method: method.to_owned(),
            path: path.to_owned(),
            origin: origin.map(str::to_owned),
            content_type: content_type.map(str::to_owned),
            body_length: 0,
        }
    }

    /// DER tag: SEQUENCE, opening an ECDSA signature.
    const DER_SEQUENCE_TAG: u8 = 0x30;

    /// A reason code as the JSON body carries it.
    fn reason(code: u16) -> Option<u64> {
        Some(u64::from(code))
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

    /// The response body as a JSON value.
    fn body_json(response: &[u8]) -> serde_json::Value {
        serde_json::from_str(body_text(response)).expect("JSON")
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

    /// Missing and plain-HTTP origins are refused before any parsing.
    #[test]
    fn json_origin_gate() {
        let backend = backend();
        let manager = TransactionManager::new();
        let now = UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS);
        for origin in [None, Some("http://example.com")] {
            let response = dispatch(
                &request_with_origin("POST", "/sign", origin, Some("application/json")),
                b"{}",
                now,
                &backend,
                &manager,
            );
            let body = body_json(&response);
            assert_eq!(
                body.get("reasonCode").and_then(serde_json::Value::as_u64),
                reason(values::REASON_FORBIDDEN)
            );
        }
        assert!(backend.signed().is_empty());
    }

    /// A requested digest is honored; an unknown one is refused as
    /// unimplemented rather than silently substituted.
    #[test]
    fn json_hash_is_honored() {
        use refineid_digest::HashAlg;
        let backend = backend();
        let manager = TransactionManager::new();
        let now = UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS);
        let nonce = "n".repeat(values::NONCE_MINIMUM_LENGTH);
        let body = format!(
            "{{\"content\":\"{}\",\"contentType\":\"data\",\"hashAlgorithm\":\"SHA384\"}}",
            base64::encode(format!("{ORIGIN};{nonce}").as_bytes())
        );
        let response = dispatch(
            &request("POST", "/sign", Some("application/json")),
            body.as_bytes(),
            now,
            &backend,
            &manager,
        );
        let body = body_json(&response);
        assert_eq!(
            body.get("signatureAlgorithm")
                .and_then(serde_json::Value::as_str),
            Some("SHA384withRSA")
        );
        assert_eq!(backend.signed().remove(0).hash, HashAlg::Sha384);
        let body = "{\"content\":\"eA==\",\"contentType\":\"data\",\"hashAlgorithm\":\"SHA1\"}";
        let response = dispatch(
            &request("POST", "/sign", Some("application/json")),
            body.as_bytes(),
            now,
            &backend,
            &manager,
        );
        assert_eq!(
            body_json(&response)
                .get("reasonCode")
                .and_then(serde_json::Value::as_u64),
            reason(values::REASON_NOT_IMPLEMENTED)
        );
    }

    /// CMS forms are refused on JSON with a pointer to the
    /// transaction path.
    #[test]
    fn json_signature_type_points_at_transactions() {
        let backend = backend();
        let manager = TransactionManager::new();
        let now = UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS);
        let body =
            "{\"content\":\"eA==\",\"contentType\":\"data\",\"signatureType\":\"cms-pades\"}";
        let response = dispatch(
            &request("POST", "/sign", Some("application/json")),
            body.as_bytes(),
            now,
            &backend,
            &manager,
        );
        let body = body_json(&response);
        assert_eq!(
            body.get("reasonCode").and_then(serde_json::Value::as_u64),
            reason(values::REASON_NOT_IMPLEMENTED)
        );
        assert!(
            body.get("reasonText")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|text| text.contains("transaction path"))
        );
        assert_eq!(backend.signed().len(), 0);
    }

    /// A JSON sign while the flight is held is refused without
    /// touching the backend.
    #[test]
    fn json_sign_yields_the_flight() {
        let backend = backend();
        let manager = TransactionManager::new();
        let now = UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS);
        let _held = manager.reserve_sign(now).expect("reserves");
        let nonce = "n".repeat(values::NONCE_MINIMUM_LENGTH);
        let body = format!(
            "{{\"content\":\"{}\",\"contentType\":\"data\"}}",
            base64::encode(format!("{ORIGIN};{nonce}").as_bytes())
        );
        let response = dispatch(
            &request("POST", "/sign", Some("application/json")),
            body.as_bytes(),
            now,
            &backend,
            &manager,
        );
        assert_eq!(
            body_json(&response)
                .get("reasonCode")
                .and_then(serde_json::Value::as_u64),
            reason(values::REASON_FORBIDDEN)
        );
        assert!(backend.signed().is_empty());
    }

    /// ECDSA answers carry DER; RSA answers carry the raw bytes.
    #[test]
    fn json_ecdsa_answers_der() {
        let minted = mint_certificate();
        let backend = ScriptedBackend::answering(
            [minted.der].into(),
            KeyAlgorithm::Ecdsa,
            b"card-signature".to_vec(),
        );
        let manager = TransactionManager::new();
        let now = UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS);
        let nonce = "n".repeat(values::NONCE_MINIMUM_LENGTH);
        let body = format!(
            "{{\"content\":\"{}\",\"contentType\":\"data\"}}",
            base64::encode(format!("{ORIGIN};{nonce}").as_bytes())
        );
        let response = dispatch(
            &request("POST", "/sign", Some("application/json")),
            body.as_bytes(),
            now,
            &backend,
            &manager,
        );
        let body = body_json(&response);
        let signature = body
            .get("signature")
            .and_then(serde_json::Value::as_str)
            .expect("signature");
        let decoded = base64::decode(signature).expect("base64");
        assert_eq!(decoded.first(), Some(&DER_SEQUENCE_TAG));
    }
}
