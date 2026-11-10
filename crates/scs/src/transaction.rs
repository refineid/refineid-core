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

//! The stateful SCS transaction flow (DVV SCS specification v1.3
//! sec.2.7): a signed `begin` establishes an encrypted channel, one
//! `execute` inside it produces the signature.
//!
//! `begin` arrives as a compact JWS signed by the relying service's
//! certificate; its payload carries the service's P-256 agreement key.
//! This service answers with an ephemeral public key, signed by the
//! card, and both sides derive the shared transaction key. `execute`
//! then rides as a direct-encryption A256GCM JWE under that key, and
//! so does its response. One transaction may be pending at a time;
//! `execute` consumes it whether it succeeds or not. The step logic
//! lives in the `begin` and `execution` modules; this module owns only
//! the pending slot.

use std::sync::Mutex;
use std::time::SystemTime;

use zeroize::Zeroizing;

use crate::backend::SigningBackend;
use crate::codec;
use crate::document::ExecuteDocument;
use crate::error::TransactionError;
use crate::jwe;
use crate::purpose::SignPurpose;
use crate::values;

/// One agreed SCS transaction awaiting its `execute` (v1.3 sec.2.7).
pub(crate) struct AgreedTransaction {
    /// The agreed A256GCM transaction key, scrubbed on drop.
    pub(crate) key: Zeroizing<[u8; values::TRANSACTION_KEY_LENGTH]>,
    /// The Origin that began the transaction; `execute` must match.
    pub(crate) origin: String,
    /// The card key the selector chose at `begin`.
    pub(crate) purpose: SignPurpose,
    /// The service's base64 agreement key, which the authentication
    /// challenge must be bound to.
    pub(crate) server_key: String,
}

/// The pending transaction slot.
pub struct TransactionManager {
    pending: Mutex<Option<AgreedTransaction>>,
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self {
            pending: Mutex::new(None),
        }
    }
}

impl core::fmt::Debug for TransactionManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let occupied = self
            .pending
            .lock()
            .map(|held| held.is_some())
            .unwrap_or(true);
        f.debug_struct("TransactionManager")
            .field("pending", &occupied)
            .finish()
    }
}

impl TransactionManager {
    /// A manager with no pending transaction.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle the `begin` JWS: verify it, agree the transaction key,
    /// and answer the card-signed response JWT.
    pub fn begin(
        &self,
        compact_jws: &[u8],
        origin: Option<&str>,
        now: SystemTime,
        backend: &dyn SigningBackend,
    ) -> Result<String, TransactionError> {
        let request_origin = codec::validated_origin(origin)?;
        let compact = core::str::from_utf8(compact_jws)
            .map_err(|_| TransactionError::bad_request("JWT body is not UTF-8"))?;
        let segments: Vec<&str> = compact.split('.').collect();
        if segments.len() != values::JWS_SEGMENT_COUNT
            || segments.iter().any(|segment| segment.is_empty())
        {
            return Err(TransactionError::bad_request(
                "begin transaction must be a compact JWS",
            ));
        }
        if self
            .pending
            .lock()
            .map(|held| held.is_some())
            .unwrap_or(true)
        {
            return Err(TransactionError::forbidden(
                "another signature request is already active",
            ));
        }
        let outcome = crate::begin::perform(&segments, &request_origin, now, backend)?;
        let raced = self
            .pending
            .lock()
            .map(|mut held| {
                if held.is_some() {
                    return true;
                }
                *held = Some(outcome.state);
                false
            })
            .unwrap_or(true);
        if raced {
            return Err(TransactionError::forbidden(
                "another signature request became active",
            ));
        }
        Ok(outcome.response)
    }

    /// Handle the `execute` JWE.
    ///
    /// Decrypts it under the pending key, signs, and answers the
    /// encrypted response; the pending transaction is consumed either
    /// way.
    pub fn execute(
        &self,
        compact_jwe: &[u8],
        origin: Option<&str>,
        backend: &dyn SigningBackend,
    ) -> Result<String, TransactionError> {
        let request_origin = codec::validated_origin(origin)?;
        let state = self.pending.lock().ok().and_then(|mut held| held.take());
        let Some(state) = state else {
            return Err(TransactionError::bad_request("no active transaction"));
        };
        if state.origin != request_origin {
            return Err(TransactionError::forbidden(
                "execute Origin does not match begin Origin",
            ));
        }
        let payload_bytes = jwe::decrypt(compact_jwe, &state.key)?;
        let value: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|_| TransactionError::bad_request("execute payload is not valid JSON"))?;
        let payload = ExecuteDocument::decode(&value)
            .map_err(|()| TransactionError::bad_request("execute payload is not valid JSON"))?;
        crate::execution::respond(&payload, &state, backend)
    }
}

#[cfg(test)]
mod tests {
    use super::TransactionManager;
    use crate::backend::BackendFailure;
    use crate::base64;
    use crate::error::TransactionError;
    use crate::purpose::{KeyAlgorithm, SignPurpose};
    use crate::test_support::{ScriptedBackend, mint_certificate, mint_jws};
    use std::time::{Duration, UNIX_EPOCH};

    /// Unix seconds of 2023-11-14T22:13:20Z, inside every test window.
    const TEST_NOW_SECONDS: u64 = 1_700_000_000;

    /// The test origin.
    const ORIGIN: &str = "https://example.com";

    /// A moment inside the test windows.
    fn test_now() -> std::time::SystemTime {
        UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS)
    }

    /// One relying-service identity: the minted certificate, whose key
    /// signs the JWS and agrees the channel.
    struct Service {
        cert_der: Vec<u8>,
        key: p256::ecdsa::SigningKey,
        spki_der: Vec<u8>,
    }

    /// Mint the service identity.
    fn service() -> Service {
        let minted = mint_certificate();
        let point = minted.key.verifying_key().to_sec1_point(false);
        let spki_der = crate::localhost::subject_public_key_info(point.as_bytes())
            .expect("service SPKI encodes");
        Service {
            cert_der: minted.der,
            key: minted.key,
            spki_der,
        }
    }

    /// The service's agreement scalar.
    fn service_scalar(service: &Service) -> &elliptic_curve::NonZeroScalar<p256::NistP256> {
        service.key.as_nonzero_scalar()
    }

    /// A begin payload for `service`.
    fn begin_payload(service: &Service) -> serde_json::Value {
        serde_json::from_str(&format!(
            "{{\"version\":\"1.3\",\"serverKey\":\"{}\",\"serverCert\":\"{}\"}}",
            base64::encode(&service.spki_der),
            base64::encode(&service.cert_der),
        ))
        .expect("payload parses")
    }

    /// The shared key of `service` with the begin answer's ephemeral
    /// key.
    fn shared_key(service: &Service, begin_answer: &str) -> Vec<u8> {
        let segments: Vec<&str> = begin_answer.split('.').collect();
        assert_eq!(segments.len(), crate::values::JWS_SEGMENT_COUNT);
        let payload = segments[1];
        let payload = base64::decode_url(payload).expect("payload decodes");
        let response: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
        let transaction = response
            .get("transaction")
            .and_then(serde_json::Value::as_str)
            .expect("transaction key");
        let peer_der = base64::decode(transaction).expect("SPKI decodes");
        let peer = crate::codec::p256_spki_key(&peer_der).expect("peer parses");
        let shared =
            elliptic_curve::ecdh::diffie_hellman(service_scalar(service), peer.as_affine());
        shared.raw_secret_bytes().as_slice().to_vec()
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

    /// Signs placed by a begin alone.
    const SIGNS_AFTER_BEGIN: usize = 1;

    /// Signs placed by a begin and its execute.
    const SIGNS_AFTER_EXECUTE: usize = 2;

    /// Begin, then execute: the channel carries one signature.
    #[test]
    fn begin_then_execute_signs() {
        use refineid_digest::HashAlg;
        let service = service();
        let backend = backend();
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        let answer = manager
            .begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("begin succeeds");
        // The begin response is a signed JWT carrying the ephemeral key.
        assert_eq!(answer.split('.').count(), crate::values::JWS_SEGMENT_COUNT);
        assert_eq!(backend.signed().len(), SIGNS_AFTER_BEGIN);
        let begin_sign = backend.signed().remove(0);
        assert_eq!(begin_sign.purpose, SignPurpose::Authentication);
        assert_eq!(begin_sign.hash, HashAlg::Sha256);
        // The execute rides encrypted under the agreed key.
        let key = shared_key(&service, &answer);
        let nonce = "n".repeat(crate::values::NONCE_MINIMUM_LENGTH);
        let challenge = format!("{ORIGIN};{nonce};{}", base64::encode(&service.spki_der));
        let execute = format!(
            "{{\"version\":\"1.3\",\"content\":\"{}\",\"contentType\":\"data\"}}",
            base64::encode(challenge.as_bytes())
        );
        let key_array: &[u8; crate::values::TRANSACTION_KEY_LENGTH] =
            key.as_slice().try_into().expect("32-byte key");
        let envelope = crate::jwe::encrypt(execute.as_bytes(), key_array).expect("encrypts");
        let sealed = manager
            .execute(envelope.as_bytes(), Some(ORIGIN), &backend)
            .expect("execute succeeds");
        let plaintext = crate::jwe::decrypt(sealed.as_bytes(), key_array).expect("decrypts");
        let response: serde_json::Value = serde_json::from_slice(&plaintext).expect("JSON");
        assert_eq!(
            response.get("status").and_then(serde_json::Value::as_str),
            Some("ok")
        );
        assert_eq!(
            response
                .get("signature")
                .and_then(serde_json::Value::as_str),
            Some(base64::encode(b"card-signature")).as_deref()
        );
        assert_eq!(backend.signed().len(), SIGNS_AFTER_EXECUTE);
    }

    /// A second begin while one is pending is forbidden, and execute
    /// consumes the transaction either way.
    #[test]
    fn pending_transaction_is_exclusive_and_consumed() {
        let service = service();
        let backend = backend();
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        manager
            .begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("first begin succeeds");
        assert_eq!(
            manager.begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend),
            Err(TransactionError::forbidden(
                "another signature request is already active"
            ))
        );
        // A garbage execute still consumes the pending transaction.
        assert!(
            manager
                .execute(b"not-a-jwe", Some(ORIGIN), &backend)
                .is_err()
        );
        assert_eq!(
            manager.execute(b"not-a-jwe", Some(ORIGIN), &backend),
            Err(TransactionError::bad_request("no active transaction"))
        );
    }

    /// Execute from another origin is forbidden.
    #[test]
    fn execute_origin_must_match_begin() {
        let service = service();
        let backend = backend();
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        let answer = manager
            .begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("begin succeeds");
        let key = shared_key(&service, &answer);
        let key_array: &[u8; crate::values::TRANSACTION_KEY_LENGTH] =
            key.as_slice().try_into().expect("32-byte key");
        let envelope = crate::jwe::encrypt(b"{}", key_array).expect("encrypts");
        assert_eq!(
            manager.execute(envelope.as_bytes(), Some("https://other.example"), &backend),
            Err(TransactionError::forbidden(
                "execute Origin does not match begin Origin"
            ))
        );
    }

    /// A backend with no certificate fails the begin before any
    /// signing.
    #[test]
    fn empty_chain_refuses_begin() {
        let service = service();
        let backend = ScriptedBackend::answering(Vec::new(), KeyAlgorithm::Rsa, Vec::new());
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        assert_eq!(
            manager.begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend),
            Err(TransactionError::internal_error(
                "signing backend returned no end-user certificate"
            ))
        );
        assert!(backend.signed().is_empty());
    }

    /// A backend refusal fails the begin with the backend's reason.
    #[test]
    fn backend_refusal_fails_begin() {
        let service = service();
        let minted = mint_certificate();
        let backend = ScriptedBackend::refusing_sign(
            [minted.der].into(),
            BackendFailure::CredentialRefused("no card".to_owned()),
        );
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        assert_eq!(
            manager.begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend),
            Err(TransactionError {
                code: crate::values::REASON_UNAUTHORIZED,
                message: "Unauthorized: no card".to_owned(),
            })
        );
    }
}
