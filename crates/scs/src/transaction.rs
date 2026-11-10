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
//! so does its response.
//!
//! The specification allows only one active signature creation
//! request at a time (v1.3 sec.2.1), across the JSON and transaction
//! paths alike: one flight slot, reserved before any card I/O and
//! released after. A reservation held across a PIN prompt blocks the
//! next request with the specified "already active" reason instead of
//! queueing a second ceremony. An agreed transaction the caller never
//! executes expires after [`values::TRANSACTION_TIME_TO_LIVE`], so a
//! closed tab cannot wedge the service.
//!
//! The step logic lives in the `begin` and `execution` modules; this
//! module owns only the flight slot. No mutex is ever held across
//! card I/O: reservation, promotion, and release are each a single
//! locked transition.

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
    /// challenge is bound to.
    pub(crate) server_key: String,
}

/// The single signature flight: idle, reserved across card I/O, or
/// an agreed transaction awaiting its `execute`.
enum Slot {
    /// No ceremony in flight.
    Idle,
    /// A ceremony reserved the flight and has not finished.
    Busy,
    /// An agreed transaction awaiting its `execute`, with the moment
    /// it was agreed.
    Active(AgreedTransaction, SystemTime),
}

/// A held reservation of the single flight, releasing it on drop.
pub(crate) struct FlightReservation<'a> {
    slot: &'a Mutex<Slot>,
    keep: bool,
}

impl FlightReservation<'_> {
    /// Promote the reservation to an agreed transaction awaiting its
    /// `execute`.
    fn promote(mut self, state: AgreedTransaction, now: SystemTime) {
        if let Ok(mut slot) = self.slot.lock() {
            *slot = Slot::Active(state, now);
        }
        self.keep = true;
    }
}

impl Drop for FlightReservation<'_> {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if let Ok(mut slot) = self.slot.lock()
            && matches!(*slot, Slot::Busy)
        {
            *slot = Slot::Idle;
        }
    }
}

/// The single-flight slot.
pub struct TransactionManager {
    slot: Mutex<Slot>,
}

impl core::fmt::Debug for TransactionManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let occupied = self
            .slot
            .lock()
            .map(|slot| !matches!(*slot, Slot::Idle))
            .unwrap_or(true);
        f.debug_struct("TransactionManager")
            .field("pending", &occupied)
            .finish()
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self {
            slot: Mutex::new(Slot::Idle),
        }
    }
}

impl TransactionManager {
    /// A manager with no ceremony in flight.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve the flight for one JSON sign, releasing it when the
    /// reservation drops.
    pub(crate) fn reserve_sign(
        &self,
        now: SystemTime,
    ) -> Result<FlightReservation<'_>, TransactionError> {
        let mut slot = self.slot.lock().map_err(|_| busy())?;
        evict_expired(&mut slot, now);
        if !matches!(*slot, Slot::Idle) {
            return Err(busy());
        }
        *slot = Slot::Busy;
        Ok(FlightReservation {
            slot: &self.slot,
            keep: false,
        })
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
        let reservation = self.reserve_sign(now)?;
        match crate::begin::perform(&segments, &request_origin, now, backend) {
            Ok(outcome) => {
                reservation.promote(outcome.state, now);
                Ok(outcome.response)
            }
            Err(error) => Err(error),
        }
    }

    /// Handle the `execute` JWE.
    ///
    /// Decrypts it under the pending key, signs, and answers the
    /// encrypted response; the pending transaction is consumed either
    /// way, and the flight stays reserved across the ceremony.
    pub fn execute(
        &self,
        compact_jwe: &[u8],
        origin: Option<&str>,
        now: SystemTime,
        backend: &dyn SigningBackend,
    ) -> Result<String, TransactionError> {
        let request_origin = codec::validated_origin(origin)?;
        let state = {
            let mut slot = self.slot.lock().map_err(|_| busy())?;
            let expired = is_expired(&slot, now);
            if expired {
                *slot = Slot::Idle;
            }
            if matches!(*slot, Slot::Busy) {
                return Err(busy());
            }
            let Slot::Active(state, _) = core::mem::replace(&mut *slot, Slot::Busy) else {
                *slot = Slot::Idle;
                if expired {
                    return Err(TransactionError::bad_request("transaction expired"));
                }
                return Err(TransactionError::bad_request("no active transaction"));
            };
            state
        };
        let _reservation = FlightReservation {
            slot: &self.slot,
            keep: false,
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
        crate::execution::respond(&payload, &state, backend, now)
    }
}

/// The specified "already active" refusal.
fn busy() -> TransactionError {
    TransactionError::forbidden("another signature request is already active")
}

/// Whether the slot holds an agreed transaction older than its
/// time to live.
fn is_expired(slot: &Slot, now: SystemTime) -> bool {
    matches!(slot, Slot::Active(_, agreed) if now
        .duration_since(*agreed)
        .is_ok_and(|age| age > values::TRANSACTION_TIME_TO_LIVE))
}

/// Drop an agreed transaction older than its time to live, so an
/// abandoned `begin` cannot wedge the service.
fn evict_expired(slot: &mut Slot, now: SystemTime) {
    if is_expired(slot, now) {
        *slot = Slot::Idle;
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
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Unix seconds of 2023-11-14T22:13:20Z, inside every test window.
    const TEST_NOW_SECONDS: u64 = 1_700_000_000;

    /// The test origin.
    const ORIGIN: &str = "https://example.com";

    /// A moment inside the test windows.
    fn test_now() -> SystemTime {
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

    /// The shared key as the fixed transaction array.
    fn shared_array(
        service: &Service,
        begin_answer: &str,
    ) -> [u8; crate::values::TRANSACTION_KEY_LENGTH] {
        shared_key(service, begin_answer)
            .as_slice()
            .try_into()
            .expect("32-byte key")
    }

    /// A backend answering a fixed signature for the minted chain.
    fn backend() -> ScriptedBackend {
        backend_with(KeyAlgorithm::Rsa)
    }

    /// A backend answering a fixed signature behind `algorithm`.
    fn backend_with(algorithm: KeyAlgorithm) -> ScriptedBackend {
        let minted = mint_certificate();
        ScriptedBackend::answering([minted.der].into(), algorithm, b"card-signature".to_vec())
    }

    /// Signs placed by a begin alone.
    const SIGNS_AFTER_BEGIN: usize = 1;

    /// Signs placed by a begin and its execute.
    const SIGNS_AFTER_EXECUTE: usize = 2;

    /// Begin, then execute: the channel carries one signature, and
    /// the SCS binds the challenge to the agreement it made.
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
        assert_eq!(answer.split('.').count(), crate::values::JWS_SEGMENT_COUNT);
        assert_eq!(backend.signed().len(), SIGNS_AFTER_BEGIN);
        let begin_sign = backend.signed().remove(0);
        assert_eq!(begin_sign.purpose, SignPurpose::Authentication);
        assert_eq!(begin_sign.hash, HashAlg::Sha256);
        // The caller sends origin;nonce; the card signs the bound triple.
        let key = shared_array(&service, &answer);
        let nonce = "n".repeat(crate::values::NONCE_MINIMUM_LENGTH);
        let challenge = format!("{ORIGIN};{nonce}");
        let execute = format!(
            "{{\"version\":\"1.3\",\"content\":\"{}\",\"contentType\":\"data\"}}",
            base64::encode(challenge.as_bytes())
        );
        let envelope = crate::jwe::encrypt(execute.as_bytes(), &key).expect("encrypts");
        let sealed = manager
            .execute(envelope.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("execute succeeds");
        let plaintext = crate::jwe::decrypt(sealed.as_bytes(), &key).expect("decrypts");
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
        assert_eq!(
            response
                .get("signatureAlgorithm")
                .and_then(serde_json::Value::as_str),
            Some("SHA256withRSA")
        );
        assert_eq!(backend.signed().len(), SIGNS_AFTER_EXECUTE);
        let bound = format!("{challenge};{}", base64::encode(&service.spki_der));
        assert_eq!(backend.signed().remove(1).data, bound.as_bytes());
    }

    /// A pre-bound triple is refused: the caller sends the pair.
    #[test]
    fn prebound_triple_is_refused() {
        let service = service();
        let backend = backend();
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        let answer = manager
            .begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("begin succeeds");
        let key = shared_array(&service, &answer);
        let nonce = "n".repeat(crate::values::NONCE_MINIMUM_LENGTH);
        let triple = format!("{ORIGIN};{nonce};{}", base64::encode(&service.spki_der));
        let execute = format!(
            "{{\"version\":\"1.3\",\"content\":\"{}\",\"contentType\":\"data\"}}",
            base64::encode(triple.as_bytes())
        );
        let envelope = crate::jwe::encrypt(execute.as_bytes(), &key).expect("encrypts");
        assert_eq!(
            manager.execute(envelope.as_bytes(), Some(ORIGIN), test_now(), &backend),
            Err(TransactionError::bad_request(
                "authentication challenge must be origin;nonce"
            ))
        );
    }

    /// The signature algorithm defaults to the card key and refuses a
    /// mismatch.
    #[test]
    fn signature_algorithm_follows_the_key() {
        let service = service();
        let backend = backend_with(KeyAlgorithm::Ecdsa);
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        let answer = manager
            .begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("begin succeeds");
        let key = shared_array(&service, &answer);
        // Omitted: the ECDSA default answers, and the raw pair signs
        // as DER.
        let nonce = "n".repeat(crate::values::NONCE_MINIMUM_LENGTH);
        let execute = format!(
            "{{\"version\":\"1.3\",\"content\":\"{}\",\"contentType\":\"data\"}}",
            base64::encode(format!("{ORIGIN};{nonce}").as_bytes())
        );
        let envelope = crate::jwe::encrypt(execute.as_bytes(), &key).expect("encrypts");
        let sealed = manager
            .execute(envelope.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("execute succeeds");
        let plaintext = crate::jwe::decrypt(sealed.as_bytes(), &key).expect("decrypts");
        let response: serde_json::Value = serde_json::from_slice(&plaintext).expect("JSON");
        assert_eq!(
            response
                .get("signatureAlgorithm")
                .and_then(serde_json::Value::as_str),
            Some("SHA256withECDSA")
        );
    }

    /// An explicit signature algorithm that contradicts the card key
    /// is refused.
    #[test]
    fn mismatched_signature_algorithm_is_refused() {
        let service = service();
        let backend = backend_with(KeyAlgorithm::Ecdsa);
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        let answer = manager
            .begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("begin succeeds");
        let key = shared_array(&service, &answer);
        let nonce = "n".repeat(crate::values::NONCE_MINIMUM_LENGTH);
        let execute = format!(
            "{{\"version\":\"1.3\",\"content\":\"{}\",\"contentType\":\"data\",\"signatureAlgorithm\":\"RSA\"}}",
            base64::encode(format!("{ORIGIN};{nonce}").as_bytes())
        );
        let envelope = crate::jwe::encrypt(execute.as_bytes(), &key).expect("encrypts");
        assert_eq!(
            manager.execute(envelope.as_bytes(), Some(ORIGIN), test_now(), &backend),
            Err(TransactionError::bad_request(
                "signature algorithm RSA does not match the card key"
            ))
        );
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
                .execute(b"not-a-jwe", Some(ORIGIN), test_now(), &backend)
                .is_err()
        );
        assert_eq!(
            manager.execute(b"not-a-jwe", Some(ORIGIN), test_now(), &backend),
            Err(TransactionError::bad_request("no active transaction"))
        );
    }

    /// An agreed transaction the caller never executes expires.
    #[test]
    fn abandoned_transaction_expires() {
        let service = service();
        let backend = backend();
        let manager = TransactionManager::new();
        let begin_jws = mint_jws(&service.key, &begin_payload(&service));
        manager
            .begin(begin_jws.as_bytes(), Some(ORIGIN), test_now(), &backend)
            .expect("begin succeeds");
        let late = test_now() + crate::values::TRANSACTION_TIME_TO_LIVE + Duration::from_secs(1);
        assert_eq!(
            manager.execute(b"not-a-jwe", Some(ORIGIN), late, &backend),
            Err(TransactionError::bad_request("transaction expired"))
        );
        // And the flight is free again.
        manager
            .begin(begin_jws.as_bytes(), Some(ORIGIN), late, &backend)
            .expect("begin succeeds after expiry");
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
        let key = shared_array(&service, &answer);
        let envelope = crate::jwe::encrypt(b"{}", &key).expect("encrypts");
        assert_eq!(
            manager.execute(
                envelope.as_bytes(),
                Some("https://other.example"),
                test_now(),
                &backend
            ),
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
