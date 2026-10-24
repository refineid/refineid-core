// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! A batch is admitted only when its completed result travels in one frame
//! (RAPP v26.10.22 section 7.2 item 4, section 9.3), and a seal the frame
//! limit refuses leaves the send sequence where it was (section 7.2 item 3).

use std::collections::BTreeMap;

use refineid_rapp::{
    CardKeyProfile, CardOperation, CardOperationError, CardOperationResult, Envelope, GrantsHash,
    HandshakeRole, MAX_FRAME_PLAINTEXT, MessageType, OPERATION_ID_SIZE, OperationId,
    OperationRequest, OperationResultMessage, PAIR_ID_SIZE, PairId, ProfileName, ProxyDispatch,
    ProxyOperationEngine, RequestError, RequesterEngineError, RequesterOperationEngine,
    ResultError, SESSION_ID_SIZE, SecureChannel, SessionHandshakeParameters, SessionId,
    SignatureAlgorithm, TypedMessage, UserApproval, WireValue, generate_pair_key_material,
};

const START_MS: u64 = 1_000;
const LIFETIME_MS: u64 = 60_000;
const MAXIMUM_LIFETIME_MS: u64 = 300_000;
const SHA256_DIGEST_SIZE: usize = 32;
/// Every signature of a sealed batch is `u8::MAX`; its length is what the
/// frame bound sees.
const SIGNATURE_BYTE: u8 = u8::MAX;
/// The first `rsa_2048` batch size whose completed result exceeds
/// `MAX_FRAME_PLAINTEXT`.
const RSA_2048_SIGNATURES_OVER_ONE_FRAME: usize = 253;
const TRANSPORT_PROFILE: &str = "relay-websocket-v1";

/// A batch request built without the admission check, so an oversized one
/// can be offered to each border.
fn batch(byte: u8, key_profile: CardKeyProfile, documents: usize) -> OperationRequest {
    let algorithm = match key_profile {
        CardKeyProfile::EcdsaP256 | CardKeyProfile::EcdsaP384 => SignatureAlgorithm::EcdsaSha256,
        CardKeyProfile::Rsa2048 | CardKeyProfile::Rsa3072 => SignatureAlgorithm::RsaPkcs1Sha256,
    };
    OperationRequest {
        operation_id: OperationId::from_array([byte; OPERATION_ID_SIZE]),
        profile: ProfileName::DocumentSigning,
        local_start_ms: START_MS,
        expires_after_ms: LIFETIME_MS,
        operation: CardOperation::BatchSignDocuments {
            document_names: (0..documents)
                .map(|index| format!("Document {index}.pdf"))
                .collect(),
            key_profile,
            algorithm,
            digests: vec![vec![SIGNATURE_BYTE; SHA256_DIGEST_SIZE]; documents],
        },
    }
}

/// The `operation.request` body of `request` as the wire carries it.
fn wire_body(request: &OperationRequest) -> BTreeMap<String, WireValue> {
    let (action, context, payload) = request.wire_parts();
    let mut body = BTreeMap::new();
    body.insert(
        "operation_id".into(),
        WireValue::Bytes(request.operation_id.as_bytes().to_vec()),
    );
    body.insert(
        "profile".into(),
        WireValue::Text(request.profile.as_str().to_owned()),
    );
    body.insert("action".into(), WireValue::Text(action.to_owned()));
    body.insert(
        "expires_after_ms".into(),
        WireValue::Unsigned(request.expires_after_ms),
    );
    body.insert("context".into(), WireValue::Map(context));
    body.insert("payload".into(), WireValue::Map(payload));
    body
}

/// Whether the completed result of `count` signatures of `key_profile`
/// encodes within one frame at the largest sequence.
fn result_encodes_in_one_frame(count: usize, key_profile: CardKeyProfile) -> bool {
    let signatures = vec![vec![SIGNATURE_BYTE; key_profile.signature_size()]; count];
    let message = OperationResultMessage::completed(
        OperationId::from_array([SIGNATURE_BYTE; OPERATION_ID_SIZE]),
        &CardOperationResult::Signatures(signatures),
    );
    let envelope = Envelope::reconstruct(
        MessageType::OperationResult,
        SessionId::from_array([SIGNATURE_BYTE; SESSION_ID_SIZE]),
        u64::MAX,
        message.to_wire_body().expect("a completed result encodes"),
    )
    .expect("a completed result fits its schema");
    match envelope.encode() {
        Ok(bytes) => bytes.len() <= MAX_FRAME_PLAINTEXT,
        Err(_) => false,
    }
}

fn admitted(count: usize, key_profile: CardKeyProfile) -> bool {
    batch(1, key_profile, count).validate().is_ok()
}

/// The smallest batch of `key_profile` the admission check refuses.
fn first_refused_count(key_profile: CardKeyProfile) -> usize {
    let mut low = 1;
    let mut high = MAX_FRAME_PLAINTEXT;
    assert!(admitted(low, key_profile));
    assert!(!admitted(high, key_profile));
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if admitted(middle, key_profile) {
            low = middle;
        } else {
            high = middle;
        }
    }
    high
}

/// Two ends of one operational session after the Noise KK handshake:
/// (requester, custodian).
fn session_channels() -> (SecureChannel, SecureChannel) {
    let requester_keys = generate_pair_key_material().expect("requester keys");
    let custodian_keys = generate_pair_key_material().expect("custodian keys");
    let pair_id = PairId::from_array([1; PAIR_ID_SIZE]);
    let grants_hash = GrantsHash::from_array([2; 32]);
    let mut requester = refineid_rapp::HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Initiator,
        local_keys: &requester_keys,
        remote_public_key: custodian_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile: TRANSPORT_PROFILE,
    })
    .expect("requester handshake");
    let mut custodian = refineid_rapp::HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Responder,
        local_keys: &custodian_keys,
        remote_public_key: requester_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile: TRANSPORT_PROFILE,
    })
    .expect("custodian handshake");
    let first = requester.write_message().expect("message 1");
    custodian.read_message(&first).expect("message 1 read");
    let second = custodian.write_message().expect("message 2");
    requester.read_message(&second).expect("message 2 read");
    (
        requester
            .complete()
            .expect("requester complete")
            .secure_channel,
        custodian
            .complete()
            .expect("custodian complete")
            .secure_channel,
    )
}

fn sent(dispatch: ProxyDispatch) -> TypedMessage {
    match dispatch {
        ProxyDispatch::Send(message) => message,
        other => panic!("expected a message to send, got {other:?}"),
    }
}

#[test]
fn a_batch_whose_result_overflows_one_frame_is_refused() {
    let request = batch(
        1,
        CardKeyProfile::Rsa2048,
        RSA_2048_SIGNATURES_OVER_ONE_FRAME,
    );
    assert_eq!(
        OperationRequest::from_wire_body(wire_body(&request), START_MS),
        Err(RequestError::Refused(
            refineid_rapp::OperationRequestRefusal {
                operation_id: request.operation_id,
                error: ResultError::UnsupportedParameter,
            }
        ))
    );
    let mut requester = RequesterOperationEngine::new();
    assert_eq!(
        requester.begin(request).err(),
        Some(RequesterEngineError::InvalidLocalRequest(
            CardOperationError::BatchTooLarge
        ))
    );
}

#[test]
fn the_largest_batch_that_fits_is_admitted() {
    let count = RSA_2048_SIGNATURES_OVER_ONE_FRAME - 1;
    let request = batch(1, CardKeyProfile::Rsa2048, count);
    let mut requester = RequesterOperationEngine::new();
    let wire = requester
        .begin(request.clone())
        .expect("the largest batch that fits starts");
    let mut engine = ProxyOperationEngine::new(vec![ProfileName::DocumentSigning]);
    let received = OperationRequest::from_wire_body(wire_body(&request), START_MS)
        .expect("the custodian admits the batch");
    assert_eq!(received.operation, request.operation);
    assert!(matches!(
        engine.receive(TypedMessage::OperationRequest(received)),
        Ok(ProxyDispatch::InspectPrerequisites(_))
    ));
    drop(wire);
    engine
        .prerequisites_complete(request.operation_id, START_MS, MAXIMUM_LIFETIME_MS)
        .expect("the reads complete");
    engine
        .approve(
            request.operation_id,
            UserApproval::for_request(&request, START_MS),
            START_MS,
            MAXIMUM_LIFETIME_MS,
        )
        .expect("approval");
    for _ in 0..count {
        engine
            .record_batch_signature(
                request.operation_id,
                vec![SIGNATURE_BYTE; CardKeyProfile::Rsa2048.signature_size()],
            )
            .expect("one signature");
    }
    let result = sent(
        engine
            .complete_batch(request.operation_id)
            .expect("every document is signed"),
    );
    let (mut requester_channel, mut custodian_channel) = session_channels();
    let frame = custodian_channel
        .seal(
            result.message_type(),
            result.to_wire_body().expect("the result encodes"),
        )
        .expect("the result of the largest batch that fits seals");
    let opened = requester_channel
        .open(&frame)
        .expect("the requester opens it");
    assert_eq!(opened.message_type, MessageType::OperationResult);
}

#[test]
fn batch_bounds_hold_for_every_key_profile() {
    for key_profile in [
        CardKeyProfile::EcdsaP256,
        CardKeyProfile::EcdsaP384,
        CardKeyProfile::Rsa2048,
        CardKeyProfile::Rsa3072,
    ] {
        let refused = first_refused_count(key_profile);
        assert!(
            result_encodes_in_one_frame(refused - 1, key_profile),
            "{key_profile:?}: the largest admitted batch encodes in one frame"
        );
        assert!(
            !result_encodes_in_one_frame(refused, key_profile),
            "{key_profile:?}: the first refused batch does not"
        );
    }
    assert_eq!(
        first_refused_count(CardKeyProfile::Rsa2048),
        RSA_2048_SIGNATURES_OVER_ONE_FRAME
    );
}

#[test]
fn a_refused_seal_leaves_the_send_sequence_unchanged() {
    let (mut requester_channel, mut custodian_channel) = session_channels();
    let oversized = OperationResultMessage::completed(
        OperationId::from_array([SIGNATURE_BYTE; OPERATION_ID_SIZE]),
        &CardOperationResult::Certificate(vec![SIGNATURE_BYTE; MAX_FRAME_PLAINTEXT]),
    );
    assert!(
        custodian_channel
            .seal(
                MessageType::OperationResult,
                oversized.to_wire_body().expect("the body builds"),
            )
            .is_err()
    );
    let fitting = OperationResultMessage::completed(
        OperationId::from_array([SIGNATURE_BYTE; OPERATION_ID_SIZE]),
        &CardOperationResult::Certificate(vec![SIGNATURE_BYTE; SHA256_DIGEST_SIZE]),
    );
    let frame = custodian_channel
        .seal(
            MessageType::OperationResult,
            fitting.to_wire_body().expect("the body builds"),
        )
        .expect("the next envelope seals");
    let opened = requester_channel
        .open(&frame)
        .expect("the peer accepts the first sequence");
    assert_eq!(opened.sequence, 0);
}
