// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Byte-exact replay of the RAPP v26.10.22 operation-message corpus.
//!
//! Every body decodes into its typed message and re-encodes to the identical
//! bytes, so an independently written peer and this crate put the same bytes
//! on the wire. Every rejected body is refused.

use std::collections::BTreeMap;

use refineid_rapp::{
    CardKeyProfile, CardOperation, CardOperationResult, CardStatusMessage, CertificateFingerprint,
    CertificateKind, Envelope, MessageType, OperationId, PairId, ProgressEvent,
    ProtocolErrorMessage, ResultError, ResultStatus, SessionId, SignatureAlgorithm, TypedMessage,
    WireValue, decode_deterministic_cbor, encode_deterministic_cbor,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-operation-v26.10.22.json");
const SESSION_ID: SessionId = SessionId::from_array([0xbb; 16]);

#[derive(Deserialize)]
struct Corpus {
    format: String,
    protocol_document_version: String,
    fixed_inputs: FixedInputs,
    vectors: Vec<Vector>,
    rejected: Vec<Vector>,
}

#[derive(Deserialize)]
struct FixedInputs {
    operation_id_result: String,
    operation_id_error: String,
    pair_id: String,
    certificate_der: String,
    local_start_ms: u64,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    message_type: String,
    body_hex: String,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("the checked-in operation corpus must be valid JSON")
}

fn message_type(name: &str) -> MessageType {
    match name {
        "OperationRequest" => MessageType::OperationRequest,
        "OperationResult" => MessageType::OperationResult,
        "OperationProgress" => MessageType::OperationProgress,
        "PairingStored" => MessageType::PairingStored,
        "CardStatus" => MessageType::CardStatus,
        "Error" => MessageType::Error,
        other => panic!("unregistered corpus message type {other}"),
    }
}

fn body(hex_body: &str) -> BTreeMap<String, WireValue> {
    let WireValue::Map(map) = decode_deterministic_cbor(&hex::decode(hex_body).expect("valid hex"))
        .expect("corpus body is deterministic CBOR")
    else {
        panic!("corpus body must be a map");
    };
    map
}

/// Decodes one vector into its typed message exactly as a receiver would.
fn decode(vector: &Vector, inputs: &FixedInputs) -> Result<TypedMessage, String> {
    let envelope = Envelope::reconstruct(
        message_type(&vector.message_type),
        SESSION_ID,
        0,
        body(&vector.body_hex),
    )
    .map_err(|error| format!("{error:?}"))?;
    TypedMessage::from_envelope(envelope, inputs.local_start_ms)
        .map_err(|error| format!("{error:?}"))
}

fn find(corpus: &Corpus, name: &str) -> TypedMessage {
    let vector = corpus
        .vectors
        .iter()
        .find(|vector| vector.name == name)
        .unwrap_or_else(|| panic!("corpus lacks {name}"));
    decode(vector, &corpus.fixed_inputs).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn identifier(hex_text: &str) -> OperationId {
    OperationId::reconstruct(&hex::decode(hex_text).expect("valid hex")).expect("id length")
}

#[test]
fn corpus_names_this_protocol_version() {
    let corpus = corpus();
    assert_eq!(corpus.format, "fi.refineid.rapp.operation-vectors");
    assert_eq!(corpus.protocol_document_version, "26.10.22");
}

#[test]
fn every_body_decodes_and_re_encodes_byte_for_byte() {
    let corpus = corpus();
    for vector in &corpus.vectors {
        let message = decode(vector, &corpus.fixed_inputs)
            .unwrap_or_else(|error| panic!("{} fails decoding: {error}", vector.name));
        let encoded = encode_deterministic_cbor(&WireValue::Map(
            message
                .to_wire_body()
                .unwrap_or_else(|error| panic!("{} fails to encode: {error:?}", vector.name)),
        ))
        .expect("typed body encodes");
        assert_eq!(hex::encode(encoded), vector.body_hex, "{}", vector.name);
    }
}

#[test]
fn every_rejected_body_is_refused() {
    let corpus = corpus();
    for vector in &corpus.rejected {
        assert!(
            decode(vector, &corpus.fixed_inputs).is_err(),
            "{} was accepted",
            vector.name
        );
    }
}

#[test]
fn completed_responses_read_as_the_operation_they_answer() {
    let corpus = corpus();
    for (name, operation) in [
        ("result-completed-inspection", CardOperation::InspectCard),
        ("result-completed-identity", CardOperation::ReadIdentity),
        (
            "result-completed-certificate",
            CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            },
        ),
    ] {
        let TypedMessage::OperationResult(result) = find(&corpus, name) else {
            panic!("{name} is not a result");
        };
        result
            .response
            .as_ref()
            .unwrap_or_else(|| panic!("{name} carries no response"))
            .typed_for(&operation)
            .unwrap_or_else(|error| panic!("{name} does not answer its operation: {error:?}"));
    }
}

#[test]
fn results_and_errors_decode_to_their_meaning() {
    let corpus = corpus();
    for (name, status, error) in [
        (
            "result-rejected-user-cancelled",
            ResultStatus::Rejected,
            ResultError::UserCancelled,
        ),
        (
            "result-cancelled-operation-expired",
            ResultStatus::Cancelled,
            ResultError::OperationExpired,
        ),
        (
            "result-rejected-card-error",
            ResultStatus::Rejected,
            ResultError::CardError,
        ),
        (
            "result-rejected-retry-floor",
            ResultStatus::Rejected,
            ResultError::RetryFloor,
        ),
        (
            "result-rejected-invalid-lifetime",
            ResultStatus::Rejected,
            ResultError::InvalidLifetime,
        ),
    ] {
        let TypedMessage::OperationResult(result) = find(&corpus, name) else {
            panic!("{name} is a result");
        };
        assert_eq!(result.status, status, "{name}");
        assert_eq!(result.error, Some(error), "{name}");
    }
    let operation_id = identifier(&corpus.fixed_inputs.operation_id_error);
    assert_eq!(
        find(&corpus, "error-busy"),
        TypedMessage::Error(ProtocolErrorMessage::busy(operation_id))
    );
    assert_eq!(
        find(&corpus, "error-duplicate-operation"),
        TypedMessage::Error(ProtocolErrorMessage::duplicate(operation_id))
    );
    assert_eq!(
        find(&corpus, "error-operation-failed-bare"),
        TypedMessage::Error(ProtocolErrorMessage {
            error: ResultError::OperationFailed,
            operation_id: None,
        })
    );
}

#[test]
fn card_status_carries_the_certificate_fingerprint() {
    let corpus = corpus();
    let certificate = hex::decode(&corpus.fixed_inputs.certificate_der).expect("valid hex");
    assert_eq!(
        find(&corpus, "card-status-present"),
        TypedMessage::CardStatus(CardStatusMessage::Present(
            CertificateFingerprint::of_certificate(&certificate)
        ))
    );
    assert_eq!(
        find(&corpus, "card-status-absent"),
        TypedMessage::CardStatus(CardStatusMessage::Absent)
    );
}

#[test]
fn storage_and_progress_decode_to_their_meaning() {
    let corpus = corpus();
    let TypedMessage::PairingStored(stored) = find(&corpus, "pairing-stored") else {
        panic!("pairing-stored is a storage confirmation");
    };
    assert_eq!(
        stored.pair_id,
        PairId::reconstruct(&hex::decode(&corpus.fixed_inputs.pair_id).expect("valid hex"))
            .expect("pair id length")
    );
    let operation_id = identifier(&corpus.fixed_inputs.operation_id_result);
    for (name, event) in [
        ("progress-queued", ProgressEvent::Queued),
        ("progress-consent-shown", ProgressEvent::ConsentShown),
        ("progress-waiting-for-card", ProgressEvent::WaitingForCard),
        ("progress-card-wait-ended", ProgressEvent::CardWaitEnded),
    ] {
        let TypedMessage::OperationProgress(progress) = find(&corpus, name) else {
            panic!("{name} is a progress update");
        };
        assert_eq!(progress.event, event, "{name}");
        assert_eq!(progress.operation_id, operation_id, "{name}");
    }
}

#[test]
fn a_batch_carries_its_documents_and_signatures_in_order() {
    let corpus = corpus();
    let TypedMessage::OperationRequest(request) = find(&corpus, "request-batch-sign-documents")
    else {
        panic!("the batch request is admitted");
    };
    let CardOperation::BatchSignDocuments {
        document_names,
        key_profile,
        algorithm,
        digests,
    } = &request.operation
    else {
        panic!("the batch request names a batch");
    };
    assert_eq!(document_names, &["Contract.pdf", "Annex.pdf"]);
    assert_eq!(*key_profile, CardKeyProfile::EcdsaP256);
    assert_eq!(*algorithm, SignatureAlgorithm::EcdsaSha256);
    assert_eq!(digests.len(), document_names.len());

    let TypedMessage::OperationResult(completed) =
        find(&corpus, "result-completed-batch-signatures")
    else {
        panic!("the batch result is a result");
    };
    completed
        .validate_for(completed.operation_id, &request.operation)
        .expect("the completed batch answers the batch");
    let Ok(CardOperationResult::Signatures(signatures)) = completed
        .response
        .as_ref()
        .expect("a completed batch carries signatures")
        .typed_for(&request.operation)
    else {
        panic!("the completed batch reads as signatures");
    };
    assert_eq!(signatures.len(), digests.len());
}
