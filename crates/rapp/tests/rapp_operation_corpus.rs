// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Byte-exact replay of the RAPP v26.10.10 operation-message corpus.
//!
//! Every body decodes into its typed message and re-encodes to the identical
//! bytes, so an independently written peer and this crate put the same bytes
//! on the wire. Request vectors also pin the section 8.2.1 commitment.

use std::collections::BTreeMap;

use refineid_rapp::{
    CardKeyProfile, CardOperation, CardOperationResult, CertificateKind, Envelope, MessageType,
    OperationId, OperationReference, OperationState, PairId, ProtocolErrorMessage, ResultError,
    ResultStatus, SessionId, SignatureAlgorithm, TypedMessage, WireValue,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-operation-v26.10.10.json");

#[derive(Deserialize)]
struct Corpus {
    format: String,
    protocol_document_version: String,
    fixed_inputs: FixedInputs,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct FixedInputs {
    pair_id: String,
    session_id: String,
    local_start_ms: u64,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    message_type: String,
    body_hex: String,
    request_hash_hex: Option<String>,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("the checked-in operation corpus must be valid JSON")
}

fn message_type(name: &str) -> MessageType {
    match name {
        "OperationRequest" => MessageType::OperationRequest,
        "OperationResult" => MessageType::OperationResult,
        "OperationResultAck" => MessageType::OperationResultAck,
        "OperationStatusRequest" => MessageType::OperationStatusRequest,
        "OperationStatus" => MessageType::OperationStatus,
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
fn typed(vector: &Vector, inputs: &FixedInputs) -> TypedMessage {
    let session_id = SessionId::reconstruct(&hex::decode(&inputs.session_id).expect("valid hex"))
        .expect("session id length");
    let pair_id = PairId::reconstruct(&hex::decode(&inputs.pair_id).expect("valid hex"))
        .expect("pair id length");
    let envelope = Envelope::reconstruct(
        message_type(&vector.message_type),
        session_id,
        0,
        body(&vector.body_hex),
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap_or_else(|error| panic!("{} fails the envelope schema: {error:?}", vector.name));
    TypedMessage::from_envelope(envelope, pair_id, inputs.local_start_ms)
        .unwrap_or_else(|error| panic!("{} fails typed decoding: {error:?}", vector.name))
}

#[test]
fn corpus_names_this_protocol_version() {
    let corpus = corpus();
    assert_eq!(corpus.format, "fi.refineid.rapp.operation-vectors-v1");
    assert_eq!(corpus.protocol_document_version, "26.10.10");
    assert_eq!(corpus.vectors.len(), 34);
}

#[test]
fn every_body_decodes_and_re_encodes_byte_for_byte() {
    let corpus = corpus();
    for vector in &corpus.vectors {
        let message = typed(vector, &corpus.fixed_inputs);
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
fn request_commitments_match() {
    let corpus = corpus();
    for vector in &corpus.vectors {
        let Some(expected) = &vector.request_hash_hex else {
            continue;
        };
        let TypedMessage::OperationRequest(request) = typed(vector, &corpus.fixed_inputs) else {
            panic!("{} is not an admitted request", vector.name);
        };
        assert_eq!(
            &hex::encode(request.request_hash().expect("hash succeeds").as_bytes()),
            expected,
            "{}",
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
        let vector = corpus
            .vectors
            .iter()
            .find(|vector| vector.name == name)
            .unwrap_or_else(|| panic!("corpus lacks {name}"));
        let TypedMessage::OperationResult(result) = typed(vector, &corpus.fixed_inputs) else {
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
fn registry_values_decode_to_their_meaning() {
    let corpus = corpus();
    let find = |name: &str| {
        let vector = corpus
            .vectors
            .iter()
            .find(|vector| vector.name == name)
            .unwrap_or_else(|| panic!("corpus lacks {name}"));
        typed(vector, &corpus.fixed_inputs)
    };

    let TypedMessage::OperationStatus(in_flight) = find("status-in-flight") else {
        panic!("status-in-flight is a status");
    };
    assert_eq!(in_flight.state, Some(OperationState::Executing));
    assert!(!in_flight.retired);

    let TypedMessage::OperationStatus(retired) = find("status-completed-retired") else {
        panic!("status-completed-retired is a status");
    };
    assert_eq!(retired.state, Some(OperationState::Completed));
    assert!(retired.retired);

    let TypedMessage::OperationResult(tombstone) = find("result-retired-completed") else {
        panic!("result-retired-completed is a result");
    };
    assert!(tombstone.retired);
    assert_eq!(tombstone.status, ResultStatus::Completed);
    assert_eq!(tombstone.error, Some(ResultError::OperationAlreadyRetired));

    let TypedMessage::OperationResult(typo) = find("result-rejected-invalid-credential") else {
        panic!("result-rejected-invalid-credential is a result");
    };
    assert_eq!(typo.status, ResultStatus::Rejected);
    assert_eq!(typo.error, Some(ResultError::InvalidCredential));
    assert_eq!(typo.remaining_retries, Some(2));

    let TypedMessage::OperationResult(blocked) = find("result-credential-rejected-card-blocked")
    else {
        panic!("result-credential-rejected-card-blocked is a result");
    };
    assert_eq!(blocked.status, ResultStatus::CredentialRejected);
    assert_eq!(blocked.error, Some(ResultError::CardBlocked));

    let operation_id = OperationId::from_array([0x66; 16]);
    assert_eq!(
        find("error-duplicate-operation"),
        TypedMessage::Error(ProtocolErrorMessage::DuplicateOperation(operation_id))
    );
    assert_eq!(
        find("error-unknown-operation-bare"),
        TypedMessage::Error(ProtocolErrorMessage::UnknownOperation(None))
    );
}

/// The batch the corpus's batch vectors answer.
fn batch_operation(corpus: &Corpus) -> CardOperation {
    let TypedMessage::OperationRequest(request) = typed(
        corpus
            .vectors
            .iter()
            .find(|vector| vector.name == "request-batch-sign-documents")
            .expect("corpus has the batch request"),
        &corpus.fixed_inputs,
    ) else {
        panic!("the batch request is admitted");
    };
    request.operation
}

#[test]
fn batch_request_carries_its_documents_in_order() {
    let corpus = corpus();
    let CardOperation::BatchSignDocuments {
        document_names,
        key_profile,
        algorithm,
        digests,
    } = batch_operation(&corpus)
    else {
        panic!("the batch request names a batch");
    };
    assert_eq!(document_names, ["Contract.pdf", "Annex.pdf"]);
    assert_eq!(key_profile, CardKeyProfile::EcdsaP256);
    assert_eq!(algorithm, SignatureAlgorithm::EcdsaSha256);
    assert_eq!(digests.len(), 2);
}

#[test]
fn batch_results_read_as_signatures_and_partial_progress() {
    let corpus = corpus();
    let operation = batch_operation(&corpus);
    let find = |name: &str| {
        let vector = corpus
            .vectors
            .iter()
            .find(|vector| vector.name == name)
            .unwrap_or_else(|| panic!("corpus lacks {name}"));
        let TypedMessage::OperationResult(result) = typed(vector, &corpus.fixed_inputs) else {
            panic!("{name} is a result");
        };
        result
    };

    let completed = find("result-completed-batch-signatures");
    let reference = OperationReference {
        operation_id: completed.operation_id,
        request_hash: completed.request_hash,
    };
    completed
        .validate_for(reference, &operation)
        .expect("the completed batch answers the batch");
    let Ok(CardOperationResult::Signatures(signatures)) = completed
        .response
        .as_ref()
        .expect("a completed batch carries signatures")
        .typed_for(&operation)
    else {
        panic!("the completed batch reads as signatures");
    };
    assert_eq!(signatures.len(), 2);

    let partial = find("result-ambiguous-batch-partial");
    assert_eq!(partial.status, ResultStatus::Ambiguous);
    assert_eq!(partial.error, Some(ResultError::CardError));
    partial
        .validate_for(reference, &operation)
        .expect("the partial batch answers the batch");
    assert_eq!(
        partial
            .partial_batch_signatures(&operation)
            .expect("partial progress")
            .len(),
        1
    );
}
