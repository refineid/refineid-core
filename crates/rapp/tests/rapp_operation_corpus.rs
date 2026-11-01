// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Byte-exact replay of the RAPP v26.11.1 operation-message corpus.
//!
//! Every body decodes into its typed message and re-encodes to the identical
//! bytes, so an independently written peer and this crate put the same bytes
//! on the wire. Every rejected body is refused.

use std::collections::BTreeMap;

use refineid_rapp::{
    CardKeyProfile, CardOperation, CardOperationError, CardOperationResult, CardPresence,
    CardReader, CardStatusMessage, CertificateFingerprint, CertificateKind, ContainedFiles,
    Envelope, MessageType, OperationId, OperationRequest, OperationRequestRefusal, PairId,
    ProfileName, ProgressEvent, ProtocolErrorMessage, RequestError, ResultError, ResultStatus,
    SESSION_ID_SIZE, SessionId, SignatureAlgorithm, TypedMessage, WireError, WireValue,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const CORPUS: &str = include_str!("../../../doc/protocols/vectors/rapp-operation-v26.11.1.json");
const SESSION_ID: SessionId = SessionId::from_array([0xbb; 16]);

#[derive(Deserialize)]
struct Corpus {
    format: String,
    protocol_document_version: String,
    fixed_inputs: FixedInputs,
    vectors: Vec<Vector>,
    rejected: Vec<Vector>,
    refused: Vec<RefusedVector>,
    rejected_by_frame_bound: Vec<FrameBoundVector>,
}

/// A well-formed request the custodian answers with a rejected result.
#[derive(Deserialize)]
struct RefusedVector {
    name: String,
    message_type: String,
    body_hex: String,
    error: String,
}

#[derive(Deserialize)]
struct FixedInputs {
    operation_id_request: String,
    operation_id_result: String,
    operation_id_error: String,
    pair_id: String,
    certificate_der: String,
    digest_sha256: String,
    local_start_ms: u64,
    expires_after_ms: u64,
    package_name: String,
    package_files: Vec<String>,
}

/// A `sign_document` of a package too large to keep as bytes: the rule
/// that rebuilds it, and what the rebuilt request must measure.
#[derive(Deserialize)]
struct FrameBoundVector {
    name: String,
    message_type: String,
    document_name: String,
    entry_bytes: usize,
    entry_index_digits: usize,
    frame_plaintext_limit: usize,
    smallest_refused_count: usize,
    admitted_envelope_length: usize,
    refused_envelope_length: usize,
    refused_body_sha256_hex: String,
}

/// The letter that pads a frame-bound entry to its length.
const ENTRY_PADDING: char = 'x';

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
    assert_eq!(corpus.protocol_document_version, "26.11.1");
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
fn card_status_carries_the_certificate_fingerprint_and_the_reader() {
    let corpus = corpus();
    let certificate = hex::decode(&corpus.fixed_inputs.certificate_der).expect("valid hex");
    let present = CardPresence::Present(CertificateFingerprint::of_certificate(&certificate));
    for (name, card, reader) in [
        (
            "card-status-present-reader-attached",
            present,
            CardReader::Attached,
        ),
        ("card-status-present-no-reader", present, CardReader::Absent),
        (
            "card-status-absent-reader-attached",
            CardPresence::Absent,
            CardReader::Attached,
        ),
        (
            "card-status-absent-no-reader",
            CardPresence::Absent,
            CardReader::Absent,
        ),
    ] {
        assert_eq!(
            find(&corpus, name),
            TypedMessage::CardStatus(CardStatusMessage { card, reader }),
            "{name}"
        );
    }
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

#[test]
fn a_package_carries_its_name_and_every_file_in_order() {
    let corpus = corpus();
    let TypedMessage::OperationRequest(request) = find(&corpus, "request-sign-document-package")
    else {
        panic!("the package request is admitted");
    };
    let CardOperation::SignDocument {
        document_name,
        contained_files: Some(files),
        key_profile,
        algorithm,
        ..
    } = &request.operation
    else {
        panic!("the package request names a package");
    };
    assert_eq!(document_name, &corpus.fixed_inputs.package_name);
    assert_eq!(files.names(), corpus.fixed_inputs.package_files.as_slice());
    assert_eq!(*key_profile, CardKeyProfile::Rsa2048);
    assert_eq!(*algorithm, SignatureAlgorithm::RsaPkcs1Sha256);

    let TypedMessage::OperationRequest(single) = find(&corpus, "request-sign-document") else {
        panic!("the single request is admitted");
    };
    assert!(matches!(
        single.operation,
        CardOperation::SignDocument {
            contained_files: None,
            ..
        }
    ));
}

/// Entry `index` of a frame-bound vector, by its rule.
fn frame_bound_entry(vector: &FrameBoundVector, index: usize) -> String {
    let mut entry = format!("{index:0width$}", width = vector.entry_index_digits);
    while entry.len() < vector.entry_bytes {
        entry.push(ENTRY_PADDING);
    }
    entry
}

/// The package request of a frame-bound vector with `count` entries, built
/// without the admission check so that the refused one can be measured.
fn frame_bound_request(
    corpus: &Corpus,
    vector: &FrameBoundVector,
    count: usize,
) -> OperationRequest {
    let inputs = &corpus.fixed_inputs;
    OperationRequest {
        operation_id: identifier(&inputs.operation_id_request),
        profile: ProfileName::DocumentSigning,
        local_start_ms: inputs.local_start_ms,
        expires_after_ms: inputs.expires_after_ms,
        operation: CardOperation::SignDocument {
            document_name: vector.document_name.clone(),
            contained_files: Some(
                ContainedFiles::reconstruct(
                    (0..count)
                        .map(|index| frame_bound_entry(vector, index))
                        .collect(),
                )
                .expect("the entries are usable names"),
            ),
            key_profile: CardKeyProfile::Rsa2048,
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest: hex::decode(&inputs.digest_sha256).expect("valid hex"),
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

/// The envelope of `body` at the widest sequence with a zero session.
fn widest_envelope(body: BTreeMap<String, WireValue>) -> Result<Vec<u8>, WireError> {
    Envelope::reconstruct(
        MessageType::OperationRequest,
        SessionId::from_array([u8::MIN; SESSION_ID_SIZE]),
        u64::MAX,
        body,
    )?
    .encode()
}

#[test]
fn the_smallest_package_over_one_frame_is_refused_and_one_fewer_admitted() {
    let corpus = corpus();
    assert_eq!(corpus.rejected_by_frame_bound.len(), 1);
    for vector in &corpus.rejected_by_frame_bound {
        assert_eq!(vector.name, "request-sign-document-package-over-one-frame");
        assert_eq!(
            message_type(&vector.message_type),
            MessageType::OperationRequest
        );
        assert_eq!(
            vector.frame_plaintext_limit,
            refineid_rapp::MAX_FRAME_PLAINTEXT
        );

        let refused = frame_bound_request(&corpus, vector, vector.smallest_refused_count);
        let body = wire_body(&refused);
        let digest = Sha256::digest(
            encode_deterministic_cbor(&WireValue::Map(body.clone())).expect("the body encodes"),
        );
        assert_eq!(hex::encode(digest), vector.refused_body_sha256_hex);
        assert_eq!(
            widest_envelope(body.clone()),
            Err(WireError::OversizedPlaintext {
                got: vector.refused_envelope_length
            })
        );
        assert_eq!(
            refused.validate(),
            Err(CardOperationError::PackageTooLarge),
            "the requester refuses the package before sending"
        );
        assert_eq!(
            OperationRequest::from_wire_body(body, corpus.fixed_inputs.local_start_ms),
            Err(RequestError::Refused(OperationRequestRefusal {
                operation_id: refused.operation_id,
                error: ResultError::UnsupportedParameter,
            })),
            "the custodian refuses it at admission"
        );

        let admitted = frame_bound_request(&corpus, vector, vector.smallest_refused_count - 1);
        let body = wire_body(&admitted);
        assert_eq!(
            widest_envelope(body.clone()).map(|bytes| bytes.len()),
            Ok(vector.admitted_envelope_length)
        );
        assert_eq!(admitted.validate(), Ok(()));
        assert_eq!(
            OperationRequest::from_wire_body(body, corpus.fixed_inputs.local_start_ms)
                .map(|request| request.operation),
            Ok(admitted.operation)
        );
    }
}

#[test]
fn every_refused_request_is_answered_with_its_rejection() {
    let corpus = corpus();
    assert!(!corpus.refused.is_empty());
    let request_id = identifier(&corpus.fixed_inputs.operation_id_request);
    for refused in &corpus.refused {
        assert_eq!(refused.error, "unsupported_parameter", "{}", refused.name);
        let vector = Vector {
            name: refused.name.clone(),
            message_type: refused.message_type.clone(),
            body_hex: refused.body_hex.clone(),
        };
        assert_eq!(
            decode(&vector, &corpus.fixed_inputs),
            Ok(TypedMessage::OperationRequestRefused(
                OperationRequestRefusal {
                    operation_id: request_id,
                    error: ResultError::UnsupportedParameter,
                }
            )),
            "{}",
            refused.name
        );
    }
}
