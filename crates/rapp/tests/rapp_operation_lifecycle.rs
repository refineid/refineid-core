// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Operation lifecycles of RAPP v26.11.1 section 8, with the requester and
//! custodian engines exchanging messages through their wire encoding.

use refineid_rapp::{
    CardInspection, CardKeyProfile, CardOperation, CardOperationResult, Envelope, OperationId,
    OperationRequest, OperationResultMessage, ProfileName, ProxyDispatch, ProxyFailure,
    ProxyOperationEngine, ProxySessionCloseAction, RequesterDispatch, RequesterOperationEngine,
    ResultError, ResultStatus, SessionId, SignatureAlgorithm, TypedMessage, UserApproval,
};

const SESSION_ID: SessionId = SessionId::from_array([0x5e; 16]);
const START_MS: u64 = 1_000;
const LIFETIME_MS: u64 = 60_000;
const MAXIMUM_LIFETIME_MS: u64 = 300_000;
const SHA256_DIGEST_SIZE: usize = 32;
/// The initial byte of a direct-convention answer to reset (ISO/IEC 7816-3).
const ANSWER_TO_RESET_BYTE: u8 = 0x3b;
const ANSWER_TO_RESET_SIZE: usize = 20;

/// Carries a message across the wire: encode its body, decode it again.
fn across(message: &TypedMessage) -> TypedMessage {
    let envelope = Envelope::reconstruct(
        message.message_type(),
        SESSION_ID,
        0,
        message.to_wire_body().expect("the message encodes"),
    )
    .expect("the body fits its schema");
    TypedMessage::from_envelope(envelope, START_MS).expect("the message decodes")
}

fn request(byte: u8, operation: CardOperation) -> OperationRequest {
    OperationRequest::reconstruct(
        OperationId::from_array([byte; 16]),
        operation.required_profile(),
        START_MS,
        LIFETIME_MS,
        operation,
    )
    .expect("a registered request")
}

fn signing(byte: u8) -> OperationRequest {
    request(
        byte,
        CardOperation::SignDocument {
            document_name: "Contract.pdf".to_owned(),
            contained_files: None,
            key_profile: CardKeyProfile::EcdsaP256,
            algorithm: SignatureAlgorithm::EcdsaSha256,
            digest: vec![0xcc; SHA256_DIGEST_SIZE],
        },
    )
}

fn batch(byte: u8, documents: usize) -> OperationRequest {
    request(
        byte,
        CardOperation::BatchSignDocuments {
            document_names: (0..documents)
                .map(|index| format!("Document {index}.pdf"))
                .collect(),
            key_profile: CardKeyProfile::EcdsaP256,
            algorithm: SignatureAlgorithm::EcdsaSha256,
            digests: vec![vec![0xcc; SHA256_DIGEST_SIZE]; documents],
        },
    )
}

fn custodian() -> ProxyOperationEngine {
    ProxyOperationEngine::new(vec![
        ProfileName::CardStatus,
        ProfileName::Authentication,
        ProfileName::DocumentSigning,
    ])
}

fn sent(dispatch: ProxyDispatch) -> TypedMessage {
    match dispatch {
        ProxyDispatch::Send(message) => message,
        other => panic!("expected a message to send, got {other:?}"),
    }
}

/// Admits `request` on the custodian and gives it the card: the next step
/// the custodian takes.
fn admit(
    engine: &mut ProxyOperationEngine,
    requester: &mut RequesterOperationEngine,
    request: &OperationRequest,
) -> ProxyDispatch {
    let wire = requester
        .begin(request.clone())
        .expect("the requester starts");
    assert!(matches!(
        engine.receive(across(&wire)),
        Ok(ProxyDispatch::InspectPrerequisites(_))
    ));
    engine
        .prerequisites_complete(request.operation_id, START_MS, MAXIMUM_LIFETIME_MS)
        .expect("the reads complete")
}

#[test]
fn a_signature_waits_for_consent() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    let request = signing(1);
    assert!(matches!(
        admit(&mut engine, &mut requester, &request),
        ProxyDispatch::AwaitConsent(operation_id) if operation_id == request.operation_id
    ));
}

#[test]
fn a_read_answers_without_consent() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    let request = request(1, CardOperation::InspectCard);
    let ProxyDispatch::ExecuteSafeRead { read, .. } = admit(&mut engine, &mut requester, &request)
    else {
        panic!("a read runs once it has the card");
    };
    assert_eq!(read.operation, request.operation);
    let answer = CardOperationResult::Inspection(CardInspection {
        answer_to_reset: vec![ANSWER_TO_RESET_BYTE; ANSWER_TO_RESET_SIZE],
    });
    let result = sent(
        engine
            .finish_completed(
                request.operation_id,
                OperationResultMessage::completed(request.operation_id, &answer),
            )
            .expect("completion"),
    );
    assert_eq!(
        requester.receive(across(&result)).expect("result"),
        RequesterDispatch::Completed {
            operation_id: request.operation_id,
            result: answer,
        }
    );
}

#[test]
fn an_approved_signature_reaches_the_requester() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    let request = signing(1);
    admit(&mut engine, &mut requester, &request);
    let ProxyDispatch::ExecuteCardCommand { command, .. } = engine
        .approve(
            request.operation_id,
            UserApproval::for_request(&request, START_MS),
            START_MS,
            MAXIMUM_LIFETIME_MS,
        )
        .expect("approval")
    else {
        panic!("approval of a signature gives the card command");
    };
    let operation = command.execute(|command| command.operation);
    assert_eq!(operation, request.operation);
    let answer = CardOperationResult::Signature(vec![0xee; SHA256_DIGEST_SIZE]);
    let result = sent(
        engine
            .finish_completed(
                request.operation_id,
                OperationResultMessage::completed(request.operation_id, &answer),
            )
            .expect("completion"),
    );
    assert_eq!(
        requester.receive(across(&result)).expect("result"),
        RequesterDispatch::Completed {
            operation_id: request.operation_id,
            result: answer,
        }
    );
}

#[test]
fn an_approval_gives_one_card_command() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    let request = signing(1);
    admit(&mut engine, &mut requester, &request);
    let approval = UserApproval::for_request(&request, START_MS);
    engine
        .approve(
            request.operation_id,
            approval,
            START_MS,
            MAXIMUM_LIFETIME_MS,
        )
        .expect("first approval");
    assert!(
        engine
            .approve(
                request.operation_id,
                approval,
                START_MS,
                MAXIMUM_LIFETIME_MS
            )
            .is_err()
    );
}

#[test]
fn a_late_approval_cancels_without_a_card_command() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    let request = signing(1);
    admit(&mut engine, &mut requester, &request);
    let late = START_MS + LIFETIME_MS + 1;
    let result = sent(
        engine
            .approve(
                request.operation_id,
                UserApproval::for_request(&request, late),
                late,
                MAXIMUM_LIFETIME_MS,
            )
            .expect("dispatch"),
    );
    assert_eq!(
        requester.receive(across(&result)).expect("result"),
        RequesterDispatch::Ended {
            operation_id: request.operation_id,
            status: ResultStatus::Cancelled,
            error: ResultError::OperationExpired,
        }
    );
}

#[test]
fn the_retry_floor_reaches_the_requester_as_a_rejection() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    let request = signing(1);
    admit(&mut engine, &mut requester, &request);
    engine
        .approve(
            request.operation_id,
            UserApproval::for_request(&request, START_MS),
            START_MS,
            MAXIMUM_LIFETIME_MS,
        )
        .expect("approval");
    let result = sent(
        engine
            .finish_failure(request.operation_id, ProxyFailure::RetryFloor)
            .expect("refusal"),
    );
    assert_eq!(
        requester.receive(across(&result)).expect("result"),
        RequesterDispatch::Ended {
            operation_id: request.operation_id,
            status: ResultStatus::Rejected,
            error: ResultError::RetryFloor,
        }
    );
}

#[test]
fn a_second_request_while_one_is_live_is_busy() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    admit(&mut engine, &mut requester, &signing(1));
    let mut other_requester = RequesterOperationEngine::new();
    let second = signing(2);
    let wire = other_requester.begin(second.clone()).expect("begin");
    let refusal = sent(engine.receive(across(&wire)).expect("dispatch"));
    assert_eq!(
        other_requester.receive(across(&refusal)).expect("refusal"),
        RequesterDispatch::Refused {
            operation_id: second.operation_id,
            error: ResultError::Busy,
        }
    );
}

#[test]
fn a_batch_completes_only_with_every_signature_in_order() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    let request = batch(1, 2);
    admit(&mut engine, &mut requester, &request);
    engine
        .approve(
            request.operation_id,
            UserApproval::for_request(&request, START_MS),
            START_MS,
            MAXIMUM_LIFETIME_MS,
        )
        .expect("approval");
    let signatures = vec![
        vec![0xe1; SHA256_DIGEST_SIZE],
        vec![0xe2; SHA256_DIGEST_SIZE],
    ];
    engine
        .record_batch_signature(request.operation_id, signatures[0].clone())
        .expect("first document");
    assert!(engine.complete_batch(request.operation_id).is_err());
    engine
        .record_batch_signature(request.operation_id, signatures[1].clone())
        .expect("second document");
    assert!(
        engine
            .record_batch_signature(request.operation_id, signatures[1].clone())
            .is_err()
    );
    let result = sent(
        engine
            .complete_batch(request.operation_id)
            .expect("complete"),
    );
    assert_eq!(
        requester.receive(across(&result)).expect("result"),
        RequesterDispatch::Completed {
            operation_id: request.operation_id,
            result: CardOperationResult::Signatures(signatures),
        }
    );
}

#[test]
fn a_batch_names_at_least_one_document() {
    assert!(
        OperationRequest::reconstruct(
            OperationId::from_array([1; 16]),
            ProfileName::DocumentSigning,
            START_MS,
            LIFETIME_MS,
            CardOperation::BatchSignDocuments {
                document_names: Vec::new(),
                key_profile: CardKeyProfile::EcdsaP256,
                algorithm: SignatureAlgorithm::EcdsaSha256,
                digests: Vec::new(),
            },
        )
        .is_err()
    );
    let many = 100;
    let request = batch(1, many);
    let CardOperation::BatchSignDocuments { digests, .. } = &request.operation else {
        panic!("a batch");
    };
    assert_eq!(digests.len(), many);
}

#[test]
fn closing_the_session_ends_both_sides_of_the_operation() {
    let mut engine = custodian();
    let mut requester = RequesterOperationEngine::new();
    let request = signing(1);
    admit(&mut engine, &mut requester, &request);
    engine
        .approve(
            request.operation_id,
            UserApproval::for_request(&request, START_MS),
            START_MS,
            MAXIMUM_LIFETIME_MS,
        )
        .expect("approval");
    assert_eq!(
        engine.session_closed(),
        Some(ProxySessionCloseAction::ContinueCardExchange(
            request.operation_id
        ))
    );
    assert_eq!(requester.session_closed(), Some(request.operation_id));
}
