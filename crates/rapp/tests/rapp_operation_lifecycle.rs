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

//! Executable evidence for the RAPP at-most-once and result-delivery boundary.

use refineid_rapp::{
    ApprovalOutcome, AuthorizationStage, AuthorizationTransaction, AuthorizedCardCommand,
    CardKeyProfile, CardOperation, CardOperationResult, JournalRecord, JournalStore, OperationId,
    OperationReference, OperationRequest, OperationResultMessage, OperationState, PairId,
    PendingCardCommand, ProfileName, ProtocolErrorMessage, ProxyDispatch, ProxyFailure,
    ProxyOperationEngine, RequestHash, ResultError, ResultJournalStore, ResultStatus, SessionId,
    SignatureAlgorithm, StatusReport, TypedMessage, UserApproval,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreEvent {
    Persist(OperationState, u8),
    PersistResult(OperationState, u8),
    RetainUncertain(OperationState, u8),
    Acknowledge(OperationState, u8),
}

#[derive(Default)]
struct MemoryResultStore {
    events: Vec<StoreEvent>,
    retained_result: Option<OperationResultMessage>,
    fail_next_write: bool,
}

impl MemoryResultStore {
    const fn maybe_fail(&mut self) -> Result<(), &'static str> {
        if self.fail_next_write {
            self.fail_next_write = false;
            Err("injected durable-store failure")
        } else {
            Ok(())
        }
    }
}

impl JournalStore for MemoryResultStore {
    type Error = &'static str;

    fn persist(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.maybe_fail()?;
        self.events
            .push(StoreEvent::Persist(record.state, record.transmission_count));
        Ok(())
    }
}

impl ResultJournalStore for MemoryResultStore {
    fn persist_result(
        &mut self,
        record: &JournalRecord,
        result: &OperationResultMessage,
    ) -> Result<(), Self::Error> {
        self.maybe_fail()?;
        self.retained_result = Some(result.clone());
        self.events.push(StoreEvent::PersistResult(
            record.state,
            record.transmission_count,
        ));
        Ok(())
    }

    fn retain_uncertain_result(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.maybe_fail()?;
        assert!(
            self.retained_result.is_some(),
            "delivery uncertainty must retain an already-durable result"
        );
        self.events.push(StoreEvent::RetainUncertain(
            record.state,
            record.transmission_count,
        ));
        Ok(())
    }

    fn acknowledge_result(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.maybe_fail()?;
        self.retained_result = None;
        self.events.push(StoreEvent::Acknowledge(
            record.state,
            record.transmission_count,
        ));
        Ok(())
    }
}

fn consequential_request() -> OperationRequest {
    OperationRequest::reconstruct(
        OperationId::from_array([0x11; 16]),
        PairId::from_array([0x22; 16]),
        SessionId::from_array([0x33; 16]),
        ProfileName::Authentication,
        1_000,
        5_000,
        CardOperation::BrowserAuthenticate {
            origin: "https://example.invalid".into(),
            key_profile: CardKeyProfile::EcdsaP256,
            algorithm: SignatureAlgorithm::EcdsaSha256,
            digest: vec![0x44; 32],
        },
    )
    .expect("the fixed request vector is valid")
}

fn consented_transaction() -> AuthorizationTransaction {
    let mut transaction = AuthorizationTransaction::prepare(consequential_request())
        .expect("the fixed request vector is valid");
    transaction
        .prerequisites_complete()
        .expect("prerequisites complete once");
    transaction
}

fn approval() -> UserApproval {
    UserApproval::for_request(&consequential_request(), 1_100)
        .expect("the fixed request vector has a deterministic hash")
}

fn executing_transaction(
    store: &mut MemoryResultStore,
) -> (
    AuthorizationTransaction,
    PendingCardCommand<AuthorizedCardCommand>,
) {
    let mut transaction = consented_transaction();
    let ApprovalOutcome::ExecuteCardCommand(command) = transaction
        .approve(store, approval(), 1_100, 10_000)
        .expect("fresh exact approval is accepted")
    else {
        panic!("a consequential approval yields the card command");
    };
    (transaction, command)
}

fn completed_result(transaction: &AuthorizationTransaction) -> OperationResultMessage {
    OperationResultMessage::completed(
        transaction.reference(),
        &CardOperationResult::Signature(vec![0x55; 64]),
    )
}

#[test]
fn durable_in_flight_entry_precedes_the_only_physical_command() {
    let mut store = MemoryResultStore::default();
    let (transaction, command) = executing_transaction(&mut store);
    let mut physical_transmissions = 0_u8;

    assert_eq!(
        store.events,
        [StoreEvent::Persist(OperationState::Executing, 1)]
    );
    command.execute(|command| {
        physical_transmissions += 1;
        assert_eq!(command.operation, consequential_request().operation);
    });

    assert_eq!(physical_transmissions, 1);
    assert_eq!(transaction.stage(), AuthorizationStage::Executing);
    assert_eq!(transaction.journal().record().transmission_count, 1);
    assert!(!transaction.journal().record().automatic_retry_permitted);
}

#[test]
fn a_second_approval_cannot_create_another_card_command() {
    let mut store = MemoryResultStore::default();
    let (mut transaction, _command) = executing_transaction(&mut store);
    let writes = store.events.len();

    assert!(
        transaction
            .approve(&mut store, approval(), 1_101, 10_000)
            .is_err()
    );
    assert_eq!(store.events.len(), writes);
}

#[test]
fn persistence_failure_prevents_command_exposure() {
    let mut store = MemoryResultStore {
        fail_next_write: true,
        ..MemoryResultStore::default()
    };
    let mut transaction = consented_transaction();

    assert!(
        transaction
            .approve(&mut store, approval(), 1_100, 10_000)
            .is_err()
    );
    assert_eq!(transaction.stage(), AuthorizationStage::AwaitingConsent);
    assert_eq!(transaction.journal().record().transmission_count, 0);
    assert!(store.events.is_empty());
}

#[test]
fn expired_approval_writes_nothing() {
    let mut store = MemoryResultStore::default();
    let mut transaction = consented_transaction();
    let late = UserApproval::for_request(&consequential_request(), 6_001)
        .expect("the fixed request vector has a deterministic hash");

    assert!(
        transaction
            .approve(&mut store, late, 6_001, 10_000)
            .is_err()
    );
    assert!(store.events.is_empty());
}

#[test]
fn result_is_durable_before_release_and_acknowledgment_erases_it() {
    let mut store = MemoryResultStore::default();
    let (mut transaction, command) = executing_transaction(&mut store);
    command.execute(|_| ());
    let result = completed_result(&transaction);

    transaction
        .finish_completed(&mut store, result.clone())
        .expect("a valid completed result is persisted");
    assert_eq!(transaction.stage(), AuthorizationStage::ResultPending);
    assert_eq!(transaction.retained_result(), Some(&result));
    assert_eq!(store.retained_result.as_ref(), Some(&result));
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::PersistResult(OperationState::ResultPending, 1))
    );

    transaction
        .acknowledge_result(&mut store, transaction.reference())
        .expect("the exact acknowledgment completes delivery");
    assert_eq!(transaction.stage(), AuthorizationStage::Terminal);
    assert_eq!(transaction.operation_state(), OperationState::Completed);
    assert_eq!(transaction.retained_result(), None);
    assert_eq!(store.retained_result, None);
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::Acknowledge(OperationState::Completed, 1))
    );
}

#[test]
fn lost_ack_retains_result_and_forbids_automatic_replay() {
    let mut store = MemoryResultStore::default();
    let (mut transaction, command) = executing_transaction(&mut store);
    command.execute(|_| ());
    let result = completed_result(&transaction);
    transaction
        .finish_completed(&mut store, result.clone())
        .expect("result is durable before transport release");

    transaction
        .delivery_became_uncertain(&mut store)
        .expect("session loss marks delivery uncertain");
    assert_eq!(
        transaction.operation_state(),
        OperationState::DeliveryUncertain
    );
    assert_eq!(transaction.retained_result(), Some(&result));
    assert_eq!(store.retained_result.as_ref(), Some(&result));
    assert!(!transaction.journal().record().automatic_retry_permitted);
    assert_eq!(
        store.events.last(),
        Some(&StoreEvent::RetainUncertain(
            OperationState::DeliveryUncertain,
            1,
        ))
    );
    assert!(
        transaction
            .approve(&mut store, approval(), 1_200, 10_000)
            .is_err()
    );
}

#[test]
fn crash_after_transmission_is_ambiguous_and_never_retried() {
    let mut store = MemoryResultStore::default();
    let (mut transaction, command) = executing_transaction(&mut store);
    command.execute(|_| ());

    transaction
        .recover_after_crash(&mut store)
        .expect("executing work recovers as ambiguous");
    assert_eq!(transaction.operation_state(), OperationState::Ambiguous);
    assert_eq!(transaction.journal().record().transmission_count, 1);
    assert!(!transaction.journal().record().automatic_retry_permitted);
}

#[test]
fn a_failure_result_is_retained_for_identical_retransmissions() {
    let mut store = MemoryResultStore::default();
    let mut transaction = consented_transaction();
    let result = OperationResultMessage::failure(transaction.reference(), ProxyFailure::UserDenied);

    transaction
        .finish_failure_result(&mut store, &result)
        .expect("a denial is journaled");
    assert_eq!(transaction.operation_state(), OperationState::Rejected);
    assert_eq!(transaction.retained_result(), Some(&result));
    assert_eq!(result.status, ResultStatus::Rejected);
    assert_eq!(result.error, Some(ResultError::UserCancelled));
    assert_eq!(
        store.events,
        [StoreEvent::PersistResult(OperationState::Rejected, 0)]
    );
}

#[test]
fn request_hash_is_bound_to_the_pairing_not_the_session_local_time_or_expiry() {
    let original = consequential_request();
    let mut local_only_change = original.clone();
    local_only_change.local_start_ms += 99_000;
    local_only_change.expires_after_ms += 99_000;
    assert_eq!(
        original.request_hash().expect("hash succeeds"),
        local_only_change.request_hash().expect("hash succeeds")
    );

    let mut session_change = original.clone();
    session_change.session_id = SessionId::from_array([0x99; 16]);
    assert_eq!(
        original.request_hash().expect("hash succeeds"),
        session_change.request_hash().expect("hash succeeds"),
        "a retransmission on a later session hashes the same"
    );

    let mut pair_change = original.clone();
    pair_change.pair_id = PairId::from_array([0x98; 16]);
    assert_ne!(
        original.request_hash().expect("hash succeeds"),
        pair_change.request_hash().expect("hash succeeds")
    );

    let mut semantic_change = original.clone();
    semantic_change.operation = CardOperation::BrowserAuthenticate {
        origin: "https://different.example.invalid".into(),
        key_profile: CardKeyProfile::EcdsaP256,
        algorithm: SignatureAlgorithm::EcdsaSha256,
        digest: vec![0x44; 32],
    };
    assert_ne!(
        original.request_hash().expect("hash succeeds"),
        semantic_change.request_hash().expect("hash succeeds")
    );

    let mut operation_id_change = original.clone();
    operation_id_change.operation_id = OperationId::from_array([0xaa; 16]);
    assert_ne!(
        original.request_hash().expect("hash succeeds"),
        operation_id_change.request_hash().expect("hash succeeds")
    );

    assert_ne!(
        original.request_hash().expect("hash succeeds"),
        RequestHash::from_array([0; 32]),
        "the fixed vector must not collapse to the all-zero sentinel"
    );
}

fn engine_with_request(store: &mut MemoryResultStore) -> ProxyOperationEngine {
    let mut engine = ProxyOperationEngine::new(vec![ProfileName::Authentication]);
    assert!(matches!(
        engine.receive(
            store,
            TypedMessage::OperationRequest(consequential_request()),
            1_000
        ),
        Ok(ProxyDispatch::InspectPrerequisites(_))
    ));
    engine
}

fn reference() -> OperationReference {
    let request = consequential_request();
    OperationReference {
        operation_id: request.operation_id,
        request_hash: request.request_hash().expect("hash succeeds"),
    }
}

#[test]
fn identical_retransmission_joins_the_live_operation() {
    let mut store = MemoryResultStore::default();
    let mut engine = engine_with_request(&mut store);

    assert!(matches!(
        engine.receive(
            &mut store,
            TypedMessage::OperationRequest(consequential_request()),
            1_010
        ),
        Ok(ProxyDispatch::IgnoredDuplicate(_))
    ));
    assert!(store.events.is_empty());
}

#[test]
fn changed_content_under_a_live_identifier_is_a_duplicate_operation() {
    let mut store = MemoryResultStore::default();
    let mut engine = engine_with_request(&mut store);
    let mut changed = consequential_request();
    changed.operation = CardOperation::BrowserAuthenticate {
        origin: "https://other.example.invalid".into(),
        key_profile: CardKeyProfile::EcdsaP256,
        algorithm: SignatureAlgorithm::EcdsaSha256,
        digest: vec![0x44; 32],
    };

    let Ok(ProxyDispatch::Send(TypedMessage::Error(error))) =
        engine.receive(&mut store, TypedMessage::OperationRequest(changed), 1_010)
    else {
        panic!("changed content is refused with an error");
    };
    assert_eq!(
        error,
        ProtocolErrorMessage::DuplicateOperation(reference().operation_id)
    );
}

#[test]
fn a_retained_failure_answers_a_retransmission_without_the_card() {
    let mut store = MemoryResultStore::default();
    let mut engine = engine_with_request(&mut store);
    engine
        .prerequisites_complete(reference().operation_id)
        .expect("prerequisites complete");
    engine
        .finish_failure(
            &mut store,
            reference().operation_id,
            ProxyFailure::UserDenied,
        )
        .expect("the denial is journaled");

    let Ok(ProxyDispatch::Send(TypedMessage::OperationResult(result))) = engine.receive(
        &mut store,
        TypedMessage::OperationRequest(consequential_request()),
        1_020,
    ) else {
        panic!("the retained failure is re-delivered");
    };
    assert_eq!(result.status, ResultStatus::Rejected);
    assert_eq!(result.error, Some(ResultError::UserCancelled));
}

#[test]
fn an_acknowledged_result_answers_as_retired_and_the_status_says_so() {
    let mut store = MemoryResultStore::default();
    let mut engine = engine_with_request(&mut store);
    let operation_id = reference().operation_id;
    engine
        .prerequisites_complete(operation_id)
        .expect("prerequisites complete");
    let Ok(ProxyDispatch::ExecuteCardCommand { command, .. }) =
        engine.approve(&mut store, operation_id, approval(), 1_100, 10_000)
    else {
        panic!("approval yields the card command");
    };
    command.execute(|_| ());
    let completed = OperationResultMessage::completed(
        reference(),
        &CardOperationResult::Signature(vec![0x55; 64]),
    );
    engine
        .finish_completed(&mut store, operation_id, completed)
        .expect("the result is retained");
    assert!(matches!(
        engine.receive(
            &mut store,
            TypedMessage::OperationResultAck(reference()),
            1_200
        ),
        Ok(ProxyDispatch::ResultAcknowledged(_))
    ));

    let Ok(ProxyDispatch::Send(TypedMessage::OperationResult(retired))) = engine.receive(
        &mut store,
        TypedMessage::OperationRequest(consequential_request()),
        1_300,
    ) else {
        panic!("a retired operation answers with its tombstone");
    };
    assert!(retired.retired);
    assert_eq!(retired.status, ResultStatus::Completed);
    assert_eq!(retired.error, Some(ResultError::OperationAlreadyRetired));
    assert_eq!(retired.response, None);

    let Ok(ProxyDispatch::Send(TypedMessage::OperationStatus(report))) = engine.receive(
        &mut store,
        TypedMessage::OperationStatusRequest(operation_id),
        1_400,
    ) else {
        panic!("a retired operation reports its status alone");
    };
    assert_eq!(
        report,
        StatusReport {
            operation_id,
            known: true,
            state: Some(OperationState::Completed),
            request_hash: Some(reference().request_hash),
            retired: true,
        }
    );
}

#[test]
fn status_of_a_pending_result_re_delivers_it() {
    let mut store = MemoryResultStore::default();
    let mut engine = ProxyOperationEngine::new(vec![ProfileName::Authentication]);
    let mut request = consequential_request();
    request.profile = ProfileName::CardStatus;
    request.operation = CardOperation::InspectCard;
    let operation_id = request.operation_id;
    engine
        .receive(&mut store, TypedMessage::OperationRequest(request), 1_000)
        .expect("an ungranted profile is answered, not punished");

    let Ok(ProxyDispatch::SendAll(messages)) = engine.receive(
        &mut store,
        TypedMessage::OperationStatusRequest(operation_id),
        1_100,
    ) else {
        panic!("the status re-delivers the retained result");
    };
    assert!(matches!(messages.as_slice(), [
        TypedMessage::OperationStatus(StatusReport { known: true, retired: false, .. }),
        TypedMessage::OperationResult(result),
    ] if result.error == Some(ResultError::Unauthorized)));
}

#[test]
fn a_second_request_while_one_is_live_is_refused_with_operation_failed() {
    let mut store = MemoryResultStore::default();
    let mut engine = engine_with_request(&mut store);
    let mut second = consequential_request();
    second.operation_id = OperationId::from_array([0x77; 16]);

    assert!(matches!(
        engine.receive(&mut store, TypedMessage::OperationRequest(second), 1_010),
        Ok(ProxyDispatch::Send(TypedMessage::Error(
            ProtocolErrorMessage::OperationFailed(_)
        )))
    ));
}
