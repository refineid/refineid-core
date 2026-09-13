//! Total proxy-side operation dispatcher and card-command boundary.

use core::fmt;

use super::{
    ApprovalOutcome, AuthorizationError, AuthorizationStage, AuthorizationTransaction,
    AuthorizedCardCommand, AuthorizedSafeRead, CardOperationError, JournalError,
    JournalRecoveryStore, JournalStore, OperationId, OperationProgressMessage, OperationReference,
    OperationRequest, OperationResultMessage, OperationState, PendingCardCommand, ProfileName,
    ProgressEvent, ProtocolErrorMessage, ProxyCancelOutcome, RecoveredProxyRecord, ResultError,
    ResultJournalStore, ResultStatus, StatusReport, TypedMessage, UserApproval,
};

/// Operations for one authenticated proxy session. Exactly one may be active.
#[derive(Debug)]
pub struct ProxyOperationEngine {
    granted_profiles: Vec<ProfileName>,
    operations: Vec<AuthorizationTransaction>,
    recovered: Vec<RecoveredProxyRecord>,
}

impl ProxyOperationEngine {
    /// Create a dispatcher bound to the exact profiles authenticated by the
    /// pairing transcript. An empty grant set deliberately permits no
    /// operation.
    #[must_use]
    pub const fn new(granted_profiles: Vec<ProfileName>) -> Self {
        Self {
            granted_profiles,
            operations: Vec::new(),
            recovered: Vec::new(),
        }
    }

    /// Load durable records and classify every interrupted operation without
    /// offering command or result replay.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on a persistence failure or a record that
    /// contradicts a machine invariant.
    pub fn recover<S: JournalRecoveryStore>(
        store: &mut S,
        granted_profiles: Vec<ProfileName>,
    ) -> Result<Self, ProxyEngineError<S::Error>> {
        let mut records = store.load_all().map_err(ProxyEngineError::Persistence)?;
        for index in 0..records.len() {
            let operation_id = records[index].record.operation_id;
            if records[..index]
                .iter()
                .any(|entry| entry.record.operation_id == operation_id)
            {
                return Err(ProxyEngineError::LocalInvariantFailure);
            }
            validate_recovered(&records[index])?;
            match records[index].record.state {
                OperationState::Requested
                | OperationState::AwaitingConsent
                | OperationState::Prepared => {
                    records[index].record.state = OperationState::Cancelled;
                    store
                        .persist(&records[index].record)
                        .map_err(ProxyEngineError::Persistence)?;
                }
                OperationState::Committed | OperationState::Executing => {
                    records[index].record.state = OperationState::Ambiguous;
                    records[index].record.automatic_retry_permitted = false;
                    store
                        .persist(&records[index].record)
                        .map_err(ProxyEngineError::Persistence)?;
                }
                OperationState::ResultPending => {
                    records[index].record.state = OperationState::DeliveryUncertain;
                    records[index].record.automatic_retry_permitted = false;
                    store
                        .retain_uncertain_result(&records[index].record)
                        .map_err(ProxyEngineError::Persistence)?;
                }
                state if state.is_terminal() => {}
                OperationState::None => {
                    return Err(ProxyEngineError::LocalInvariantFailure);
                }
                _ => return Err(ProxyEngineError::LocalInvariantFailure),
            }
        }
        Ok(Self {
            granted_profiles,
            operations: Vec::new(),
            recovered: records,
        })
    }

    /// Dispatch a typed authenticated peer message.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an authenticated protocol violation, an
    /// expired request, or a persistence failure.
    pub fn receive<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        message: TypedMessage,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        match message {
            TypedMessage::OperationRequest(request) => self.receive_request(request),
            TypedMessage::OperationCommit(reference) => {
                self.receive_commit(store, reference, now_ms, maximum_lifetime_ms)
            }
            TypedMessage::OperationCancel(cancellation) => {
                let operation_id = cancellation.reference.operation_id;
                let Some(index) = self.index(operation_id) else {
                    return Ok(stale(operation_id));
                };
                if self.operations[index].operation_state().is_terminal() {
                    return Ok(stale(operation_id));
                }
                let outcome = self.operations[index]
                    .receive_cancel(store, &cancellation, true)
                    .map_err(map_peer_authorization_error)?;
                Ok(match outcome {
                    ProxyCancelOutcome::Cancelled => ProxyDispatch::Cancelled(operation_id),
                    ProxyCancelOutcome::Advisory => {
                        ProxyDispatch::AdvisoryCancellation(operation_id)
                    }
                })
            }
            TypedMessage::OperationResultAck(reference) => {
                let operation_id = reference.operation_id;
                let Some(index) = self.index(operation_id) else {
                    return Ok(stale(operation_id));
                };
                if self.operations[index].operation_state().is_terminal() {
                    return Ok(stale(operation_id));
                }
                self.operations[index]
                    .acknowledge_result(store, reference)
                    .map_err(map_peer_authorization_error)?;
                Ok(ProxyDispatch::ResultAcknowledged(operation_id))
            }
            TypedMessage::OperationStatusRequest(operation_id) => {
                let message = self.operation(operation_id).map_or_else(
                    || {
                        self.recovered(operation_id).map_or_else(
                            || status_message(None, operation_id),
                            recovered_status_message,
                        )
                    },
                    |operation| status_message(Some(operation), operation_id),
                );
                Ok(ProxyDispatch::Send(message))
            }
            other => {
                let Some(operation_id) = referenced_operation_id(&other) else {
                    return Ok(ProxyDispatch::NotOperation(other));
                };
                let Some(index) = self.index(operation_id) else {
                    return Ok(stale(operation_id));
                };
                if self.operations[index].operation_state().is_terminal() {
                    return Ok(stale(operation_id));
                }
                Err(ProxyEngineError::AuthenticatedProtocolViolation(
                    ProxyViolation::IllegalMessageForActiveOperation,
                ))
            }
        }
    }

    /// Mark bounded prerequisite reads complete before presenting consent.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or an illegal local
    /// transition.
    pub fn prerequisites_complete(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), ProxyEngineError<()>> {
        self.operation_mut(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?
            .prerequisites_complete()
            .map_err(map_local_authorization_error)
    }

    /// Apply exact local user approval.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or an illegal local
    /// transition.
    pub fn approve(
        &mut self,
        operation_id: OperationId,
        approval: UserApproval,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<ProxyDispatch, ProxyEngineError<()>> {
        let outcome = self
            .operation_mut(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?
            .approve(approval, now_ms, maximum_lifetime_ms)
            .map_err(map_local_authorization_error)?;
        Ok(match outcome {
            ApprovalOutcome::Prepared(reference) => {
                ProxyDispatch::Send(TypedMessage::OperationPrepared(reference))
            }
            ApprovalOutcome::ExecuteSafeRead(read) => {
                ProxyDispatch::ExecuteSafeRead { operation_id, read }
            }
        })
    }

    /// Persist transmission number one and expose the only executable command.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation, an illegal local
    /// transition, or a persistence failure.
    pub fn begin_card_command<S: JournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
    ) -> Result<PendingCardCommand<AuthorizedCardCommand>, ProxyEngineError<S::Error>> {
        self.operation_mut(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?
            .begin_card_command(store)
            .map_err(map_local_authorization_error)
    }

    /// Persist a completed result before releasing it to the requester.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation, an illegal local
    /// transition, or a persistence failure.
    pub fn finish_completed<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
        result: OperationResultMessage,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        self.operation_mut(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?
            .finish_completed(store, result.clone())
            .map_err(map_local_authorization_error)?;
        Ok(ProxyDispatch::Send(TypedMessage::OperationResult(result)))
    }

    /// Construct, validate, persist, and release a stable non-success result.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation, an invalid status and
    /// error pairing, an illegal local transition, or a persistence failure.
    pub fn finish_failure<S: JournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
        status: ResultStatus,
        error: ResultError,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        let operation = self
            .operation_mut(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?;
        let result = OperationResultMessage::failure(operation.reference(), status, error)
            .map_err(ProxyEngineError::InvalidLocalResult)?;
        operation
            .finish_failure_result(store, &result)
            .map_err(map_local_authorization_error)?;
        Ok(ProxyDispatch::SendFailure {
            close_session: matches!(
                error,
                ResultError::RetryPolicyRefused
                    | ResultError::CredentialRejected
                    | ResultError::CardCompletionAmbiguous
            ),
            message: TypedMessage::OperationResult(result),
        })
    }

    /// Create an authenticated advisory progress message for an active operation.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation.
    pub fn report_progress(
        &self,
        operation_id: OperationId,
        event: ProgressEvent,
    ) -> Result<TypedMessage, ProxyEngineError<()>> {
        let op = self
            .operation(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?;
        Ok(TypedMessage::OperationProgress(OperationProgressMessage {
            reference: op.reference(),
            event,
        }))
    }

    /// Apply authenticated-session closure under every operation boundary.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an illegal local transition or a persistence
    /// failure.
    pub fn session_closed<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<Vec<ProxySessionCloseAction>, ProxyEngineError<S::Error>> {
        let mut actions = Vec::new();
        for operation in &mut self.operations {
            let operation_id = operation.reference().operation_id;
            match operation.stage() {
                AuthorizationStage::Requested
                | AuthorizationStage::AwaitingConsent
                | AuthorizationStage::Prepared
                | AuthorizationStage::ExecutingSafeRead
                | AuthorizationStage::Committed => {
                    let cancellation = super::CancelMessage {
                        reference: operation.reference(),
                        reason: None,
                    };
                    operation
                        .receive_cancel(store, &cancellation, true)
                        .map_err(map_local_authorization_error)?;
                    actions.push(ProxySessionCloseAction::Cancelled(operation_id));
                }
                AuthorizationStage::Executing => {
                    actions.push(ProxySessionCloseAction::ContinueCardExchange(operation_id));
                }
                AuthorizationStage::ResultPending => {
                    operation
                        .delivery_became_uncertain(store)
                        .map_err(map_local_authorization_error)?;
                    actions.push(ProxySessionCloseAction::DeliveryUncertain(operation_id));
                }
                AuthorizationStage::Terminal => {}
            }
        }
        Ok(actions)
    }

    fn receive_request<E>(
        &mut self,
        request: OperationRequest,
    ) -> Result<ProxyDispatch, ProxyEngineError<E>> {
        if !self.granted_profiles.contains(&request.profile) {
            return Err(ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::ProfileNotGranted,
            ));
        }
        if let Some(index) = self.index(request.operation_id) {
            if self.operations[index].operation_state().is_terminal() {
                return Ok(stale(request.operation_id));
            }
            return Err(ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::ActiveOperationIdReused,
            ));
        }
        if self
            .recovered
            .iter()
            .any(|entry| entry.record.operation_id == request.operation_id)
        {
            return Ok(stale(request.operation_id));
        }
        if self
            .operations
            .iter()
            .any(|operation| !operation.operation_state().is_terminal())
        {
            return Ok(ProxyDispatch::Send(TypedMessage::Error(
                ProtocolErrorMessage::Busy,
            )));
        }
        let operation_id = request.operation_id;
        let transaction = AuthorizationTransaction::prepare(request).map_err(|_| {
            ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::InvalidOperationRequest,
            )
        })?;
        self.operations.push(transaction);
        Ok(ProxyDispatch::InspectPrerequisites(operation_id))
    }

    fn receive_commit<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        reference: OperationReference,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        let operation_id = reference.operation_id;
        let Some(index) = self.index(operation_id) else {
            return Ok(stale(operation_id));
        };
        let operation = &mut self.operations[index];
        if operation.operation_state().is_terminal() {
            return Ok(stale(operation_id));
        }
        if matches!(
            operation.stage(),
            AuthorizationStage::Committed
                | AuthorizationStage::Executing
                | AuthorizationStage::ResultPending
        ) {
            if operation.reference() == reference {
                return Ok(ProxyDispatch::IgnoredDuplicateCommit(operation_id));
            }
            return Err(ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::ReferenceMismatch,
            ));
        }
        match operation.commit(store, reference, now_ms, maximum_lifetime_ms) {
            Ok(()) => Ok(ProxyDispatch::BeginCardCommand(operation_id)),
            Err(AuthorizationError::Expired) => {
                let result = OperationResultMessage::failure(
                    operation.reference(),
                    ResultStatus::Cancelled,
                    ResultError::RequestExpired,
                )
                .map_err(ProxyEngineError::InvalidLocalResult)?;
                operation
                    .finish_failure_result(store, &result)
                    .map_err(map_local_authorization_error)?;
                Ok(ProxyDispatch::Send(TypedMessage::OperationResult(result)))
            }
            Err(error) => Err(map_peer_authorization_error(error)),
        }
    }

    fn operation(&self, operation_id: OperationId) -> Option<&AuthorizationTransaction> {
        let index = self.index(operation_id)?;
        self.operations.get(index)
    }

    fn recovered(&self, operation_id: OperationId) -> Option<&RecoveredProxyRecord> {
        self.recovered
            .iter()
            .find(|entry| entry.record.operation_id == operation_id)
    }

    fn operation_mut(
        &mut self,
        operation_id: OperationId,
    ) -> Option<&mut AuthorizationTransaction> {
        let index = self.index(operation_id)?;
        self.operations.get_mut(index)
    }

    fn index(&self, operation_id: OperationId) -> Option<usize> {
        self.operations
            .iter()
            .position(|operation| operation.reference().operation_id == operation_id)
    }
}

/// Bounded step the proxy adapter must execute next.
#[derive(Debug)]
pub enum ProxyDispatch {
    /// Perform the profile's safe prerequisite inspection.
    InspectPrerequisites(OperationId),
    /// Execute the authorized safe read; no consequential command.
    ExecuteSafeRead {
        /// Operation the read belongs to.
        operation_id: OperationId,
        /// Single-use authorization for the safe read.
        read: AuthorizedSafeRead,
    },
    /// Begin the single authorized card command.
    BeginCardCommand(OperationId),
    /// Operation was safely cancelled.
    Cancelled(OperationId),
    /// Post-commit cancel recorded; the operation continues.
    AdvisoryCancellation(OperationId),
    /// Requester acknowledged the completed result.
    ResultAcknowledged(OperationId),
    /// Duplicate commit matching the committed hash was discarded.
    IgnoredDuplicateCommit(OperationId),
    /// Stale-reference race; answer without state change.
    IgnoredStale {
        /// Stale operation the peer referenced.
        operation_id: OperationId,
        /// Unknown-operation answer to send.
        response: TypedMessage,
    },
    /// Send this message on the authenticated channel.
    Send(TypedMessage),
    /// Send this failure result; the session may have to close.
    SendFailure {
        /// Failure result to send.
        message: TypedMessage,
        /// The session must close after the send.
        close_session: bool,
    },
    /// Message is not an operation message; no operation effect.
    NotOperation(TypedMessage),
}

/// Close-time classification of the active proxy operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxySessionCloseAction {
    /// Zero transmissions were proven; the operation is cancelled.
    Cancelled(OperationId),
    /// The in-flight card exchange finishes locally.
    ContinueCardExchange(OperationId),
    /// A completed result exists but delivery was not acknowledged.
    DeliveryUncertain(OperationId),
}

const fn status_message(
    operation: Option<&AuthorizationTransaction>,
    operation_id: OperationId,
) -> TypedMessage {
    let report = match operation {
        Some(operation) => StatusReport {
            operation_id,
            known: true,
            state: Some(operation.operation_state()),
            request_hash: Some(operation.reference().request_hash),
        },
        None => StatusReport {
            operation_id,
            known: false,
            state: None,
            request_hash: None,
        },
    };
    TypedMessage::OperationStatus(report)
}

const fn recovered_status_message(entry: &RecoveredProxyRecord) -> TypedMessage {
    TypedMessage::OperationStatus(StatusReport {
        operation_id: entry.record.operation_id,
        known: true,
        state: Some(entry.record.state),
        request_hash: Some(entry.record.request_hash),
    })
}

fn validate_recovered<E>(entry: &RecoveredProxyRecord) -> Result<(), ProxyEngineError<E>> {
    if entry.record.state == OperationState::None
        || entry.record.transmission_count > 1
        || entry.record.automatic_retry_permitted
        || (entry.record.state == OperationState::Committed && entry.record.transmission_count != 0)
        || (entry.record.state == OperationState::Executing && entry.record.transmission_count != 1)
    {
        return Err(ProxyEngineError::LocalInvariantFailure);
    }
    let result_required = matches!(
        entry.record.state,
        OperationState::ResultPending | OperationState::DeliveryUncertain
    );
    if result_required != entry.retained_result.is_some() {
        return Err(ProxyEngineError::LocalInvariantFailure);
    }
    Ok(())
}

const fn stale(operation_id: OperationId) -> ProxyDispatch {
    ProxyDispatch::IgnoredStale {
        operation_id,
        response: TypedMessage::Error(ProtocolErrorMessage::UnknownOperation(Some(operation_id))),
    }
}

const fn referenced_operation_id(message: &TypedMessage) -> Option<OperationId> {
    match message {
        TypedMessage::OperationRequest(request) => Some(request.operation_id),
        TypedMessage::OperationPrepared(reference)
        | TypedMessage::OperationCommit(reference)
        | TypedMessage::OperationResultAck(reference) => Some(reference.operation_id),
        TypedMessage::OperationCancel(cancel) => Some(cancel.reference.operation_id),
        TypedMessage::OperationResult(result) => Some(result.operation_id),
        TypedMessage::OperationStatusRequest(operation_id) => Some(*operation_id),
        TypedMessage::OperationStatus(report) => Some(report.operation_id),
        TypedMessage::OperationProgress(progress) => Some(progress.reference.operation_id),
        _ => None,
    }
}

fn map_peer_authorization_error<E>(error: AuthorizationError<E>) -> ProxyEngineError<E> {
    match error {
        AuthorizationError::Journal(error) => map_journal_error(error),
        AuthorizationError::Expired => ProxyEngineError::PeerRequestExpired,
        AuthorizationError::CommitMismatch => {
            ProxyEngineError::AuthenticatedProtocolViolation(ProxyViolation::ReferenceMismatch)
        }
        AuthorizationError::WrongStage(_) => ProxyEngineError::AuthenticatedProtocolViolation(
            ProxyViolation::IllegalOperationTransition,
        ),
        AuthorizationError::ApprovalMismatch | AuthorizationError::InvalidResult => {
            ProxyEngineError::LocalInvariantFailure
        }
    }
}

fn map_local_authorization_error<E>(error: AuthorizationError<E>) -> ProxyEngineError<E> {
    match error {
        AuthorizationError::Journal(error) => map_journal_error(error),
        AuthorizationError::Expired
        | AuthorizationError::ApprovalMismatch
        | AuthorizationError::CommitMismatch
        | AuthorizationError::WrongStage(_)
        | AuthorizationError::InvalidResult => ProxyEngineError::InvalidLocalTransition,
    }
}

fn map_journal_error<E>(error: JournalError<E>) -> ProxyEngineError<E> {
    match error {
        JournalError::Persistence(error) => ProxyEngineError::Persistence(error),
        JournalError::InvalidState { .. }
        | JournalError::RequestHashMismatch
        | JournalError::AlreadyTransmitted => ProxyEngineError::LocalInvariantFailure,
    }
}

/// Authenticated protocol violation observed by the proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyViolation {
    /// Request names a profile outside the granted set.
    ProfileNotGranted,
    /// Request reuses the identifier of the active operation.
    ActiveOperationIdReused,
    /// Request fails schema, registry, or context validation.
    InvalidOperationRequest,
    /// Message is illegal for the active operation's state.
    IllegalMessageForActiveOperation,
    /// Message demands a transition the machine does not define.
    IllegalOperationTransition,
    /// Echoed request hash differs from the journal.
    ReferenceMismatch,
}

/// Proxy operation-engine failure.
#[derive(Debug)]
pub enum ProxyEngineError<E> {
    /// Durable persistence failed; no credential command may be sent.
    Persistence(E),
    /// Locally produced result failed its typed validation.
    InvalidLocalResult(CardOperationError),
    /// Local call is illegal from the current operation state.
    InvalidLocalTransition,
    /// Local durable state contradicts a machine invariant.
    LocalInvariantFailure,
    /// Local call references an operation this engine does not hold.
    UnknownLocalOperation,
    /// Request expired before it could be admitted.
    PeerRequestExpired,
    /// Authenticated peer traffic violated the protocol.
    AuthenticatedProtocolViolation(ProxyViolation),
}

impl<E: fmt::Debug> fmt::Display for ProxyEngineError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl<E: fmt::Debug> core::error::Error for ProxyEngineError<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CardOperation, OperationId, PairId, SessionId};

    fn inspection_request() -> OperationRequest {
        OperationRequest::reconstruct(
            OperationId::from_array([0x11; 16]),
            PairId::from_array([0x22; 16]),
            SessionId::from_array([0x33; 16]),
            ProfileName::CardStatus,
            1_000,
            5_000,
            CardOperation::InspectCard,
        )
        .expect("registered card-status request")
    }

    #[test]
    fn authenticated_out_of_grant_request_is_a_protocol_violation() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::Authentication]);

        assert!(matches!(
            engine.receive_request::<()>(inspection_request()),
            Err(ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::ProfileNotGranted
            ))
        ));
    }

    #[test]
    fn authenticated_granted_request_reaches_prerequisite_inspection() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);

        assert!(matches!(
            engine.receive_request::<()>(inspection_request()),
            Ok(ProxyDispatch::InspectPrerequisites(_))
        ));
    }

    #[test]
    fn authenticated_operation_progress_reports_waiting_for_card() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let request = inspection_request();
        let op_id = request.operation_id;
        let expected_hash = request.request_hash().expect("valid request hash");
        assert!(engine.receive_request::<()>(request).is_ok());

        let progress = engine
            .report_progress(op_id, ProgressEvent::WaitingForCard)
            .expect("report progress succeeds");

        assert_eq!(
            progress,
            TypedMessage::OperationProgress(OperationProgressMessage {
                reference: OperationReference {
                    operation_id: op_id,
                    request_hash: expected_hash,
                },
                event: ProgressEvent::WaitingForCard,
            })
        );
    }
}
