//! Total proxy-side operation dispatcher and card-command boundary.

use core::fmt;

use super::{
    ApprovalOutcome, AuthorizationError, AuthorizationStage, AuthorizationTransaction,
    AuthorizedCardCommand, AuthorizedSafeRead, CardOperationResult, JournalError,
    JournalRecoveryStore, JournalStore, OperationId, OperationJournal, OperationProgressMessage,
    OperationReference, OperationRequest, OperationResultMessage, OperationState,
    PendingCardCommand, ProfileName, ProgressEvent, ProtocolErrorMessage, ProxyFailure,
    RecoveredProxyRecord, ResultJournalStore, ResultStatus, StatusReport, TypedMessage,
    UserApproval,
};

/// Maximum incoming operation requests permitted per rolling minute window.
/// Sized for reasonable human interaction (e.g. web surfing) while weeding out
/// broken or malicious client loops.
pub const MAX_OPERATIONS_PER_MINUTE: usize = 30;

/// Rolling rate limit window duration in milliseconds.
pub const RATE_LIMIT_WINDOW_MS: u64 = 60_000;

/// Operations for one authenticated proxy session. Exactly one may be active.
#[derive(Debug)]
pub struct ProxyOperationEngine {
    granted_profiles: Vec<ProfileName>,
    operations: Vec<AuthorizationTransaction>,
    recovered: Vec<RecoveredProxyRecord>,
    request_timestamps: Vec<u64>,
}

impl ProxyOperationEngine {
    /// Create a dispatcher bound to the exact profiles authenticated by the
    /// pairing transcript. An ungranted profile is answered with an
    /// `unauthorized` result.
    #[must_use]
    pub const fn new(granted_profiles: Vec<ProfileName>) -> Self {
        Self {
            granted_profiles,
            operations: Vec::new(),
            recovered: Vec::new(),
            request_timestamps: Vec::new(),
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
                _ => return Err(ProxyEngineError::LocalInvariantFailure),
            }
        }
        Ok(Self {
            granted_profiles,
            operations: Vec::new(),
            recovered: records,
            request_timestamps: Vec::new(),
        })
    }

    /// Dispatch a typed authenticated peer message.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an authenticated protocol violation or a
    /// persistence failure.
    pub fn receive<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        message: TypedMessage,
        now_ms: u64,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        match message {
            TypedMessage::OperationRequest(request) => self.receive_request(store, request, now_ms),
            TypedMessage::OperationRequestRefused(refusal) => Ok(ProxyDispatch::Send(
                TypedMessage::OperationResult(OperationResultMessage::rejection(
                    refusal.reference,
                    ResultStatus::Rejected,
                    refusal.error,
                )),
            )),
            TypedMessage::OperationResultAck(reference) => {
                self.receive_acknowledgment(store, reference)
            }
            TypedMessage::OperationStatusRequest(operation_id) => {
                Ok(self.status_answer(operation_id))
            }
            // Advisory progress is proxy-to-requester only; inbound progress
            // is ignored.
            TypedMessage::OperationProgress(_) => Ok(ProxyDispatch::NotOperation(message)),
            TypedMessage::OperationResult(_) | TypedMessage::OperationStatus(_) => {
                self.refuse_requester_only(message)
            }
            other => Ok(ProxyDispatch::NotOperation(other)),
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
    /// A consequential action's in-flight entry is durable before the card
    /// command is returned. An approval that arrives after the request's
    /// local deadline cancels the operation instead (section 8.2.1); no card
    /// command is produced.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation, an illegal local
    /// transition, or a persistence failure.
    pub fn approve<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
        approval: UserApproval,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        let operation = self
            .operation_mut(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?;
        if operation.stage() == AuthorizationStage::AwaitingConsent
            && operation.is_expired(now_ms, maximum_lifetime_ms)
        {
            return self.finish_failure(store, operation_id, ProxyFailure::RequestExpired);
        }
        let outcome = operation
            .approve(store, approval, now_ms, maximum_lifetime_ms)
            .map_err(map_local_authorization_error)?;
        Ok(match outcome {
            ApprovalOutcome::ExecuteCardCommand(command) => ProxyDispatch::ExecuteCardCommand {
                operation_id,
                command,
            },
            ApprovalOutcome::ExecuteSafeRead(read) => {
                ProxyDispatch::ExecuteSafeRead { operation_id, read }
            }
        })
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

    /// Record a stable failure and release it.
    ///
    /// Three failures also close the session: a refused retry, a blocked
    /// credential, and an ambiguous card completion. Each means the endpoint
    /// can no longer make safe progress on this session.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation, an illegal local
    /// transition, or a persistence failure.
    pub fn finish_failure<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
        failure: ProxyFailure,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        let operation = self
            .operation_mut(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?;
        let result = OperationResultMessage::failure_with_batch(
            operation.reference(),
            failure,
            operation.batch_signatures(),
        );
        operation
            .finish_failure_result(store, &result)
            .map_err(map_local_authorization_error)?;
        Ok(ProxyDispatch::SendFailure {
            close_session: failure.closes_session(),
            message: TypedMessage::OperationResult(result),
        })
    }

    /// Persist one batch signature before the next document is signed
    /// (section 9.3). A signature recorded here is delivered even if the
    /// batch is interrupted.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation, an operation that is
    /// not an executing batch, or a persistence failure.
    pub fn record_batch_signature<S: JournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
        signature: Vec<u8>,
    ) -> Result<(), ProxyEngineError<S::Error>> {
        self.operation_mut(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?
            .record_batch_signature(store, signature)
            .map_err(map_local_authorization_error)
    }

    /// Answer a batch once every document's signature is journaled, with
    /// exactly those signatures.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation, a batch with documents
    /// left to sign, or a persistence failure.
    pub fn complete_batch<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        let operation = self
            .operation(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?;
        let result = OperationResultMessage::completed(
            operation.reference(),
            &CardOperationResult::Signatures(operation.batch_signatures().to_vec()),
        );
        self.finish_completed(store, operation_id, result)
    }

    /// Create an authenticated advisory progress message for an active operation.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or an invalid local transition.
    pub fn report_progress(
        &self,
        operation_id: OperationId,
        event: ProgressEvent,
    ) -> Result<TypedMessage, ProxyEngineError<()>> {
        let op = self
            .operation(operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)?;
        if op.operation_state().is_terminal() {
            return Err(ProxyEngineError::InvalidLocalTransition);
        }
        Ok(TypedMessage::OperationProgress(OperationProgressMessage {
            reference: op.reference(),
            event,
        }))
    }

    /// Classify every live operation when the session closes.
    ///
    /// An operation still awaiting consent is cancelled with nothing sent to
    /// the card; one executing on the card runs to its own conclusion; a
    /// completed result not yet acknowledged stays retained for re-delivery
    /// (section 8.3).
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
                | AuthorizationStage::ExecutingSafeRead => {
                    let result = OperationResultMessage::failure(
                        operation.reference(),
                        ProxyFailure::Cancelled,
                    );
                    operation
                        .finish_failure_result(store, &result)
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

    /// Admits a new request, or resolves a reused identifier from the live
    /// table, the journal and the tombstones (section 8.2.2).
    fn receive_request<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        request: OperationRequest,
        now_ms: u64,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        let operation_id = request.operation_id;
        let cutoff = now_ms.saturating_sub(RATE_LIMIT_WINDOW_MS);
        self.request_timestamps.retain(|&ts| ts >= cutoff);
        if self.request_timestamps.len() >= MAX_OPERATIONS_PER_MINUTE {
            return Ok(ProxyDispatch::Send(TypedMessage::Error(
                ProtocolErrorMessage::OperationFailed(Some(operation_id)),
            )));
        }
        self.request_timestamps.push(now_ms);

        let request_hash = request.request_hash().map_err(|_| {
            ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::InvalidOperationRequest,
            )
        })?;
        if let Some(operation) = self.operation(operation_id) {
            if operation.reference().request_hash != request_hash {
                return Ok(duplicate(operation_id));
            }
            if let Some(retained) = operation.retained_result() {
                return Ok(ProxyDispatch::Send(TypedMessage::OperationResult(
                    retained.clone(),
                )));
            }
            if operation.operation_state() == OperationState::Completed {
                return Ok(ProxyDispatch::Send(TypedMessage::OperationResult(
                    OperationResultMessage::retired(
                        operation.reference(),
                        ResultStatus::Completed,
                        None,
                    ),
                )));
            }
            return Ok(ProxyDispatch::IgnoredDuplicate(operation_id));
        }
        if let Some(entry) = self.recovered(operation_id) {
            if entry.record.request_hash != request_hash {
                return Ok(duplicate(operation_id));
            }
            return Ok(ProxyDispatch::Send(TypedMessage::OperationResult(
                recovered_answer(entry),
            )));
        }
        if self
            .operations
            .iter()
            .any(|operation| !operation.operation_state().is_terminal())
        {
            return Ok(ProxyDispatch::Send(TypedMessage::Error(
                ProtocolErrorMessage::OperationFailed(Some(operation_id)),
            )));
        }
        let profile = request.profile;
        let transaction = AuthorizationTransaction::prepare(request).map_err(|_| {
            ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::InvalidOperationRequest,
            )
        })?;
        self.operations.push(transaction);
        if !self.granted_profiles.contains(&profile) {
            return self.finish_failure(store, operation_id, ProxyFailure::Unauthorized);
        }
        Ok(ProxyDispatch::InspectPrerequisites(operation_id))
    }

    /// Retires an acknowledged result, live or re-delivered; any other
    /// acknowledgment is ignored without touching a tombstone (section 8.2.5).
    fn receive_acknowledgment<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        reference: OperationReference,
    ) -> Result<ProxyDispatch, ProxyEngineError<S::Error>> {
        let operation_id = reference.operation_id;
        if let Some(operation) = self.operation_mut(operation_id) {
            if operation.stage() != AuthorizationStage::ResultPending
                || operation.reference() != reference
            {
                return Ok(ProxyDispatch::NotOperation(
                    TypedMessage::OperationResultAck(reference),
                ));
            }
            operation
                .acknowledge_result(store, reference)
                .map_err(map_local_authorization_error)?;
            return Ok(ProxyDispatch::ResultAcknowledged(operation_id));
        }
        let Some(entry) = self.recovered.iter_mut().find(|entry| {
            entry.record.operation_id == operation_id
                && entry.record.request_hash == reference.request_hash
                && entry.record.state == OperationState::DeliveryUncertain
        }) else {
            return Ok(ProxyDispatch::NotOperation(
                TypedMessage::OperationResultAck(reference),
            ));
        };
        let mut journal = OperationJournal::recovered(entry.record.clone());
        journal
            .acknowledge_result(store)
            .map_err(map_journal_error)?;
        entry.record = journal.record().clone();
        entry.retained_result = None;
        Ok(ProxyDispatch::ResultAcknowledged(operation_id))
    }

    /// The status report, followed by the result it re-delivers when one is
    /// retained (section 8.3).
    fn status_answer(&self, operation_id: OperationId) -> ProxyDispatch {
        if let Some(operation) = self.operation(operation_id) {
            let state = operation.operation_state();
            let report = TypedMessage::OperationStatus(StatusReport {
                operation_id,
                known: true,
                state: Some(state),
                request_hash: Some(operation.reference().request_hash),
                retired: state == OperationState::Completed,
            });
            return match operation.retained_result() {
                Some(retained) => ProxyDispatch::SendAll(vec![
                    report,
                    TypedMessage::OperationResult(retained.clone()),
                ]),
                None => ProxyDispatch::Send(report),
            };
        }
        if let Some(entry) = self.recovered(operation_id) {
            let retired = entry.record.state == OperationState::Completed;
            let report = TypedMessage::OperationStatus(StatusReport {
                operation_id,
                known: true,
                state: Some(entry.record.state),
                request_hash: Some(entry.record.request_hash),
                retired,
            });
            if retired {
                return ProxyDispatch::Send(report);
            }
            return ProxyDispatch::SendAll(vec![
                report,
                TypedMessage::OperationResult(recovered_answer(entry)),
            ]);
        }
        ProxyDispatch::Send(TypedMessage::OperationStatus(StatusReport {
            operation_id,
            known: false,
            state: None,
            request_hash: None,
            retired: false,
        }))
    }

    /// A requester-only message is a violation only when it names a live
    /// operation; otherwise it is a stale race.
    fn refuse_requester_only<E>(
        &self,
        message: TypedMessage,
    ) -> Result<ProxyDispatch, ProxyEngineError<E>> {
        let Some(operation_id) = referenced_operation_id(&message) else {
            return Ok(ProxyDispatch::NotOperation(message));
        };
        match self.operation(operation_id) {
            Some(operation) if !operation.operation_state().is_terminal() => {
                Err(ProxyEngineError::AuthenticatedProtocolViolation(
                    ProxyViolation::IllegalMessageForActiveOperation,
                ))
            }
            _ => Ok(stale(operation_id)),
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
    /// The in-flight entry is durable; execute the single card command.
    ExecuteCardCommand {
        /// Operation the command belongs to.
        operation_id: OperationId,
        /// The one-shot command.
        command: PendingCardCommand<AuthorizedCardCommand>,
    },
    /// Requester acknowledged the completed result.
    ResultAcknowledged(OperationId),
    /// An identical retransmission joined the operation already under way.
    IgnoredDuplicate(OperationId),
    /// Stale-reference race; answer without state change.
    IgnoredStale {
        /// Stale operation the peer referenced.
        operation_id: OperationId,
        /// Unknown-operation answer to send.
        response: TypedMessage,
    },
    /// Send this message on the authenticated channel.
    Send(TypedMessage),
    /// Send these messages in order, such as a status report and the result
    /// it re-delivers.
    SendAll(Vec<TypedMessage>),
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

/// The result a journaled operation from an earlier session answers with.
fn recovered_answer(entry: &RecoveredProxyRecord) -> OperationResultMessage {
    if let Some(retained) = &entry.retained_result {
        return retained.clone();
    }
    let reference = OperationReference {
        operation_id: entry.record.operation_id,
        request_hash: entry.record.request_hash,
    };
    let failure = match entry.record.state {
        OperationState::Completed => {
            return OperationResultMessage::retired(reference, ResultStatus::Completed, None);
        }
        OperationState::Cancelled | OperationState::Denied => ProxyFailure::Cancelled,
        OperationState::CredentialRejected => ProxyFailure::CredentialRejected,
        OperationState::Ambiguous
        | OperationState::Committed
        | OperationState::Executing
        | OperationState::ResultPending
        | OperationState::DeliveryUncertain => {
            let completed = entry
                .record
                .batch
                .as_ref()
                .map_or(&[][..], |batch| batch.completed_signatures.as_slice());
            return OperationResultMessage::failure_with_batch(
                reference,
                ProxyFailure::CardCompletionAmbiguous,
                completed,
            );
        }
        OperationState::None
        | OperationState::Requested
        | OperationState::AwaitingConsent
        | OperationState::Prepared
        | OperationState::Rejected => ProxyFailure::RetryPolicyRefused,
    };
    OperationResultMessage::failure(reference, failure)
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
    let result_allowed = match entry.record.state {
        OperationState::ResultPending | OperationState::DeliveryUncertain => {
            if entry.retained_result.is_none() {
                return Err(ProxyEngineError::LocalInvariantFailure);
            }
            true
        }
        OperationState::Cancelled
        | OperationState::Denied
        | OperationState::Rejected
        | OperationState::CredentialRejected
        | OperationState::Ambiguous => true,
        _ => false,
    };
    if entry.retained_result.is_some() && !result_allowed {
        return Err(ProxyEngineError::LocalInvariantFailure);
    }
    if let Some(result) = &entry.retained_result
        && (result.operation_id != entry.record.operation_id
            || result.request_hash != entry.record.request_hash)
    {
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

const fn duplicate(operation_id: OperationId) -> ProxyDispatch {
    ProxyDispatch::Send(TypedMessage::Error(
        ProtocolErrorMessage::DuplicateOperation(operation_id),
    ))
}

const fn referenced_operation_id(message: &TypedMessage) -> Option<OperationId> {
    match message {
        TypedMessage::OperationRequest(request) => Some(request.operation_id),
        TypedMessage::OperationRequestRefused(refusal) => Some(refusal.reference.operation_id),
        TypedMessage::OperationResultAck(reference) => Some(reference.operation_id),
        TypedMessage::OperationResult(result) => Some(result.operation_id),
        TypedMessage::OperationStatusRequest(operation_id) => Some(*operation_id),
        TypedMessage::OperationStatus(report) => Some(report.operation_id),
        TypedMessage::OperationProgress(progress) => Some(progress.reference.operation_id),
        _ => None,
    }
}

fn map_local_authorization_error<E>(error: AuthorizationError<E>) -> ProxyEngineError<E> {
    match error {
        AuthorizationError::Journal(error) => map_journal_error(error),
        AuthorizationError::Expired
        | AuthorizationError::ApprovalMismatch
        | AuthorizationError::ReferenceMismatch
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
    /// Request fails schema, registry, or context validation.
    InvalidOperationRequest,
    /// Message is illegal for the active operation's state.
    IllegalMessageForActiveOperation,
}

/// Proxy operation-engine failure.
#[derive(Debug)]
pub enum ProxyEngineError<E> {
    /// Durable persistence failed; no credential command may be sent.
    Persistence(E),
    /// Local call is illegal from the current operation state.
    InvalidLocalTransition,
    /// Local durable state contradicts a machine invariant.
    LocalInvariantFailure,
    /// Local call references an operation this engine does not hold.
    UnknownLocalOperation,
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
    use crate::{CardOperation, JournalStore, OperationId, PairId, SessionId};

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

    struct TestStore;
    impl JournalStore for TestStore {
        type Error = ();
        fn persist(&mut self, _record: &crate::JournalRecord) -> Result<(), Self::Error> {
            Ok(())
        }
    }
    impl ResultJournalStore for TestStore {
        fn persist_result(
            &mut self,
            _record: &crate::JournalRecord,
            _result: &OperationResultMessage,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
        fn retain_uncertain_result(
            &mut self,
            _record: &crate::JournalRecord,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
        fn acknowledge_result(
            &mut self,
            _record: &crate::JournalRecord,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn authenticated_out_of_grant_request_is_answered_unauthorized() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::Authentication]);

        assert!(matches!(
            engine.receive_request(&mut TestStore, inspection_request(), 1_000),
            Ok(ProxyDispatch::SendFailure {
                message: TypedMessage::OperationResult(OperationResultMessage {
                    error: Some(crate::ResultError::Unauthorized),
                    ..
                }),
                close_session: false,
            })
        ));
    }

    #[test]
    fn authenticated_granted_request_reaches_prerequisite_inspection() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);

        assert!(matches!(
            engine.receive_request(&mut TestStore, inspection_request(), 1_000),
            Ok(ProxyDispatch::InspectPrerequisites(_))
        ));
    }

    #[test]
    fn authenticated_operation_progress_reports_waiting_for_card() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let request = inspection_request();
        let op_id = request.operation_id;
        let expected_hash = request.request_hash().expect("valid request hash");
        assert!(
            engine
                .receive_request(&mut TestStore, request, 1_000)
                .is_ok()
        );

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

    #[test]
    fn terminal_operation_rejects_report_progress() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let request = inspection_request();
        let op_id = request.operation_id;
        assert!(
            engine
                .receive_request(&mut TestStore, request, 1_000)
                .is_ok()
        );

        // Session closed cancels the active operation, making it terminal
        assert!(engine.session_closed(&mut TestStore).is_ok());

        assert!(matches!(
            engine.report_progress(op_id, ProgressEvent::WaitingForCard),
            Err(ProxyEngineError::InvalidLocalTransition)
        ));
    }

    #[test]
    fn proxy_rate_limiter_blocks_excessive_requests() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        for i in 0..MAX_OPERATIONS_PER_MINUTE {
            let mut req = inspection_request();
            let mut op_bytes = [0x11; 16];
            op_bytes[0] = i as u8;
            req.operation_id = OperationId::from_array(op_bytes);
            let dispatch = engine.receive_request(&mut TestStore, req, 1_000 + i as u64);
            assert!(dispatch.is_ok());
            engine.operations.clear();
        }

        // 31st request at 1_500ms is refused by the rate limiter
        let mut req_overflow = inspection_request();
        req_overflow.operation_id = OperationId::from_array([0x99; 16]);
        let overflow_dispatch = engine.receive_request(&mut TestStore, req_overflow, 1_500);
        assert!(matches!(
            overflow_dispatch,
            Ok(ProxyDispatch::Send(TypedMessage::Error(
                ProtocolErrorMessage::OperationFailed(_)
            )))
        ));

        // After window expires (60_000ms later at 61_001ms), requests should be accepted again
        let mut req_after = inspection_request();
        req_after.operation_id = OperationId::from_array([0xaa; 16]);
        let after_dispatch =
            engine.receive_request(&mut TestStore, req_after, 1_000 + RATE_LIMIT_WINDOW_MS + 1);
        assert!(matches!(
            after_dispatch,
            Ok(ProxyDispatch::InspectPrerequisites(_))
        ));
    }

    #[test]
    fn inbound_operation_progress_on_proxy_is_tolerated_as_not_operation() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let request = inspection_request();
        let op_id = request.operation_id;
        let expected_hash = request.request_hash().expect("valid request hash");
        assert!(
            engine
                .receive_request(&mut TestStore, request, 1_000)
                .is_ok()
        );

        let progress_msg = TypedMessage::OperationProgress(OperationProgressMessage {
            reference: OperationReference {
                operation_id: op_id,
                request_hash: expected_hash,
            },
            event: ProgressEvent::WaitingForCard,
        });

        let outcome = engine
            .receive(&mut TestStore, progress_msg, 1_000)
            .expect("receive succeeds");
        assert!(matches!(outcome, ProxyDispatch::NotOperation(_)));
    }
}
