//! Durable requester-side operation protocol.

use core::fmt;

use super::{
    CardOperationError, CardOperationResult, OperationProgressMessage, OperationReference,
    OperationRequest, OperationResultMessage, OperationState, PairId, ProgressEvent, RequestHash,
    ResultError, ResultStatus, SessionId, StatusReport, TypedMessage,
};

/// Complete non-secret requester journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequesterJournalRecord {
    /// Long-term pair binding.
    pub pair_id: PairId,
    /// Session the operation was requested on.
    pub session_id: SessionId,
    /// Unique at-most-once operation identifier.
    pub operation_id: super::OperationId,
    /// Deterministic request commitment.
    pub request_hash: RequestHash,
    /// Durable operation state.
    pub state: OperationState,
    /// Completed public output retained under local platform encryption until
    /// result acknowledgment succeeds.
    pub retained_result: Option<CardOperationResult>,
    /// Authenticated status reconciliation annotation. It never changes the
    /// terminal local state machine.
    pub reconciliation: Option<StatusReport>,
}

/// Atomic encrypted requester-journal storage boundary.
pub trait RequesterJournalStore {
    /// Storage-backend failure.
    type Error;

    /// Atomically persist the whole record before the corresponding outgoing
    /// protocol message is released to the transport.
    ///
    /// # Errors
    /// The storage-backend failure.
    fn persist(&mut self, record: &RequesterJournalRecord) -> Result<(), Self::Error>;
}

/// Restart-recovery extension for device-local requester journals.
pub trait RequesterRecoveryStore: RequesterJournalStore {
    /// Load every retained record for the pairing. Secret credential entry is
    /// never part of these records.
    ///
    /// # Errors
    /// The storage-backend failure.
    fn load_all(&mut self) -> Result<Vec<RequesterJournalRecord>, Self::Error>;
}

/// One requester operation from local intent through result acknowledgment.
#[derive(Debug)]
pub struct RequesterOperation {
    request: OperationRequest,
    reference: OperationReference,
    record: RequesterJournalRecord,
}

impl RequesterOperation {
    /// Creates a new operation ID instance; no state is durable yet.
    ///
    /// # Errors
    /// [`CardOperationError`] when the request hash cannot be computed.
    pub fn new(request: OperationRequest) -> Result<Self, CardOperationError> {
        let request_hash = request.request_hash()?;
        let reference = OperationReference {
            operation_id: request.operation_id,
            request_hash,
        };
        let record = RequesterJournalRecord {
            pair_id: request.pair_id,
            session_id: request.session_id,
            operation_id: request.operation_id,
            request_hash,
            state: OperationState::None,
            retained_result: None,
            reconciliation: None,
        };
        Ok(Self {
            request,
            reference,
            record,
        })
    }

    /// Current durable projection.
    #[must_use]
    pub const fn record(&self) -> &RequesterJournalRecord {
        &self.record
    }

    /// Persist request intent before returning `operation.request` for send.
    ///
    /// # Errors
    /// [`RequesterError`] on a wrong state or a persistence failure.
    pub fn begin<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<TypedMessage, RequesterError<S::Error>> {
        self.require_state(OperationState::None)?;
        self.persist_state(store, OperationState::Requested)?;
        Ok(TypedMessage::OperationRequest(self.request.clone()))
    }

    /// The terminal state an unanswered request reaches when its session
    /// ends.
    ///
    /// The custodian may have acted on a consequential request after
    /// consent, so its fate is ambiguous until reconciled (section 8.3); a
    /// safe read touched no credential and simply ends.
    const fn unanswered_terminal(&self) -> OperationState {
        if self.request.operation.is_consequential() {
            OperationState::Ambiguous
        } else {
            OperationState::Cancelled
        }
    }

    /// Abandon the request locally; no message travels (section 8.3).
    ///
    /// # Errors
    /// [`RequesterError`] when the request is no longer awaiting its result,
    /// or on a persistence failure.
    pub fn cancel<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<OperationState, RequesterError<S::Error>> {
        self.require_state(OperationState::Requested)?;
        let terminal = self.unanswered_terminal();
        self.persist_state(store, terminal)?;
        Ok(terminal)
    }

    /// Validate and durably retain a result.
    ///
    /// A live completed result is held until the acknowledgment is
    /// delivered; every other status, and a retired completed one, is
    /// terminal at once and is never acknowledged.
    ///
    /// # Errors
    /// [`RequesterError`] on a result that fails typed validation, a result
    /// for an operation no longer awaiting one, or a persistence failure.
    pub fn receive_result<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        result: OperationResultMessage,
    ) -> Result<RequesterResultAction, RequesterError<S::Error>> {
        result
            .validate_for(self.reference, &self.request.operation)
            .map_err(RequesterError::Operation)?;
        self.require_state(OperationState::Requested)?;
        if let (ResultStatus::Completed, false, Some(response)) =
            (result.status, result.retired, &result.response)
        {
            self.record.retained_result = Some(
                response
                    .typed_for(&self.request.operation)
                    .map_err(RequesterError::Operation)?,
            );
            self.persist_state(store, OperationState::ResultPending)?;
            return Ok(RequesterResultAction::SendAcknowledgment(
                TypedMessage::OperationResultAck(self.reference),
            ));
        }
        let terminal = result_status_state(result.status);
        self.persist_state(store, terminal)?;
        Ok(RequesterResultAction::Terminal {
            state: terminal,
            status: result.status,
            error: result.error,
            remaining_retries: result.remaining_retries,
        })
    }

    /// Persist successful acknowledgment delivery before releasing the result
    /// to the requesting application.
    ///
    /// # Errors
    /// [`RequesterError`] on a wrong state, a missing retained result, or a
    /// persistence failure.
    pub fn acknowledgment_sent<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<CardOperationResult, RequesterError<S::Error>> {
        self.require_state(OperationState::ResultPending)?;
        let result = self
            .record
            .retained_result
            .take()
            .ok_or(RequesterError::MissingResult)?;
        let previous_state = self.record.state;
        self.record.state = OperationState::Completed;
        if let Err(error) = store.persist(&self.record) {
            self.record.state = previous_state;
            self.record.retained_result = Some(result);
            return Err(RequesterError::Persistence(error));
        }
        Ok(result)
    }

    /// Receive an authenticated advisory progress update.
    ///
    /// Progress updates do not change durable operation state or lifecycle.
    ///
    /// # Errors
    /// [`RequesterError`] on an unexpected terminal state or a reference mismatch.
    pub fn receive_progress<E>(
        &self,
        progress: &OperationProgressMessage,
    ) -> Result<ProgressEvent, RequesterError<E>> {
        if self.record.state.is_terminal() {
            return Err(RequesterError::WrongState(self.record.state));
        }
        if progress.reference != self.reference {
            return Err(RequesterError::ReferenceMismatch);
        }
        Ok(progress.event)
    }

    /// Classifies a closed session exactly once.
    ///
    /// # Errors
    /// [`RequesterError`] on an unclassifiable state or a persistence
    /// failure.
    pub fn session_closed<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<OperationState, RequesterError<S::Error>> {
        let terminal = match self.record.state {
            OperationState::Requested => self.unanswered_terminal(),
            OperationState::ResultPending => OperationState::DeliveryUncertain,
            state if state.is_terminal() => return Ok(state),
            state => return Err(RequesterError::WrongState(state)),
        };
        self.persist_state(store, terminal)?;
        Ok(terminal)
    }

    /// Build a post-reconnection status query without changing terminal state.
    #[must_use]
    pub const fn status_query(&self) -> TypedMessage {
        TypedMessage::OperationStatusRequest(self.request.operation_id)
    }

    /// Store an authenticated reconciliation answer as an annotation only.
    ///
    /// # Errors
    /// [`RequesterError`] on a foreign operation identifier, a reference
    /// mismatch, or a persistence failure.
    pub fn annotate_status<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        report: StatusReport,
    ) -> Result<(), RequesterError<S::Error>> {
        if report.operation_id != self.request.operation_id {
            return Err(RequesterError::UnknownOperationRace);
        }
        if let Some(hash) = report.request_hash
            && hash != self.reference.request_hash
        {
            return Err(RequesterError::ReferenceMismatch);
        }
        self.record.reconciliation = Some(report);
        store
            .persist(&self.record)
            .map_err(RequesterError::Persistence)
    }

    fn require_state<E>(&self, expected: OperationState) -> Result<(), RequesterError<E>> {
        if self.record.state == expected {
            Ok(())
        } else {
            Err(RequesterError::WrongState(self.record.state))
        }
    }

    fn persist_state<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        state: OperationState,
    ) -> Result<(), RequesterError<S::Error>> {
        let previous = self.record.state;
        self.record.state = state;
        if let Err(error) = store.persist(&self.record) {
            self.record.state = previous;
            return Err(RequesterError::Persistence(error));
        }
        Ok(())
    }
}

/// Caller action after a durably stored result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequesterResultAction {
    /// Send this exact hash acknowledgment, then call `acknowledgment_sent`.
    SendAcknowledgment(TypedMessage),
    /// No acknowledgment is required.
    Terminal {
        /// Journaled terminal state.
        state: OperationState,
        /// Status the result reported.
        status: ResultStatus,
        /// Error the result named.
        error: Option<ResultError>,
        /// Remaining credential attempts the result reported.
        remaining_retries: Option<u8>,
    },
}

/// The journal state a non-acknowledged result leaves; a retired completed
/// result has nothing left to deliver.
const fn result_status_state(status: ResultStatus) -> OperationState {
    match status {
        ResultStatus::Completed => OperationState::Completed,
        ResultStatus::Cancelled => OperationState::Cancelled,
        ResultStatus::Rejected => OperationState::Rejected,
        ResultStatus::CredentialRejected => OperationState::CredentialRejected,
        ResultStatus::Ambiguous => OperationState::Ambiguous,
    }
}

/// Requester protocol or persistence failure.
#[derive(Debug)]
pub enum RequesterError<E> {
    /// Durable persistence failed; the message is not released.
    Persistence(E),
    /// Message failed its typed operation validation.
    Operation(CardOperationError),
    /// Input is illegal from the current durable state.
    WrongState(OperationState),
    /// Echoed request hash differs from the journal.
    ReferenceMismatch,
    /// Reference to a different or terminal operation; a normal race.
    UnknownOperationRace,
    /// Acknowledged record retains no result body.
    MissingResult,
}

impl<E: fmt::Debug> fmt::Display for RequesterError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl<E: fmt::Debug> core::error::Error for RequesterError<E> {}
