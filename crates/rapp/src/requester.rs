//! Durable requester-side operation protocol.

use core::fmt;

use super::{
    CancelMessage, CardOperationError, CardOperationResult, OperationProgressMessage,
    OperationReference, OperationRequest, OperationResultMessage, OperationState, PairId,
    ProgressEvent, RequestHash, ResultStatus, SessionId, StatusReport, TypedMessage,
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

    /// Accept exact `operation.prepared` and journal it.
    ///
    /// # Errors
    /// [`RequesterError`] on a wrong state, a reference mismatch, a prepared
    /// echo for a safe read, or a persistence failure.
    pub fn receive_prepared<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        reference: OperationReference,
    ) -> Result<(), RequesterError<S::Error>> {
        self.require_state(OperationState::Requested)?;
        self.require_reference(reference)?;
        if !self.request.operation.is_consequential() {
            return Err(RequesterError::UnexpectedPreparedForSafeRead);
        }
        self.persist_state(store, OperationState::Prepared)
    }

    /// Persist the requester's point of no return before releasing commit.
    ///
    /// # Errors
    /// [`RequesterError`] on a wrong state or a persistence failure.
    pub fn commit<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<TypedMessage, RequesterError<S::Error>> {
        self.require_state(OperationState::Prepared)?;
        self.persist_state(store, OperationState::Committed)?;
        Ok(TypedMessage::OperationCommit(self.reference))
    }

    /// Journal and emit an advisory cancellation. Before commit this is a
    /// terminal cancellation. After commit it cannot prove that the card
    /// command did not execute, so the operation remains committed.
    ///
    /// # Errors
    /// [`RequesterError`] on a terminal or illegal state or a persistence
    /// failure.
    pub fn cancel<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        reason: Option<String>,
    ) -> Result<RequesterCancelAction, RequesterError<S::Error>> {
        let message = TypedMessage::OperationCancel(CancelMessage {
            reference: self.reference,
            reason,
        });
        match self.record.state {
            OperationState::Requested
            | OperationState::AwaitingConsent
            | OperationState::Prepared => {
                self.persist_state(store, OperationState::Cancelled)?;
                Ok(RequesterCancelAction::Terminal(message))
            }
            OperationState::Committed
            | OperationState::Executing
            | OperationState::ResultPending => Ok(RequesterCancelAction::Advisory(message)),
            state if state.is_terminal() => Err(RequesterError::UnknownOperationRace),
            state => Err(RequesterError::WrongState(state)),
        }
    }

    /// Apply a cancellation sent by the proxy under the same commit boundary.
    ///
    /// # Errors
    /// [`RequesterError`] on a reference mismatch, a terminal or illegal
    /// state, or a persistence failure.
    pub fn receive_cancel<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        cancellation: &CancelMessage,
    ) -> Result<OperationState, RequesterError<S::Error>> {
        self.require_reference(cancellation.reference)?;
        match self.record.state {
            OperationState::Requested
            | OperationState::AwaitingConsent
            | OperationState::Prepared => {
                self.persist_state(store, OperationState::Cancelled)?;
                Ok(OperationState::Cancelled)
            }
            OperationState::Committed
            | OperationState::Executing
            | OperationState::ResultPending => Ok(self.record.state),
            state if state.is_terminal() => Err(RequesterError::UnknownOperationRace),
            state => Err(RequesterError::WrongState(state)),
        }
    }

    /// Validate and durably retain a result. Completed results require an ack;
    /// all other statuses become terminal immediately and receive no ack.
    ///
    /// # Errors
    /// [`RequesterError`] on a result that fails typed validation, a status
    /// illegal for the current state, or a persistence failure.
    pub fn receive_result<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        result: OperationResultMessage,
    ) -> Result<RequesterResultAction, RequesterError<S::Error>> {
        result
            .validate_for(self.reference, &self.request.operation)
            .map_err(RequesterError::Operation)?;
        let legal_state = match result.status {
            ResultStatus::Completed => {
                if self.request.operation.is_consequential() {
                    self.record.state == OperationState::Committed
                } else {
                    self.record.state == OperationState::Requested
                }
            }
            ResultStatus::Denied => matches!(
                self.record.state,
                OperationState::Requested | OperationState::Prepared
            ),
            ResultStatus::Cancelled | ResultStatus::Rejected | ResultStatus::CredentialRejected => {
                matches!(
                    self.record.state,
                    OperationState::Requested
                        | OperationState::Prepared
                        | OperationState::Committed
                )
            }
            ResultStatus::Ambiguous => self.record.state == OperationState::Committed,
        };
        if !legal_state {
            return Err(RequesterError::WrongState(self.record.state));
        }
        if result.status == ResultStatus::Completed {
            self.record.retained_result = result.result;
            self.persist_state(store, OperationState::ResultPending)?;
            Ok(RequesterResultAction::SendAcknowledgment(
                TypedMessage::OperationResultAck(self.reference),
            ))
        } else {
            let terminal = result_status_state(result.status);
            self.persist_state(store, terminal)?;
            Ok(RequesterResultAction::Terminal(terminal))
        }
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

    /// Classifies a closed session exactly once from the local commit boundary.
    ///
    /// # Errors
    /// [`RequesterError`] on an unclassifiable state or a persistence
    /// failure.
    pub fn session_closed<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<OperationState, RequesterError<S::Error>> {
        let terminal = match self.record.state {
            OperationState::Requested
            | OperationState::AwaitingConsent
            | OperationState::Prepared => OperationState::Cancelled,
            OperationState::Committed | OperationState::Executing => OperationState::Ambiguous,
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

    fn require_reference<E>(&self, reference: OperationReference) -> Result<(), RequesterError<E>> {
        if reference == self.reference {
            Ok(())
        } else if reference.operation_id != self.reference.operation_id {
            Err(RequesterError::UnknownOperationRace)
        } else {
            Err(RequesterError::ReferenceMismatch)
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
    Terminal(OperationState),
}

/// Requester action after local cancellation is made durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequesterCancelAction {
    /// Cancellation is terminal because no commit was released.
    Terminal(TypedMessage),
    /// Cancellation is advisory because commit was already released.
    Advisory(TypedMessage),
}

const fn result_status_state(status: ResultStatus) -> OperationState {
    match status {
        ResultStatus::Completed => OperationState::ResultPending,
        ResultStatus::Denied => OperationState::Denied,
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
    /// Prepared echo arrived for an action without prepare and commit.
    UnexpectedPreparedForSafeRead,
    /// Acknowledged record retains no result body.
    MissingResult,
}

impl<E: fmt::Debug> fmt::Display for RequesterError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl<E: fmt::Debug> core::error::Error for RequesterError<E> {}
