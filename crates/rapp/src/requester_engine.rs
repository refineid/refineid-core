//! Total requester-side operation dispatcher.

use core::fmt;

use super::{
    CardOperationError, CardOperationResult, OperationId, OperationRequest, OperationState,
    ProgressEvent, ProtocolErrorMessage, RequesterCancelAction, RequesterError,
    RequesterJournalRecord, RequesterJournalStore, RequesterOperation, RequesterRecoveryStore,
    RequesterResultAction, StatusReport, TypedMessage,
};

/// All live and terminal requester operations for one paired endpoint.
///
/// Terminal entries remain addressable for authenticated status annotations.
/// Integrations may remove them only after their durable retention policy has
/// expired.
#[derive(Debug, Default)]
pub struct RequesterOperationEngine {
    operations: Vec<RequesterOperation>,
    recovered: Vec<RequesterJournalRecord>,
}

impl RequesterOperationEngine {
    /// Construct an engine with no live or recovered operations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operations: Vec::new(),
            recovered: Vec::new(),
        }
    }

    /// Load and fail closed every journal left by a previous process. No
    /// recovered operation returns to a live protocol state.
    ///
    /// # Errors
    /// [`RequesterEngineError`] on a persistence failure or a record that
    /// contradicts a machine invariant.
    pub fn recover<S: RequesterRecoveryStore>(
        store: &mut S,
    ) -> Result<Self, RequesterEngineError<S::Error>> {
        let mut records = store
            .load_all()
            .map_err(RequesterEngineError::Persistence)?;
        for index in 0..records.len() {
            if records[..index]
                .iter()
                .any(|record| record.operation_id == records[index].operation_id)
            {
                return Err(RequesterEngineError::LocalInvariantFailure);
            }
            let next = match records[index].state {
                OperationState::Requested
                | OperationState::AwaitingConsent
                | OperationState::Prepared => Some(OperationState::Cancelled),
                OperationState::Committed | OperationState::Executing => {
                    Some(OperationState::Ambiguous)
                }
                OperationState::ResultPending => Some(OperationState::DeliveryUncertain),
                OperationState::None => {
                    return Err(RequesterEngineError::LocalInvariantFailure);
                }
                state if state.is_terminal() => None,
                _ => return Err(RequesterEngineError::LocalInvariantFailure),
            };
            if let Some(state) = next {
                records[index].state = state;
                store
                    .persist(&records[index])
                    .map_err(RequesterEngineError::Persistence)?;
            }
            let result_required = records[index].state == OperationState::DeliveryUncertain;
            if result_required != records[index].retained_result.is_some() {
                return Err(RequesterEngineError::LocalInvariantFailure);
            }
        }
        Ok(Self {
            operations: Vec::new(),
            recovered: records,
        })
    }

    /// Durably begin a unique operation before releasing its request frame.
    ///
    /// # Errors
    /// [`RequesterEngineError`] on a duplicate identifier, an invalid
    /// request, or a persistence failure.
    pub fn begin<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        request: OperationRequest,
    ) -> Result<TypedMessage, RequesterEngineError<S::Error>> {
        if self.contains(request.operation_id) {
            return Err(RequesterEngineError::DuplicateLocalOperationId);
        }
        let mut operation =
            RequesterOperation::new(request).map_err(RequesterEngineError::InvalidLocalRequest)?;
        let message = operation.begin(store).map_err(map_requester_error)?;
        self.operations.push(operation);
        Ok(message)
    }

    /// Persist requester commit before releasing the exact commit message.
    ///
    /// # Errors
    /// [`RequesterEngineError`] on an unknown operation, an illegal state,
    /// or a persistence failure.
    pub fn commit<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
    ) -> Result<TypedMessage, RequesterEngineError<S::Error>> {
        let operation = self
            .operation_mut(operation_id)
            .ok_or(RequesterEngineError::UnknownLocalOperation)?;
        operation.commit(store).map_err(map_requester_error)
    }

    /// Persist local cancellation and return the exact message to release.
    ///
    /// # Errors
    /// [`RequesterEngineError`] on an unknown operation, an illegal state,
    /// or a persistence failure.
    pub fn cancel<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
        reason: Option<String>,
    ) -> Result<RequesterCancelAction, RequesterEngineError<S::Error>> {
        let operation = self
            .operation_mut(operation_id)
            .ok_or(RequesterEngineError::UnknownLocalOperation)?;
        operation.cancel(store, reason).map_err(map_requester_error)
    }

    /// Classify one authenticated inbound message without leaving sequencing
    /// decisions to the platform integration.
    ///
    /// # Errors
    /// [`RequesterEngineError`] on an authenticated protocol violation, a
    /// local invariant failure, or a persistence failure.
    pub fn receive<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        message: TypedMessage,
    ) -> Result<RequesterDispatch, RequesterEngineError<S::Error>> {
        if let TypedMessage::OperationStatus(report) = &message {
            return self.receive_status(store, *report);
        }
        if let TypedMessage::Error(error) = &message {
            return Ok(match *error {
                ProtocolErrorMessage::Busy => RequesterDispatch::PeerBusy,
                ProtocolErrorMessage::UnknownOperation(operation_id) => {
                    RequesterDispatch::PeerUnknownOperation(operation_id)
                }
            });
        }

        let Some(operation_id) = referenced_operation_id(&message) else {
            return Ok(RequesterDispatch::NotOperation(message));
        };
        let Some(index) = self.index(operation_id) else {
            return Ok(stale(operation_id));
        };
        if self.operations[index].record().state.is_terminal() {
            return Ok(stale(operation_id));
        }

        match message {
            TypedMessage::OperationPrepared(reference) => {
                self.operations[index]
                    .receive_prepared(store, reference)
                    .map_err(map_requester_error)?;
                Ok(RequesterDispatch::Prepared(operation_id))
            }
            TypedMessage::OperationResult(result) => {
                let action = self.operations[index]
                    .receive_result(store, result)
                    .map_err(map_requester_error)?;
                Ok(match action {
                    RequesterResultAction::SendAcknowledgment(message) => {
                        RequesterDispatch::SendResultAcknowledgment {
                            operation_id,
                            message,
                        }
                    }
                    RequesterResultAction::Terminal(state) => RequesterDispatch::Terminal {
                        operation_id,
                        state,
                    },
                })
            }
            TypedMessage::OperationCancel(cancellation) => {
                let state = self.operations[index]
                    .receive_cancel(store, &cancellation)
                    .map_err(map_requester_error)?;
                Ok(RequesterDispatch::CancellationReceived {
                    operation_id,
                    state,
                })
            }
            TypedMessage::OperationProgress(progress) => {
                let event = self.operations[index]
                    .receive_progress(&progress)
                    .map_err(map_requester_error)?;
                Ok(RequesterDispatch::Progress {
                    operation_id,
                    event,
                })
            }
            _ => Err(RequesterEngineError::AuthenticatedProtocolViolation(
                RequesterViolation::IllegalMessageForActiveOperation,
            )),
        }
    }

    /// Persist successful ack release before returning the result to the app.
    ///
    /// # Errors
    /// [`RequesterEngineError`] on an unknown operation, an illegal state,
    /// or a persistence failure.
    pub fn acknowledgment_released<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        operation_id: OperationId,
    ) -> Result<CardOperationResult, RequesterEngineError<S::Error>> {
        let operation = self
            .operation_mut(operation_id)
            .ok_or(RequesterEngineError::UnknownLocalOperation)?;
        operation
            .acknowledgment_sent(store)
            .map_err(map_requester_error)
    }

    /// Classify every operation when its authenticated session closes.
    ///
    /// # Errors
    /// [`RequesterEngineError`] on an unclassifiable state or a persistence
    /// failure.
    pub fn session_closed<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<Vec<(OperationId, OperationState)>, RequesterEngineError<S::Error>> {
        let mut classified = Vec::new();
        for operation in &mut self.operations {
            if operation.record().state.is_terminal() {
                continue;
            }
            let operation_id = operation.record().operation_id;
            let state = operation
                .session_closed(store)
                .map_err(map_requester_error)?;
            classified.push((operation_id, state));
        }
        Ok(classified)
    }

    /// Build a status query for either a live or recovered durable record.
    ///
    /// # Errors
    /// [`RequesterEngineError::UnknownLocalOperation`] when this engine does
    /// not hold the operation.
    pub fn status_query(
        &self,
        operation_id: OperationId,
    ) -> Result<TypedMessage, RequesterEngineError<core::convert::Infallible>> {
        if self.contains(operation_id) {
            Ok(TypedMessage::OperationStatusRequest(operation_id))
        } else {
            Err(RequesterEngineError::UnknownLocalOperation)
        }
    }

    fn receive_status<S: RequesterJournalStore>(
        &mut self,
        store: &mut S,
        report: StatusReport,
    ) -> Result<RequesterDispatch, RequesterEngineError<S::Error>> {
        let operation_id = report.operation_id;
        if let Some(operation) = self.operation_mut(operation_id) {
            operation
                .annotate_status(store, report)
                .map_err(map_requester_error)?;
        } else if let Some(record) = self
            .recovered
            .iter_mut()
            .find(|record| record.operation_id == operation_id)
        {
            if let Some(hash) = report.request_hash
                && hash != record.request_hash
            {
                return Err(RequesterEngineError::AuthenticatedProtocolViolation(
                    RequesterViolation::ReferenceMismatch,
                ));
            }
            record.reconciliation = Some(report);
            store
                .persist(record)
                .map_err(RequesterEngineError::Persistence)?;
        } else {
            return Ok(stale(operation_id));
        }
        Ok(RequesterDispatch::StatusAnnotated(operation_id))
    }

    fn operation_mut(&mut self, operation_id: OperationId) -> Option<&mut RequesterOperation> {
        let index = self.index(operation_id)?;
        self.operations.get_mut(index)
    }

    fn index(&self, operation_id: OperationId) -> Option<usize> {
        self.operations
            .iter()
            .position(|operation| operation.record().operation_id == operation_id)
    }

    fn contains(&self, operation_id: OperationId) -> bool {
        self.index(operation_id).is_some()
            || self
                .recovered
                .iter()
                .any(|record| record.operation_id == operation_id)
    }
}

/// Required caller action after dispatching an inbound operation message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequesterDispatch {
    /// Proxy is ready; the requester decides whether to commit.
    Prepared(OperationId),
    /// Release this acknowledgment for the completed result.
    SendResultAcknowledgment {
        /// Acknowledged operation.
        operation_id: OperationId,
        /// Exact acknowledgment to send.
        message: TypedMessage,
    },
    /// Operation reached the journaled terminal state.
    Terminal {
        /// Terminated operation.
        operation_id: OperationId,
        /// Journaled terminal state.
        state: OperationState,
    },
    /// Peer cancellation was journaled.
    CancellationReceived {
        /// Cancelled operation.
        operation_id: OperationId,
        /// Journaled terminal state.
        state: OperationState,
    },
    /// Authenticated status report was stored as a journal annotation.
    StatusAnnotated(OperationId),
    /// Advisory operation progress update reported by proxy.
    Progress {
        /// Active operation.
        operation_id: OperationId,
        /// Specific progress event.
        event: ProgressEvent,
    },
    /// Peer already serves a live session for this pairing.
    PeerBusy,
    /// Peer answered a stale reference; a normal race.
    PeerUnknownOperation(Option<OperationId>),
    /// Stale-reference race; answer without state change.
    IgnoredStale {
        /// Stale operation the peer referenced.
        operation_id: OperationId,
        /// Unknown-operation answer to send.
        response: TypedMessage,
    },
    /// Message is not an operation message; no operation effect.
    NotOperation(TypedMessage),
}

const fn stale(operation_id: OperationId) -> RequesterDispatch {
    RequesterDispatch::IgnoredStale {
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

fn map_requester_error<E>(error: RequesterError<E>) -> RequesterEngineError<E> {
    match error {
        RequesterError::Persistence(error) => RequesterEngineError::Persistence(error),
        RequesterError::Operation(_) => RequesterEngineError::AuthenticatedProtocolViolation(
            RequesterViolation::InvalidOperationMessage,
        ),
        RequesterError::WrongState(_) => RequesterEngineError::AuthenticatedProtocolViolation(
            RequesterViolation::IllegalOperationTransition,
        ),
        RequesterError::ReferenceMismatch => RequesterEngineError::AuthenticatedProtocolViolation(
            RequesterViolation::ReferenceMismatch,
        ),
        RequesterError::UnexpectedPreparedForSafeRead => {
            RequesterEngineError::AuthenticatedProtocolViolation(
                RequesterViolation::UnexpectedPreparedForSafeRead,
            )
        }
        RequesterError::UnknownOperationRace => RequesterEngineError::LocalRaceClassification,
        RequesterError::MissingResult => RequesterEngineError::LocalInvariantFailure,
    }
}

/// Authenticated protocol violation observed by the requester.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequesterViolation {
    /// Message is illegal for the active operation's state.
    IllegalMessageForActiveOperation,
    /// Operation message failed its typed validation.
    InvalidOperationMessage,
    /// Message demands a transition the machine does not define.
    IllegalOperationTransition,
    /// Echoed request hash differs from the journal.
    ReferenceMismatch,
    /// Prepared echo arrived for an action without prepare and commit.
    UnexpectedPreparedForSafeRead,
}

/// Requester operation-engine failure.
#[derive(Debug)]
pub enum RequesterEngineError<E> {
    /// Durable persistence failed; the message is not released.
    Persistence(E),
    /// Local request failed its typed validation.
    InvalidLocalRequest(CardOperationError),
    /// Local request reuses a known operation identifier.
    DuplicateLocalOperationId,
    /// Local call references an operation this engine does not hold.
    UnknownLocalOperation,
    /// Local reference resolved to a stale-reference race.
    LocalRaceClassification,
    /// Local durable state contradicts a machine invariant.
    LocalInvariantFailure,
    /// Authenticated peer traffic violated the protocol.
    AuthenticatedProtocolViolation(RequesterViolation),
}

impl<E: fmt::Debug> fmt::Display for RequesterEngineError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl<E: fmt::Debug> core::error::Error for RequesterEngineError<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CardOperation, OperationId, OperationProgressMessage, OperationReference, PairId,
        ProfileName, ProgressEvent, SessionId,
    };

    struct TestStore(Option<RequesterJournalRecord>);
    impl RequesterJournalStore for TestStore {
        type Error = ();
        fn persist(&mut self, record: &RequesterJournalRecord) -> Result<(), ()> {
            self.0 = Some(record.clone());
            Ok(())
        }
    }

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
    fn progress_updates_are_dispatched_without_changing_operation_state() {
        let mut engine = RequesterOperationEngine::new();
        let mut store = TestStore(None);
        let request = inspection_request();
        let op_id = request.operation_id;
        let request_hash = request.request_hash().expect("valid request hash");

        let _begin_msg = engine.begin(&mut store, request).expect("begin succeeds");
        assert_eq!(
            store.0.as_ref().expect("operation record").state,
            OperationState::Requested
        );

        let progress_msg = TypedMessage::OperationProgress(OperationProgressMessage {
            reference: OperationReference {
                operation_id: op_id,
                request_hash,
            },
            event: ProgressEvent::WaitingForCard,
        });

        let dispatch = engine
            .receive(&mut store, progress_msg)
            .expect("receive progress succeeds");

        assert_eq!(
            dispatch,
            RequesterDispatch::Progress {
                operation_id: op_id,
                event: ProgressEvent::WaitingForCard,
            }
        );

        assert_eq!(
            store.0.as_ref().expect("operation record").state,
            OperationState::Requested
        );
    }
}
