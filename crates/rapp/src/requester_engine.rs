//! Requester-side operations of one session (RAPP v26.10.22 section 8).

use core::fmt;
use std::collections::BTreeSet;

use super::{
    CardOperationError, CardOperationResult, CardStatusMessage, OperationId, OperationRequest,
    ProgressEvent, ProtocolErrorMessage, ResultError, ResultStatus, TypedMessage,
};

/// The requester's operations on one session: one live at a time, every
/// identifier used once. Nothing outlives the session; a requester that did
/// not receive a result starts a new operation (section 8.1 item 3).
#[derive(Debug, Default)]
pub struct RequesterOperationEngine {
    live: Option<OperationRequest>,
    used: BTreeSet<OperationId>,
}

impl RequesterOperationEngine {
    /// An engine with no operation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            live: None,
            used: BTreeSet::new(),
        }
    }

    /// Start an operation; the returned message is its `operation.request`.
    ///
    /// # Errors
    /// [`RequesterEngineError`] while another operation is live, on an
    /// identifier this session has used, or on an invalid request.
    pub fn begin(
        &mut self,
        request: OperationRequest,
    ) -> Result<TypedMessage, RequesterEngineError> {
        if self.live.is_some() {
            return Err(RequesterEngineError::LiveOperation);
        }
        if self.used.contains(&request.operation_id) {
            return Err(RequesterEngineError::DuplicateLocalOperationId);
        }
        request
            .validate()
            .map_err(RequesterEngineError::InvalidLocalRequest)?;
        self.used.insert(request.operation_id);
        self.live = Some(request.clone());
        Ok(TypedMessage::OperationRequest(request))
    }

    /// Stop waiting for the live operation; nothing travels. A result that
    /// arrives for it later is ignored.
    ///
    /// # Errors
    /// [`RequesterEngineError::UnknownLocalOperation`] when it is not live.
    pub fn cancel(&mut self, operation_id: OperationId) -> Result<(), RequesterEngineError> {
        if self.live_id() != Some(operation_id) {
            return Err(RequesterEngineError::UnknownLocalOperation);
        }
        self.live = None;
        Ok(())
    }

    /// Classify one authenticated inbound message.
    ///
    /// # Errors
    /// [`RequesterEngineError::AuthenticatedProtocolViolation`] when the
    /// custodian sends a message only a requester sends, or a result that
    /// does not answer the live request; the session closes.
    pub fn receive(
        &mut self,
        message: TypedMessage,
    ) -> Result<RequesterDispatch, RequesterEngineError> {
        match message {
            TypedMessage::CardStatus(status) => Ok(RequesterDispatch::CardStatus(status)),
            TypedMessage::Error(error) => Ok(self.receive_error(error)),
            TypedMessage::OperationProgress(progress) => {
                Ok(if self.live_id() == Some(progress.operation_id) {
                    RequesterDispatch::Progress {
                        operation_id: progress.operation_id,
                        event: progress.event,
                    }
                } else {
                    RequesterDispatch::Ignored(progress.operation_id)
                })
            }
            TypedMessage::OperationResult(result) => {
                let operation_id = result.operation_id;
                let Some(request) = self.live.take_if(|live| live.operation_id == operation_id)
                else {
                    return Ok(RequesterDispatch::Ignored(operation_id));
                };
                result
                    .validate_for(operation_id, &request.operation)
                    .map_err(|_| {
                        RequesterEngineError::AuthenticatedProtocolViolation(
                            RequesterViolation::InvalidResult,
                        )
                    })?;
                Ok(match (result.status, result.response, result.error) {
                    (ResultStatus::Completed, Some(response), None) => {
                        RequesterDispatch::Completed {
                            operation_id,
                            result: response.typed_for(&request.operation).map_err(|_| {
                                RequesterEngineError::AuthenticatedProtocolViolation(
                                    RequesterViolation::InvalidResult,
                                )
                            })?,
                        }
                    }
                    (status, None, Some(error)) => RequesterDispatch::Ended {
                        operation_id,
                        status,
                        error,
                    },
                    _ => {
                        return Err(RequesterEngineError::AuthenticatedProtocolViolation(
                            RequesterViolation::InvalidResult,
                        ));
                    }
                })
            }
            TypedMessage::OperationRequest(_) | TypedMessage::OperationRequestRefused(_) => {
                Err(RequesterEngineError::AuthenticatedProtocolViolation(
                    RequesterViolation::RequesterOnlyMessage,
                ))
            }
            other => Ok(RequesterDispatch::NotOperation(other)),
        }
    }

    /// The session closed: the live operation, if any, is lost with it.
    pub fn session_closed(&mut self) -> Option<OperationId> {
        self.used.clear();
        self.live.take().map(|request| request.operation_id)
    }

    fn receive_error(&mut self, error: ProtocolErrorMessage) -> RequesterDispatch {
        match error.operation_id {
            Some(operation_id) if self.live_id() == Some(operation_id) => {
                self.live = None;
                RequesterDispatch::Refused {
                    operation_id,
                    error: error.error,
                }
            }
            Some(operation_id) => RequesterDispatch::Ignored(operation_id),
            None => RequesterDispatch::PeerError(error.error),
        }
    }

    fn live_id(&self) -> Option<OperationId> {
        self.live.as_ref().map(|request| request.operation_id)
    }
}

/// What an inbound message means to the requester.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequesterDispatch {
    /// The custodian's card is present, with its fingerprint, or absent
    /// (section 8.4).
    CardStatus(CardStatusMessage),
    /// The live operation's state changed.
    Progress {
        /// The live operation.
        operation_id: OperationId,
        /// What changed.
        event: ProgressEvent,
    },
    /// The live operation completed.
    Completed {
        /// The operation.
        operation_id: OperationId,
        /// Its answer.
        result: CardOperationResult,
    },
    /// The live operation ended without completing.
    Ended {
        /// The operation.
        operation_id: OperationId,
        /// Rejected or cancelled.
        status: ResultStatus,
        /// Why.
        error: ResultError,
    },
    /// The custodian refused the request before admitting it (`busy`,
    /// `duplicate_operation`).
    Refused {
        /// The refused operation.
        operation_id: OperationId,
        /// Why.
        error: ResultError,
    },
    /// An `error` naming no operation.
    PeerError(ResultError),
    /// A message for an operation that is no longer live.
    Ignored(OperationId),
    /// Not an operation message.
    NotOperation(TypedMessage),
}

/// Authenticated protocol violation observed by the requester.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequesterViolation {
    /// The custodian sent a message only a requester sends.
    RequesterOnlyMessage,
    /// A result does not answer the live request.
    InvalidResult,
}

/// Requester operation-engine failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequesterEngineError {
    /// Another operation of the session is live.
    LiveOperation,
    /// The identifier was already used on this session.
    DuplicateLocalOperationId,
    /// The request failed its typed validation.
    InvalidLocalRequest(CardOperationError),
    /// The operation is not live.
    UnknownLocalOperation,
    /// Authenticated peer traffic violated the protocol; close the session.
    AuthenticatedProtocolViolation(RequesterViolation),
}

impl fmt::Display for RequesterEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for RequesterEngineError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CardInspection, CardOperation, OperationResultMessage, ProfileName, ProxyFailure};

    const START_MS: u64 = 1_000;
    const LIFETIME_MS: u64 = 5_000;

    fn inspection_request(byte: u8) -> OperationRequest {
        OperationRequest::reconstruct(
            OperationId::from_array([byte; 16]),
            ProfileName::CardStatus,
            START_MS,
            LIFETIME_MS,
            CardOperation::InspectCard,
        )
        .expect("registered card-status request")
    }

    #[test]
    fn one_operation_is_live_at_a_time() {
        let mut engine = RequesterOperationEngine::new();
        engine.begin(inspection_request(1)).expect("first");
        assert_eq!(
            engine.begin(inspection_request(2)),
            Err(RequesterEngineError::LiveOperation)
        );
    }

    #[test]
    fn a_completed_result_ends_the_operation() {
        let mut engine = RequesterOperationEngine::new();
        let request = inspection_request(1);
        engine.begin(request.clone()).expect("begin");
        let answer = CardOperationResult::Inspection(CardInspection {
            answer_to_reset: vec![1, 2, 3],
        });
        let dispatch = engine
            .receive(TypedMessage::OperationResult(
                OperationResultMessage::completed(request.operation_id, &answer),
            ))
            .expect("result");
        assert_eq!(
            dispatch,
            RequesterDispatch::Completed {
                operation_id: request.operation_id,
                result: answer,
            }
        );
        assert_eq!(
            engine.begin(request),
            Err(RequesterEngineError::DuplicateLocalOperationId)
        );
    }

    #[test]
    fn a_failure_result_ends_the_operation_with_its_error() {
        let mut engine = RequesterOperationEngine::new();
        let request = inspection_request(1);
        engine.begin(request.clone()).expect("begin");
        assert_eq!(
            engine
                .receive(TypedMessage::OperationResult(
                    OperationResultMessage::failure(request.operation_id, ProxyFailure::UserDenied)
                ))
                .expect("result"),
            RequesterDispatch::Ended {
                operation_id: request.operation_id,
                status: ResultStatus::Rejected,
                error: ResultError::UserCancelled,
            }
        );
        engine
            .begin(inspection_request(2))
            .expect("a new one may start");
    }

    #[test]
    fn busy_refuses_the_live_request() {
        let mut engine = RequesterOperationEngine::new();
        let request = inspection_request(1);
        engine.begin(request.clone()).expect("begin");
        assert_eq!(
            engine
                .receive(TypedMessage::Error(ProtocolErrorMessage::busy(
                    request.operation_id
                )))
                .expect("error"),
            RequesterDispatch::Refused {
                operation_id: request.operation_id,
                error: ResultError::Busy,
            }
        );
    }

    #[test]
    fn a_result_for_another_operation_is_ignored() {
        let mut engine = RequesterOperationEngine::new();
        engine.begin(inspection_request(1)).expect("begin");
        let other = OperationId::from_array([9; 16]);
        assert_eq!(
            engine
                .receive(TypedMessage::OperationResult(
                    OperationResultMessage::failure(other, ProxyFailure::UserDenied)
                ))
                .expect("result"),
            RequesterDispatch::Ignored(other)
        );
    }

    #[test]
    fn closing_the_session_loses_the_live_operation() {
        let mut engine = RequesterOperationEngine::new();
        let request = inspection_request(1);
        engine.begin(request.clone()).expect("begin");
        assert_eq!(engine.session_closed(), Some(request.operation_id));
        assert_eq!(engine.session_closed(), None);
    }
}
