//! Custodian-side operations of one session (RAPP v26.11.1 section 8).

use core::fmt;
use std::collections::BTreeSet;

use super::{
    AuthorizationStage, AuthorizationTransaction, AuthorizedCardCommand, AuthorizedSafeRead,
    CardOperationResult, CardStatusMessage, OperationId, OperationProgressMessage,
    OperationRequest, OperationResultMessage, PendingCardCommand, PrerequisitesOutcome,
    ProfileName, ProgressEvent, ProtocolErrorMessage, ProxyFailure, ResultStatus, TypedMessage,
    UserApproval,
};

/// Most operation identifiers one session remembers for the duplicate check
/// of RAPP v26.11.1 section 8.1 item 1. A local resource bound: one session
/// is one workstation, and a requester that starts more operations than this
/// on one session has its session closed.
pub const MAX_SEEN_OPERATION_IDS: usize = 4_096;

/// The operations of one authenticated session: one live at a time, and
/// every identifier used once; at most [`MAX_SEEN_OPERATION_IDS`] are
/// remembered. Nothing outlives the session.
#[derive(Debug)]
pub struct ProxyOperationEngine {
    granted_profiles: Vec<ProfileName>,
    live: Option<AuthorizationTransaction>,
    seen: BTreeSet<OperationId>,
}

impl ProxyOperationEngine {
    /// Create a dispatcher bound to the profiles the pairing granted.
    #[must_use]
    pub const fn new(granted_profiles: Vec<ProfileName>) -> Self {
        Self {
            granted_profiles,
            live: None,
            seen: BTreeSet::new(),
        }
    }

    /// Dispatch a typed authenticated peer message.
    ///
    /// # Errors
    /// [`ProxyEngineError::AuthenticatedProtocolViolation`] when the requester
    /// sends a message only a custodian sends, or more distinct operation
    /// identifiers than [`MAX_SEEN_OPERATION_IDS`]; the session closes.
    pub fn receive(&mut self, message: TypedMessage) -> Result<ProxyDispatch, ProxyEngineError> {
        match message {
            TypedMessage::OperationRequest(request) => self.receive_request(request),
            TypedMessage::OperationRequestRefused(refusal) => {
                if let Some(answer) = self.admission_refusal(refusal.operation_id)? {
                    return Ok(answer);
                }
                Ok(ProxyDispatch::Send(TypedMessage::OperationResult(
                    OperationResultMessage::rejection(
                        refusal.operation_id,
                        ResultStatus::Rejected,
                        refusal.error,
                    ),
                )))
            }
            TypedMessage::OperationResult(_)
            | TypedMessage::OperationProgress(_)
            | TypedMessage::CardStatus(_) => Err(ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::CustodianOnlyMessage,
            )),
            other => Ok(ProxyDispatch::NotOperation(other)),
        }
    }

    /// The operation has the card and its prerequisite reads are done. An
    /// action that needs the holder's authorization goes to consent; a read
    /// skips consent and runs (section 8.2 items 3 and 6). An operation whose
    /// deadline has passed is cancelled instead (section 8.1 item 2). `now_ms`
    /// is the continuous clock.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or an illegal transition.
    pub fn prerequisites_complete(
        &mut self,
        operation_id: OperationId,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<ProxyDispatch, ProxyEngineError> {
        let operation = self.live_mut(operation_id)?;
        if operation.stage() == AuthorizationStage::Requested
            && operation.is_expired(now_ms, maximum_lifetime_ms)
        {
            return self.finish_failure(operation_id, ProxyFailure::RequestExpired);
        }
        let outcome = operation
            .prerequisites_complete()
            .map_err(|_| ProxyEngineError::InvalidLocalTransition)?;
        Ok(match outcome {
            PrerequisitesOutcome::AwaitConsent => ProxyDispatch::AwaitConsent(operation_id),
            PrerequisitesOutcome::ExecuteSafeRead(read) => {
                ProxyDispatch::ExecuteSafeRead { operation_id, read }
            }
        })
    }

    /// Apply the holder's approval. An approval after the request's deadline
    /// cancels the operation instead and no card command exists (section 8.1
    /// item 2). `now_ms` is the continuous clock.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or an illegal transition.
    pub fn approve(
        &mut self,
        operation_id: OperationId,
        approval: UserApproval,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<ProxyDispatch, ProxyEngineError> {
        let operation = self.live_mut(operation_id)?;
        if operation.stage() == AuthorizationStage::AwaitingConsent
            && operation.is_expired(now_ms, maximum_lifetime_ms)
        {
            return self.finish_failure(operation_id, ProxyFailure::RequestExpired);
        }
        let command = operation
            .approve(approval, now_ms, maximum_lifetime_ms)
            .map_err(|_| ProxyEngineError::InvalidLocalTransition)?;
        Ok(ProxyDispatch::ExecuteCardCommand {
            operation_id,
            command,
        })
    }

    /// Cancel the live operation when its deadline has passed before the card
    /// was commanded, waiting in the queue or for consent (section 8.1 item
    /// 2); `None` when nothing is due.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an illegal transition.
    pub fn expire_due(
        &mut self,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<Option<ProxyDispatch>, ProxyEngineError> {
        let Some(operation) = &self.live else {
            return Ok(None);
        };
        let waiting = matches!(
            operation.stage(),
            AuthorizationStage::Requested | AuthorizationStage::AwaitingConsent
        );
        if !waiting || !operation.is_expired(now_ms, maximum_lifetime_ms) {
            return Ok(None);
        }
        let operation_id = operation.operation_id();
        self.finish_failure(operation_id, ProxyFailure::RequestExpired)
            .map(Some)
    }

    /// End the operation with its completed result.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or a result that does not
    /// answer it.
    pub fn finish_completed(
        &mut self,
        operation_id: OperationId,
        result: OperationResultMessage,
    ) -> Result<ProxyDispatch, ProxyEngineError> {
        self.live_mut(operation_id)?
            .finish_completed(&result)
            .map_err(|_| ProxyEngineError::InvalidLocalTransition)?;
        Ok(ProxyDispatch::Send(TypedMessage::OperationResult(result)))
    }

    /// End the operation with a result that did not complete.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or an operation that
    /// already has its result.
    pub fn finish_failure(
        &mut self,
        operation_id: OperationId,
        failure: ProxyFailure,
    ) -> Result<ProxyDispatch, ProxyEngineError> {
        let result = OperationResultMessage::failure(operation_id, failure);
        self.live_mut(operation_id)?
            .finish_failure(&result)
            .map_err(|_| ProxyEngineError::InvalidLocalTransition)?;
        Ok(ProxyDispatch::Send(TypedMessage::OperationResult(result)))
    }

    /// Record one batch signature as the card makes it.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or one that is not an
    /// executing batch.
    pub fn record_batch_signature(
        &mut self,
        operation_id: OperationId,
        signature: Vec<u8>,
    ) -> Result<(), ProxyEngineError> {
        self.live_mut(operation_id)?
            .record_batch_signature(signature)
            .map_err(|_| ProxyEngineError::InvalidLocalTransition)
    }

    /// Answer a batch once every document is signed, with exactly those
    /// signatures.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or a batch with documents
    /// left to sign.
    pub fn complete_batch(
        &mut self,
        operation_id: OperationId,
    ) -> Result<ProxyDispatch, ProxyEngineError> {
        let signatures = self.live_mut(operation_id)?.batch_signatures().to_vec();
        let result = OperationResultMessage::completed(
            operation_id,
            &CardOperationResult::Signatures(signatures),
        );
        self.finish_completed(operation_id, result)
    }

    /// The card-status notice for the session (section 8.4).
    #[must_use]
    pub const fn report_card_status(status: CardStatusMessage) -> TypedMessage {
        TypedMessage::CardStatus(status)
    }

    /// A progress message for the live operation.
    ///
    /// # Errors
    /// [`ProxyEngineError`] on an unknown operation or one that has its
    /// result.
    pub fn report_progress(
        &self,
        operation_id: OperationId,
        event: ProgressEvent,
    ) -> Result<TypedMessage, ProxyEngineError> {
        match &self.live {
            Some(operation) if operation.operation_id() == operation_id => {
                if operation.is_terminal() {
                    return Err(ProxyEngineError::InvalidLocalTransition);
                }
                Ok(TypedMessage::OperationProgress(OperationProgressMessage {
                    operation_id,
                    event,
                }))
            }
            _ => Err(ProxyEngineError::UnknownLocalOperation),
        }
    }

    /// The session closed: every operation of it is over (section 8.1 item
    /// 3). A card command in progress runs to the card's answer, which is
    /// discarded; anything else is dropped.
    pub fn session_closed(&mut self) -> Option<ProxySessionCloseAction> {
        self.seen.clear();
        let operation = self.live.take()?;
        let operation_id = operation.operation_id();
        match operation.stage() {
            AuthorizationStage::Terminal => None,
            AuthorizationStage::Executing | AuthorizationStage::ExecutingSafeRead => {
                Some(ProxySessionCloseAction::ContinueCardExchange(operation_id))
            }
            AuthorizationStage::Requested | AuthorizationStage::AwaitingConsent => {
                Some(ProxySessionCloseAction::Dropped(operation_id))
            }
        }
    }

    fn receive_request(
        &mut self,
        request: OperationRequest,
    ) -> Result<ProxyDispatch, ProxyEngineError> {
        let operation_id = request.operation_id;
        if let Some(answer) = self.admission_refusal(operation_id)? {
            return Ok(answer);
        }
        if !self.granted_profiles.contains(&request.profile) {
            return Ok(ProxyDispatch::Send(TypedMessage::OperationResult(
                OperationResultMessage::failure(operation_id, ProxyFailure::Unauthorized),
            )));
        }
        self.live = Some(AuthorizationTransaction::prepare(request));
        Ok(ProxyDispatch::InspectPrerequisites(operation_id))
    }

    /// The `error` that refuses a request before admission: an identifier
    /// the session has seen, or a second request while one is live
    /// (section 8.1 item 1). Every identifier counts as seen from here on,
    /// up to [`MAX_SEEN_OPERATION_IDS`]; a fresh identifier past that bound
    /// is a violation and the session closes.
    fn admission_refusal(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<ProxyDispatch>, ProxyEngineError> {
        if self.seen.contains(&operation_id) {
            return Ok(Some(ProxyDispatch::Send(TypedMessage::Error(
                ProtocolErrorMessage::duplicate(operation_id),
            ))));
        }
        if self.seen.len() >= MAX_SEEN_OPERATION_IDS {
            return Err(ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::OperationMemoryExhausted,
            ));
        }
        self.seen.insert(operation_id);
        if self
            .live
            .as_ref()
            .is_some_and(|operation| !operation.is_terminal())
        {
            return Ok(Some(ProxyDispatch::Send(TypedMessage::Error(
                ProtocolErrorMessage::busy(operation_id),
            ))));
        }
        Ok(None)
    }

    fn live_mut(
        &mut self,
        operation_id: OperationId,
    ) -> Result<&mut AuthorizationTransaction, ProxyEngineError> {
        self.live
            .as_mut()
            .filter(|operation| operation.operation_id() == operation_id)
            .ok_or(ProxyEngineError::UnknownLocalOperation)
    }
}

/// Bounded step the custodian adapter executes next.
#[derive(Debug)]
pub enum ProxyDispatch {
    /// Take the operation's turn on the card and perform the reads that
    /// precede the PIN.
    InspectPrerequisites(OperationId),
    /// Take the PIN: ask the holder when the custodian does not hold it.
    AwaitConsent(OperationId),
    /// Execute the read; no private key, no PIN.
    ExecuteSafeRead {
        /// Operation the read belongs to.
        operation_id: OperationId,
        /// The read.
        read: AuthorizedSafeRead,
    },
    /// Execute the one card command.
    ExecuteCardCommand {
        /// Operation the command belongs to.
        operation_id: OperationId,
        /// The one-shot command.
        command: PendingCardCommand<AuthorizedCardCommand>,
    },
    /// Send this message on the session.
    Send(TypedMessage),
    /// Not an operation message.
    NotOperation(TypedMessage),
}

/// What happens to the live operation when its session closes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxySessionCloseAction {
    /// The card was not commanded; the operation is dropped.
    Dropped(OperationId),
    /// The card command runs to the card's answer, which is discarded.
    ContinueCardExchange(OperationId),
}

/// Authenticated protocol violation observed by the custodian.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyViolation {
    /// The requester sent a message only a custodian sends.
    CustodianOnlyMessage,
    /// The requester sent more distinct operation identifiers on one session
    /// than [`MAX_SEEN_OPERATION_IDS`].
    OperationMemoryExhausted,
}

/// Custodian operation-engine failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyEngineError {
    /// Local call is illegal from the operation's current stage.
    InvalidLocalTransition,
    /// Local call names an operation this session does not hold.
    UnknownLocalOperation,
    /// Authenticated peer traffic violated the protocol; close the session.
    AuthenticatedProtocolViolation(ProxyViolation),
}

impl fmt::Display for ProxyEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for ProxyEngineError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CardOperation, CardPresence, CardReader, OPERATION_ID_SIZE, OperationRequestRefusal,
        ResultError,
    };

    const START_MS: u64 = 1_000;
    const LIFETIME_MS: u64 = 5_000;
    const MAXIMUM_LIFETIME_MS: u64 = 300_000;

    fn inspection_request(byte: u8) -> OperationRequest {
        inspection_request_for(OperationId::from_array([byte; 16]))
    }

    fn inspection_request_for(operation_id: OperationId) -> OperationRequest {
        OperationRequest::reconstruct(
            operation_id,
            ProfileName::CardStatus,
            START_MS,
            LIFETIME_MS,
            CardOperation::InspectCard,
        )
        .expect("registered card-status request")
    }

    /// The `index`-th of a run of distinct identifiers.
    fn numbered_operation_id(index: usize) -> OperationId {
        let mut bytes = [0; OPERATION_ID_SIZE];
        bytes[..size_of::<usize>()].copy_from_slice(&index.to_be_bytes());
        OperationId::from_array(bytes)
    }

    /// An engine that has refused `MAX_SEEN_OPERATION_IDS` distinct requests
    /// as unauthorized, so its memory of identifiers is full.
    fn engine_with_full_memory() -> ProxyOperationEngine {
        let mut engine = ProxyOperationEngine::new(Vec::new());
        for index in 0..MAX_SEEN_OPERATION_IDS {
            let result = sent_result(
                engine
                    .receive(TypedMessage::OperationRequest(inspection_request_for(
                        numbered_operation_id(index),
                    )))
                    .expect("refused, not a violation"),
            );
            assert_eq!(result.error, Some(ResultError::Unauthorized));
        }
        engine
    }

    fn sent_error(dispatch: ProxyDispatch) -> ProtocolErrorMessage {
        match dispatch {
            ProxyDispatch::Send(TypedMessage::Error(error)) => error,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    fn sent_result(dispatch: ProxyDispatch) -> OperationResultMessage {
        match dispatch {
            ProxyDispatch::Send(TypedMessage::OperationResult(result)) => result,
            other => panic!("expected a result, got {other:?}"),
        }
    }

    #[test]
    fn an_ungranted_profile_is_answered_unauthorized() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::Authentication]);
        let request = inspection_request(1);
        let result = sent_result(
            engine
                .receive(TypedMessage::OperationRequest(request))
                .expect("dispatch"),
        );
        assert_eq!(result.error, Some(ResultError::Unauthorized));
    }

    #[test]
    fn a_second_request_while_one_is_live_is_busy() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        assert!(matches!(
            engine.receive(TypedMessage::OperationRequest(inspection_request(1))),
            Ok(ProxyDispatch::InspectPrerequisites(_))
        ));
        let second = inspection_request(2);
        assert_eq!(
            sent_error(
                engine
                    .receive(TypedMessage::OperationRequest(second.clone()))
                    .expect("dispatch")
            ),
            ProtocolErrorMessage::busy(second.operation_id)
        );
    }

    #[test]
    fn an_identifier_is_used_once_per_session() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let request = inspection_request(1);
        engine
            .receive(TypedMessage::OperationRequest(request.clone()))
            .expect("admitted");
        engine
            .finish_failure(request.operation_id, ProxyFailure::UserDenied)
            .expect("ended");
        assert_eq!(
            sent_error(
                engine
                    .receive(TypedMessage::OperationRequest(request.clone()))
                    .expect("dispatch")
            ),
            ProtocolErrorMessage::duplicate(request.operation_id)
        );
    }

    #[test]
    fn the_seen_set_is_bounded() {
        let mut engine = engine_with_full_memory();
        assert_eq!(
            engine
                .receive(TypedMessage::OperationRequest(inspection_request_for(
                    numbered_operation_id(MAX_SEEN_OPERATION_IDS),
                )))
                .expect_err("violation"),
            ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::OperationMemoryExhausted
            )
        );
    }

    #[test]
    fn a_refusal_relay_past_the_bound_is_a_violation() {
        let mut engine = engine_with_full_memory();
        assert_eq!(
            engine
                .receive(TypedMessage::OperationRequestRefused(
                    OperationRequestRefusal {
                        operation_id: numbered_operation_id(MAX_SEEN_OPERATION_IDS),
                        error: ResultError::InvalidLifetime,
                    },
                ))
                .expect_err("violation"),
            ProxyEngineError::AuthenticatedProtocolViolation(
                ProxyViolation::OperationMemoryExhausted
            )
        );
    }

    #[test]
    fn a_duplicate_is_still_reported_at_the_bound() {
        let mut engine = engine_with_full_memory();
        let seen = numbered_operation_id(MAX_SEEN_OPERATION_IDS - 1);
        assert_eq!(
            sent_error(
                engine
                    .receive(TypedMessage::OperationRequest(inspection_request_for(seen)))
                    .expect("dispatch")
            ),
            ProtocolErrorMessage::duplicate(seen)
        );
    }

    #[test]
    fn session_close_resets_the_seen_bound() {
        let mut engine = engine_with_full_memory();
        assert_eq!(engine.session_closed(), None);
        let result = sent_result(
            engine
                .receive(TypedMessage::OperationRequest(inspection_request_for(
                    numbered_operation_id(MAX_SEEN_OPERATION_IDS),
                )))
                .expect("admitted to the duplicate check"),
        );
        assert_eq!(result.error, Some(ResultError::Unauthorized));
    }

    #[test]
    fn a_refused_request_is_answered_with_its_error() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let operation_id = OperationId::from_array([3; 16]);
        let result = sent_result(
            engine
                .receive(TypedMessage::OperationRequestRefused(
                    OperationRequestRefusal {
                        operation_id,
                        error: ResultError::InvalidLifetime,
                    },
                ))
                .expect("dispatch"),
        );
        assert_eq!(result.status, ResultStatus::Rejected);
        assert_eq!(result.error, Some(ResultError::InvalidLifetime));
    }

    #[test]
    fn a_read_skips_consent() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let request = inspection_request(1);
        let operation_id = request.operation_id;
        engine
            .receive(TypedMessage::OperationRequest(request.clone()))
            .expect("admitted");
        let ProxyDispatch::ExecuteSafeRead { read, .. } = engine
            .prerequisites_complete(operation_id, START_MS, MAXIMUM_LIFETIME_MS)
            .expect("the read has the card")
        else {
            panic!("a read runs without consent");
        };
        assert_eq!(read.operation, request.operation);
        assert!(
            engine
                .approve(
                    operation_id,
                    UserApproval::for_request(&request, START_MS),
                    START_MS,
                    MAXIMUM_LIFETIME_MS,
                )
                .is_err(),
            "a read has no consent to approve"
        );
    }

    #[test]
    fn an_operation_that_gets_the_card_after_its_deadline_is_cancelled() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let request = inspection_request(1);
        engine
            .receive(TypedMessage::OperationRequest(request.clone()))
            .expect("admitted");
        let late = START_MS + LIFETIME_MS + 1;
        let result = sent_result(
            engine
                .prerequisites_complete(request.operation_id, late, MAXIMUM_LIFETIME_MS)
                .expect("dispatch"),
        );
        assert_eq!(result.status, ResultStatus::Cancelled);
        assert_eq!(result.error, Some(ResultError::OperationExpired));
    }

    #[test]
    fn a_waiting_operation_expires_without_an_approval() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        engine
            .receive(TypedMessage::OperationRequest(inspection_request(1)))
            .expect("admitted");
        assert!(
            engine
                .expire_due(START_MS + LIFETIME_MS, MAXIMUM_LIFETIME_MS)
                .expect("poll")
                .is_none()
        );
        let result = sent_result(
            engine
                .expire_due(START_MS + LIFETIME_MS + 1, MAXIMUM_LIFETIME_MS)
                .expect("poll")
                .expect("due"),
        );
        assert_eq!(result.error, Some(ResultError::OperationExpired));
    }

    #[test]
    fn a_requester_sending_custodian_messages_closes_the_session() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        assert_eq!(
            engine
                .receive(TypedMessage::CardStatus(CardStatusMessage {
                    card: CardPresence::Absent,
                    reader: CardReader::Absent,
                }))
                .expect_err("violation"),
            ProxyEngineError::AuthenticatedProtocolViolation(ProxyViolation::CustodianOnlyMessage)
        );
    }

    #[test]
    fn closing_the_session_ends_every_operation() {
        let mut engine = ProxyOperationEngine::new(vec![ProfileName::CardStatus]);
        let request = inspection_request(1);
        engine
            .receive(TypedMessage::OperationRequest(request.clone()))
            .expect("admitted");
        assert_eq!(
            engine.session_closed(),
            Some(ProxySessionCloseAction::Dropped(request.operation_id))
        );
        assert_eq!(engine.session_closed(), None);
    }
}
