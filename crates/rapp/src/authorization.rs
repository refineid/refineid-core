//! Hash-bound user approval and at-most-once card-command authorization.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    CancelMessage, CardOperation, CardOperationError, JournalError, JournalStore, OperationId,
    OperationJournal, OperationRequest, OperationResultMessage, OperationState, PendingCardCommand,
    RequestHash, ResultJournalStore, ResultStatus, WireValue,
};

/// Explicit local user approval of one exact operation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserApproval {
    operation_id: OperationId,
    request_hash: RequestHash,
    approved_at_ms: u64,
}

impl UserApproval {
    /// Binds approval to the complete deterministic request hash displayed by
    /// the authorizer UI.
    ///
    /// # Errors
    /// [`CardOperationError`] when the request hash cannot be computed.
    pub fn for_request(
        request: &OperationRequest,
        approved_at_ms: u64,
    ) -> Result<Self, CardOperationError> {
        Ok(Self {
            operation_id: request.operation_id,
            request_hash: request.request_hash()?,
            approved_at_ms,
        })
    }

    /// Time at which the local authorizer confirmed the request.
    #[must_use]
    pub const fn approved_at_ms(&self) -> u64 {
        self.approved_at_ms
    }
}

/// Closed command handed to the card integration after durable commit.
///
/// It carries no CAN, PIN, PUK, or raw APDU. The authorizer obtains required
/// credentials locally and the platform card adapter maps this semantic
/// operation to the reviewed card protocol implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCardCommand {
    /// Exact semantic operation approved by the user.
    pub operation: CardOperation,
}

/// Registered non-consequential read that never consumes the credential
/// command journal or retry budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedSafeRead {
    /// Exact semantic read approved under its profile.
    pub operation: CardOperation,
}

/// One operation from request validation through durable terminal state.
#[derive(Debug)]
pub struct AuthorizationTransaction {
    request: OperationRequest,
    request_hash: RequestHash,
    journal: OperationJournal,
    stage: AuthorizationStage,
    retained_result: Option<OperationResultMessage>,
}

impl AuthorizationTransaction {
    /// Prepares an operation without persisting or transmitting anything.
    ///
    /// # Errors
    /// [`CardOperationError`] when the request hash cannot be computed.
    pub fn prepare(request: OperationRequest) -> Result<Self, CardOperationError> {
        let request_hash = request.request_hash()?;
        let journal = OperationJournal::prepared(
            request.pair_id,
            request.session_id,
            request.operation_id,
            request_hash,
        );
        Ok(Self {
            request,
            request_hash,
            journal,
            stage: AuthorizationStage::Requested,
            retained_result: None,
        })
    }

    /// Exact request presented for local consent.
    #[must_use]
    pub const fn request(&self) -> &OperationRequest {
        &self.request
    }

    /// Durable journal view for crash recovery and result reporting.
    #[must_use]
    pub const fn journal(&self) -> &OperationJournal {
        &self.journal
    }

    /// Exact operation/hash binding used by every subsequent message.
    #[must_use]
    pub const fn reference(&self) -> OperationReference {
        OperationReference {
            operation_id: self.request.operation_id,
            request_hash: self.request_hash,
        }
    }

    /// Protocol-visible state. Before durable commit the transaction stage is
    /// authoritative; after result creation the journal is authoritative.
    #[must_use]
    pub const fn operation_state(&self) -> OperationState {
        match self.stage {
            AuthorizationStage::Requested => OperationState::Requested,
            AuthorizationStage::AwaitingConsent | AuthorizationStage::ExecutingSafeRead => {
                OperationState::AwaitingConsent
            }
            AuthorizationStage::Prepared => OperationState::Prepared,
            AuthorizationStage::Committed => OperationState::Committed,
            AuthorizationStage::Executing => OperationState::Executing,
            AuthorizationStage::ResultPending => OperationState::ResultPending,
            AuthorizationStage::Terminal => self.journal.record().state,
        }
    }

    /// Current protocol phase.
    #[must_use]
    pub const fn stage(&self) -> AuthorizationStage {
        self.stage
    }

    /// Records completion of the profile's bounded, non-consequential card
    /// reads. Consent must not be requested before this point.
    ///
    /// # Errors
    /// [`AuthorizationError::WrongStage`] outside the requested stage.
    pub fn prerequisites_complete(&mut self) -> Result<(), AuthorizationError<()>> {
        if self.stage != AuthorizationStage::Requested {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        self.stage = AuthorizationStage::AwaitingConsent;
        Ok(())
    }

    /// Accepts exact local consent and makes `operation.prepared` available.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a wrong stage, an approval that does not
    /// cover the exact request, or an expired validity interval.
    pub fn approve(
        &mut self,
        approval: UserApproval,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<ApprovalOutcome, AuthorizationError<()>> {
        if self.stage != AuthorizationStage::AwaitingConsent {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        self.validate_approval(approval, now_ms, maximum_lifetime_ms)?;
        if self.request.operation.is_consequential() {
            self.stage = AuthorizationStage::Prepared;
            Ok(ApprovalOutcome::Prepared(OperationReference {
                operation_id: self.request.operation_id,
                request_hash: self.request_hash,
            }))
        } else {
            self.stage = AuthorizationStage::ExecutingSafeRead;
            Ok(ApprovalOutcome::ExecuteSafeRead(AuthorizedSafeRead {
                operation: self.request.operation.clone(),
            }))
        }
    }

    /// Persists the point of no return only after validating exact approval,
    /// pair/session binding, and expiry.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a wrong stage, a commit-echo mismatch,
    /// expiry, or a journal failure.
    pub fn commit<S: JournalStore>(
        &mut self,
        store: &mut S,
        requester_commit: OperationReference,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<(), AuthorizationError<S::Error>> {
        if self.stage != AuthorizationStage::Prepared {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        if requester_commit.operation_id != self.request.operation_id
            || requester_commit.request_hash != self.request_hash
        {
            return Err(AuthorizationError::CommitMismatch);
        }
        if now_ms
            > self
                .request
                .local_deadline_ms(maximum_lifetime_ms)
                .map_err(|_| AuthorizationError::Expired)?
        {
            return Err(AuthorizationError::Expired);
        }
        self.journal
            .commit(store, self.request_hash)
            .map_err(AuthorizationError::Journal)?;
        self.stage = AuthorizationStage::Committed;
        Ok(())
    }

    /// Atomically records transmission number one and returns the only value a
    /// card adapter is allowed to execute.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a wrong stage or a journal failure.
    pub fn begin_card_command<S: JournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<PendingCardCommand<AuthorizedCardCommand>, AuthorizationError<S::Error>> {
        if self.stage != AuthorizationStage::Committed {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        let command = AuthorizedCardCommand {
            operation: self.request.operation.clone(),
        };
        let pending = self
            .journal
            .begin_card_command(store, command)
            .map_err(|(error, _command)| AuthorizationError::Journal(error))?;
        self.stage = AuthorizationStage::Executing;
        Ok(pending)
    }

    /// Persists an unambiguous terminal result after the single card exchange.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a wrong stage or a journal failure.
    pub fn finish<S: JournalStore>(
        &mut self,
        store: &mut S,
        terminal_state: OperationState,
    ) -> Result<(), AuthorizationError<S::Error>> {
        if self.stage != AuthorizationStage::Executing {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        self.journal
            .finish(store, terminal_state)
            .map_err(AuthorizationError::Journal)?;
        self.stage = AuthorizationStage::Terminal;
        Ok(())
    }

    /// Validate and persist a stable non-success result from any legal
    /// pre-result stage. No arbitrary exception text enters the protocol.
    ///
    /// # Errors
    /// [`AuthorizationError`] on an invalid result, a wrong stage, or a
    /// journal failure.
    pub fn finish_failure_result<S: JournalStore>(
        &mut self,
        store: &mut S,
        result: &OperationResultMessage,
    ) -> Result<(), AuthorizationError<S::Error>> {
        let reference = OperationReference {
            operation_id: self.request.operation_id,
            request_hash: self.request_hash,
        };
        if result.status == ResultStatus::Completed {
            return Err(AuthorizationError::InvalidResult);
        }
        result
            .validate_for(reference, &self.request.operation)
            .map_err(|_| AuthorizationError::InvalidResult)?;
        let terminal_state =
            failure_state(result.status).ok_or(AuthorizationError::InvalidResult)?;
        match self.stage {
            AuthorizationStage::Requested
            | AuthorizationStage::AwaitingConsent
            | AuthorizationStage::Prepared
            | AuthorizationStage::ExecutingSafeRead => self
                .journal
                .finish_safe_read_failure(store, terminal_state)
                .map_err(AuthorizationError::Journal)?,
            AuthorizationStage::Committed if terminal_state == OperationState::Cancelled => self
                .journal
                .cancel_committed_before_transmission(store)
                .map_err(AuthorizationError::Journal)?,
            AuthorizationStage::Executing => self
                .journal
                .finish(store, terminal_state)
                .map_err(AuthorizationError::Journal)?,
            stage => return Err(AuthorizationError::WrongStage(stage)),
        }
        self.stage = AuthorizationStage::Terminal;
        Ok(())
    }

    /// Apply an exact cancellation under the durable commit boundary.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a reference mismatch, a wrong stage, or a
    /// journal failure.
    pub fn receive_cancel<S: JournalStore>(
        &mut self,
        store: &mut S,
        cancellation: &CancelMessage,
        transmission_proven_not_started: bool,
    ) -> Result<ProxyCancelOutcome, AuthorizationError<S::Error>> {
        if cancellation.reference.operation_id != self.request.operation_id
            || cancellation.reference.request_hash != self.request_hash
        {
            return Err(AuthorizationError::CommitMismatch);
        }
        match self.stage {
            AuthorizationStage::Requested
            | AuthorizationStage::AwaitingConsent
            | AuthorizationStage::Prepared
            | AuthorizationStage::ExecutingSafeRead => {
                self.journal
                    .finish_safe_read_failure(store, OperationState::Cancelled)
                    .map_err(AuthorizationError::Journal)?;
                self.stage = AuthorizationStage::Terminal;
                Ok(ProxyCancelOutcome::Cancelled)
            }
            AuthorizationStage::Committed if transmission_proven_not_started => {
                self.journal
                    .cancel_committed_before_transmission(store)
                    .map_err(AuthorizationError::Journal)?;
                self.stage = AuthorizationStage::Terminal;
                Ok(ProxyCancelOutcome::Cancelled)
            }
            AuthorizationStage::Committed
            | AuthorizationStage::Executing
            | AuthorizationStage::ResultPending => Ok(ProxyCancelOutcome::Advisory),
            stage @ AuthorizationStage::Terminal => Err(AuthorizationError::WrongStage(stage)),
        }
    }

    /// Atomically retain a completed result before it can be sent. This covers
    /// both consequential commands and registered safe reads.
    ///
    /// # Errors
    /// [`AuthorizationError`] on an invalid result, a wrong stage, or a
    /// journal failure.
    pub fn finish_completed<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        result: OperationResultMessage,
    ) -> Result<(), AuthorizationError<S::Error>> {
        let reference = OperationReference {
            operation_id: self.request.operation_id,
            request_hash: self.request_hash,
        };
        if result.status != ResultStatus::Completed {
            return Err(AuthorizationError::InvalidResult);
        }
        result
            .validate_for(reference, &self.request.operation)
            .map_err(|_| AuthorizationError::InvalidResult)?;
        match self.stage {
            AuthorizationStage::Executing => self
                .journal
                .finish_completed(store, &result)
                .map_err(AuthorizationError::Journal)?,
            AuthorizationStage::ExecutingSafeRead => self
                .journal
                .finish_safe_read_completed(store, &result)
                .map_err(AuthorizationError::Journal)?,
            stage => return Err(AuthorizationError::WrongStage(stage)),
        }
        self.retained_result = Some(result);
        self.stage = AuthorizationStage::ResultPending;
        Ok(())
    }

    /// Persist a non-success registered safe-read result.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a wrong stage or a journal failure.
    pub fn finish_safe_read_failure<S: JournalStore>(
        &mut self,
        store: &mut S,
        terminal_state: OperationState,
    ) -> Result<(), AuthorizationError<S::Error>> {
        if self.stage != AuthorizationStage::ExecutingSafeRead {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        self.journal
            .finish_safe_read_failure(store, terminal_state)
            .map_err(AuthorizationError::Journal)?;
        self.stage = AuthorizationStage::Terminal;
        Ok(())
    }

    /// Exact retained result, available only while acknowledgment is pending.
    #[must_use]
    pub const fn retained_result(&self) -> Option<&OperationResultMessage> {
        self.retained_result.as_ref()
    }

    /// Atomically persist acknowledgment before erasing the retained body.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a wrong stage, an acknowledgment that does
    /// not echo the reference, or a journal failure.
    pub fn acknowledge_result<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        acknowledgment: OperationReference,
    ) -> Result<(), AuthorizationError<S::Error>> {
        if self.stage != AuthorizationStage::ResultPending {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        if acknowledgment.operation_id != self.request.operation_id
            || acknowledgment.request_hash != self.request_hash
        {
            return Err(AuthorizationError::CommitMismatch);
        }
        self.journal
            .acknowledge_result(store)
            .map_err(AuthorizationError::Journal)?;
        self.retained_result = None;
        self.stage = AuthorizationStage::Terminal;
        Ok(())
    }

    /// Session loss after result send retains the encrypted result and forbids
    /// automatic command or result replay.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a wrong stage or a journal failure.
    pub fn delivery_became_uncertain<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<(), AuthorizationError<S::Error>> {
        if self.stage != AuthorizationStage::ResultPending {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        self.journal
            .mark_delivery_uncertain(store)
            .map_err(AuthorizationError::Journal)?;
        self.stage = AuthorizationStage::Terminal;
        Ok(())
    }

    /// Converts a committed/executing record after process recovery to an
    /// ambiguous terminal result. It never offers a retransmission.
    ///
    /// # Errors
    /// [`AuthorizationError`] on an illegal journal state or a journal
    /// failure.
    pub fn recover_after_crash<S: JournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<(), AuthorizationError<S::Error>> {
        self.journal
            .recover_after_crash(store)
            .map_err(AuthorizationError::Journal)?;
        self.stage = AuthorizationStage::Terminal;
        Ok(())
    }

    fn validate_approval(
        &self,
        approval: UserApproval,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<(), AuthorizationError<()>> {
        if approval.operation_id != self.request.operation_id
            || approval.request_hash != self.request_hash
        {
            return Err(AuthorizationError::ApprovalMismatch);
        }
        let deadline = self
            .request
            .local_deadline_ms(maximum_lifetime_ms)
            .map_err(|_| AuthorizationError::Expired)?;
        if approval.approved_at_ms < self.request.local_start_ms
            || approval.approved_at_ms > deadline
            || now_ms > deadline
        {
            return Err(AuthorizationError::Expired);
        }
        Ok(())
    }
}

/// Protocol phase enforced by `AuthorizationTransaction`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationStage {
    /// Request was validated; safe reads have not completed.
    Requested,
    /// Safe reads completed and local consent may be requested.
    AwaitingConsent,
    /// Local user consented; waiting for requester commit.
    Prepared,
    /// Registered non-consequential read is executing without prepare/commit.
    ExecutingSafeRead,
    /// Commit is durable; no physical transmission has started.
    Committed,
    /// Exactly one physical command has been handed to the card adapter.
    Executing,
    /// Completed result is durably retained until exact acknowledgment.
    ResultPending,
    /// Durable terminal result.
    Terminal,
}

/// Result of local user approval based on profile consequence classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalOutcome {
    /// Send `operation.prepared` and wait for the exact requester commit.
    Prepared(OperationReference),
    /// Execute this bounded read and answer directly with a result.
    ExecuteSafeRead(AuthorizedSafeRead),
}

/// Proxy cancellation classification at the durable commit boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyCancelOutcome {
    /// Zero transmissions were proven; the operation is cancelled.
    Cancelled,
    /// Commit passed; the cancel is recorded and the operation continues.
    Advisory,
}

const fn failure_state(status: ResultStatus) -> Option<OperationState> {
    match status {
        ResultStatus::Completed => None,
        ResultStatus::Denied => Some(OperationState::Denied),
        ResultStatus::Cancelled => Some(OperationState::Cancelled),
        ResultStatus::Rejected => Some(OperationState::Rejected),
        ResultStatus::CredentialRejected => Some(OperationState::CredentialRejected),
        ResultStatus::Ambiguous => Some(OperationState::Ambiguous),
    }
}

/// Exact operation identifier and request-hash echo used by prepare, commit,
/// cancel, result acknowledgment, and status messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationReference {
    /// Semantic operation identifier.
    pub operation_id: OperationId,
    /// Hash of the complete typed request.
    pub request_hash: RequestHash,
}

impl OperationReference {
    /// Encode the common two-field body.
    #[must_use]
    pub fn to_wire_body(self) -> BTreeMap<String, WireValue> {
        let mut body = BTreeMap::new();
        body.insert(
            "operation_id".into(),
            WireValue::Bytes(self.operation_id.as_bytes().to_vec()),
        );
        body.insert(
            "request_hash".into(),
            WireValue::Bytes(self.request_hash.as_bytes().to_vec()),
        );
        body
    }

    /// Decode the common body after envelope schema validation.
    ///
    /// # Errors
    /// [`CardOperationError`] on a missing, mistyped, or extra field.
    pub fn from_wire_body(
        mut body: BTreeMap<String, WireValue>,
    ) -> Result<Self, CardOperationError> {
        let operation_id = match body.remove("operation_id") {
            Some(WireValue::Bytes(value)) => OperationId::reconstruct(&value)
                .map_err(|_| CardOperationError::InvalidIdentifier)?,
            _ => return Err(CardOperationError::InvalidField("operation_id")),
        };
        let request_hash = match body.remove("request_hash") {
            Some(WireValue::Bytes(value)) => RequestHash::reconstruct(&value)
                .map_err(|_| CardOperationError::InvalidIdentifier)?,
            _ => return Err(CardOperationError::InvalidField("request_hash")),
        };
        if !body.is_empty() {
            return Err(CardOperationError::UnexpectedField);
        }
        Ok(Self {
            operation_id,
            request_hash,
        })
    }
}

/// Advisory progress event during credential operation processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressEvent {
    /// Proxy is waiting for card presentation.
    WaitingForCard,
    /// Card presentation wait has ended (card presented or removed).
    CardWaitEnded,
    /// Forward-compatible unknown progress event.
    Unknown,
}

impl ProgressEvent {
    /// Wire discriminant name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WaitingForCard => "waiting_for_card",
            Self::CardWaitEnded => "card_wait_ended",
            Self::Unknown => "unknown",
        }
    }

    /// Parse wire discriminant name. Unknown event strings parse as [`Self::Unknown`].
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "waiting_for_card" => Self::WaitingForCard,
            "card_wait_ended" => Self::CardWaitEnded,
            _ => Self::Unknown,
        }
    }
}

/// Advisory operation progress update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationProgressMessage {
    /// Operation identifier and request-hash echo.
    pub reference: OperationReference,
    /// Specific progress event.
    pub event: ProgressEvent,
}

impl OperationProgressMessage {
    /// Encode the wire body.
    #[must_use]
    pub fn to_wire_body(self) -> BTreeMap<String, WireValue> {
        let mut body = self.reference.to_wire_body();
        body.insert("event".into(), WireValue::Text(self.event.as_str().into()));
        body
    }

    /// Decode the wire body after envelope schema validation.
    ///
    /// # Errors
    /// [`CardOperationError`] on a missing, mistyped, or extra field.
    pub fn from_wire_body(
        mut body: BTreeMap<String, WireValue>,
    ) -> Result<Self, CardOperationError> {
        let event = match body.remove("event") {
            Some(WireValue::Text(value)) => ProgressEvent::parse(&value),
            _ => return Err(CardOperationError::InvalidField("event")),
        };
        let reference = OperationReference::from_wire_body(body)?;
        Ok(Self { reference, event })
    }
}

/// Authorization transaction failure.
#[derive(Debug)]
pub enum AuthorizationError<E> {
    /// Approval did not cover the exact request.
    ApprovalMismatch,
    /// Requester commit did not echo the prepared operation and hash.
    CommitMismatch,
    /// Request or approval was outside its validity interval.
    Expired,
    /// Method was called outside the required protocol phase.
    WrongStage(AuthorizationStage),
    /// Result status, hash, or typed body did not match the authorized request.
    InvalidResult,
    /// Durable at-most-once journal failure.
    Journal(JournalError<E>),
}

impl<E: fmt::Debug> fmt::Display for AuthorizationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl<E: fmt::Debug> core::error::Error for AuthorizationError<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OperationId, RequestHash};

    #[test]
    fn progress_event_round_trip() {
        assert_eq!(
            ProgressEvent::parse("waiting_for_card"),
            ProgressEvent::WaitingForCard
        );
        assert_eq!(ProgressEvent::WaitingForCard.as_str(), "waiting_for_card");
        assert_eq!(
            ProgressEvent::parse("card_wait_ended"),
            ProgressEvent::CardWaitEnded
        );
        assert_eq!(ProgressEvent::CardWaitEnded.as_str(), "card_wait_ended");
        assert_eq!(
            ProgressEvent::parse("future_extension"),
            ProgressEvent::Unknown
        );
    }

    #[test]
    fn operation_progress_message_round_trip() {
        let reference = OperationReference {
            operation_id: OperationId::from_array([0x42; 16]),
            request_hash: RequestHash::from_array([0x33; 32]),
        };
        let msg = OperationProgressMessage {
            reference,
            event: ProgressEvent::WaitingForCard,
        };
        let wire = msg.to_wire_body();
        let decoded = OperationProgressMessage::from_wire_body(wire).expect("valid decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn operation_progress_message_adversarial_decoding() {
        let reference = OperationReference {
            operation_id: OperationId::from_array([0x42; 16]),
            request_hash: RequestHash::from_array([0x33; 32]),
        };

        // Unknown event name parses successfully as ProgressEvent::Unknown
        let mut body = reference.to_wire_body();
        body.insert(
            "event".into(),
            WireValue::Text("unexpected_future_event".into()),
        );
        let decoded =
            OperationProgressMessage::from_wire_body(body).expect("unknown event tolerant");
        assert_eq!(decoded.event, ProgressEvent::Unknown);
        assert_eq!(decoded.reference, reference);

        // Missing event field
        let body = reference.to_wire_body();
        assert_eq!(
            OperationProgressMessage::from_wire_body(body),
            Err(CardOperationError::InvalidField("event"))
        );

        // Wrong type event field (integer instead of text)
        let mut body = reference.to_wire_body();
        body.insert("event".into(), WireValue::Unsigned(123));
        assert_eq!(
            OperationProgressMessage::from_wire_body(body),
            Err(CardOperationError::InvalidField("event"))
        );

        // Extra field in body
        let mut body = reference.to_wire_body();
        body.insert("event".into(), WireValue::Text("waiting_for_card".into()));
        body.insert(
            "extra_bogus_field".into(),
            WireValue::Text("malicious".into()),
        );
        assert_eq!(
            OperationProgressMessage::from_wire_body(body),
            Err(CardOperationError::UnexpectedField)
        );
    }
}
