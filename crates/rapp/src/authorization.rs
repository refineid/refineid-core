//! Holder consent and the one card command an approved operation gives.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    CardOperation, CardOperationError, CardOperationResult, OperationId, OperationRequest,
    OperationResultMessage, ResultStatus, WireValue,
};

/// The holder's approval of one operation of the session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserApproval {
    operation_id: OperationId,
    approved_at_ms: u64,
}

impl UserApproval {
    /// Approval of `request`, the admitted request a PIN prompt rendered or
    /// the held PIN 1 authorizes.
    #[must_use]
    pub const fn for_request(request: &OperationRequest, approved_at_ms: u64) -> Self {
        Self {
            operation_id: request.operation_id,
            approved_at_ms,
        }
    }

    /// Time at which the holder confirmed the request.
    #[must_use]
    pub const fn approved_at_ms(&self) -> u64 {
        self.approved_at_ms
    }
}

/// Closed command handed to the card integration after approval.
///
/// It carries no CAN, PIN, PUK, or raw APDU. The custodian obtains required
/// credentials locally and the platform card adapter maps this semantic
/// operation to the reviewed card protocol implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCardCommand {
    /// Exact semantic operation approved by the holder.
    pub operation: CardOperation,
}

/// Registered read that commands no private key and no PIN.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedSafeRead {
    /// Exact semantic read.
    pub operation: CardOperation,
}

/// The one command an approval gives. It is not clonable and executing it
/// consumes it, so an approved operation commands the card once.
#[derive(Debug)]
pub struct PendingCardCommand<C> {
    command: C,
}

impl<C> PendingCardCommand<C> {
    /// Consume the command into the card adapter.
    pub fn execute<R>(self, transmit_once: impl FnOnce(C) -> R) -> R {
        transmit_once(self.command)
    }
}

/// One operation of a session from admission to its result (RAPP v26.10.22
/// section 8). It lives in memory only and ends with the session.
#[derive(Debug)]
pub struct AuthorizationTransaction {
    request: OperationRequest,
    stage: AuthorizationStage,
    batch_signatures: Vec<Vec<u8>>,
}

impl AuthorizationTransaction {
    /// Admits a request; a PIN prompt, when one is shown, renders from this
    /// snapshot.
    #[must_use]
    pub const fn prepare(request: OperationRequest) -> Self {
        Self {
            request,
            stage: AuthorizationStage::Requested,
            batch_signatures: Vec::new(),
        }
    }

    /// The request as admitted.
    #[must_use]
    pub const fn request(&self) -> &OperationRequest {
        &self.request
    }

    /// The operation's identifier.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.request.operation_id
    }

    /// Current phase.
    #[must_use]
    pub const fn stage(&self) -> AuthorizationStage {
        self.stage
    }

    /// Whether the operation has its result.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.stage, AuthorizationStage::Terminal)
    }

    /// Records that the operation has the card and its prerequisite reads
    /// are done. An action that needs the holder's authorization waits for
    /// consent; a read skips consent and runs (section 8.2 items 3 and 6).
    ///
    /// # Errors
    /// [`AuthorizationError::WrongStage`] outside the requested stage.
    pub fn prerequisites_complete(&mut self) -> Result<PrerequisitesOutcome, AuthorizationError> {
        if self.stage != AuthorizationStage::Requested {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        if self.request.operation.is_consequential() {
            self.stage = AuthorizationStage::AwaitingConsent;
            return Ok(PrerequisitesOutcome::AwaitConsent);
        }
        self.stage = AuthorizationStage::ExecutingSafeRead;
        Ok(PrerequisitesOutcome::ExecuteSafeRead(AuthorizedSafeRead {
            operation: self.request.operation.clone(),
        }))
    }

    /// Accepts the holder's approval and hands out the one card command.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a wrong stage, an approval of another
    /// operation, or an approval outside the request's lifetime.
    pub fn approve(
        &mut self,
        approval: UserApproval,
        now_ms: u64,
        maximum_lifetime_ms: u64,
    ) -> Result<PendingCardCommand<AuthorizedCardCommand>, AuthorizationError> {
        if self.stage != AuthorizationStage::AwaitingConsent {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        if approval.operation_id != self.request.operation_id {
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
        self.stage = AuthorizationStage::Executing;
        Ok(PendingCardCommand {
            command: AuthorizedCardCommand {
                operation: self.request.operation.clone(),
            },
        })
    }

    /// Ends the operation with a result that did not complete.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a completed or mismatched result, or an
    /// operation that already has its result.
    pub fn finish_failure(
        &mut self,
        result: &OperationResultMessage,
    ) -> Result<(), AuthorizationError> {
        if self.is_terminal() {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        if result.status == ResultStatus::Completed {
            return Err(AuthorizationError::InvalidResult);
        }
        result
            .validate_for(self.request.operation_id, &self.request.operation)
            .map_err(|_| AuthorizationError::InvalidResult)?;
        self.stage = AuthorizationStage::Terminal;
        Ok(())
    }

    /// Ends the operation with its completed result. A batch completes only
    /// with exactly the signatures it recorded, one per document.
    ///
    /// # Errors
    /// [`AuthorizationError`] on a result that does not answer the request,
    /// or a stage in which the card was not commanded.
    pub fn finish_completed(
        &mut self,
        result: &OperationResultMessage,
    ) -> Result<(), AuthorizationError> {
        if !matches!(
            self.stage,
            AuthorizationStage::Executing | AuthorizationStage::ExecutingSafeRead
        ) {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        if result.status != ResultStatus::Completed {
            return Err(AuthorizationError::InvalidResult);
        }
        result
            .validate_for(self.request.operation_id, &self.request.operation)
            .map_err(|_| AuthorizationError::InvalidResult)?;
        if let Some(total) = self.request.operation.batch_total() {
            let recorded = CardOperationResult::Signatures(self.batch_signatures.clone());
            let answered = result
                .response
                .as_ref()
                .map(|response| response.typed_for(&self.request.operation));
            if self.batch_signatures.len() != total || answered != Some(Ok(recorded)) {
                return Err(AuthorizationError::InvalidResult);
            }
        }
        self.stage = AuthorizationStage::Terminal;
        Ok(())
    }

    /// Records one batch signature as the card makes it.
    ///
    /// # Errors
    /// [`AuthorizationError`] outside an executing batch, or past its last
    /// document.
    pub fn record_batch_signature(&mut self, signature: Vec<u8>) -> Result<(), AuthorizationError> {
        if self.stage != AuthorizationStage::Executing {
            return Err(AuthorizationError::WrongStage(self.stage));
        }
        let total = self
            .request
            .operation
            .batch_total()
            .ok_or(AuthorizationError::InvalidResult)?;
        if self.batch_signatures.len() >= total || signature.is_empty() {
            return Err(AuthorizationError::InvalidResult);
        }
        self.batch_signatures.push(signature);
        Ok(())
    }

    /// The signatures a batch has made so far, in document order; empty for
    /// every other operation.
    #[must_use]
    pub fn batch_signatures(&self) -> &[Vec<u8>] {
        &self.batch_signatures
    }

    /// Whether the request's local deadline has passed (section 8.1 item 2).
    #[must_use]
    pub fn is_expired(&self, now_ms: u64, maximum_lifetime_ms: u64) -> bool {
        self.request
            .local_deadline_ms(maximum_lifetime_ms)
            .is_ok_and(|deadline| now_ms > deadline)
    }
}

/// Phase of one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationStage {
    /// Admitted; the reads that precede the PIN have not completed.
    Requested,
    /// The custodian takes the PIN, asking the holder when it does not
    /// hold it; only an action that needs a PIN comes here.
    AwaitingConsent,
    /// A registered read is running.
    ExecutingSafeRead,
    /// The one card command has been handed to the card adapter.
    Executing,
    /// The result is out.
    Terminal,
}

/// What follows once an operation has the card and its prerequisite reads
/// are done.
#[derive(Debug)]
pub enum PrerequisitesOutcome {
    /// Take the PIN: ask the holder when the custodian does not hold it.
    AwaitConsent,
    /// Execute this read and answer directly with a result; no PIN.
    ExecuteSafeRead(AuthorizedSafeRead),
}

/// A change of an operation's state that the custodian reports while it is
/// pending (RAPP v26.10.22 section 8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressEvent {
    /// Another session's operation holds the card.
    Queued,
    /// A PIN prompt is on the custodian's screen.
    ConsentShown,
    /// The custodian waits for the holder to present the card.
    WaitingForCard,
    /// The card was found or the wait is over.
    CardWaitEnded,
}

impl ProgressEvent {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::ConsentShown => "consent_shown",
            Self::WaitingForCard => "waiting_for_card",
            Self::CardWaitEnded => "card_wait_ended",
        }
    }

    /// Parse a wire name.
    ///
    /// # Errors
    /// [`CardOperationError::InvalidField`] for a name outside section 7.1.
    pub fn parse(value: &str) -> Result<Self, CardOperationError> {
        Ok(match value {
            "queued" => Self::Queued,
            "consent_shown" => Self::ConsentShown,
            "waiting_for_card" => Self::WaitingForCard,
            "card_wait_ended" => Self::CardWaitEnded,
            _ => return Err(CardOperationError::InvalidField("event")),
        })
    }
}

/// One `operation.progress`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationProgressMessage {
    /// The pending operation.
    pub operation_id: OperationId,
    /// What changed.
    pub event: ProgressEvent,
}

impl OperationProgressMessage {
    /// Encode the wire body.
    #[must_use]
    pub fn to_wire_body(self) -> BTreeMap<String, WireValue> {
        BTreeMap::from([
            (
                "operation_id".into(),
                WireValue::Bytes(self.operation_id.as_bytes().to_vec()),
            ),
            ("event".into(), WireValue::Text(self.event.as_str().into())),
        ])
    }

    /// Decode the wire body after envelope schema validation.
    ///
    /// # Errors
    /// [`CardOperationError`] on a missing, mistyped, unregistered, or extra
    /// field.
    pub fn from_wire_body(
        mut body: BTreeMap<String, WireValue>,
    ) -> Result<Self, CardOperationError> {
        let operation_id = match body.remove("operation_id") {
            Some(WireValue::Bytes(value)) => OperationId::reconstruct(&value)
                .map_err(|_| CardOperationError::InvalidIdentifier)?,
            _ => return Err(CardOperationError::InvalidField("operation_id")),
        };
        let event = match body.remove("event") {
            Some(WireValue::Text(value)) => ProgressEvent::parse(&value)?,
            _ => return Err(CardOperationError::InvalidField("event")),
        };
        if !body.is_empty() {
            return Err(CardOperationError::UnexpectedField);
        }
        Ok(Self {
            operation_id,
            event,
        })
    }
}

/// Authorization transaction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    /// The approval is for another operation.
    ApprovalMismatch,
    /// Request or approval was outside its validity interval.
    Expired,
    /// Method was called outside the required phase.
    WrongStage(AuthorizationStage),
    /// The result does not answer the admitted request.
    InvalidResult,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for AuthorizationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperationId;

    const EVENTS: [(ProgressEvent, &str); 4] = [
        (ProgressEvent::Queued, "queued"),
        (ProgressEvent::ConsentShown, "consent_shown"),
        (ProgressEvent::WaitingForCard, "waiting_for_card"),
        (ProgressEvent::CardWaitEnded, "card_wait_ended"),
    ];

    #[test]
    fn progress_event_round_trip() {
        for (event, name) in EVENTS {
            assert_eq!(event.as_str(), name);
            assert_eq!(ProgressEvent::parse(name), Ok(event));
        }
    }

    #[test]
    fn an_unregistered_progress_event_is_malformed() {
        assert_eq!(
            ProgressEvent::parse("future_extension"),
            Err(CardOperationError::InvalidField("event"))
        );
    }

    #[test]
    fn operation_progress_message_round_trip() {
        for (event, _) in EVENTS {
            let message = OperationProgressMessage {
                operation_id: OperationId::from_array([0x42; 16]),
                event,
            };
            assert_eq!(
                OperationProgressMessage::from_wire_body(message.to_wire_body()),
                Ok(message)
            );
        }
    }

    #[test]
    fn operation_progress_message_adversarial_decoding() {
        let message = OperationProgressMessage {
            operation_id: OperationId::from_array([0x42; 16]),
            event: ProgressEvent::WaitingForCard,
        };

        let mut body = message.to_wire_body();
        body.remove("event");
        assert_eq!(
            OperationProgressMessage::from_wire_body(body),
            Err(CardOperationError::InvalidField("event"))
        );

        let mut body = message.to_wire_body();
        body.insert("event".into(), WireValue::Unsigned(123));
        assert_eq!(
            OperationProgressMessage::from_wire_body(body),
            Err(CardOperationError::InvalidField("event"))
        );

        let mut body = message.to_wire_body();
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
