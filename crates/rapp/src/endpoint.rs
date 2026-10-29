//! Established-session endpoint: failures close the session and never the
//! pairing (RAPP v26.10.29 section 10.1).

use super::{
    BinaryFrame, CloseReason, CryptoError, MessageError, MessageType, OpenError, PairId,
    ProxyViolation, RappState, RequesterViolation, SecureChannel, SecurityOutcome,
    SessionCloseMessage, TypedMessage, WireError,
};
use core::fmt;

/// An authenticated RAPP endpoint with one current secure session.
pub struct EstablishedEndpoint {
    pair_id: PairId,
    channel: Option<SecureChannel>,
    state: RappState,
}

impl EstablishedEndpoint {
    /// Creates an endpoint after a successful session handshake.
    #[must_use]
    pub const fn new(pair_id: PairId, channel: SecureChannel, state: RappState) -> Self {
        Self {
            pair_id,
            channel: Some(channel),
            state,
        }
    }

    /// The pairing this session belongs to.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.pair_id
    }

    /// Current product state projection.
    #[must_use]
    pub const fn state(&self) -> &RappState {
        &self.state
    }

    /// Opens and fully validates one encrypted frame. A frame that fails
    /// authentication closes the session; an authenticated one that violates
    /// the protocol closes it with a sealed `protocol_violation` notice. The
    /// pairing stays.
    ///
    /// # Errors
    /// [`EndpointError::SessionClosed`] when the session is already closed.
    pub fn receive(
        &mut self,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<ReceiveOutcome, EndpointError> {
        let Some(channel) = self.channel.as_mut() else {
            return Err(EndpointError::SessionClosed);
        };
        match channel.open(frame) {
            Ok(envelope) => match TypedMessage::from_envelope(envelope, now_ms) {
                Ok(message) if permitted_in_established_session(&message) => {
                    Ok(ReceiveOutcome::Message(message))
                }
                Ok(message) => Ok(self.close_for_violation(
                    AuthenticatedViolation::UnexpectedPhase(message.message_type()),
                )),
                Err(error) => Ok(self.close_for_violation(AuthenticatedViolation::Semantic(error))),
            },
            Err(OpenError::SessionIntegrityFailure) => {
                let outcome = self.state.session_integrity_failed();
                self.channel = None;
                Ok(ReceiveOutcome::SessionClosed(outcome))
            }
            Err(OpenError::AuthenticatedProtocolViolation(wire_error)) => {
                Ok(self.close_for_violation(AuthenticatedViolation::Wire(wire_error)))
            }
        }
    }

    /// Encrypts one schema-validated outgoing message. Sequence allocation and
    /// session binding remain inside the secure channel.
    ///
    /// # Errors
    /// [`EndpointError`] on a closed session, a wrong-phase message, or an
    /// encoding or encryption failure.
    pub fn send(&mut self, message: &TypedMessage) -> Result<BinaryFrame, EndpointError> {
        if !permitted_in_established_session(message) {
            return Err(EndpointError::UnexpectedPhase(message.message_type()));
        }
        let channel = self.channel.as_mut().ok_or(EndpointError::SessionClosed)?;
        let body = message.to_wire_body().map_err(EndpointError::Message)?;
        channel
            .seal(message.message_type(), body)
            .map_err(EndpointError::Crypto)
    }

    /// Closes the local secure channel; the pairing stays.
    pub fn close_session(&mut self) {
        self.channel = None;
    }

    /// Closes after nothing arrived for the session silence limit (section
    /// 8.3).
    pub fn close_for_silence(&mut self) -> SecurityOutcome {
        let outcome = self.state.silence_limit_reached();
        self.channel = None;
        outcome
    }

    /// Closes after an operation engine found the peer's traffic violating
    /// the protocol.
    pub fn close_for_operation_violation(
        &mut self,
        violation: OperationViolation,
    ) -> ReceiveOutcome {
        self.close_for_violation(AuthenticatedViolation::Operation(violation))
    }

    fn close_for_violation(&mut self, violation: AuthenticatedViolation) -> ReceiveOutcome {
        let outcome = self.state.authenticated_protocol_violation();
        let notice = self
            .send(&TypedMessage::SessionClose(SessionCloseMessage {
                reason: CloseReason::ProtocolViolation,
            }))
            .ok();
        self.channel = None;
        ReceiveOutcome::ViolationClosed {
            violation,
            outcome,
            notice,
        }
    }
}

impl fmt::Debug for EstablishedEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EstablishedEndpoint")
            .field("pair_id", &self.pair_id)
            .field(
                "channel",
                &self.channel.as_ref().map(|_| "[secure channel]"),
            )
            .field("state", &self.state)
            .finish()
    }
}

/// Result of processing one incoming encrypted frame.
#[derive(Debug)]
pub enum ReceiveOutcome {
    /// Authenticated, schema-valid application message.
    Message(TypedMessage),
    /// A frame failed authentication; the session closed.
    SessionClosed(SecurityOutcome),
    /// Authenticated traffic violated the protocol; the session closed and
    /// the pairing stays. Deliver `notice`, then drop the link.
    ViolationClosed {
        /// The violation.
        violation: AuthenticatedViolation,
        /// Effects the endpoint carries out.
        outcome: SecurityOutcome,
        /// The sealed `protocol_violation` close, when it could be sealed.
        notice: Option<BinaryFrame>,
    },
}

/// An authenticated message that violated the protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedViolation {
    /// Canonical framing, envelope, session, or sequence violation.
    Wire(WireError),
    /// Typed-message or profile semantic violation.
    Semantic(MessageError),
    /// A message the session's phase does not admit: a pairing message, a
    /// `session.ready` on a healthy session, or anything but `session.ready`
    /// or a close as the Custodian's first message.
    UnexpectedPhase(MessageType),
    /// The Custodian's `session.ready` parameters differ from the local
    /// view.
    ReadyParameterMismatch,
    /// An operation engine had no legal transition for the message.
    Operation(OperationViolation),
}

/// The operation engine that found a violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationViolation {
    /// The requester's engine.
    Requester(RequesterViolation),
    /// The custodian's engine.
    Proxy(ProxyViolation),
}

/// Established-endpoint processing failure.
#[derive(Debug)]
pub enum EndpointError {
    /// The secure channel is no longer available.
    SessionClosed,
    /// Outgoing encryption or encoding failed.
    Crypto(CryptoError),
    /// Local typed-message construction failed before transmission.
    Message(MessageError),
    /// Local code attempted to send a message from an earlier protocol phase.
    UnexpectedPhase(MessageType),
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for EndpointError {}

const fn permitted_in_established_session(message: &TypedMessage) -> bool {
    !matches!(
        message,
        TypedMessage::PairingHello(_)
            | TypedMessage::PairingConfirm(_)
            | TypedMessage::PairingAbort(_)
            | TypedMessage::PairingStored(_)
            | TypedMessage::SessionReady(_)
    )
}
