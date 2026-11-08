//! Established-session endpoint: failures close the session and never the
//! pairing (RAPP v26.11.8 section 10.1).

use super::{
    BinaryFrame, CloseReason, CryptoError, EndpointRole, MessageError, MessageType, OpenError,
    PairId, ProxyViolation, RappState, RequesterViolation, SecureChannel, SecurityOutcome,
    SessionCloseMessage, TypedMessage, WireError,
};
use core::fmt;

/// An authenticated RAPP endpoint with one current secure session.
///
/// A Custodian's endpoint admits the Requester's `session.hello` as the
/// first message, or a `pairing_revoked` close in its place; any other
/// first message, and a `session.hello` anywhere else, closes the session
/// as an authenticated protocol violation, so no `operation.request` is
/// admitted before the Requester named itself (RAPP v26.11.8 section 7.1
/// item 6).
///
/// A close is acknowledged (section 7.1 item 7): a received
/// `session.close` is answered with one carrying the same reason, and once
/// this endpoint sent a close it sends nothing more and waits for the
/// peer's echo, ignoring everything else; a close arriving then is the
/// echo, or a close that crossed this endpoint's, and is not answered.
pub struct EstablishedEndpoint {
    pair_id: PairId,
    channel: Option<SecureChannel>,
    state: RappState,
    awaiting_session_hello: bool,
    close_sent: Option<CloseReason>,
}

impl EstablishedEndpoint {
    /// Creates an endpoint after a successful session handshake. A
    /// Custodian's endpoint awaits the Requester's `session.hello`.
    #[must_use]
    pub const fn new(pair_id: PairId, channel: SecureChannel, state: RappState) -> Self {
        Self {
            pair_id,
            channel: Some(channel),
            awaiting_session_hello: matches!(state.role, EndpointRole::Proxy),
            close_sent: None,
            state,
        }
    }

    /// Whether this endpoint sent a close and waits for the peer's echo.
    #[must_use]
    pub const fn awaits_close_echo(&self) -> bool {
        self.close_sent.is_some() && self.channel.is_some()
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
    /// the protocol closes it with a sealed `protocol_violation` notice and
    /// waits for its echo. A received close is answered with its echo and
    /// closes the session. The pairing stays.
    ///
    /// # Errors
    /// [`EndpointError::SessionClosed`] when the session is already closed.
    pub fn receive(
        &mut self,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<ReceiveOutcome, EndpointError> {
        if let Some(sent) = self.close_sent {
            return self.receive_while_closing(frame, now_ms, sent);
        }
        let Some(channel) = self.channel.as_mut() else {
            return Err(EndpointError::SessionClosed);
        };
        match channel.open(frame) {
            Ok(envelope) => match TypedMessage::from_envelope(envelope, now_ms) {
                Ok(TypedMessage::SessionClose(close))
                    if self.admits(&TypedMessage::SessionClose(close)) =>
                {
                    Ok(self.answer_close(close.reason))
                }
                Ok(message) if self.admits(&message) => {
                    if matches!(message, TypedMessage::SessionHello(_)) {
                        self.awaiting_session_hello = false;
                    }
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
    /// session binding remain inside the secure channel. A `session.close`
    /// is the last message: the endpoint then waits for its echo and sends
    /// nothing more.
    ///
    /// # Errors
    /// [`EndpointError`] on a closed session or one that sent its close, a
    /// wrong-phase message, or an encoding or encryption failure.
    pub fn send(&mut self, message: &TypedMessage) -> Result<BinaryFrame, EndpointError> {
        if !permitted_in_established_session(message) {
            return Err(EndpointError::UnexpectedPhase(message.message_type()));
        }
        if self.close_sent.is_some() {
            return Err(EndpointError::SessionClosed);
        }
        let frame = self.seal(message)?;
        if let TypedMessage::SessionClose(close) = message {
            self.close_sent = Some(close.reason);
        }
        Ok(frame)
    }

    fn seal(&mut self, message: &TypedMessage) -> Result<BinaryFrame, EndpointError> {
        let channel = self.channel.as_mut().ok_or(EndpointError::SessionClosed)?;
        let body = message.to_wire_body().map_err(EndpointError::Message)?;
        channel
            .seal(message.message_type(), body)
            .map_err(EndpointError::Crypto)
    }

    /// The peer closed the session: answer with the echo, the close with
    /// the same reason, and close (section 7.1 item 7).
    fn answer_close(&mut self, reason: CloseReason) -> ReceiveOutcome {
        let echo = self
            .seal(&TypedMessage::SessionClose(SessionCloseMessage { reason }))
            .ok();
        self.channel = None;
        ReceiveOutcome::PeerClosed { reason, echo }
    }

    /// One frame while this endpoint waits for the echo of its close
    /// `sent`: a close is the echo, or a close that crossed this endpoint's,
    /// and ends the session unanswered; anything else authenticated is
    /// ignored; a frame that fails authentication ends the session.
    fn receive_while_closing(
        &mut self,
        frame: &BinaryFrame,
        now_ms: u64,
        sent: CloseReason,
    ) -> Result<ReceiveOutcome, EndpointError> {
        let Some(channel) = self.channel.as_mut() else {
            return Err(EndpointError::SessionClosed);
        };
        let opened = channel.open(frame);
        let outcome = match opened.map(|envelope| TypedMessage::from_envelope(envelope, now_ms)) {
            Ok(Ok(TypedMessage::SessionClose(close))) => ReceiveOutcome::CloseAcknowledged {
                reason: close.reason,
                crossing: close.reason != sent,
            },
            Ok(_) => return Ok(ReceiveOutcome::IgnoredWhileClosing),
            Err(_) => ReceiveOutcome::SessionClosed(SecurityOutcome {
                actions: Vec::new(),
            }),
        };
        self.channel = None;
        Ok(outcome)
    }

    /// Whether the session's phase admits the received `message`: a
    /// Custodian awaiting the Requester's `session.hello` admits only it or
    /// a `pairing_revoked` close; otherwise a `session.hello` is never
    /// admitted.
    const fn admits(&self, message: &TypedMessage) -> bool {
        match message {
            TypedMessage::SessionHello(_) => self.awaiting_session_hello,
            TypedMessage::SessionClose(close)
                if matches!(close.reason, CloseReason::PairingRevoked) =>
            {
                true
            }
            _ => !self.awaiting_session_hello && permitted_in_established_session(message),
        }
    }

    /// Closes the local secure channel, also while waiting for an echo; the
    /// pairing stays.
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
        if notice.is_none() {
            self.channel = None;
        }
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
    /// The peer closed the session with `reason`; deliver `echo`, the close
    /// that acknowledges it, when it could be sealed, then drop the link
    /// (section 7.1 item 7).
    PeerClosed {
        /// The received reason.
        reason: CloseReason,
        /// The sealed echo.
        echo: Option<BinaryFrame>,
    },
    /// The close this endpoint waited on arrived: the echo of its own, or,
    /// with `crossing`, a close with another reason that crossed it, whose
    /// reason the endpoint acts on. The session closed; drop the link.
    CloseAcknowledged {
        /// The received reason.
        reason: CloseReason,
        /// The received reason differs from the one this endpoint sent.
        crossing: bool,
    },
    /// An authenticated message arrived while this endpoint waits for the
    /// echo of its close; it is ignored.
    IgnoredWhileClosing,
    /// A frame failed authentication; the session closed.
    SessionClosed(SecurityOutcome),
    /// Authenticated traffic violated the protocol; the session closes and
    /// the pairing stays. Deliver `notice`, wait for its echo as for any
    /// close, then drop the link.
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
    /// `session.ready` on a healthy session, anything but `session.ready`
    /// or a close as the Custodian's first message, anything but
    /// `session.hello` or a `pairing_revoked` close as the Requester's
    /// first message, or a `session.hello` anywhere else.
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
            | TypedMessage::SessionHello(_)
    )
}
