//! An established session with its liveness (RAPP v26.11.2 section 8.3).

use super::{
    AuthenticatedViolation, BinaryFrame, CloseReason, EndpointError, EstablishedEndpoint,
    LivenessDecision, LivenessMessage, LivenessTracker, OperationViolation, PingChallenge,
    PongDisposition, ReceiveOutcome, SecurityOutcome, SessionCloseMessage, TypedMessage,
};

/// Established encrypted session with authenticated liveness.
#[derive(Debug)]
pub struct EstablishedSessionRuntime {
    endpoint: EstablishedEndpoint,
    liveness: LivenessTracker,
}

impl EstablishedSessionRuntime {
    /// Start liveness over an established endpoint, with the peer last heard
    /// at `now_ms`.
    #[must_use]
    pub const fn new(endpoint: EstablishedEndpoint, now_ms: u64) -> Self {
        Self {
            endpoint,
            liveness: LivenessTracker::new(now_ms),
        }
    }

    /// Underlying cryptographic endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &EstablishedEndpoint {
        &self.endpoint
    }

    /// Mutable underlying cryptographic endpoint.
    pub const fn endpoint_mut(&mut self) -> &mut EstablishedEndpoint {
        &mut self.endpoint
    }

    /// Close both the cryptographic endpoint and its liveness tracker.
    pub fn close_session(&mut self) {
        self.liveness.close();
        self.endpoint.close_session();
    }

    /// Seal an authenticated `session.close` carrying `reason`; the caller
    /// delivers the frame and waits for the peer's echo, which
    /// [`Self::receive`] reports as [`RuntimeReceive::CloseAcknowledged`],
    /// within its bound, then drops the link (RAPP v26.11.2 section 7.1
    /// item 7). Liveness stops; nothing more is sent.
    ///
    /// # Errors
    /// [`EndpointError`] when the session is already closed, its close was
    /// sent, or the notice cannot be sealed; the session is then closed.
    pub fn close_with_reason(&mut self, reason: CloseReason) -> Result<BinaryFrame, EndpointError> {
        let notice = TypedMessage::SessionClose(SessionCloseMessage { reason });
        let sealed = self.endpoint.send(&notice);
        self.liveness.close();
        if sealed.is_err() {
            self.close_session();
        }
        sealed
    }

    /// Whether this endpoint sent a close and waits for the peer's echo.
    #[must_use]
    pub const fn awaits_close_echo(&self) -> bool {
        self.endpoint.awaits_close_echo()
    }

    /// Close after an operation engine found the peer's traffic violating
    /// the protocol; the pairing stays.
    pub fn close_for_operation_violation(
        &mut self,
        violation: OperationViolation,
    ) -> RuntimeReceive {
        self.liveness.close();
        match self.endpoint.close_for_operation_violation(violation) {
            ReceiveOutcome::ViolationClosed {
                violation,
                outcome,
                notice,
            } => RuntimeReceive::ViolationClosed {
                violation,
                outcome,
                notice,
            },
            ReceiveOutcome::SessionClosed(outcome) => RuntimeReceive::SessionClosed(outcome),
            other => runtime_outcome(other),
        }
    }

    /// Receive one encrypted frame and consume liveness messages centrally.
    ///
    /// # Errors
    /// [`RuntimeError`] separating receive-path faults from pong-response
    /// send faults.
    pub fn receive(
        &mut self,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<RuntimeReceive, RuntimeError> {
        let outcome = self
            .endpoint
            .receive(frame, now_ms)
            .map_err(RuntimeError::Receive)?;
        if matches!(outcome, ReceiveOutcome::Message(_)) {
            self.liveness.heard(now_ms);
        }
        match outcome {
            ReceiveOutcome::Message(TypedMessage::LivenessPing(ping)) => {
                let reply = TypedMessage::LivenessPong(LivenessMessage {
                    challenge: ping.challenge,
                });
                let frame = self.endpoint.send(&reply).map_err(RuntimeError::Send)?;
                Ok(RuntimeReceive::Send(frame))
            }
            ReceiveOutcome::Message(TypedMessage::LivenessPong(pong)) => {
                Ok(match self.liveness.receive_pong(now_ms, pong.challenge) {
                    PongDisposition::Accepted => RuntimeReceive::LivenessConfirmed,
                    PongDisposition::IgnoredUnmatched => RuntimeReceive::IgnoredStalePong,
                })
            }
            ReceiveOutcome::Message(message) => Ok(RuntimeReceive::Message(message)),
            ReceiveOutcome::IgnoredWhileClosing => Ok(RuntimeReceive::IgnoredWhileClosing),
            other => {
                self.liveness.close();
                Ok(runtime_outcome(other))
            }
        }
    }

    /// Advance the liveness clock.
    ///
    /// # Errors
    /// [`EndpointError`] when a due ping cannot be sealed.
    pub fn poll(
        &mut self,
        now_ms: u64,
        next_challenge: PingChallenge,
    ) -> Result<RuntimePoll, EndpointError> {
        match self.liveness.poll(now_ms, next_challenge) {
            LivenessDecision::NoAction => Ok(RuntimePoll::NoAction),
            LivenessDecision::SendPing(challenge) => {
                let ping = TypedMessage::LivenessPing(LivenessMessage { challenge });
                Ok(RuntimePoll::Send(self.endpoint.send(&ping)?))
            }
            LivenessDecision::CloseSession => Ok(RuntimePoll::SessionClosed(
                self.endpoint.close_for_silence(),
            )),
            LivenessDecision::AlreadyClosed => Ok(RuntimePoll::AlreadyClosed),
        }
    }
}

/// The runtime form of an endpoint outcome that carries no liveness.
fn runtime_outcome(outcome: ReceiveOutcome) -> RuntimeReceive {
    match outcome {
        ReceiveOutcome::Message(message) => RuntimeReceive::Message(message),
        ReceiveOutcome::PeerClosed { reason, echo } => RuntimeReceive::PeerClosed { reason, echo },
        ReceiveOutcome::CloseAcknowledged { reason, crossing } => {
            RuntimeReceive::CloseAcknowledged { reason, crossing }
        }
        ReceiveOutcome::IgnoredWhileClosing => RuntimeReceive::IgnoredWhileClosing,
        ReceiveOutcome::SessionClosed(outcome) => RuntimeReceive::SessionClosed(outcome),
        ReceiveOutcome::ViolationClosed {
            violation,
            outcome,
            notice,
        } => RuntimeReceive::ViolationClosed {
            violation,
            outcome,
            notice,
        },
    }
}

/// Where a runtime fault occurred.
#[derive(Debug)]
pub enum RuntimeError {
    /// Fault while receiving.
    Receive(EndpointError),
    /// Fault while producing a local response frame.
    Send(EndpointError),
}

/// Outcome of receiving one encrypted frame.
#[derive(Debug)]
pub enum RuntimeReceive {
    /// Non-liveness authenticated message for the caller.
    Message(TypedMessage),
    /// Frame to send; a liveness answer was produced centrally.
    Send(BinaryFrame),
    /// The outstanding ping was answered.
    LivenessConfirmed,
    /// Pong matched no outstanding ping; discarded.
    IgnoredStalePong,
    /// A frame failed authentication; the session closed.
    SessionClosed(SecurityOutcome),
    /// The peer closed the session with an authenticated notice; deliver
    /// `echo`, the close that acknowledges it, when it could be sealed, then
    /// drop the link (RAPP v26.11.2 section 7.1 item 7).
    PeerClosed {
        /// The received reason.
        reason: CloseReason,
        /// The sealed echo.
        echo: Option<BinaryFrame>,
    },
    /// The echo of this endpoint's close arrived, or, with `crossing`, a
    /// close with another reason that crossed it; the session closed. Act
    /// on a crossing reason; drop the link.
    CloseAcknowledged {
        /// The received reason.
        reason: CloseReason,
        /// The received reason differs from the one this endpoint sent.
        crossing: bool,
    },
    /// A message arrived while this endpoint waits for the echo of its
    /// close; it is ignored.
    IgnoredWhileClosing,
    /// Authenticated traffic violated the protocol; the session closes and
    /// the pairing stays. Deliver `notice`, wait for its echo, then drop the
    /// link.
    ViolationClosed {
        /// The violation.
        violation: AuthenticatedViolation,
        /// Effects the endpoint carries out.
        outcome: SecurityOutcome,
        /// The sealed `protocol_violation` close, when it could be sealed.
        notice: Option<BinaryFrame>,
    },
}

/// Outcome of advancing the liveness clock.
#[derive(Debug)]
pub enum RuntimePoll {
    /// Nothing is due.
    NoAction,
    /// Ping frame to send.
    Send(BinaryFrame),
    /// The silence limit closed the session.
    SessionClosed(SecurityOutcome),
    /// The session was already closed.
    AlreadyClosed,
}
