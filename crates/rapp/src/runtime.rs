//! An established session with its liveness (RAPP v26.10.21 section 8.3).

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

    /// Seal an authenticated `session.close` carrying `reason`, then close
    /// the session; the caller delivers the frame and drops the link.
    ///
    /// # Errors
    /// [`EndpointError`] when the session is already closed or the notice
    /// cannot be sealed; the session is closed either way.
    pub fn close_with_reason(&mut self, reason: CloseReason) -> Result<BinaryFrame, EndpointError> {
        let notice = TypedMessage::SessionClose(SessionCloseMessage { reason });
        let sealed = self.endpoint.send(&notice);
        self.close_session();
        sealed
    }

    /// Close after an operation engine found the peer's traffic violating
    /// the protocol; the pairing stays.
    pub fn close_for_operation_violation(
        &mut self,
        violation: OperationViolation,
    ) -> RuntimeReceive {
        self.liveness.close();
        match self.endpoint.close_for_operation_violation(violation) {
            ReceiveOutcome::ViolationClosed { violation, outcome } => {
                RuntimeReceive::ViolationClosed { violation, outcome }
            }
            ReceiveOutcome::SessionClosed(outcome) => RuntimeReceive::SessionClosed(outcome),
            ReceiveOutcome::Message(message) => RuntimeReceive::Message(message),
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
            ReceiveOutcome::Message(TypedMessage::SessionClose(close)) => {
                self.close_session();
                Ok(RuntimeReceive::PeerClosed(close.reason))
            }
            ReceiveOutcome::Message(message) => Ok(RuntimeReceive::Message(message)),
            ReceiveOutcome::SessionClosed(outcome) => {
                self.liveness.close();
                Ok(RuntimeReceive::SessionClosed(outcome))
            }
            ReceiveOutcome::ViolationClosed { violation, outcome } => {
                self.liveness.close();
                Ok(RuntimeReceive::ViolationClosed { violation, outcome })
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
    /// The peer closed the session with an authenticated notice.
    PeerClosed(CloseReason),
    /// Authenticated traffic violated the protocol; the session closed and
    /// the pairing stays.
    ViolationClosed {
        /// The violation.
        violation: AuthenticatedViolation,
        /// Effects the endpoint carries out.
        outcome: SecurityOutcome,
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
