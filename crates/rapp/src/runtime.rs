//! Established-session liveness composition.

use super::{
    AuthenticatedViolation, BinaryFrame, CloseReason, EndpointError, EstablishedEndpoint,
    LivenessConfig, LivenessDecision, LivenessError, LivenessMessage, LivenessTracker, PairStore,
    PingChallenge, PongDisposition, ReceiveOutcome, SecurityOutcome, SessionCloseMessage,
    TypedMessage,
};

/// Established encrypted session with authenticated cryptographic liveness.
#[derive(Debug)]
pub struct EstablishedSessionRuntime {
    endpoint: EstablishedEndpoint,
    liveness: LivenessTracker,
}

impl EstablishedSessionRuntime {
    /// Start liveness tracking over an established endpoint.
    ///
    /// # Errors
    /// [`LivenessError`] when the policy fails validation.
    pub fn new(
        endpoint: EstablishedEndpoint,
        config: LivenessConfig,
        now_ms: u64,
    ) -> Result<Self, LivenessError> {
        Ok(Self {
            endpoint,
            liveness: LivenessTracker::new(config, now_ms)?,
        })
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
    pub fn close_with_reason(
        &mut self,
        reason: CloseReason,
    ) -> Result<BinaryFrame, EndpointError<()>> {
        let notice = TypedMessage::SessionClose(SessionCloseMessage {
            reason,
            last_received_sequence: self.last_received_sequence(),
        });
        let sealed = self.endpoint.send(&notice);
        self.close_session();
        sealed
    }

    /// Receive one encrypted frame and consume liveness messages centrally.
    ///
    /// # Errors
    /// [`RuntimeError`] separating receive-path faults from pong-response
    /// send faults.
    pub fn receive<S: PairStore>(
        &mut self,
        store: &mut S,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<RuntimeReceive, RuntimeError<S::Error>> {
        match self
            .endpoint
            .receive(store, frame, now_ms)
            .map_err(RuntimeError::Receive)?
        {
            ReceiveOutcome::Message(TypedMessage::LivenessPing(ping)) => {
                let reply = TypedMessage::LivenessPong(LivenessMessage {
                    challenge: ping.challenge,
                    last_received_sequence: self.last_received_sequence(),
                });
                let frame = self.endpoint.send(&reply).map_err(RuntimeError::Send)?;
                Ok(RuntimeReceive::Send(frame))
            }
            ReceiveOutcome::Message(TypedMessage::LivenessPong(pong)) => {
                match self.liveness.receive_pong(now_ms, pong.challenge) {
                    PongDisposition::Accepted => {
                        let outcome = self.endpoint.liveness_restored();
                        Ok(RuntimeReceive::LivenessRestored(outcome))
                    }
                    PongDisposition::IgnoredUnmatched => Ok(RuntimeReceive::IgnoredStalePong),
                }
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
            ReceiveOutcome::PairRevoked { violation, outcome } => {
                self.liveness.close();
                Ok(RuntimeReceive::PairRevoked { violation, outcome })
            }
        }
    }

    /// Advance the injected monotonic liveness policy.
    ///
    /// # Errors
    /// [`EndpointError`] when a due probe cannot be sealed or sent.
    pub fn poll(
        &mut self,
        now_ms: u64,
        next_challenge: PingChallenge,
        jitter_ms: i64,
    ) -> Result<RuntimePoll, EndpointError<()>> {
        match self.liveness.poll(now_ms, next_challenge, jitter_ms) {
            LivenessDecision::NoAction => Ok(RuntimePoll::NoAction),
            LivenessDecision::SendPing(challenge) => {
                let ping = TypedMessage::LivenessPing(LivenessMessage {
                    challenge,
                    last_received_sequence: self.last_received_sequence(),
                });
                Ok(RuntimePoll::Send(self.endpoint.send(&ping)?))
            }
            LivenessDecision::ProbeMissed { next_probe_at_ms } => {
                let outcome = self.endpoint.liveness_missed();
                Ok(RuntimePoll::Checking {
                    next_probe_at_ms,
                    outcome,
                })
            }
            LivenessDecision::CloseSession => {
                let outcome = self.endpoint.close_for_connectivity_failure();
                Ok(RuntimePoll::SessionClosed(outcome))
            }
            LivenessDecision::AlreadyClosed => Ok(RuntimePoll::AlreadyClosed),
        }
    }

    fn last_received_sequence(&self) -> u64 {
        self.endpoint.last_received_sequence().unwrap_or(0)
    }
}

/// Runtime failure preserves whether the fault occurred while receiving from
/// a durable paired endpoint or while producing a local response frame.
#[derive(Debug)]
pub enum RuntimeError<E> {
    /// Fault while receiving from the durable paired endpoint.
    Receive(EndpointError<E>),
    /// Fault while producing a local response frame.
    Send(EndpointError<()>),
}

/// Outcome of receiving one encrypted frame.
#[derive(Debug)]
pub enum RuntimeReceive {
    /// Non-liveness authenticated message for the caller.
    Message(TypedMessage),
    /// Frame to send; a liveness answer was produced centrally.
    Send(BinaryFrame),
    /// Exact challenge echo restored liveness.
    LivenessRestored(SecurityOutcome),
    /// Pong matched no outstanding ping; discarded, not liveness proof.
    IgnoredStalePong,
    /// Session closed; ordered effects to execute.
    SessionClosed(SecurityOutcome),
    /// The peer closed the session with an authenticated notice.
    PeerClosed(CloseReason),
    /// Pairing revoked after an authenticated violation.
    PairRevoked {
        /// Violation that revoked the pairing.
        violation: AuthenticatedViolation,
        /// Ordered security effects to execute.
        outcome: SecurityOutcome,
    },
}

/// Outcome of advancing the liveness policy.
#[derive(Debug)]
pub enum RuntimePoll {
    /// Nothing is due.
    NoAction,
    /// Liveness probe frame to send.
    Send(BinaryFrame),
    /// Probe unanswered; new operations blocked during recovery.
    Checking {
        /// Monotonic time of the next probe.
        next_probe_at_ms: u64,
        /// Ordered security effects to execute.
        outcome: SecurityOutcome,
    },
    /// Liveness hard deadline closed the session.
    SessionClosed(SecurityOutcome),
    /// Session was already closed.
    AlreadyClosed,
}
