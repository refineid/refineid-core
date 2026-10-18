//! Fail-closed established-session endpoint composition.

use super::{
    BinaryFrame, CryptoError, MessageError, MessageType, OpenError, PairId, PairStore,
    PairStoreError, PairTombstone, ProxyViolation, RappState, RequesterViolation, SecureChannel,
    SecurityOutcome, TypedMessage, WireError,
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

    /// Current product state projection.
    #[must_use]
    pub const fn state(&self) -> &RappState {
        &self.state
    }

    /// Most recently authenticated peer sequence for liveness messages.
    pub fn last_received_sequence(&self) -> Option<u64> {
        self.channel
            .as_ref()
            .and_then(SecureChannel::last_received_sequence)
    }

    /// Opens and fully validates one encrypted frame.
    ///
    /// A successfully authenticated grammar/sequence violation revokes the
    /// pair immediately on this first event. A frame that cannot be
    /// authenticated closes only this session, preventing unauthenticated
    /// network traffic from deleting a valid pairing.
    ///
    /// # Errors
    /// [`EndpointError`] when the session is already closed or the
    /// revocation tombstone cannot be persisted.
    pub fn receive<S: PairStore>(
        &mut self,
        store: &mut S,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<ReceiveOutcome, EndpointError<S::Error>> {
        let Some(channel) = self.channel.as_mut() else {
            return Err(EndpointError::SessionClosed);
        };

        match channel.open(frame) {
            Ok(envelope) => match TypedMessage::from_envelope(envelope, self.pair_id, now_ms) {
                Ok(message) if permitted_in_established_session(&message) => {
                    Ok(ReceiveOutcome::Message(message))
                }
                Ok(message) => self.revoke_for_violation(
                    store,
                    now_ms,
                    AuthenticatedViolation::UnexpectedPhase(message.message_type()),
                ),
                Err(error) => self.revoke_for_violation(
                    store,
                    now_ms,
                    AuthenticatedViolation::Semantic(error),
                ),
            },
            Err(OpenError::SessionIntegrityFailure) => {
                let outcome = self.state.session_integrity_failed();
                self.channel = None;
                Ok(ReceiveOutcome::SessionClosed(outcome))
            }
            Err(OpenError::AuthenticatedProtocolViolation(wire_error)) => {
                self.revoke_for_violation(store, now_ms, AuthenticatedViolation::Wire(wire_error))
            }
        }
    }

    /// Encrypts one schema-validated outgoing message. Sequence allocation and
    /// session binding remain inside the secure channel.
    ///
    /// # Errors
    /// [`EndpointError`] on a closed session, a wrong-phase message, or an
    /// encoding or encryption failure.
    pub fn send(&mut self, message: &TypedMessage) -> Result<BinaryFrame, EndpointError<()>> {
        if !permitted_in_established_session(message) {
            return Err(EndpointError::UnexpectedPhase(message.message_type()));
        }
        let channel = self.channel.as_mut().ok_or(EndpointError::SessionClosed)?;
        let body = message.to_wire_body().map_err(EndpointError::Message)?;
        channel
            .seal(message.message_type(), body)
            .map_err(EndpointError::Crypto)
    }

    /// Closes the local secure channel without revoking the long-term pair.
    pub fn close_session(&mut self) {
        self.channel = None;
    }

    /// Close for unattributable connectivity failure while preserving pairing.
    pub fn close_for_connectivity_failure(&mut self) -> SecurityOutcome {
        let outcome = self.state.session_integrity_failed();
        self.channel = None;
        outcome
    }

    /// Project the first missed authenticated liveness probe.
    pub fn liveness_missed(&mut self) -> SecurityOutcome {
        self.state.liveness_missed()
    }

    /// Project an exact authenticated pong.
    pub fn liveness_restored(&mut self) -> SecurityOutcome {
        self.state.liveness_restored()
    }

    /// Revoke for a requester-engine violation through the same fail-closed
    /// path used by authenticated wire and message violations.
    ///
    /// # Errors
    /// [`EndpointError::PairRevocationFailed`] when the tombstone cannot be
    /// persisted.
    pub fn revoke_requester_violation<S: PairStore>(
        &mut self,
        store: &mut S,
        now_ms: u64,
        violation: RequesterViolation,
    ) -> Result<ReceiveOutcome, EndpointError<S::Error>> {
        self.revoke_for_violation(
            store,
            now_ms,
            AuthenticatedViolation::RequesterState(violation),
        )
    }

    /// Revoke for a proxy-engine violation on its first authenticated event.
    ///
    /// # Errors
    /// [`EndpointError::PairRevocationFailed`] when the tombstone cannot be
    /// persisted.
    pub fn revoke_proxy_violation<S: PairStore>(
        &mut self,
        store: &mut S,
        now_ms: u64,
        violation: ProxyViolation,
    ) -> Result<ReceiveOutcome, EndpointError<S::Error>> {
        self.revoke_for_violation(store, now_ms, AuthenticatedViolation::ProxyState(violation))
    }

    /// Revoke this pairing after the card rejects CAN, PIN 1, or PIN 2.
    ///
    /// The caller seals the bounded `credential_rejected` result first when
    /// the authenticated channel is still usable. This method then destroys
    /// the channel and durably tombstones the pair before control returns.
    ///
    /// # Errors
    /// [`EndpointError::PairRevocationFailed`] when the tombstone cannot be
    /// persisted.
    pub fn revoke_credential_rejection<S: PairStore>(
        &mut self,
        store: &mut S,
        now_ms: u64,
    ) -> Result<SecurityOutcome, EndpointError<S::Error>> {
        let outcome = self.state.credential_rejected();
        self.channel = None;
        store
            .revoke(PairTombstone {
                pair_id: self.pair_id,
                revoked_at_ms: now_ms,
            })
            .map_err(EndpointError::PairRevocationFailed)?;
        Ok(outcome)
    }

    fn revoke_for_violation<S: PairStore>(
        &mut self,
        store: &mut S,
        now_ms: u64,
        violation: AuthenticatedViolation,
    ) -> Result<ReceiveOutcome, EndpointError<S::Error>> {
        let outcome = self.state.authenticated_protocol_violation();
        self.channel = None;
        store
            .revoke(PairTombstone {
                pair_id: self.pair_id,
                revoked_at_ms: now_ms,
            })
            .map_err(EndpointError::PairRevocationFailed)?;
        Ok(ReceiveOutcome::PairRevoked { violation, outcome })
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
    /// Unattributable integrity failure closed only the session.
    SessionClosed(SecurityOutcome),
    /// First authenticated violation destroyed the pair immediately.
    PairRevoked {
        /// Exact authenticated wire or semantic violation.
        violation: AuthenticatedViolation,
        /// Product state effects that platform adapters must project.
        outcome: SecurityOutcome,
    },
}

/// Attributable violation which triggers immediate first-incident revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedViolation {
    /// Canonical framing, envelope, session, or sequence violation.
    Wire(WireError),
    /// Nested typed-message or profile/action semantic violation.
    Semantic(MessageError),
    /// Authenticated message belongs to pairing or session authentication,
    /// not an already-established application session.
    UnexpectedPhase(MessageType),
    /// Requester operation machine had no legal active transition.
    RequesterState(RequesterViolation),
    /// Proxy operation machine had no legal active transition.
    ProxyState(ProxyViolation),
}

/// Established-endpoint processing failure.
#[derive(Debug)]
pub enum EndpointError<E> {
    /// The secure channel is no longer available.
    SessionClosed,
    /// Outgoing encryption or encoding failed.
    Crypto(CryptoError),
    /// Local typed-message construction failed before transmission.
    Message(MessageError),
    /// Local code attempted to send a message from an earlier protocol phase.
    UnexpectedPhase(MessageType),
    /// Pair-key destruction could not be durably completed. The in-memory
    /// endpoint remains failed closed and cannot process more traffic.
    PairRevocationFailed(PairStoreError<E>),
}

impl<E: fmt::Debug> fmt::Display for EndpointError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl<E: fmt::Debug> core::error::Error for EndpointError<E> {}

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
