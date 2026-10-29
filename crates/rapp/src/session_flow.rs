//! Fresh mutually authenticated sessions for a stored pair.

use core::fmt;

use super::{
    AuthenticatedViolation, BinaryFrame, CloseReason, CryptoError, EndpointRole,
    EstablishedEndpoint, HandshakeChannel, HandshakeRole, MessageError, OpenError, PairKeyMaterial,
    PairRecord, PairingState, RappState, SecureChannel, SessionCloseMessage,
    SessionHandshakeParameters, SessionParameters, SessionReadyMessage, SessionState,
    TransportProfile, TypedMessage,
};

/// Evidence supplied by the requester integration that the user explicitly
/// initiated this new session. RAPP never automatically reconnects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExplicitUserIntent(());

impl ExplicitUserIntent {
    /// Record a fresh local user action at the platform boundary.
    #[must_use]
    pub const fn record() -> Self {
        Self(())
    }
}

/// In-progress mandatory Noise KK session handshake.
pub struct SessionHandshake {
    role: EndpointRole,
    pair_id: super::PairId,
    expected_parameters: SessionParameters,
    local_keys: PairKeyMaterial,
    channel: HandshakeChannel,
}

impl SessionHandshake {
    /// Requester-only explicit session start over `transport`, the
    /// transport profile of the connection (RAPP v26.10.29 §4.3).
    ///
    /// # Errors
    /// [`SessionError`] on a role violation or a handshake-construction
    /// failure.
    pub fn begin_requester(
        pair: &PairRecord,
        transport: TransportProfile,
        _intent: ExplicitUserIntent,
    ) -> Result<Self, SessionError> {
        if pair.role() != EndpointRole::Requester {
            return Err(SessionError::RoleViolation);
        }
        Self::begin(pair, transport)
    }

    /// Proxy-side response to one incoming connection over `transport`. This never
    /// initiates a connection or automatic reconnection.
    ///
    /// # Errors
    /// [`SessionError`] on a role violation or a handshake-construction
    /// failure.
    pub fn begin_proxy(
        pair: &PairRecord,
        transport: TransportProfile,
    ) -> Result<Self, SessionError> {
        if pair.role() != EndpointRole::Proxy {
            return Err(SessionError::RoleViolation);
        }
        Self::begin(pair, transport)
    }

    fn begin(pair: &PairRecord, transport: TransportProfile) -> Result<Self, SessionError> {
        if !pair.is_storage_confirmed() {
            return Err(SessionError::StorageUnconfirmed);
        }
        let local_keys =
            PairKeyMaterial::reconstruct(*pair.local_static_private(), *pair.local_static_public());
        let role = pair.role();
        let pair_id = pair.pair_id();
        let expected_parameters = SessionParameters {
            transport_profile: transport.name().to_owned(),
            candidate_id: transport.candidate_id().to_owned(),
            grants_hash: pair.grants_hash(),
        };
        let channel = HandshakeChannel::session(&SessionHandshakeParameters {
            role: match role {
                EndpointRole::Requester => HandshakeRole::Initiator,
                EndpointRole::Proxy => HandshakeRole::Responder,
            },
            local_keys: &local_keys,
            remote_public_key: pair.remote_static_public(),
            pair_id,
            grants_hash: pair.grants_hash(),
            transport_profile: transport.name(),
        })
        .map_err(SessionError::Crypto)?;
        Ok(Self {
            role,
            pair_id,
            expected_parameters,
            local_keys,
            channel,
        })
    }

    /// Produce the next empty-payload handshake frame.
    ///
    /// # Errors
    /// [`SessionError::Crypto`] when it is not this role's turn or the
    /// handshake already failed.
    pub fn write_message(&mut self) -> Result<BinaryFrame, SessionError> {
        self.channel.write_message().map_err(SessionError::Crypto)
    }

    /// Consume the next handshake frame and reject payload data.
    ///
    /// # Errors
    /// [`SessionError::Crypto`] on a failed handshake message or a non-empty
    /// payload.
    pub fn read_message(&mut self, frame: &BinaryFrame) -> Result<(), SessionError> {
        self.channel
            .read_message(frame)
            .map_err(SessionError::Crypto)
    }

    /// Whether role-specific Noise KK has completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.channel.is_complete()
    }

    /// Complete Noise and enter `session.ready` authentication.
    ///
    /// # Errors
    /// [`SessionError`] when Noise is incomplete or the handshake produced
    /// pairing-channel identifiers.
    pub fn into_authentication(self) -> Result<SessionAuthentication, SessionError> {
        let completion = self.channel.complete().map_err(SessionError::Crypto)?;
        if completion.pair_id.is_some() {
            return Err(SessionError::UnexpectedPairId);
        }
        Ok(SessionAuthentication {
            role: self.role,
            pair_id: self.pair_id,
            session_id: completion.session_id,
            expected_parameters: self.expected_parameters,
            channel: Some(completion.secure_channel),
            ready: false,
            _local_keys: self.local_keys,
        })
    }
}

impl fmt::Debug for SessionHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionHandshake")
            .field("role", &self.role)
            .field("pair_id", &self.pair_id)
            .field("expected_parameters", &self.expected_parameters)
            .field("local_keys", &"[pair key material]")
            .field("complete", &self.channel.is_complete())
            .finish()
    }
}

/// A completed Noise KK session that is not healthy until `session.ready`:
/// the Custodian sends it, the Requester verifies it (RAPP v26.10.29 section
/// 7.1 item 5). A revoking endpoint sends the `pairing_revoked` close in its
/// place (section 4.6 item 2).
pub struct SessionAuthentication {
    role: EndpointRole,
    pair_id: super::PairId,
    session_id: super::SessionId,
    expected_parameters: SessionParameters,
    channel: Option<SecureChannel>,
    ready: bool,
    _local_keys: PairKeyMaterial,
}

impl SessionAuthentication {
    /// The Custodian's `session.ready`: the exact session parameters with a
    /// caller-generated fresh nonce. The session is then healthy.
    ///
    /// # Errors
    /// [`SessionError`] for a Requester, a second ready, a closed channel, or
    /// a seal failure.
    pub fn send_ready(&mut self, nonce: [u8; 32]) -> Result<BinaryFrame, SessionError> {
        if self.role != EndpointRole::Proxy {
            return Err(SessionError::RoleViolation);
        }
        if self.ready {
            return Err(SessionError::DuplicateReady);
        }
        let frame = self.seal(&TypedMessage::SessionReady(SessionReadyMessage {
            parameters: self.expected_parameters.clone(),
            nonce,
        }))?;
        self.ready = true;
        Ok(frame)
    }

    /// The Requester reads the Custodian's first message: `session.ready`,
    /// or a close in its place. Anything else, and ready parameters that
    /// differ from the local view, close the session with a sealed
    /// `protocol_violation` notice; the pairing stays (section 10.1 item 2).
    ///
    /// # Errors
    /// [`SessionError`] for a Custodian, a ready already verified, a closed
    /// channel, or a frame that fails authentication, which closes the
    /// session without a notice.
    pub fn receive_ready(
        &mut self,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<ReadyOutcome, SessionError> {
        if self.role != EndpointRole::Requester {
            return Err(SessionError::RoleViolation);
        }
        if self.ready {
            return Err(SessionError::DuplicateReady);
        }
        let channel = self.channel.as_mut().ok_or(SessionError::Closed)?;
        let envelope = match channel.open(frame) {
            Ok(envelope) => envelope,
            Err(OpenError::SessionIntegrityFailure) => {
                self.channel = None;
                return Err(SessionError::IntegrityFailure);
            }
            Err(OpenError::AuthenticatedProtocolViolation(error)) => {
                return Ok(self.close_for_violation(AuthenticatedViolation::Wire(error)));
            }
        };
        Ok(match TypedMessage::from_envelope(envelope, now_ms) {
            Ok(TypedMessage::SessionReady(ready))
                if ready.parameters == self.expected_parameters =>
            {
                self.ready = true;
                ReadyOutcome::Verified
            }
            Ok(TypedMessage::SessionReady(_)) => {
                self.close_for_violation(AuthenticatedViolation::ReadyParameterMismatch)
            }
            Ok(TypedMessage::SessionClose(close)) => {
                self.channel = None;
                ReadyOutcome::PeerClosed(close.reason)
            }
            Ok(message) => self.close_for_violation(AuthenticatedViolation::UnexpectedPhase(
                message.message_type(),
            )),
            Err(error) => self.close_for_violation(AuthenticatedViolation::Semantic(error)),
        })
    }

    /// The first and only message of a session whose pairing this endpoint
    /// revoked: the sealed `session.close` with reason `pairing_revoked`
    /// (section 4.6 item 2). The session closes; no card session starts.
    ///
    /// # Errors
    /// [`SessionError`] after the Custodian sent `session.ready`, on a closed
    /// channel, or on a seal failure.
    pub fn send_revocation_notice(&mut self) -> Result<BinaryFrame, SessionError> {
        if self.role == EndpointRole::Proxy && self.ready {
            return Err(SessionError::DuplicateReady);
        }
        let sealed = self.seal(&TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::PairingRevoked,
        }));
        self.channel = None;
        sealed
    }

    /// Promote to a healthy endpoint once the Custodian sent, or the
    /// Requester verified, `session.ready`.
    ///
    /// # Errors
    /// [`SessionError`] before ready or when the channel is closed.
    pub fn into_established(mut self) -> Result<EstablishedEndpoint, SessionError> {
        if !self.ready {
            return Err(SessionError::ReadyIncomplete);
        }
        let channel = self.channel.take().ok_or(SessionError::Closed)?;
        Ok(EstablishedEndpoint::new(
            self.pair_id,
            channel,
            RappState {
                role: self.role,
                pairing: PairingState::PairedConnected,
                session: SessionState::Healthy,
            },
        ))
    }

    /// The session identifier derived from the handshake hash.
    #[must_use]
    pub const fn session_id(&self) -> super::SessionId {
        self.session_id
    }

    fn seal(&mut self, message: &TypedMessage) -> Result<BinaryFrame, SessionError> {
        let channel = self.channel.as_mut().ok_or(SessionError::Closed)?;
        let body = message.to_wire_body().map_err(SessionError::Message)?;
        channel
            .seal(message.message_type(), body)
            .map_err(SessionError::Crypto)
    }

    fn close_for_violation(&mut self, violation: AuthenticatedViolation) -> ReadyOutcome {
        let notice = self
            .seal(&TypedMessage::SessionClose(SessionCloseMessage {
                reason: CloseReason::ProtocolViolation,
            }))
            .ok();
        self.channel = None;
        ReadyOutcome::ViolationClosed { violation, notice }
    }
}

impl fmt::Debug for SessionAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionAuthentication")
            .field("role", &self.role)
            .field("pair_id", &self.pair_id)
            .field("session_id", &self.session_id)
            .field(
                "channel",
                &self.channel.as_ref().map(|_| "[secure channel]"),
            )
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

/// What the Requester's reading of the Custodian's first message gives.
#[derive(Debug)]
pub enum ReadyOutcome {
    /// The parameters match; promote with
    /// [`SessionAuthentication::into_established`].
    Verified,
    /// The Custodian closed the session in place of `session.ready`, as a
    /// revoking Custodian does; the session is closed.
    PeerClosed(CloseReason),
    /// Authenticated traffic violated the protocol; the session is closed
    /// and the pairing stays. Deliver `notice`, the sealed
    /// `protocol_violation` close, then drop the link.
    ViolationClosed {
        /// The violation.
        violation: AuthenticatedViolation,
        /// The sealed close, when it could be sealed.
        notice: Option<BinaryFrame>,
    },
}

/// Session establishment failure.
#[derive(Debug)]
pub enum SessionError {
    /// Call contradicts the stored pair's endpoint role.
    RoleViolation,
    /// The peer never confirmed that it stored the pairing, so the record
    /// opens no session (RAPP v26.10.29 section 4.3 item 4).
    StorageUnconfirmed,
    /// Handshake or channel cryptography failed.
    Crypto(CryptoError),
    /// A local message failed to encode.
    Message(MessageError),
    /// Frame failed authenticated decryption; not peer-attributable. The
    /// session closed.
    IntegrityFailure,
    /// Session handshake produced pairing-channel identifiers.
    UnexpectedPairId,
    /// `session.ready` was already sent or verified.
    DuplicateReady,
    /// Promotion was attempted before `session.ready`.
    ReadyIncomplete,
    /// Channel is already closed.
    Closed,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for SessionError {}
