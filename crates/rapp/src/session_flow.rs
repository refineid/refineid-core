//! Fresh mutually authenticated sessions for a stored pair.

use core::fmt;

use super::{
    BinaryFrame, CryptoError, EndpointRole, EstablishedEndpoint, HandshakeChannel, HandshakeRole,
    MessageError, OpenError, PairKeyMaterial, PairRecord, PairStore, PairStoreError, PairTombstone,
    PairingState, RappState, SecureChannel, SessionHandshakeParameters, SessionParameters,
    SessionReadyMessage, SessionState, TransportProfile, TypedMessage,
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
    /// transport profile of the connection (RAPP v26.10.9 §4.3).
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

    /// Complete Noise and enter mutual parameter-echo verification.
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
            local_ready_sent: false,
            peer_ready_received: false,
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

/// Authenticated session which is not healthy until both parameter echoes are
/// sent and verified.
pub struct SessionAuthentication {
    role: EndpointRole,
    pair_id: super::PairId,
    session_id: super::SessionId,
    expected_parameters: SessionParameters,
    channel: Option<SecureChannel>,
    local_ready_sent: bool,
    peer_ready_received: bool,
    _local_keys: PairKeyMaterial,
}

impl SessionAuthentication {
    /// Send local exact parameters with a caller-generated fresh nonce.
    ///
    /// # Errors
    /// [`SessionError`] on a duplicate ready, a closed channel, or a seal
    /// failure.
    pub fn send_ready(&mut self, nonce: [u8; 32]) -> Result<BinaryFrame, SessionError> {
        if self.local_ready_sent {
            return Err(SessionError::DuplicateReady);
        }
        let message = TypedMessage::SessionReady(SessionReadyMessage {
            parameters: self.expected_parameters.clone(),
            nonce,
        });
        let channel = self.channel.as_mut().ok_or(SessionError::Closed)?;
        let body = message.to_wire_body().map_err(SessionError::Message)?;
        let frame = channel
            .seal(message.message_type(), body)
            .map_err(SessionError::Crypto)?;
        self.local_ready_sent = true;
        Ok(frame)
    }

    /// Verify the peer's authenticated exact parameter echo. Any decrypted
    /// mismatch revokes this pair immediately on its first occurrence.
    ///
    /// # Errors
    /// [`SessionError`] on an integrity failure, an authenticated violation
    /// that revokes the pairing, or a failed tombstone write.
    pub fn receive_ready<S: PairStore>(
        &mut self,
        store: &mut S,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<(), SessionError<S::Error>> {
        if self.peer_ready_received {
            return self.revoke(store, now_ms, SessionError::DuplicateReady);
        }
        let channel = self.channel.as_mut().ok_or(SessionError::Closed)?;
        let envelope = match channel.open(frame) {
            Ok(envelope) => envelope,
            Err(OpenError::SessionIntegrityFailure) => {
                self.channel = None;
                return Err(SessionError::IntegrityFailure);
            }
            Err(OpenError::AuthenticatedProtocolViolation(error)) => {
                return self.revoke(store, now_ms, SessionError::AuthenticatedWire(error));
            }
        };
        let message = match TypedMessage::from_envelope(envelope, self.pair_id, now_ms) {
            Ok(message) => message,
            Err(error) => return self.revoke(store, now_ms, SessionError::Message(error)),
        };
        let TypedMessage::SessionReady(ready) = message else {
            return self.revoke(store, now_ms, SessionError::UnexpectedMessage);
        };
        if ready.parameters != self.expected_parameters {
            return self.revoke(store, now_ms, SessionError::ParameterMismatch);
        }
        self.peer_ready_received = true;
        Ok(())
    }

    /// Promote to a healthy endpoint only after both directions verified ready.
    ///
    /// # Errors
    /// [`SessionError`] before both ready echoes verify or when the channel
    /// is already closed.
    pub fn into_established(mut self) -> Result<EstablishedEndpoint, SessionError> {
        if !self.local_ready_sent || !self.peer_ready_received {
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
                operation: super::OperationState::None,
                requires_user_intent: false,
            },
        ))
    }

    /// Fresh session identifier used in operation request hashes.
    #[must_use]
    pub const fn session_id(&self) -> super::SessionId {
        self.session_id
    }

    fn revoke<S: PairStore>(
        &mut self,
        store: &mut S,
        now_ms: u64,
        _cause: SessionError<()>,
    ) -> Result<(), SessionError<S::Error>> {
        self.channel = None;
        store
            .revoke(PairTombstone {
                pair_id: self.pair_id,
                revoked_at_ms: now_ms,
            })
            .map_err(SessionError::PairRevocationFailed)?;
        Err(SessionError::PairRevoked)
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
            .field("local_ready_sent", &self.local_ready_sent)
            .field("peer_ready_received", &self.peer_ready_received)
            .finish_non_exhaustive()
    }
}

/// Session establishment failure.
#[derive(Debug)]
pub enum SessionError<E = ()> {
    /// Call contradicts the stored pair's endpoint role.
    RoleViolation,
    /// Handshake or channel cryptography failed.
    Crypto(CryptoError),
    /// Authenticated message failed semantic decoding.
    Message(MessageError),
    /// Successfully decrypted envelope violated the wire schema.
    AuthenticatedWire(super::WireError),
    /// Frame failed authenticated decryption; not peer-attributable.
    IntegrityFailure,
    /// Session handshake produced pairing-channel identifiers.
    UnexpectedPairId,
    /// A second ready echo arrived or was sent.
    DuplicateReady,
    /// Message type is not legal during ready verification.
    UnexpectedMessage,
    /// Peer's ready parameters differ from the local view.
    ParameterMismatch,
    /// Promotion was attempted before both ready echoes verified.
    ReadyIncomplete,
    /// Channel is already closed.
    Closed,
    /// Pair store could not persist the revocation tombstone.
    PairRevocationFailed(PairStoreError<E>),
    /// Pairing was revoked by an authenticated violation.
    PairRevoked,
}

impl<E: fmt::Debug> fmt::Display for SessionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl<E: fmt::Debug> core::error::Error for SessionError<E> {}
