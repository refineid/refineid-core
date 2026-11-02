//! Fresh mutually authenticated sessions for a stored pair.

use core::fmt;

use super::{
    AuthenticatedViolation, BinaryFrame, CloseReason, CryptoError, DisplayName, EndpointRole,
    EstablishedEndpoint, HandshakeChannel, HandshakeRole, MessageError, OpenError, PairKeyMaterial,
    PairRecord, PairingState, RappState, SecureChannel, SessionCloseMessage,
    SessionHandshakeParameters, SessionHelloMessage, SessionParameters, SessionReadyMessage,
    SessionState, TransportProfile, TypedMessage,
};

/// Evidence supplied by the requester integration that this dial is one
/// the requester may make (RAPP v26.11.2 section 8.3): the custodian
/// appeared, a local consumer asked for the card, a redial within the
/// redial window, or a revoking pairing's one attempt (section 4.6 item 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExplicitUserIntent(());

impl ExplicitUserIntent {
    /// Record at the platform boundary that the dial is one section 8.3
    /// admits.
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
    /// transport profile of the connection (RAPP v26.11.2 §4.3).
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

    /// Proxy-side response to one incoming connection over `transport`. A
    /// custodian never dials.
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
            hello_sent: false,
            close_sent: None,
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
/// the Custodian sends it, the Requester verifies it and answers with
/// `session.hello` (RAPP v26.11.2 section 7.1 items 5 and 6). A revoking
/// endpoint sends the `pairing_revoked` close in their place (section 4.6
/// item 2).
pub struct SessionAuthentication {
    role: EndpointRole,
    pair_id: super::PairId,
    session_id: super::SessionId,
    expected_parameters: SessionParameters,
    channel: Option<SecureChannel>,
    ready: bool,
    hello_sent: bool,
    close_sent: Option<CloseReason>,
    _local_keys: PairKeyMaterial,
}

impl SessionAuthentication {
    /// The Custodian's `session.ready`: the exact session parameters with a
    /// caller-generated fresh nonce and the Custodian's current
    /// `display_name` (section 4.3 item 4). The session is then healthy.
    ///
    /// # Errors
    /// [`SessionError`] for a Requester, a second ready, a closed channel, or
    /// a seal failure.
    pub fn send_ready(
        &mut self,
        nonce: [u8; 32],
        display_name: &DisplayName,
    ) -> Result<BinaryFrame, SessionError> {
        if self.role != EndpointRole::Proxy {
            return Err(SessionError::RoleViolation);
        }
        if self.ready {
            return Err(SessionError::DuplicateReady);
        }
        if self.close_sent.is_some() {
            return Err(SessionError::Closed);
        }
        let frame = self.seal(&TypedMessage::SessionReady(SessionReadyMessage {
            parameters: self.expected_parameters.clone(),
            nonce,
            display_name: display_name.clone(),
        }))?;
        self.ready = true;
        Ok(frame)
    }

    /// The Requester reads the Custodian's first message: `session.ready`,
    /// or a close in its place. Anything else, ready parameters that differ
    /// from the local view, and a missing, blank or over-long
    /// `display_name`, close the session with a sealed `protocol_violation`
    /// notice; the pairing stays (section 4.3 item 4, section 10.1 item 2).
    /// A verified ready gives the Custodian's display name; answer it with
    /// [`Self::send_hello`].
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
        if self.close_sent.is_some() {
            return Err(SessionError::Closed);
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
                ReadyOutcome::Verified {
                    custodian_name: ready.display_name,
                }
            }
            Ok(TypedMessage::SessionReady(_)) => {
                self.close_for_violation(AuthenticatedViolation::ReadyParameterMismatch)
            }
            Ok(TypedMessage::SessionClose(close)) => {
                let echo = self
                    .seal(&TypedMessage::SessionClose(SessionCloseMessage {
                        reason: close.reason,
                    }))
                    .ok();
                self.channel = None;
                ReadyOutcome::PeerClosed {
                    reason: close.reason,
                    echo,
                }
            }
            Ok(message) => self.close_for_violation(AuthenticatedViolation::UnexpectedPhase(
                message.message_type(),
            )),
            Err(error) => self.close_for_violation(AuthenticatedViolation::Semantic(error)),
        })
    }

    /// The Requester's `session.hello`, its first message once it verified
    /// `session.ready`, carrying its current `display_name` (section 7.1
    /// item 6). The Requester promotes the session only after sending it.
    ///
    /// # Errors
    /// [`SessionError`] for a Custodian, before the ready is verified, on a
    /// second hello, a closed channel, or a seal failure.
    pub fn send_hello(&mut self, display_name: &DisplayName) -> Result<BinaryFrame, SessionError> {
        if self.role != EndpointRole::Requester {
            return Err(SessionError::RoleViolation);
        }
        if !self.ready {
            return Err(SessionError::ReadyIncomplete);
        }
        if self.hello_sent {
            return Err(SessionError::DuplicateHello);
        }
        let frame = self.seal(&TypedMessage::SessionHello(SessionHelloMessage {
            display_name: display_name.clone(),
        }))?;
        self.hello_sent = true;
        Ok(frame)
    }

    /// The first and only message of a session whose pairing this endpoint
    /// revoked: the sealed `session.close` with reason `pairing_revoked`
    /// (section 4.6 item 2). No card session starts; the session waits for
    /// the peer's echo, read with [`Self::receive_close_echo`] (section 7.1
    /// item 7).
    ///
    /// # Errors
    /// [`SessionError`] after the Custodian sent `session.ready`, on a closed
    /// channel, or on a seal failure.
    pub fn send_revocation_notice(&mut self) -> Result<BinaryFrame, SessionError> {
        if self.role == EndpointRole::Proxy && self.ready {
            return Err(SessionError::DuplicateReady);
        }
        if self.close_sent.is_some() {
            return Err(SessionError::Closed);
        }
        let sealed = self.seal(&TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::PairingRevoked,
        }));
        match sealed {
            Ok(_) => self.close_sent = Some(CloseReason::PairingRevoked),
            Err(_) => self.channel = None,
        }
        sealed
    }

    /// One frame from the peer while this endpoint waits for the echo of
    /// the close it sent in place of `session.ready` or `session.hello`
    /// (section 7.1 item 7): a close is the echo, or a close that crossed
    /// this endpoint's, and ends the session unanswered; any other
    /// authenticated message, the Custodian's `session.ready` and
    /// `card.status` included, is ignored; a frame that fails
    /// authentication ends the session.
    ///
    /// # Errors
    /// [`SessionError::Closed`] when no close of this endpoint awaits its
    /// echo.
    pub fn receive_close_echo(
        &mut self,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<CloseEcho, SessionError> {
        let sent = self.close_sent.ok_or(SessionError::Closed)?;
        let channel = self.channel.as_mut().ok_or(SessionError::Closed)?;
        let outcome = match channel
            .open(frame)
            .map(|envelope| TypedMessage::from_envelope(envelope, now_ms))
        {
            Ok(Ok(TypedMessage::SessionClose(close))) => CloseEcho::Acknowledged {
                reason: close.reason,
                crossing: close.reason != sent,
            },
            Ok(_) => return Ok(CloseEcho::Ignored),
            Err(_) => CloseEcho::Closed,
        };
        self.channel = None;
        Ok(outcome)
    }

    /// Promote to a healthy endpoint once the Custodian sent
    /// `session.ready`, or the Requester verified it and sent
    /// `session.hello`.
    ///
    /// # Errors
    /// [`SessionError`] before ready or the Requester's hello, or when the
    /// channel is closed.
    pub fn into_established(mut self) -> Result<EstablishedEndpoint, SessionError> {
        if self.close_sent.is_some() {
            return Err(SessionError::Closed);
        }
        if !self.ready || (self.role == EndpointRole::Requester && !self.hello_sent) {
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
        if notice.is_some() {
            self.close_sent = Some(CloseReason::ProtocolViolation);
        } else {
            self.channel = None;
        }
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
            .field("hello_sent", &self.hello_sent)
            .finish_non_exhaustive()
    }
}

/// What the Requester's reading of the Custodian's first message gives.
#[derive(Debug)]
pub enum ReadyOutcome {
    /// The parameters match and the Custodian named itself: keep the name
    /// in the pair record (section 4.3 item 4), send
    /// [`SessionAuthentication::send_hello`], then promote with
    /// [`SessionAuthentication::into_established`].
    Verified {
        /// The Custodian's current display name.
        custodian_name: DisplayName,
    },
    /// The Custodian closed the session in place of `session.ready`, as a
    /// revoking Custodian does; the session is closed. Deliver `echo`, the
    /// close that acknowledges it, then drop the link (section 7.1 item 7).
    PeerClosed {
        /// The received reason.
        reason: CloseReason,
        /// The sealed echo, when it could be sealed.
        echo: Option<BinaryFrame>,
    },
    /// Authenticated traffic violated the protocol; the session closes and
    /// the pairing stays. Deliver `notice`, the sealed `protocol_violation`
    /// close, wait for its echo with
    /// [`SessionAuthentication::receive_close_echo`], then drop the link.
    ViolationClosed {
        /// The violation.
        violation: AuthenticatedViolation,
        /// The sealed close, when it could be sealed.
        notice: Option<BinaryFrame>,
    },
}

/// One frame read while waiting for the echo of this endpoint's close
/// (section 7.1 item 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseEcho {
    /// The echo arrived, or, with `crossing`, a close with another reason
    /// that crossed this endpoint's; act on a crossing reason. The session
    /// closed; drop the link.
    Acknowledged {
        /// The received reason.
        reason: CloseReason,
        /// The received reason differs from the one this endpoint sent.
        crossing: bool,
    },
    /// Another message; it is ignored and the wait goes on.
    Ignored,
    /// A frame failed authentication; the session closed.
    Closed,
}

/// Session establishment failure.
#[derive(Debug)]
pub enum SessionError {
    /// Call contradicts the stored pair's endpoint role.
    RoleViolation,
    /// The peer never confirmed that it stored the pairing, so the record
    /// opens no session (RAPP v26.11.2 section 4.3 item 4).
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
    /// `session.hello` was already sent.
    DuplicateHello,
    /// Promotion was attempted before `session.ready`, or, on the
    /// Requester, before `session.hello`.
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
