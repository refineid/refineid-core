//! Manual pairing from one-use offer through mutually confirmed grants.

use core::fmt;

use super::{
    BinaryFrame, CryptoError, EndpointRole, HandshakeChannel, HandshakeRole, MessageError,
    NegotiatedParameters, OpenError, PairKeyMaterial, PairRecord, PairRecordError,
    PairTransportBinding, PairingConfirmMessage, PairingHandshakeParameters, PairingHelloMessage,
    PairingOffer, PairingOfferError, ProfileName, SecureChannel, TransportCandidate, TypedMessage,
    compute_grants_hash,
};

/// In-progress mandatory Noise `XXpsk3` handshake.
pub struct PairingHandshake {
    role: EndpointRole,
    offer: PairingOffer,
    offer_hash: [u8; 32],
    candidate: TransportCandidate,
    offered_profiles: Vec<ProfileName>,
    local_keys: PairKeyMaterial,
    channel: HandshakeChannel,
}

impl PairingHandshake {
    /// Creates one handshake for exactly one offered transport candidate.
    ///
    /// # Errors
    /// [`PairingAttemptFailure`] returning the still-live offer when the
    /// candidate is not unique, a profile is unregistered, or the handshake
    /// cannot be constructed.
    #[allow(
        clippy::result_large_err,
        reason = "the failure returns ownership of the still-live offer so a later candidate attempt can reuse it"
    )]
    pub fn begin(
        role: EndpointRole,
        offer: PairingOffer,
        candidate_id: &str,
        local_keys: PairKeyMaterial,
    ) -> Result<Self, PairingAttemptFailure> {
        let matches = offer
            .transports
            .iter()
            .filter(|candidate| candidate.candidate_id == candidate_id)
            .cloned()
            .collect::<Vec<_>>();
        let [candidate] = matches.as_slice() else {
            return Err(PairingAttemptFailure::new(
                PairingError::CandidateNotUnique,
                offer,
            ));
        };
        let candidate = candidate.clone();
        let offered_profiles = match parse_profile_names(&offer.profiles) {
            Ok(profiles) => profiles,
            Err(error) => return Err(PairingAttemptFailure::new(error, offer)),
        };
        let offer_hash = match offer.offer_hash().map_err(PairingError::Offer) {
            Ok(hash) => hash,
            Err(error) => return Err(PairingAttemptFailure::new(error, offer)),
        };
        let channel = match HandshakeChannel::pairing(&PairingHandshakeParameters {
            role: handshake_role(role),
            local_keys: &local_keys,
            pairing_secret: offer.pairing_secret(),
            offer_hash,
            transport_profile: &candidate.profile,
        })
        .map_err(PairingError::Crypto)
        {
            Ok(channel) => channel,
            Err(error) => return Err(PairingAttemptFailure::new(error, offer)),
        };
        Ok(Self {
            role,
            offer,
            offer_hash,
            candidate,
            offered_profiles,
            local_keys,
            channel,
        })
    }

    /// Produce the next role-specific empty-payload handshake frame.
    ///
    /// # Errors
    /// [`PairingError::Crypto`] when it is not this role's turn or the
    /// handshake already failed.
    pub fn write_message(&mut self) -> Result<BinaryFrame, PairingError> {
        self.channel.write_message().map_err(PairingError::Crypto)
    }

    /// Consume one role-specific handshake frame and reject payload bytes.
    ///
    /// # Errors
    /// [`PairingError::Crypto`] on a failed handshake message or a non-empty
    /// payload.
    pub fn read_message(&mut self, frame: &BinaryFrame) -> Result<(), PairingError> {
        self.channel
            .read_message(frame)
            .map_err(PairingError::Crypto)
    }

    /// Whether the Noise handshake has completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.channel.is_complete()
    }

    /// End an unauthenticated candidate attempt without consuming the active
    /// pairing offer. The caller may start another candidate only after recovering
    /// this value, so two attempts cannot share the one-use secret.
    #[must_use]
    pub fn abort(self) -> PairingOffer {
        self.offer
    }

    /// Complete Noise, destroy the pairing secret, and enter authenticated explicit
    /// confirmation. If Noise is not complete, the failure returns ownership
    /// of the still-live offer for a later candidate attempt.
    ///
    /// # Errors
    /// [`PairingAttemptFailure`] returning the still-live offer when Noise is
    /// incomplete or the channel identifiers are missing.
    #[allow(
        clippy::result_large_err,
        reason = "the failure returns ownership of the still-live offer so a later candidate attempt can reuse it"
    )]
    pub fn into_confirmation(self) -> Result<PairingConfirmation, PairingAttemptFailure> {
        let Self {
            role,
            offer,
            offer_hash,
            candidate,
            offered_profiles,
            local_keys,
            channel,
        } = self;
        let completion = match channel.complete().map_err(PairingError::Crypto) {
            Ok(completion) => completion,
            Err(error) => return Err(PairingAttemptFailure::new(error, offer)),
        };
        let Some(pair_id) = completion.pair_id else {
            return Err(PairingAttemptFailure::new(
                PairingError::MissingPairId,
                offer,
            ));
        };
        let Some(rendezvous_token) = completion.rendezvous_token else {
            return Err(PairingAttemptFailure::new(
                PairingError::MissingPairId,
                offer,
            ));
        };
        drop(offer);
        Ok(PairingConfirmation {
            role,
            pair_id,
            rendezvous_token,
            offer_hash,
            candidate,
            offered_profiles,
            local_keys,
            remote_static_public: completion.remote_static_key,
            channel: completion.secure_channel,
            local_hello_sent: false,
            peer_hello: None,
            local_grants: None,
            peer_grants: None,
        })
    }
}

/// An unauthenticated candidate failure that returns the active pairing offer.
///
/// The offer is intentionally not printable or clonable. Recover it with
/// [`Self::into_parts`] before beginning a replacement candidate attempt.
pub struct PairingAttemptFailure {
    error: PairingError,
    offer: PairingOffer,
}

impl PairingAttemptFailure {
    const fn new(error: PairingError, offer: PairingOffer) -> Self {
        Self { error, offer }
    }

    /// Failure that ended the candidate attempt.
    #[must_use]
    pub const fn error(&self) -> &PairingError {
        &self.error
    }

    /// Recover the failure and the still-live offer.
    #[must_use]
    pub fn into_parts(self) -> (PairingError, PairingOffer) {
        (self.error, self.offer)
    }
}

impl fmt::Debug for PairingAttemptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingAttemptFailure")
            .field("error", &self.error)
            .field("offer", &"<redacted active offer>")
            .finish()
    }
}

impl fmt::Debug for PairingHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingHandshake")
            .field("role", &self.role)
            .field("offer", &"[secret-bearing offer]")
            .field("candidate", &self.candidate.candidate_id)
            .field("offered_profiles", &self.offered_profiles)
            .field("local_keys", &"[pair key material]")
            .field("complete", &self.channel.is_complete())
            .finish_non_exhaustive()
    }
}

/// Authenticated pairing channel awaiting hello and equal grant confirmation.
pub struct PairingConfirmation {
    role: EndpointRole,
    pair_id: super::PairId,
    rendezvous_token: super::RendezvousToken,
    offer_hash: [u8; 32],
    candidate: TransportCandidate,
    offered_profiles: Vec<ProfileName>,
    local_keys: PairKeyMaterial,
    remote_static_public: [u8; 32],
    channel: SecureChannel,
    local_hello_sent: bool,
    peer_hello: Option<PairingHelloMessage>,
    local_grants: Option<Vec<ProfileName>>,
    peer_grants: Option<Vec<ProfileName>>,
}

impl PairingConfirmation {
    /// Pair identifier derived from the authenticated transcript.
    #[must_use]
    pub const fn pair_id(&self) -> super::PairId {
        self.pair_id
    }

    /// Send the local peer label and exact negotiated-parameter echo.
    ///
    /// # Errors
    /// [`PairingError`] on a duplicate hello or a seal failure.
    pub fn send_hello(
        &mut self,
        display_name: String,
        platform: String,
    ) -> Result<BinaryFrame, PairingError> {
        if self.local_hello_sent {
            return Err(PairingError::DuplicateMessage);
        }
        let requested_profiles =
            (self.role == EndpointRole::Requester).then(|| self.offered_profiles.clone());
        let message = TypedMessage::PairingHello(PairingHelloMessage {
            parameters: NegotiatedParameters {
                offer_hash: self.offer_hash,
                transport_profile: self.candidate.profile.clone(),
                candidate_id: self.candidate.candidate_id.clone(),
            },
            display_name,
            platform,
            requested_profiles,
        });
        let frame = seal_typed(&mut self.channel, &message)?;
        self.local_hello_sent = true;
        Ok(frame)
    }

    /// Receive and verify the authenticated peer hello and full parameter echo.
    ///
    /// # Errors
    /// [`PairingError`] on a duplicate or unexpected message, a parameter
    /// mismatch, or a role violation.
    ///
    /// # Panics
    /// Never; the hello is stored before it is borrowed back.
    pub fn receive_hello(
        &mut self,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<&PairingHelloMessage, PairingError> {
        if self.peer_hello.is_some() {
            return Err(PairingError::DuplicateMessage);
        }
        let TypedMessage::PairingHello(hello) =
            open_typed(&mut self.channel, frame, self.pair_id, now_ms)?
        else {
            return Err(PairingError::UnexpectedMessage);
        };
        let expected = NegotiatedParameters {
            offer_hash: self.offer_hash,
            transport_profile: self.candidate.profile.clone(),
            candidate_id: self.candidate.candidate_id.clone(),
        };
        if hello.parameters != expected {
            return Err(PairingError::ParameterMismatch);
        }
        match self.role {
            EndpointRole::Requester if hello.requested_profiles.is_some() => {
                return Err(PairingError::RoleViolation);
            }
            EndpointRole::Proxy => {
                let requested = hello
                    .requested_profiles
                    .as_ref()
                    .ok_or(PairingError::RoleViolation)?;
                if requested != &self.offered_profiles {
                    return Err(PairingError::GrantMismatch);
                }
            }
            EndpointRole::Requester => {}
        }
        self.peer_hello = Some(hello);
        Ok(self.peer_hello.as_ref().expect("just inserted"))
    }

    /// Send the locally confirmed, sorted grant set.
    ///
    /// # Errors
    /// [`PairingError`] before both hellos complete, on a duplicate
    /// confirmation, an invalid grant set, or a grant mismatch.
    pub fn send_confirmation(
        &mut self,
        mut granted_profiles: Vec<ProfileName>,
    ) -> Result<BinaryFrame, PairingError> {
        if !self.local_hello_sent || self.peer_hello.is_none() {
            return Err(PairingError::HelloIncomplete);
        }
        if self.local_grants.is_some() {
            return Err(PairingError::DuplicateMessage);
        }
        validate_grants(&granted_profiles, &self.offered_profiles)?;
        granted_profiles
            .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        if let Some(peer) = self.peer_grants.as_ref()
            && peer != &granted_profiles
        {
            return Err(PairingError::GrantMismatch);
        }
        let message = TypedMessage::PairingConfirm(PairingConfirmMessage {
            granted_profiles: granted_profiles.clone(),
        });
        let frame = seal_typed(&mut self.channel, &message)?;
        self.local_grants = Some(granted_profiles);
        Ok(frame)
    }

    /// Receive the peer's explicit grant confirmation.
    ///
    /// # Errors
    /// [`PairingError`] on a duplicate or unexpected message, an invalid
    /// grant set, or a grant mismatch.
    ///
    /// # Panics
    /// Never; the grant set is stored before it is borrowed back.
    pub fn receive_confirmation(
        &mut self,
        frame: &BinaryFrame,
        now_ms: u64,
    ) -> Result<&[ProfileName], PairingError> {
        if self.peer_grants.is_some() {
            return Err(PairingError::DuplicateMessage);
        }
        let TypedMessage::PairingConfirm(confirm) =
            open_typed(&mut self.channel, frame, self.pair_id, now_ms)?
        else {
            return Err(PairingError::UnexpectedMessage);
        };
        validate_grants(&confirm.granted_profiles, &self.offered_profiles)?;
        if let Some(local) = self.local_grants.as_ref()
            && local != &confirm.granted_profiles
        {
            return Err(PairingError::GrantMismatch);
        }
        self.peer_grants = Some(confirm.granted_profiles);
        Ok(self.peer_grants.as_deref().expect("just inserted"))
    }

    /// Build the only persistable record after both explicit confirmations.
    /// Dropping this value closes and destroys the pairing-channel keys.
    ///
    /// # Errors
    /// [`PairingError`] before both hellos and both equal confirmations
    /// complete, or when the record cannot be constructed.
    pub fn into_pair_record(self, created_at_ms: u64) -> Result<PairRecord, PairingError> {
        if !self.local_hello_sent || self.peer_hello.is_none() {
            return Err(PairingError::HelloIncomplete);
        }
        let local_grants = self
            .local_grants
            .ok_or(PairingError::ConfirmationIncomplete)?;
        let peer_grants = self
            .peer_grants
            .ok_or(PairingError::ConfirmationIncomplete)?;
        if local_grants != peer_grants {
            return Err(PairingError::GrantMismatch);
        }
        let grants_hash = compute_grants_hash(&local_grants).map_err(PairingError::Crypto)?;
        let local_private = self.local_keys.with_private_key(|bytes| *bytes);
        PairRecord::new(
            self.pair_id,
            self.rendezvous_token,
            self.role,
            local_private,
            *self.local_keys.public_key(),
            self.remote_static_public,
            grants_hash,
            local_grants,
            PairTransportBinding {
                profile: self.candidate.profile,
                candidate_id: self.candidate.candidate_id,
                parameters: self.candidate.parameters,
            },
            created_at_ms,
        )
        .map_err(PairingError::PairRecord)
    }
}

impl fmt::Debug for PairingConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingConfirmation")
            .field("role", &self.role)
            .field("pair_id", &self.pair_id)
            .field("candidate", &self.candidate.candidate_id)
            .field("local_keys", &"[pair key material]")
            .field("channel", &"[secure channel]")
            .field("local_hello_sent", &self.local_hello_sent)
            .field("peer_hello_received", &self.peer_hello.is_some())
            .field("local_grants", &self.local_grants)
            .field("peer_grants", &self.peer_grants)
            .finish_non_exhaustive()
    }
}

pub(crate) const fn handshake_role(role: EndpointRole) -> HandshakeRole {
    match role {
        EndpointRole::Requester => HandshakeRole::Initiator,
        EndpointRole::Proxy => HandshakeRole::Responder,
    }
}

fn parse_profile_names(names: &[String]) -> Result<Vec<ProfileName>, PairingError> {
    let mut profiles = names
        .iter()
        .map(|name| ProfileName::parse(name).ok_or(PairingError::UnsupportedProfile))
        .collect::<Result<Vec<_>, _>>()?;
    validate_grants(&profiles, &profiles)?;
    profiles.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    Ok(profiles)
}

fn validate_grants(grants: &[ProfileName], offered: &[ProfileName]) -> Result<(), PairingError> {
    let mut names = grants
        .iter()
        .map(|profile| profile.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    if grants.is_empty()
        || names.windows(2).any(|pair| pair[0] == pair[1])
        || grants.iter().any(|grant| !offered.contains(grant))
    {
        return Err(PairingError::InvalidGrantSet);
    }
    Ok(())
}

fn seal_typed(
    channel: &mut SecureChannel,
    message: &TypedMessage,
) -> Result<BinaryFrame, PairingError> {
    let body = message.to_wire_body().map_err(PairingError::Message)?;
    channel
        .seal(message.message_type(), body)
        .map_err(PairingError::Crypto)
}

fn open_typed(
    channel: &mut SecureChannel,
    frame: &BinaryFrame,
    pair_id: super::PairId,
    now_ms: u64,
) -> Result<TypedMessage, PairingError> {
    let envelope = channel.open(frame).map_err(PairingError::Open)?;
    TypedMessage::from_envelope(envelope, pair_id, now_ms).map_err(PairingError::Message)
}

/// Pairing attempt failure. Once Noise authenticated the peer, semantic/open
/// violations abort and invalidate this offer but do not create a pair record.
#[derive(Debug, Clone, Copy)]
pub enum PairingError {
    /// Offer failed structural or policy validation.
    Offer(PairingOfferError),
    /// Handshake or channel cryptography failed.
    Crypto(CryptoError),
    /// Authenticated frame failed decryption or envelope validation.
    Open(OpenError),
    /// Authenticated message failed semantic decoding.
    Message(MessageError),
    /// Pair record could not be constructed.
    PairRecord(PairRecordError),
    /// Candidate identifier matches zero or several offered candidates.
    CandidateNotUnique,
    /// Offer names a profile outside the registry.
    UnsupportedProfile,
    /// Completed handshake produced no pairing-channel identifiers.
    MissingPairId,
    /// The same confirmation-phase message arrived or was sent twice.
    DuplicateMessage,
    /// Message type is not legal in the confirmation phase.
    UnexpectedMessage,
    /// Peer's negotiated-parameter echo differs from the local view.
    ParameterMismatch,
    /// Requested-profile field contradicts the sender's role.
    RoleViolation,
    /// Confirmation was attempted before both hellos completed.
    HelloIncomplete,
    /// Pair record was requested before both confirmations.
    ConfirmationIncomplete,
    /// Grant set is empty, duplicated, or outside the offered set.
    InvalidGrantSet,
    /// The two granted sets are not equal.
    GrantMismatch,
}

impl fmt::Display for PairingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for PairingError {}
