//! Manual pairing from one-use offer through mutually confirmed grants.

use core::fmt;

use super::{
    BinaryFrame, CryptoError, EndpointRole, HandshakeChannel, HandshakeRole, MessageError,
    NegotiatedParameters, OpenError, PairKeyMaterial, PairRecord, PairRecordError,
    PairingConfirmMessage, PairingHandshakeParameters, PairingHelloMessage, PairingOffer,
    PairingOfferError, PairingSecret, PairingStoredMessage, ProfileName, SecureChannel,
    TransportCandidate, TypedMessage, compute_grants_hash,
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
        pairing_secret: &PairingSecret,
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
            pairing_secret,
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
        drop(offer);
        Ok(PairingConfirmation {
            role,
            pair_id,
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
        let TypedMessage::PairingHello(hello) = open_typed(&mut self.channel, frame, now_ms)?
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
        let TypedMessage::PairingConfirm(confirm) = open_typed(&mut self.channel, frame, now_ms)?
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

    /// Build the only persistable record after both explicit confirmations,
    /// keeping the pairing channel open for the storage confirmation
    /// (section 4.3 item 4). The caller stores the record durably and then
    /// confirms the storage with [`PairingStorage::send_stored`].
    ///
    /// # Errors
    /// [`PairingError`] before both hellos and both equal confirmations
    /// complete, or when the record cannot be constructed.
    pub fn into_storage(
        self,
        created_at_ms: u64,
    ) -> Result<(PairRecord, PairingStorage), PairingError> {
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
        let record = PairRecord::new(
            self.pair_id,
            self.role,
            local_private,
            *self.local_keys.public_key(),
            self.remote_static_public,
            grants_hash,
            local_grants,
            created_at_ms,
        )
        .map_err(PairingError::PairRecord)?
        .awaiting_storage_confirmation();
        Ok((
            record,
            PairingStorage {
                pair_id: self.pair_id,
                channel: self.channel,
                local_stored_sent: false,
                peer_stored: false,
            },
        ))
    }
}

/// The pairing between equal confirmation and activity: each endpoint
/// stores its record and confirms the storage over the still-open channel
/// (section 4.3 item 4).
///
/// Dropping this value closes and destroys the pairing-channel keys. A
/// value dropped before [`Self::into_active`] belongs to a pairing the peer
/// never confirmed; the caller revokes the record it stored (section 4.6).
pub struct PairingStorage {
    pair_id: super::PairId,
    channel: SecureChannel,
    local_stored_sent: bool,
    peer_stored: bool,
}

impl PairingStorage {
    /// Pair identifier derived from the authenticated transcript.
    #[must_use]
    pub const fn pair_id(&self) -> super::PairId {
        self.pair_id
    }

    /// Confirm to the peer that the local record is durably stored. Called
    /// once, after the store reported the record written.
    ///
    /// # Errors
    /// [`PairingError::DuplicateMessage`] on a second confirmation, or a
    /// seal failure.
    pub fn send_stored(&mut self) -> Result<BinaryFrame, PairingError> {
        if self.local_stored_sent {
            return Err(PairingError::DuplicateMessage);
        }
        let frame = self.seal_stored(self.pair_id)?;
        self.local_stored_sent = true;
        Ok(frame)
    }

    /// Receive the peer's storage confirmation. A pair identifier other
    /// than the derived one is an authenticated protocol violation.
    ///
    /// # Errors
    /// [`PairingError`] on a duplicate or unexpected message, or
    /// [`PairingError::PairIdMismatch`].
    pub fn receive_stored(&mut self, frame: &BinaryFrame, now_ms: u64) -> Result<(), PairingError> {
        if self.peer_stored {
            return Err(PairingError::DuplicateMessage);
        }
        let TypedMessage::PairingStored(stored) = open_typed(&mut self.channel, frame, now_ms)?
        else {
            return Err(PairingError::UnexpectedMessage);
        };
        if stored.pair_id != self.pair_id {
            return Err(PairingError::PairIdMismatch);
        }
        self.peer_stored = true;
        Ok(())
    }

    /// Whether both the local confirmation was sent and the peer's received.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        self.local_stored_sent && self.peer_stored
    }

    /// Close the pairing channel and prove the pairing active: the only way
    /// to obtain an [`ActivePairing`].
    ///
    /// # Errors
    /// [`PairingError::StorageUnconfirmed`] before both confirmations.
    pub fn into_active(self) -> Result<ActivePairing, PairingError> {
        if !self.is_confirmed() {
            return Err(PairingError::StorageUnconfirmed);
        }
        Ok(ActivePairing {
            pair_id: self.pair_id,
        })
    }

    fn seal_stored(&mut self, pair_id: super::PairId) -> Result<BinaryFrame, PairingError> {
        seal_typed(
            &mut self.channel,
            &TypedMessage::PairingStored(PairingStoredMessage { pair_id }),
        )
    }

    /// A storage confirmation naming another pairing, for the mismatch test.
    #[cfg(test)]
    fn send_stored_as(&mut self, pair_id: super::PairId) -> Result<BinaryFrame, PairingError> {
        self.seal_stored(pair_id)
    }
}

impl fmt::Debug for PairingStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingStorage")
            .field("pair_id", &self.pair_id)
            .field("channel", &"[secure channel]")
            .field("local_stored_sent", &self.local_stored_sent)
            .field("peer_stored", &self.peer_stored)
            .finish()
    }
}

/// Proof that both endpoints stored the pairing and confirmed it to each
/// other (section 4.3 item 4). Only [`PairingStorage::into_active`] makes
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivePairing {
    pair_id: super::PairId,
}

impl ActivePairing {
    /// Pair identifier of the active pairing.
    #[must_use]
    pub const fn pair_id(&self) -> super::PairId {
        self.pair_id
    }

    /// The stored record in its confirmed form, to be stored again in
    /// place of the unconfirmed one: the only way a record becomes
    /// confirmed (section 4.3 item 4).
    ///
    /// # Errors
    /// [`PairingError::PairIdMismatch`] when `record` belongs to another
    /// pairing.
    pub fn confirm(self, record: PairRecord) -> Result<PairRecord, PairingError> {
        if record.pair_id() != self.pair_id {
            return Err(PairingError::PairIdMismatch);
        }
        Ok(record.storage_confirmed())
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
    now_ms: u64,
) -> Result<TypedMessage, PairingError> {
    let envelope = channel.open(frame).map_err(PairingError::Open)?;
    TypedMessage::from_envelope(envelope, now_ms).map_err(PairingError::Message)
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
    /// The peer's storage confirmation names another pairing: an
    /// authenticated protocol violation (section 4.3 item 4).
    PairIdMismatch,
    /// Activity was claimed before both storage confirmations.
    StorageUnconfirmed,
}

impl fmt::Display for PairingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for PairingError {}

#[cfg(test)]
mod tests {
    use super::{PairingConfirmation, PairingError, PairingHandshake, PairingStorage};
    use crate::{
        BootstrapAnswer, EndpointRole, OfferId, PairId, PairingOffer, PairingSecret, ProfileName,
        STREAM_CANDIDATE_ID, TransportProfile, generate_pair_key_material,
    };

    /// Synthetic one-use offer identifier.
    const OFFER_ID_BYTE: u8 = b'o';
    /// Synthetic bearer pairing secret.
    const PAIRING_SECRET_BYTE: u8 = b's';
    /// A pair identifier no ceremony derives, for the mismatch test.
    const FOREIGN_PAIR_ID_BYTE: u8 = b'x';
    /// Monotonic milliseconds at which the confirmation frames are read.
    const CONFIRMATION_AT_MS: u64 = 100;
    /// Platform time recorded as the record's creation.
    const CREATED_AT_MS: u64 = 200;

    fn confirmed_pair() -> (PairingConfirmation, PairingConfirmation) {
        let profiles = vec![ProfileName::Authentication.as_str().to_owned()];
        let proxy_offer = PairingOffer::create(
            OfferId::from_array([OFFER_ID_BYTE; 32]),
            profiles,
            &[TransportProfile::Stream],
        )
        .expect("the offer fixture is valid");
        let bootstrap = proxy_offer.to_cbor().expect("the offer encodes");
        let Ok(BootstrapAnswer::Offer(offer)) =
            BootstrapAnswer::from_bootstrap(&bootstrap, TransportProfile::Stream)
        else {
            panic!("the bootstrap decodes as the offer");
        };
        let pairing_secret = PairingSecret::from_random_bytes([PAIRING_SECRET_BYTE; 32]);
        let mut requester = PairingHandshake::begin(
            EndpointRole::Requester,
            offer,
            STREAM_CANDIDATE_ID,
            generate_pair_key_material().expect("requester keys"),
            &pairing_secret,
        )
        .expect("requester pairing starts");
        let mut proxy = PairingHandshake::begin(
            EndpointRole::Proxy,
            proxy_offer,
            STREAM_CANDIDATE_ID,
            generate_pair_key_material().expect("proxy keys"),
            &pairing_secret,
        )
        .expect("proxy pairing starts");
        let first = requester.write_message().expect("message one");
        proxy.read_message(&first).expect("proxy reads one");
        let second = proxy.write_message().expect("message two");
        requester
            .read_message(&second)
            .expect("requester reads two");
        let third = requester.write_message().expect("message three");
        proxy.read_message(&third).expect("proxy reads three");
        let mut requester = requester.into_confirmation().expect("requester confirms");
        let mut proxy = proxy.into_confirmation().expect("proxy confirms");
        let requester_hello = requester
            .send_hello("Requester".into(), "test".into())
            .expect("requester hello");
        proxy
            .receive_hello(&requester_hello, CONFIRMATION_AT_MS)
            .expect("proxy reads hello");
        let proxy_hello = proxy
            .send_hello("Proxy".into(), "test".into())
            .expect("proxy hello");
        requester
            .receive_hello(&proxy_hello, CONFIRMATION_AT_MS)
            .expect("requester reads hello");
        let grants = vec![ProfileName::Authentication];
        let requester_confirmation = requester
            .send_confirmation(grants.clone())
            .expect("requester grants");
        proxy
            .receive_confirmation(&requester_confirmation, CONFIRMATION_AT_MS)
            .expect("proxy reads grants");
        let proxy_confirmation = proxy.send_confirmation(grants).expect("proxy grants");
        requester
            .receive_confirmation(&proxy_confirmation, CONFIRMATION_AT_MS)
            .expect("requester reads grants");
        (requester, proxy)
    }

    fn storages() -> (PairingStorage, PairingStorage) {
        let (requester, proxy) = confirmed_pair();
        let (_, requester_storage) = requester
            .into_storage(CREATED_AT_MS)
            .expect("requester record");
        let (_, proxy_storage) = proxy.into_storage(CREATED_AT_MS).expect("proxy record");
        (requester_storage, proxy_storage)
    }

    #[test]
    fn both_confirmations_make_the_pairing_active() {
        let (requester, proxy) = confirmed_pair();
        let (requester_record, mut requester) = requester
            .into_storage(CREATED_AT_MS)
            .expect("requester record");
        let (proxy_record, mut proxy) = proxy.into_storage(CREATED_AT_MS).expect("proxy record");
        assert!(!requester_record.is_storage_confirmed());
        assert!(!proxy_record.is_storage_confirmed());
        assert!(!requester.is_confirmed());
        let requester_stored = requester.send_stored().expect("requester confirms");
        let proxy_stored = proxy.send_stored().expect("proxy confirms");
        proxy
            .receive_stored(&requester_stored, CONFIRMATION_AT_MS)
            .expect("proxy reads the confirmation");
        requester
            .receive_stored(&proxy_stored, CONFIRMATION_AT_MS)
            .expect("requester reads the confirmation");
        let pair_id = requester.pair_id();
        let active = requester.into_active().expect("active");
        assert_eq!(active.pair_id(), pair_id);
        let confirmed = active
            .confirm(requester_record)
            .expect("the active pairing confirms its own record");
        assert!(confirmed.is_storage_confirmed());
        assert_eq!(confirmed.pair_id(), pair_id);
        assert_eq!(proxy.into_active().expect("active").pair_id(), pair_id);
    }

    #[test]
    fn an_active_pairing_confirms_only_its_own_record() {
        let (requester, proxy) = confirmed_pair();
        let (requester_record, mut requester) = requester
            .into_storage(CREATED_AT_MS)
            .expect("requester record");
        let (_, mut proxy) = proxy.into_storage(CREATED_AT_MS).expect("proxy record");
        let requester_stored = requester.send_stored().expect("requester confirms");
        let proxy_stored = proxy.send_stored().expect("proxy confirms");
        proxy
            .receive_stored(&requester_stored, CONFIRMATION_AT_MS)
            .expect("proxy reads the confirmation");
        requester
            .receive_stored(&proxy_stored, CONFIRMATION_AT_MS)
            .expect("requester reads the confirmation");
        let (other_requester, _) = confirmed_pair();
        let (other_record, _) = other_requester
            .into_storage(CREATED_AT_MS)
            .expect("another pairing's record");
        assert_ne!(other_record.pair_id(), requester_record.pair_id());
        let active = requester.into_active().expect("active");
        assert!(matches!(
            active.confirm(other_record),
            Err(PairingError::PairIdMismatch)
        ));
    }

    #[test]
    fn a_pairing_without_the_peers_confirmation_is_not_active() {
        let (mut requester, _proxy) = storages();
        requester.send_stored().expect("requester confirms");
        assert!(matches!(
            requester.into_active(),
            Err(PairingError::StorageUnconfirmed)
        ));
    }

    #[test]
    fn a_pairing_without_the_local_confirmation_is_not_active() {
        let (mut requester, mut proxy) = storages();
        let proxy_stored = proxy.send_stored().expect("proxy confirms");
        requester
            .receive_stored(&proxy_stored, CONFIRMATION_AT_MS)
            .expect("requester reads the confirmation");
        assert!(matches!(
            requester.into_active(),
            Err(PairingError::StorageUnconfirmed)
        ));
    }

    #[test]
    fn a_confirmation_naming_another_pairing_is_a_violation() {
        let (mut requester, mut proxy) = storages();
        let foreign = proxy
            .send_stored_as(PairId::from_array([FOREIGN_PAIR_ID_BYTE; 16]))
            .expect("the frame seals");
        assert!(matches!(
            requester.receive_stored(&foreign, CONFIRMATION_AT_MS),
            Err(PairingError::PairIdMismatch)
        ));
    }

    #[test]
    fn each_confirmation_is_sent_and_received_once() {
        let (mut requester, mut proxy) = storages();
        let stored = requester.send_stored().expect("first confirmation");
        assert!(matches!(
            requester.send_stored(),
            Err(PairingError::DuplicateMessage)
        ));
        proxy
            .receive_stored(&stored, CONFIRMATION_AT_MS)
            .expect("proxy reads it");
        let again = requester
            .send_stored_as(requester.pair_id())
            .expect("seals");
        assert!(matches!(
            proxy.receive_stored(&again, CONFIRMATION_AT_MS),
            Err(PairingError::DuplicateMessage)
        ));
    }
}
