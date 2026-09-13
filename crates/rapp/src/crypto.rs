// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Mandatory Noise construction and transcript-bound hashes.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use zeroize::ZeroizeOnDrop;

use super::{
    BinaryFrame, Envelope, FrameError, GRANTS_HASH_SIZE, GrantsHash, MANDATORY_PAIRING_SUITE,
    MANDATORY_SESSION_SUITE, MAX_FRAME_PLAINTEXT, MAX_FRAME_SIZE, MessageType, OperationId,
    PAIR_ID_SIZE, PairId, PairingSecret, ProfileName, RENDEZVOUS_TOKEN_SIZE, REQUEST_HASH_SIZE,
    RendezvousToken, RequestHash, SESSION_ID_SIZE, SequenceGuard, SessionId, VISIBLE_WIRE_VERSION,
    WireError, WireValue, encode_deterministic_cbor,
};

const X25519_KEY_SIZE: usize = 32;
const NOISE_TAG_SIZE: usize = 16;

/// Local endpoint role in the fixed RAPP Noise patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Noise initiator. RAPP fixes this as the requester.
    Initiator,
    /// Noise responder. RAPP fixes this as the authorization proxy.
    Responder,
}

/// Fresh pair-specific X25519 key material.
#[derive(ZeroizeOnDrop)]
pub struct PairKeyMaterial {
    private_key: [u8; X25519_KEY_SIZE],
    public_key: [u8; X25519_KEY_SIZE],
}

impl PairKeyMaterial {
    /// Reconstruct bytes obtained from a device-only platform key store.
    #[must_use]
    pub const fn reconstruct(
        private_key: [u8; X25519_KEY_SIZE],
        public_key: [u8; X25519_KEY_SIZE],
    ) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    /// Pair-specific public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.public_key
    }

    /// Give a platform key-store adapter a scoped view of private bytes.
    ///
    /// The adapter must store them device-only, excluded from backup and
    /// synchronization, and must not retain the borrowed slice.
    pub fn with_private_key<R>(&self, use_key: impl FnOnce(&[u8; X25519_KEY_SIZE]) -> R) -> R {
        use_key(&self.private_key)
    }
}

impl core::fmt::Debug for PairKeyMaterial {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PairKeyMaterial")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Pairing-handshake transcript parameters known before Noise starts.
pub struct PairingHandshakeParameters<'a> {
    /// Fixed local Noise role.
    pub role: HandshakeRole,
    /// Fresh pair-specific local static key.
    pub local_keys: &'a PairKeyMaterial,
    /// One-use QR bearer secret mixed as `psk3`.
    pub pairing_secret: &'a PairingSecret,
    /// Hash of the pairing offer with the bearer secret removed.
    pub offer_hash: [u8; 32],
    /// Selected registered transport profile.
    pub transport_profile: &'a str,
}

/// Session-handshake transcript parameters known before Noise starts.
pub struct SessionHandshakeParameters<'a> {
    /// Fixed local Noise role.
    pub role: HandshakeRole,
    /// Stored pair-specific local key.
    pub local_keys: &'a PairKeyMaterial,
    /// Stored public key of the paired peer.
    pub remote_public_key: &'a [u8; X25519_KEY_SIZE],
    /// Pair identifier derived during pairing.
    pub pair_id: PairId,
    /// Hash of the mutually confirmed grant set.
    pub grants_hash: GrantsHash,
    /// Selected registered transport profile.
    pub transport_profile: &'a str,
}

impl core::fmt::Debug for PairingHandshakeParameters<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PairingHandshakeParameters")
            .field("role", &self.role)
            .field("transport_profile", &self.transport_profile)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for SessionHandshakeParameters<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionHandshakeParameters")
            .field("role", &self.role)
            .field("pair_id", &self.pair_id)
            .field("transport_profile", &self.transport_profile)
            .finish_non_exhaustive()
    }
}

/// Noise handshake plus the values derived on completion.
pub struct HandshakeChannel {
    state: HandshakeState,
    derive_pair: bool,
}

impl core::fmt::Debug for HandshakeChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandshakeChannel")
            .field("derive_pair", &self.derive_pair)
            .finish_non_exhaustive()
    }
}

/// Result of a completed Noise handshake.
pub struct HandshakeCompletion {
    /// Encrypted transport channel with fresh directional sequences.
    pub secure_channel: SecureChannel,
    /// Identifier derived from this fresh authenticated handshake.
    pub session_id: SessionId,
    /// Pairing-only identifier derived from the transcript.
    pub pair_id: Option<PairId>,
    /// Pairing-only transport rendezvous token derived from the transcript.
    pub rendezvous_token: Option<RendezvousToken>,
    /// Authenticated remote pair-specific static key.
    pub remote_static_key: [u8; X25519_KEY_SIZE],
}

impl core::fmt::Debug for HandshakeCompletion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandshakeCompletion")
            .field("session_id", &self.session_id)
            .field("pair_id", &self.pair_id)
            .finish_non_exhaustive()
    }
}

/// Mutually authenticated encrypted RAPP transport channel.
pub struct SecureChannel {
    noise: TransportState,
    sequence: SequenceGuard,
}

impl core::fmt::Debug for SecureChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecureChannel")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

/// Cryptographic construction failure before or during authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Mandatory suite could not be configured.
    Configuration,
    /// Resolver returned unexpected key material.
    InvalidKeyLength,
    /// Noise handshake processing failed.
    NoiseHandshake,
    /// A handshake message carried forbidden payload data.
    NonEmptyHandshakePayload,
    /// Transport conversion was requested too early.
    HandshakeIncomplete,
    /// Completed handshake did not expose the authenticated remote static key.
    MissingRemoteStatic,
    /// Frame crossed a named resource limit.
    Frame(FrameError),
    /// Transcript or outgoing envelope was not valid RAPP CBOR.
    Wire(WireError),
}

/// Failure while opening a post-handshake frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// Not attributable to the peer: close only this session.
    SessionIntegrityFailure,
    /// Successfully decrypted nonconforming traffic: revoke the pairing.
    AuthenticatedProtocolViolation(WireError),
}

/// Generate a fresh pair-specific X25519 key pair using the Noise resolver.
///
/// # Errors
/// [`CryptoError`] when the mandatory suite or resolver key generation fails.
pub fn generate_pair_key_material() -> Result<PairKeyMaterial, CryptoError> {
    let params: NoiseParams = MANDATORY_PAIRING_SUITE
        .parse()
        .map_err(|_| CryptoError::Configuration)?;
    let keypair = Builder::new(params)
        .generate_keypair()
        .map_err(|_| CryptoError::Configuration)?;
    let private_key: [u8; X25519_KEY_SIZE] = keypair
        .private
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let public_key: [u8; X25519_KEY_SIZE] = keypair
        .public
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    Ok(PairKeyMaterial::reconstruct(private_key, public_key))
}

impl HandshakeChannel {
    /// Begin the mandatory `XXpsk3` pairing handshake.
    ///
    /// # Errors
    /// [`CryptoError`] when the suite, keys, or prologue cannot be
    /// configured.
    pub fn pairing(parameters: &PairingHandshakeParameters<'_>) -> Result<Self, CryptoError> {
        let prologue = pairing_prologue(parameters.offer_hash, parameters.transport_profile)?;
        let params: NoiseParams = MANDATORY_PAIRING_SUITE
            .parse()
            .map_err(|_| CryptoError::Configuration)?;
        let builder = Builder::new(params)
            .local_private_key(&parameters.local_keys.private_key)
            .map_err(|_| CryptoError::Configuration)?
            .psk(3, parameters.pairing_secret.expose())
            .map_err(|_| CryptoError::Configuration)?
            .prologue(&prologue)
            .map_err(|_| CryptoError::Configuration)?;
        Ok(Self {
            state: build(builder, parameters.role)?,
            derive_pair: true,
        })
    }

    /// Begin the mandatory pair-specific KK session handshake.
    ///
    /// # Errors
    /// [`CryptoError`] when the suite, keys, or prologue cannot be
    /// configured.
    pub fn session(parameters: &SessionHandshakeParameters<'_>) -> Result<Self, CryptoError> {
        let prologue = session_prologue(
            parameters.pair_id,
            parameters.grants_hash,
            parameters.transport_profile,
        )?;
        let params: NoiseParams = MANDATORY_SESSION_SUITE
            .parse()
            .map_err(|_| CryptoError::Configuration)?;
        let builder = Builder::new(params)
            .local_private_key(&parameters.local_keys.private_key)
            .map_err(|_| CryptoError::Configuration)?
            .remote_public_key(parameters.remote_public_key)
            .map_err(|_| CryptoError::Configuration)?
            .prologue(&prologue)
            .map_err(|_| CryptoError::Configuration)?;
        Ok(Self {
            state: build(builder, parameters.role)?,
            derive_pair: false,
        })
    }

    /// Produce one Noise handshake frame with the required empty payload.
    ///
    /// # Errors
    /// [`CryptoError`] when Noise refuses the message or the frame crosses a
    /// resource limit.
    pub fn write_message(&mut self) -> Result<BinaryFrame, CryptoError> {
        let mut output = vec![0_u8; MAX_FRAME_SIZE];
        let length = self
            .state
            .write_message(&[], &mut output)
            .map_err(|_| CryptoError::NoiseHandshake)?;
        output.truncate(length);
        BinaryFrame::reconstruct(output).map_err(CryptoError::Frame)
    }

    /// Consume one Noise handshake frame and require an empty payload.
    ///
    /// # Errors
    /// [`CryptoError`] on a failed handshake message or a non-empty payload.
    pub fn read_message(&mut self, frame: &BinaryFrame) -> Result<(), CryptoError> {
        let mut payload = vec![0_u8; MAX_FRAME_SIZE];
        let length = self
            .state
            .read_message(frame.as_bytes(), &mut payload)
            .map_err(|_| CryptoError::NoiseHandshake)?;
        if length != 0 {
            return Err(CryptoError::NonEmptyHandshakePayload);
        }
        Ok(())
    }

    /// Whether the role-specific handshake pattern has completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Derive identifiers and enter Noise transport mode.
    ///
    /// # Errors
    /// [`CryptoError`] when the handshake is incomplete or exposes no
    /// authenticated remote static key.
    pub fn complete(self) -> Result<HandshakeCompletion, CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::HandshakeIncomplete);
        }
        let session_id = derive_session_id(self.state.get_handshake_hash());
        let pair_id = self
            .derive_pair
            .then(|| derive_pair_id(self.state.get_handshake_hash()));
        let rendezvous_token = self
            .derive_pair
            .then(|| derive_rendezvous_token(self.state.get_handshake_hash()));
        let remote_static: [u8; X25519_KEY_SIZE] = self
            .state
            .get_remote_static()
            .ok_or(CryptoError::MissingRemoteStatic)?
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let noise = self
            .state
            .into_transport_mode()
            .map_err(|_| CryptoError::NoiseHandshake)?;
        Ok(HandshakeCompletion {
            secure_channel: SecureChannel {
                noise,
                sequence: SequenceGuard::new(session_id),
            },
            session_id,
            pair_id,
            rendezvous_token,
            remote_static_key: remote_static,
        })
    }
}

impl SecureChannel {
    /// Most recently authenticated peer sequence, including handshake-channel
    /// application messages such as `session.ready`.
    #[must_use]
    pub const fn last_received_sequence(&self) -> Option<u64> {
        self.sequence.last_received_sequence()
    }

    /// Encrypt one validated envelope and advance the send sequence once.
    ///
    /// # Errors
    /// [`CryptoError`] on an invalid body, sequence exhaustion, or an
    /// encryption failure.
    pub fn seal(
        &mut self,
        message_type: MessageType,
        body: BTreeMap<String, WireValue>,
    ) -> Result<BinaryFrame, CryptoError> {
        let envelope = self
            .sequence
            .next_outgoing(message_type, body)
            .map_err(CryptoError::Wire)?;
        let plaintext = envelope.encode().map_err(CryptoError::Wire)?;
        let mut output = vec![0_u8; plaintext.len() + NOISE_TAG_SIZE];
        let length = self
            .noise
            .write_message(&plaintext, &mut output)
            .map_err(|_| CryptoError::NoiseHandshake)?;
        output.truncate(length);
        BinaryFrame::reconstruct(output).map_err(CryptoError::Frame)
    }

    /// Authenticate, decrypt, parse, and sequence-check one frame.
    ///
    /// # Errors
    /// [`OpenError`] separating unattributable decryption failures from
    /// authenticated protocol violations.
    pub fn open(&mut self, frame: &BinaryFrame) -> Result<Envelope, OpenError> {
        let maximum_plaintext = frame.as_bytes().len().saturating_sub(NOISE_TAG_SIZE);
        let mut plaintext = vec![0_u8; maximum_plaintext.min(MAX_FRAME_PLAINTEXT)];
        let length = self
            .noise
            .read_message(frame.as_bytes(), &mut plaintext)
            .map_err(|_| OpenError::SessionIntegrityFailure)?;
        plaintext.truncate(length);
        let envelope =
            Envelope::decode(&plaintext).map_err(OpenError::AuthenticatedProtocolViolation)?;
        self.sequence
            .accept_incoming(&envelope)
            .map_err(OpenError::AuthenticatedProtocolViolation)?;
        Ok(envelope)
    }
}

fn build(builder: Builder<'_>, role: HandshakeRole) -> Result<HandshakeState, CryptoError> {
    match role {
        HandshakeRole::Initiator => builder.build_initiator(),
        HandshakeRole::Responder => builder.build_responder(),
    }
    .map_err(|_| CryptoError::Configuration)
}

/// Derive a session identifier from a completed Noise transcript.
#[must_use]
pub fn derive_session_id(handshake_hash: &[u8]) -> SessionId {
    let digest = Sha256::new()
        .chain_update(b"RAPP-session-id-v1")
        .chain_update(handshake_hash)
        .finalize();
    let mut bytes = [0_u8; SESSION_ID_SIZE];
    bytes.copy_from_slice(&digest[..SESSION_ID_SIZE]);
    SessionId::from_array(bytes)
}

/// Derive a permanent pair identifier from a completed pairing transcript.
#[must_use]
pub fn derive_pair_id(handshake_hash: &[u8]) -> PairId {
    let digest = Sha256::new()
        .chain_update(b"RAPP-pair-id-v1")
        .chain_update(handshake_hash)
        .finalize();
    let mut bytes = [0_u8; PAIR_ID_SIZE];
    bytes.copy_from_slice(&digest[..PAIR_ID_SIZE]);
    PairId::from_array(bytes)
}

/// Derive the pair-specific transport rendezvous token from a completed
/// pairing transcript. Wire-safe by construction: computationally unlinkable
/// to `pair_id` without the handshake hash.
#[must_use]
pub fn derive_rendezvous_token(handshake_hash: &[u8]) -> RendezvousToken {
    let digest = Sha256::new()
        .chain_update(b"RAPP-rendezvous-v1")
        .chain_update(handshake_hash)
        .finalize();
    let mut bytes = [0_u8; RENDEZVOUS_TOKEN_SIZE];
    bytes.copy_from_slice(&digest[..RENDEZVOUS_TOKEN_SIZE]);
    RendezvousToken::from_array(bytes)
}

/// Hash the lexicographically sorted granted-profile registry names.
///
/// # Errors
/// [`CryptoError::Wire`] when deterministic encoding fails.
pub fn compute_grants_hash(profiles: &[ProfileName]) -> Result<GrantsHash, CryptoError> {
    let mut names = profiles
        .iter()
        .map(|profile| profile.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    names.dedup();
    let value = WireValue::Array(
        names
            .into_iter()
            .map(|name| WireValue::Text(name.to_owned()))
            .collect(),
    );
    let encoded = encode_deterministic_cbor(&value).map_err(CryptoError::Wire)?;
    let digest = Sha256::digest(encoded);
    let mut bytes = [0_u8; GRANTS_HASH_SIZE];
    bytes.copy_from_slice(&digest);
    Ok(GrantsHash::from_array(bytes))
}

/// Bind the exact typed operation request to its secure channel.
///
/// # Errors
/// [`CryptoError::Wire`] when deterministic encoding fails.
pub fn compute_request_hash(
    session_id: SessionId,
    operation_id: OperationId,
    profile: ProfileName,
    action: &str,
    context: BTreeMap<String, WireValue>,
    payload: BTreeMap<String, WireValue>,
) -> Result<RequestHash, CryptoError> {
    let preimage = WireValue::Array(vec![
        WireValue::Text("RAPP-request-v1".to_owned()),
        WireValue::Bytes(session_id.as_bytes().to_vec()),
        WireValue::Bytes(operation_id.as_bytes().to_vec()),
        WireValue::Text(profile.as_str().to_owned()),
        WireValue::Text(action.to_owned()),
        WireValue::Map(context),
        WireValue::Map(payload),
    ]);
    let encoded = encode_deterministic_cbor(&preimage).map_err(CryptoError::Wire)?;
    let digest = Sha256::digest(encoded);
    let mut bytes = [0_u8; REQUEST_HASH_SIZE];
    bytes.copy_from_slice(&digest);
    Ok(RequestHash::from_array(bytes))
}

fn pairing_prologue(offer_hash: [u8; 32], transport_profile: &str) -> Result<Vec<u8>, CryptoError> {
    encode_deterministic_cbor(&WireValue::Array(vec![
        WireValue::Text("RAPP-pairing-v1".to_owned()),
        version_value(),
        WireValue::Text(MANDATORY_PAIRING_SUITE.to_owned()),
        WireValue::Bytes(offer_hash.to_vec()),
        WireValue::Text(transport_profile.to_owned()),
    ]))
    .map_err(CryptoError::Wire)
}

fn session_prologue(
    pair_id: PairId,
    grants_hash: GrantsHash,
    transport_profile: &str,
) -> Result<Vec<u8>, CryptoError> {
    encode_deterministic_cbor(&WireValue::Array(vec![
        WireValue::Text("RAPP-session-v1".to_owned()),
        version_value(),
        WireValue::Text(MANDATORY_SESSION_SUITE.to_owned()),
        WireValue::Bytes(pair_id.as_bytes().to_vec()),
        WireValue::Bytes(grants_hash.as_bytes().to_vec()),
        WireValue::Text(transport_profile.to_owned()),
    ]))
    .map_err(CryptoError::Wire)
}

fn version_value() -> WireValue {
    WireValue::Array(vec![
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.0)),
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.1)),
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.2)),
    ])
}
