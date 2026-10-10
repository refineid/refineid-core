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

//! Native Noise implementation for the operational session handshake.
//!
//! Implements `Noise_KK_25519_ChaChaPoly_SHA512` (RAPP v26.10.10 section 6.3):
//! Curve25519 Diffie-Hellman, ChaCha20-Poly1305, and SHA-512 per Noise
//! Protocol Framework revision 34.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
};
use curve25519_dalek::{montgomery::MontgomeryPoint, traits::Identity};
use hmac::Hmac;
use hmac::digest::{KeyInit as HmacKeyInit, Mac};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::{CryptoError, HandshakeRole, MANDATORY_SESSION_SUITE, NOISE_TAG_SIZE, X25519_KEY_SIZE};

type HmacSha512 = Hmac<Sha512>;

/// Length of each `Noise_KK` handshake message: one ephemeral public key and
/// the tag over the empty payload.
pub const KK_HANDSHAKE_MESSAGE_SIZE: usize = X25519_KEY_SIZE + NOISE_TAG_SIZE;

/// Nonce zero-prefix length in bytes for ChaCha20Poly1305 in Noise.
const NONCE_ZERO_PREFIX_LEN: usize = 4;

/// Single cipher state holding a 32-byte key and 64-bit sequence counter.
#[derive(Clone, Default)]
pub struct NoiseCipherState {
    key: Option<[u8; 32]>,
    nonce: u64,
}

impl Drop for NoiseCipherState {
    fn drop(&mut self) {
        if let Some(mut k) = self.key.take() {
            k.zeroize();
        }
    }
}

impl NoiseCipherState {
    /// Create a new cipher state without a key.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    /// Initialize the cipher state with key material and reset the nonce counter.
    pub fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = Some(key);
        self.nonce = 0;
    }

    /// Whether a cipher key has been initialized.
    #[must_use]
    pub const fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Encrypt plaintext with associated authenticated data.
    ///
    /// # Errors
    /// Returns [`CryptoError::NoiseHandshake`] on encryption failure or counter overflow.
    pub fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let Some(key) = self.key else {
            return Ok(plaintext.to_vec());
        };
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes[NONCE_ZERO_PREFIX_LEN..].copy_from_slice(&self.nonce.to_le_bytes());
        let cipher = ChaCha20Poly1305::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| CryptoError::NoiseHandshake)?;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(CryptoError::NoiseHandshake)?;
        Ok(ciphertext)
    }

    /// Decrypt ciphertext with associated authenticated data.
    ///
    /// # Errors
    /// Returns [`CryptoError::NoiseHandshake`] on decryption failure or counter overflow.
    pub fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let Some(key) = self.key else {
            return Ok(ciphertext.to_vec());
        };
        if ciphertext.len() < NOISE_TAG_SIZE {
            return Err(CryptoError::NoiseHandshake);
        }
        let mut nonce_bytes = [0_u8; 12];
        nonce_bytes[NONCE_ZERO_PREFIX_LEN..].copy_from_slice(&self.nonce.to_le_bytes());
        let cipher = ChaCha20Poly1305::new((&key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| CryptoError::NoiseHandshake)?;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(CryptoError::NoiseHandshake)?;
        Ok(plaintext)
    }
}

/// Noise symmetric state tracking chaining key, transcript hash, and cipher.
pub struct NoiseSymmetricState {
    chaining_key: [u8; 64],
    handshake_hash: [u8; 64],
    cipher: NoiseCipherState,
}

impl NoiseSymmetricState {
    /// Initialize symmetric state with protocol name.
    #[must_use]
    pub fn new(protocol_name: &[u8]) -> Self {
        let h = if protocol_name.len() <= 64 {
            let mut buf = [0_u8; 64];
            buf[..protocol_name.len()].copy_from_slice(protocol_name);
            buf
        } else {
            let digest = Sha512::digest(protocol_name);
            let mut buf = [0_u8; 64];
            buf.copy_from_slice(&digest);
            buf
        };
        Self {
            chaining_key: h,
            handshake_hash: h,
            cipher: NoiseCipherState::new(),
        }
    }

    /// Transcript handshake hash.
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 64] {
        self.handshake_hash
    }

    /// Mix data into transcript hash: `h = HASH(h || data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha512::new();
        hasher.update(self.handshake_hash);
        hasher.update(data);
        self.handshake_hash.copy_from_slice(&hasher.finalize());
    }

    /// Key derivation helper using HMAC-SHA512 chaining.
    fn derive_2(ck: &[u8; 64], input_key_material: &[u8]) -> ([u8; 64], [u8; 32]) {
        let mut temp_mac = HmacSha512::new_from_slice(ck).expect("64-byte key is valid for HMAC");
        temp_mac.update(input_key_material);
        let temp_key = temp_mac.finalize().into_bytes();

        let mut mac1 =
            HmacSha512::new_from_slice(&temp_key).expect("64-byte key is valid for HMAC");
        mac1.update(&[1]);
        let output1 = mac1.finalize().into_bytes();

        let mut mac2 =
            HmacSha512::new_from_slice(&temp_key).expect("64-byte key is valid for HMAC");
        mac2.update(&output1);
        mac2.update(&[2]);
        let output2 = mac2.finalize().into_bytes();

        let mut out1 = [0_u8; 64];
        let mut out2 = [0_u8; 32];
        out1.copy_from_slice(&output1);
        out2.copy_from_slice(&output2[..32]);
        (out1, out2)
    }

    /// Mix key material into chaining key and rekey cipher: `(ck, k) = HKDF(ck, material, 2)`.
    pub fn mix_key(&mut self, material: &[u8]) {
        let (next_ck, k) = Self::derive_2(&self.chaining_key, material);
        self.chaining_key = next_ck;
        self.cipher.initialize_key(k);
    }

    /// Encrypt plaintext with current handshake hash as associated data, then mix ciphertext.
    ///
    /// # Errors
    /// Returns [`CryptoError::NoiseHandshake`] on encryption failure.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ciphertext = self.cipher.encrypt(&self.handshake_hash, plaintext)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// Decrypt ciphertext with current handshake hash as associated data, then mix ciphertext.
    ///
    /// # Errors
    /// Returns [`CryptoError::NoiseHandshake`] on decryption failure.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let plaintext = self.cipher.decrypt(&self.handshake_hash, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Split chaining key into two transport cipher keys: `(c1, c2) = HKDF(ck, zerolen, 2)`.
    #[must_use]
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        let mut temp_mac =
            HmacSha512::new_from_slice(&self.chaining_key).expect("64-byte key is valid for HMAC");
        temp_mac.update(&[]);
        let temp_key = temp_mac.finalize().into_bytes();

        let mut mac1 =
            HmacSha512::new_from_slice(&temp_key).expect("64-byte key is valid for HMAC");
        mac1.update(&[1]);
        let output1 = mac1.finalize().into_bytes();

        let mut mac2 =
            HmacSha512::new_from_slice(&temp_key).expect("64-byte key is valid for HMAC");
        mac2.update(&output1);
        mac2.update(&[2]);
        let output2 = mac2.finalize().into_bytes();

        let mut c1 = [0_u8; 32];
        let mut c2 = [0_u8; 32];
        c1.copy_from_slice(&output1[..32]);
        c2.copy_from_slice(&output2[..32]);
        (c1, c2)
    }
}

/// Compute public X25519 point from private scalar with standard clamping.
#[must_use]
pub fn x25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*private_key).0
}

/// Compute constant-time X25519 Diffie-Hellman agreement, rejecting identity points.
fn dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let point = MontgomeryPoint(*public_key);
    let shared = point.mul_clamped(*private_key);
    if shared == MontgomeryPoint::identity() {
        return Err(CryptoError::Configuration);
    }
    Ok(shared.0)
}

/// Two-way transport cipher state for post-handshake message encryption.
pub struct NoiseTransport {
    send: NoiseCipherState,
    receive: NoiseCipherState,
}

impl core::fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoiseTransport").finish_non_exhaustive()
    }
}

impl NoiseTransport {
    /// Create a transport channel from send and receive cipher states.
    #[must_use]
    pub const fn new(send: NoiseCipherState, receive: NoiseCipherState) -> Self {
        Self { send, receive }
    }

    /// Encrypt application plaintext into the provided output slice.
    ///
    /// # Errors
    /// Returns [`CryptoError::NoiseHandshake`] on encryption failure or insufficient buffer.
    pub fn write_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let ciphertext = self.send.encrypt(&[], payload)?;
        if message.len() < ciphertext.len() {
            return Err(CryptoError::NoiseHandshake);
        }
        message[..ciphertext.len()].copy_from_slice(&ciphertext);
        Ok(ciphertext.len())
    }

    /// Decrypt transport ciphertext into the provided output slice.
    ///
    /// # Errors
    /// Returns [`CryptoError::NoiseHandshake`] on decryption failure or insufficient buffer.
    pub fn read_message(
        &mut self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let plaintext = self.receive.decrypt(&[], payload)?;
        if message.len() < plaintext.len() {
            return Err(CryptoError::NoiseHandshake);
        }
        message[..plaintext.len()].copy_from_slice(&plaintext);
        Ok(plaintext.len())
    }
}

/// Handshake state machine for `Noise_KK_25519_ChaChaPoly_SHA512`.
pub struct KkHandshakeState {
    role: HandshakeRole,
    symmetric: NoiseSymmetricState,
    local_static_priv: [u8; X25519_KEY_SIZE],
    remote_static_pub: [u8; X25519_KEY_SIZE],
    local_ephemeral_priv: Option<[u8; X25519_KEY_SIZE]>,
    remote_ephemeral_pub: Option<[u8; X25519_KEY_SIZE]>,
    fixed_ephemeral_priv: Option<[u8; X25519_KEY_SIZE]>,
    message_index: usize,
    finished: bool,
}

impl Drop for KkHandshakeState {
    fn drop(&mut self) {
        self.local_static_priv.zeroize();
        if let Some(mut ephemeral) = self.local_ephemeral_priv.take() {
            ephemeral.zeroize();
        }
        if let Some(mut fixed) = self.fixed_ephemeral_priv.take() {
            fixed.zeroize();
        }
    }
}

impl KkHandshakeState {
    /// Initialize a `Noise_KK` session handshake state with both static
    /// public keys as pre-messages.
    ///
    /// # Errors
    /// Returns [`CryptoError::Configuration`] if prologue mixing or keys fail.
    pub fn new(
        role: HandshakeRole,
        local_static_priv: &[u8; X25519_KEY_SIZE],
        remote_static_pub: &[u8; X25519_KEY_SIZE],
        prologue: &[u8],
    ) -> Result<Self, CryptoError> {
        let mut symmetric = NoiseSymmetricState::new(MANDATORY_SESSION_SUITE.as_bytes());
        symmetric.mix_hash(prologue);

        let local_static_pub = x25519_public_key(local_static_priv);
        // Pre-messages: -> s, <- s
        match role {
            HandshakeRole::Initiator => {
                symmetric.mix_hash(&local_static_pub);
                symmetric.mix_hash(remote_static_pub);
            }
            HandshakeRole::Responder => {
                symmetric.mix_hash(remote_static_pub);
                symmetric.mix_hash(&local_static_pub);
            }
        }

        Ok(Self {
            role,
            symmetric,
            local_static_priv: *local_static_priv,
            remote_static_pub: *remote_static_pub,
            local_ephemeral_priv: None,
            remote_ephemeral_pub: None,
            fixed_ephemeral_priv: None,
            message_index: 0,
            finished: false,
        })
    }

    /// Fix the ephemeral private key for known-answer vectors.
    pub fn set_fixed_ephemeral_for_testing(&mut self, fixed: [u8; X25519_KEY_SIZE]) {
        self.fixed_ephemeral_priv = Some(fixed);
    }

    /// Transcript handshake hash.
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 64] {
        self.symmetric.handshake_hash()
    }

    /// Remote static public key.
    #[must_use]
    pub const fn remote_static(&self) -> [u8; X25519_KEY_SIZE] {
        self.remote_static_pub
    }

    /// Whether the two-message handshake has completed.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Produce the next handshake message frame payload.
    ///
    /// # Errors
    /// Returns [`CryptoError::NoiseHandshake`] on protocol violation or cipher error.
    pub fn write_message(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if self.finished {
            return Err(CryptoError::NoiseHandshake);
        }
        let message = match (self.role, self.message_index) {
            (HandshakeRole::Initiator, 0) => self.write_initiator_message_1(payload)?,
            (HandshakeRole::Responder, 1) => self.write_responder_message_2(payload)?,
            _ => return Err(CryptoError::NoiseHandshake),
        };
        if output.len() < message.len() {
            return Err(CryptoError::NoiseHandshake);
        }
        output[..message.len()].copy_from_slice(&message);
        self.advance();
        Ok(message.len())
    }

    /// Consume the incoming handshake message frame payload.
    ///
    /// # Errors
    /// Returns [`CryptoError::NoiseHandshake`] on protocol violation or decryption error.
    pub fn read_message(
        &mut self,
        message: &[u8],
        payload_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        if self.finished || message.len() < KK_HANDSHAKE_MESSAGE_SIZE {
            return Err(CryptoError::NoiseHandshake);
        }
        let payload = match (self.role, self.message_index) {
            (HandshakeRole::Responder, 0) => self.read_responder_message_1(message)?,
            (HandshakeRole::Initiator, 1) => self.read_initiator_message_2(message)?,
            _ => return Err(CryptoError::NoiseHandshake),
        };
        if payload_out.len() < payload.len() {
            return Err(CryptoError::NoiseHandshake);
        }
        payload_out[..payload.len()].copy_from_slice(&payload);
        self.advance();
        Ok(payload.len())
    }

    fn advance(&mut self) {
        self.message_index += 1;
        if self.message_index == 2 {
            self.finished = true;
            if let Some(mut ephemeral) = self.local_ephemeral_priv.take() {
                ephemeral.zeroize();
            }
        }
    }

    /// Samples (or takes the fixed) ephemeral key, writes `e` and mixes it.
    fn write_ephemeral(
        &mut self,
        buffer: &mut Vec<u8>,
    ) -> Result<[u8; X25519_KEY_SIZE], CryptoError> {
        let ephemeral_priv = if let Some(fixed) = self.fixed_ephemeral_priv {
            fixed
        } else {
            let mut key = [0_u8; X25519_KEY_SIZE];
            getrandom::fill(&mut key).map_err(|_| CryptoError::Configuration)?;
            key
        };
        let ephemeral_pub = x25519_public_key(&ephemeral_priv);
        self.local_ephemeral_priv = Some(ephemeral_priv);
        buffer.extend_from_slice(&ephemeral_pub);
        self.symmetric.mix_hash(&ephemeral_pub);
        Ok(ephemeral_priv)
    }

    /// Reads `e` and mixes it.
    fn read_ephemeral(&mut self, message: &[u8]) -> Result<[u8; X25519_KEY_SIZE], CryptoError> {
        let ephemeral_pub: [u8; X25519_KEY_SIZE] = message[..X25519_KEY_SIZE]
            .try_into()
            .map_err(|_| CryptoError::NoiseHandshake)?;
        self.remote_ephemeral_pub = Some(ephemeral_pub);
        self.symmetric.mix_hash(&ephemeral_pub);
        Ok(ephemeral_pub)
    }

    /// Message 1: `e, es, ss`
    fn write_initiator_message_1(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = Vec::with_capacity(KK_HANDSHAKE_MESSAGE_SIZE + payload.len());
        let ephemeral_priv = self.write_ephemeral(&mut buffer)?;
        self.symmetric
            .mix_key(&dh(&ephemeral_priv, &self.remote_static_pub)?);
        self.symmetric
            .mix_key(&dh(&self.local_static_priv, &self.remote_static_pub)?);
        buffer.extend_from_slice(&self.symmetric.encrypt_and_hash(payload)?);
        Ok(buffer)
    }

    /// Read Message 1: `e, es, ss`
    fn read_responder_message_1(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ephemeral_pub = self.read_ephemeral(message)?;
        self.symmetric
            .mix_key(&dh(&self.local_static_priv, &ephemeral_pub)?);
        self.symmetric
            .mix_key(&dh(&self.local_static_priv, &self.remote_static_pub)?);
        self.symmetric.decrypt_and_hash(&message[X25519_KEY_SIZE..])
    }

    /// Message 2: `e, ee, se`
    fn write_responder_message_2(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let remote_ephemeral = self
            .remote_ephemeral_pub
            .ok_or(CryptoError::NoiseHandshake)?;
        let mut buffer = Vec::with_capacity(KK_HANDSHAKE_MESSAGE_SIZE + payload.len());
        let ephemeral_priv = self.write_ephemeral(&mut buffer)?;
        self.symmetric
            .mix_key(&dh(&ephemeral_priv, &remote_ephemeral)?);
        self.symmetric
            .mix_key(&dh(&ephemeral_priv, &self.remote_static_pub)?);
        buffer.extend_from_slice(&self.symmetric.encrypt_and_hash(payload)?);
        Ok(buffer)
    }

    /// Read Message 2: `e, ee, se`
    fn read_initiator_message_2(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let local_ephemeral = self
            .local_ephemeral_priv
            .ok_or(CryptoError::NoiseHandshake)?;
        let ephemeral_pub = self.read_ephemeral(message)?;
        self.symmetric
            .mix_key(&dh(&local_ephemeral, &ephemeral_pub)?);
        self.symmetric
            .mix_key(&dh(&self.local_static_priv, &ephemeral_pub)?);
        self.symmetric.decrypt_and_hash(&message[X25519_KEY_SIZE..])
    }

    /// Enter transport mode once the handshake has completed.
    ///
    /// # Errors
    /// Returns [`CryptoError::HandshakeIncomplete`] if called before the handshake finishes.
    pub fn into_transport(self) -> Result<NoiseTransport, CryptoError> {
        if !self.finished {
            return Err(CryptoError::HandshakeIncomplete);
        }
        let (c1, c2) = self.symmetric.split();
        let mut send = NoiseCipherState::new();
        let mut receive = NoiseCipherState::new();
        match self.role {
            HandshakeRole::Initiator => {
                send.initialize_key(c1);
                receive.initialize_key(c2);
            }
            HandshakeRole::Responder => {
                send.initialize_key(c2);
                receive.initialize_key(c1);
            }
        }
        Ok(NoiseTransport::new(send, receive))
    }
}
