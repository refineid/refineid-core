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

//! Native post-quantum hybrid Noise implementation.
//!
//! Implements `Noise_KKhfs_25519+MLKEM768_ChaChaPoly_SHA512` combining classical
//! Curve25519 Diffie-Hellman with NIST FIPS 203 ML-KEM-768 key encapsulation.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
};
use curve25519_dalek::{montgomery::MontgomeryPoint, traits::Identity};
use hmac::Hmac;
use hmac::digest::{KeyInit as HmacKeyInit, Mac};
use ml_kem::{
    KeyExport,
    kem::Decapsulate,
    ml_kem_768::{DecapsulationKey, EncapsulationKey},
};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::{CryptoError, HandshakeRole, MANDATORY_SESSION_SUITE, NOISE_TAG_SIZE, X25519_KEY_SIZE};

type HmacSha512 = Hmac<Sha512>;

/// ML-KEM-768 encapsulation key size in bytes (FIPS 203).
pub const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;

/// ML-KEM-768 ciphertext size in bytes (FIPS 203).
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;

/// ML-KEM-768 shared secret size in bytes.
pub const MLKEM768_SHARED_SECRET_SIZE: usize = 32;

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

/// Handshake state machine for `Noise_KKhfs_25519+MLKEM768_ChaChaPoly_SHA256`.
pub struct KkHfsHandshakeState {
    role: HandshakeRole,
    symmetric: NoiseSymmetricState,
    local_static_priv: [u8; 32],
    remote_static_pub: [u8; 32],
    local_ephemeral_priv: Option<[u8; 32]>,
    remote_ephemeral_pub: Option<[u8; 32]>,
    local_mlkem_dk: Option<DecapsulationKey>,
    remote_mlkem_ek: Option<EncapsulationKey>,
    fixed_ephemeral_priv: Option<[u8; 32]>,
    fixed_mlkem_seed: Option<[u8; 64]>,
    fixed_mlkem_m: Option<[u8; 32]>,
    message_index: usize,
    finished: bool,
}

impl Drop for KkHfsHandshakeState {
    fn drop(&mut self) {
        self.local_static_priv.zeroize();
        if let Some(mut ep) = self.local_ephemeral_priv.take() {
            ep.zeroize();
        }
        if let Some(mut fep) = self.fixed_ephemeral_priv.take() {
            fep.zeroize();
        }
        if let Some(mut fseed) = self.fixed_mlkem_seed.take() {
            fseed.zeroize();
        }
        if let Some(mut fm) = self.fixed_mlkem_m.take() {
            fm.zeroize();
        }
    }
}

impl KkHfsHandshakeState {
    /// Initialize a new KKhfs session handshake state.
    ///
    /// # Errors
    /// Returns [`CryptoError::Configuration`] if prologue mixing or keys fail.
    pub fn new(
        role: HandshakeRole,
        local_static_priv: &[u8; 32],
        remote_static_pub: &[u8; 32],
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
            local_mlkem_dk: None,
            remote_mlkem_ek: None,
            fixed_ephemeral_priv: None,
            fixed_mlkem_seed: None,
            fixed_mlkem_m: None,
            message_index: 0,
            finished: false,
        })
    }

    /// Set fixed ephemeral key material for deterministic testing and known answer vectors.
    pub fn set_fixed_ephemerals_for_testing(
        &mut self,
        fixed_x25519_priv: Option<[u8; 32]>,
        fixed_mlkem_seed: Option<[u8; 64]>,
        fixed_mlkem_m: Option<[u8; 32]>,
    ) {
        self.fixed_ephemeral_priv = fixed_x25519_priv;
        self.fixed_mlkem_seed = fixed_mlkem_seed;
        self.fixed_mlkem_m = fixed_mlkem_m;
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
        match (self.role, self.message_index) {
            (HandshakeRole::Initiator, 0) => self.write_initiator_message_1(payload, output),
            (HandshakeRole::Responder, 1) => self.write_responder_message_2(payload, output),
            _ => Err(CryptoError::NoiseHandshake),
        }
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
        if self.finished {
            return Err(CryptoError::NoiseHandshake);
        }
        match (self.role, self.message_index) {
            (HandshakeRole::Responder, 0) => self.read_responder_message_1(message, payload_out),
            (HandshakeRole::Initiator, 1) => self.read_initiator_message_2(message, payload_out),
            _ => Err(CryptoError::NoiseHandshake),
        }
    }

    /// Message 1: `e, es, ekem, ss`
    fn write_initiator_message_1(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let ephem_priv = if let Some(fixed) = self.fixed_ephemeral_priv {
            fixed
        } else {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key).map_err(|_| CryptoError::Configuration)?;
            key
        };
        let ephem_pub = x25519_public_key(&ephem_priv);
        self.local_ephemeral_priv = Some(ephem_priv);

        let mut buffer =
            Vec::with_capacity(32 + MLKEM768_PUBLIC_KEY_SIZE + 16 + payload.len() + 16);

        // e: write unencrypted ephemeral public key
        buffer.extend_from_slice(&ephem_pub);
        self.symmetric.mix_hash(&ephem_pub);

        // es: DH(e, s_remote)
        let es_secret = dh(&ephem_priv, &self.remote_static_pub)?;
        self.symmetric.mix_key(&es_secret);

        // ekem: ML-KEM-768 key generation and encrypted public key
        let dk = if let Some(seed) = self.fixed_mlkem_seed {
            DecapsulationKey::from_seed(seed.into())
        } else {
            let mut seed = [0_u8; 64];
            getrandom::fill(&mut seed).map_err(|_| CryptoError::Configuration)?;
            DecapsulationKey::from_seed(seed.into())
        };
        let ek = dk.encapsulation_key();
        let ek_bytes = ek.to_bytes();
        let encrypted_ek = self.symmetric.encrypt_and_hash(&ek_bytes)?;
        buffer.extend_from_slice(&encrypted_ek);
        self.local_mlkem_dk = Some(dk);

        // ss: DH(s_local, s_remote)
        let ss_secret = dh(&self.local_static_priv, &self.remote_static_pub)?;
        self.symmetric.mix_key(&ss_secret);

        // payload
        let encrypted_payload = self.symmetric.encrypt_and_hash(payload)?;
        buffer.extend_from_slice(&encrypted_payload);

        if output.len() < buffer.len() {
            return Err(CryptoError::NoiseHandshake);
        }
        output[..buffer.len()].copy_from_slice(&buffer);
        self.message_index = 1;
        Ok(buffer.len())
    }

    /// Read Message 1: `e, es, ekem, ss`
    fn read_responder_message_1(
        &mut self,
        message: &[u8],
        payload_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let expected_min = 32 + MLKEM768_PUBLIC_KEY_SIZE + NOISE_TAG_SIZE + NOISE_TAG_SIZE;
        if message.len() < expected_min {
            return Err(CryptoError::NoiseHandshake);
        }

        // e: take 32 bytes
        let mut ephem_pub = [0_u8; 32];
        ephem_pub.copy_from_slice(&message[..32]);
        self.remote_ephemeral_pub = Some(ephem_pub);
        self.symmetric.mix_hash(&ephem_pub);

        // es: DH(s_local, e_remote)
        let es_secret = dh(&self.local_static_priv, &ephem_pub)?;
        self.symmetric.mix_key(&es_secret);

        // ekem: decrypt 1184 + 16 = 1200 bytes
        let ek_end = 32 + MLKEM768_PUBLIC_KEY_SIZE + NOISE_TAG_SIZE;
        let encrypted_ek = &message[32..ek_end];
        let ek_bytes = self.symmetric.decrypt_and_hash(encrypted_ek)?;
        let ek_array = ek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::NoiseHandshake)?;
        let ek = EncapsulationKey::new(ek_array).map_err(|_| CryptoError::NoiseHandshake)?;
        self.remote_mlkem_ek = Some(ek);

        // ss: DH(s_local, s_remote)
        let ss_secret = dh(&self.local_static_priv, &self.remote_static_pub)?;
        self.symmetric.mix_key(&ss_secret);

        // payload
        let encrypted_payload = &message[ek_end..];
        let payload = self.symmetric.decrypt_and_hash(encrypted_payload)?;
        if payload_out.len() < payload.len() {
            return Err(CryptoError::NoiseHandshake);
        }
        payload_out[..payload.len()].copy_from_slice(&payload);
        self.message_index = 1;
        Ok(payload.len())
    }

    /// Message 2: `e, ee, kemct, se`
    fn write_responder_message_2(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let remote_ephem = self
            .remote_ephemeral_pub
            .ok_or(CryptoError::NoiseHandshake)?;
        let remote_ek = self
            .remote_mlkem_ek
            .as_ref()
            .ok_or(CryptoError::NoiseHandshake)?;

        let ephem_priv = if let Some(fixed) = self.fixed_ephemeral_priv {
            fixed
        } else {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key).map_err(|_| CryptoError::Configuration)?;
            key
        };
        let ephem_pub = x25519_public_key(&ephem_priv);
        self.local_ephemeral_priv = Some(ephem_priv);

        let mut buffer =
            Vec::with_capacity(32 + MLKEM768_CIPHERTEXT_SIZE + 16 + payload.len() + 16);

        // e: write unencrypted ephemeral public key
        buffer.extend_from_slice(&ephem_pub);
        self.symmetric.mix_hash(&ephem_pub);

        // ee: DH(e_local, e_remote)
        let ee_secret = dh(&ephem_priv, &remote_ephem)?;
        self.symmetric.mix_key(&ee_secret);

        // kemct: ML-KEM-768 encapsulation
        let (ct, shared_secret) = if let Some(m) = self.fixed_mlkem_m {
            remote_ek.encapsulate_deterministic(&m.into())
        } else {
            let mut m = [0_u8; 32];
            getrandom::fill(&mut m).map_err(|_| CryptoError::Configuration)?;
            remote_ek.encapsulate_deterministic(&m.into())
        };
        let encrypted_ct = self.symmetric.encrypt_and_hash(ct.as_slice())?;
        buffer.extend_from_slice(&encrypted_ct);
        self.symmetric.mix_key(shared_secret.as_slice());

        // se: DH(e_local, s_remote)
        let se_secret = dh(&ephem_priv, &self.remote_static_pub)?;
        self.symmetric.mix_key(&se_secret);

        // payload
        let encrypted_payload = self.symmetric.encrypt_and_hash(payload)?;
        buffer.extend_from_slice(&encrypted_payload);

        if output.len() < buffer.len() {
            return Err(CryptoError::NoiseHandshake);
        }
        output[..buffer.len()].copy_from_slice(&buffer);
        self.message_index = 2;
        self.finished = true;
        Ok(buffer.len())
    }

    /// Read Message 2: `e, ee, kemct, se`
    fn read_initiator_message_2(
        &mut self,
        message: &[u8],
        payload_out: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let expected_min = 32 + MLKEM768_CIPHERTEXT_SIZE + NOISE_TAG_SIZE + NOISE_TAG_SIZE;
        if message.len() < expected_min {
            return Err(CryptoError::NoiseHandshake);
        }
        let local_ephem = self
            .local_ephemeral_priv
            .ok_or(CryptoError::NoiseHandshake)?;
        let local_dk = self
            .local_mlkem_dk
            .as_ref()
            .ok_or(CryptoError::NoiseHandshake)?;

        // e: take 32 bytes
        let mut ephem_pub = [0_u8; 32];
        ephem_pub.copy_from_slice(&message[..32]);
        self.remote_ephemeral_pub = Some(ephem_pub);
        self.symmetric.mix_hash(&ephem_pub);

        // ee: DH(e_local, e_remote)
        let ee_secret = dh(&local_ephem, &ephem_pub)?;
        self.symmetric.mix_key(&ee_secret);

        // kemct: decrypt 1088 + 16 = 1104 bytes
        let ct_end = 32 + MLKEM768_CIPHERTEXT_SIZE + NOISE_TAG_SIZE;
        let encrypted_ct = &message[32..ct_end];
        let ct_bytes = self.symmetric.decrypt_and_hash(encrypted_ct)?;
        let ct_array = ct_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::NoiseHandshake)?;
        let shared_secret = local_dk.decapsulate(ct_array);
        self.symmetric.mix_key(shared_secret.as_slice());

        // se: DH(s_local, e_remote)
        let se_secret = dh(&self.local_static_priv, &ephem_pub)?;
        self.symmetric.mix_key(&se_secret);

        // payload
        let encrypted_payload = &message[ct_end..];
        let payload = self.symmetric.decrypt_and_hash(encrypted_payload)?;
        if payload_out.len() < payload.len() {
            return Err(CryptoError::NoiseHandshake);
        }
        payload_out[..payload.len()].copy_from_slice(&payload);
        self.message_index = 2;
        self.finished = true;
        Ok(payload.len())
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
