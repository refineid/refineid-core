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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Phantom-typed containers for cryptographic outputs.
//!
//! Phase 2 of the workspace-wide "no untyped bytes across the
//! card boundary" migration. Every cryptographic value that
//! flows between modules -- ciphertext, MAC tag, signature,
//! nonce, shared secret -- has a typed container that carries
//! its **algorithm** (the operation that produced it) and, where
//! the spec fixes one, its **length contract**. The compiler
//! refuses to pass a CMAC-AES tag where an AES-CBC ciphertext
//! is expected; a `Nonce<8>` cannot be passed to a function
//! expecting `Nonce<16>`.
//!
//! The algorithm space is expressed via Style A -- zero-sized
//! marker types (`AesCbc`, `CmacAes`, `EcdsaP256`, ...) used as
//! phantom type parameters. Each marker carries no runtime
//! data; its only job is to distinguish "this is a CBC
//! ciphertext" from "this is a CMAC tag" at compile time. New
//! algorithms land as new marker types next to the existing
//! ones -- sibling, not enum variants.
//!
//! See `doc/typing-discipline.md` for the policy rules these
//! containers exist to enforce.

use core::fmt;
use core::marker::PhantomData;

// =========================================================
// Algorithm marker types.
//
// One zero-sized struct per algorithm refineid uses. The
// markers live next to the container types so a `use
// container::{Ciphertext, AesCbc}` brings the algorithm and
// its container together.
// =========================================================

/// Marker: AES-256 in CBC mode (no padding; refineid's secure
/// messaging mode for FINEID S1 v4.0+ and eMRTD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesCbc;

/// Marker: AES-256 in ECB mode (used by secure messaging only
/// for `IV = AES-ECB(K_enc, SSC)` IV derivation, never as a
/// general bulk cipher).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AesEcb;

/// Marker: AES-256-CMAC at full 16-byte tag length (RFC 4493
/// with AES-256). Used internally; secure messaging emits the
/// truncated 8-byte variant on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmacAes;

/// Marker: AES-256-CMAC truncated to 8 bytes for the DO 8E
/// secure-messaging MAC field. Distinct from [`CmacAes`] so a
/// full 16-byte tag cannot be silently sent where the
/// 8-byte field belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmacAesTruncated;

/// Marker: ECDSA over NIST P-256 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaP256;

/// Marker: ECDSA over NIST P-384 with SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaP384;

/// Marker: ECDSA over Brainpool P-384r1 with SHA-384 (FINEID
/// G3-ECC root + S4-1 v4.0 signing keys use this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaBrainpoolP384r1;

/// Marker: ECDSA signature in ASN.1 DER form (`SEQUENCE { r
/// INTEGER, s INTEGER }`), curve-agnostic.
///
/// Distinct from the curve-specific `EcdsaP256` / `EcdsaP384` /
/// `EcdsaBrainpoolP384r1` markers in two ways:
///
/// 1. The curve is *not* fixed at the type level -- the
///    verifier supplies the curve at runtime (CMS/X.509 paths
///    pick the curve from the issuer's SPKI). Use this marker
///    when the bytes are "a DER ECDSA signature whose curve is
///    determined by the surrounding context" rather than "a
///    signature provably produced under P-256".
/// 2. The encoding is locked: DER SEQUENCE-of-INTEGER. Raw
///    `r || s` concatenation form is *not* a `Signature<EcdsaDer>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdsaDer;

/// Marker: RSA PKCS#1 v1.5 with SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPkcs1Sha256;

/// Marker: RSA PKCS#1 v1.5 with SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPkcs1Sha384;

/// Marker: RSA PKCS#1 v1.5 with SHA-512.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPkcs1Sha512;

/// Marker: RSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
///
/// This is the fixed modern profile used by EU trusted-list XML
/// signatures. Keeping the salt and mask profile in the marker prevents
/// a caller from treating arbitrary PSS parameters as interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPssSha256;

/// Marker: Brainpool P-384r1 elliptic curve (the curve tag for
/// PACE-CAM / FINEID G3-ECC public-key and signature containers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrainpoolP384r1;

// =========================================================
// Containers.
// =========================================================

/// Encrypted bytes produced by a specific symmetric cipher.
///
/// The `Alg` phantom binds the bytes to the cipher / mode that
/// produced them, so a function `fn decrypt(c:
/// Ciphertext<AesCbc>)` will refuse a `Ciphertext<AesEcb>` at
/// compile time.
///
/// The byte content stays as `Vec<u8>` because ciphertext
/// length is mode-dependent (CBC is a multiple of the block
/// size; future GCM adds an auth-tag suffix). For
/// length-fixed values use [`Nonce`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext<Alg> {
    /// Raw ciphertext bytes; length determined by `Alg`'s mode.
    bytes: Vec<u8>,
    /// Type-level tag binding the value to a specific algorithm.
    _phantom: PhantomData<Alg>,
}

impl<Alg> Ciphertext<Alg> {
    /// Wrap raw ciphertext bytes produced by `Alg`.
    ///
    /// Caller asserts the bytes ARE the output of `Alg` --
    /// this constructor doesn't verify because that would
    /// require a key. Typed-correctly-by-construction
    /// callers invoke this from the cipher's encrypt function.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _phantom: PhantomData,
        }
    }

    /// Borrow the underlying ciphertext bytes for transmission
    /// onto the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the container and return the owned ciphertext
    /// bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the ciphertext in bytes. Tier 0 `usize`;
    /// arithmetic count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the ciphertext is empty (operationally this
    /// shouldn't happen for a real encrypt output).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Authentication tag produced by a specific MAC algorithm.
///
/// Same shape as [`Ciphertext`] but expresses a different
/// security role (integrity / authenticity, not
/// confidentiality). Distinct type so the compiler refuses to
/// pass a CMAC tag where ciphertext is expected.
///
/// No derived `PartialEq`: MAC verification is a timing-sensitive
/// comparison, and the live paths do it with
/// `bool::from(a.ct_eq(b))` on the raw bytes. Deriving `==` here
/// would offer a variable-time shortcut right next to the value it
/// must never be used on.
#[derive(Debug, Clone)]
pub struct Mac<Alg> {
    /// Raw MAC tag bytes produced by `Alg`.
    bytes: Vec<u8>,
    /// Type-level tag binding the value to the MAC algorithm.
    _phantom: PhantomData<Alg>,
}

impl<Alg> Mac<Alg> {
    /// Wrap raw MAC bytes produced by `Alg`.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _phantom: PhantomData,
        }
    }

    /// Borrow the underlying MAC bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the container and return the owned MAC bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the MAC tag in bytes. Tier 0 `usize`.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the MAC tag is empty (operationally this
    /// shouldn't happen).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Signature produced by a specific signature algorithm.
///
/// `Alg` distinguishes ECDSA-P256 from RSA-PKCS#1 from
/// Brainpool ECDSA, so a verifier built for one curve refuses
/// to accept a signature for another.
///
/// No derived `PartialEq`: signatures are accepted by cryptographic
/// verification against a public key, never by byte-equality with
/// another signature (ECDSA is randomized, so byte-comparison is
/// wrong as well as timing-variable).
#[derive(Debug, Clone)]
pub struct Signature<Alg> {
    /// Raw signature bytes produced by `Alg`.
    bytes: Vec<u8>,
    /// Type-level tag binding the value to the signature algorithm.
    _phantom: PhantomData<Alg>,
}

impl<Alg> Signature<Alg> {
    /// Wrap raw signature bytes produced by `Alg`.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _phantom: PhantomData,
        }
    }

    /// Borrow the underlying signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the container and return the owned signature bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the signature in bytes (modulus length for RSA;
    /// `2 * curve_size` for ECDSA raw concat). Tier 0 `usize`.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the signature is empty (operationally never).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Fixed-length nonce.
///
/// `N` makes the length part of the type: a `Nonce<8>` cannot
/// be passed to a function expecting `Nonce<16>`. PACE step 1
/// produces a `Nonce<16>` (AES block size); the encrypted
/// challenge produced by PACE step 2 is a different role
/// (ciphertext, not nonce) and uses [`Ciphertext`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce<const N: usize> {
    /// Fixed-length nonce payload; length encoded in the type parameter `N`.
    bytes: [u8; N],
}

impl<const N: usize> Nonce<N> {
    /// Wrap a fixed-length byte array as a nonce.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Borrow the underlying fixed-length byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consume the container and return the owned fixed-length
    /// byte array.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }

    /// Length of the nonce in bytes; equals the const generic `N`.
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// `true` when `N == 0` (compile-time-known per
    /// instantiation).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

// `EcdhSharedSecret<Curve>` used to live here. It was removed as
// dead API: the live PACE / chip-authentication paths pass the
// pre-KDF x-coordinate as `Zeroizing<Vec<u8>>` straight into the
// KDF and never needed the container. Reintroduce it only together
// with a consumer, and with a redacted `Debug` plus zeroize-on-drop
// (the omissions that made the dead version a hazard).

// =========================================================
// Display impls -- hex for compact diagnostic output.
//
// Length-bearing roles render as "<role>(<n> bytes)" so the
// content stays out of logs unless an explicit accessor is
// used. Confidentiality / authenticity values must not leak
// in operator-visible strings.
// =========================================================

impl<Alg> fmt::Display for Ciphertext<Alg> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ciphertext({} bytes)", self.bytes.len())
    }
}

impl<Alg> fmt::Display for Mac<Alg> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mac({} bytes)", self.bytes.len())
    }
}

impl<Alg> fmt::Display for Signature<Alg> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({} bytes)", self.bytes.len())
    }
}

impl<const N: usize> fmt::Display for Nonce<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({N} bytes)")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AesCbc, Ciphertext, CmacAes, CmacAesTruncated, EcdsaP256, Mac, Nonce, RsaPkcs1Sha256,
        Signature,
    };

    /// Length of the short fixture payload.
    const SAMPLE_PAYLOAD_LEN: usize = 4;
    /// Arbitrary short fixture payload for container round-trips.
    const SAMPLE_PAYLOAD: [u8; SAMPLE_PAYLOAD_LEN] = [1, 2, 3, 4];
    /// AES-CMAC full MAC length (SP 800-38B: one block).
    const CMAC_FULL_LEN: usize = 16;
    /// Secure-messaging truncated MAC length (ISO 7816-4: eight bytes).
    const CMAC_TRUNCATED_LEN: usize = 8;
    /// AES block / IV-sized nonce length.
    const NONCE_BLOCK_LEN: usize = 16;
    /// Send-sequence-counter-sized nonce length.
    const NONCE_SSC_LEN: usize = 8;
    /// Arbitrary fixture fill byte for the block-sized nonce.
    const NONCE_BLOCK_FILL: u8 = 0xAB;
    /// Arbitrary fixture fill byte for the SSC-sized nonce.
    const NONCE_SSC_FILL: u8 = 0xCD;
    /// ECDSA P-256 raw `r || s` signature length.
    const P256_RAW_SIGNATURE_LEN: usize = 64;
    /// RSA-2048 signature length in bytes.
    const RSA_2048_SIGNATURE_LEN: usize = 256;

    #[test]
    fn ciphertext_carries_algorithm_at_type_level() {
        let cbc: Ciphertext<AesCbc> = Ciphertext::new(SAMPLE_PAYLOAD.to_vec());
        // Compile-test: the two algorithms produce distinct
        // types and the compiler refuses cross-assignment.
        // (Uncommenting the next line would fail to build.)
        // let _: Ciphertext<AesEcb> = cbc;
        assert_eq!(cbc.as_bytes(), &SAMPLE_PAYLOAD);
        assert_eq!(cbc.len(), SAMPLE_PAYLOAD.len());
    }

    #[test]
    fn mac_carries_algorithm_at_type_level() {
        let full: Mac<CmacAes> = Mac::new(vec![0_u8; CMAC_FULL_LEN]);
        let truncated: Mac<CmacAesTruncated> = Mac::new(vec![0_u8; CMAC_TRUNCATED_LEN]);
        assert_eq!(full.len(), CMAC_FULL_LEN);
        assert_eq!(truncated.len(), CMAC_TRUNCATED_LEN);
        // Compile-test: Mac<CmacAes> and Mac<CmacAesTruncated>
        // are different types; a function for one refuses the
        // other.
    }

    #[test]
    fn nonce_length_is_part_of_the_type() {
        let block_nonce: Nonce<NONCE_BLOCK_LEN> = Nonce::new([NONCE_BLOCK_FILL; NONCE_BLOCK_LEN]);
        let ssc_nonce: Nonce<NONCE_SSC_LEN> = Nonce::new([NONCE_SSC_FILL; NONCE_SSC_LEN]);
        assert_eq!(block_nonce.len(), NONCE_BLOCK_LEN);
        assert_eq!(ssc_nonce.len(), NONCE_SSC_LEN);
        // Compile-test: the two nonce lengths are different types.
    }

    #[test]
    fn signature_carries_algorithm() {
        let p256: Signature<EcdsaP256> = Signature::new(vec![0_u8; P256_RAW_SIGNATURE_LEN]);
        let rsa: Signature<RsaPkcs1Sha256> = Signature::new(vec![0_u8; RSA_2048_SIGNATURE_LEN]);
        assert_eq!(p256.len(), P256_RAW_SIGNATURE_LEN);
        assert_eq!(rsa.len(), RSA_2048_SIGNATURE_LEN);
    }
}
