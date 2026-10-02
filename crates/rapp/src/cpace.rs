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

//! CPace: Balanced Password-Authenticated Key Exchange over Ristretto255.
//!
//! Implements a balanced PAKE over Curve25519 using the prime-order Ristretto255
//! group abstraction. Provides mathematical immunity against offline dictionary
//! attacks across untrusted relays: an observer sees only uniform curve points
//! and cannot verify candidate 6-digit codes offline.

use core::fmt;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use hmac::Hmac;
use hmac::digest::{KeyInit as HmacKeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    BinaryFrame, HandshakeRole, OFFER_ID_SIZE, OfferId, PAIRING_SECRET_SIZE, PairingSecret,
    WIRE_VERSION_V26_10_1, WireValue, decode_deterministic_cbor, encode_deterministic_cbor,
};

/// Suite identifier for RAPP CPaceRistretto255 KC2 profile with Noise_XXpsk3.
pub const CPACE_KC2_SUITE: &str =
    "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512";

/// Byte length of an encoded CPace public point.
pub const CPACE_POINT_SIZE: usize = 32;

/// Byte length of a CPace KC2 mutual confirmation tag (FIRST32 of HMAC-SHA-512).
pub const CPACE_TAG_SIZE: usize = 32;

/// Byte length of the pseudorandom key (PRK) from HKDF-Extract-SHA512.
pub const CPACE_PRK_SIZE: usize = 64;

/// Byte length of the pre-shared key (PSK) output from HKDF-Expand-SHA512.
pub const CPACE_PSK_SIZE: usize = 32;

/// Byte length of a CPace confirmation key (K_A, K_B) from HKDF-Expand-SHA512.
pub const CPACE_CONFIRMATION_KEY_SIZE: usize = 32;

/// Byte length of the CPace KC2 transcript hash ($TH$).
pub const CPACE_TRANSCRIPT_HASH_SIZE: usize = 64;

/// Byte length of a CPace Step 1 frame payload ($Y_A$).
pub const CPACE_STEP1_MSG_SIZE: usize = CPACE_POINT_SIZE;

/// Byte length of a CPace Step 2 frame payload ($Y_B \parallel T_B$).
pub const CPACE_STEP2_MSG_SIZE: usize = CPACE_POINT_SIZE + CPACE_TAG_SIZE;

/// Byte length of a CPace Step 3 frame payload ($T_A$).
pub const CPACE_STEP3_MSG_SIZE: usize = CPACE_TAG_SIZE;

/// Domain separator for CPace Ristretto255 group environment (draft-irtf-cfrg-cpace-21).
const CPACE_RISTRETTO255_DSI: &[u8] = b"CPaceRistretto255";
/// Domain separator for intermediate session key derivation (draft-irtf-cfrg-cpace-21).
const CPACE_RISTRETTO255_ISK_DSI: &[u8] = b"CPaceRistretto255_ISK";
/// SHA-512 input block size in bytes (draft-irtf-cfrg-cpace-21).
const SHA512_INPUT_BLOCK_SIZE: usize = 128;
/// Wire framing domain identifier for legacy CPace.
const CPACE_FRAME_DOMAIN: &str = "RAPP-cpace-v1";
/// Pairing context array domain identifier (RAPP v26.10.1 §6.1.1).
const CPACE_CONTEXT_DOMAIN: &str = "RAPP-PAIRING-CONTEXT-v2";
/// Domain separation prefix for KC2 transcript hash ($TH$).
const CPACE_TRANSCRIPT_PREFIX: &[u8] = b"RAPP-CPACE-TRANSCRIPT-v2";
/// HKDF info string for PSK derivation.
const CPACE_HKDF_PSK_INFO: &[u8] = b"RAPP-NOISE-PSK-v2";
/// HKDF info string for Initiator confirmation key ($K_A$) derivation.
const CPACE_HKDF_CONFIRM_A_KEY_INFO: &[u8] = b"RAPP-CPACE-CONFIRM-A-KEY-v2";
/// HKDF info string for Responder confirmation key ($K_B$) derivation.
const CPACE_HKDF_CONFIRM_B_KEY_INFO: &[u8] = b"RAPP-CPACE-CONFIRM-B-KEY-v2";
/// Domain prefix for Initiator confirmation tag ($T_A$) HMAC input.
const CPACE_CONFIRM_A_TAG_PREFIX: &[u8] = b"RAPP-CPACE-CONFIRM-A-v2";
/// Domain prefix for Responder confirmation tag ($T_B$) HMAC input.
const CPACE_CONFIRM_B_TAG_PREFIX: &[u8] = b"RAPP-CPACE-CONFIRM-B-v2";

type HmacSha512 = Hmac<Sha512>;

/// CPace PAKE protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpaceError {
    /// The supplied 6-digit pairing code is empty or malformed.
    InvalidCode,
    /// Random scalar generation produced an invalid/zero scalar.
    InvalidScalar,
    /// The peer's public group element is malformed or not on the curve.
    InvalidPoint,
    /// The derived shared point is the group identity element.
    IdentitySharedPoint,
    /// The derived generator point is the group identity element (abort on identity).
    IdentityGenerator,
    /// Mutual confirmation tag ($T_A$ or $T_B$) verification failed.
    ConfirmationTagMismatch,
    /// Received CPace binary frame was malformed, oversized, or carried wrong domain.
    MalformedFrame,
}

impl fmt::Display for CpaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCode => formatter.write_str("invalid or empty pairing code"),
            Self::InvalidScalar => formatter.write_str("failed to sample valid scalar"),
            Self::InvalidPoint => {
                formatter.write_str("peer group element is invalid or not canonical")
            }
            Self::IdentitySharedPoint => {
                formatter.write_str("derived shared point is group identity")
            }
            Self::IdentityGenerator => {
                formatter.write_str("derived generator point is group identity")
            }
            Self::ConfirmationTagMismatch => formatter.write_str("CPace confirmation tag mismatch"),
            Self::MalformedFrame => formatter.write_str("malformed CPace binary frame"),
        }
    }
}

impl core::error::Error for CpaceError {}

/// Ephemeral state for one party in the CPace key exchange.
#[derive(ZeroizeOnDrop)]
pub struct CpaceState {
    #[zeroize(skip)]
    role: HandshakeRole,
    offer_id: [u8; OFFER_ID_SIZE],
    #[zeroize(skip)]
    scalar: Scalar,
    my_public: [u8; CPACE_POINT_SIZE],
}

impl CpaceState {
    /// Start a CPace exchange for the given role, pairing code, offer ID, and 64 random bytes.
    ///
    /// # Errors
    /// [`CpaceError`] if the code is invalid or scalar generation fails.
    pub fn new(
        role: HandshakeRole,
        pairing_code: &str,
        offer_id: &OfferId,
        random_bytes_64: &[u8; 64],
    ) -> Result<Self, CpaceError> {
        let normalized_code = normalize_code(pairing_code)?;
        let generator = calculate_generator(normalized_code.as_bytes(), &[], offer_id.as_bytes());

        let scalar = Scalar::from_bytes_mod_order_wide(random_bytes_64);
        if scalar == Scalar::ZERO {
            return Err(CpaceError::InvalidScalar);
        }

        let my_point = generator * scalar;
        let my_public = my_point.compress().to_bytes();

        let mut offer_id_bytes = [0_u8; OFFER_ID_SIZE];
        offer_id_bytes.copy_from_slice(offer_id.as_bytes());

        Ok(Self {
            role,
            offer_id: offer_id_bytes,
            scalar,
            my_public,
        })
    }

    /// Public ephemeral point to transmit to the peer (32 bytes).
    #[must_use]
    pub const fn public_point(&self) -> &[u8; CPACE_POINT_SIZE] {
        &self.my_public
    }

    /// Complete the exchange by processing the peer's 32-byte public point.
    ///
    /// Derives the 256-bit [`PairingSecret`] using `draft-irtf-cfrg-cpace-21` ISK derivation.
    ///
    /// # Errors
    /// [`CpaceError::InvalidPoint`] if the peer point is not a canonical Ristretto point.
    /// [`CpaceError::IdentitySharedPoint`] if the exchange resulted in identity.
    pub fn finish(
        self,
        peer_public_bytes: &[u8; CPACE_POINT_SIZE],
    ) -> Result<PairingSecret, CpaceError> {
        let compressed = CompressedRistretto(*peer_public_bytes);
        let peer_point = compressed.decompress().ok_or(CpaceError::InvalidPoint)?;

        if peer_point == RistrettoPoint::identity() {
            return Err(CpaceError::InvalidPoint);
        }

        let shared_point = peer_point * self.scalar;
        if shared_point == RistrettoPoint::identity() {
            return Err(CpaceError::IdentitySharedPoint);
        }

        let shared_point_bytes = shared_point.compress().to_bytes();

        // Transcript ordering: initiator point first, responder point second
        let (initiator_point, responder_point) = match self.role {
            HandshakeRole::Initiator => (&self.my_public, peer_public_bytes),
            HandshakeRole::Responder => (peer_public_bytes, &self.my_public),
        };

        let isk = calculate_isk(
            &self.offer_id,
            &shared_point_bytes,
            initiator_point,
            &[],
            responder_point,
            &[],
        );

        let mut psk = [0_u8; PAIRING_SECRET_SIZE];
        psk.copy_from_slice(&isk[..PAIRING_SECRET_SIZE]);

        Ok(PairingSecret::from_random_bytes(psk))
    }

    /// Produce a deterministic-CBOR binary frame carrying this peer's public group element.
    ///
    /// # Errors
    /// [`CpaceError::MalformedFrame`] if encoding fails.
    pub fn write_message(&self) -> Result<BinaryFrame, CpaceError> {
        encode_cpace_frame(&self.my_public)
    }

    /// Read and verify the peer's binary frame, completing the exchange and deriving the secret.
    ///
    /// # Errors
    /// [`CpaceError`] if the frame is malformed, point is invalid, or shared point is identity.
    pub fn read_message(self, frame: &BinaryFrame) -> Result<PairingSecret, CpaceError> {
        let peer_point = decode_cpace_frame(frame)?;
        self.finish(&peer_point)
    }
}

/// Encodes a CPace public point into a deterministic-CBOR binary frame:
/// `["RAPP-cpace-v1", bstr .size 32]`
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if CBOR serialization or frame reconstruction fails.
pub fn encode_cpace_frame(
    public_point: &[u8; CPACE_POINT_SIZE],
) -> Result<BinaryFrame, CpaceError> {
    let wire = WireValue::Array(vec![
        WireValue::Text(CPACE_FRAME_DOMAIN.to_owned()),
        WireValue::Bytes(public_point.to_vec()),
    ]);
    let encoded = encode_deterministic_cbor(&wire).map_err(|_| CpaceError::MalformedFrame)?;
    BinaryFrame::reconstruct(encoded).map_err(|_| CpaceError::MalformedFrame)
}

/// Decodes a peer's CPace public point from a binary frame:
/// `["RAPP-cpace-v1", bstr .size 32]`
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if the frame does not match the exact expected schema.
pub fn decode_cpace_frame(frame: &BinaryFrame) -> Result<[u8; CPACE_POINT_SIZE], CpaceError> {
    let wire =
        decode_deterministic_cbor(frame.as_bytes()).map_err(|_| CpaceError::MalformedFrame)?;
    let WireValue::Array(elements) = wire else {
        return Err(CpaceError::MalformedFrame);
    };
    if elements.len() != 2 {
        return Err(CpaceError::MalformedFrame);
    }
    let WireValue::Text(ref domain) = elements[0] else {
        return Err(CpaceError::MalformedFrame);
    };
    if domain != CPACE_FRAME_DOMAIN {
        return Err(CpaceError::MalformedFrame);
    }
    let WireValue::Bytes(ref bytes) = elements[1] else {
        return Err(CpaceError::MalformedFrame);
    };
    let point_bytes: [u8; CPACE_POINT_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CpaceError::MalformedFrame)?;
    Ok(point_bytes)
}

/// LEB128 encoding of length (draft-irtf-cfrg-cpace-21 Appendix A.1.1).
#[must_use]
pub fn encode_leb128_len(mut len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        if len < 128 {
            out.push(len as u8);
            break;
        }
        out.push(((len & 0x7f) as u8) | 0x80);
        len >>= 7;
    }
    out
}

/// Prepend LEB128 length to data (draft-irtf-cfrg-cpace-21 Appendix A.1.1).
#[must_use]
pub fn prepend_len(data: &[u8]) -> Vec<u8> {
    let mut out = encode_leb128_len(data.len());
    out.extend_from_slice(data);
    out
}

/// Length-value concatenation (draft-irtf-cfrg-cpace-21 Appendix A.1.3).
#[must_use]
pub fn lv_cat(slices: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for slice in slices {
        out.extend(encode_leb128_len(slice.len()));
        out.extend_from_slice(slice);
    }
    out
}

/// Generator string construction with zero padding (draft-irtf-cfrg-cpace-21 Section 8.1 & Appendix A.2).
#[must_use]
pub fn generator_string(
    dsi: &[u8],
    prs: &[u8],
    ci: &[u8],
    sid: &[u8],
    s_in_bytes: usize,
) -> Vec<u8> {
    let dsi_len = encode_leb128_len(dsi.len()).len() + dsi.len();
    let prs_len = encode_leb128_len(prs.len()).len() + prs.len();
    let used = 1 + prs_len + dsi_len;
    let len_zpad = s_in_bytes.saturating_sub(used);
    let zpad = vec![0u8; len_zpad];
    lv_cat(&[dsi, prs, &zpad, ci, sid])
}

/// Initiator-responder transcript encoding (draft-irtf-cfrg-cpace-21 Appendix A.3.4).
#[must_use]
pub fn transcript_ir(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
    let mut out = lv_cat(&[ya, ada]);
    out.extend(lv_cat(&[yb, adb]));
    out
}

/// Computes the CPace generator point $g$ (draft-irtf-cfrg-cpace-21 Section 8.3).
#[must_use]
pub fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let gen_str = generator_string(
        CPACE_RISTRETTO255_DSI,
        prs,
        ci,
        sid,
        SHA512_INPUT_BLOCK_SIZE,
    );
    let mut hasher = Sha512::new();
    hasher.update(&gen_str);
    let hash: [u8; 64] = hasher.finalize().into();

    let point = RistrettoPoint::from_uniform_bytes(&hash);
    if point == RistrettoPoint::identity() {
        // Highly improbable (2^-252), fallback to basepoint
        RISTRETTO_BASEPOINT_POINT
    } else {
        point
    }
}

/// Computes the 64-byte intermediate session key (ISK) (draft-irtf-cfrg-cpace-21 Section 7.2).
#[must_use]
pub fn calculate_isk(
    sid: &[u8],
    shared_point: &[u8; CPACE_POINT_SIZE],
    ya: &[u8],
    ada: &[u8],
    yb: &[u8],
    adb: &[u8],
) -> [u8; 64] {
    let mut isk_input = lv_cat(&[CPACE_RISTRETTO255_ISK_DSI, sid, shared_point]);
    isk_input.extend(transcript_ir(ya, ada, yb, adb));
    let mut hasher = Sha512::new();
    hasher.update(&isk_input);
    hasher.finalize().into()
}

/// Derives the 32-byte offer identifier for manual code-based pairing without out-of-band URI transport.
///
/// # Errors
/// [`CpaceError::InvalidCode`] if the code is empty or malformed.
pub fn derive_manual_offer_id(code: &str) -> Result<OfferId, CpaceError> {
    let normalized = normalize_code(code)?;
    let mut hasher = Sha256::new();
    hasher.update(b"RAPP-manual-offer-id-v1");
    let len = normalized.len() as u16;
    hasher.update(len.to_be_bytes());
    hasher.update(normalized.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; OFFER_ID_SIZE];
    bytes.copy_from_slice(&digest);
    Ok(OfferId::from_array(bytes))
}

/// Normalizes a human-entered pairing code (removes ASCII whitespace and normalizes to uppercase).
fn normalize_code(code: &str) -> Result<String, CpaceError> {
    let trimmed: String = code.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(CpaceError::InvalidCode);
    }
    // Verify numeric or alphanumeric characters
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(CpaceError::InvalidCode);
    }
    Ok(trimmed.to_ascii_uppercase())
}

/// Encodes a deterministic CBOR pairing context array conforming to RAPP v26.10.1 §6.1.1.
///
/// ```cddl
/// pairing-context = [
///   "RAPP-PAIRING-CONTEXT-v2",
///   [26, 10, 1],                                                              ; wire version [Year, Month, Day]
///   "CPACE-RISTR255-SHA512-RAPP-KC2 + Noise_XXpsk3_25519_ChaChaPoly_SHA512", ; full suite literal
///   "fi.refineid.rapp.ble.v1",                                               ; transport profile
///   "ble-direct-1",                                                          ; candidate identifier
///   bstr .size 32,                                                           ; offer_hash
///   "requester",                                                             ; initiator role A
///   "custodian"                                                              ; responder role B
/// ]
/// ```
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if CBOR serialization fails.
pub fn encode_pairing_context_v2(
    wire_version: [u64; 3],
    suite: &str,
    transport_profile: &str,
    candidate_id: &str,
    offer_hash: &[u8; 32],
    initiator_role: &str,
    responder_role: &str,
) -> Result<Vec<u8>, CpaceError> {
    let wire = WireValue::Array(vec![
        WireValue::Text(CPACE_CONTEXT_DOMAIN.to_owned()),
        WireValue::Array(vec![
            WireValue::Unsigned(wire_version[0]),
            WireValue::Unsigned(wire_version[1]),
            WireValue::Unsigned(wire_version[2]),
        ]),
        WireValue::Text(suite.to_owned()),
        WireValue::Text(transport_profile.to_owned()),
        WireValue::Text(candidate_id.to_owned()),
        WireValue::Bytes(offer_hash.to_vec()),
        WireValue::Text(initiator_role.to_owned()),
        WireValue::Text(responder_role.to_owned()),
    ]);
    encode_deterministic_cbor(&wire).map_err(|_| CpaceError::MalformedFrame)
}

/// Encodes the standard RAPP BLE pairing context array for the given offer hash.
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if CBOR serialization fails.
pub fn standard_pairing_context_v2(offer_hash: &[u8; 32]) -> Result<Vec<u8>, CpaceError> {
    encode_pairing_context_v2(
        [
            u64::from(WIRE_VERSION_V26_10_1.0),
            u64::from(WIRE_VERSION_V26_10_1.1),
            u64::from(WIRE_VERSION_V26_10_1.2),
        ],
        CPACE_KC2_SUITE,
        "fi.refineid.rapp.ble.v1",
        "ble-direct-1",
        offer_hash,
        "requester",
        "custodian",
    )
}

/// Samples a non-zero scalar using exact rejection sampling per draft-irtf-cfrg-cpace-21 Section 8.3 (Option A).
///
/// # Errors
/// [`CpaceError::InvalidScalar`] if the 32-byte representation is non-canonical or zero.
pub fn sample_scalar_canonical(bytes_32: &[u8; 32]) -> Result<Scalar, CpaceError> {
    let scalar_opt: Option<Scalar> = Scalar::from_canonical_bytes(*bytes_32).into();
    let scalar = scalar_opt.ok_or(CpaceError::InvalidScalar)?;
    if scalar == Scalar::ZERO {
        return Err(CpaceError::InvalidScalar);
    }
    Ok(scalar)
}

/// Samples a non-zero scalar using 64-byte wide reduction modulo $q$ per RAPP KC2 profile (Option B).
///
/// # Errors
/// [`CpaceError::InvalidScalar`] if the reduced scalar is zero (probability $2^{-512}$).
pub fn sample_scalar_wide(bytes_64: &[u8; 64]) -> Result<Scalar, CpaceError> {
    let scalar = Scalar::from_bytes_mod_order_wide(bytes_64);
    if scalar == Scalar::ZERO {
        return Err(CpaceError::InvalidScalar);
    }
    Ok(scalar)
}

/// Computes the CPace generator point $G$ according to the KC2 profile (abort on identity).
///
/// # Errors
/// [`CpaceError::IdentityGenerator`] if the mapped point is the group identity.
pub fn calculate_generator_kc2(
    prs: &[u8],
    context: &[u8],
    sid: &[u8],
) -> Result<RistrettoPoint, CpaceError> {
    let gen_str = generator_string(
        CPACE_RISTRETTO255_DSI,
        prs,
        context,
        sid,
        SHA512_INPUT_BLOCK_SIZE,
    );
    let mut hasher = Sha512::new();
    hasher.update(&gen_str);
    let hash: [u8; 64] = hasher.finalize().into();

    let point = RistrettoPoint::from_uniform_bytes(&hash);
    if point == RistrettoPoint::identity() {
        return Err(CpaceError::IdentityGenerator);
    }
    Ok(point)
}

/// Computes the 64-byte CPace KC2 transcript hash $TH$ per RAPP v26.10.1 §6.1.3:
/// `SHA-512(lv_cat(["RAPP-CPACE-TRANSCRIPT-v2", SID, C, Y_A, Y_B]))`.
#[must_use]
pub fn calculate_transcript_hash_v2(
    sid: &[u8],
    context: &[u8],
    ya: &[u8; CPACE_POINT_SIZE],
    yb: &[u8; CPACE_POINT_SIZE],
) -> [u8; CPACE_TRANSCRIPT_HASH_SIZE] {
    let cat = lv_cat(&[CPACE_TRANSCRIPT_PREFIX, sid, context, ya, yb]);
    let mut hasher = Sha512::new();
    hasher.update(&cat);
    hasher.finalize().into()
}

/// HKDF-Extract-SHA512 per RFC 5869 Section 2.2:
/// `PRK = HMAC-SHA512(salt, IKM)`.
#[must_use]
pub fn hkdf_extract_sha512(salt: &[u8], ikm: &[u8]) -> [u8; CPACE_PRK_SIZE] {
    let mut mac = HmacSha512::new_from_slice(salt).expect("HMAC supports arbitrary key length");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// HKDF-Expand-SHA512 for a single 32-byte output block (N=1) per RFC 5869 Section 2.3:
/// `OKM = HMAC-SHA512(PRK, info || 0x01)[..32]`.
#[must_use]
pub fn hkdf_expand_sha512_32(prk: &[u8; CPACE_PRK_SIZE], info: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha512::new_from_slice(prk).expect("HMAC supports arbitrary key length");
    mac.update(info);
    mac.update(&[1u8]);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

/// Computes a 32-byte mutual confirmation tag (FIRST32 of HMAC-SHA-512) per RAPP v26.10.1 §6.1.3:
/// `FIRST32(HMAC-SHA512(key, lv_cat([tag_prefix, TH])))`.
#[must_use]
pub fn calculate_confirmation_tag(
    key: &[u8; CPACE_CONFIRMATION_KEY_SIZE],
    tag_prefix: &[u8],
    th: &[u8; CPACE_TRANSCRIPT_HASH_SIZE],
) -> [u8; CPACE_TAG_SIZE] {
    let data = lv_cat(&[tag_prefix, th]);
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC supports arbitrary key length");
    mac.update(&data);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; CPACE_TAG_SIZE];
    tag.copy_from_slice(&result[..CPACE_TAG_SIZE]);
    tag
}

/// Verifies a 32-byte confirmation tag in constant time.
///
/// # Errors
/// [`CpaceError::ConfirmationTagMismatch`] if the tag does not match in constant time.
pub fn verify_tag_constant_time(
    expected: &[u8; CPACE_TAG_SIZE],
    actual: &[u8; CPACE_TAG_SIZE],
) -> Result<(), CpaceError> {
    if bool::from(expected.ct_eq(actual)) {
        Ok(())
    } else {
        Err(CpaceError::ConfirmationTagMismatch)
    }
}

/// Key material derived from CPace KC2 transcript and intermediate session key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CpaceKc2Keys {
    prk: [u8; CPACE_PRK_SIZE],
    psk: [u8; CPACE_PSK_SIZE],
    k_a: [u8; CPACE_CONFIRMATION_KEY_SIZE],
    k_b: [u8; CPACE_CONFIRMATION_KEY_SIZE],
    #[zeroize(skip)]
    tag_a: [u8; CPACE_TAG_SIZE],
    #[zeroize(skip)]
    tag_b: [u8; CPACE_TAG_SIZE],
}

impl CpaceKc2Keys {
    /// 64-byte pseudorandom key (PRK) from HKDF-Extract.
    #[must_use]
    pub const fn prk(&self) -> &[u8; CPACE_PRK_SIZE] {
        &self.prk
    }

    /// 32-byte pre-shared key (PSK) for Noise_XXpsk3.
    #[must_use]
    pub const fn psk(&self) -> &[u8; CPACE_PSK_SIZE] {
        &self.psk
    }

    /// 32-byte Initiator confirmation key ($K_A$).
    #[must_use]
    pub const fn k_a(&self) -> &[u8; CPACE_CONFIRMATION_KEY_SIZE] {
        &self.k_a
    }

    /// 32-byte Responder confirmation key ($K_B$).
    #[must_use]
    pub const fn k_b(&self) -> &[u8; CPACE_CONFIRMATION_KEY_SIZE] {
        &self.k_b
    }

    /// 32-byte Initiator confirmation tag ($T_A$).
    #[must_use]
    pub const fn tag_a(&self) -> &[u8; CPACE_TAG_SIZE] {
        &self.tag_a
    }

    /// 32-byte Responder confirmation tag ($T_B$).
    #[must_use]
    pub const fn tag_b(&self) -> &[u8; CPACE_TAG_SIZE] {
        &self.tag_b
    }

    /// Consume this key schedule into a [`PairingSecret`].
    #[must_use]
    pub fn into_pairing_secret(self) -> PairingSecret {
        PairingSecret::from_random_bytes(self.psk)
    }
}

impl fmt::Debug for CpaceKc2Keys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CpaceKc2Keys([redacted])")
    }
}

/// Derives the full CPace KC2 key schedule and confirmation authenticators.
#[must_use]
pub fn derive_kc2_keys(isk: &[u8; 64], th: &[u8; CPACE_TRANSCRIPT_HASH_SIZE]) -> CpaceKc2Keys {
    let prk = hkdf_extract_sha512(th, isk);
    let psk = hkdf_expand_sha512_32(&prk, CPACE_HKDF_PSK_INFO);
    let k_a = hkdf_expand_sha512_32(&prk, CPACE_HKDF_CONFIRM_A_KEY_INFO);
    let k_b = hkdf_expand_sha512_32(&prk, CPACE_HKDF_CONFIRM_B_KEY_INFO);
    let tag_a = calculate_confirmation_tag(&k_a, CPACE_CONFIRM_A_TAG_PREFIX, th);
    let tag_b = calculate_confirmation_tag(&k_b, CPACE_CONFIRM_B_TAG_PREFIX, th);

    CpaceKc2Keys {
        prk,
        psk,
        k_a,
        k_b,
        tag_a,
        tag_b,
    }
}

/// Ephemeral state for the CPace KC2 Initiator (Requester) after Step 1.
#[derive(ZeroizeOnDrop)]
pub struct CpaceKc2Initiator {
    #[zeroize(skip)]
    scalar: Scalar,
    my_public: [u8; CPACE_POINT_SIZE],
    sid: [u8; OFFER_ID_SIZE],
    context: Vec<u8>,
}

impl CpaceKc2Initiator {
    /// Initializes the CPace KC2 Initiator using 64 random bytes (Option B wide reduction).
    ///
    /// Generates $x_A \leftarrow \text{Scalar} \setminus \{0\}$ and computes $Y_A = x_A \cdot G$.
    ///
    /// # Errors
    /// [`CpaceError`] if the code is invalid, scalar is zero, or generator derivation fails.
    pub fn new(
        pairing_code: &str,
        context: &[u8],
        offer_id: &OfferId,
        random_bytes_64: &[u8; 64],
    ) -> Result<(Self, [u8; CPACE_POINT_SIZE]), CpaceError> {
        let scalar = sample_scalar_wide(random_bytes_64)?;
        Self::new_with_scalar(pairing_code, context, offer_id, scalar)
    }

    /// Initializes the CPace KC2 Initiator with an explicit non-zero scalar.
    ///
    /// # Errors
    /// [`CpaceError`] if the code is invalid, scalar is zero, or generator derivation fails.
    pub fn new_with_scalar(
        pairing_code: &str,
        context: &[u8],
        offer_id: &OfferId,
        scalar: Scalar,
    ) -> Result<(Self, [u8; CPACE_POINT_SIZE]), CpaceError> {
        if scalar == Scalar::ZERO {
            return Err(CpaceError::InvalidScalar);
        }
        let normalized = normalize_code(pairing_code)?;
        let mut sid_bytes = [0_u8; OFFER_ID_SIZE];
        sid_bytes.copy_from_slice(offer_id.as_bytes());

        let generator = calculate_generator_kc2(normalized.as_bytes(), context, &sid_bytes)?;
        let my_point = generator * scalar;
        let my_public = my_point.compress().to_bytes();

        let state = Self {
            scalar,
            my_public,
            sid: sid_bytes,
            context: context.to_vec(),
        };
        Ok((state, my_public))
    }

    /// Public ephemeral point $Y_A$ (32 bytes).
    #[must_use]
    pub const fn public_point(&self) -> &[u8; CPACE_POINT_SIZE] {
        &self.my_public
    }

    /// Process Responder's Step 2 message ($Y_B \parallel T_B$, 64 bytes).
    ///
    /// Decompresses $Y_B$, computes shared point $K$, derives keys, and verifies $T_B$ in constant time.
    /// Returns the Initiator's Step 3 authenticator $T_A$ (32 bytes) and the final [`PairingSecret`].
    ///
    /// # Errors
    /// [`CpaceError::InvalidPoint`] if $Y_B$ is invalid or identity.
    /// [`CpaceError::IdentitySharedPoint`] if $K$ is identity.
    /// [`CpaceError::ConfirmationTagMismatch`] if $T_B$ fails constant-time verification.
    pub fn process_step2(
        self,
        step2_bytes: &[u8; CPACE_STEP2_MSG_SIZE],
    ) -> Result<([u8; CPACE_TAG_SIZE], PairingSecret), CpaceError> {
        let mut yb_bytes = [0_u8; CPACE_POINT_SIZE];
        let mut tb_bytes = [0_u8; CPACE_TAG_SIZE];
        yb_bytes.copy_from_slice(&step2_bytes[..CPACE_POINT_SIZE]);
        tb_bytes.copy_from_slice(&step2_bytes[CPACE_POINT_SIZE..]);

        let compressed = CompressedRistretto(yb_bytes);
        let peer_point = compressed.decompress().ok_or(CpaceError::InvalidPoint)?;
        if peer_point == RistrettoPoint::identity() {
            return Err(CpaceError::InvalidPoint);
        }

        let shared_point = peer_point * self.scalar;
        if shared_point == RistrettoPoint::identity() {
            return Err(CpaceError::IdentitySharedPoint);
        }
        let shared_point_bytes = shared_point.compress().to_bytes();

        let isk = calculate_isk(
            &self.sid,
            &shared_point_bytes,
            &self.my_public,
            &[],
            &yb_bytes,
            &[],
        );
        let th = calculate_transcript_hash_v2(&self.sid, &self.context, &self.my_public, &yb_bytes);
        let keys = derive_kc2_keys(&isk, &th);

        verify_tag_constant_time(keys.tag_b(), &tb_bytes)?;

        let tag_a = *keys.tag_a();
        let pairing_secret = keys.into_pairing_secret();
        Ok((tag_a, pairing_secret))
    }

    /// Process Responder's Step 2 message from a byte slice ($Y_B \parallel T_B$, 64 bytes).
    ///
    /// # Errors
    /// [`CpaceError::MalformedFrame`] if slice is not 64 bytes.
    /// [`CpaceError`] if verification fails.
    pub fn process_step2_slice(
        self,
        slice: &[u8],
    ) -> Result<([u8; CPACE_TAG_SIZE], PairingSecret), CpaceError> {
        let step2_bytes: [u8; CPACE_STEP2_MSG_SIZE] =
            slice.try_into().map_err(|_| CpaceError::MalformedFrame)?;
        self.process_step2(&step2_bytes)
    }

    /// Process Responder's Step 2 message from a [`BinaryFrame`].
    ///
    /// # Errors
    /// [`CpaceError`] if frame is invalid or verification fails.
    pub fn process_step2_frame(
        self,
        frame: &BinaryFrame,
    ) -> Result<(BinaryFrame, PairingSecret), CpaceError> {
        let (tag_a, secret) = self.process_step2_slice(frame.as_bytes())?;
        let frame_a = encode_kc2_step3_frame(&tag_a)?;
        Ok((frame_a, secret))
    }
}

impl fmt::Debug for CpaceKc2Initiator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CpaceKc2Initiator([redacted])")
    }
}

/// Responder (Custodian) handler for CPace KC2.
pub struct CpaceKc2Responder;

impl CpaceKc2Responder {
    /// Process Initiator's Step 1 message ($Y_A$, 32 bytes) using 64 random bytes (Option B).
    ///
    /// # Errors
    /// [`CpaceError`] if inputs are invalid or peer point is invalid/identity.
    pub fn process_step1(
        pairing_code: &str,
        context: &[u8],
        offer_id: &OfferId,
        ya_bytes: &[u8; CPACE_POINT_SIZE],
        random_bytes_64: &[u8; 64],
    ) -> Result<([u8; CPACE_STEP2_MSG_SIZE], CpaceKc2ResponderWaiting), CpaceError> {
        let scalar = sample_scalar_wide(random_bytes_64)?;
        Self::process_step1_with_scalar(pairing_code, context, offer_id, ya_bytes, scalar)
    }

    /// Process Initiator's Step 1 message ($Y_A$, 32 bytes) with an explicit scalar.
    ///
    /// Computes $Y_B = x_B \cdot G$, shared point $K = x_B \cdot Y_A$, derives keys, and emits $Y_B \parallel T_B$ (64 bytes).
    ///
    /// # Errors
    /// [`CpaceError::InvalidScalar`] if scalar is zero.
    /// [`CpaceError::InvalidPoint`] if $Y_A$ is invalid or identity.
    /// [`CpaceError::IdentitySharedPoint`] if $K$ is identity.
    pub fn process_step1_with_scalar(
        pairing_code: &str,
        context: &[u8],
        offer_id: &OfferId,
        ya_bytes: &[u8; CPACE_POINT_SIZE],
        scalar: Scalar,
    ) -> Result<([u8; CPACE_STEP2_MSG_SIZE], CpaceKc2ResponderWaiting), CpaceError> {
        if scalar == Scalar::ZERO {
            return Err(CpaceError::InvalidScalar);
        }
        let compressed = CompressedRistretto(*ya_bytes);
        let peer_point = compressed.decompress().ok_or(CpaceError::InvalidPoint)?;
        if peer_point == RistrettoPoint::identity() {
            return Err(CpaceError::InvalidPoint);
        }

        let normalized = normalize_code(pairing_code)?;
        let mut sid_bytes = [0_u8; OFFER_ID_SIZE];
        sid_bytes.copy_from_slice(offer_id.as_bytes());

        let generator = calculate_generator_kc2(normalized.as_bytes(), context, &sid_bytes)?;
        let my_point = generator * scalar;
        let yb_bytes = my_point.compress().to_bytes();

        let shared_point = peer_point * scalar;
        if shared_point == RistrettoPoint::identity() {
            return Err(CpaceError::IdentitySharedPoint);
        }
        let shared_point_bytes = shared_point.compress().to_bytes();

        let isk = calculate_isk(
            &sid_bytes,
            &shared_point_bytes,
            ya_bytes,
            &[],
            &yb_bytes,
            &[],
        );
        let th = calculate_transcript_hash_v2(&sid_bytes, context, ya_bytes, &yb_bytes);
        let keys = derive_kc2_keys(&isk, &th);

        let mut step2_msg = [0_u8; CPACE_STEP2_MSG_SIZE];
        step2_msg[..CPACE_POINT_SIZE].copy_from_slice(&yb_bytes);
        step2_msg[CPACE_POINT_SIZE..].copy_from_slice(keys.tag_b());

        let waiting = CpaceKc2ResponderWaiting {
            expected_tag_a: *keys.tag_a(),
            psk: *keys.psk(),
        };

        Ok((step2_msg, waiting))
    }

    /// Process Initiator's Step 1 message from a byte slice ($Y_A$, 32 bytes).
    ///
    /// # Errors
    /// [`CpaceError::MalformedFrame`] if slice is not 32 bytes.
    /// [`CpaceError`] if step 1 processing fails.
    pub fn process_step1_slice(
        pairing_code: &str,
        context: &[u8],
        offer_id: &OfferId,
        ya_slice: &[u8],
        random_bytes_64: &[u8; 64],
    ) -> Result<([u8; CPACE_STEP2_MSG_SIZE], CpaceKc2ResponderWaiting), CpaceError> {
        let ya_bytes: [u8; CPACE_POINT_SIZE] = ya_slice
            .try_into()
            .map_err(|_| CpaceError::MalformedFrame)?;
        Self::process_step1(pairing_code, context, offer_id, &ya_bytes, random_bytes_64)
    }

    /// Process Initiator's Step 1 message from a [`BinaryFrame`].
    ///
    /// # Errors
    /// [`CpaceError`] if frame is invalid or step 1 processing fails.
    pub fn process_step1_frame(
        pairing_code: &str,
        context: &[u8],
        offer_id: &OfferId,
        frame: &BinaryFrame,
        random_bytes_64: &[u8; 64],
    ) -> Result<(BinaryFrame, CpaceKc2ResponderWaiting), CpaceError> {
        let (step2_bytes, waiting) = Self::process_step1_slice(
            pairing_code,
            context,
            offer_id,
            frame.as_bytes(),
            random_bytes_64,
        )?;
        let frame_b = encode_kc2_step2_frame(&step2_bytes)?;
        Ok((frame_b, waiting))
    }
}

/// Ephemeral state for the CPace KC2 Responder (Custodian) awaiting Initiator's Step 3 ($T_A$).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CpaceKc2ResponderWaiting {
    #[zeroize(skip)]
    expected_tag_a: [u8; CPACE_TAG_SIZE],
    psk: [u8; CPACE_PSK_SIZE],
}

impl fmt::Debug for CpaceKc2ResponderWaiting {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CpaceKc2ResponderWaiting([redacted])")
    }
}

impl CpaceKc2ResponderWaiting {
    /// Expected Initiator confirmation tag ($T_A$, 32 bytes).
    #[must_use]
    pub const fn expected_tag_a(&self) -> &[u8; CPACE_TAG_SIZE] {
        &self.expected_tag_a
    }

    /// Process Initiator's Step 3 message ($T_A$, 32 bytes).
    ///
    /// Verifies $T_A$ in constant time and returns the established [`PairingSecret`].
    ///
    /// # Errors
    /// [`CpaceError::ConfirmationTagMismatch`] if $T_A$ does not match.
    pub fn process_step3(
        self,
        ta_bytes: &[u8; CPACE_TAG_SIZE],
    ) -> Result<PairingSecret, CpaceError> {
        verify_tag_constant_time(&self.expected_tag_a, ta_bytes)?;
        Ok(PairingSecret::from_random_bytes(self.psk))
    }

    /// Process Initiator's Step 3 message from a byte slice ($T_A$, 32 bytes).
    ///
    /// # Errors
    /// [`CpaceError::MalformedFrame`] if slice is not 32 bytes.
    /// [`CpaceError`] if tag verification fails.
    pub fn process_step3_slice(self, slice: &[u8]) -> Result<PairingSecret, CpaceError> {
        let ta_bytes: [u8; CPACE_TAG_SIZE] =
            slice.try_into().map_err(|_| CpaceError::MalformedFrame)?;
        self.process_step3(&ta_bytes)
    }

    /// Process Initiator's Step 3 message from a [`BinaryFrame`].
    ///
    /// # Errors
    /// [`CpaceError`] if frame is malformed or tag verification fails.
    pub fn process_step3_frame(self, frame: &BinaryFrame) -> Result<PairingSecret, CpaceError> {
        self.process_step3_slice(frame.as_bytes())
    }
}

/// Encodes Step 1 message ($Y_A$, 32 bytes) as a [`BinaryFrame`].
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if frame reconstruction fails.
pub fn encode_kc2_step1_frame(ya: &[u8; CPACE_POINT_SIZE]) -> Result<BinaryFrame, CpaceError> {
    BinaryFrame::reconstruct(ya.to_vec()).map_err(|_| CpaceError::MalformedFrame)
}

/// Decodes Step 1 message ($Y_A$, 32 bytes) from a [`BinaryFrame`].
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if the frame is not exactly 32 bytes.
pub fn decode_kc2_step1_frame(frame: &BinaryFrame) -> Result<[u8; CPACE_POINT_SIZE], CpaceError> {
    frame
        .as_bytes()
        .try_into()
        .map_err(|_| CpaceError::MalformedFrame)
}

/// Encodes Step 2 message ($Y_B \parallel T_B$, 64 bytes) as a [`BinaryFrame`].
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if frame reconstruction fails.
pub fn encode_kc2_step2_frame(
    step2_bytes: &[u8; CPACE_STEP2_MSG_SIZE],
) -> Result<BinaryFrame, CpaceError> {
    BinaryFrame::reconstruct(step2_bytes.to_vec()).map_err(|_| CpaceError::MalformedFrame)
}

/// Decodes Step 2 message ($Y_B \parallel T_B$, 64 bytes) from a [`BinaryFrame`].
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if the frame is not exactly 64 bytes.
pub fn decode_kc2_step2_frame(
    frame: &BinaryFrame,
) -> Result<[u8; CPACE_STEP2_MSG_SIZE], CpaceError> {
    frame
        .as_bytes()
        .try_into()
        .map_err(|_| CpaceError::MalformedFrame)
}

/// Encodes Step 3 message ($T_A$, 32 bytes) as a [`BinaryFrame`].
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if frame reconstruction fails.
pub fn encode_kc2_step3_frame(ta: &[u8; CPACE_TAG_SIZE]) -> Result<BinaryFrame, CpaceError> {
    BinaryFrame::reconstruct(ta.to_vec()).map_err(|_| CpaceError::MalformedFrame)
}

/// Decodes Step 3 message ($T_A$, 32 bytes) from a [`BinaryFrame`].
///
/// # Errors
/// [`CpaceError::MalformedFrame`] if the frame is not exactly 32 bytes.
pub fn decode_kc2_step3_frame(frame: &BinaryFrame) -> Result<[u8; CPACE_TAG_SIZE], CpaceError> {
    frame
        .as_bytes()
        .try_into()
        .map_err(|_| CpaceError::MalformedFrame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpace_successful_key_agreement() {
        let offer_id = OfferId::from_array([0x42; OFFER_ID_SIZE]);
        let code = "123 456";

        let random_a = [0x11; 64];
        let random_b = [0x22; 64];

        let alice = CpaceState::new(HandshakeRole::Initiator, code, &offer_id, &random_a)
            .expect("alice init succeeds");
        let bob = CpaceState::new(HandshakeRole::Responder, code, &offer_id, &random_b)
            .expect("bob init succeeds");

        let alice_public = *alice.public_point();
        let bob_public = *bob.public_point();

        // Ensure public points are non-zero and distinct
        assert_ne!(alice_public, [0_u8; 32]);
        assert_ne!(bob_public, [0_u8; 32]);
        assert_ne!(alice_public, bob_public);

        let secret_a = alice.finish(&bob_public).expect("alice completes");
        let secret_b = bob.finish(&alice_public).expect("bob completes");

        // Both parties arrive at the identical 256-bit pairing secret
        assert_eq!(secret_a.expose(), secret_b.expose());
    }

    #[test]
    fn cpace_mismatched_codes_produce_different_secrets() {
        let offer_id = OfferId::from_array([0x42; OFFER_ID_SIZE]);
        let code_alice = "123456";
        let code_eve = "123457";

        let random_a = [0x11; 64];
        let random_e = [0x33; 64];

        let alice = CpaceState::new(HandshakeRole::Initiator, code_alice, &offer_id, &random_a)
            .expect("alice init succeeds");
        let eve = CpaceState::new(HandshakeRole::Responder, code_eve, &offer_id, &random_e)
            .expect("eve init succeeds");

        let alice_public = *alice.public_point();
        let eve_public = *eve.public_point();

        let secret_a = alice.finish(&eve_public).expect("alice completes");
        let secret_e = eve.finish(&alice_public).expect("eve completes");

        // With different codes, derived secrets MUST NOT match
        assert_ne!(secret_a.expose(), secret_e.expose());
    }

    #[test]
    fn cpace_rejects_invalid_public_point() {
        let offer_id = OfferId::from_array([0x42; OFFER_ID_SIZE]);
        let alice = CpaceState::new(HandshakeRole::Initiator, "654321", &offer_id, &[0x55; 64])
            .expect("alice init succeeds");

        // Non-canonical Ristretto point (all 0xFF is not a canonical Ristretto encoding)
        let invalid_point = [0xFF; 32];
        let result = alice.finish(&invalid_point);
        assert_eq!(
            result.expect_err("non-canonical point should fail"),
            CpaceError::InvalidPoint
        );
    }

    #[test]
    fn cpace_binary_frame_round_trip() {
        let offer_id = OfferId::from_array([0x77; OFFER_ID_SIZE]);
        let code = "987 654";

        let alice = CpaceState::new(HandshakeRole::Initiator, code, &offer_id, &[0xAA; 64])
            .expect("alice init succeeds");
        let bob = CpaceState::new(HandshakeRole::Responder, code, &offer_id, &[0xBB; 64])
            .expect("bob init succeeds");

        // Alice writes frame, Bob reads frame
        let alice_frame = alice.write_message().expect("alice encodes frame");
        // Bob writes frame, Alice reads frame
        let bob_frame = bob.write_message().expect("bob encodes frame");

        let secret_b = bob
            .read_message(&alice_frame)
            .expect("bob reads alice frame");
        let secret_a = alice
            .read_message(&bob_frame)
            .expect("alice reads bob frame");

        assert_eq!(secret_a.expose(), secret_b.expose());
    }

    #[test]
    fn cpace_rejects_malformed_binary_frame() {
        // Garbage frame
        let garbage = BinaryFrame::reconstruct(vec![0x01, 0x02, 0x03]).expect("valid frame bytes");
        assert_eq!(
            decode_cpace_frame(&garbage).expect_err("garbage frame should fail"),
            CpaceError::MalformedFrame
        );

        // Frame with wrong domain
        let wrong_domain = WireValue::Array(vec![
            WireValue::Text("WRONG-domain".to_owned()),
            WireValue::Bytes(vec![0u8; 32]),
        ]);
        let encoded = encode_deterministic_cbor(&wrong_domain).expect("cbor encoding succeeds");
        let frame = BinaryFrame::reconstruct(encoded).expect("frame reconstruction succeeds");
        assert_eq!(
            decode_cpace_frame(&frame).expect_err("wrong domain should fail"),
            CpaceError::MalformedFrame
        );
    }

    #[test]
    fn cpace_draft_appendix_a_utility_functions() {
        // Appendix A.1.2: prepend_len(b"") -> 00
        assert_eq!(prepend_len(b""), vec![0x00]);
        // prepend_len(b"1234") -> 0431323334
        assert_eq!(prepend_len(b"1234"), vec![0x04, 0x31, 0x32, 0x33, 0x34]);

        // Appendix A.1.4: lv_cat(b"1234", b"5", b"", b"678") -> 043132333401350003363738
        let cat = lv_cat(&[b"1234", b"5", b"", b"678"]);
        let expected = [
            0x04, 0x31, 0x32, 0x33, 0x34, 0x01, 0x35, 0x00, 0x03, 0x36, 0x37, 0x38,
        ];
        assert_eq!(cat, expected);
    }

    #[test]
    fn cpace_draft_appendix_b3_official_test_vector() {
        // draft-irtf-cfrg-cpace-21 Appendix B.3 (CPACE-RISTR255-SHA512)
        let prs = b"Password";
        let dsi = b"CPaceRistretto255";
        let ci: [u8; 24] = [
            0x0b, 0x41, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6f, 0x72, 0x0b, 0x42,
            0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72,
        ];
        let sid: [u8; 16] = [
            0x7e, 0x4b, 0x47, 0x91, 0xd6, 0xa8, 0xef, 0x01, 0x9b, 0x93, 0x6c, 0x79, 0xfb, 0x7f,
            0x2c, 0x57,
        ];

        let gen_str = generator_string(dsi, prs, &ci, &sid, 128);
        assert_eq!(gen_str.len(), 170);

        let mut hasher = Sha512::new();
        hasher.update(&gen_str);
        let gen_str_hash: [u8; 64] = hasher.finalize().into();
        let expected_hash_prefix: [u8; 8] = [0xda, 0x6d, 0x3d, 0xdc, 0x88, 0x02, 0xfc, 0xa9];
        assert_eq!(&gen_str_hash[..8], &expected_hash_prefix);

        let g = RistrettoPoint::from_uniform_bytes(&gen_str_hash);
        let encoded_g = g.compress().to_bytes();
        let expected_g: [u8; 32] = [
            0x22, 0x2b, 0x6b, 0x19, 0x5f, 0xe8, 0x4b, 0x16, 0x52, 0xba, 0xdb, 0x6f, 0x6a, 0x3a,
            0xe3, 0xd2, 0x43, 0x41, 0xe7, 0x30, 0x69, 0x67, 0xf0, 0xb8, 0x11, 0x5b, 0x40, 0xd5,
            0x69, 0x8c, 0x7e, 0x56,
        ];
        assert_eq!(encoded_g, expected_g);

        // Party A scalar and public point
        let ya_bytes: [u8; 32] = [
            0xda, 0x3d, 0x23, 0x70, 0x0a, 0x9e, 0x56, 0x99, 0x25, 0x8a, 0xef, 0x94, 0xdc, 0x06,
            0x0d, 0xfd, 0xa5, 0xeb, 0xb6, 0x1f, 0x02, 0xa5, 0xea, 0x77, 0xfa, 0xd5, 0x3f, 0x4f,
            0xf0, 0x97, 0x6d, 0x08,
        ];
        let ya = Scalar::from_canonical_bytes(ya_bytes).expect("canonical scalar");
        let ya_point = g * ya;
        let ya_public = ya_point.compress().to_bytes();
        let expected_ya: [u8; 32] = [
            0xd6, 0xba, 0xc4, 0x80, 0xf2, 0xc3, 0x86, 0xc3, 0x94, 0xef, 0xc7, 0xc4, 0x7a, 0xdb,
            0x99, 0x25, 0xdc, 0xd2, 0x63, 0x0b, 0x64, 0xf2, 0x40, 0xc5, 0x0f, 0x8d, 0x0e, 0xec,
            0x48, 0x2b, 0x91, 0x57,
        ];
        assert_eq!(ya_public, expected_ya);

        // Party B scalar and public point
        let yb_bytes: [u8; 32] = [
            0xd2, 0x31, 0x6b, 0x45, 0x47, 0x18, 0xc3, 0x53, 0x62, 0xd8, 0x3d, 0x69, 0xdf, 0x63,
            0x20, 0xf3, 0x85, 0x78, 0xed, 0x59, 0x84, 0x65, 0x14, 0x35, 0xe2, 0x94, 0x97, 0x62,
            0xd9, 0x00, 0xb8, 0x0d,
        ];
        let yb = Scalar::from_canonical_bytes(yb_bytes).expect("canonical scalar");
        let yb_point = g * yb;
        let yb_public = yb_point.compress().to_bytes();
        let expected_yb: [u8; 32] = [
            0x3e, 0xa7, 0xe0, 0xb1, 0x95, 0x60, 0xd7, 0xc0, 0xb0, 0xf5, 0x73, 0x4f, 0x63, 0xb9,
            0x55, 0x28, 0x6d, 0xfa, 0x82, 0x32, 0xb5, 0xeb, 0xe6, 0x33, 0x24, 0xe2, 0xd9, 0xe7,
            0x43, 0x3f, 0x72, 0x58,
        ];
        assert_eq!(yb_public, expected_yb);

        // Shared point K
        let k_a = (CompressedRistretto(yb_public).decompress().expect("valid") * ya)
            .compress()
            .to_bytes();
        let k_b = (CompressedRistretto(ya_public).decompress().expect("valid") * yb)
            .compress()
            .to_bytes();
        assert_eq!(k_a, k_b);
        let expected_k: [u8; 32] = [
            0x80, 0xb6, 0x9a, 0x8a, 0x76, 0x45, 0x7a, 0xb6, 0xa4, 0xd7, 0xf8, 0x87, 0xa4, 0xbf,
            0x6b, 0x55, 0xa2, 0xf8, 0x0a, 0xc1, 0x9c, 0x33, 0x3f, 0x91, 0x7a, 0x05, 0xfc, 0x98,
            0x87, 0xc8, 0xb4, 0x0f,
        ];
        assert_eq!(k_a, expected_k);

        // ISK derivation
        let ada = b"ADa";
        let adb = b"ADb";
        let isk = calculate_isk(&sid, &k_a, &ya_public, ada, &yb_public, adb);
        let expected_isk_prefix: [u8; 8] = [0xb6, 0x9e, 0xff, 0xbf, 0x61, 0xb5, 0x1d, 0x56];
        assert_eq!(&isk[..8], &expected_isk_prefix);
        let expected_isk_suffix: [u8; 8] = [0x3f, 0xa2, 0x06, 0x8a, 0xf7, 0x90, 0x04, 0x47];
        assert_eq!(&isk[56..], &expected_isk_suffix);
    }

    #[test]
    fn cpace_kc2_golden_synthetic_vectors() {
        let code = "7KX4M9";
        let sid_bytes =
            hex::decode("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
                .expect("valid hex");
        let offer_hash_bytes: [u8; 32] =
            hex::decode("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
                .expect("valid hex")
                .try_into()
                .expect("offer hash is 32 bytes");

        let sid_array: [u8; 32] = sid_bytes.as_slice().try_into().expect("sid is 32 bytes");
        let offer_id = OfferId::from_array(sid_array);

        // 1. Context C (192 bytes)
        let context = standard_pairing_context_v2(&offer_hash_bytes).expect("context cbor");
        assert_eq!(context.len(), 192);
        let expected_context_hex = concat!(
            "8877524150502d50414952494e472d434f4e544558542d763283181a0a01784543504143452d5249",
            "5354523235352d5348413531322d524150502d4b4332202b204e6f6973655f585870736b335f32",
            "353531395f436861436861506f6c795f5348413531327766692e726566696e6569642e72617070",
            "2e626c652e76316c626c652d6469726563742d315820303132333435363738393a3b3c3d3e3f40",
            "4142434445464748494a4b4c4d4e4f6972657175657374657269637573746f6469616e"
        );
        assert_eq!(hex::encode(&context), expected_context_hex);

        // 2. Generator G (32 bytes)
        let g = calculate_generator_kc2(code.as_bytes(), &context, &sid_bytes)
            .expect("generator computation");
        assert_ne!(g, RistrettoPoint::identity());
        let g_bytes = g.compress().to_bytes();
        assert_eq!(
            hex::encode(g_bytes),
            "6c94a85a14bcd59f7a698e52cf852cacbe664d68c16c2a0da7b0ac453fb98579"
        );

        // 3. Option B Scalars: 64 repeated bytes
        let random_a = [0x55_u8; 64];
        let random_b = [0x66_u8; 64];

        let scalar_a = sample_scalar_wide(&random_a).expect("scalar A");
        assert_eq!(
            hex::encode(scalar_a.as_bytes()),
            "4ff685e0a9d1b2fe09107fae2c074f4c773fa7b2f07bf944bf886529096b8806"
        );

        let scalar_b = sample_scalar_wide(&random_b).expect("scalar B");
        assert_eq!(
            hex::encode(scalar_b.as_bytes()),
            "0006d881f4d3680e83d49bf6423e9fb9284c62d620fbc452b23de06471807001"
        );

        // 4. Step 1: Initiator computes Y_A (32 bytes)
        let (alice, msg1) = CpaceKc2Initiator::new(code, &context, &offer_id, &random_a)
            .expect("alice init succeeds");
        assert_eq!(
            hex::encode(msg1),
            "0075b41eb07484791ed4a484b7482d5efe14b651f064f1b7628ef5d7bbc91c68"
        );

        // 5. Step 2: Responder processes Y_A and outputs Y_B || T_B (64 bytes)
        let (msg2, bob_waiting) =
            CpaceKc2Responder::process_step1(code, &context, &offer_id, &msg1, &random_b)
                .expect("bob step1 succeeds");
        assert_eq!(msg2.len(), 64);
        assert_eq!(
            hex::encode(&msg2[..32]),
            "26a02e436b318a54e6430738593e73331ab08737ea2ef019fc6f3979d6335325"
        );
        assert_eq!(
            hex::encode(&msg2[32..]),
            "d8b3b7ef675c2031f8d04b42684b5c8ec843f780ac743da937408b0aeaf99274"
        );

        // 6. Step 3: Initiator verifies T_B and outputs T_A (32 bytes) + PSK
        let (msg3, alice_secret) = alice.process_step2(&msg2).expect("alice step2 succeeds");
        assert_eq!(
            hex::encode(msg3),
            "5d80dbd8048e08d9defb5cd73ba52a8e02d50fb29dcc78c4972f281d0446d536"
        );
        assert_eq!(
            hex::encode(alice_secret.expose()),
            "998543e2fda707e9de7e21d563d2bca662e4961bd4540a5627d7ecd71d1194e1"
        );

        // 7. Responder verifies T_A and completes with PSK
        let bob_secret = bob_waiting
            .process_step3(&msg3)
            .expect("bob step3 succeeds");
        assert_eq!(
            hex::encode(bob_secret.expose()),
            "998543e2fda707e9de7e21d563d2bca662e4961bd4540a5627d7ecd71d1194e1"
        );
        assert_eq!(alice_secret.expose(), bob_secret.expose());

        // 8. Verify all published intermediate cryptographic values
        let yb_arr: [u8; 32] = msg2[..32].try_into().expect("msg2 yb slice is 32 bytes");
        let ya_point = g * scalar_a;
        assert_eq!(ya_point.compress().to_bytes(), msg1);
        let yb_point = g * scalar_b;
        assert_eq!(yb_point.compress().to_bytes(), yb_arr);
        let k_point = yb_point * scalar_a;
        assert_eq!(ya_point * scalar_b, k_point);
        assert_eq!(
            hex::encode(k_point.compress().to_bytes()),
            "5eab93c54e9e1ce8778551758416dd9888bbc83f23107db835723d9e53bdf041"
        );

        let isk = calculate_isk(
            &sid_bytes,
            &k_point.compress().to_bytes(),
            &msg1,
            &[],
            &yb_arr,
            &[],
        );
        assert_eq!(
            hex::encode(isk),
            "40b4e7f5fa390b7ef61b49ffc12a54193569670598ae59c5320f3affa581dd7d3e76344bb9f64aa179d64eb41c338e67212040d724ecc322998f98cdf5825e51"
        );

        let th = calculate_transcript_hash_v2(&sid_bytes, &context, &msg1, &yb_arr);
        assert_eq!(
            hex::encode(th),
            "8347ef65ddad97740b2545cb438aa5d6be6b647ad441b571f3a519dc3b777ac705928927d5c56b954dc7c9d7dd41eb621c4b5b977e063feef7ec7a82d6535535"
        );

        let keys = derive_kc2_keys(&isk, &th);
        assert_eq!(
            hex::encode(keys.prk()),
            "9ebb54de035bce9116244ed937c00396ac5766c346b2956f07eb24e9f570f65f93e546f640573c56deae81670bc5fb2f24fd89aa67cb6e753be2f85cc138f6f8"
        );
        assert_eq!(
            hex::encode(keys.psk()),
            "998543e2fda707e9de7e21d563d2bca662e4961bd4540a5627d7ecd71d1194e1"
        );
        assert_eq!(
            hex::encode(keys.k_a()),
            "f1307a4104ed2b1d822fc0e361f6b10eb68618953dfdc1528b103b3f211a0cf9"
        );
        assert_eq!(
            hex::encode(keys.k_b()),
            "06b3bbd73f40f0cd2c0c41ebfc5d53cc99796919dd420d9fd7376b15d28753cd"
        );
        assert_eq!(
            hex::encode(keys.tag_a()),
            "5d80dbd8048e08d9defb5cd73ba52a8e02d50fb29dcc78c4972f281d0446d536"
        );
        assert_eq!(
            hex::encode(keys.tag_b()),
            "d8b3b7ef675c2031f8d04b42684b5c8ec843f780ac743da937408b0aeaf99274"
        );
    }

    #[test]
    fn cpace_kc2_mismatched_code_fails_tag_b() {
        let offer_hash = [0x30; 32];
        let offer_id = OfferId::from_array([0x10; 32]);
        let context = standard_pairing_context_v2(&offer_hash).expect("context succeeds");

        let (alice, msg1) = CpaceKc2Initiator::new("7KX4M9", &context, &offer_id, &[0x11; 64])
            .expect("alice init succeeds");
        let (msg2, _) =
            CpaceKc2Responder::process_step1("7KX4M8", &context, &offer_id, &msg1, &[0x22; 64])
                .expect("responder step1 succeeds");

        let err = alice
            .process_step2(&msg2)
            .expect_err("mismatched code must fail tag B");
        assert_eq!(err, CpaceError::ConfirmationTagMismatch);
    }

    #[test]
    fn cpace_kc2_mismatched_context_fails_tag_b() {
        let offer_hash_a = [0x30; 32];
        let offer_hash_b = [0x31; 32];
        let offer_id = OfferId::from_array([0x10; 32]);
        let context_a = standard_pairing_context_v2(&offer_hash_a).expect("context a succeeds");
        let context_b = standard_pairing_context_v2(&offer_hash_b).expect("context b succeeds");

        let (alice, msg1) = CpaceKc2Initiator::new("7KX4M9", &context_a, &offer_id, &[0x11; 64])
            .expect("alice init succeeds");
        let (msg2, _) =
            CpaceKc2Responder::process_step1("7KX4M9", &context_b, &offer_id, &msg1, &[0x22; 64])
                .expect("responder step1 succeeds");

        let err = alice
            .process_step2(&msg2)
            .expect_err("mismatched context must fail tag B");
        assert_eq!(err, CpaceError::ConfirmationTagMismatch);
    }

    #[test]
    fn cpace_kc2_corrupted_step2_tag_fails() {
        let offer_hash = [0x30; 32];
        let offer_id = OfferId::from_array([0x10; 32]);
        let context = standard_pairing_context_v2(&offer_hash).expect("context succeeds");

        let (alice, msg1) = CpaceKc2Initiator::new("7KX4M9", &context, &offer_id, &[0x11; 64])
            .expect("alice init succeeds");
        let (mut msg2, _) =
            CpaceKc2Responder::process_step1("7KX4M9", &context, &offer_id, &msg1, &[0x22; 64])
                .expect("responder step1 succeeds");

        msg2[63] ^= 0x01;
        let err = alice
            .process_step2(&msg2)
            .expect_err("tampered tag B must fail");
        assert_eq!(err, CpaceError::ConfirmationTagMismatch);
    }

    #[test]
    fn cpace_kc2_corrupted_step3_tag_fails() {
        let offer_hash = [0x30; 32];
        let offer_id = OfferId::from_array([0x10; 32]);
        let context = standard_pairing_context_v2(&offer_hash).expect("context succeeds");

        let (alice, msg1) = CpaceKc2Initiator::new("7KX4M9", &context, &offer_id, &[0x11; 64])
            .expect("alice init succeeds");
        let (msg2, bob_waiting) =
            CpaceKc2Responder::process_step1("7KX4M9", &context, &offer_id, &msg1, &[0x22; 64])
                .expect("responder step1 succeeds");

        let (mut msg3, _) = alice.process_step2(&msg2).expect("alice step2 succeeds");
        msg3[31] ^= 0x01;
        let err = bob_waiting
            .process_step3(&msg3)
            .expect_err("tampered tag A must fail");
        assert_eq!(err, CpaceError::ConfirmationTagMismatch);
    }

    #[test]
    fn cpace_kc2_rejects_identity_peer_points() {
        let offer_hash = [0x30; 32];
        let offer_id = OfferId::from_array([0x10; 32]);
        let context = standard_pairing_context_v2(&offer_hash).expect("context succeeds");

        let identity_bytes = RistrettoPoint::identity().compress().to_bytes();
        let err = CpaceKc2Responder::process_step1(
            "7KX4M9",
            &context,
            &offer_id,
            &identity_bytes,
            &[0x22; 64],
        )
        .expect_err("identity YA must fail");
        assert_eq!(err, CpaceError::InvalidPoint);

        let (alice, _) = CpaceKc2Initiator::new("7KX4M9", &context, &offer_id, &[0x11; 64])
            .expect("alice init succeeds");
        let mut bad_step2 = [0u8; 64];
        bad_step2[..32].copy_from_slice(&identity_bytes);
        let err2 = alice
            .process_step2(&bad_step2)
            .expect_err("identity YB must fail");
        assert_eq!(err2, CpaceError::InvalidPoint);
    }

    #[test]
    fn cpace_kc2_rejects_non_canonical_point() {
        let offer_hash = [0x30; 32];
        let offer_id = OfferId::from_array([0x10; 32]);
        let context = standard_pairing_context_v2(&offer_hash).expect("context succeeds");

        let non_canonical = [0xFF; 32];
        let err = CpaceKc2Responder::process_step1(
            "7KX4M9",
            &context,
            &offer_id,
            &non_canonical,
            &[0x22; 64],
        )
        .expect_err("non-canonical YA must fail");
        assert_eq!(err, CpaceError::InvalidPoint);

        let (alice, _) = CpaceKc2Initiator::new("7KX4M9", &context, &offer_id, &[0x11; 64])
            .expect("alice init succeeds");
        let mut bad_step2 = [0u8; 64];
        bad_step2[..32].copy_from_slice(&non_canonical);
        let err2 = alice
            .process_step2(&bad_step2)
            .expect_err("non-canonical YB must fail");
        assert_eq!(err2, CpaceError::InvalidPoint);
    }

    #[test]
    fn cpace_kc2_canonical_scalar_sampling() {
        let valid_canonical = [1u8; 32];
        let scalar = sample_scalar_canonical(&valid_canonical).expect("valid scalar");
        assert_ne!(scalar, Scalar::ZERO);

        let zero_scalar = [0u8; 32];
        assert_eq!(
            sample_scalar_canonical(&zero_scalar).expect_err("zero scalar must fail"),
            CpaceError::InvalidScalar
        );
    }

    #[test]
    fn cpace_kc2_binary_frame_round_trip() {
        let offer_hash = [0x42; 32];
        let offer_id = OfferId::from_array([0x77; OFFER_ID_SIZE]);
        let context = standard_pairing_context_v2(&offer_hash).expect("context succeeds");
        let code = "987 654";

        let (alice, ya) = CpaceKc2Initiator::new(code, &context, &offer_id, &[0xAA; 64])
            .expect("alice init succeeds");
        let frame1 = encode_kc2_step1_frame(&ya).expect("frame 1 encodes");
        assert_eq!(
            decode_kc2_step1_frame(&frame1).expect("frame 1 decodes"),
            ya
        );

        let (frame2, bob_waiting) =
            CpaceKc2Responder::process_step1_frame(code, &context, &offer_id, &frame1, &[0xBB; 64])
                .expect("bob step 1 frame succeeds");

        let (frame3, secret_a) = alice
            .process_step2_frame(&frame2)
            .expect("alice step 2 frame succeeds");
        let secret_b = bob_waiting
            .process_step3_frame(&frame3)
            .expect("bob step 3 frame succeeds");

        assert_eq!(secret_a.expose(), secret_b.expose());
    }

    #[test]
    fn cpace_kc2_error_display() {
        assert_eq!(
            CpaceError::IdentityGenerator.to_string(),
            "derived generator point is group identity"
        );
        assert_eq!(
            CpaceError::ConfirmationTagMismatch.to_string(),
            "CPace confirmation tag mismatch"
        );
    }
}
