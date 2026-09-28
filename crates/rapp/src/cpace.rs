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
use sha2::{Digest, Sha256, Sha512};
use zeroize::ZeroizeOnDrop;

use super::{
    BinaryFrame, HandshakeRole, OFFER_ID_SIZE, OfferId, PAIRING_SECRET_SIZE, PairingSecret,
    WireValue, decode_deterministic_cbor, encode_deterministic_cbor,
};

/// Byte length of an encoded CPace public point.
pub const CPACE_POINT_SIZE: usize = 32;

/// Domain separator for CPace Ristretto255 group environment (draft-irtf-cfrg-cpace-21).
const CPACE_RISTRETTO255_DSI: &[u8] = b"CPaceRistretto255";
/// Domain separator for intermediate session key derivation (draft-irtf-cfrg-cpace-21).
const CPACE_RISTRETTO255_ISK_DSI: &[u8] = b"CPaceRistretto255_ISK";
/// SHA-512 input block size in bytes (draft-irtf-cfrg-cpace-21).
const SHA512_INPUT_BLOCK_SIZE: usize = 128;
/// Wire framing domain identifier.
const CPACE_FRAME_DOMAIN: &str = "RAPP-cpace-v1";

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

/// Normalizes a human-entered pairing code (removes ASCII whitespace).
fn normalize_code(code: &str) -> Result<String, CpaceError> {
    let trimmed: String = code.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(CpaceError::InvalidCode);
    }
    // Verify numeric or alphanumeric characters
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(CpaceError::InvalidCode);
    }
    Ok(trimmed)
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
}
