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

//! ECDSA signature verification over NIST P-256 and P-384.
//!
//! A key is accepted only on a named curve this module supports, P-256
//! (`secp256r1`) or P-384 (`secp384r1`), referenced by its OID (RFC 5480
//! sec. 2.1.1: PKIX keys use `namedCurve`, and explicit `ECParameters`
//! are refused).
//!
//! Curve arithmetic, SEC 1 point validation, and prehash ECDSA
//! verification delegate to [`p256::ecdsa`] and [`p384::ecdsa`] (both
//! configured with `NORMALIZE_S = false`, accepting standard X.509 / CMS
//! / PKCS#11 signatures across the full `[1, n-1]` scalar range).
//! Deterministic RFC 6979 test signing behind `testkit` delegates to
//! `ecdsa::hazmat::sign_prehashed_rfc6979`.

use crate::container::{EcdsaDer, EcdsaP256, EcdsaP384, Signature};
use crate::oid::{Oid as KnownOid, known};
use refineid_digest::{Sha1, Sha224, Sha256, Sha384, Sha512};

/// SEC 1 uncompressed-point leading format octet (`04`).
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
/// Coordinates in an affine EC point -- X and Y (SEC 1 sec. 2.3.3: an
/// uncompressed point body is two equal-width coordinates).
const POINT_COORDINATE_COUNT: usize = 2;
/// Components in an ECDSA signature -- `r` and `s` (RFC 3279 sec. 2.2.3:
/// `Ecdsa-Sig-Value` is a `SEQUENCE` of two `INTEGER`s).
const SIG_COMPONENT_COUNT: usize = 2;
/// Byte length of a P-256 field element or scalar -- a 256-bit prime
/// field (FIPS 186-4 D.1.2.3 / SEC 2 sec. 2.4.2).
const P256_FIELD_LEN: usize = 32;
/// Byte length of a P-384 field element or scalar -- a 384-bit prime
/// field (FIPS 186-4 D.1.2.4 / SEC 2 sec. 2.5.1).
const P384_FIELD_LEN: usize = 48;

/// Supported NIST named curves for ECDSA verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamedCurve {
    /// NIST P-256 (`secp256r1` / `prime256v1`).
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
}

impl NamedCurve {
    /// Resolve a `namedCurve` OID to a supported [`NamedCurve`].
    fn from_oid(oid: KnownOid<'_>) -> Option<Self> {
        if oid == known::SECP256R1 {
            Some(Self::P256)
        } else if oid == known::SECP384R1 {
            Some(Self::P384)
        } else {
            None
        }
    }

    /// Coordinate and scalar width in octets for this curve.
    const fn field_len(self) -> usize {
        match self {
            Self::P256 => P256_FIELD_LEN,
            Self::P384 => P384_FIELD_LEN,
        }
    }

    /// Encoded uncompressed SEC 1 point width (`1 + 2 * field_len`).
    const fn uncompressed_point_len(self) -> usize {
        self.field_len()
            .saturating_mul(POINT_COORDINATE_COUNT)
            .saturating_add(1)
    }

    /// Fixed-width raw `r || s` signature length (`2 * field_len`).
    pub(crate) const fn raw_signature_len(self) -> usize {
        self.field_len().saturating_mul(SIG_COMPONENT_COUNT)
    }
}

/// Error returned from the ECDSA verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaError {
    /// Curve modulus `p` is malformed (retained for API compatibility).
    BadModulus,
    /// Public key `(Q.x, Q.y)` was not on the curve or had the
    /// wrong encoding (only the uncompressed `04 || X || Y` SEC 1
    /// form of exact field width is accepted).
    BadPublicKey,
    /// Signature parse failed -- ECDSA DER signatures must be one
    /// canonical `SEQUENCE { r INTEGER, s INTEGER }` of positive
    /// minimal integers, and raw signatures must match the curve's
    /// `2 * field_len` width with non-zero halves.
    BadSignature,
    /// `r` or `s` not in `[1, n-1]`.
    SigOutOfRange,
    /// `s` had no inverse mod `n` (retained for API compatibility).
    NotInvertible,
    /// Final compare: `r' != r mod n` -- the signature does not
    /// verify against the supplied public key and message digest.
    VerifyFailed,
}

impl core::fmt::Display for EcdsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadModulus => write!(f, "ECDSA: curve modulus malformed"),
            Self::BadPublicKey => write!(f, "ECDSA: public key off-curve or bad encoding"),
            Self::BadSignature => write!(f, "ECDSA: signature SEQUENCE malformed"),
            Self::SigOutOfRange => write!(f, "ECDSA: r or s out of [1, n-1]"),
            Self::NotInvertible => write!(f, "ECDSA: s has no inverse mod n"),
            Self::VerifyFailed => write!(f, "ECDSA: verification rejected"),
        }
    }
}

impl core::error::Error for EcdsaError {}

/// Uncompressed SEC 1 elliptic-curve point: `04 || X || Y`.
///
/// The constructor `Sec1UncompressedPoint::from_bytes` is the trust
/// boundary: it asserts the leading `04` marker byte
/// (`SEC1_UNCOMPRESSED_TAG`), the even body length, and a non-empty
/// body. Compressed (tag `02` / `03`) and hybrid (tag `06` / `07`)
/// SEC 1 forms are *not* a `Sec1UncompressedPoint` -- this codebase
/// only verifies uncompressed-form keys (FINEID S2 sec. 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sec1UncompressedPoint {
    /// SEC 1 uncompressed-form payload: `04 || X || Y`, X and Y equal-length.
    bytes: Vec<u8>,
}

/// Parse error for `Sec1UncompressedPoint::from_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sec1ParseError {
    /// Buffer empty or doesn't start with the uncompressed-form
    /// magic byte `SEC1_UNCOMPRESSED_TAG` (`04`).
    BadFormatByte,
    /// `04 || X || Y` requires `X` and `Y` of equal length;
    /// odd-length body or empty body are both rejected here.
    BadBodyLength,
}

impl core::fmt::Display for Sec1ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadFormatByte => {
                write!(f, "SEC1 point: expected the uncompressed-form leading tag")
            }
            Self::BadBodyLength => write!(f, "SEC1 point: body must be 2*coord-len, > 0"),
        }
    }
}

impl core::error::Error for Sec1ParseError {}

impl Sec1UncompressedPoint {
    /// Wrap raw SEC 1 bytes. Validates the leading
    /// [`SEC1_UNCOMPRESSED_TAG`] byte and the even-length body
    /// invariant.
    ///
    /// # Errors
    /// [`Sec1ParseError`] if the buffer is empty, doesn't start
    /// with the uncompressed tag, or has an odd-length body.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Result<Self, Sec1ParseError> {
        if bytes.first().copied() != Some(SEC1_UNCOMPRESSED_TAG) {
            return Err(Sec1ParseError::BadFormatByte);
        }
        let body_len = bytes
            .len()
            .checked_sub(1)
            .ok_or(Sec1ParseError::BadFormatByte)?;
        if body_len == 0 || !body_len.is_multiple_of(POINT_COORDINATE_COUNT) {
            return Err(Sec1ParseError::BadBodyLength);
        }
        Ok(Self { bytes })
    }

    /// Borrow the underlying SEC 1 bytes (`04 || X || Y`).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the wrapper and return the owned SEC 1 bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the encoded point in bytes (`1 + 2 * coord_len`).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the underlying buffer is empty (constructor
    /// rejects this; method retained for API symmetry).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// On-curve public key decoded from an uncompressed SEC 1 point.
enum VerifiedPublicKey {
    /// Validated NIST P-256 verifying key.
    P256(p256::ecdsa::VerifyingKey),
    /// Validated NIST P-384 verifying key.
    P384(p384::ecdsa::VerifyingKey),
}

impl VerifiedPublicKey {
    /// Validate `pubkey_sec1` as an uncompressed on-curve public key on `curve`
    /// (SEC 1 sec. 2.3.4, sec. 2.3.6, and sec. 3.2.2.1).
    fn from_sec1(
        curve: NamedCurve,
        pubkey_sec1: &Sec1UncompressedPoint,
    ) -> Result<Self, EcdsaError> {
        let bytes = pubkey_sec1.as_bytes();
        if bytes.first().copied() != Some(SEC1_UNCOMPRESSED_TAG)
            || bytes.len() != curve.uncompressed_point_len()
        {
            return Err(EcdsaError::BadPublicKey);
        }
        match curve {
            NamedCurve::P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self::P256)
                .map_err(|_e| EcdsaError::BadPublicKey),
            NamedCurve::P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                .map(Self::P384)
                .map_err(|_e| EcdsaError::BadPublicKey),
        }
    }

    /// Verify non-zero big-endian scalar magnitudes `(r_bytes, s_bytes)` over
    /// `message_digest`.
    fn verify_scalars(
        &self,
        r_bytes: &[u8],
        s_bytes: &[u8],
        message_digest: &[u8],
    ) -> Result<(), EcdsaError> {
        match self {
            Self::P256(vk) => {
                use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
                let r = pad_scalar::<P256_FIELD_LEN>(r_bytes)?;
                let s = pad_scalar::<P256_FIELD_LEN>(s_bytes)?;
                let sig = p256::ecdsa::Signature::from_scalars(r, s)
                    .map_err(|_e| EcdsaError::SigOutOfRange)?;
                vk.verify_prehash(message_digest, &sig)
                    .map_err(|_e| EcdsaError::VerifyFailed)
            }
            Self::P384(vk) => {
                use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
                let r = pad_scalar::<P384_FIELD_LEN>(r_bytes)?;
                let s = pad_scalar::<P384_FIELD_LEN>(s_bytes)?;
                let sig = p384::ecdsa::Signature::from_scalars(r, s)
                    .map_err(|_e| EcdsaError::SigOutOfRange)?;
                vk.verify_prehash(message_digest, &sig)
                    .map_err(|_e| EcdsaError::VerifyFailed)
            }
        }
    }
}

/// Left-pad a big-endian scalar magnitude into a fixed-width field array.
fn pad_scalar<const N: usize>(magnitude: &[u8]) -> Result<[u8; N], EcdsaError> {
    let lead_zeros = N
        .checked_sub(magnitude.len())
        .ok_or(EcdsaError::SigOutOfRange)?;
    let mut out = [0_u8; N];
    if let Some(tail) = out.get_mut(lead_zeros..) {
        tail.copy_from_slice(magnitude);
    }
    Ok(out)
}

/// Verify a DER-encoded ECDSA signature over an already-computed digest.
///
/// - `curve` -- [`NamedCurve::P256`] or [`NamedCurve::P384`].
/// - `pubkey_sec1` -- uncompressed SEC 1 point (`04 || X || Y`).
/// - `signature_der` -- strict DER `SEQUENCE { r INTEGER, s INTEGER }`.
/// - `message_digest` -- prehashed message digest of any supported hash width.
///
/// # Errors
/// [`EcdsaError`] on malformed public key, non-canonical DER signature,
/// out-of-range scalar, or cryptographic verification mismatch.
pub(crate) fn verify_prehashed(
    curve: NamedCurve,
    pubkey_sec1: &Sec1UncompressedPoint,
    signature_der: &Signature<EcdsaDer>,
    message_digest: &[u8],
) -> Result<(), EcdsaError> {
    let vk = VerifiedPublicKey::from_sec1(curve, pubkey_sec1)?;
    let (r_bytes, s_bytes) = signature_der.parse_ecdsa_signature()?;
    vk.verify_scalars(r_bytes, s_bytes, message_digest)
}

impl Signature<EcdsaDer> {
    /// Convert fixed-width `r || s` concatenation (XMLDSig / PKCS#11 / JWS)
    /// into canonical ASN.1 DER `Ecdsa-Sig-Value`.
    ///
    /// # Errors
    /// [`EcdsaError::BadSignature`] when the input is empty, has an odd
    /// length, or exceeds DER length limits.
    pub fn from_raw_concatenation(raw: &[u8]) -> Result<Self, EcdsaError> {
        use spki::der::{Encode as _, SliceWriter, asn1::UintRef};

        if raw.is_empty() || !raw.len().is_multiple_of(SIG_COMPONENT_COUNT) {
            return Err(EcdsaError::BadSignature);
        }
        let half = raw.len() >> 1_u32;
        let (r, s) = raw.split_at(half);
        let pair = [
            UintRef::new(r).map_err(|_e| EcdsaError::BadSignature)?,
            UintRef::new(s).map_err(|_e| EcdsaError::BadSignature)?,
        ];
        let encoded_len = pair
            .encoded_len()
            .and_then(usize::try_from)
            .map_err(|_e| EcdsaError::BadSignature)?;
        let mut out = vec![0_u8; encoded_len];
        let mut writer = SliceWriter::new(&mut out);
        pair.encode(&mut writer)
            .map_err(|_e| EcdsaError::BadSignature)?;
        let written_len = writer
            .finish()
            .map_err(|_e| EcdsaError::BadSignature)?
            .len();
        if written_len != encoded_len {
            return Err(EcdsaError::BadSignature);
        }
        Ok(Self::new(out))
    }

    /// Decode a strict DER `Ecdsa-Sig-Value` into the positive minimal
    /// big-endian magnitudes of `r` and `s` (RFC 3279 sec. 2.2.3,
    /// ITU-T X.690 sec. 8.3).
    fn parse_ecdsa_signature(&self) -> Result<(&[u8], &[u8]), EcdsaError> {
        use spki::der::{Decode as _, Reader as _, SliceReader, asn1::UintRef};

        let mut reader =
            SliceReader::new(self.as_bytes()).map_err(|_e| EcdsaError::BadSignature)?;
        let (r, s) = reader
            .sequence(|seq| {
                let r = UintRef::decode(seq)?;
                let s = UintRef::decode(seq)?;
                Ok((r.as_bytes(), s.as_bytes()))
            })
            .map_err(|_e: spki::der::Error| EcdsaError::BadSignature)?;
        reader.finish().map_err(|_e| EcdsaError::BadSignature)?;
        if r.is_empty() || r.iter().all(|&b| b == 0) || s.is_empty() || s.iter().all(|&b| b == 0) {
            return Err(EcdsaError::BadSignature);
        }
        Ok((r, s))
    }
}

/// Pull the [`NamedCurve`] and uncompressed public point out of an EC
/// `SubjectPublicKeyInfo`.
///
/// RFC 5480 sec. 2.1.1: the parameters must be a supported `namedCurve`
/// OID (`secp256r1` or `secp384r1`). Explicit `ECParameters`,
/// `implicitCurve`, an unknown curve OID, unused BIT STRING bits, or a
/// point that is not uncompressed SEC 1 of the curve's width all return
/// `None`.
#[must_use]
pub(crate) fn extract_ec_pubkey(spki_der: &[u8]) -> Option<(NamedCurve, Sec1UncompressedPoint)> {
    use spki::SubjectPublicKeyInfoRef;
    use spki::der::Decode as _;
    use spki::der::asn1::ObjectIdentifier;

    let info = SubjectPublicKeyInfoRef::from_der(spki_der).ok()?;
    if info.algorithm.oid.as_bytes() != known::EC_PUBLIC_KEY.as_bytes() {
        return None;
    }
    let curve_oid = info
        .algorithm
        .parameters?
        .decode_as::<ObjectIdentifier>()
        .ok()?;
    let curve = NamedCurve::from_oid(KnownOid::new(curve_oid.as_bytes()).ok()?)?;
    // An EC point is octet-aligned. `as_bytes`, unlike `raw_bytes`,
    // refuses a BIT STRING that declares unused trailing bits.
    let pubkey =
        Sec1UncompressedPoint::from_bytes(info.subject_public_key.as_bytes()?.to_vec()).ok()?;
    if pubkey.len() != curve.uncompressed_point_len() {
        return None;
    }
    Some((curve, pubkey))
}

impl Signature<EcdsaP384> {
    /// Convert this raw `r || s` ECDSA signature into ASN.1 DER
    /// `SEQUENCE { INTEGER r, INTEGER s }` form (FINEID S1 v4.2
    /// sec. 3.8.3).
    #[must_use]
    pub fn into_der(self) -> Option<Signature<EcdsaDer>> {
        Signature::<EcdsaDer>::from_raw_concatenation(self.as_bytes()).ok()
    }
}

impl Signature<EcdsaP256> {
    /// Convert this raw `r || s` ECDSA signature into ASN.1 DER
    /// `SEQUENCE { INTEGER r, INTEGER s }` form.
    #[must_use]
    pub fn into_der(self) -> Option<Signature<EcdsaDer>> {
        Signature::<EcdsaDer>::from_raw_concatenation(self.as_bytes()).ok()
    }
}

impl Sec1UncompressedPoint {
    /// Verify a fixed-width `r || s` signature directly against `self`
    /// on `curve` without intermediate DER re-encoding.
    fn verify_raw(
        &self,
        curve: NamedCurve,
        signature_raw: &[u8],
        message_digest: &[u8],
    ) -> Result<(), EcdsaError> {
        if signature_raw.len() != curve.raw_signature_len() {
            return Err(EcdsaError::BadSignature);
        }
        let vk = VerifiedPublicKey::from_sec1(curve, self)?;
        let (r_half, s_half) = signature_raw.split_at(curve.field_len());
        if r_half.iter().all(|&b| b == 0) || s_half.iter().all(|&b| b == 0) {
            return Err(EcdsaError::BadSignature);
        }
        vk.verify_scalars(r_half, s_half, message_digest)
    }

    /// Verify an ECDSA P-256 + SHA-256 raw `r || s` signature against
    /// this public key.
    ///
    /// # Errors
    /// [`EcdsaError`] on bad key, bad raw signature shape, out-of-range
    /// scalar, or verification mismatch.
    pub fn verify_p256_sha256_raw(
        &self,
        signature_raw: Signature<EcdsaP256>,
        message_digest: Sha256,
    ) -> Result<(), EcdsaError> {
        self.verify_raw(
            NamedCurve::P256,
            signature_raw.as_bytes(),
            message_digest.as_bytes(),
        )
    }

    /// Verify an ECDSA P-384 + SHA-384 raw `r || s` signature against
    /// this public key (FINEID S1 v4.2 sec. 3.8.3).
    ///
    /// # Errors
    /// [`EcdsaError`] on bad key, bad raw signature shape, out-of-range
    /// scalar, or verification mismatch.
    pub fn verify_p384_sha384_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha384,
    ) -> Result<(), EcdsaError> {
        self.verify_raw(
            NamedCurve::P384,
            signature_raw.as_bytes(),
            message_digest.as_bytes(),
        )
    }

    /// Verify a P-384 ECDSA raw `r || s` signature over a SHA-1 digest.
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as [`Self::verify_p384_sha384_raw`].
    pub fn verify_p384_sha1_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha1,
    ) -> Result<(), EcdsaError> {
        self.verify_raw(
            NamedCurve::P384,
            signature_raw.as_bytes(),
            message_digest.as_bytes(),
        )
    }

    /// Verify a P-384 ECDSA raw `r || s` signature over a SHA-224 digest.
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as [`Self::verify_p384_sha384_raw`].
    pub fn verify_p384_sha224_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha224,
    ) -> Result<(), EcdsaError> {
        self.verify_raw(
            NamedCurve::P384,
            signature_raw.as_bytes(),
            message_digest.as_bytes(),
        )
    }

    /// Verify a P-384 ECDSA raw `r || s` signature over a SHA-256 digest.
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as [`Self::verify_p384_sha384_raw`].
    pub fn verify_p384_sha256_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha256,
    ) -> Result<(), EcdsaError> {
        self.verify_raw(
            NamedCurve::P384,
            signature_raw.as_bytes(),
            message_digest.as_bytes(),
        )
    }

    /// Verify a P-384 ECDSA raw `r || s` signature over a SHA-512 digest.
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as [`Self::verify_p384_sha384_raw`].
    pub fn verify_p384_sha512_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha512,
    ) -> Result<(), EcdsaError> {
        self.verify_raw(
            NamedCurve::P384,
            signature_raw.as_bytes(),
            message_digest.as_bytes(),
        )
    }
}

/// Test-only deterministic RFC 6979 ECDSA signing backed by [`ecdsa`],
/// [`p256`], and [`p384`].
///
/// Compiled only for unit tests and the `testkit` feature; never linked
/// into production builds.
#[cfg(any(test, feature = "testkit"))]
pub(crate) mod signing {
    use super::{NamedCurve, P256_FIELD_LEN, P384_FIELD_LEN, Sec1UncompressedPoint, pad_scalar};
    use crate::container::{EcdsaDer, Signature};
    use crate::oid::Oid as KnownOid;
    use crate::signed_data::HashAlgorithm;

    /// Curve-typed inner signing key.
    #[derive(Clone)]
    enum CurveSigningKey {
        /// NIST P-256 signing key.
        P256(p256::ecdsa::SigningKey),
        /// NIST P-384 signing key.
        P384(p384::ecdsa::SigningKey),
    }

    /// An ECDSA private key on a supported curve, paired with its
    /// uncompressed SEC 1 public point.
    #[derive(Clone)]
    pub(crate) struct SigningKey {
        /// Secret scalar key (`ZeroizeOnDrop` upstream).
        key: CurveSigningKey,
        /// Uncompressed public point `d * G`.
        public: Sec1UncompressedPoint,
    }

    impl core::fmt::Debug for SigningKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("SigningKey")
                .field("public", &self.public)
                .finish_non_exhaustive()
        }
    }

    impl SigningKey {
        /// Construct the key whose private scalar is big-endian `scalar`
        /// on `curve_oid`. Returns `None` for an unsupported curve or a
        /// scalar outside `[1, n-1]`.
        pub(crate) fn from_scalar(curve_oid: KnownOid<'_>, scalar: &[u8]) -> Option<Self> {
            if scalar.is_empty() || scalar.iter().all(|&b| b == 0) {
                return None;
            }
            match NamedCurve::from_oid(curve_oid)? {
                NamedCurve::P256 => {
                    let bytes = pad_scalar::<P256_FIELD_LEN>(scalar).ok()?;
                    let key = p256::ecdsa::SigningKey::from_slice(&bytes).ok()?;
                    let sec1 = key.verifying_key().to_sec1_point(false);
                    let public =
                        Sec1UncompressedPoint::from_bytes(sec1.as_bytes().to_vec()).ok()?;
                    Some(Self {
                        key: CurveSigningKey::P256(key),
                        public,
                    })
                }
                NamedCurve::P384 => {
                    let bytes = pad_scalar::<P384_FIELD_LEN>(scalar).ok()?;
                    let key = p384::ecdsa::SigningKey::from_slice(&bytes).ok()?;
                    let sec1 = key.verifying_key().to_sec1_point(false);
                    let public =
                        Sec1UncompressedPoint::from_bytes(sec1.as_bytes().to_vec()).ok()?;
                    Some(Self {
                        key: CurveSigningKey::P384(key),
                        public,
                    })
                }
            }
        }

        /// Deterministic fixture key derived from `seed` and a counter
        /// octet under `hash`.
        pub(crate) fn derive(curve_oid: KnownOid<'_>, hash: HashAlgorithm, seed: &[u8]) -> Self {
            let curve =
                NamedCurve::from_oid(curve_oid).expect("test keys are derived on a table curve");
            let width = curve.field_len();
            (0..=u8::MAX)
                .find_map(|counter| {
                    let mut input = seed.to_vec();
                    input.push(counter);
                    let digest = hash.digest(&input);
                    let candidate = digest.get(..width).unwrap_or(&digest);
                    Self::from_scalar(curve_oid, candidate)
                })
                .expect("a run of digests yields a scalar in range")
        }

        /// Borrow the uncompressed SEC 1 public point.
        pub(crate) const fn public_point(&self) -> &Sec1UncompressedPoint {
            &self.public
        }

        /// Deterministic RFC 6979 DER ECDSA signature over `message`
        /// hashed with `hash`.
        pub(crate) fn sign(&self, hash: HashAlgorithm, message: &[u8]) -> Signature<EcdsaDer> {
            Signature::<EcdsaDer>::from_raw_concatenation(&self.sign_raw(hash, message))
                .expect("two equal-width components encode")
        }

        /// Deterministic RFC 6979 fixed-width `r || s` signature over
        /// `message` hashed with `hash`.
        pub(crate) fn sign_raw(&self, hash: HashAlgorithm, message: &[u8]) -> Vec<u8> {
            self.sign_raw_digest(hash, &hash.digest(message))
        }

        /// Deterministic RFC 6979 fixed-width `r || s` signature over
        /// precomputed `digest` under `hash`.
        pub(crate) fn sign_raw_digest(&self, hash: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
            match (&self.key, hash) {
                (CurveSigningKey::P256(key), HashAlgorithm::Sha256) => {
                    sign_rfc6979::<p256::NistP256, sha2::Sha256>(key, digest)
                }
                (CurveSigningKey::P256(key), HashAlgorithm::Sha384) => {
                    sign_rfc6979::<p256::NistP256, sha2::Sha384>(key, digest)
                }
                (CurveSigningKey::P256(key), HashAlgorithm::Sha512) => {
                    sign_rfc6979::<p256::NistP256, sha2::Sha512>(key, digest)
                }
                (CurveSigningKey::P384(key), HashAlgorithm::Sha256) => {
                    sign_rfc6979::<p384::NistP384, sha2::Sha256>(key, digest)
                }
                (CurveSigningKey::P384(key), HashAlgorithm::Sha384) => {
                    sign_rfc6979::<p384::NistP384, sha2::Sha384>(key, digest)
                }
                (CurveSigningKey::P384(key), HashAlgorithm::Sha512) => {
                    sign_rfc6979::<p384::NistP384, sha2::Sha512>(key, digest)
                }
            }
        }
    }

    /// Sign `digest` deterministically under curve `C` and RFC 6979 HMAC digest `D`.
    fn sign_rfc6979<C, D>(key: &ecdsa::SigningKey<C>, digest: &[u8]) -> Vec<u8>
    where
        C: ecdsa::EcdsaCurve + p256::elliptic_curve::CurveArithmetic,
        D: sha2::Digest + sha2::digest::block_api::BlockSizeUser,
    {
        let non_empty_digest = if digest.is_empty() {
            &[0_u8][..]
        } else {
            digest
        };
        ecdsa::hazmat::sign_prehashed_rfc6979::<C, D>(
            key.as_nonzero_scalar(),
            non_empty_digest,
            &[],
        )
        .0
        .to_bytes()
        .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EcdsaError, NamedCurve, P256_FIELD_LEN, P384_FIELD_LEN, SEC1_UNCOMPRESSED_TAG,
        Sec1UncompressedPoint, VerifiedPublicKey, verify_prehashed,
    };
    use crate::container::{EcdsaDer, EcdsaP256, EcdsaP384, Signature};
    use crate::hex::Hex;
    use crypto_bigint::{
        BoxedUint, Odd, Resize as _, modular::BoxedMontyForm, modular::BoxedMontyParams,
    };
    use p256::elliptic_curve::{Curve as _, sec1::ToSec1Point as _};

    /// ASN.1 SEQUENCE tag, constructed form.
    const ASN1_SEQUENCE_TAG: u8 = 0x30;
    /// ASN.1 INTEGER tag.
    const ASN1_INTEGER_TAG: u8 = 0x02;
    /// DER INTEGER sign-padding byte.
    const DER_SIGN_PAD: u8 = 0;
    /// Smallest byte value with the DER sign bit set.
    const HIGH_BIT_SET: u8 = 0x80;
    /// DER 1-octet long-form length marker.
    const DER_LONG_FORM_1B: u8 = 0x81;
    /// Universal OBJECT IDENTIFIER tag.
    const OID_TAG: u8 = 0x06;
    /// Universal OCTET STRING tag.
    const OCTET_STRING_TAG: u8 = 0x04;
    /// Universal BIT STRING tag.
    const BIT_STRING_TAG: u8 = 0x03;
    /// Universal NULL tag.
    const NULL_TAG: u8 = 0x05;

    /// Odd-width raw fixture -- cannot split into two equal halves.
    const ODD_RAW: [u8; ODD_RAW_LEN] = [1, 2, 3];
    /// Its width, named for the array type position.
    const ODD_RAW_LEN: usize = 3;

    /// Fill byte for an `r` magnitude whose top bit is set.
    const R_FILL_TOP_BIT_SET: u8 = 0xFE;
    /// Trailing fill for the `s` half behind its [`HIGH_BIT_SET`] lead byte.
    const S_FILL_TAIL: u8 = 0x11;
    /// Largest byte with the top bit clear.
    const TOP_BIT_CLEAR_MAX: u8 = 0x7F;
    /// Count of leading zero bytes in the leading-zeros fixture's `r` half.
    const LEADING_ZERO_COUNT: usize = 5;
    /// `r` fill following the fixture's leading zeros.
    const R_FILL_AFTER_ZEROS: u8 = 0xAB;
    /// `s` fill for the leading-zeros fixture.
    const S_FILL: u8 = 0x33;

    /// P-256 CAVP / RFC 6979 test vector public key X.
    const P256_CAVP_QX: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
        "60fed4ba255a9d31c961eb74c6356d68",
        "c049b8923b61fa6ce669622e60f29fb6",
    ));
    /// P-256 CAVP / RFC 6979 test vector public key Y.
    const P256_CAVP_QY: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
        "7903fe1008b8bc99a41ae9e95628bc64",
        "f2f1b20c2d7e9f5177a3c294d4462299",
    ));
    /// P-256 CAVP / RFC 6979 test vector signature R.
    const P256_CAVP_R: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d6",
        "9d2c877b56aaf991c34d0ea84eaf3716",
    ));
    /// P-256 CAVP / RFC 6979 test vector signature S.
    const P256_CAVP_S: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
        "f7cb1c942d657c41d436c7a1b6e29f65",
        "f3e900dbb9aff4064dc4ab2f843acda8",
    ));

    /// P-384 CAVP / RFC 6979 test vector public key X.
    const P384_CAVP_QX: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
        "ec3a4e415b4e19a4568618029f427fa5",
        "da9a8bc4ae92e02e06aae5286b300c64",
        "def8f0ea9055866064a254515480bc13",
    ));
    /// P-384 CAVP / RFC 6979 test vector public key Y.
    const P384_CAVP_QY: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
        "8015d9b72d7d57244ea8ef9ac0c62189",
        "6708a59367f9dfb9f54ca84b3f1c9db1",
        "288b231c3ae0d4fe7344fd",
        "2533264720",
    ));
    /// P-384 CAVP / RFC 6979 test vector signature R.
    const P384_CAVP_R: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
        "94edbb92a5ecb8aad4736e56c691916b",
        "3f88140666ce9fa73d64c4ea95ad133c",
        "81a648152e44acf96e36dd1e80fabe46",
    ));
    /// P-384 CAVP / RFC 6979 test vector signature S.
    const P384_CAVP_S: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
        "99ef4aeb15f178cea1fe40db2603138f",
        "130e740a19624526203b6351d0a3a94f",
        "a329c145786e679e7b82c71a38628ac8",
    ));

    /// RFC 6979 sec. A.2.5 P-256 private key `x`.
    const RFC6979_P256_X: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
        "C9AFA9D845BA75166B5C215767B1D693",
        "4E50C3DB36E89B127B8A622B120F6721",
    ));
    /// RFC 6979 sec. A.2.6 P-384 private key `x`.
    const RFC6979_P384_X: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
        "6B9D3DAD2E1B8C1C05B19875B6659F4D",
        "E23C3B667BF297BA9AA47740787137D8",
        "96D5724E4C70A825F872C9EA60D2EDF5",
    ));

    /// Fixed test message string for the CAVP / RFC 6979 vectors.
    const CAVP_MESSAGE: &[u8] = b"sample";
    /// SEC 1 uncompressed point byte width for P-256.
    const P256_SEC1_POINT_LEN: usize = 1 + P256_FIELD_LEN + P256_FIELD_LEN;
    /// Raw concatenated r||s signature byte width for P-256.
    const P256_RAW_SIGNATURE_LEN: usize = P256_FIELD_LEN + P256_FIELD_LEN;
    /// SEC 1 uncompressed point byte width for P-384.
    const P384_SEC1_POINT_LEN: usize = 1 + P384_FIELD_LEN + P384_FIELD_LEN;
    /// Raw concatenated r||s signature byte width for P-384.
    const P384_RAW_SIGNATURE_LEN: usize = P384_FIELD_LEN + P384_FIELD_LEN;
    /// ANSI X9.62 `prime-field`, the `fieldType` of explicit `ECParameters`.
    const PRIME_FIELD: crate::oid::Oid<'static> = crate::oid::Oid::const_new(
        ::const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.1.1").as_bytes(),
    );
    /// `ECParameters.version` `ecpVer1` (SEC 1 sec. C.2).
    const EC_PARAMETERS_VERSION: u8 = 1;

    fn raw_rs_p384_high_bit_set() -> Vec<u8> {
        let mut v = vec![R_FILL_TOP_BIT_SET; P384_FIELD_LEN];
        v.extend(core::iter::once(HIGH_BIT_SET).chain(core::iter::repeat_n(
            S_FILL_TAIL,
            P384_FIELD_LEN.saturating_sub(1),
        )));
        v
    }

    fn raw_rs_p384_high_bit_clear() -> Vec<u8> {
        let mut v = vec![1; P384_FIELD_LEN];
        v.extend(core::iter::repeat_n(TOP_BIT_CLEAR_MAX, P384_FIELD_LEN));
        v
    }

    fn raw_rs_p384_leading_zeros() -> Vec<u8> {
        let mut v = vec![0; LEADING_ZERO_COUNT];
        v.extend(core::iter::repeat_n(
            R_FILL_AFTER_ZEROS,
            P384_FIELD_LEN.saturating_sub(LEADING_ZERO_COUNT),
        ));
        v.extend(core::iter::repeat_n(S_FILL, P384_FIELD_LEN));
        v
    }

    fn without_leading_zeros(magnitude: &[u8]) -> &[u8] {
        let mut i: usize = 0;
        while i.saturating_add(1) < magnitude.len() && magnitude.get(i).copied() == Some(0) {
            i = i.saturating_add(1);
        }
        magnitude.get(i..).unwrap_or(&[])
    }

    fn sec1(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut point = vec![SEC1_UNCOMPRESSED_TAG];
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        point
    }

    fn components(signature: &Signature<EcdsaDer>, width: usize) -> Vec<u8> {
        let (r, s) = signature.parse_ecdsa_signature().expect("signature parses");
        let mut raw = Vec::new();
        for component in [r, s] {
            raw.extend(core::iter::repeat_n(
                0,
                width.saturating_sub(component.len()),
            ));
            raw.extend_from_slice(component);
        }
        raw
    }

    #[test]
    fn into_der_round_trips_through_parser() {
        for raw in [
            raw_rs_p384_high_bit_set(),
            raw_rs_p384_high_bit_clear(),
            raw_rs_p384_leading_zeros(),
        ] {
            let (r_slice, s_slice) = raw.split_at(raw.len() >> 1);
            let r_expected = r_slice.to_vec();
            let s_expected = s_slice.to_vec();
            let sig: Signature<EcdsaP384> = Signature::new(raw);
            let der = sig
                .into_der()
                .expect("into_der must succeed for valid raw signature");
            let (r_parsed, s_parsed) = der
                .parse_ecdsa_signature()
                .expect("DER from into_der parses back");
            assert_eq!(r_parsed, without_leading_zeros(r_expected.as_slice()));
            assert_eq!(s_parsed, without_leading_zeros(s_expected.as_slice()));
        }
    }

    #[test]
    fn xml_raw_signature_converts_to_der_components() {
        /// Bytes per signature component in this fixture.
        const COMPONENT_BYTES: usize = 4;
        /// Leading zero bytes opening the fixture's `r` half.
        const R_LEADING_ZEROS: usize = 2;
        /// Total fixture width: two [`COMPONENT_BYTES`] halves.
        const RAW_LEN: usize = 8;
        /// Raw `r || s`: `r` opens with two zeros, `s` opens with [`HIGH_BIT_SET`].
        const RAW_RS: [u8; RAW_LEN] = [0, 0, 1, 2, HIGH_BIT_SET, 3, 4, 5];
        let converted = Signature::<EcdsaDer>::from_raw_concatenation(&RAW_RS);
        let signature = converted.expect("valid equal-width XML signature components must convert");
        let (r, s) = signature
            .parse_ecdsa_signature()
            .expect("converted signature must be valid DER");
        assert_eq!(Some(r), RAW_RS.get(R_LEADING_ZEROS..COMPONENT_BYTES));
        assert_eq!(Some(s), RAW_RS.get(COMPONENT_BYTES..));
    }

    #[test]
    fn xml_raw_signature_rejects_missing_or_unequal_components() {
        assert!(matches!(
            Signature::<EcdsaDer>::from_raw_concatenation(&[]),
            Err(EcdsaError::BadSignature)
        ));
        assert!(matches!(
            Signature::<EcdsaDer>::from_raw_concatenation(&ODD_RAW),
            Err(EcdsaError::BadSignature)
        ));
    }

    #[test]
    fn cavp_p256_sha256_signature_verifies() {
        let mut sec1_bytes = Vec::with_capacity(P256_SEC1_POINT_LEN);
        sec1_bytes.push(SEC1_UNCOMPRESSED_TAG);
        sec1_bytes.extend_from_slice(&P256_CAVP_QX);
        sec1_bytes.extend_from_slice(&P256_CAVP_QY);
        let pubkey = Sec1UncompressedPoint::from_bytes(sec1_bytes).expect("valid P-256 public key");

        let mut raw_sig = Vec::with_capacity(P256_RAW_SIGNATURE_LEN);
        raw_sig.extend_from_slice(&P256_CAVP_R);
        raw_sig.extend_from_slice(&P256_CAVP_S);
        let sig: Signature<EcdsaP256> = Signature::new(raw_sig);

        let digest = refineid_digest::Sha256::of(CAVP_MESSAGE);
        assert_eq!(pubkey.verify_p256_sha256_raw(sig, digest), Ok(()));
    }

    #[test]
    fn cavp_p384_sha384_signature_verifies() {
        let mut sec1_bytes = Vec::with_capacity(P384_SEC1_POINT_LEN);
        sec1_bytes.push(SEC1_UNCOMPRESSED_TAG);
        sec1_bytes.extend_from_slice(&P384_CAVP_QX);
        sec1_bytes.extend_from_slice(&P384_CAVP_QY);
        let pubkey = Sec1UncompressedPoint::from_bytes(sec1_bytes).expect("valid P-384 public key");

        let mut raw_sig = Vec::with_capacity(P384_RAW_SIGNATURE_LEN);
        raw_sig.extend_from_slice(&P384_CAVP_R);
        raw_sig.extend_from_slice(&P384_CAVP_S);
        let sig: Signature<EcdsaP384> = Signature::new(raw_sig);

        let digest = refineid_digest::Sha384::of(CAVP_MESSAGE);
        assert_eq!(pubkey.verify_p384_sha384_raw(sig, digest), Ok(()));
    }

    #[test]
    fn into_der_rejects_empty_and_odd_lengths() {
        let empty_p384: Signature<EcdsaP384> = Signature::new(Vec::new());
        assert!(empty_p384.into_der().is_none());

        let odd_p384: Signature<EcdsaP384> = Signature::new(ODD_RAW.to_vec());
        assert!(odd_p384.into_der().is_none());

        let empty_p256: Signature<EcdsaP256> = Signature::new(Vec::new());
        assert!(empty_p256.into_der().is_none());

        let odd_p256: Signature<EcdsaP256> = Signature::new(ODD_RAW.to_vec());
        assert!(odd_p256.into_der().is_none());
    }

    #[test]
    fn rfc6979_p256_sha256_sample_is_reproduced() {
        let key =
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP256R1, &RFC6979_P256_X)
                .expect("RFC 6979 key is in range");
        assert_eq!(
            key.public_point().as_bytes(),
            sec1(&P256_CAVP_QX, &P256_CAVP_QY).as_slice()
        );
        let signature = key.sign(crate::signed_data::HashAlgorithm::Sha256, CAVP_MESSAGE);
        let mut expected = P256_CAVP_R.to_vec();
        expected.extend_from_slice(&P256_CAVP_S);
        assert_eq!(components(&signature, P256_FIELD_LEN), expected);
    }

    #[test]
    fn rfc6979_p384_sha384_sample_is_reproduced() {
        let key =
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP384R1, &RFC6979_P384_X)
                .expect("RFC 6979 key is in range");
        assert_eq!(
            key.public_point().as_bytes(),
            sec1(&P384_CAVP_QX, &P384_CAVP_QY).as_slice()
        );
        let signature = key.sign(crate::signed_data::HashAlgorithm::Sha384, CAVP_MESSAGE);
        let mut expected = P384_CAVP_R.to_vec();
        expected.extend_from_slice(&P384_CAVP_S);
        assert_eq!(components(&signature, P384_FIELD_LEN), expected);
    }

    #[test]
    fn signing_refuses_a_scalar_outside_the_order() {
        let p256_order = p256::NistP256::ORDER.to_be_bytes();
        let p384_order = p384::NistP384::ORDER.to_be_bytes();
        assert!(
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP256R1, &[0]).is_none()
        );
        assert!(
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP256R1, &p256_order)
                .is_none()
        );
        assert!(
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP384R1, &p384_order)
                .is_none()
        );
        assert!(
            super::signing::SigningKey::from_scalar(crate::oid::known::BRAINPOOL_P256R1, &[1])
                .is_none()
        );
        // Short positive scalar slices remain accepted via left-padding.
        assert!(
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP256R1, &[1]).is_some()
        );
    }

    #[test]
    fn ecdsa_value_must_be_one_canonical_pair() {
        /// Canonical body byte length of two single-octet DER INTEGERs (`02 01 01 02 01 01`).
        const CANONICAL_PAIR_BODY_LEN: u8 = 6;
        let tlv = |tag: u8, value: &[u8]| refineid_ber::tlv(tag, value).expect("fixture TLV");
        let integer = |value: &[u8]| tlv(ASN1_INTEGER_TAG, value);
        let pair = |body: Vec<u8>| Signature::<EcdsaDer>::new(tlv(ASN1_SEQUENCE_TAG, &body));
        let one = integer(&[1]);

        let canonical_body = [one.clone(), one.clone()].concat();
        let canonical = pair(canonical_body.clone());
        assert_eq!(
            canonical.parse_ecdsa_signature(),
            Ok((&[1_u8][..], &[1_u8][..]))
        );

        let mut non_minimal_seq_len =
            vec![ASN1_SEQUENCE_TAG, DER_LONG_FORM_1B, CANONICAL_PAIR_BODY_LEN];
        non_minimal_seq_len.extend_from_slice(&canonical_body);

        for malformed in [
            pair([one.clone(), one.clone(), one.clone()].concat()),
            pair(one.clone()),
            pair([integer(&[DER_SIGN_PAD, 1]), one.clone()].concat()),
            pair([integer(&[HIGH_BIT_SET]), one.clone()].concat()),
            pair([integer(&[]), one.clone()].concat()),
            pair([integer(&[DER_SIGN_PAD]), one.clone()].concat()),
            pair([one.clone(), integer(&[DER_SIGN_PAD])].concat()),
            Signature::<EcdsaDer>::new(non_minimal_seq_len),
        ] {
            assert_eq!(
                malformed.parse_ecdsa_signature(),
                Err(EcdsaError::BadSignature)
            );
        }
        let mut trailing = canonical.into_bytes();
        trailing.push(DER_SIGN_PAD);
        assert_eq!(
            Signature::<EcdsaDer>::new(trailing).parse_ecdsa_signature(),
            Err(EcdsaError::BadSignature)
        );
    }

    /// Big-endian domain parameters derived for test fixtures.
    struct CurveParameters {
        p: Vec<u8>,
        a: Vec<u8>,
        b: Vec<u8>,
        gx: Vec<u8>,
        gy: Vec<u8>,
        n: Vec<u8>,
    }

    /// Derive `(p, a, b, gx, gy, n)` in big-endian bytes from the FIPS 186-4
    /// Solinas prime exponents and upstream generator / order so test fixtures
    /// carry no hand-copied hex parameter tables.
    fn curve_parameters(curve: NamedCurve) -> CurveParameters {
        /// NIST curves use `a = p - 3`.
        const MINUS_A: u64 = 3;
        /// Bits per byte for `BoxedUint` precision calculation.
        const BITS_PER_BYTE: u32 = 8;
        /// P-256 Solinas exponent 224 (`p = 2^256 - 2^224 + 2^192 + 2^96 - 1`).
        const P256_EXP_224: u32 = 224;
        /// P-256 Solinas exponent 192.
        const P256_EXP_192: u32 = 192;
        /// Shared Solinas exponent 96.
        const SOLINAS_EXP_96: u32 = 96;
        /// P-384 Solinas exponent 128 (`p = 2^384 - 2^128 - 2^96 + 2^32 - 1`).
        const P384_EXP_128: u32 = 128;
        /// P-384 Solinas exponent 32.
        const P384_EXP_32: u32 = 32;

        let width = curve.field_len();
        let bits = u32::try_from(width)
            .expect("fits u32")
            .saturating_mul(BITS_PER_BYTE);
        let one = BoxedUint::one_with_precision(bits);
        let bit = |exp: u32| one.shl_vartime(exp).expect("exponent < bits");
        // Modulo `2^bits`, `0 - 1` is `2^bits - 1`.
        let two_pow_bits_minus_one = BoxedUint::zero_with_precision(bits).wrapping_sub(&one);

        let (p_uint, gx, gy, n) = match curve {
            NamedCurve::P256 => {
                let p = two_pow_bits_minus_one
                    .wrapping_sub(bit(P256_EXP_224))
                    .wrapping_add(bit(P256_EXP_192))
                    .wrapping_add(bit(SOLINAS_EXP_96));
                let generator = p256::AffinePoint::GENERATOR.to_sec1_point(false);
                (
                    p,
                    generator.x().expect("generator x").as_slice().to_vec(),
                    generator.y().expect("generator y").as_slice().to_vec(),
                    p256::NistP256::ORDER.to_be_bytes().to_vec(),
                )
            }
            NamedCurve::P384 => {
                let p = two_pow_bits_minus_one
                    .wrapping_sub(bit(P384_EXP_128))
                    .wrapping_sub(bit(SOLINAS_EXP_96))
                    .wrapping_add(bit(P384_EXP_32));
                let generator = p384::AffinePoint::GENERATOR.to_sec1_point(false);
                (
                    p,
                    generator.x().expect("generator x").as_slice().to_vec(),
                    generator.y().expect("generator y").as_slice().to_vec(),
                    p384::NistP384::ORDER.to_be_bytes().to_vec(),
                )
            }
        };

        let a_uint = p_uint.wrapping_sub(BoxedUint::from(MINUS_A).resize(bits));
        let p_odd: Odd<BoxedUint> = Option::from(Odd::new(p_uint.clone())).expect("odd prime");
        let params = BoxedMontyParams::new(p_odd);
        let gx_m = BoxedMontyForm::new(BoxedUint::from_be_slice(&gx, bits).expect("gx"), &params);
        let gy_m = BoxedMontyForm::new(BoxedUint::from_be_slice(&gy, bits).expect("gy"), &params);
        let a_m = BoxedMontyForm::new(a_uint.clone(), &params);
        let b_uint =
            (&(&gy_m * &gy_m) - &(&(&(&gx_m * &gx_m) * &gx_m) + &(&a_m * &gx_m))).retrieve();
        let fixed = |v: &BoxedUint| {
            let bytes = v.to_be_bytes();
            bytes
                .get(bytes.len().saturating_sub(width)..)
                .expect("field-width tail")
                .to_vec()
        };
        CurveParameters {
            p: fixed(&p_uint),
            a: fixed(&a_uint),
            b: fixed(&b_uint),
            gx,
            gy,
            n,
        }
    }

    #[test]
    fn explicit_curve_parameters_are_refused() {
        let tlv = |tag: u8, value: &[u8]| refineid_ber::tlv(tag, value).expect("fixture TLV");
        let integer = |magnitude: &[u8]| {
            let mut body = Vec::new();
            if magnitude
                .first()
                .is_some_and(|byte| byte & HIGH_BIT_SET != 0)
            {
                body.push(DER_SIGN_PAD);
            }
            body.extend_from_slice(magnitude);
            tlv(ASN1_INTEGER_TAG, &body)
        };
        let oid = |oid: crate::oid::Oid<'_>| tlv(OID_TAG, oid.as_bytes());
        let sequence = |parts: &[Vec<u8>]| tlv(ASN1_SEQUENCE_TAG, &parts.concat());

        let CurveParameters { p, a, b, gx, gy, n } = curve_parameters(NamedCurve::P256);
        let field = sequence(&[oid(PRIME_FIELD), integer(&p)]);
        let coefficients = sequence(&[tlv(OCTET_STRING_TAG, &a), tlv(OCTET_STRING_TAG, &b)]);
        let explicit = sequence(&[
            integer(&[EC_PARAMETERS_VERSION]),
            field,
            coefficients,
            tlv(OCTET_STRING_TAG, &sec1(&gx, &gy)),
            integer(&n),
        ]);
        let mut point = vec![0];
        point.extend_from_slice(&sec1(&P256_CAVP_QX, &P256_CAVP_QY));
        let key_bits = tlv(BIT_STRING_TAG, &point);
        let spki = |parameters: Vec<u8>| {
            sequence(&[
                sequence(&[oid(crate::oid::known::EC_PUBLIC_KEY), parameters]),
                key_bits.clone(),
            ])
        };

        let named = spki(oid(crate::oid::known::SECP256R1));
        assert!(super::extract_ec_pubkey(&named).is_some());
        crate::x509::SpkiDer::try_from(named.as_slice()).expect("named curve is accepted");

        for refused in [explicit, tlv(NULL_TAG, &[])] {
            let der = spki(refused);
            assert!(super::extract_ec_pubkey(&der).is_none());
            assert!(crate::x509::SpkiDer::try_from(der.as_slice()).is_err());
        }

        // Reject unsupported named curves (Brainpool), hybrid (`06`), compressed (`02`),
        // infinity (`00`), unused BIT STRING bits, and trailing bytes after the SPKI SEQUENCE.
        /// SEC 1 hybrid even-Y tag (`06`), refused despite matching uncompressed byte length.
        const SEC1_HYBRID_EVEN_TAG: u8 = 0x06;
        /// SEC 1 compressed even-Y tag (`02`), refused at the SPKI boundary.
        const SEC1_COMPRESSED_EVEN_TAG: u8 = 0x02;
        let spki_with_bits = |bit_string_body: Vec<u8>| {
            sequence(&[
                sequence(&[
                    oid(crate::oid::known::EC_PUBLIC_KEY),
                    oid(crate::oid::known::SECP256R1),
                ]),
                tlv(BIT_STRING_TAG, &bit_string_body),
            ])
        };
        let mut hybrid_bits = vec![0, SEC1_HYBRID_EVEN_TAG];
        hybrid_bits.extend_from_slice(&P256_CAVP_QX);
        hybrid_bits.extend_from_slice(&P256_CAVP_QY);
        let mut compressed_bits = vec![0, SEC1_COMPRESSED_EVEN_TAG];
        compressed_bits.extend_from_slice(&P256_CAVP_QX);
        let infinity_bits = vec![0, 0];
        let mut unused_bits_point = vec![1];
        unused_bits_point.extend_from_slice(&sec1(&P256_CAVP_QX, &P256_CAVP_QY));
        let mut trailing_spki = named;
        trailing_spki.push(0);

        for malformed_spki in [
            spki(oid(crate::oid::known::BRAINPOOL_P256R1)),
            spki_with_bits(hybrid_bits),
            spki_with_bits(compressed_bits),
            spki_with_bits(infinity_bits),
            spki_with_bits(unused_bits_point),
            trailing_spki,
        ] {
            assert!(super::extract_ec_pubkey(&malformed_spki).is_none());
        }
    }

    fn point_with_short_coordinates(curve: NamedCurve) -> (Vec<u8>, BoxedUint, BoxedUint) {
        /// `(p + 1) / 4` is `p + 1` shifted right by two bits (`p == 3 mod 4`).
        const QUARTER_SHIFT: u32 = 2;
        /// Candidate `x` values tried before giving up.
        const CANDIDATES: u64 = 4096;
        /// Bits per byte.
        const BITS_PER_BYTE: u32 = 8;

        let CurveParameters { p, a, b, .. } = curve_parameters(curve);
        let bits = u32::try_from(curve.field_len())
            .expect("fits u32")
            .saturating_mul(BITS_PER_BYTE);
        let p_uint = BoxedUint::from_be_slice(&p, bits).expect("field prime");
        let a_uint = BoxedUint::from_be_slice(&a, bits).expect("a coeff");
        let b_uint = BoxedUint::from_be_slice(&b, bits).expect("b coeff");
        let p_odd: Odd<BoxedUint> = Option::from(Odd::new(p_uint.clone())).expect("odd prime");
        let params = BoxedMontyParams::new(p_odd);
        let a_m = BoxedMontyForm::new(a_uint, &params);
        let b_m = BoxedMontyForm::new(b_uint, &params);
        let one = BoxedUint::one_with_precision(bits);
        let root_exponent = p_uint.wrapping_add(&one).shr(QUARTER_SHIFT);

        let (x, y) = (1..CANDIDATES)
            .find_map(|candidate| {
                let x = BoxedUint::from(candidate).resize(bits);
                let x_m = BoxedMontyForm::new(x.clone(), &params);
                let rhs = &(&(&(&x_m * &x_m) * &x_m) + &(&a_m * &x_m)) + &b_m;
                let root = rhs.pow(&root_exponent).retrieve();
                let negated = p_uint.wrapping_sub(&root);
                [root, negated].into_iter().find_map(|y| {
                    let y_m = BoxedMontyForm::new(y.clone(), &params);
                    let on_curve = (&y_m * &y_m) == rhs;
                    let leading = y.to_be_bytes().first().copied();
                    (on_curve && leading == Some(0)).then_some((x.clone(), y))
                })
            })
            .expect("a non-zero small point exists among the candidates");
        (p, x, y)
    }

    #[test]
    fn public_key_coordinates_are_field_elements_of_the_field_width() {
        /// Compressed SEC 1 even-Y tag (`02`), refused by `Sec1UncompressedPoint`.
        const SEC1_COMPRESSED_EVEN_TAG: u8 = 0x02;

        for curve in [NamedCurve::P256, NamedCurve::P384] {
            let width = curve.field_len();
            let CurveParameters { p, gx, gy, .. } = curve_parameters(curve);
            let public_key = |bytes: Vec<u8>| {
                Sec1UncompressedPoint::from_bytes(bytes)
                    .map_err(|_e| EcdsaError::BadPublicKey)
                    .and_then(|point| VerifiedPublicKey::from_sec1(curve, &point))
                    .map(|_vk| ())
            };

            // Canonical generator succeeds; x = p, y = p, identity / zero coordinates,
            // off-curve, compressed, and wrong-width fail.
            assert_eq!(public_key(sec1(&gx, &gy)), Ok(()));
            assert_eq!(public_key(sec1(&p, &gy)), Err(EcdsaError::BadPublicKey));
            assert_eq!(public_key(sec1(&gx, &p)), Err(EcdsaError::BadPublicKey));
            assert_eq!(public_key(vec![0]), Err(EcdsaError::BadPublicKey));
            assert_eq!(
                public_key(sec1(&vec![0; width], &vec![0; width])),
                Err(EcdsaError::BadPublicKey)
            );

            let mut off_curve_y = gy.clone();
            if let Some(last) = off_curve_y.last_mut() {
                *last ^= 1;
            }
            assert_eq!(
                public_key(sec1(&gx, &off_curve_y)),
                Err(EcdsaError::BadPublicKey)
            );

            let mut compressed = vec![SEC1_COMPRESSED_EVEN_TAG];
            compressed.extend_from_slice(&gx);
            assert_eq!(public_key(compressed), Err(EcdsaError::BadPublicKey));

            let wide = |coordinate: &[u8]| [&[0][..], coordinate].concat();
            assert_eq!(
                public_key(sec1(&wide(&gx), &wide(&gy))),
                Err(EcdsaError::BadPublicKey)
            );

            let (_p_bytes, x, y) = point_with_short_coordinates(curve);
            let full = |value: &BoxedUint| {
                let bytes = value.to_be_bytes();
                bytes
                    .get(bytes.len().saturating_sub(width)..)
                    .expect("field-width tail")
                    .to_vec()
            };
            assert_eq!(public_key(sec1(&full(&x), &full(&y))), Ok(()));

            let p_uint = BoxedUint::from_be_slice(&p, x.bits_precision()).expect("prime");
            let x_alias = p_uint.wrapping_add(&x);
            assert!(
                x_alias > p_uint,
                "alias stays in (p, 2^bits) without wrapping"
            );
            assert_eq!(
                public_key(sec1(&full(&x_alias), &full(&y))),
                Err(EcdsaError::BadPublicKey)
            );

            let short_width = width.saturating_sub(1);
            let shorten = |value: &BoxedUint| {
                let bytes = value.to_be_bytes();
                bytes
                    .get(bytes.len().saturating_sub(short_width)..)
                    .expect("shortened coordinate")
                    .to_vec()
            };
            assert_eq!(
                public_key(sec1(&shorten(&x), &shorten(&y))),
                Err(EcdsaError::BadPublicKey)
            );
        }
    }

    #[test]
    fn both_high_s_and_low_s_signatures_verify() {
        /// Bits per byte for `BoxedUint` precision calculation.
        const BITS_PER_BYTE: u32 = 8;

        // Both RFC 6979 `b"sample"` vectors have `s > n / 2` (high-S). Verify that both the
        // original high-S signature and its low-S negation `(r, n - s)` are accepted across
        // both raw and DER verification paths.
        let p256_bits = u32::try_from(P256_FIELD_LEN)
            .expect("fits u32")
            .saturating_mul(BITS_PER_BYTE);
        let p256_n = BoxedUint::from_be_slice(&p256::NistP256::ORDER.to_be_bytes(), p256_bits)
            .expect("order");
        let p256_s = BoxedUint::from_be_slice(&P256_CAVP_S, p256_bits).expect("s");
        let p256_low_s = p256_n.wrapping_sub(&p256_s).to_be_bytes();
        let p256_pubkey =
            Sec1UncompressedPoint::from_bytes(sec1(&P256_CAVP_QX, &P256_CAVP_QY)).expect("pubkey");
        let p256_digest = refineid_digest::Sha256::of(CAVP_MESSAGE);

        for s_bytes in [P256_CAVP_S.as_slice(), p256_low_s.as_ref()] {
            let raw = [P256_CAVP_R.as_slice(), s_bytes].concat();
            let raw_sig: Signature<EcdsaP256> = Signature::new(raw.clone());
            assert_eq!(
                p256_pubkey.verify_p256_sha256_raw(raw_sig, p256_digest),
                Ok(())
            );
            let der_sig = Signature::<EcdsaDer>::from_raw_concatenation(&raw).expect("der");
            assert_eq!(
                verify_prehashed(
                    NamedCurve::P256,
                    &p256_pubkey,
                    &der_sig,
                    p256_digest.as_bytes()
                ),
                Ok(())
            );
        }

        let p384_bits = u32::try_from(P384_FIELD_LEN)
            .expect("fits u32")
            .saturating_mul(BITS_PER_BYTE);
        let p384_n = BoxedUint::from_be_slice(&p384::NistP384::ORDER.to_be_bytes(), p384_bits)
            .expect("order");
        let p384_s = BoxedUint::from_be_slice(&P384_CAVP_S, p384_bits).expect("s");
        let p384_low_s = p384_n.wrapping_sub(&p384_s).to_be_bytes();
        let p384_pubkey =
            Sec1UncompressedPoint::from_bytes(sec1(&P384_CAVP_QX, &P384_CAVP_QY)).expect("pubkey");
        let p384_digest = refineid_digest::Sha384::of(CAVP_MESSAGE);

        for s_bytes in [P384_CAVP_S.as_slice(), p384_low_s.as_ref()] {
            let raw = [P384_CAVP_R.as_slice(), s_bytes].concat();
            let raw_sig: Signature<EcdsaP384> = Signature::new(raw.clone());
            assert_eq!(
                p384_pubkey.verify_p384_sha384_raw(raw_sig, p384_digest),
                Ok(())
            );
            let der_sig = Signature::<EcdsaDer>::from_raw_concatenation(&raw).expect("der");
            assert_eq!(
                verify_prehashed(
                    NamedCurve::P384,
                    &p384_pubkey,
                    &der_sig,
                    p384_digest.as_bytes()
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn cross_hash_and_error_classifications_hold() {
        /// RFC 6979 sec. A.2.5 P-256 + SHA-512 `b"sample"` expected `r`
        /// (split to avoid a binary-radix lookalike inside hex digits).
        const RFC6979_P256_SHA512_R: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
            "8496a60",
            "b5e9b47c825488827e0495b0e",
            "3fa109ec4568fd3f8d1097678eb97f00",
        ));
        /// RFC 6979 sec. A.2.5 P-256 + SHA-512 `b"sample"` expected `s`.
        const RFC6979_P256_SHA512_S: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
            "2362ab1adbe2b8adf9cb9edab740ea60",
            "49c0281",
            "14f2460f96554f61fae3302fe",
        ));
        /// RFC 6979 sec. A.2.6 P-384 + SHA-512 `b"sample"` expected `r`.
        const RFC6979_P384_SHA512_R: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
            "ed0959d5880ab2d869ae7f6c2915c6d6",
            "0f96507f9cb3e047c004",
            "6861da4a799c",
            "fe30f35cc900056d7c99cd7882433709",
        ));
        /// RFC 6979 sec. A.2.6 P-384 + SHA-512 `b"sample"` expected `s`.
        const RFC6979_P384_SHA512_S: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
            "512c8cceee3890a84058ce1e22dbc219",
            "8f42323ce8aca91",
            "35329f03c068e5112",
            "dc7cc3ef3446defceb01a45c2667fdd5",
        ));
        /// Raw width of the zero-half DER canonicalization fixture.
        const ZERO_FIXTURE_LEN: usize = 8;
        /// Canonical DER body length for `INTEGER 0, INTEGER 0`.
        const ZERO_PAIR_SEQ_LEN: u8 = 6;
        /// Oversized scalar width (`P256_FIELD_LEN + 1`).
        const OVERSIZED_P256_SCALAR_LEN: usize = P256_FIELD_LEN + 1;

        let p256_key =
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP256R1, &RFC6979_P256_X)
                .expect("P-256 key");
        let p384_key =
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP384R1, &RFC6979_P384_X)
                .expect("P-384 key");

        // Published RFC 6979 A.2.5 (P-256 + SHA-512) and A.2.6 (P-384 + SHA-512) wide-digest
        // vectors pin leftmost-`bits(n)` truncation on both signing and verification.
        let sha512_digest = refineid_digest::Sha512::of(CAVP_MESSAGE);
        let p256_sha512_sig =
            p256_key.sign(crate::signed_data::HashAlgorithm::Sha512, CAVP_MESSAGE);
        assert_eq!(
            components(&p256_sha512_sig, P256_FIELD_LEN),
            [
                RFC6979_P256_SHA512_R.as_slice(),
                RFC6979_P256_SHA512_S.as_slice()
            ]
            .concat()
        );
        assert_eq!(
            verify_prehashed(
                NamedCurve::P256,
                p256_key.public_point(),
                &p256_sha512_sig,
                sha512_digest.as_bytes()
            ),
            Ok(())
        );

        // P-384 across all five raw digest entry points (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512).
        let sha1_digest = refineid_digest::Sha1::of(CAVP_MESSAGE);
        let sig_sha1 = Signature::<EcdsaP384>::new(p384_key.sign_raw_digest(
            crate::signed_data::HashAlgorithm::Sha384,
            sha1_digest.as_bytes(),
        ));
        assert_eq!(
            p384_key
                .public_point()
                .verify_p384_sha1_raw(sig_sha1, sha1_digest),
            Ok(())
        );

        let sha224_digest = refineid_digest::Sha224::of(CAVP_MESSAGE);
        let sig_sha224 = Signature::<EcdsaP384>::new(p384_key.sign_raw_digest(
            crate::signed_data::HashAlgorithm::Sha384,
            sha224_digest.as_bytes(),
        ));
        assert_eq!(
            p384_key
                .public_point()
                .verify_p384_sha224_raw(sig_sha224, sha224_digest),
            Ok(())
        );

        let sha256_digest = refineid_digest::Sha256::of(CAVP_MESSAGE);
        let sig_sha256 = Signature::<EcdsaP384>::new(
            p384_key.sign_raw(crate::signed_data::HashAlgorithm::Sha256, CAVP_MESSAGE),
        );
        assert_eq!(
            p384_key
                .public_point()
                .verify_p384_sha256_raw(sig_sha256, sha256_digest),
            Ok(())
        );

        let raw_p384_sha512 =
            p384_key.sign_raw(crate::signed_data::HashAlgorithm::Sha512, CAVP_MESSAGE);
        assert_eq!(
            raw_p384_sha512,
            [
                RFC6979_P384_SHA512_R.as_slice(),
                RFC6979_P384_SHA512_S.as_slice()
            ]
            .concat()
        );
        let sig_sha512 = Signature::<EcdsaP384>::new(raw_p384_sha512);
        assert_eq!(
            p384_key
                .public_point()
                .verify_p384_sha512_raw(sig_sha512, sha512_digest),
            Ok(())
        );

        // Empty-digest guard in `sign_raw_digest` and `verify_prehashed`.
        let empty_digest_raw =
            p256_key.sign_raw_digest(crate::signed_data::HashAlgorithm::Sha256, &[]);
        let empty_digest_der =
            Signature::<EcdsaDer>::from_raw_concatenation(&empty_digest_raw).expect("der");
        assert_eq!(
            verify_prehashed(
                NamedCurve::P256,
                p256_key.public_point(),
                &empty_digest_der,
                &[]
            ),
            Ok(())
        );

        // Zero-half raw input encodes as canonical DER `INTEGER 0` (`02 01 00`) and is rejected
        // by `parse_ecdsa_signature` and `verify_prehashed` with `BadSignature`.
        let zero_der = Signature::<EcdsaDer>::from_raw_concatenation(&[0; ZERO_FIXTURE_LEN])
            .expect("zero halves still encode as canonical DER INTEGER 0");
        assert_eq!(
            zero_der.as_bytes(),
            [
                ASN1_SEQUENCE_TAG,
                ZERO_PAIR_SEQ_LEN,
                ASN1_INTEGER_TAG,
                1,
                0,
                ASN1_INTEGER_TAG,
                1,
                0
            ]
        );
        assert_eq!(
            zero_der.parse_ecdsa_signature(),
            Err(EcdsaError::BadSignature)
        );
        assert_eq!(
            verify_prehashed(
                NamedCurve::P256,
                p256_key.public_point(),
                &zero_der,
                sha256_digest.as_bytes()
            ),
            Err(EcdsaError::BadSignature)
        );

        // DER-path `SigOutOfRange` classification for `r == n`, `s == n`, and `r` wider than field.
        let p256_order_bytes = p256::NistP256::ORDER.to_be_bytes();
        let der_r_eq_n = Signature::<EcdsaDer>::from_raw_concatenation(
            &[p256_order_bytes.as_slice(), P256_CAVP_S.as_slice()].concat(),
        )
        .expect("der");
        let der_s_eq_n = Signature::<EcdsaDer>::from_raw_concatenation(
            &[P256_CAVP_R.as_slice(), p256_order_bytes.as_slice()].concat(),
        )
        .expect("der");
        let der_oversized_r = Signature::<EcdsaDer>::from_raw_concatenation(
            &[
                vec![1; OVERSIZED_P256_SCALAR_LEN].as_slice(),
                vec![1; OVERSIZED_P256_SCALAR_LEN].as_slice(),
            ]
            .concat(),
        )
        .expect("der");
        for out_of_range_der in [der_r_eq_n, der_s_eq_n, der_oversized_r] {
            assert_eq!(
                verify_prehashed(
                    NamedCurve::P256,
                    p256_key.public_point(),
                    &out_of_range_der,
                    sha256_digest.as_bytes()
                ),
                Err(EcdsaError::SigOutOfRange)
            );
        }

        // Error classification on raw verification: wrong width -> BadSignature, zero half ->
        // BadSignature, scalar == n -> SigOutOfRange, flipped digest -> VerifyFailed.
        assert_eq!(
            p256_key.public_point().verify_p256_sha256_raw(
                Signature::<EcdsaP256>::new(vec![1; P384_RAW_SIGNATURE_LEN]),
                sha256_digest
            ),
            Err(EcdsaError::BadSignature)
        );
        let mut zero_r = vec![0; P256_FIELD_LEN];
        zero_r.extend_from_slice(&P256_CAVP_S);
        assert_eq!(
            p256_key
                .public_point()
                .verify_p256_sha256_raw(Signature::<EcdsaP256>::new(zero_r), sha256_digest),
            Err(EcdsaError::BadSignature)
        );
        let mut order_r = p256::NistP256::ORDER.to_be_bytes().to_vec();
        order_r.extend_from_slice(&P256_CAVP_S);
        assert_eq!(
            p256_key
                .public_point()
                .verify_p256_sha256_raw(Signature::<EcdsaP256>::new(order_r), sha256_digest),
            Err(EcdsaError::SigOutOfRange)
        );
        let wrong_digest = refineid_digest::Sha256::of(b"tampered");
        let valid_p256_sig =
            Signature::<EcdsaP256>::new([P256_CAVP_R.as_slice(), P256_CAVP_S.as_slice()].concat());
        assert_eq!(
            p256_key
                .public_point()
                .verify_p256_sha256_raw(valid_p256_sig, wrong_digest),
            Err(EcdsaError::VerifyFailed)
        );
    }
}
