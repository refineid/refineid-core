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

//! RSA-PKCS1v15-SHA256 signature verification.
//!
//! Just enough RSA to verify a CRL or OCSP response signed by
//! the DVV CA chain. No key generation, no signing, no
//! private-key handling -- this module never holds a secret. The
//! one exception is the test signer in `signing`, compiled only
//! for tests and the `testkit` feature, which signs with a
//! published test key.
//!
//! Builds on `crypto-bigint`'s `BoxedUint` + `BoxedMontyForm`
//! for arbitrary-precision modular exponentiation. Padding +
//! `DigestInfo` matching follow RFC 8017 §8.2.
//!
//! Constant-time hardening is *not* a goal here -- this verifier
//! only sees CA-published signatures, so timing leaks on the
//! padding/DigestInfo compare don't reveal anything secret.

use crypto_bigint::{
    BoxedUint, Odd,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::container::{RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512, RsaPssSha256, Signature};
use refineid_digest::{HashAlg, SHA1_LEN, SHA384_LEN, SHA512_LEN};

/// Leading-zero byte in a big-endian integer magnitude
/// representation. A zero byte in this position has no
/// numeric weight -- canonical PKCS#1 form (RFC 8017 §3.1)
/// strips every such byte. Used by the value-to-bytes
/// constructors and the corresponding round-trip tests.
const LEADING_ZERO_BYTE: u8 = 0;

/// Bits in one byte. The host platform's byte is 8 bits (POSIX
/// `CHAR_BIT` is mandated to 8 on every platform this code
/// targets; Rust additionally pins `u8` at 8 bits). Used by
/// `raw_recover` to convert a modulus byte-length into the bit
/// count `BoxedUint::from_be_slice` wants.
const BITS_PER_BYTE: u32 = 8;

/// `usize` companion to [`BITS_PER_BYTE`] for buffer arithmetic.
const BITS_PER_BYTE_USIZE: usize = 8;

/// `BoxedUint` limb size in bits. The crypto-bigint crate
/// stores arbitrary-precision integers as a sequence of `u64`
/// "limbs"; precision arguments to its constructors round up
/// to a multiple of one limb. Used to align the bit-precision
/// argument in `raw_recover` so the modulus and signature fit
/// in a whole number of limbs.
const BOXED_UINT_LIMB_BITS: u32 = 64;

/// SHA-256 output width used by the fixed RSA-PSS profile.
const SHA256_OUTPUT_BYTES: usize = 32;

/// Salt width in the EU trusted-list RSA-PSS profile.
const PSS_SHA256_SALT_BYTES: usize = SHA256_OUTPUT_BYTES;

/// Eight zero octets prefixed to `mHash || salt` by EMSA-PSS.
const PSS_ZERO_PREFIX_BYTES: usize = 8;

/// EMSA-PSS trailer field value, 188 decimal (RFC 8017 sec. 9.1.1).
const PSS_TRAILER_FIELD: u8 = 0xBC;

/// Separator between the zero padding string and salt in EMSA-PSS DB.
const PSS_DB_SEPARATOR: u8 = 0x01;

/// Mask whose every bit is one, used to inspect the unused high bits.
const FULL_BYTE_MASK: u8 = 0xFF;

/// EMSA-PSS bytes outside the hash and the salt-bearing data
/// block: the [`PSS_DB_SEPARATOR`] byte and the trailer field.
/// This is the additive term in RFC 8017 sec. 9.1.2 step 3's
/// "emLen < hLen + sLen + 2" consistency check.
const PSS_SEPARATOR_AND_TRAILER_BYTES: usize = 2;

/// RSA modulus in PKCS#1 form (RFC 8017 §3.1): big-endian
/// magnitude bytes, no leading-zero sign byte. Constructor
/// enforces:
///
/// - non-empty;
/// - first byte non-zero (canonical PKCS#1; the ASN.1 INTEGER
///   sign-byte must already be stripped by the parser before
///   calling here);
/// - bit length in [512, 16384] -- below 512 isn't real RSA
///   (FIPS 186-5 floor is 2048, but FINEID legacy cards still
///   issue some 1024-bit), above 16384 is past anything the
///   ecosystem produces;
/// - low byte odd -- RSA moduli are products of two odd primes;
///   an even modulus means the parser gave us garbage and the
///   verifier would reject it later anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaModulus(Vec<u8>);

/// Construction errors for [`RsaModulus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaModulusError {
    /// Input slice was empty.
    Empty,
    /// First byte was zero -- modulus must be in canonical
    /// PKCS#1 form with the ASN.1 sign byte already stripped.
    LeadingZero,
    /// Bit length below the floor.
    BitsTooFew {
        /// Observed modulus bit length. Tier 0 `usize`;
        /// arithmetic count.
        bits: usize,
        /// Refineid's accepted floor. Tier 0 `usize`.
        min: usize,
    },
    /// Bit length above the ceiling.
    BitsTooMany {
        /// Observed modulus bit length. Tier 0 `usize`.
        bits: usize,
        /// Refineid's accepted ceiling. Tier 0 `usize`.
        max: usize,
    },
    /// Low byte was even.
    Even,
}

impl core::fmt::Display for RsaModulusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "RSA modulus: empty"),
            Self::LeadingZero => write!(f, "RSA modulus: leading zero byte (not canonical PKCS#1)"),
            Self::BitsTooFew { bits, min } => {
                write!(f, "RSA modulus: {bits}-bit, minimum is {min}")
            }
            Self::BitsTooMany { bits, max } => {
                write!(f, "RSA modulus: {bits}-bit, maximum is {max}")
            }
            Self::Even => write!(f, "RSA modulus: even (not a product of odd primes)"),
        }
    }
}

impl core::error::Error for RsaModulusError {}

impl RsaModulus {
    /// Minimum modulus size accepted. The keys this type admits
    /// are the FINEID issuing CAs (RSA 4096 or elliptic-curve) and the
    /// card's own authentication key as the PKCS#11 module reads it
    /// (RSA 3072 on FINEID S4-1 v3.1, secp384r1 on v4.0). 512-bit
    /// RSA has been factored publicly since 1999 and 1024-bit is
    /// deprecated everywhere; nothing legitimate here is below 2048.
    pub const MIN_BITS: usize = 2048;
    /// Maximum modulus size accepted. 16 kbit ceiling is well
    /// past anything the ecosystem produces (current upper end
    /// is 4096-bit RSA in the FINEID issuing CAs).
    pub const MAX_BITS: usize = 16384;

    /// Build from PKCS#1 magnitude bytes (no sign byte).
    ///
    /// # Errors
    /// [`RsaModulusError`] when the bytes don't satisfy the
    /// canonical PKCS#1 form / size / parity invariants.
    pub fn try_from_pkcs1(bytes: &[u8]) -> Result<Self, RsaModulusError> {
        let first = *bytes.first().ok_or(RsaModulusError::Empty)?;
        if first == 0 {
            return Err(RsaModulusError::LeadingZero);
        }
        let last = *bytes.last().ok_or(RsaModulusError::Empty)?;
        if last & 1 == 0 {
            return Err(RsaModulusError::Even);
        }
        let leading: usize =
            usize::try_from(first.leading_zeros()).map_err(|_e| RsaModulusError::Empty)?;
        let bits = bytes
            .len()
            .checked_mul(BITS_PER_BYTE_USIZE)
            .and_then(|n| n.checked_sub(leading))
            .ok_or(RsaModulusError::Empty)?;
        if bits < Self::MIN_BITS {
            return Err(RsaModulusError::BitsTooFew {
                bits,
                min: Self::MIN_BITS,
            });
        }
        if bits > Self::MAX_BITS {
            return Err(RsaModulusError::BitsTooMany {
                bits,
                max: Self::MAX_BITS,
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Magnitude bytes, big-endian, leading zero stripped.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Byte length of the modulus -- this is `k` in PKCS#1
    /// terminology (RFC 8017 §3.1), the natural signature
    /// length.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.0.len()
    }

    /// Bit length of the modulus.
    #[must_use]
    pub fn bit_length(&self) -> usize {
        // Invariant: try_from_pkcs1 rejects empty input and caps
        // bit-length at MAX_BITS, so byte_len stays small enough
        // that multiplying by the bits-per-byte factor cannot
        // overflow usize on any supported platform.
        // `leading_zeros()` of a u8 fits in [0, 8] which trivially
        // converts to usize, and a non-zero first byte (also enforced
        // at construction) guarantees the subtraction cannot wrap.
        // Arithmetic stays total (never panics): the zero fallbacks
        // are unreachable for any constructed value.
        let Some(first) = self.0.first().copied() else {
            return 0;
        };
        let leading = usize::try_from(first.leading_zeros()).unwrap_or(0);
        self.0
            .len()
            .checked_mul(BITS_PER_BYTE_USIZE)
            .and_then(|n| n.checked_sub(leading))
            .unwrap_or(0)
    }
}

/// RSA public exponent in PKCS#1 form (RFC 8017 §3.1):
/// big-endian magnitude bytes, no leading-zero sign byte.
/// Constructor enforces:
///
/// - non-empty;
/// - first byte non-zero (canonical PKCS#1 form);
/// - low byte odd -- public exponents are odd (the common
///   values 3, 17, 65537 all are; an even exponent breaks
///   coprimality with phi(n) = (p-1)(q-1) since both p-1 and
///   q-1 are even).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicExponent(Vec<u8>);

/// Construction errors for [`RsaPublicExponent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPublicExponentError {
    /// Input slice was empty.
    Empty,
    /// First byte was zero.
    LeadingZero,
    /// Low byte was even.
    Even,
    /// Public exponent was below the RFC 8017 minimum of three.
    TooSmall,
    /// Public exponent exceeded the bounded 256-bit verification profile.
    TooLarge {
        /// Observed exponent bit length.
        bits: usize,
        /// Accepted ceiling.
        max: usize,
    },
}

impl core::fmt::Display for RsaPublicExponentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "RSA public exponent: empty"),
            Self::LeadingZero => write!(
                f,
                "RSA public exponent: leading zero byte (not canonical PKCS#1)"
            ),
            Self::Even => write!(f, "RSA public exponent: even (not coprime with phi(n))"),
            Self::TooSmall => write!(f, "RSA public exponent: below three"),
            Self::TooLarge { bits, max } => {
                write!(f, "RSA public exponent: {bits}-bit, maximum is {max}")
            }
        }
    }
}

impl core::error::Error for RsaPublicExponentError {}

impl RsaPublicExponent {
    /// Largest exponent accepted by the public verification path.
    /// FIPS 186-5 bounds newly generated RSA exponents to 256 bits.
    pub const MAX_BITS: usize = 256;

    /// Build from PKCS#1 magnitude bytes (no sign byte).
    ///
    /// # Errors
    /// [`RsaPublicExponentError`] when the bytes don't satisfy
    /// the canonical PKCS#1 form / parity invariants.
    pub fn try_from_pkcs1(bytes: &[u8]) -> Result<Self, RsaPublicExponentError> {
        let first = *bytes.first().ok_or(RsaPublicExponentError::Empty)?;
        if first == 0 {
            return Err(RsaPublicExponentError::LeadingZero);
        }
        let last = *bytes.last().ok_or(RsaPublicExponentError::Empty)?;
        if last & 1 == 0 {
            return Err(RsaPublicExponentError::Even);
        }
        /// Smallest valid RSA public exponent (RFC 8017 sec. 3.1:
        /// `e` is an integer between 3 and `n - 1`).
        const MIN_PUBLIC_EXPONENT: u8 = 3;
        if bytes.len() == 1 && first < MIN_PUBLIC_EXPONENT {
            return Err(RsaPublicExponentError::TooSmall);
        }
        let leading = usize::try_from(first.leading_zeros())
            .map_err(|_error| RsaPublicExponentError::Empty)?;
        let bits = bytes
            .len()
            .checked_mul(BITS_PER_BYTE_USIZE)
            .and_then(|width| width.checked_sub(leading))
            .ok_or(RsaPublicExponentError::Empty)?;
        if bits > Self::MAX_BITS {
            return Err(RsaPublicExponentError::TooLarge {
                bits,
                max: Self::MAX_BITS,
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Build from a `u64` integer value. The integer is encoded
    /// big-endian with leading zeros stripped to canonical
    /// PKCS#1 form.
    ///
    /// # Errors
    /// [`RsaPublicExponentError::Empty`] when the value is zero,
    /// [`RsaPublicExponentError::TooSmall`] when the value is one,
    /// [`RsaPublicExponentError::Even`] when the value is even.
    pub fn try_from_value(value: u64) -> Result<Self, RsaPublicExponentError> {
        if value == 0 {
            return Err(RsaPublicExponentError::Empty);
        }
        let be = value.to_be_bytes();
        // Strip leading zero bytes to canonical PKCS#1 form.
        let leading_zeros = be.iter().take_while(|&&b| b == LEADING_ZERO_BYTE).count();
        let stripped = be
            .get(leading_zeros..)
            .ok_or(RsaPublicExponentError::Empty)?;
        Self::try_from_pkcs1(stripped)
    }

    /// `e = 65537` (Fermat prime `F_4` / `2^16 + 1`), the standard
    /// RSA public exponent per NIST SP 800-56B and the value
    /// FINEID issues. Wire form: `01 00 01`.
    #[must_use]
    pub fn e_65537() -> Self {
        /// Canonical big-endian PKCS#1 wire form of 65537 -- the
        /// three magnitude bytes of `2^16 + 1` (RFC 8017 sec. 3.1).
        /// Constructor invariants (non-empty, no leading zero, odd
        /// low byte) are satisfied by inspection of the literal.
        const E_65537_PKCS1_BYTES: &[u8] = &[0x01, 0x00, 0x01];
        Self(E_65537_PKCS1_BYTES.to_vec())
    }

    /// `e = 3`, the smallest valid RSA public exponent
    /// (RFC 8017 §3.1 / "e is an integer between 3 and n−1").
    /// Largely historical; FIPS 186-5 §A.1.1.2 requires e in
    /// `[2^16 + 1, 2^256 - 1]` for new keys.
    #[must_use]
    pub fn e_3() -> Self {
        /// Canonical big-endian PKCS#1 wire form of 3 -- a single
        /// magnitude byte. Constructor invariants satisfied by
        /// inspection.
        const E_3_PKCS1_BYTES: &[u8] = &[0x03];
        Self(E_3_PKCS1_BYTES.to_vec())
    }

    /// Magnitude bytes, big-endian, leading zero stripped.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Parsed RSA public key. Constructors of the field types
/// validate at the trust boundary; downstream code receives
/// parse-and-checked values.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// RSA modulus `n` (Tier 1 newtype enforcing PKCS#1 canonical
    /// form: non-empty, no leading zero, odd, in
    /// `MIN_BITS..=MAX_BITS`).
    pub modulus: RsaModulus,
    /// RSA public exponent `e` (Tier 1 newtype enforcing odd,
    /// at least 3, and within an accepted range).
    pub exponent: RsaPublicExponent,
}

/// Error returned from the PKCS#1 v1.5 RSA verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaVerifyError {
    /// Modulus parsed as zero or even.
    BadModulus,
    /// Signature is a different size than the modulus (or
    /// signature ≥ modulus).
    SignatureOutOfRange,
    /// Decoded message didn't match the PKCS#1 v1.5 padding shape.
    BadPadding,
    /// Decoded payload didn't carry the SHA-256 `DigestInfo`
    /// prefix.
    BadDigestInfo,
    /// Decoded payload's hash didn't match `SHA-256(message)`.
    BadDigest,
}

impl core::fmt::Display for RsaVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadModulus => write!(f, "RSA: malformed modulus"),
            Self::SignatureOutOfRange => write!(f, "RSA: signature out of range vs modulus"),
            Self::BadPadding => write!(f, "RSA: PKCS#1 v1.5 padding mismatch"),
            Self::BadDigestInfo => write!(f, "RSA: SHA-256 DigestInfo prefix mismatch"),
            Self::BadDigest => write!(f, "RSA: signature digest does not match message"),
        }
    }
}

impl core::error::Error for RsaVerifyError {}

/// `DigestInfo` prefix (RFC 8017 §9.2 note 1) followed by the
/// hash itself.
const SHA256_DIGEST_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// PKCS#1 v1.5 `DigestInfo` prefix for SHA-384 (RFC 8017 §9.2
/// step 2 / appendix B.1). The final byte is the OCTET STRING
/// length octet, 48 decimal, introducing the hash itself.
const SHA384_DIGEST_INFO: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
/// PKCS#1 v1.5 `DigestInfo` prefix for SHA-512 (RFC 8017 §9.2
/// step 2 / appendix B.1). The final byte is the OCTET STRING
/// length octet, 64 decimal, introducing the hash itself.
const SHA512_DIGEST_INFO: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// First byte of an EMSA-PKCS1-v1_5 encoded message (RFC 8017
/// sec. 9.2): a zero octet keeping the encoded value below the
/// modulus.
const EMSA_PKCS1_V15_LEADING_BYTE: u8 = 0x00;

/// Second byte of an EMSA-PKCS1-v1_5 encoded message: the block
/// type marking private-key (signature) operations (RFC 8017
/// sec. 9.2 step 5).
const EMSA_PKCS1_V15_BLOCK_TYPE: u8 = 0x01;

/// Fill byte of the EMSA-PKCS1-v1_5 padding string `PS` -- every
/// bit set (RFC 8017 sec. 9.2 step 4).
const EMSA_PKCS1_V15_PS_FILL: u8 = 0xFF;

/// Zero separator byte between the padding string `PS` and the
/// `DigestInfo` payload `T` (RFC 8017 sec. 9.2 step 5).
const EMSA_PKCS1_V15_SEPARATOR: u8 = 0x00;

/// Offset of the padding string `PS` inside the encoded message:
/// the leading zero byte and the block-type byte come first.
const EMSA_PKCS1_V15_PS_OFFSET: usize = 2;

/// Minimum length of the padding string `PS` -- at least eight
/// octets (RFC 8017 sec. 9.2 step 3).
const EMSA_PKCS1_V15_MIN_PS_BYTES: usize = 8;

/// Fixed EMSA-PKCS1-v1_5 overhead around the `DigestInfo`
/// payload: leading zero byte, block-type byte, minimum padding
/// string and the zero separator -- the eleven bytes behind
/// RFC 8017 sec. 9.2 step 3's "intended encoded message length
/// too short" check.
const EMSA_PKCS1_V15_MIN_OVERHEAD_BYTES: usize =
    EMSA_PKCS1_V15_PS_OFFSET + EMSA_PKCS1_V15_MIN_PS_BYTES + 1;

// `verify_pkcs1v15_sha256` is a method on `RsaPublicKey`. See
// `RsaPublicKey::verify_pkcs1v15_sha256` below.

/// Verify a PKCS#1 v1.5 signature over `SHA-384(message)`.
///
/// # Errors
/// As for `verify_pkcs1v15_sha256`.
pub(crate) fn verify_pkcs1v15_sha384(
    key: &RsaPublicKey,
    message: &[u8],
    signature: &Signature<RsaPkcs1Sha384>,
) -> Result<(), RsaVerifyError> {
    let mut hasher = Sha384::new();
    hasher.update(message);
    let digest = hasher.finalize();
    verify_pkcs1v15(
        key,
        SHA384_DIGEST_INFO,
        digest.as_ref(),
        signature.as_bytes(),
    )
}

/// Verify a PKCS#1 v1.5 signature over `SHA-512(message)`.
///
/// # Errors
/// As for `verify_pkcs1v15_sha256`.
pub(crate) fn verify_pkcs1v15_sha512(
    key: &RsaPublicKey,
    message: &[u8],
    signature: &Signature<RsaPkcs1Sha512>,
) -> Result<(), RsaVerifyError> {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let digest = hasher.finalize();
    verify_pkcs1v15(
        key,
        SHA512_DIGEST_INFO,
        digest.as_ref(),
        signature.as_bytes(),
    )
}

/// PKCS#1 v1.5 verifier core. Computes `s^e mod n`, strips
/// padding, and matches the `DigestInfo` prefix + `digest`.
fn verify_pkcs1v15(
    key: &RsaPublicKey,
    digest_info_prefix: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), RsaVerifyError> {
    let em = key.raw_recover(signature)?;

    // PKCS#1 v1.5 EMSA shape (RFC 8017 sec. 9.2): the leading
    // zero byte, the block-type byte, a padding string PS of at
    // least eight fill bytes, the zero separator, then
    // T = DigestInfo || H(M).
    let min_em_len = digest_info_prefix
        .len()
        .checked_add(digest.len())
        .and_then(|n| n.checked_add(EMSA_PKCS1_V15_MIN_OVERHEAD_BYTES))
        .ok_or(RsaVerifyError::BadPadding)?;
    if em.len() < min_em_len
        || em.first().copied() != Some(EMSA_PKCS1_V15_LEADING_BYTE)
        || em.get(1).copied() != Some(EMSA_PKCS1_V15_BLOCK_TYPE)
    {
        return Err(RsaVerifyError::BadPadding);
    }
    let mut i: usize = EMSA_PKCS1_V15_PS_OFFSET;
    while em.get(i).copied() == Some(EMSA_PKCS1_V15_PS_FILL) {
        i = i.checked_add(1).ok_or(RsaVerifyError::BadPadding)?;
    }
    let ps_len = i
        .checked_sub(EMSA_PKCS1_V15_PS_OFFSET)
        .ok_or(RsaVerifyError::BadPadding)?;
    if ps_len < EMSA_PKCS1_V15_MIN_PS_BYTES || em.get(i).copied() != Some(EMSA_PKCS1_V15_SEPARATOR)
    {
        return Err(RsaVerifyError::BadPadding);
    }
    let payload_start = i.checked_add(1).ok_or(RsaVerifyError::BadPadding)?;
    let payload = em.get(payload_start..).ok_or(RsaVerifyError::BadPadding)?;

    let expected_payload_len = digest_info_prefix
        .len()
        .checked_add(digest.len())
        .ok_or(RsaVerifyError::BadDigestInfo)?;
    if payload.len() != expected_payload_len {
        return Err(RsaVerifyError::BadDigestInfo);
    }
    let (prefix, embedded) = payload.split_at(digest_info_prefix.len());
    if prefix != digest_info_prefix {
        return Err(RsaVerifyError::BadDigestInfo);
    }
    if embedded != digest {
        return Err(RsaVerifyError::BadDigest);
    }
    Ok(())
}

/// Length in bytes of the leading byte of an ISO/IEC 9796-2 DS1 message.
const ISO9796_DS1_LEADING_LEN: usize = 1;
/// Leading byte of an ISO/IEC 9796-2 DS1 recoverable message.
const ISO9796_DS1_LEADING_BYTE: u8 = 0x6A;
/// Length in bytes of the implicit SHA-1 trailer in ISO/IEC 9796-2 DS1.
const ISO9796_DS1_IMPLICIT_TRAILER_LEN: usize = 1;
/// Implicit single-byte trailer for SHA-1 in ISO/IEC 9796-2 DS1.
const ISO9796_DS1_TRAILER_IMPLICIT_SHA1: u8 = 0xBC;
/// Explicit two-byte trailer terminator in ISO/IEC 9796-2 DS1.
const ISO9796_DS1_TRAILER_EXPLICIT_END: u8 = 0xCC;
/// Length of an explicit two-byte ISO/IEC 9796-2 DS1 trailer (`HFI || CC`).
const ISO9796_DS1_EXPLICIT_TRAILER_LEN: usize = 2;
/// ISO/IEC 10118-3 hash-function identifier for SHA-256.
const ISO10118_HFI_SHA256: u8 = 0x34;
/// ISO/IEC 10118-3 hash-function identifier for SHA-384.
const ISO10118_HFI_SHA384: u8 = 0x36;
/// ISO/IEC 10118-3 hash-function identifier for SHA-512.
const ISO10118_HFI_SHA512: u8 = 0x35;
/// Minimum length of a recovered ISO/IEC 9796-2 DS1 message: leading byte,
/// shortest supported digest (SHA-1), and single-byte implicit trailer.
const ISO9796_DS1_MIN_RECOVERED_LEN: usize =
    ISO9796_DS1_LEADING_LEN + SHA1_LEN + ISO9796_DS1_IMPLICIT_TRAILER_LEN;

/// Recovered message from an ISO/IEC 9796-2 Digital Signature Scheme 1
/// verification (used by ICAO 9303-11 Active Authentication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iso9796Ds1Recovered {
    /// Random recoverable message padding (`M1`) emitted by the chip.
    pub m1: Vec<u8>,
    /// Hash algorithm decoded from the ISO/IEC 9796-2 trailer.
    pub hash: HashAlg,
}

impl RsaPublicKey {
    /// Verify a PKCS#1 v1.5 signature over `SHA-256(message)`
    /// against this key.
    ///
    /// # Errors
    /// Padding / digest mismatches as listed in
    /// [`RsaVerifyError`].
    pub fn verify_pkcs1v15_sha256(
        &self,
        message: &[u8],
        signature: &Signature<RsaPkcs1Sha256>,
    ) -> Result<(), RsaVerifyError> {
        let mut hasher = Sha256::new();
        hasher.update(message.as_ref());
        let digest = hasher.finalize();
        verify_pkcs1v15(
            self,
            SHA256_DIGEST_INFO,
            digest.as_ref(),
            signature.as_bytes(),
        )
    }

    /// Verify PKCS#1 v1.5 against an already-computed SHA-256 digest.
    ///
    /// # Errors
    /// Returns [`RsaVerifyError`] when the signature has invalid padding,
    /// length, or an embedded digest that does not match.
    pub fn verify_pkcs1v15_sha256_digest(
        &self,
        digest: &[u8; SHA256_OUTPUT_BYTES],
        signature: &Signature<RsaPkcs1Sha256>,
    ) -> Result<(), RsaVerifyError> {
        verify_pkcs1v15(self, SHA256_DIGEST_INFO, digest, signature.as_bytes())
    }

    /// Verify PKCS#1 v1.5 against an already-computed SHA-384 digest.
    ///
    /// # Errors
    /// Returns [`RsaVerifyError`] when the signature has invalid padding,
    /// length, or an embedded digest that does not match.
    pub fn verify_pkcs1v15_sha384_digest(
        &self,
        digest: &[u8; SHA384_LEN],
        signature: &Signature<RsaPkcs1Sha384>,
    ) -> Result<(), RsaVerifyError> {
        verify_pkcs1v15(self, SHA384_DIGEST_INFO, digest, signature.as_bytes())
    }

    /// Verify PKCS#1 v1.5 against an already-computed SHA-512 digest.
    ///
    /// # Errors
    /// Returns [`RsaVerifyError`] when the signature has invalid padding,
    /// length, or an embedded digest that does not match.
    pub fn verify_pkcs1v15_sha512_digest(
        &self,
        digest: &[u8; SHA512_LEN],
        signature: &Signature<RsaPkcs1Sha512>,
    ) -> Result<(), RsaVerifyError> {
        verify_pkcs1v15(self, SHA512_DIGEST_INFO, digest, signature.as_bytes())
    }

    /// Verify an ISO/IEC 9796-2 Digital Signature Scheme 1 signature with
    /// message recovery (ICAO 9303-11 Active Authentication).
    ///
    /// # Errors
    /// [`RsaVerifyError::BadPadding`] for structural or trailer mismatches,
    /// [`RsaVerifyError::BadDigest`] when the embedded hash disagrees with
    /// `H(M1 || challenge_m2)`, or [`RsaVerifyError::BadModulus`] /
    /// [`RsaVerifyError::SignatureOutOfRange`] on RSA recovery failure.
    pub fn verify_iso9796_2_ds1(
        &self,
        challenge_m2: &[u8],
        signature: &[u8],
    ) -> Result<Iso9796Ds1Recovered, RsaVerifyError> {
        let recovered = self.raw_recover(signature)?;
        let k = recovered.len();
        if k < ISO9796_DS1_MIN_RECOVERED_LEN
            || recovered.first().copied() != Some(ISO9796_DS1_LEADING_BYTE)
        {
            return Err(RsaVerifyError::BadPadding);
        }
        let last_idx = k
            .checked_sub(ISO9796_DS1_IMPLICIT_TRAILER_LEN)
            .ok_or(RsaVerifyError::BadPadding)?;
        let last = recovered
            .get(last_idx)
            .copied()
            .ok_or(RsaVerifyError::BadPadding)?;
        let (hash, trailer_len) = match last {
            ISO9796_DS1_TRAILER_IMPLICIT_SHA1 => (HashAlg::Sha1, ISO9796_DS1_IMPLICIT_TRAILER_LEN),
            ISO9796_DS1_TRAILER_EXPLICIT_END => {
                let hfi_idx = k
                    .checked_sub(ISO9796_DS1_EXPLICIT_TRAILER_LEN)
                    .ok_or(RsaVerifyError::BadPadding)?;
                let hfi = recovered
                    .get(hfi_idx)
                    .copied()
                    .ok_or(RsaVerifyError::BadPadding)?;
                let alg = match hfi {
                    ISO10118_HFI_SHA256 => HashAlg::Sha256,
                    ISO10118_HFI_SHA384 => HashAlg::Sha384,
                    ISO10118_HFI_SHA512 => HashAlg::Sha512,
                    _ => return Err(RsaVerifyError::BadPadding),
                };
                (alg, ISO9796_DS1_EXPLICIT_TRAILER_LEN)
            }
            _ => return Err(RsaVerifyError::BadPadding),
        };
        let digest_len = hash.digest_len();
        let footer = digest_len
            .checked_add(trailer_len)
            .and_then(|n| n.checked_add(ISO9796_DS1_LEADING_LEN))
            .ok_or(RsaVerifyError::BadPadding)?;
        if k < footer {
            return Err(RsaVerifyError::BadPadding);
        }
        let hash_end = k
            .checked_sub(trailer_len)
            .ok_or(RsaVerifyError::BadPadding)?;
        let m1_end = hash_end
            .checked_sub(digest_len)
            .ok_or(RsaVerifyError::BadPadding)?;
        let m1 = recovered
            .get(ISO9796_DS1_LEADING_LEN..m1_end)
            .ok_or(RsaVerifyError::BadPadding)?
            .to_vec();
        let embedded_hash = recovered
            .get(m1_end..hash_end)
            .ok_or(RsaVerifyError::BadPadding)?;
        let mut message = Vec::with_capacity(m1.len().saturating_add(challenge_m2.len()));
        message.extend_from_slice(&m1);
        message.extend_from_slice(challenge_m2);
        if hash.digest(&message) != embedded_hash {
            return Err(RsaVerifyError::BadDigest);
        }
        Ok(Iso9796Ds1Recovered { m1, hash })
    }

    /// Verify a PKCS#1 v1.5 signature over `SHA-384(message)`.
    ///
    /// # Errors
    /// Padding, length or digest mismatch as listed in
    /// [`RsaVerifyError`].
    pub fn verify_pkcs1v15_sha384(
        &self,
        message: &[u8],
        signature: &Signature<RsaPkcs1Sha384>,
    ) -> Result<(), RsaVerifyError> {
        verify_pkcs1v15_sha384(self, message, signature)
    }

    /// Verify a PKCS#1 v1.5 signature over `SHA-512(message)`.
    ///
    /// # Errors
    /// Padding, length or digest mismatch as listed in
    /// [`RsaVerifyError`].
    pub fn verify_pkcs1v15_sha512(
        &self,
        message: &[u8],
        signature: &Signature<RsaPkcs1Sha512>,
    ) -> Result<(), RsaVerifyError> {
        verify_pkcs1v15_sha512(self, message, signature)
    }

    /// Verify RSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
    ///
    /// This is the fixed profile identified by the EU trusted-list XML
    /// signature algorithms. Parameters are not caller-selectable: an
    /// XML signature that names another salt length, mask digest or
    /// trailer is rejected before it reaches this method.
    ///
    /// # Errors
    /// [`RsaVerifyError`] for a signature outside the modulus, malformed
    /// EMSA-PSS encoding, or digest mismatch.
    pub fn verify_pss_sha256(
        &self,
        message: &[u8],
        signature: &Signature<RsaPssSha256>,
    ) -> Result<(), RsaVerifyError> {
        let digest = Sha256::digest(message);
        self.verify_pss_sha256_digest(digest.as_ref(), signature)
    }

    /// Verify the fixed RSA-PSS profile against an existing SHA-256
    /// message digest.
    ///
    /// # Errors
    /// As for [`Self::verify_pss_sha256`].
    pub fn verify_pss_sha256_digest(
        &self,
        digest: &[u8],
        signature: &Signature<RsaPssSha256>,
    ) -> Result<(), RsaVerifyError> {
        if digest.len() != SHA256_OUTPUT_BYTES {
            return Err(RsaVerifyError::BadDigest);
        }
        let recovered = self.raw_recover(signature.as_bytes())?;
        let modulus_bits = self.modulus.bit_length();
        let encoded_bits = modulus_bits
            .checked_sub(1)
            .ok_or(RsaVerifyError::BadModulus)?;
        let encoded_len = encoded_bits
            .checked_add(BITS_PER_BYTE_USIZE - 1)
            .and_then(|bits| bits.checked_div(BITS_PER_BYTE_USIZE))
            .ok_or(RsaVerifyError::BadModulus)?;
        let encoded = recovered
            .get(recovered.len().saturating_sub(encoded_len)..)
            .ok_or(RsaVerifyError::BadPadding)?;
        let leading_len = recovered
            .len()
            .checked_sub(encoded.len())
            .ok_or(RsaVerifyError::BadPadding)?;
        if recovered
            .get(..leading_len)
            .is_none_or(|leading| leading.iter().any(|byte| *byte != 0))
        {
            return Err(RsaVerifyError::BadPadding);
        }
        verify_pss_encoded_sha256(encoded, encoded_bits, digest)
    }

    /// RSA-recover the encoded message `EM = s^e mod n` and
    /// return it as exactly `k` big-endian bytes (where `k` is
    /// the modulus byte size). Shared between the PKCS#1 v1.5
    /// and RSA-PSS verification paths.
    fn raw_recover(&self, signature: &[u8]) -> Result<Vec<u8>, RsaVerifyError> {
        let key = self;
        let k = key.modulus.byte_len();
        if signature.len() != k {
            return Err(RsaVerifyError::SignatureOutOfRange);
        }
        // bits_precision = k bytes * BITS_PER_BYTE, rounded up
        // to BOXED_UINT_LIMB_BITS.
        let bits_precision = u32::try_from(k)
            .map_err(|_e| RsaVerifyError::BadModulus)?
            .checked_mul(BITS_PER_BYTE)
            .ok_or(RsaVerifyError::BadModulus)?
            .next_multiple_of(BOXED_UINT_LIMB_BITS);
        let modulus = BoxedUint::from_be_slice(key.modulus.as_bytes(), bits_precision)
            .map_err(|_e| RsaVerifyError::BadModulus)?;
        let exponent = BoxedUint::from_be_slice_vartime(key.exponent.as_bytes());
        let signature_uint = BoxedUint::from_be_slice(signature, bits_precision)
            .map_err(|_e| RsaVerifyError::SignatureOutOfRange)?;
        if signature_uint >= modulus {
            return Err(RsaVerifyError::SignatureOutOfRange);
        }
        let odd_modulus: Odd<BoxedUint> =
            Option::from(Odd::new(modulus)).ok_or(RsaVerifyError::BadModulus)?;
        let params = BoxedMontyParams::new(odd_modulus);
        let sig_form = BoxedMontyForm::new(signature_uint, &params);
        let m_form = sig_form.pow(&exponent);
        let m = m_form.retrieve();
        let em_box = m.to_be_bytes();
        let em = match em_box.len().cmp(&k) {
            core::cmp::Ordering::Greater => {
                let extra = em_box
                    .len()
                    .checked_sub(k)
                    .ok_or(RsaVerifyError::BadPadding)?;
                let prefix = em_box.get(..extra).ok_or(RsaVerifyError::BadPadding)?;
                if prefix.iter().any(|&b| b != 0) {
                    return Err(RsaVerifyError::BadPadding);
                }
                em_box
                    .get(extra..)
                    .ok_or(RsaVerifyError::BadPadding)?
                    .to_vec()
            }
            core::cmp::Ordering::Less => {
                let pad = k
                    .checked_sub(em_box.len())
                    .ok_or(RsaVerifyError::BadPadding)?;
                let mut padded = vec![0_u8; pad];
                padded.extend_from_slice(&em_box);
                padded
            }
            core::cmp::Ordering::Equal => em_box.to_vec(),
        };
        Ok(em)
    }
}

fn verify_pss_encoded_sha256(
    encoded: &[u8],
    encoded_bits: usize,
    message_digest: &[u8],
) -> Result<(), RsaVerifyError> {
    let minimum = SHA256_OUTPUT_BYTES
        .checked_add(PSS_SHA256_SALT_BYTES)
        .and_then(|length| length.checked_add(PSS_SEPARATOR_AND_TRAILER_BYTES))
        .ok_or(RsaVerifyError::BadPadding)?;
    if encoded.len() < minimum || encoded.last().copied() != Some(PSS_TRAILER_FIELD) {
        return Err(RsaVerifyError::BadPadding);
    }
    let db_len = encoded
        .len()
        .checked_sub(SHA256_OUTPUT_BYTES + 1)
        .ok_or(RsaVerifyError::BadPadding)?;
    let (masked_db, hash_and_trailer) = encoded.split_at(db_len);
    let hash = hash_and_trailer
        .get(..SHA256_OUTPUT_BYTES)
        .ok_or(RsaVerifyError::BadPadding)?;

    let total_bits = encoded
        .len()
        .checked_mul(BITS_PER_BYTE_USIZE)
        .ok_or(RsaVerifyError::BadPadding)?;
    let unused_bits = total_bits
        .checked_sub(encoded_bits)
        .ok_or(RsaVerifyError::BadPadding)?;
    if unused_bits >= BITS_PER_BYTE_USIZE {
        return Err(RsaVerifyError::BadPadding);
    }
    let high_mask = if unused_bits == 0 {
        0
    } else {
        FULL_BYTE_MASK << (BITS_PER_BYTE_USIZE - unused_bits)
    };
    if masked_db
        .first()
        .is_none_or(|first| *first & high_mask != 0)
    {
        return Err(RsaVerifyError::BadPadding);
    }

    let mask = mgf1_sha256(hash, db_len)?;
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(mask)
        .map(|(encoded_byte, mask_byte)| encoded_byte ^ mask_byte)
        .collect();
    if let Some(first) = db.first_mut() {
        *first &= !high_mask;
    } else {
        return Err(RsaVerifyError::BadPadding);
    }

    let padding_len = db_len
        .checked_sub(PSS_SHA256_SALT_BYTES + 1)
        .ok_or(RsaVerifyError::BadPadding)?;
    if db
        .get(..padding_len)
        .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
        || db.get(padding_len).copied() != Some(PSS_DB_SEPARATOR)
    {
        return Err(RsaVerifyError::BadPadding);
    }
    let salt = db
        .get(padding_len.saturating_add(1)..)
        .filter(|salt| salt.len() == PSS_SHA256_SALT_BYTES)
        .ok_or(RsaVerifyError::BadPadding)?;
    let mut hasher = Sha256::new();
    hasher.update([0_u8; PSS_ZERO_PREFIX_BYTES]);
    hasher.update(message_digest);
    hasher.update(salt);
    if hasher.finalize().as_slice() != hash {
        return Err(RsaVerifyError::BadDigest);
    }
    Ok(())
}

fn mgf1_sha256(seed: &[u8], output_len: usize) -> Result<Vec<u8>, RsaVerifyError> {
    let blocks = output_len
        .checked_add(SHA256_OUTPUT_BYTES - 1)
        .and_then(|length| length.checked_div(SHA256_OUTPUT_BYTES))
        .ok_or(RsaVerifyError::BadPadding)?;
    let mut mask = Vec::with_capacity(output_len);
    for index in 0..blocks {
        let counter = u32::try_from(index).map_err(|_error| RsaVerifyError::BadPadding)?;
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        mask.extend_from_slice(&hasher.finalize());
    }
    mask.truncate(output_len);
    Ok(mask)
}

/// Encode `message` and `salt` into an `encoded_bits`-wide EMSA-PSS
/// message block with SHA-256 and MGF1-SHA-256 (RFC 8017 sec. 9.1.1).
#[cfg(any(test, feature = "testkit"))]
fn emsa_pss_sha256_encode(message: &[u8], salt: &[u8], encoded_bits: usize) -> Vec<u8> {
    let encoded_len = encoded_bits.div_ceil(BITS_PER_BYTE_USIZE);
    let mut hasher = Sha256::new();
    hasher.update([0_u8; PSS_ZERO_PREFIX_BYTES]);
    hasher.update(Sha256::digest(message));
    hasher.update(salt);
    let hash = hasher.finalize();
    let db_len = encoded_len
        .checked_sub(SHA256_OUTPUT_BYTES + 1)
        .expect("test encoded_bits holds SHA-256 hash and trailer");
    let padding_len = db_len
        .checked_sub(salt.len() + 1)
        .expect("test encoded_bits holds salt and separator");
    let mut db = vec![0_u8; padding_len];
    db.push(PSS_DB_SEPARATOR);
    db.extend_from_slice(salt);
    let mask = mgf1_sha256(&hash, db_len).expect("the mask length is in range");
    let mut encoded: Vec<u8> = db
        .iter()
        .zip(mask)
        .map(|(byte, mask)| byte ^ mask)
        .collect();
    let unused_bits = encoded_len * BITS_PER_BYTE_USIZE - encoded_bits;
    if let Some(first) = encoded.first_mut()
        && unused_bits != 0
    {
        *first &= FULL_BYTE_MASK >> unused_bits;
    }
    encoded.extend_from_slice(&hash);
    encoded.push(PSS_TRAILER_FIELD);
    encoded
}

/// RSA signing with a published test key, for fixtures only.
///
/// Compiled for this crate's tests and behind the `testkit` feature.
/// Signing is the textbook `m^d mod n` over `crypto-bigint`, with no
/// blinding and no CRT: the keys it holds are public test keys.
#[cfg(any(test, feature = "testkit"))]
pub(crate) mod signing {
    use super::{
        BITS_PER_BYTE, BOXED_UINT_LIMB_BITS, EMSA_PKCS1_V15_BLOCK_TYPE,
        EMSA_PKCS1_V15_LEADING_BYTE, EMSA_PKCS1_V15_PS_FILL, EMSA_PKCS1_V15_PS_OFFSET,
        EMSA_PKCS1_V15_SEPARATOR, HashAlg, ISO9796_DS1_EXPLICIT_TRAILER_LEN,
        ISO9796_DS1_IMPLICIT_TRAILER_LEN, ISO9796_DS1_LEADING_BYTE, ISO9796_DS1_LEADING_LEN,
        ISO9796_DS1_TRAILER_EXPLICIT_END, ISO9796_DS1_TRAILER_IMPLICIT_SHA1, ISO10118_HFI_SHA256,
        ISO10118_HFI_SHA384, ISO10118_HFI_SHA512, RsaModulus, RsaPublicExponent,
        SHA256_DIGEST_INFO, SHA384_DIGEST_INFO, SHA512_DIGEST_INFO, emsa_pss_sha256_encode,
    };
    use crate::signed_data::HashAlgorithm;
    use crypto_bigint::{
        BoxedUint, Odd,
        modular::{BoxedMontyForm, BoxedMontyParams},
    };

    /// An RSA private key: the public modulus and exponent and the
    /// private exponent `d`.
    #[derive(Clone)]
    pub(crate) struct RsaSigningKey {
        /// `n`.
        modulus: RsaModulus,
        /// `e`.
        exponent: RsaPublicExponent,
        /// `d`, at the modulus precision.
        private_exponent: BoxedUint,
        /// Montgomery parameters for `n`.
        params: BoxedMontyParams,
    }

    impl core::fmt::Debug for RsaSigningKey {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("RsaSigningKey")
                .field("modulus_bits", &self.modulus.bit_length())
                .finish_non_exhaustive()
        }
    }

    impl RsaSigningKey {
        /// The key with big-endian magnitudes `modulus`,
        /// `public_exponent` and `private_exponent`; `None` when the
        /// public parts are not an RSA public key or `d` is not below
        /// `n`.
        pub(crate) fn from_parts(
            modulus: &[u8],
            public_exponent: &[u8],
            private_exponent: &[u8],
        ) -> Option<Self> {
            let modulus = RsaModulus::try_from_pkcs1(modulus).ok()?;
            let exponent = RsaPublicExponent::try_from_pkcs1(public_exponent).ok()?;
            let precision = Self::precision(&modulus)?;
            let n = BoxedUint::from_be_slice(modulus.as_bytes(), precision).ok()?;
            let d = BoxedUint::from_be_slice(private_exponent, precision).ok()?;
            if d >= n {
                return None;
            }
            let odd: Odd<BoxedUint> = Option::from(Odd::new(n))?;
            Some(Self {
                modulus,
                exponent,
                private_exponent: d,
                params: BoxedMontyParams::new(odd),
            })
        }

        /// The limb-aligned bit precision of `modulus`.
        fn precision(modulus: &RsaModulus) -> Option<u32> {
            Some(
                u32::try_from(modulus.byte_len())
                    .ok()?
                    .checked_mul(BITS_PER_BYTE)?
                    .next_multiple_of(BOXED_UINT_LIMB_BITS),
            )
        }

        /// The modulus.
        pub(crate) const fn modulus(&self) -> &RsaModulus {
            &self.modulus
        }

        /// The public exponent.
        pub(crate) const fn exponent(&self) -> &RsaPublicExponent {
            &self.exponent
        }

        /// `encoded^d mod n` as exactly modulus-length octets.
        fn private_operation(&self, encoded: &[u8]) -> Vec<u8> {
            let precision = Self::precision(&self.modulus).expect("the key's own precision");
            let m = BoxedUint::from_be_slice(encoded, precision).expect("encoded fits the modulus");
            let s = BoxedMontyForm::new(m, &self.params)
                .pow(&self.private_exponent)
                .retrieve();
            let bytes = s.to_be_bytes();
            let width = self.modulus.byte_len();
            let start = bytes.len().saturating_sub(width);
            let mut out = vec![EMSA_PKCS1_V15_LEADING_BYTE; width.saturating_sub(bytes.len())];
            out.extend_from_slice(bytes.get(start..).unwrap_or_default());
            out
        }

        /// The RSASSA-PKCS1-v1_5 signature over `message` hashed with
        /// `hash` (RFC 8017 sec.8.2.1, EMSA-PKCS1-v1_5 sec.9.2).
        pub(crate) fn sign_pkcs1v15(&self, hash: HashAlgorithm, message: &[u8]) -> Vec<u8> {
            self.sign_pkcs1v15_digest(hash, &hash.digest(message))
        }

        /// As [`Self::sign_pkcs1v15`], over `digest`, a digest under
        /// `hash` the caller computed: what a card signs after PSO:HASH.
        pub(crate) fn sign_pkcs1v15_digest(&self, hash: HashAlgorithm, digest: &[u8]) -> Vec<u8> {
            let prefix = match hash {
                HashAlgorithm::Sha256 => SHA256_DIGEST_INFO,
                HashAlgorithm::Sha384 => SHA384_DIGEST_INFO,
                HashAlgorithm::Sha512 => SHA512_DIGEST_INFO,
            };
            let mut digest_info = prefix.to_vec();
            digest_info.extend_from_slice(digest);
            let width = self.modulus.byte_len();
            let fill = width
                .checked_sub(digest_info.len() + EMSA_FRAME_BYTES)
                .expect("a test modulus holds the DigestInfo");
            let mut encoded = vec![EMSA_PKCS1_V15_LEADING_BYTE, EMSA_PKCS1_V15_BLOCK_TYPE];
            encoded.resize(encoded.len() + fill, EMSA_PKCS1_V15_PS_FILL);
            encoded.push(EMSA_PKCS1_V15_SEPARATOR);
            encoded.extend_from_slice(&digest_info);
            self.private_operation(&encoded)
        }

        /// The RSASSA-PSS signature over `message` with SHA-256,
        /// MGF1-SHA-256 and `salt` of any length the modulus holds (RFC
        /// 8017 sec.8.1.1, EMSA-PSS sec.9.1.1).
        pub(crate) fn sign_pss_sha256(&self, message: &[u8], salt: &[u8]) -> Vec<u8> {
            let encoded_bits = self.modulus.bit_length().saturating_sub(1);
            let encoded = emsa_pss_sha256_encode(message, salt, encoded_bits);
            self.private_operation(&encoded)
        }

        /// An ISO/IEC 9796-2 DS1 signature over `challenge_m2` under `hash`
        /// using deterministic `M1` bytes, or `None` if the modulus cannot
        /// hold the DS1 frame.
        pub(crate) fn sign_iso9796_2_ds1(
            &self,
            hash: HashAlg,
            challenge_m2: &[u8],
        ) -> Option<Vec<u8>> {
            let trailer: &[u8] = match hash {
                HashAlg::Sha1 => &ISO9796_DS1_TRAILER_SHA1,
                HashAlg::Sha256 => &ISO9796_DS1_TRAILER_SHA256,
                HashAlg::Sha384 => &ISO9796_DS1_TRAILER_SHA384,
                HashAlg::Sha512 => &ISO9796_DS1_TRAILER_SHA512,
            };
            let width = self.modulus.byte_len();
            let frame_overhead = ISO9796_DS1_LEADING_LEN
                .checked_add(hash.digest_len())?
                .checked_add(trailer.len())?;
            let m1_len = width.checked_sub(frame_overhead)?;
            let m1 = vec![ISO9796_DS1_TEST_M1_FILL; m1_len];
            let mut message = Vec::with_capacity(m1.len().saturating_add(challenge_m2.len()));
            message.extend_from_slice(&m1);
            message.extend_from_slice(challenge_m2);
            let digest = hash.digest(&message);
            let mut encoded = Vec::with_capacity(width);
            encoded.push(ISO9796_DS1_LEADING_BYTE);
            encoded.extend_from_slice(&m1);
            encoded.extend_from_slice(&digest);
            encoded.extend_from_slice(trailer);
            Some(self.private_operation(&encoded))
        }

        /// Sign a raw modulus-width encoded block for negative unit tests.
        #[cfg(test)]
        pub(crate) fn sign_raw_encoded(&self, encoded: &[u8]) -> Vec<u8> {
            self.private_operation(encoded)
        }
    }

    /// EMSA-PKCS1-v1_5 octets around the padding string and the
    /// `DigestInfo`: the leading zero, the block type and the
    /// separator.
    const EMSA_FRAME_BYTES: usize = EMSA_PKCS1_V15_PS_OFFSET + 1;

    /// Deterministic fill byte for the `M1` recoverable section in
    /// test ISO/IEC 9796-2 DS1 signatures.
    const ISO9796_DS1_TEST_M1_FILL: u8 = 0xA5;

    /// Implicit single-byte trailer for SHA-1.
    const ISO9796_DS1_TRAILER_SHA1: [u8; ISO9796_DS1_IMPLICIT_TRAILER_LEN] =
        [ISO9796_DS1_TRAILER_IMPLICIT_SHA1];
    /// Explicit two-byte trailer for SHA-256.
    const ISO9796_DS1_TRAILER_SHA256: [u8; ISO9796_DS1_EXPLICIT_TRAILER_LEN] =
        [ISO10118_HFI_SHA256, ISO9796_DS1_TRAILER_EXPLICIT_END];
    /// Explicit two-byte trailer for SHA-384.
    const ISO9796_DS1_TRAILER_SHA384: [u8; ISO9796_DS1_EXPLICIT_TRAILER_LEN] =
        [ISO10118_HFI_SHA384, ISO9796_DS1_TRAILER_EXPLICIT_END];
    /// Explicit two-byte trailer for SHA-512.
    const ISO9796_DS1_TRAILER_SHA512: [u8; ISO9796_DS1_EXPLICIT_TRAILER_LEN] =
        [ISO10118_HFI_SHA512, ISO9796_DS1_TRAILER_EXPLICIT_END];
}

#[cfg(test)]
mod tests {
    use super::{
        BITS_PER_BYTE_USIZE, HashAlg, ISO9796_DS1_EXPLICIT_TRAILER_LEN,
        ISO9796_DS1_IMPLICIT_TRAILER_LEN, ISO9796_DS1_LEADING_BYTE, ISO9796_DS1_LEADING_LEN,
        ISO9796_DS1_TRAILER_EXPLICIT_END, LEADING_ZERO_BYTE, RsaModulus, RsaModulusError,
        RsaPublicExponent, RsaPublicExponentError, RsaPublicKey, RsaVerifyError,
        SHA256_OUTPUT_BYTES, SHA384_LEN, SHA512_LEN, emsa_pss_sha256_encode,
        verify_pss_encoded_sha256,
    };
    use crate::container::{
        RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512, RsaPssSha256, Signature,
    };
    use crate::signed_data::HashAlgorithm;
    use crate::testkit::TestKey;
    use crate::x509::extract_rsa_public_key;
    use sha2::{Digest as _, Sha256, Sha384, Sha512};

    /// Bytes-per-modulus for RSA-2048 (modulus byte length k =
    /// `modulus_bits` / 8). Reused across fixture builders below.
    const RSA_2048_MODULUS_BYTE_LEN: usize = 256;
    /// Bytes-per-modulus for a 256-bit modulus -- well under
    /// the [`RsaModulus::MIN_BITS`] floor, used by the "too
    /// small" rejection test.
    const TOO_SMALL_MODULUS_BYTE_LEN: usize = 32;
    /// Bytes-per-modulus one byte under the 2048-bit floor, so the
    /// boundary itself is exercised rather than a value far below it.
    const BELOW_FLOOR_MODULUS_BYTE_LEN: usize = RSA_2048_MODULUS_BYTE_LEN - 1;
    /// Arbitrary odd test bitpattern: every byte is 193 decimal,
    /// low bit set so the modulus is odd. The high nibble is
    /// non-zero so the bit length matches `byte_len * 8`.
    const ODD_FILL_BYTE: u8 = 0xC1;
    /// Same pattern but with low bit cleared -- used to drive
    /// the even-modulus rejection path.
    const EVEN_FILL_BYTE: u8 = 0xC0;
    /// Signature size that doesn't match `modulus byte_len` --
    /// half-size triggers `SignatureOutOfRange`.
    const HALF_K_SIGNATURE_BYTE_LEN: usize = 128;
    /// Filler byte for the synthetic signature input. Any value
    /// works for the mismatch test.
    const SIGNATURE_FILL_BYTE: u8 = 0xAB;
    /// ASN.1 INTEGER sign byte (X.690 §8.3.2): a leading zero octet
    /// prepended to a positive integer whose high bit would
    /// otherwise make it parse as negative. The parser strips
    /// it; `try_from_pkcs1` rejects non-stripped bytes that
    /// retain it.
    const ASN1_INTEGER_SIGN_BYTE: u8 = 0x00;

    /// Build the standard RSA-2048 fixture modulus. Always `Some`
    /// for the well-formed odd fill; callers assert on it so a
    /// broken fixture fails the test instead of panicking here.
    fn fixture_2048_modulus() -> Option<RsaModulus> {
        RsaModulus::try_from_pkcs1(&vec![ODD_FILL_BYTE; RSA_2048_MODULUS_BYTE_LEN]).ok()
    }

    /// Assert that `result` is `Err(expected)`. Avoids `.unwrap_err()`
    /// (`clippy::unwrap_used`) while still giving a clear failure
    /// message on the wrong branch.
    fn assert_err_eq<T: core::fmt::Debug, E: PartialEq + core::fmt::Debug>(
        result: Result<T, E>,
        expected: &E,
    ) {
        assert!(
            result.is_err(),
            "expected Err({expected:?}), got {result:?}"
        );
        if let Err(error) = result {
            assert_eq!(&error, expected);
        }
    }

    #[test]
    fn rejects_signature_size_mismatch() {
        use crate::container::{RsaPkcs1Sha256, Signature};
        let modulus = fixture_2048_modulus();
        assert!(
            modulus.is_some(),
            "well-formed odd fill at 2048 bits must construct"
        );
        let Some(modulus) = modulus else { return };
        let key = RsaPublicKey {
            modulus,
            exponent: RsaPublicExponent::e_65537(),
        };
        let sig =
            Signature::<RsaPkcs1Sha256>::new(vec![SIGNATURE_FILL_BYTE; HALF_K_SIGNATURE_BYTE_LEN]);
        assert_err_eq(
            key.verify_pkcs1v15_sha256(b"x", &sig),
            &RsaVerifyError::SignatureOutOfRange,
        );
    }

    #[test]
    fn rejects_even_modulus_at_construction() {
        // Even modulus (low bit = 0) is rejected at the type
        // boundary -- the verifier never sees it because
        // RsaPublicKey can't hold one.
        assert_err_eq(
            RsaModulus::try_from_pkcs1(&vec![EVEN_FILL_BYTE; RSA_2048_MODULUS_BYTE_LEN]),
            &RsaModulusError::Even,
        );
    }

    #[test]
    fn rejects_too_small_modulus_at_construction() {
        /// Bit length of the too-small fixture: the fill byte has
        /// its high bit set, so the modulus spans the full byte
        /// width.
        const TOO_SMALL_MODULUS_BITS: usize = TOO_SMALL_MODULUS_BYTE_LEN * BITS_PER_BYTE_USIZE;
        let r = RsaModulus::try_from_pkcs1(&[ODD_FILL_BYTE; TOO_SMALL_MODULUS_BYTE_LEN]);
        assert!(matches!(
            r,
            Err(RsaModulusError::BitsTooFew {
                bits: TOO_SMALL_MODULUS_BITS,
                min: RsaModulus::MIN_BITS
            })
        ));
    }

    #[test]
    fn rejects_modulus_one_byte_below_floor() {
        /// Bit length of the just-under fixture: full-width bytes,
        /// one byte short of the floor.
        const BELOW_FLOOR_MODULUS_BITS: usize = BELOW_FLOOR_MODULUS_BYTE_LEN * BITS_PER_BYTE_USIZE;
        let r = RsaModulus::try_from_pkcs1(&[ODD_FILL_BYTE; BELOW_FLOOR_MODULUS_BYTE_LEN]);
        assert!(matches!(
            r,
            Err(RsaModulusError::BitsTooFew {
                bits: BELOW_FLOOR_MODULUS_BITS,
                min: RsaModulus::MIN_BITS
            })
        ));
    }

    #[test]
    fn rejects_leading_zero_modulus() {
        // ASN.1 INTEGER sign byte must be stripped before
        // calling try_from_pkcs1 -- otherwise we'd accept the
        // non-canonical form. Build a fixed-size `[u8; N+1]`
        // with the sign byte slotted at index 0.
        let mut bytes = [ODD_FILL_BYTE; RSA_2048_MODULUS_BYTE_LEN + 1];
        if let Some(slot) = bytes.first_mut() {
            *slot = ASN1_INTEGER_SIGN_BYTE;
        }
        assert_err_eq(
            RsaModulus::try_from_pkcs1(&bytes),
            &RsaModulusError::LeadingZero,
        );
    }

    #[test]
    fn rejects_even_exponent_at_construction() {
        /// Smallest even candidate value -- drives the parity
        /// rejection (public exponents must be odd to stay
        /// coprime with phi(n)).
        const EVEN_EXPONENT_VALUE: u64 = 2;
        assert_err_eq(
            RsaPublicExponent::try_from_value(EVEN_EXPONENT_VALUE),
            &RsaPublicExponentError::Even,
        );
    }

    #[test]
    fn rejects_exponent_below_three_at_construction() {
        assert_err_eq(
            RsaPublicExponent::try_from_value(1),
            &RsaPublicExponentError::TooSmall,
        );
    }

    #[test]
    fn rejects_oversized_exponent_at_construction() {
        const OVER_LIMIT_BYTES: usize = 33;
        /// Bit length of the 33-byte fixture exponent: every byte
        /// is one, so only the lowest bit of the first byte
        /// counts -- one past [`RsaPublicExponent::MAX_BITS`].
        const OVER_LIMIT_BITS: usize = 257;
        assert_err_eq(
            RsaPublicExponent::try_from_pkcs1(&[1; OVER_LIMIT_BYTES]),
            &RsaPublicExponentError::TooLarge {
                bits: OVER_LIMIT_BITS,
                max: RsaPublicExponent::MAX_BITS,
            },
        );
    }

    #[test]
    fn e_65537_canonical_form() {
        // F_4 = 2^16 + 1. Asserts the canonical PKCS#1 wire form
        // (no leading zero, big-endian magnitude) by *deriving*
        // the expected bytes from the integer value rather than
        // hand-coding them. The expression form makes the
        // mathematics self-documenting (no magic literal).
        const F_4: u64 = (1_u64 << 16) + 1;
        let be = F_4.to_be_bytes();
        let leading_zeros = be.iter().take_while(|&&b| b == LEADING_ZERO_BYTE).count();
        let e = RsaPublicExponent::e_65537();
        assert_eq!(e.as_bytes(), be.get(leading_zeros..).unwrap_or(&[]));
    }

    #[test]
    fn fixed_sha256_pss_encoding_verifies_and_detects_tampering() {
        const ENCODED_BITS: usize = 1023;
        let mut salt = [0_u8; SHA256_OUTPUT_BYTES];
        getrandom::fill(&mut salt).expect("random salt for PSS test");
        let message = b"trusted-list signed info";
        let digest = Sha256::digest(message);
        let encoded = emsa_pss_sha256_encode(message, &salt, ENCODED_BITS);
        assert_eq!(
            verify_pss_encoded_sha256(&encoded, ENCODED_BITS, &digest),
            Ok(())
        );

        let mut tampered = encoded;
        if let Some(trailer) = tampered.last_mut() {
            *trailer ^= 1;
        }
        assert_eq!(
            verify_pss_encoded_sha256(&tampered, ENCODED_BITS, &digest),
            Err(RsaVerifyError::BadPadding)
        );
    }

    #[test]
    fn fixed_sha256_pss_rejects_other_salt_widths() {
        const ENCODED_BITS: usize = 1023;
        const WRONG_SALT_BYTES: usize = 31;
        /// Arbitrary salt fill byte for the wrong-width encoding.
        const WRONG_SALT_FILL_BYTE: u8 = 7;
        let message = b"trusted-list signed info";
        let digest = Sha256::digest(message);
        let encoded = emsa_pss_sha256_encode(
            message,
            &[WRONG_SALT_FILL_BYTE; WRONG_SALT_BYTES],
            ENCODED_BITS,
        );
        assert!(verify_pss_encoded_sha256(&encoded, ENCODED_BITS, &digest).is_err());
    }

    #[test]
    fn pkcs1v15_and_pss_round_trip_and_reject_tampering() {
        const MESSAGE: &[u8] = b"refineid rsa verification round-trip";
        const TAMPERED_MESSAGE: &[u8] = b"refineid rsa verification tampered";
        const SALT_FILL_BYTE: u8 = 0x5A;

        let signing_key = TestKey::rsa_2048();
        let public_key =
            extract_rsa_public_key(&signing_key.spki()).expect("RFC 9500 RSA SPKI parses");

        let sig_256 =
            Signature::<RsaPkcs1Sha256>::new(signing_key.sign_with(HashAlgorithm::Sha256, MESSAGE));
        assert_eq!(public_key.verify_pkcs1v15_sha256(MESSAGE, &sig_256), Ok(()));
        assert_err_eq(
            public_key.verify_pkcs1v15_sha256(TAMPERED_MESSAGE, &sig_256),
            &RsaVerifyError::BadDigest,
        );

        let sig_384 =
            Signature::<RsaPkcs1Sha384>::new(signing_key.sign_with(HashAlgorithm::Sha384, MESSAGE));
        assert_eq!(public_key.verify_pkcs1v15_sha384(MESSAGE, &sig_384), Ok(()));

        let sig_512 =
            Signature::<RsaPkcs1Sha512>::new(signing_key.sign_with(HashAlgorithm::Sha512, MESSAGE));
        assert_eq!(public_key.verify_pkcs1v15_sha512(MESSAGE, &sig_512), Ok(()));

        let salt = [SALT_FILL_BYTE; SHA256_OUTPUT_BYTES];
        let sig_pss = Signature::<RsaPssSha256>::new(
            signing_key
                .sign_pss_sha256(MESSAGE, &salt)
                .expect("RSA signing key produces PSS signature"),
        );
        assert_eq!(public_key.verify_pss_sha256(MESSAGE, &sig_pss), Ok(()));
        assert_err_eq(
            public_key.verify_pss_sha256(TAMPERED_MESSAGE, &sig_pss),
            &RsaVerifyError::BadDigest,
        );

        let modulus_sig = Signature::<RsaPkcs1Sha256>::new(public_key.modulus.as_bytes().to_vec());
        assert_err_eq(
            public_key.verify_pkcs1v15_sha256(MESSAGE, &modulus_sig),
            &RsaVerifyError::SignatureOutOfRange,
        );
    }

    #[test]
    fn pkcs1v15_digest_variants_verify_and_reject_tampering() {
        const MESSAGE: &[u8] = b"refineid prehashed pkcs1v15 digest test";
        /// Single-bit XOR mask used to tamper with a digest byte.
        const BIT_FLIP_MASK: u8 = 0x01;

        let signing_key = TestKey::rsa_2048();
        let public_key =
            extract_rsa_public_key(&signing_key.spki()).expect("RFC 9500 RSA SPKI parses");

        let digest_384: [u8; SHA384_LEN] = Sha384::digest(MESSAGE).into();
        let sig_384 =
            Signature::<RsaPkcs1Sha384>::new(signing_key.sign_with(HashAlgorithm::Sha384, MESSAGE));
        assert_eq!(
            public_key.verify_pkcs1v15_sha384_digest(&digest_384, &sig_384),
            Ok(())
        );
        let mut bad_384 = digest_384;
        if let Some(first) = bad_384.first_mut() {
            *first ^= BIT_FLIP_MASK;
        }
        assert_err_eq(
            public_key.verify_pkcs1v15_sha384_digest(&bad_384, &sig_384),
            &RsaVerifyError::BadDigest,
        );

        let digest_512: [u8; SHA512_LEN] = Sha512::digest(MESSAGE).into();
        let sig_512 =
            Signature::<RsaPkcs1Sha512>::new(signing_key.sign_with(HashAlgorithm::Sha512, MESSAGE));
        assert_eq!(
            public_key.verify_pkcs1v15_sha512_digest(&digest_512, &sig_512),
            Ok(())
        );
        let mut bad_512 = digest_512;
        if let Some(first) = bad_512.first_mut() {
            *first ^= BIT_FLIP_MASK;
        }
        assert_err_eq(
            public_key.verify_pkcs1v15_sha512_digest(&bad_512, &sig_512),
            &RsaVerifyError::BadDigest,
        );
    }

    #[test]
    fn iso9796_2_ds1_verifies_all_hashes_and_rejects_malformed_inputs() {
        const CHALLENGE: &[u8] = b"AA-RND8!";
        const WRONG_CHALLENGE: &[u8] = b"AA-RND8?";
        /// Unknown single-byte trailer that matches neither implicit nor explicit endings.
        const BAD_TRAILER_BYTE: u8 = 0xDD;
        /// Unknown ISO/IEC 10118 hash-function identifier paired with the explicit end byte.
        const UNKNOWN_HFI_BYTE: u8 = 0x39;
        /// Arbitrary fill byte for synthetic negative encoded blocks.
        const NEGATIVE_BLOCK_FILL: u8 = 0x11;
        /// Number of supported ISO/IEC 9796-2 DS1 hash algorithms.
        const HASH_COUNT: usize = 4;
        const ALL_HASHES: [HashAlg; HASH_COUNT] = [
            HashAlg::Sha1,
            HashAlg::Sha256,
            HashAlg::Sha384,
            HashAlg::Sha512,
        ];

        let signing_key = TestKey::rsa_2048();
        let public_key =
            extract_rsa_public_key(&signing_key.spki()).expect("RFC 9500 RSA SPKI parses");
        let rsa_signer = signing_key
            .rsa_signing_key()
            .expect("RFC 9500 test key is RSA");

        for hash in ALL_HASHES {
            let signature = signing_key
                .sign_iso9796_2_ds1(hash, CHALLENGE)
                .expect("RSA test key produces ISO 9796-2 DS1 signature");
            let recovered = public_key
                .verify_iso9796_2_ds1(CHALLENGE, &signature)
                .expect("valid ISO 9796-2 DS1 signature must verify");
            assert_eq!(recovered.hash, hash);
            let trailer_len = match hash {
                HashAlg::Sha1 => ISO9796_DS1_IMPLICIT_TRAILER_LEN,
                HashAlg::Sha256 | HashAlg::Sha384 | HashAlg::Sha512 => {
                    ISO9796_DS1_EXPLICIT_TRAILER_LEN
                }
            };
            let expected_m1_len = RSA_2048_MODULUS_BYTE_LEN
                - ISO9796_DS1_LEADING_LEN
                - hash.digest_len()
                - trailer_len;
            assert_eq!(recovered.m1.len(), expected_m1_len);

            assert_err_eq(
                public_key.verify_iso9796_2_ds1(WRONG_CHALLENGE, &signature),
                &RsaVerifyError::BadDigest,
            );
        }

        // Wrong leading byte: a PKCS#1 v1.5 signature recovers starting with the
        // EMSA leading zero rather than ISO9796_DS1_LEADING_BYTE.
        let pkcs1_sig = signing_key.sign_with(HashAlgorithm::Sha256, CHALLENGE);
        assert_err_eq(
            public_key.verify_iso9796_2_ds1(CHALLENGE, &pkcs1_sig),
            &RsaVerifyError::BadPadding,
        );

        // Unknown trailer terminator byte.
        let mut bad_trailer_block = vec![NEGATIVE_BLOCK_FILL; RSA_2048_MODULUS_BYTE_LEN];
        if let Some(first) = bad_trailer_block.first_mut() {
            *first = ISO9796_DS1_LEADING_BYTE;
        }
        if let Some(last) = bad_trailer_block.last_mut() {
            *last = BAD_TRAILER_BYTE;
        }
        let bad_trailer_sig = rsa_signer.sign_raw_encoded(&bad_trailer_block);
        assert_err_eq(
            public_key.verify_iso9796_2_ds1(CHALLENGE, &bad_trailer_sig),
            &RsaVerifyError::BadPadding,
        );

        // Unknown hash-function identifier before explicit trailer end byte.
        let mut bad_hfi_block = vec![NEGATIVE_BLOCK_FILL; RSA_2048_MODULUS_BYTE_LEN];
        if let Some(first) = bad_hfi_block.first_mut() {
            *first = ISO9796_DS1_LEADING_BYTE;
        }
        let hfi_index = RSA_2048_MODULUS_BYTE_LEN - ISO9796_DS1_EXPLICIT_TRAILER_LEN;
        if let Some(slot) = bad_hfi_block.get_mut(hfi_index) {
            *slot = UNKNOWN_HFI_BYTE;
        }
        if let Some(last) = bad_hfi_block.last_mut() {
            *last = ISO9796_DS1_TRAILER_EXPLICIT_END;
        }
        let bad_hfi_sig = rsa_signer.sign_raw_encoded(&bad_hfi_block);
        assert_err_eq(
            public_key.verify_iso9796_2_ds1(CHALLENGE, &bad_hfi_sig),
            &RsaVerifyError::BadPadding,
        );

        // Signature length mismatch.
        let short_sig = vec![SIGNATURE_FILL_BYTE; HALF_K_SIGNATURE_BYTE_LEN];
        assert_err_eq(
            public_key.verify_iso9796_2_ds1(CHALLENGE, &short_sig),
            &RsaVerifyError::SignatureOutOfRange,
        );
    }
}
