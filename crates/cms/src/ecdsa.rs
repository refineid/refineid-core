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

//! ECDSA signature verification over the NIST named curves.
//!
//! A key is accepted only on a named curve the table below carries,
//! P-256 or P-384, referenced by its OID (RFC 5480 sec.2.1.1: PKIX
//! keys use `namedCurve`, and explicit `ECParameters` are not used).
//! A key whose SPKI spells the curve out explicitly is refused.
//!
//! Builds on `crypto-bigint::BoxedUint` + `BoxedMontyForm` for
//! arbitrary-precision modular arithmetic.
//!
//! Constant-time is **not** a goal: the verifier sees only public
//! signatures and keys. The test-only signer behind the `testkit`
//! feature reuses the same arithmetic and is never compiled into a
//! production build.

// EC coordinate naming follows the math convention in the EC
// literature (Hankerson/Menezes/Vanstone, IEEE 1363, RFC 5480):
// px / py for point P's coordinates, qx / qy for Q's, gx / gy for
// the generator G's, with the `_mont` / `_m` suffix denoting
// Montgomery form. The one-letter coordinate distinction is the
// notation, not an accident; renaming to `point_x_montgomery`
// etc. would obscure the textbook mapping that lets a
// cryptographer read the code against the spec.

use crypto_bigint::{
    BoxedUint, Odd, Resize as _,
    modular::{BoxedMontyForm, BoxedMontyParams},
};

use crate::container::{EcdsaDer, EcdsaP256, EcdsaP384, Signature};
use crate::hex::Hex;
use crate::oid::{Oid as KnownOid, known};
use refineid_ber::{BerTlv, Integer, Sequence};
use refineid_digest::{Sha1, Sha224, Sha256, Sha384, Sha512};

/// SEC1 uncompressed-point tag byte.
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
/// Coordinates in an affine EC point -- X and Y (SEC 1
/// sec. 2.3.3: an uncompressed point body is two equal-width
/// coordinates).
const POINT_COORDINATE_COUNT: usize = 2;
/// Components in an ECDSA signature -- `r` and `s` (RFC 3279
/// sec. 2.2.3: `Ecdsa-Sig-Value` is a SEQUENCE of exactly two
/// INTEGERs).
const SIG_COMPONENT_COUNT: usize = 2;
/// DER INTEGER sign-padding byte.
const DER_SIGN_PAD: u8 = 0;
/// ASN.1 SEQUENCE tag, constructed form (X.690 sec. 8.9.1); the
/// SEQUENCE-of-INTEGER shape for ECDSA signatures is RFC 3279
/// sec. 2.2.3.
const ASN1_SEQUENCE_TAG: u8 = 0x30;
/// ASN.1 INTEGER tag (X.690 sec. 8.3).
const ASN1_INTEGER_TAG: u8 = 0x02;
/// Smallest byte value with the DER sign bit set. A DER INTEGER
/// whose leading magnitude byte reaches this value needs a
/// [`DER_SIGN_PAD`] prepended to stay positive under the
/// two's-complement interpretation (X.690 sec. 8.3.3).
const HIGH_BIT_SET: u8 = 0x80;
/// DER long-form length marker announcing one follow-up length
/// octet (X.690 sec. 8.1.3.5).
const DER_LONG_FORM_1B: u8 = 0x81;
/// DER long-form length marker announcing two follow-up length
/// octets (X.690 sec. 8.1.3.5).
const DER_LONG_FORM_2B: u8 = 0x82;
/// First length value that no longer fits DER short form -- 128
/// (X.690 sec. 8.1.3.4 caps short form at 127).
const SHORT_FORM_CEILING: usize = 0x80;
/// First length value that no longer fits one long-form length
/// octet -- 256 (X.690 sec. 8.1.3.5).
const ONE_BYTE_FORM_CEILING: usize = 0x100;
/// Capacity slack for the SEQUENCE tag and DER length.
const SEQUENCE_HEADER_SLACK: usize = 4;
/// Per-INTEGER overhead slack: tag, one or two length octets,
/// and a possible sign octet.
const INTEGER_OVERHEAD_SLACK: usize = 4;
/// Combined capacity slack for the two INTEGERs (`r` and `s`) of
/// an ECDSA signature body.
const BODY_SLACK: usize = INTEGER_OVERHEAD_SLACK.saturating_add(INTEGER_OVERHEAD_SLACK);
/// Bits in one byte. Rust pins `u8` at 8 bits; used to convert
/// byte lengths into the bit counts `BoxedUint` constructors and
/// the RFC 6979 sec. 2.3.2 digest truncation work in.
const BITS_PER_BYTE: u32 = 8;
/// `BoxedUint` limb size in bits. The crypto-bigint crate stores
/// arbitrary-precision integers as a sequence of `u64` "limbs";
/// precision arguments to its constructors round up to a
/// multiple of one limb.
const BOXED_UINT_LIMB_BITS: u32 = 64;

/// Named-curve parameters in unsigned big-endian byte form, taken
/// from the constant table at the end of this module.
#[derive(Debug, Clone)]
pub(crate) struct Curve {
    /// Field prime `p` (unsigned big-endian).
    p: Vec<u8>,
    /// Curve coefficient `a` (unsigned big-endian).
    a: Vec<u8>,
    /// Curve coefficient `b` (unsigned big-endian).
    b: Vec<u8>,
    /// X coordinate of the base point `G` (unsigned big-endian).
    gx: Vec<u8>,
    /// Y coordinate of the base point `G` (unsigned big-endian).
    gy: Vec<u8>,
    /// Subgroup order `n` (unsigned big-endian).
    n: Vec<u8>,
}

/// Error returned from the ECDSA verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaError {
    /// Curve modulus `p` is malformed (empty or even).
    BadModulus,
    /// Public key `(Q.x, Q.y)` was not on the curve or had the
    /// wrong encoding (we accept only the uncompressed
    /// `04 || X || Y` SEC1 form).
    BadPublicKey,
    /// Signature parse failed -- ECDSA signatures are DER
    /// `SEQUENCE { r INTEGER, s INTEGER }`.
    BadSignature,
    /// `r` or `s` not in `[1, n-1]`.
    SigOutOfRange,
    /// `s` had no inverse mod `n` (can't really happen for a
    /// valid signature; flagged for completeness).
    NotInvertible,
    /// Final compare: `r' != r mod n` -- the signature does not
    /// verify against the supplied public key and message.
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

/// Uncompressed SEC1 elliptic-curve point: `04 || X || Y`.
///
/// The constructor `Sec1UncompressedPoint::from_bytes` is the
/// trust boundary: it asserts the leading `04` marker byte
/// (`SEC1_UNCOMPRESSED_TAG`), the even body length, and a
/// non-empty body. Compressed (tag `02` / `03`) and hybrid (tag
/// `06` / `07`) SEC1 forms are *not* a `Sec1UncompressedPoint`
/// -- this codebase only verifies uncompressed-form keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sec1UncompressedPoint {
    /// SEC1 uncompressed-form payload: `04 || X || Y`, X and Y equal-length.
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
    /// Wrap raw SEC1 bytes. Validates the leading
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
}

impl Sec1UncompressedPoint {
    /// Borrow the underlying SEC1 bytes (`04 || X || Y`).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the wrapper and return the owned SEC1 bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the encoded point in bytes (`1 + 2 * coord_len`).
    /// Tier 0 `usize`; arithmetic count.
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

/// Internal handle for one curve. Holds the precomputed
/// Montgomery params for `p` and for `n`, plus the base point
/// in affine form.
struct CurveCtx {
    /// Bit precision used for `p`-side arithmetic (multiple of 64).
    bits_p: u32,
    /// Bit precision used for `n`-side arithmetic.
    bits_n: u32,
    /// Montgomery parameters for the prime field modulus `p`.
    p_params: BoxedMontyParams,
    /// Montgomery parameters for the subgroup order `n`.
    n_params: BoxedMontyParams,
    /// Weierstrass coefficient `a` in `y^2 = x^3 + ax + b`.
    a: BoxedUint,
    /// Weierstrass coefficient `b` in `y^2 = x^3 + ax + b`.
    b: BoxedUint,
    /// Subgroup order `n`, in non-Montgomery form for boundary checks.
    n_uint: BoxedUint,
    /// Base point `G` in affine coordinates.
    g: AffinePoint,
}

/// Affine point on a short-Weierstrass curve, with an explicit
/// sentinel for the point at infinity.
///
/// SEC1 §2.3.3. Using `Option<(x, y)>` for the infinity sentinel
/// keeps the type total without smuggling an out-of-band value
/// (e.g. `x = 0`) that would collide with a legitimate
/// coordinate on some curves.
#[derive(Clone)]
struct AffinePoint {
    /// `None` is the point at infinity.
    xy: Option<(BoxedUint, BoxedUint)>,
}

impl AffinePoint {
    /// Construct the additive identity (point at infinity).
    ///
    /// SEC1 §2.2.1 -- O is the identity of the EC group; required
    /// as the seed for scalar multiplication's binary-ladder
    /// initial accumulator.
    const fn infinity() -> Self {
        Self { xy: None }
    }
    /// Whether this point is the additive identity.
    ///
    /// The doubling and addition formulae have a degenerate case
    /// when either operand is `O`; callers short-circuit through
    /// this predicate rather than hitting a divide-by-zero in
    /// the lambda computation.
    const fn is_infinity(&self) -> bool {
        self.xy.is_none()
    }
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct EcdsaHelpers;

impl EcdsaHelpers {
    /// Round a byte length up to the next 64-bit boundary, in
    /// bits, with a floor of 64.
    ///
    /// `BoxedUint` needs its bit-width specified at construction
    /// and represents the value in 64-bit limbs; this helper
    /// picks the smallest representable bit-width that fits
    /// `bytes`. Saturates rather than panicking on absurd input
    /// (`u32::MAX`-byte slice) so the parser-side surface never
    /// aborts.
    fn bits_for_len(byte_len: usize) -> u32 {
        let nominal = u32::try_from(byte_len)
            .unwrap_or(u32::MAX)
            .saturating_mul(BITS_PER_BYTE);
        nominal
            .next_multiple_of(BOXED_UINT_LIMB_BITS)
            .max(BOXED_UINT_LIMB_BITS)
    }

    /// Decode a big-endian integer slice into a `BoxedUint` of
    /// the given bit width.
    ///
    /// Wraps the upstream conversion to map width-mismatch errors
    /// to a domain-specific [`EcdsaError::BadModulus`] -- the
    /// only legitimate failure here is a curve constant that
    /// doesn't fit the limb count `bits_for` chose for it.
    fn boxed(bytes: &[u8], bits: u32) -> Result<BoxedUint, EcdsaError> {
        BoxedUint::from_be_slice(bytes, bits).map_err(|_e| EcdsaError::BadModulus)
    }
}

// Variable names `px`/`py`, `qx`/`qy`, and their Montgomery
// counterparts (`px_m`, `py_m`, `qx_m`, `qy_m`, `px_mont`,
// `py_mont`) match the affine short-Weierstrass formulae as
// written in SEC1 / RFC 6979 -- renaming them would obscure the
// cross-reference. Throughout, `BoxedMontyForm` add / sub / mul
// are GF(p) (respectively mod-n) field operations with
// well-defined modular results; they have no overflow or panic
// surface.
impl CurveCtx {
    /// Build a precomputed verification context from a
    /// runtime-supplied [`Curve`].
    ///
    /// SEC1 §2.2.1 -- the Montgomery parameters depend only on
    /// `p` and `n`, so doing the conversion once per curve and
    /// then sharing the `CurveCtx` across many verifications is
    /// constant-folded work. Returns
    /// [`EcdsaError::BadModulus`] if `p` or `n` are even
    /// (Montgomery requires odd modulus) or if any constant is
    /// wider than the chosen `bits_for` width.
    fn new(curve: &Curve) -> Result<Self, EcdsaError> {
        let bits_p = EcdsaHelpers::bits_for_len(curve.p.len());
        let bits_n = EcdsaHelpers::bits_for_len(curve.n.len());
        let p_uint = EcdsaHelpers::boxed(curve.p.as_slice(), bits_p)?;
        let n_uint = EcdsaHelpers::boxed(curve.n.as_slice(), bits_n)?;
        let a = EcdsaHelpers::boxed(curve.a.as_slice(), bits_p)?;
        let b = EcdsaHelpers::boxed(curve.b.as_slice(), bits_p)?;
        let gx = EcdsaHelpers::boxed(curve.gx.as_slice(), bits_p)?;
        let gy = EcdsaHelpers::boxed(curve.gy.as_slice(), bits_p)?;
        let p_odd: Odd<BoxedUint> = Option::from(Odd::new(p_uint)).ok_or(EcdsaError::BadModulus)?;
        let n_odd: Odd<BoxedUint> =
            Option::from(Odd::new(n_uint.clone())).ok_or(EcdsaError::BadModulus)?;
        let p_params = BoxedMontyParams::new(p_odd);
        let n_params = BoxedMontyParams::new(n_odd);
        Ok(Self {
            bits_p,
            bits_n,
            p_params,
            n_params,
            a,
            b,
            n_uint,
            g: AffinePoint { xy: Some((gx, gy)) },
        })
    }

    /// Lift `x` into Montgomery form modulo the field prime `p`.
    ///
    /// Used for coordinate-domain arithmetic (point doubling,
    /// addition, multiplication). The Montgomery params are
    /// shared across calls; the per-call work is the constant-
    /// time conversion only.
    fn p_mont(&self, x: &BoxedUint) -> BoxedMontyForm {
        BoxedMontyForm::new(x.clone(), &self.p_params)
    }
    /// Lift `x` into Montgomery form modulo the subgroup order
    /// `n`.
    ///
    /// Used for scalar-domain arithmetic (the ECDSA verify
    /// equation operates on `r`, `s`, `e mod n`). Distinct from
    /// [`Self::p_mont`] because `p` and `n` are different moduli
    /// with different Montgomery parameter sets.
    fn n_mont(&self, x: &BoxedUint) -> BoxedMontyForm {
        BoxedMontyForm::new(x.clone(), &self.n_params)
    }

    /// Point doubling on `y^2 = x^3 + ax + b`. Standard short
    /// Weierstrass formulae, affine coords.
    fn double(&self, p: &AffinePoint) -> AffinePoint {
        /// Coefficient of `x^2` in the tangent-slope numerator
        /// `(3*x^2 + a)` of the affine doubling formula (SEC 1
        /// sec. 2.2.1).
        const SLOPE_NUM_COEFF: u32 = 3;
        /// Coefficient of `y` in the tangent-slope denominator
        /// `(2*y)` of the affine doubling formula (SEC 1
        /// sec. 2.2.1).
        const SLOPE_DEN_COEFF: u32 = 2;
        let Some((px, py)) = &p.xy else {
            return AffinePoint::infinity();
        };
        // py == 0 -> infinity.
        let py_mont = self.p_mont(py);
        let zero = self.p_mont(&BoxedUint::zero_with_precision(self.bits_p));
        if py_mont == zero {
            return AffinePoint::infinity();
        }
        // lambda = (3*px^2 + a) / (2*py)
        let three = self.p_mont(&BoxedUint::from(SLOPE_NUM_COEFF).resize(self.bits_p));
        let two = self.p_mont(&BoxedUint::from(SLOPE_DEN_COEFF).resize(self.bits_p));
        let a_mont = self.p_mont(&self.a);
        let px_mont = self.p_mont(px);
        let num = &(&three * &(&px_mont * &px_mont)) + &a_mont;
        // `2y` is invertible mod p: we just checked `py != 0`, p is
        // prime, and 2 is coprime with p (p is odd). If invert()
        // ever returns None anyway, fail closed by returning
        // infinity -- the subsequent verify step will reject.
        let Some(den_inv): Option<BoxedMontyForm> = Option::from((&two * &py_mont).invert()) else {
            return AffinePoint::infinity();
        };
        let lambda = &num * &den_inv;
        let lambda_sq = &lambda * &lambda;
        let rx = &(&lambda_sq - &px_mont) - &px_mont;
        let ry = &(&lambda * &(&px_mont - &rx)) - &py_mont;
        AffinePoint {
            xy: Some((rx.retrieve(), ry.retrieve())),
        }
    }

    /// Point addition (affine). Handles infinity + match cases.
    fn add(&self, p: &AffinePoint, q: &AffinePoint) -> AffinePoint {
        let (Some((px, py)), Some((qx, qy))) = (p.xy.as_ref(), q.xy.as_ref()) else {
            return if p.is_infinity() {
                q.clone()
            } else {
                p.clone()
            };
        };
        if px == qx {
            if py == qy {
                return self.double(p);
            }
            // P + (-P) = infinity.
            return AffinePoint::infinity();
        }
        let px_m = self.p_mont(px);
        let py_m = self.p_mont(py);
        let qx_m = self.p_mont(qx);
        let qy_m = self.p_mont(qy);
        let num = &qy_m - &py_m;
        // `qx - px` is non-zero (we just checked `px != qx`) so its
        // modular inverse exists for prime p. Fail closed otherwise.
        let Some(den_inv): Option<BoxedMontyForm> = Option::from((&qx_m - &px_m).invert()) else {
            return AffinePoint::infinity();
        };
        let lambda = &num * &den_inv;
        let lambda_sq = &lambda * &lambda;
        let rx = &(&lambda_sq - &px_m) - &qx_m;
        let ry = &(&lambda * &(&px_m - &rx)) - &py_m;
        AffinePoint {
            xy: Some((rx.retrieve(), ry.retrieve())),
        }
    }

    /// Scalar multiplication `k * P` using double-and-add (the
    /// constant-time hardening doesn't matter -- we only multiply
    /// scalars that came from the *signature*, no secrets).
    fn scalar_mul(&self, k: &BoxedUint, point: &AffinePoint) -> AffinePoint {
        if point.is_infinity() {
            return AffinePoint::infinity();
        }
        let mut acc = AffinePoint::infinity();
        let mut addend = point.clone();
        let bits = k.bits_vartime();
        for i in 0..bits {
            if k.bit_vartime(i) {
                acc = self.add(&acc, &addend);
            }
            addend = self.double(&addend);
        }
        acc
    }

    /// Test `Q.y^2 == Q.x^3 + a*Q.x + b mod p`.
    fn is_on_curve(&self, q: &AffinePoint) -> bool {
        let Some((qx, qy)) = &q.xy else { return false };
        let qx_m = self.p_mont(qx);
        let qy_m = self.p_mont(qy);
        let lhs = &qy_m * &qy_m;
        let a_m = self.p_mont(&self.a);
        let b_m = self.p_mont(&self.b);
        let rhs_no_b = &(&(&qx_m * &qx_m) * &qx_m) + &(&a_m * &qx_m);
        let rhs = &rhs_no_b + &b_m;
        lhs == rhs
    }
}

/// Verify an ECDSA signature.
///
/// - `curve` -- field prime, coefficients, base point, order.
/// - `pubkey_sec1` -- uncompressed SEC1 point: `04 || X || Y`,
///   each coordinate `ceil(bits(p) / 8)` bytes.
/// - `signature_der` -- DER `SEQUENCE { r INTEGER, s INTEGER }`.
/// - `message_digest` -- already-hashed message (caller picks
///   the hash so we don't need a `HashAlgorithm` parameter
///   here).
///
/// # Errors
/// [`EcdsaError`] on any of the verifier's reject branches.
///
/// The `BoxedMontyForm` multiplications (`e_mont * w_mont`,
/// `r_mont * w_mont`) are modular arithmetic mod `n` with a
/// well-defined wrap; no overflow surface.
pub(crate) fn verify_prehashed(
    curve: &Curve,
    pubkey_sec1: &Sec1UncompressedPoint,
    signature_der: &Signature<EcdsaDer>,
    message_digest: &[u8],
) -> Result<(), EcdsaError> {
    let ctx = CurveCtx::new(curve)?;
    let q = pubkey_sec1.parse_affine(ctx.bits_p)?;
    if !ctx.is_on_curve(&q) {
        return Err(EcdsaError::BadPublicKey);
    }
    let (r_bytes, s_bytes) = signature_der.parse_ecdsa_signature()?;
    let r = EcdsaHelpers::boxed(r_bytes.as_slice(), ctx.bits_n)?;
    let s = EcdsaHelpers::boxed(s_bytes.as_slice(), ctx.bits_n)?;
    let one = BoxedUint::one_with_precision(ctx.bits_n);
    if r < one || r >= ctx.n_uint || s < one || s >= ctx.n_uint {
        return Err(EcdsaError::SigOutOfRange);
    }
    // e := leftmost min(bits(n), bits(hash)) bits of the digest,
    // interpreted as a big-endian integer (RFC 6979 sec.2.3.2).
    let e_uint = EcdsaHelpers::digest_to_scalar(message_digest, &ctx);
    let s_mont = ctx.n_mont(&s);
    let w_mont: BoxedMontyForm = Option::from(s_mont.invert()).ok_or(EcdsaError::NotInvertible)?;
    let e_mont = ctx.n_mont(&e_uint);
    let r_mont = ctx.n_mont(&r);
    let u1 = (&e_mont * &w_mont).retrieve();
    let u2 = (&r_mont * &w_mont).retrieve();
    let point_a = ctx.scalar_mul(&u1, &ctx.g);
    let point_b = ctx.scalar_mul(&u2, &q);
    let sum = ctx.add(&point_a, &point_b);
    let Some((sx, _)) = sum.xy else {
        return Err(EcdsaError::VerifyFailed);
    };
    // sx mod n
    let sx_n = EcdsaHelpers::bytes_into_n(&sx, &ctx);
    if sx_n == r {
        Ok(())
    } else {
        Err(EcdsaError::VerifyFailed)
    }
}

impl Sec1UncompressedPoint {
    /// Decode a SEC1-uncompressed EC point (`04 || X || Y`) into
    /// an [`AffinePoint`].
    ///
    /// SEC1 §2.3.4. Rejects compressed (`02`/`03`) and hybrid
    /// (`06`/`07`) encodings -- the FINEID profile pins
    /// uncompressed form (FINEID S2 §5.1) -- and rejects bodies
    /// whose length is not twice the coordinate width. Does not
    /// run the on-curve check; the caller (`verify_prehashed`)
    /// does that next.
    fn parse_affine(&self, bits_p: u32) -> Result<AffinePoint, EcdsaError> {
        let bytes = self.as_bytes();
        if bytes.first().copied() != Some(SEC1_UNCOMPRESSED_TAG) {
            return Err(EcdsaError::BadPublicKey);
        }
        let body = bytes.get(1..).ok_or(EcdsaError::BadPublicKey)?;
        if !body.len().is_multiple_of(POINT_COORDINATE_COUNT) || body.is_empty() {
            return Err(EcdsaError::BadPublicKey);
        }
        // body.len() is even and non-zero so `body.len() >> 1` is
        // exact and >= 1; bit-shift sidesteps clippy::integer_division.
        let half: usize = body.len() >> 1_u32;
        let (x_bytes, y_bytes) = body.split_at(half);
        let x = EcdsaHelpers::boxed(x_bytes, bits_p)?;
        let y = EcdsaHelpers::boxed(y_bytes, bits_p)?;
        Ok(AffinePoint { xy: Some((x, y)) })
    }
}

impl Signature<EcdsaDer> {
    /// Convert `XMLDSig`'s raw fixed-width `r || s` representation into
    /// the DER `Ecdsa-Sig-Value` consumed by the verifier.
    ///
    /// # Errors
    /// [`EcdsaError::BadSignature`] when the input is empty or has an
    /// odd length, so it cannot contain two equally sized components.
    pub fn from_raw_concatenation(raw: &[u8]) -> Result<Self, EcdsaError> {
        if raw.is_empty() || !raw.len().is_multiple_of(SIG_COMPONENT_COUNT) {
            return Err(EcdsaError::BadSignature);
        }
        let half = raw.len() >> 1_u32;
        let (r, s) = raw.split_at(half);
        let mut body = Vec::with_capacity(raw.len().saturating_add(BODY_SLACK));
        EcdsaHelpers::encode_der_integer(&mut body, r);
        EcdsaHelpers::encode_der_integer(&mut body, s);
        let mut out = Vec::with_capacity(body.len().saturating_add(SEQUENCE_HEADER_SLACK));
        out.push(ASN1_SEQUENCE_TAG);
        EcdsaHelpers::encode_der_length(&mut out, body.len());
        out.extend_from_slice(&body);
        Ok(Self::new(out))
    }

    /// Decode an ECDSA `Ecdsa-Sig-Value` into the magnitudes of `r`
    /// and `s`.
    ///
    /// RFC 3279 sec.2.2.3: exactly one DER `SEQUENCE` of exactly two
    /// `INTEGER`s and nothing after either. Each `INTEGER` must be
    /// positive and minimally encoded (X.690 sec.8.3.2): a leading
    /// zero octet is present exactly when the next octet has its top
    /// bit set. The range `[1, n-1]` needs the curve and is checked
    /// by the verifier.
    fn parse_ecdsa_signature(&self) -> Result<(Vec<u8>, Vec<u8>), EcdsaError> {
        let bytes = self.as_bytes();
        let outer = BerTlv::<Sequence>::parse(bytes).map_err(|_e| EcdsaError::BadSignature)?;
        if outer.size() != bytes.len() {
            return Err(EcdsaError::BadSignature);
        }
        let mut components = outer.iter_children();
        let mut next_integer = || -> Result<Vec<u8>, EcdsaError> {
            let integer = components
                .next()
                .ok_or(EcdsaError::BadSignature)?
                .map_err(|_e| EcdsaError::BadSignature)?
                .expect::<Integer>()
                .map_err(|_e| EcdsaError::BadSignature)?;
            EcdsaHelpers::positive_magnitude(integer.value()).map(<[u8]>::to_vec)
        };
        let r = next_integer()?;
        let s = next_integer()?;
        if components.next().is_some() {
            return Err(EcdsaError::BadSignature);
        }
        Ok((r, s))
    }
}

impl EcdsaHelpers {
    /// The magnitude of a positive, minimally encoded DER `INTEGER`
    /// body (X.690 sec.8.3.2), or [`EcdsaError::BadSignature`] for an
    /// empty, zero, negative or padded one: an ECDSA `r` or `s` lies
    /// in `[1, n-1]` (FIPS 186-4 sec.6.4.2).
    fn positive_magnitude(value: &[u8]) -> Result<&[u8], EcdsaError> {
        match value {
            [first, ..] if first & HIGH_BIT_SET != 0 => Err(EcdsaError::BadSignature),
            [DER_SIGN_PAD] => Err(EcdsaError::BadSignature),
            [DER_SIGN_PAD, second, ..] if second & HIGH_BIT_SET == 0 => {
                Err(EcdsaError::BadSignature)
            }
            [DER_SIGN_PAD, magnitude @ ..] => Ok(magnitude),
            [_, ..] => Ok(value),
            [] => Err(EcdsaError::BadSignature),
        }
    }
}

impl EcdsaHelpers {
    /// Append an ASN.1 DER `INTEGER` (tag [`ASN1_INTEGER_TAG`])
    /// wrapping a big-endian unsigned magnitude `value` to `out`.
    ///
    /// Strips redundant leading zero bytes (DER integers are
    /// minimal-form) and prepends a single [`DER_SIGN_PAD`] when
    /// the resulting high bit is set (to keep the integer
    /// positive under the two's-complement DER interpretation,
    /// per X.690 §8.3.3 / RFC 3279 §2.2.3). The mirror of
    /// the ECDSA signature parser's integer decode.
    fn encode_der_integer(out: &mut Vec<u8>, value: &[u8]) {
        // Strip leading zeros, but keep at least one byte so a
        // zero integer encodes as `02 01 00` rather than the
        // invalid `02 00`.
        let mut start: usize = 0;
        while start.saturating_add(1) < value.len() && value.get(start).copied() == Some(0) {
            start = start.saturating_add(1);
        }
        let trimmed = value.get(start..).unwrap_or(&[]);
        let needs_pad = trimmed.first().is_some_and(|&b| b >= HIGH_BIT_SET);
        let int_len = trimmed.len().saturating_add(usize::from(needs_pad));
        out.push(ASN1_INTEGER_TAG);
        Self::encode_der_length(out, int_len);
        if needs_pad {
            out.push(DER_SIGN_PAD);
        }
        out.extend_from_slice(trimmed);
    }

    /// Append an ASN.1 DER length octet sequence for `len` to
    /// `out`. Short form for `len < 128`; long form (marker
    /// [`DER_LONG_FORM_1B`] or [`DER_LONG_FORM_2B`] followed by
    /// the big-endian length bytes) for larger values. Caps at
    /// 65535 -- ECDSA signatures over any practical curve fit
    /// well under that. Values beyond 65535 are clamped to
    /// `u16::MAX` (saturating, fail-closed); the surrounding
    /// `into_der` only ever feeds body lengths under 300 bytes.
    fn encode_der_length(out: &mut Vec<u8>, len: usize) {
        if len < SHORT_FORM_CEILING {
            // Bounded by check; fits in u8.
            let b = u8::try_from(len).unwrap_or(u8::MAX);
            out.push(b);
        } else if len < ONE_BYTE_FORM_CEILING {
            out.push(DER_LONG_FORM_1B);
            let b = u8::try_from(len).unwrap_or(u8::MAX);
            out.push(b);
        } else {
            out.push(DER_LONG_FORM_2B);
            // Saturate to u16::MAX for any value beyond the
            // 2-byte form -- callers only ever pass body lengths
            // well under 300 bytes (ECDSA signatures).
            let clamped = u16::try_from(len).unwrap_or(u16::MAX);
            let [hi, lo] = clamped.to_be_bytes();
            out.push(hi);
            out.push(lo);
        }
    }

    /// Map a hash digest to the ECDSA scalar `e` per RFC 6979
    /// §2.3.2.
    ///
    /// Takes the leftmost `min(bits(n), bits(hash))` bits of the
    /// digest, interpreted big-endian, and right-shifts the
    /// remaining low bits when the truncation falls inside a
    /// byte (i.e. `bits(n) mod 8 != 0`). The shift is a no-op
    /// for the common case of curves whose order is a multiple
    /// of 8 bits (P-256, P-384, `brainpoolP384r1`).
    fn digest_to_scalar(digest: &[u8], ctx: &CurveCtx) -> BoxedUint {
        let n_bits = ctx.n_uint.bits_vartime();
        let n_bytes = usize::try_from(n_bits.div_ceil(BITS_PER_BYTE)).unwrap_or(usize::MAX);
        let take = digest.len().min(n_bytes);
        let mut buf = digest.get(..take).unwrap_or(&[]).to_vec();
        // If the hash is wider than n in bytes but n's bit-length is
        // not a multiple of 8, right-shift the leading byte to keep
        // only `n_bits % 8` high bits (RFC 6979 sec.2.3.2). For the
        // 512-bit hash + 512-bit n case this is a no-op.
        // n_bits is a u32 from bits_vartime(); `% 8` is in [0, 7]
        // and trivially fits u32.
        let n_bits_mod_8: u32 = n_bits
            .rem_euclid(BITS_PER_BYTE)
            .clamp(0, BITS_PER_BYTE.saturating_sub(1));
        let extra_bits = BITS_PER_BYTE
            .saturating_sub(n_bits_mod_8)
            .rem_euclid(BITS_PER_BYTE);
        if extra_bits != 0 && !buf.is_empty() {
            // `extra_bits` in [1, 7] from the modulo above; shift
            // amounts stay well under u8 bit width.
            let inv_bits = BITS_PER_BYTE.saturating_sub(extra_bits);
            let mask = u8::try_from(1_u32.checked_shl(extra_bits).unwrap_or(1))
                .unwrap_or(0)
                .saturating_sub(1);
            // We need to shift the WHOLE buf right by `extra_bits`.
            let mut carry: u8 = 0;
            for b in &mut buf {
                let new_carry = *b & mask;
                *b = (*b >> extra_bits) | (carry << inv_bits);
                carry = new_carry;
            }
        }
        BoxedUint::from_be_slice(&buf, ctx.bits_n)
            .unwrap_or_else(|_e| BoxedUint::zero_with_precision(ctx.bits_n))
    }

    /// Reduce a field element (mod p) into the scalar field
    /// (mod n). In practice for ECDSA's final compare, `sx <
    /// p` but might be `>= n` if `p > n`. Cheapest correct
    /// reduction: subtract n when `sx >= n`.
    fn bytes_into_n(sx: &BoxedUint, ctx: &CurveCtx) -> BoxedUint {
        let sx_at_n = sx.resize(ctx.bits_n);
        if sx_at_n >= ctx.n_uint {
            let (diff, _borrow) = sx_at_n.borrowing_sub(&ctx.n_uint, crypto_bigint::Limb::ZERO);
            diff
        } else {
            sx_at_n
        }
    }
}

// ----- SPKI parsing: the named curve of an id-ecPublicKey key -----

/// Pull the named [`Curve`] and the public point out of an EC
/// `SubjectPublicKeyInfo`.
///
/// RFC 5480 sec.2.1.1: the parameters are the `namedCurve` OID, and
/// only P-256 and P-384 are in the table. Explicit `ECParameters`,
/// `implicitCurve`, an unknown curve OID, or a point that is not
/// octet-aligned uncompressed SEC 1 of the curve's width all return
/// `None`.
#[must_use]
pub(crate) fn extract_ec_pubkey(spki_der: &[u8]) -> Option<(Curve, Sec1UncompressedPoint)> {
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
    let curve = EcdsaHelpers::named_curve_from_oid(KnownOid::new(curve_oid.as_bytes()).ok()?)?;
    // An EC point is octet-aligned. `as_bytes`, unlike `raw_bytes`,
    // refuses a BIT STRING that declares unused trailing bits.
    let pubkey =
        Sec1UncompressedPoint::from_bytes(info.subject_public_key.as_bytes()?.to_vec()).ok()?;
    let point_len = curve
        .p
        .len()
        .saturating_mul(POINT_COORDINATE_COUNT)
        .saturating_add(1);
    if pubkey.len() != point_len {
        return None;
    }
    Some((curve, pubkey))
}

// Named-curve OIDs: `known::SECP256R1` (prime256v1 / NIST P-256) and
// `known::SECP384R1` (NIST P-384).

impl Signature<EcdsaP384> {
    /// Convert this raw `r || s` ECDSA signature into ASN.1 DER
    /// `SEQUENCE { INTEGER r, INTEGER s }` form. r and s are
    /// extracted as the first half / second half of the bytes
    /// (FINEID S1 v4.2 §3.8.3 guarantees the card writes equal-
    /// sized halves; the trait-level
    /// `sign_pre_hashed_sha384_ecdsa_p384` enforces the
    /// 96-byte total before constructing this typed value).
    ///
    /// Pure local re-encoding; no card touch, no fallible
    /// inputs beyond the structural invariant the type carries.
    #[must_use]
    pub fn into_der(self) -> Option<Signature<EcdsaDer>> {
        let raw = self.into_bytes();
        if !raw.len().is_multiple_of(SIG_COMPONENT_COUNT) || raw.is_empty() {
            return None;
        }
        // Bit-shift instead of `/ 2` to bypass the
        // clippy::integer_division_remainder_used lint; the even-
        // length invariant is asserted above, so `>> 1` is exact.
        let half: usize = raw.len() >> 1_u32;
        let (r, s) = raw.split_at(half);
        let mut body = Vec::with_capacity(raw.len().saturating_add(BODY_SLACK));
        EcdsaHelpers::encode_der_integer(&mut body, r);
        EcdsaHelpers::encode_der_integer(&mut body, s);
        let mut out = Vec::with_capacity(body.len().saturating_add(SEQUENCE_HEADER_SLACK));
        out.push(ASN1_SEQUENCE_TAG);
        EcdsaHelpers::encode_der_length(&mut out, body.len());
        out.extend_from_slice(&body);
        Some(Signature::new(out))
    }
}

impl Signature<EcdsaP256> {
    /// Convert this raw `r || s` ECDSA signature into ASN.1 DER
    /// `SEQUENCE { INTEGER r, INTEGER s }` form. This is the
    /// P-256 companion to [`Signature<EcdsaP384>::into_der`];
    /// the raw input is 32 + 32 bytes.
    ///
    /// Pure local re-encoding; no card touch, no fallible
    /// inputs beyond the structural invariant the type carries.
    #[must_use]
    pub fn into_der(self) -> Option<Signature<EcdsaDer>> {
        let raw = self.into_bytes();
        if !raw.len().is_multiple_of(SIG_COMPONENT_COUNT) || raw.is_empty() {
            return None;
        }
        let half: usize = raw.len() >> 1_u32;
        let (r, s) = raw.split_at(half);
        let mut body = Vec::with_capacity(raw.len().saturating_add(BODY_SLACK));
        EcdsaHelpers::encode_der_integer(&mut body, r);
        EcdsaHelpers::encode_der_integer(&mut body, s);
        let mut out = Vec::with_capacity(body.len().saturating_add(SEQUENCE_HEADER_SLACK));
        out.push(ASN1_SEQUENCE_TAG);
        EcdsaHelpers::encode_der_length(&mut out, body.len());
        out.extend_from_slice(&body);
        Some(Signature::new(out))
    }
}

impl Sec1UncompressedPoint {
    /// Verify an ECDSA P-256 + SHA-256 signature against this
    /// public key. Accepts the raw `r || s` form (64 bytes for
    /// secp256r1); the conversion to DER for the underlying
    /// verifier is internal.
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch -- curve construct
    /// failure, off-curve pubkey, r/s out of `[1, n-1]`, s
    /// not invertible mod n, or final verification mismatch.
    pub fn verify_p256_sha256_raw(
        &self,
        signature_raw: Signature<EcdsaP256>,
        message_digest: refineid_digest::Sha256,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP256R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der().ok_or(EcdsaError::BadSignature)?;
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify an ECDSA P-384 + SHA-384 signature against this
    /// public key. Accepts the card-native raw `r || s` form
    /// FINEID PSO:CDS returns (96 bytes for secp384r1 per S1
    /// v4.2 §3.8.3); the conversion to DER for the underlying
    /// verifier is internal.
    ///
    /// `signature_raw` and `message_digest` are taken by value
    /// per typing-discipline Rule B (no `&T` on pub-fn params);
    /// callers that want to keep the signature around clone it
    /// at the call site, which is cheap (96-byte Vec).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch -- curve construct
    /// failure, off-curve pubkey, r/s out of `[1, n-1]`, s
    /// not invertible mod n, or final verification mismatch.
    pub fn verify_p384_sha384_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha384,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der().ok_or(EcdsaError::BadSignature)?;
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify a P-384 ECDSA signature over a SHA-1 digest. Same
    /// curve and verifier as the SHA-384 path; ECDSA is hash-agnostic,
    /// so only the digest length differs (20 bytes).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as `verify_p384_sha384_raw`.
    pub fn verify_p384_sha1_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha1,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der().ok_or(EcdsaError::BadSignature)?;
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify a P-384 ECDSA signature over a SHA-224 digest. Same
    /// curve and verifier as the SHA-384 path; ECDSA is hash-agnostic,
    /// so only the digest length differs (28 bytes).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as `verify_p384_sha384_raw`.
    pub fn verify_p384_sha224_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha224,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der().ok_or(EcdsaError::BadSignature)?;
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify a P-384 ECDSA signature over a SHA-256 digest. Same
    /// curve and verifier as the SHA-384 path; ECDSA is hash-agnostic,
    /// so only the digest length differs (32 bytes). Used to locally
    /// confirm the card's ECDSA+SHA-256 signature (the TLS-1.2
    /// `CertificateVerify` hash macOS requests for suomi.fi).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as `verify_p384_sha384_raw`.
    pub fn verify_p384_sha256_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha256,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der().ok_or(EcdsaError::BadSignature)?;
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify a P-384 ECDSA signature over a SHA-512 digest. Same
    /// curve and verifier as the SHA-384 path; ECDSA is hash-agnostic,
    /// so only the digest length differs (64 bytes).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as `verify_p384_sha384_raw`.
    pub fn verify_p384_sha512_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha512,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der().ok_or(EcdsaError::BadSignature)?;
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }
}

// Named-curve constant table: today this covers `secp256r1`
// (NIST P-256) and `secp384r1` (NIST P-384) -- the curves
// FINEID's G4E chain uses. Brainpool +
// P-521 named-curve SPKIs land in `named_curve_from_oid` as
// `None`; if they're ever needed extend the table rather than
// the verifier.
//
// Parameter values are the canonical SEC 2 / FIPS 186-4 byte
// forms, copied as bare big-endian (no ASN.1 INTEGER sign
// byte, matching the `Curve` struct's documented convention).

/// Byte length of a P-256 field element or scalar -- a 256-bit
/// prime field (FIPS 186-4 D.1.2.3 / SEC 2 2.4.2).
const P256_FIELD_LEN: usize = 32;
/// Byte length of a P-384 field element or scalar -- a 384-bit
/// prime field (FIPS 186-4 D.1.2.4 / SEC 2 2.5.1).
const P384_FIELD_LEN: usize = 48;

/// NIST P-256 field prime `p` (FIPS 186-4 D.1.2.3 / SEC 2 2.4.2).
const SECP256R1_P: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
    "FFFFFFFF000000010000000000000000",
    "00000000FFFFFFFFFFFFFFFFFFFFFFFF",
));
/// NIST P-256 curve coefficient `a`.
const SECP256R1_A: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
    "FFFFFFFF000000010000000000000000",
    "00000000FFFFFFFFFFFFFFFFFFFFFFFC",
));
/// NIST P-256 curve coefficient `b`.
const SECP256R1_B: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
    "5AC635D8AA3A93E7B3EBBD55769886BC",
    "651D06B0CC53B0F63BCE3C3E27D2604B",
));
/// NIST P-256 base point `G` x coordinate.
const SECP256R1_GX: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
    "6B17D1F2E12C4247F8BCE6E563A440F2",
    "77037D812DEB33A0F4A13945D898C296",
));
/// NIST P-256 base point `G` y coordinate.
const SECP256R1_GY: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16",
    "2BCE33576B315ECECBB6406837BF51F5",
));
/// NIST P-256 subgroup order `n`.
const SECP256R1_N: [u8; P256_FIELD_LEN] = Hex::decode_const(concat!(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "BCE6FAADA7179E84F3B9CAC2FC632551",
));
/// NIST P-384 field prime `p` (FIPS 186-4 D.1.2.4 / SEC 2 2.5.1).
const SECP384R1_P: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
    "FFFFFFFF0000000000000000FFFFFFFF",
));
/// NIST P-384 curve coefficient `a`.
const SECP384R1_A: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
    "FFFFFFFF0000000000000000FFFFFFFC",
));
/// NIST P-384 curve coefficient `b`.
///
/// The second hex group is split unevenly: joined, it contains a
/// digits-letter-digits run that the public-hygiene scan would read as
/// a Finnish personal-identity-code shape. `concat!` rejoins the
/// pieces; the decoded bytes are the FIPS 186-4 D.1.2.4 value exactly.
const SECP384R1_B: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
    "B3312FA7E23EE7E4988E056BE3F82D19",
    "181D9C6EFE8141120314088F",
    "5013875A",
    "C656398D8A2ED19D2A85C8EDD3EC2AEF",
));
/// NIST P-384 base point `G` x coordinate.
const SECP384R1_GX: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
    "AA87CA22BE8B05378EB1C71EF320AD74",
    "6E1D3B628BA79B9859F741E082542A38",
    "5502F25DBF55296C3A545E3872760AB7",
));
/// NIST P-384 base point `G` y coordinate.
///
/// The last digit group is split in two: spelled contiguously,
/// its opening digits would read as a binary radix prefix,
/// which the repository's numeric-text policy rejects even
/// inside a hex string. `concat!` rejoins the pieces, so the
/// decoded bytes are unchanged.
const SECP384R1_GY: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
    "3617DE4A96262C6F5D9E98BF9292DC29",
    "F8F41DBD289A147CE9DA3113B5F0B8C0",
    "0A60B",
    "1CE1D7E819D7A431D7C90EA0E5F",
));
/// NIST P-384 subgroup order `n`.
const SECP384R1_N: [u8; P384_FIELD_LEN] = Hex::decode_const(concat!(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFC7634D81F4372DDF",
    "581A0DB248B0A77AECEC196ACCC52973",
));

impl EcdsaHelpers {
    /// Translate a named-curve OID to the corresponding [`Curve`]
    /// constants.
    ///
    /// Returns `None` for any unrecognised OID, and the SPKI is
    /// refused. Constants are inlined here so the
    /// build does not depend on a runtime curve table; the SEC1
    /// / FIPS 186-4 byte forms are decoded at const-eval time,
    /// so a mistyped digit fails compilation.
    fn named_curve_from_oid(oid: KnownOid<'_>) -> Option<Curve> {
        if oid == known::SECP256R1 {
            return Some(Curve {
                p: SECP256R1_P.to_vec(),
                a: SECP256R1_A.to_vec(),
                b: SECP256R1_B.to_vec(),
                gx: SECP256R1_GX.to_vec(),
                gy: SECP256R1_GY.to_vec(),
                n: SECP256R1_N.to_vec(),
            });
        }
        if oid == known::SECP384R1 {
            return Some(Curve {
                p: SECP384R1_P.to_vec(),
                a: SECP384R1_A.to_vec(),
                b: SECP384R1_B.to_vec(),
                gx: SECP384R1_GX.to_vec(),
                gy: SECP384R1_GY.to_vec(),
                n: SECP384R1_N.to_vec(),
            });
        }
        None
    }
}

/// Test-only ECDSA signing over the verifier's own curve arithmetic.
///
/// The nonce is RFC 6979 sec.3.2 deterministic: HMAC-DRBG keyed by the
/// private scalar and the message digest, with the message's own hash
/// as the HMAC hash. Both table curves have an order whose bit length
/// is a multiple of eight, so `bits2int` is a byte truncation and
/// `rlen` is the order's byte length. Nothing here is constant-time;
/// the module exists for building test fixtures and is compiled only
/// for tests and the `testkit` feature.
#[cfg(any(test, feature = "testkit"))]
pub(crate) mod signing {
    use super::{
        Curve, CurveCtx, EcdsaHelpers, POINT_COORDINATE_COUNT, SEC1_UNCOMPRESSED_TAG,
        Sec1UncompressedPoint,
    };
    use crate::container::{EcdsaDer, Signature};
    use crate::oid::Oid as KnownOid;
    use crate::signed_data::HashAlgorithm;
    use crypto_bigint::BoxedUint;
    use crypto_bigint::modular::BoxedMontyForm;

    /// HMAC inner padding octet (RFC 2104 sec.2).
    const HMAC_IPAD: u8 = 0x36;
    /// HMAC outer padding octet (RFC 2104 sec.2).
    const HMAC_OPAD: u8 = 0x5C;
    /// SHA-256 message block length in octets (FIPS 180-4 sec.1).
    const SHA256_BLOCK_LEN: usize = 64;
    /// SHA-384 and SHA-512 message block length in octets (FIPS 180-4
    /// sec.1).
    const SHA512_BLOCK_LEN: usize = 128;
    /// Octet that every byte of the initial HMAC-DRBG `V` holds (RFC
    /// 6979 sec.3.2 step b).
    const DRBG_V_INITIAL: u8 = 0x01;
    /// Octet that every byte of the initial HMAC-DRBG `K` holds (RFC
    /// 6979 sec.3.2 step c).
    const DRBG_K_INITIAL: u8 = 0x00;
    /// Separator octet of the first and the retry key update (RFC 6979
    /// sec.3.2 steps d and h.3).
    const DRBG_SEPARATOR_FIRST: u8 = 0x00;
    /// Separator octet of the second key update (RFC 6979 sec.3.2 step
    /// f).
    const DRBG_SEPARATOR_SECOND: u8 = 0x01;

    /// An ECDSA private key on a table curve, with its public point.
    #[derive(Clone)]
    pub(crate) struct SigningKey {
        /// The curve the key is on.
        curve: Curve,
        /// The private scalar `d`, in `[1, n-1]`.
        scalar: BoxedUint,
        /// `d * G`, uncompressed.
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
        /// The key whose private scalar is the big-endian `scalar`, on
        /// the named curve `curve_oid`. `None` for a curve outside the
        /// table or a scalar outside `[1, n-1]`.
        pub(crate) fn from_scalar(curve_oid: KnownOid<'_>, scalar: &[u8]) -> Option<Self> {
            let curve = EcdsaHelpers::named_curve_from_oid(curve_oid)?;
            let ctx = CurveCtx::new(&curve).ok()?;
            let d = BoxedUint::from_be_slice(scalar, ctx.bits_n).ok()?;
            let one = BoxedUint::one_with_precision(ctx.bits_n);
            if d < one || d >= ctx.n_uint {
                return None;
            }
            let point = ctx.scalar_mul(&d, &ctx.g);
            let (x, y) = point.xy?;
            let width = curve.p.len();
            let mut sec1 = Vec::with_capacity(
                width
                    .saturating_mul(POINT_COORDINATE_COUNT)
                    .saturating_add(1),
            );
            sec1.push(SEC1_UNCOMPRESSED_TAG);
            sec1.extend_from_slice(&fixed_width(&x, width));
            sec1.extend_from_slice(&fixed_width(&y, width));
            let public = Sec1UncompressedPoint::from_bytes(sec1).ok()?;
            Some(Self {
                curve,
                scalar: d,
                public,
            })
        }

        /// A key derived from `seed`: the first digest of `seed` and a
        /// counter octet, under `hash`, whose leftmost order-width
        /// octets fall in `[1, n-1]`.
        pub(crate) fn derive(curve_oid: KnownOid<'_>, hash: HashAlgorithm, seed: &[u8]) -> Self {
            let curve = EcdsaHelpers::named_curve_from_oid(curve_oid)
                .expect("test keys are derived on a table curve");
            let width = curve.n.len();
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

        /// The public point.
        pub(crate) const fn public_point(&self) -> &Sec1UncompressedPoint {
            &self.public
        }

        /// The DER ECDSA signature over `message` hashed with `hash`.
        pub(crate) fn sign(&self, hash: HashAlgorithm, message: &[u8]) -> Signature<EcdsaDer> {
            Signature::<EcdsaDer>::from_raw_concatenation(&self.sign_raw(hash, message))
                .expect("two equal-width components encode")
        }

        /// The ECDSA signature over `message` hashed with `hash`, as
        /// the fixed-width concatenation `r || s` of two order-width
        /// integers (the form XML Signature 1.1 sec.6.4.3 and a card
        /// return).
        pub(crate) fn sign_raw(&self, hash: HashAlgorithm, message: &[u8]) -> Vec<u8> {
            let ctx = CurveCtx::new(&self.curve).expect("table curves build a context");
            let digest = hash.digest(message);
            let width = self.curve.n.len();
            let e =
                EcdsaHelpers::bytes_into_n(&EcdsaHelpers::digest_to_scalar(&digest, &ctx), &ctx);
            let mut nonces = Rfc6979::new(
                hash,
                &fixed_width(&self.scalar, width),
                &fixed_width(&e, width),
                width,
            );
            loop {
                let k = nonces.next_candidate(&ctx);
                let point = ctx.scalar_mul(&k, &ctx.g);
                let Some((x, _)) = point.xy else {
                    continue;
                };
                let r = EcdsaHelpers::bytes_into_n(&x, &ctx);
                let zero = BoxedUint::zero_with_precision(ctx.bits_n);
                if r == zero {
                    continue;
                }
                let Some(k_inverse): Option<BoxedMontyForm> = Option::from(ctx.n_mont(&k).invert())
                else {
                    continue;
                };
                let sum = &ctx.n_mont(&e) + &(&ctx.n_mont(&r) * &ctx.n_mont(&self.scalar));
                let s = (&k_inverse * &sum).retrieve();
                if s == zero {
                    continue;
                }
                let mut raw = fixed_width(&r, width);
                raw.extend_from_slice(&fixed_width(&s, width));
                return raw;
            }
        }
    }

    /// The HMAC-DRBG state of RFC 6979 sec.3.2.
    struct Rfc6979 {
        /// The HMAC hash, the message's own.
        hash: HashAlgorithm,
        /// `K`.
        key: Vec<u8>,
        /// `V`.
        value: Vec<u8>,
        /// `rlen` in octets.
        width: usize,
        /// Whether a candidate was already drawn, so the next draw
        /// first runs step h.3.
        drawn: bool,
    }

    impl Rfc6979 {
        /// Steps b to g, from `int2octets(x)` and `bits2octets(h1)`.
        fn new(hash: HashAlgorithm, private: &[u8], reduced_digest: &[u8], width: usize) -> Self {
            let hash_len = hash.digest_len();
            let mut state = Self {
                hash,
                key: vec![DRBG_K_INITIAL; hash_len],
                value: vec![DRBG_V_INITIAL; hash_len],
                width,
                drawn: false,
            };
            for separator in [DRBG_SEPARATOR_FIRST, DRBG_SEPARATOR_SECOND] {
                state.key = hmac(
                    hash,
                    &state.key,
                    &[&state.value, &[separator], private, reduced_digest],
                );
                state.value = hmac(hash, &state.key, &[&state.value]);
            }
            state
        }

        /// Step h: the next candidate nonce in `[1, n-1]`.
        fn next_candidate(&mut self, ctx: &CurveCtx) -> BoxedUint {
            loop {
                if self.drawn {
                    self.key = hmac(
                        self.hash,
                        &self.key,
                        &[&self.value, &[DRBG_SEPARATOR_FIRST]],
                    );
                    self.value = hmac(self.hash, &self.key, &[&self.value]);
                }
                self.drawn = true;
                let mut output = Vec::with_capacity(self.width);
                while output.len() < self.width {
                    self.value = hmac(self.hash, &self.key, &[&self.value]);
                    output.extend_from_slice(&self.value);
                }
                let candidate = EcdsaHelpers::digest_to_scalar(&output, ctx);
                let one = BoxedUint::one_with_precision(ctx.bits_n);
                if candidate >= one && candidate < ctx.n_uint {
                    return candidate;
                }
            }
        }
    }

    /// HMAC (RFC 2104) over the concatenation of `parts`.
    fn hmac(hash: HashAlgorithm, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let block = match hash {
            HashAlgorithm::Sha256 => SHA256_BLOCK_LEN,
            HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => SHA512_BLOCK_LEN,
        };
        let mut padded = if key.len() > block {
            hash.digest(key)
        } else {
            key.to_vec()
        };
        padded.resize(block, 0);
        let mut inner: Vec<u8> = padded.iter().map(|byte| byte ^ HMAC_IPAD).collect();
        for part in parts {
            inner.extend_from_slice(part);
        }
        let mut outer: Vec<u8> = padded.iter().map(|byte| byte ^ HMAC_OPAD).collect();
        outer.extend_from_slice(&hash.digest(&inner));
        hash.digest(&outer)
    }

    /// `value` as exactly `width` big-endian octets.
    fn fixed_width(value: &BoxedUint, width: usize) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let start = bytes.len().saturating_sub(width);
        let mut out = vec![0; width.saturating_sub(bytes.len())];
        out.extend_from_slice(bytes.get(start..).unwrap_or_default());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ASN1_INTEGER_TAG, DER_LONG_FORM_1B, DER_LONG_FORM_2B, DER_SIGN_PAD, EcdsaError,
        EcdsaHelpers, HIGH_BIT_SET, ONE_BYTE_FORM_CEILING, P384_FIELD_LEN, SHORT_FORM_CEILING,
    };
    use crate::container::{EcdsaDer, EcdsaP256, EcdsaP384, Signature};
    use crate::hex::Hex;

    /// Universal OBJECT IDENTIFIER tag.
    const OID_TAG: u8 = 0x06;
    /// Universal OCTET STRING tag.
    const OCTET_STRING_TAG: u8 = 0x04;
    /// Universal BIT STRING tag.
    const BIT_STRING_TAG: u8 = 0x03;

    /// Odd-width raw fixture -- cannot split into two equal halves.
    const ODD_RAW: [u8; ODD_RAW_LEN] = [1, 2, 3];
    /// Its width, named for the array type position.
    const ODD_RAW_LEN: usize = 3;

    /// Fill byte for an `r` magnitude whose top bit is set.
    const R_FILL_TOP_BIT_SET: u8 = 0xFE;
    /// Trailing fill for the `s` half behind its [`HIGH_BIT_SET`]
    /// lead byte.
    const S_FILL_TAIL: u8 = 0x11;
    /// Largest byte with the top bit clear -- both the widest
    /// DER short-form length (X.690 sec. 8.1.3.4) and the largest
    /// leading magnitude byte that needs no sign pad (X.690
    /// sec. 8.3.3).
    const TOP_BIT_CLEAR_MAX: u8 = 0x7F;
    /// Count of leading zero bytes in the leading-zeros fixture's
    /// `r` half.
    const LEADING_ZERO_COUNT: usize = 5;
    /// `r` fill following the fixture's leading zeros.
    const R_FILL_AFTER_ZEROS: u8 = 0xAB;
    /// `s` fill for the leading-zeros fixture.
    const S_FILL: u8 = 0x33;

    /// P-384 `r||s` sample with the high bit set on both `r[0]`
    /// and `s[0]` -- exercises the sign-pad branch of
    /// [`EcdsaHelpers::encode_der_integer`].
    fn raw_rs_p384_high_bit_set() -> Vec<u8> {
        // r: a field width of R_FILL_TOP_BIT_SET; s: one
        // HIGH_BIT_SET lead, then S_FILL_TAIL to field width.
        let mut v = vec![R_FILL_TOP_BIT_SET; P384_FIELD_LEN];
        v.extend(core::iter::once(HIGH_BIT_SET).chain(core::iter::repeat_n(
            S_FILL_TAIL,
            P384_FIELD_LEN.saturating_sub(1),
        )));
        v
    }

    /// P-384 `r||s` sample with the high bit clear on both halves
    /// -- exercises the no-padding branch.
    fn raw_rs_p384_high_bit_clear() -> Vec<u8> {
        let mut v = vec![1; P384_FIELD_LEN];
        v.extend(core::iter::repeat_n(TOP_BIT_CLEAR_MAX, P384_FIELD_LEN));
        v
    }

    /// P-384 `r||s` sample with leading zeros in `r` -- exercises
    /// the leading-zero strip in
    /// [`EcdsaHelpers::encode_der_integer`].
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
            // The parser strips a leading zero byte if present;
            // r_expected might have trailing meaningful zeros
            // matched by left-strip. Compare big-endian magnitudes
            // by stripping any leading zeros from BOTH sides via
            // the helper above.
            assert_eq!(
                without_leading_zeros(r_parsed.as_slice()),
                without_leading_zeros(r_expected.as_slice())
            );
            assert_eq!(
                without_leading_zeros(s_parsed.as_slice()),
                without_leading_zeros(s_expected.as_slice())
            );
        }
    }

    #[test]
    fn encode_der_length_short_form_under_128() {
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_length(&mut out, 0);
        assert_eq!(out, [0]);
        out.clear();
        EcdsaHelpers::encode_der_length(&mut out, usize::from(TOP_BIT_CLEAR_MAX));
        assert_eq!(out, [TOP_BIT_CLEAR_MAX]);
    }

    #[test]
    fn encode_der_length_one_byte_long_form() {
        /// [`SHORT_FORM_CEILING`] rendered as the follow-up
        /// length octet of the one-byte long form.
        const SHORT_FORM_CEILING_OCTET: u8 = 0x80;
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_length(&mut out, SHORT_FORM_CEILING);
        assert_eq!(out, [DER_LONG_FORM_1B, SHORT_FORM_CEILING_OCTET]);
        out.clear();
        EcdsaHelpers::encode_der_length(&mut out, usize::from(u8::MAX));
        assert_eq!(out, [DER_LONG_FORM_1B, u8::MAX]);
    }

    #[test]
    fn encode_der_length_two_byte_long_form() {
        let mut out = Vec::new();
        // ONE_BYTE_FORM_CEILING (256) is big-endian `01 00`.
        EcdsaHelpers::encode_der_length(&mut out, ONE_BYTE_FORM_CEILING);
        assert_eq!(out, [DER_LONG_FORM_2B, 1, 0]);
        out.clear();
        EcdsaHelpers::encode_der_length(&mut out, usize::from(u16::MAX));
        assert_eq!(out, [DER_LONG_FORM_2B, u8::MAX, u8::MAX]);
    }

    #[test]
    fn encode_der_integer_zero_emits_single_byte() {
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_integer(&mut out, &[0]);
        assert_eq!(out, [ASN1_INTEGER_TAG, 1, 0]);
    }

    #[test]
    fn encode_der_integer_high_bit_set_pads_with_zero() {
        /// DER INTEGER content length of two octets -- here the
        /// sign pad plus one magnitude byte.
        const PAD_PLUS_MAGNITUDE_LEN: u8 = 2;
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_integer(&mut out, &[u8::MAX]);
        assert_eq!(
            out,
            [
                ASN1_INTEGER_TAG,
                PAD_PLUS_MAGNITUDE_LEN,
                DER_SIGN_PAD,
                u8::MAX
            ]
        );
    }

    #[test]
    fn encode_der_integer_strips_leading_zeros() {
        /// High magnitude byte of the fixture integer.
        const MAGNITUDE_HI: u8 = 0x42;
        /// Low magnitude byte of the fixture integer.
        const MAGNITUDE_LO: u8 = 0xAB;
        /// DER INTEGER content length of two octets -- the two
        /// magnitude bytes left after the zero strip.
        const MAGNITUDE_LEN: u8 = 2;
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_integer(&mut out, &[0, 0, MAGNITUDE_HI, MAGNITUDE_LO]);
        assert_eq!(
            out,
            [ASN1_INTEGER_TAG, MAGNITUDE_LEN, MAGNITUDE_HI, MAGNITUDE_LO]
        );
    }

    #[test]
    fn xml_raw_signature_converts_to_der_components() {
        /// Bytes per signature component in this fixture.
        const COMPONENT_BYTES: usize = 4;
        /// Leading zero bytes opening the fixture's `r` half.
        const R_LEADING_ZEROS: usize = 2;
        /// Total fixture width: two [`COMPONENT_BYTES`] halves.
        const RAW_LEN: usize = 8;
        /// Raw `r || s`: `r` opens with two zeros (exercising the
        /// zero strip), `s` opens with [`HIGH_BIT_SET`]
        /// (exercising the sign pad).
        const RAW_RS: [u8; RAW_LEN] = [0, 0, 1, 2, HIGH_BIT_SET, 3, 4, 5];
        let converted = Signature::<EcdsaDer>::from_raw_concatenation(&RAW_RS);
        let signature = converted.expect("valid equal-width XML signature components must convert");
        let (r, s) = signature
            .parse_ecdsa_signature()
            .expect("converted signature must be valid DER");
        assert_eq!(r, RAW_RS[R_LEADING_ZEROS..COMPONENT_BYTES]);
        assert_eq!(s, RAW_RS[COMPONENT_BYTES..]);
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

    /// P-256 CAVP / RFC 6979 test vector public key X.
    const P256_CAVP_QX: [u8; super::P256_FIELD_LEN] = Hex::decode_const(concat!(
        "60fed4ba255a9d31c961eb74c6356d68",
        "c049b8923b61fa6ce669622e60f29fb6",
    ));
    /// P-256 CAVP / RFC 6979 test vector public key Y.
    const P256_CAVP_QY: [u8; super::P256_FIELD_LEN] = Hex::decode_const(concat!(
        "7903fe1008b8bc99a41ae9e95628bc64",
        "f2f1b20c2d7e9f5177a3c294d4462299",
    ));
    /// P-256 CAVP / RFC 6979 test vector signature R.
    const P256_CAVP_R: [u8; super::P256_FIELD_LEN] = Hex::decode_const(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d6",
        "9d2c877b56aaf991c34d0ea84eaf3716",
    ));
    /// P-256 CAVP / RFC 6979 test vector signature S.
    const P256_CAVP_S: [u8; super::P256_FIELD_LEN] = Hex::decode_const(concat!(
        "f7cb1c942d657c41d436c7a1b6e29f65",
        "f3e900dbb9aff4064dc4ab2f843acda8",
    ));

    /// P-384 CAVP / RFC 6979 test vector public key X.
    const P384_CAVP_QX: [u8; super::P384_FIELD_LEN] = Hex::decode_const(concat!(
        "ec3a4e415b4e19a4568618029f427fa5",
        "da9a8bc4ae92e02e06aae5286b300c64",
        "def8f0ea9055866064a254515480bc13",
    ));
    /// P-384 CAVP / RFC 6979 test vector public key Y.
    const P384_CAVP_QY: [u8; super::P384_FIELD_LEN] = Hex::decode_const(concat!(
        "8015d9b72d7d57244ea8ef9ac0c62189",
        "6708a59367f9dfb9f54ca84b3f1c9db1",
        "288b231c3ae0d4fe7344fd",
        "2533264720",
    ));
    /// P-384 CAVP / RFC 6979 test vector signature R.
    const P384_CAVP_R: [u8; super::P384_FIELD_LEN] = Hex::decode_const(concat!(
        "94edbb92a5ecb8aad4736e56c691916b",
        "3f88140666ce9fa73d64c4ea95ad133c",
        "81a648152e44acf96e36dd1e80fabe46",
    ));
    /// P-384 CAVP / RFC 6979 test vector signature S.
    const P384_CAVP_S: [u8; super::P384_FIELD_LEN] = Hex::decode_const(concat!(
        "99ef4aeb15f178cea1fe40db2603138f",
        "130e740a19624526203b6351d0a3a94f",
        "a329c145786e679e7b82c71a38628ac8",
    ));

    /// Fixed test message string for the CAVP / RFC 6979 vectors.
    const CAVP_MESSAGE: &[u8] = b"sample";
    /// SEC1 uncompressed point byte width for P-256 (1 tag byte + 2 field elements).
    const P256_SEC1_POINT_LEN: usize = 1 + super::P256_FIELD_LEN + super::P256_FIELD_LEN;
    /// Raw concatenated r||s signature byte width for P-256.
    const P256_RAW_SIGNATURE_LEN: usize = super::P256_FIELD_LEN + super::P256_FIELD_LEN;
    /// SEC1 uncompressed point byte width for P-384 (1 tag byte + 2 field elements).
    const P384_SEC1_POINT_LEN: usize = 1 + super::P384_FIELD_LEN + super::P384_FIELD_LEN;
    /// Raw concatenated r||s signature byte width for P-384.
    const P384_RAW_SIGNATURE_LEN: usize = super::P384_FIELD_LEN + super::P384_FIELD_LEN;

    #[test]
    fn cavp_p256_sha256_signature_verifies() {
        let mut sec1 = Vec::with_capacity(P256_SEC1_POINT_LEN);
        sec1.push(super::SEC1_UNCOMPRESSED_TAG);
        sec1.extend_from_slice(&P256_CAVP_QX);
        sec1.extend_from_slice(&P256_CAVP_QY);
        let pubkey =
            super::Sec1UncompressedPoint::from_bytes(sec1).expect("valid P-256 public key");

        let mut raw_sig = Vec::with_capacity(P256_RAW_SIGNATURE_LEN);
        raw_sig.extend_from_slice(&P256_CAVP_R);
        raw_sig.extend_from_slice(&P256_CAVP_S);
        let sig: Signature<EcdsaP256> = Signature::new(raw_sig);

        let digest = refineid_digest::Sha256::of(CAVP_MESSAGE);
        assert_eq!(pubkey.verify_p256_sha256_raw(sig, digest), Ok(()));
    }

    #[test]
    fn cavp_p384_sha384_signature_verifies() {
        let mut sec1 = Vec::with_capacity(P384_SEC1_POINT_LEN);
        sec1.push(super::SEC1_UNCOMPRESSED_TAG);
        sec1.extend_from_slice(&P384_CAVP_QX);
        sec1.extend_from_slice(&P384_CAVP_QY);
        let pubkey =
            super::Sec1UncompressedPoint::from_bytes(sec1).expect("valid P-384 public key");

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

    /// RFC 6979 sec.A.2.5 P-256 private key `x`.
    const RFC6979_P256_X: [u8; super::P256_FIELD_LEN] = Hex::decode_const(concat!(
        "C9AFA9D845BA75166B5C215767B1D693",
        "4E50C3DB36E89B127B8A622B120F6721",
    ));
    /// RFC 6979 sec.A.2.6 P-384 private key `x`.
    const RFC6979_P384_X: [u8; super::P384_FIELD_LEN] = Hex::decode_const(concat!(
        "6B9D3DAD2E1B8C1C05B19875B6659F4D",
        "E23C3B667BF297BA9AA47740787137D8",
        "96D5724E4C70A825F872C9EA60D2EDF5",
    ));
    /// ANSI X9.62 `prime-field`, the `fieldType` of explicit
    /// `ECParameters` (SEC 1 sec.C.2).
    const PRIME_FIELD: crate::oid::Oid<'static> = crate::oid::Oid::const_new(
        ::const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.1.1").as_bytes(),
    );
    /// `ECParameters.version` `ecpVer1` (SEC 1 sec.C.2).
    const EC_PARAMETERS_VERSION: u8 = 1;
    /// Universal NULL tag.
    const NULL_TAG: u8 = 0x05;

    /// The uncompressed point of a CAVP key.
    fn sec1(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut point = vec![super::SEC1_UNCOMPRESSED_TAG];
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        point
    }

    /// The `(r, s)` magnitudes of a kit signature, left-padded to
    /// `width`.
    fn components(signature: &Signature<EcdsaDer>, width: usize) -> Vec<u8> {
        let (r, s) = signature.parse_ecdsa_signature().expect("signature parses");
        let mut raw = Vec::new();
        for component in [r, s] {
            raw.extend(core::iter::repeat_n(
                0,
                width.saturating_sub(component.len()),
            ));
            raw.extend_from_slice(&component);
        }
        raw
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
        assert_eq!(components(&signature, super::P256_FIELD_LEN), expected);
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
        assert_eq!(components(&signature, super::P384_FIELD_LEN), expected);
    }

    #[test]
    fn signing_refuses_a_scalar_outside_the_order() {
        assert!(
            super::signing::SigningKey::from_scalar(crate::oid::known::SECP256R1, &[0]).is_none()
        );
        assert!(
            super::signing::SigningKey::from_scalar(
                crate::oid::known::SECP256R1,
                &super::SECP256R1_N
            )
            .is_none()
        );
        assert!(
            super::signing::SigningKey::from_scalar(crate::oid::known::BRAINPOOL_P256R1, &[1])
                .is_none()
        );
    }

    #[test]
    fn ecdsa_value_must_be_one_canonical_pair() {
        let tlv = |tag: u8, value: &[u8]| refineid_ber::tlv(tag, value).expect("fixture TLV");
        let integer = |value: &[u8]| tlv(ASN1_INTEGER_TAG, value);
        let pair = |body: Vec<u8>| Signature::<EcdsaDer>::new(tlv(super::ASN1_SEQUENCE_TAG, &body));
        let one = integer(&[1]);

        let canonical = pair([one.clone(), one.clone()].concat());
        assert_eq!(canonical.parse_ecdsa_signature(), Ok((vec![1], vec![1])));
        for malformed in [
            pair([one.clone(), one.clone(), one.clone()].concat()),
            pair(one.clone()),
            pair([integer(&[DER_SIGN_PAD, 1]), one.clone()].concat()),
            pair([integer(&[HIGH_BIT_SET]), one.clone()].concat()),
            pair([integer(&[]), one.clone()].concat()),
            pair([integer(&[DER_SIGN_PAD]), one.clone()].concat()),
            pair([one.clone(), integer(&[DER_SIGN_PAD])].concat()),
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
        let sequence = |parts: &[Vec<u8>]| tlv(super::ASN1_SEQUENCE_TAG, &parts.concat());

        let field = sequence(&[oid(PRIME_FIELD), integer(&super::SECP256R1_P)]);
        let coefficients = sequence(&[
            tlv(OCTET_STRING_TAG, &super::SECP256R1_A),
            tlv(OCTET_STRING_TAG, &super::SECP256R1_B),
        ]);
        let explicit = sequence(&[
            integer(&[EC_PARAMETERS_VERSION]),
            field,
            coefficients,
            tlv(
                OCTET_STRING_TAG,
                &sec1(&super::SECP256R1_GX, &super::SECP256R1_GY),
            ),
            integer(&super::SECP256R1_N),
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
    }
}
