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

//! The elliptic curves PACE runs over, and the point surface it uses.
//!
//! The FINEID cards publish three standardized PACE domain parameters
//! (BSI TR-03110-3 table 4): NIST P-256 (`secp256r1`), NIST P-384
//! (`secp384r1`) and brainpoolP384r1 (RFC 5639 section 3.6). The field,
//! scalar and point arithmetic of each comes from its RustCrypto crate
//! -- `p256`, `p384` and `bp384` -- all three on one `elliptic-curve`
//! version. Their scalar multiplication is the constant-time
//! fixed-window method: a radix-16 digit decomposition of the scalar
//! and a precomputed table of point multiples read with constant-time
//! selection.
//!
//! [`Point`] holds the surface the handshake uses -- the generator,
//! point addition, scalar multiplication, the SEC1 uncompressed encoding
//! with the on-curve check at decode, constant-time equality, and the
//! affine x-coordinate of a shared point -- and exposes no variable-time
//! operation of the library point it wraps.

use elliptic_curve::array::typenum::Unsigned as _;
use elliptic_curve::group::{Curve as _, Group as _};
use elliptic_curve::point::AffineCoordinates as _;
use elliptic_curve::sec1::{
    Coordinates, FromSec1Point, ModulusSize, Sec1Point, ToSec1Point, UncompressedPointSize,
};
use elliptic_curve::{CurveArithmetic, FieldBytes, ProjectivePoint};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

pub use elliptic_curve::Scalar;

/// A curve PACE runs over: one with arithmetic, SEC1 point encoding,
/// and a field-element encoding SEC1 can size.
///
/// Implemented for the three standardized domain parameters the FINEID
/// cards publish, and nothing else.
pub trait PaceCurve:
    CurveArithmetic<AffinePoint: FromSec1Point<Self> + ToSec1Point<Self>>
    + elliptic_curve::Curve<FieldBytesSize: ModulusSize>
{
}

impl PaceCurve for p256::NistP256 {}
impl PaceCurve for p384::NistP384 {}
impl PaceCurve for bp384::BrainpoolP384r1 {}

/// The width of one coordinate of `C`, in bytes.
#[cfg(test)]
pub fn coordinate_len<C: PaceCurve>() -> usize {
    elliptic_curve::FieldBytesSize::<C>::USIZE
}

/// The length of a SEC1 uncompressed encoding on `C`: tag plus two
/// coordinates (SEC1 v2 section 2.3.3).
pub fn uncompressed_len<C: PaceCurve>() -> usize {
    UncompressedPointSize::<C>::USIZE
}

/// A point of `C` in SEC1 uncompressed encoding (`04 || X || Y`): one
/// tag byte and two big-endian coordinates of the field width (SEC1 v2
/// section 2.3.3).
///
/// The only constructor is [`Point::encode_uncompressed`], so a value of
/// this type is proof of a finite point's canonical encoding rather than
/// a bare byte buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sec1UncompressedPoint<C: PaceCurve>(Sec1Point<C>);

impl<C: PaceCurve> Sec1UncompressedPoint<C> {
    /// Borrow the encoded point bytes, to feed the BER encoder. No
    /// `AsRef<[u8]>`: the byte view is named, not a shape a caller can
    /// pass wherever bytes are welcome.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A point on `C`, the identity included.
///
/// Not `Copy`: a point computed from a private scalar is duplicated only
/// by an explicit `clone`, so the handshake owns every secret-dependent
/// point in a zeroizing wrapper. Zeroizing leaves the identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point<C: PaceCurve>(ProjectivePoint<C>);

impl<C: PaceCurve> Zeroize for Point<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<C: PaceCurve> Point<C> {
    /// The curve generator `G` of the domain parameters.
    #[must_use]
    pub fn generator() -> Self {
        Self(ProjectivePoint::<C>::generator())
    }

    /// Point addition.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    /// Constant-time scalar multiplication `[k] self`.
    #[must_use]
    pub fn scalar_mul(&self, k: &Scalar<C>) -> Self {
        Self(self.0 * k)
    }

    /// Encode this point in SEC1 uncompressed form. `None` for the
    /// identity, which has no uncompressed encoding.
    #[must_use]
    pub fn encode_uncompressed(&self) -> Option<Sec1UncompressedPoint<C>> {
        if bool::from(self.0.is_identity()) {
            return None;
        }
        Some(Sec1UncompressedPoint(
            self.0.to_affine().to_sec1_point(false),
        ))
    }

    /// Decode a SEC1 uncompressed encoding. `None` on a wrong length, a
    /// tag other than the uncompressed one, a coordinate that is not a
    /// canonical field element, or a point that is not on the curve
    /// (SEC1 v2 section 2.3.4). The identity has no uncompressed
    /// encoding, so a decoded point is always finite.
    #[must_use]
    pub fn decode_uncompressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != uncompressed_len::<C>() {
            return None;
        }
        let encoded = Sec1Point::<C>::from_bytes(bytes).ok()?;
        if !matches!(encoded.coordinates(), Coordinates::Uncompressed { .. }) {
            return None;
        }
        let affine = C::AffinePoint::from_sec1_point(&encoded).into_option()?;
        Some(Self(affine.into()))
    }

    /// The affine x-coordinate as big-endian bytes, the ECDH shared
    /// secret of a key-agreement point. `None` for the identity.
    #[must_use]
    pub fn x_coordinate(&self) -> Option<Zeroizing<FieldBytes<C>>> {
        if bool::from(self.0.is_identity()) {
            return None;
        }
        let affine = Zeroizing::new(self.0.to_affine());
        Some(Zeroizing::new(affine.x()))
    }
}

impl<C: PaceCurve> ConstantTimeEq for Point<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{PaceCurve, Point, Scalar, coordinate_len};
    use elliptic_curve::ff::Field as _;
    use elliptic_curve::sec1::Tag;
    use subtle::ConstantTimeEq as _;
    use zeroize::Zeroize as _;

    /// A small scalar for the multiplication checks.
    const SCALAR_A: u64 = 0x1234_5678;

    fn generator_encoding<C: PaceCurve>() -> Vec<u8> {
        Point::<C>::generator()
            .encode_uncompressed()
            .expect("generator encodes")
            .as_bytes()
            .to_vec()
    }

    fn generator_round_trips_through_sec1<C: PaceCurve>() {
        let encoded = generator_encoding::<C>();
        let coordinate = coordinate_len::<C>();
        assert_eq!(encoded.len(), 1 + coordinate + coordinate);
        assert_eq!(encoded[0], u8::from(Tag::Uncompressed));
        let decoded = Point::<C>::decode_uncompressed(&encoded).expect("encoded generator decodes");
        assert_eq!(decoded, Point::generator());
    }

    fn an_off_curve_encoding_is_rejected<C: PaceCurve>() {
        let mut encoding = generator_encoding::<C>();
        let last = encoding.len() - 1;
        encoding[last] ^= 1;
        assert!(Point::<C>::decode_uncompressed(&encoding).is_none());
    }

    fn coordinates_above_the_prime_are_rejected<C: PaceCurve>() {
        // Every prime here is below the all-ones value of its width, so
        // an all-ones coordinate is not a canonical field element.
        let mut encoding = vec![u8::MAX; generator_encoding::<C>().len()];
        encoding[0] = u8::from(Tag::Uncompressed);
        assert!(Point::<C>::decode_uncompressed(&encoding).is_none());
    }

    fn a_wrongly_tagged_or_sized_encoding_is_rejected<C: PaceCurve>() {
        let mut compressed_tag = generator_encoding::<C>();
        compressed_tag[0] = u8::from(Tag::CompressedEvenY);
        assert!(Point::<C>::decode_uncompressed(&compressed_tag).is_none());

        let encoding = generator_encoding::<C>();
        assert!(Point::<C>::decode_uncompressed(&encoding[..encoding.len() - 1]).is_none());
        assert!(Point::<C>::decode_uncompressed(&[u8::from(Tag::Identity)]).is_none());
    }

    fn order_minus_one_plus_generator_is_the_identity<C: PaceCurve>() {
        // `n` itself is zero in the scalar field, so the subgroup order is
        // pinned through `(n - 1) * G + G`: a finite point that the
        // generator completes to the identity.
        let order_minus_one =
            Point::<C>::generator().scalar_mul(&(Scalar::<C>::ZERO - Scalar::<C>::ONE));
        assert!(order_minus_one.encode_uncompressed().is_some());
        let identity = order_minus_one.add(&Point::generator());
        assert!(identity.encode_uncompressed().is_none());
        assert!(identity.x_coordinate().is_none());
    }

    fn scalar_multiples_compare_in_constant_time<C: PaceCurve>() {
        let g = Point::<C>::generator();
        let a = Scalar::<C>::from(SCALAR_A);
        let a_g = g.scalar_mul(&a);
        assert!(bool::from(a_g.ct_eq(&g.scalar_mul(&a))));
        assert!(!bool::from(a_g.ct_eq(&g)));
        assert!(bool::from(g.scalar_mul(&a.double()).ct_eq(&a_g.add(&a_g))));
    }

    fn point_zeroize_leaves_the_identity<C: PaceCurve>() {
        let mut point = Point::<C>::generator();
        point.zeroize();
        assert!(point.encode_uncompressed().is_none());
    }

    fn every_check<C: PaceCurve>() {
        generator_round_trips_through_sec1::<C>();
        an_off_curve_encoding_is_rejected::<C>();
        coordinates_above_the_prime_are_rejected::<C>();
        a_wrongly_tagged_or_sized_encoding_is_rejected::<C>();
        order_minus_one_plus_generator_is_the_identity::<C>();
        scalar_multiples_compare_in_constant_time::<C>();
        point_zeroize_leaves_the_identity::<C>();
    }

    #[test]
    fn nist_p256_point_surface() {
        every_check::<p256::NistP256>();
    }

    #[test]
    fn nist_p384_point_surface() {
        every_check::<p384::NistP384>();
    }

    #[test]
    fn brainpool_p384_r1_point_surface() {
        every_check::<bp384::BrainpoolP384r1>();
    }
}
