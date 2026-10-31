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

//! The brainpoolP384r1 elliptic curve, RFC 5639 section 3.6.
//!
//! PACE on the FINEID card runs over brainpoolP384r1. The field, scalar,
//! and point arithmetic come from the RustCrypto `bp384` crate. Scalar
//! multiplication is its constant-time fixed-window method: a radix-16
//! digit decomposition of the scalar and a precomputed table of point
//! multiples read with constant-time selection.
//!
//! This module holds the surface the handshake uses: the generator,
//! point addition, scalar multiplication, the SEC1 uncompressed
//! encoding with the on-curve check at decode, constant-time equality,
//! and the affine x-coordinate of a shared point. [`Point`] exposes no
//! variable-time operation of the library point it wraps.

use bp384::BrainpoolP384r1;
use bp384::elliptic_curve::array::typenum::Unsigned as _;
use bp384::elliptic_curve::point::AffineCoordinates as _;
use bp384::elliptic_curve::sec1::{
    Coordinates, FromSec1Point as _, ToSec1Point as _, UncompressedPointSize,
};
use bp384::r1::{AffinePoint, ProjectivePoint, Sec1Point};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

pub use bp384::r1::NonZeroScalar;
pub use bp384::{FieldBytes, Scalar};

/// Length of a SEC1 uncompressed encoding: tag plus two coordinates
/// (SEC1 v2 section 2.3.3).
const SEC1_UNCOMPRESSED_LEN: usize = UncompressedPointSize::<BrainpoolP384r1>::USIZE;

/// A brainpoolP384r1 point in SEC1 uncompressed encoding
/// (`04 || X || Y`), ninety-seven bytes: one tag byte and two
/// forty-eight-byte big-endian coordinates (SEC1 v2 section 2.3.3).
///
/// The only constructor is [`Point::encode_uncompressed`], so a value of
/// this type is proof of a finite point's canonical encoding rather than
/// a bare byte buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sec1UncompressedPoint([u8; SEC1_UNCOMPRESSED_LEN]);

impl Sec1UncompressedPoint {
    /// Borrow the encoded point bytes, to feed the BER encoder. No
    /// `AsRef<[u8]>`: the byte view is named, not a shape a caller can pass
    /// wherever bytes are welcome.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEC1_UNCOMPRESSED_LEN] {
        &self.0
    }
}

/// A point on brainpoolP384r1, the identity included.
///
/// Not `Copy`: a point computed from a private scalar is duplicated only
/// by an explicit `clone`, so the handshake owns every secret-dependent
/// point in a zeroizing wrapper. Zeroizing leaves the identity.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Point(ProjectivePoint);

impl Point {
    /// The curve generator `G` (RFC 5639 section 3.6).
    #[must_use]
    pub const fn generator() -> Self {
        Self(ProjectivePoint::GENERATOR)
    }

    /// Point addition.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        Self(self.0 + other.0)
    }

    /// Constant-time scalar multiplication `[k] self`.
    #[must_use]
    pub fn scalar_mul(&self, k: &Scalar) -> Self {
        Self(ProjectivePoint::mul(&self.0, k))
    }

    /// Encode this point in SEC1 uncompressed form. `None` for the
    /// identity, which has no uncompressed encoding.
    #[must_use]
    pub fn encode_uncompressed(&self) -> Option<Sec1UncompressedPoint> {
        let affine = self.0.to_affine();
        if bool::from(affine.is_identity()) {
            return None;
        }
        let encoded = affine.to_sec1_point(false);
        let bytes: [u8; SEC1_UNCOMPRESSED_LEN] = encoded.as_bytes().try_into().ok()?;
        Some(Sec1UncompressedPoint(bytes))
    }

    /// Decode a SEC1 uncompressed encoding. `None` on a wrong length, a
    /// tag other than the uncompressed one, a coordinate that is not a
    /// canonical field element, or a point that is not on the curve
    /// (SEC1 v2 section 2.3.4). The identity has no uncompressed
    /// encoding, so a decoded point is always finite.
    #[must_use]
    pub fn decode_uncompressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SEC1_UNCOMPRESSED_LEN {
            return None;
        }
        let encoded = Sec1Point::from_bytes(bytes).ok()?;
        if !matches!(encoded.coordinates(), Coordinates::Uncompressed { .. }) {
            return None;
        }
        let affine: AffinePoint = AffinePoint::from_sec1_point(&encoded).into_option()?;
        Some(Self(affine.into()))
    }

    /// The affine x-coordinate as big-endian bytes, the ECDH shared
    /// secret of a key-agreement point. `None` for the identity.
    #[must_use]
    pub fn x_coordinate(&self) -> Option<Zeroizing<FieldBytes>> {
        let affine = Zeroizing::new(self.0.to_affine());
        if bool::from(affine.is_identity()) {
            return None;
        }
        Some(Zeroizing::new(affine.x()))
    }
}

impl ConstantTimeEq for Point {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldBytes, Point, SEC1_UNCOMPRESSED_LEN, Scalar};
    use bp384::BrainpoolP384r1;
    use bp384::elliptic_curve::Curve as _;
    use bp384::elliptic_curve::bigint::Reduce as _;
    use bp384::elliptic_curve::sec1::Tag;
    use subtle::ConstantTimeEq as _;
    use zeroize::Zeroize as _;

    /// A small scalar for the multiplication checks.
    const SCALAR_A: u64 = 0x1234_5678;

    fn generator_encoding() -> [u8; SEC1_UNCOMPRESSED_LEN] {
        *Point::generator()
            .encode_uncompressed()
            .expect("generator encodes")
            .as_bytes()
    }

    #[test]
    fn generator_round_trips_through_sec1() {
        let encoded = generator_encoding();
        let coordinate = FieldBytes::default().len();
        assert_eq!(encoded.len(), 1 + coordinate + coordinate);
        assert_eq!(encoded[0], u8::from(Tag::Uncompressed));
        let decoded = Point::decode_uncompressed(&encoded).expect("encoded generator decodes");
        assert_eq!(decoded, Point::generator());
    }

    #[test]
    fn an_off_curve_encoding_is_rejected() {
        let mut encoding = generator_encoding();
        let last = encoding.len() - 1;
        encoding[last] ^= 1;
        assert!(Point::decode_uncompressed(&encoding).is_none());
    }

    #[test]
    fn coordinates_above_the_prime_are_rejected() {
        // The prime's leading byte is below the all-ones byte, so an
        // all-ones coordinate is not a canonical field element.
        let mut encoding = [u8::MAX; SEC1_UNCOMPRESSED_LEN];
        encoding[0] = u8::from(Tag::Uncompressed);
        assert!(Point::decode_uncompressed(&encoding).is_none());
    }

    #[test]
    fn a_wrongly_tagged_or_sized_encoding_is_rejected() {
        let mut compressed_tag = generator_encoding();
        compressed_tag[0] = u8::from(Tag::CompressedEvenY);
        assert!(Point::decode_uncompressed(&compressed_tag).is_none());

        let encoding = generator_encoding();
        assert!(Point::decode_uncompressed(&encoding[..encoding.len() - 1]).is_none());
        assert!(Point::decode_uncompressed(&[u8::from(Tag::Identity)]).is_none());
    }

    #[test]
    fn generator_times_order_is_the_identity() {
        // `n` reduces to zero in the scalar field; the library's group law
        // takes `n * G` and `(n - 1) * G + G` to the identity alike.
        let order = Scalar::reduce(BrainpoolP384r1::ORDER.as_ref());
        let identity = Point::generator().scalar_mul(&order);
        assert!(identity.encode_uncompressed().is_none());
        assert!(identity.x_coordinate().is_none());
        let order_minus_one = Point::generator().scalar_mul(&(Scalar::ZERO - Scalar::ONE));
        assert!(
            order_minus_one
                .add(&Point::generator())
                .encode_uncompressed()
                .is_none()
        );
    }

    #[test]
    fn scalar_multiples_compare_in_constant_time() {
        let g = Point::generator();
        let a = Scalar::from(SCALAR_A);
        let a_g = g.scalar_mul(&a);
        assert!(bool::from(a_g.ct_eq(&g.scalar_mul(&a))));
        assert!(!bool::from(a_g.ct_eq(&g)));
        assert!(bool::from(g.scalar_mul(&a.double()).ct_eq(&a_g.add(&a_g))));
    }

    #[test]
    fn point_zeroize_leaves_the_identity() {
        let mut point = Point::generator();
        point.zeroize();
        assert!(point.encode_uncompressed().is_none());
    }
}
