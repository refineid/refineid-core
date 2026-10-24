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
//! PACE on the FINEID card runs over brainpoolP384r1, which the general
//! elliptic-curve crates do not ship at this toolchain, so field
//! arithmetic is built here on `crypto_bigint` fixed-width Montgomery
//! form over the curve prime. Scalar multiplication is double-and-add,
//! whose timing leaks the scalar bit count; that is acceptable only
//! because the PACE scalars are ephemeral and single-use, and a
//! constant-time ladder is a documented hardening item.
//!
//! Correctness is pinned by two property tests against the generator:
//! the subgroup-order identity `n * G = infinity`, and the group
//! homomorphism `(a + b) * G = a * G + b * G`.

use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U384};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Field prime `p` (RFC 5639 section 3.6).
const P_HEX: &str = concat!(
    "8CB91E82", "A3386D28", "0F5D6F7E", "50E641DF", "152F7109", "ED5456B4", "12B1DA19", "7FB71123",
    "ACD3A729", "901D1A71", "87470013", "3107EC53"
);
/// Curve coefficient `a` in `y^2 = x^3 + a*x + b (mod p)`.
const A_HEX: &str = concat!(
    "7BC382C6", "3D8C150C", "3C72080A", "CE05AFA0", "C2BEA28E", "4FB22787", "139165EF", "BA91F90F",
    "8AA5814A", "503AD4EB", "04A8C7DD", "22CE2826"
);
/// Curve coefficient `b`.
const B_HEX: &str = concat!(
    "04A8C7DD", "22CE2826", "8B39B554", "16F0447C", "2FB77DE1", "07DCD2A6", "2E880EA5", "3EEB62D5",
    "7CB43902", "95DBC994", "3AB78696", "FA504C11"
);
/// Generator x-coordinate.
const G_X_HEX: &str = concat!(
    "1D1C64F0", "68CF45FF", "A2A63A81", "B7C13F6B", "8847A3E7", "7EF14FE3", "DB7FCAFE", "0CBD10E8",
    "E826E034", "36D646AA", "EF87B2E2", "47D4AF1E"
);
/// Generator y-coordinate.
const G_Y_HEX: &str = concat!(
    "8ABE1D75", "20F9C2A4", "5CB1EB8E", "95CFD552", "62B70B29", "FEEC5864", "E19C054F", "F9912928",
    "0E464621", "77918111", "42820341", "263C5315"
);
/// Subgroup order `n`.
const N_HEX: &str = concat!(
    "8CB91E82", "A3386D28", "0F5D6F7E", "50E641DF", "152F7109", "ED5456B3", "1F166E6C", "AC0425A7",
    "CF3AB6AF", "6B7FC310", "3B883202", "E9046565"
);

/// Subgroup order `n` as an integer, for scalar-range checks.
#[must_use]
pub fn n() -> U384 {
    U384::from_be_hex(N_HEX)
}

/// The curve prime as an odd modulus for Montgomery arithmetic.
const PRIME: Odd<U384> = Odd::<U384>::from_be_hex(P_HEX);

/// Montgomery parameters for the field GF(p).
const PARAMS: FixedMontyParams<{ U384::LIMBS }> = FixedMontyParams::new(PRIME);

/// Field element in GF(p), in Montgomery form.
type Fe = FixedMontyForm<{ U384::LIMBS }>;

/// Lift a canonical residue into the field.
fn fe(value: &U384) -> Fe {
    FixedMontyForm::new(value, &PARAMS)
}

/// Field element for the coefficient `a`.
fn fe_a() -> Fe {
    fe(&U384::from_be_hex(A_HEX))
}

/// Field element for the coefficient `b`.
fn fe_b() -> Fe {
    fe(&U384::from_be_hex(B_HEX))
}

/// Field element for the constant three, used in the doubling slope.
fn fe_three() -> Fe {
    let one = fe(&U384::ONE);
    one.add(&one).add(&one)
}

/// A brainpoolP384r1 point in SEC1 uncompressed encoding
/// (`04 || X || Y`), ninety-seven bytes: one tag byte and two
/// forty-eight-byte big-endian coordinates (SEC1 v2 section 2.3.3).
///
/// The only constructor is [`AffinePoint::encode_uncompressed`], so a
/// value of this type is proof of a finite point's canonical encoding
/// rather than a bare byte buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sec1UncompressedPoint([u8; SEC1_UNCOMPRESSED_LEN]);

/// Length of a coordinate in bytes.
const COORD_LEN: usize = 48;
/// Length of a SEC1 uncompressed encoding: tag plus two coordinates.
const SEC1_UNCOMPRESSED_LEN: usize = 1 + COORD_LEN + COORD_LEN;
/// SEC1 point-encoding tag for the uncompressed form.
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

impl Sec1UncompressedPoint {
    /// Borrow the encoded point bytes, to feed the BER encoder. No
    /// `AsRef<[u8]>`: the byte view is named, not a shape a caller can pass
    /// wherever bytes are welcome.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEC1_UNCOMPRESSED_LEN] {
        &self.0
    }
}

/// An affine point on brainpoolP384r1.
///
/// `coords == None` is the point at infinity, the additive identity;
/// `coords == Some((x, y))` is a finite point in canonical coordinates.
///
/// Not `Copy`: a point computed from a private scalar is duplicated only
/// by an explicit `clone`, so the handshake owns every secret-dependent
/// point in a zeroizing wrapper. Zeroizing wipes both coordinates and
/// leaves the point at infinity.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct AffinePoint {
    /// Coordinates, or `None` for the point at infinity.
    pub coords: Option<(U384, U384)>,
}

impl AffinePoint {
    /// The point at infinity.
    pub const INFINITY: Self = Self { coords: None };

    /// The curve generator `G` (RFC 5639 section 3.6).
    #[must_use]
    pub fn generator() -> Self {
        Self {
            coords: Some((U384::from_be_hex(G_X_HEX), U384::from_be_hex(G_Y_HEX))),
        }
    }

    /// `true` when this is the point at infinity. Test-only: the handshake
    /// reads a point's coordinates, never queries this predicate.
    #[cfg(test)]
    #[must_use]
    pub const fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    /// Check the curve equation `y^2 == x^3 + a*x + b (mod p)`.
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        let Some((x_u, y_u)) = self.coords.as_ref() else {
            return true;
        };
        let x = fe(x_u);
        let y = fe(y_u);
        let lhs = y.square();
        let rhs = x.square().mul(&x).add(&fe_a().mul(&x)).add(&fe_b());
        lhs.retrieve() == rhs.retrieve()
    }

    /// Encode this point in SEC1 uncompressed form. `None` for the point
    /// at infinity, which has no finite affine encoding.
    #[must_use]
    pub fn encode_uncompressed(&self) -> Option<Sec1UncompressedPoint> {
        let (x, y) = self.coords?;
        let mut out = [0_u8; SEC1_UNCOMPRESSED_LEN];
        out[0] = SEC1_UNCOMPRESSED_TAG;
        out[1..1 + COORD_LEN].copy_from_slice(&x.to_be_bytes());
        out[1 + COORD_LEN..].copy_from_slice(&y.to_be_bytes());
        Some(Sec1UncompressedPoint(out))
    }

    /// Decode a SEC1 uncompressed encoding. `None` on a wrong tag, a
    /// wrong length, or a point that is not on the curve.
    #[must_use]
    pub fn decode_uncompressed(bytes: &[u8]) -> Option<Self> {
        let arr: &[u8; SEC1_UNCOMPRESSED_LEN] = bytes.try_into().ok()?;
        if *arr.first()? != SEC1_UNCOMPRESSED_TAG {
            return None;
        }
        let x = U384::from_be_slice(arr.get(1..1 + COORD_LEN)?);
        let y = U384::from_be_slice(arr.get(1 + COORD_LEN..)?);
        // A coordinate is a field element, so it must be a canonical
        // residue below the prime. A value at or above p is a non-canonical
        // encoding; refuse it rather than silently reduce it, so a stored
        // coordinate is always the value it appears to be (SEC1 v2 section
        // 2.3.4).
        let prime = PRIME.get_copy();
        if x >= prime || y >= prime {
            return None;
        }
        let point = Self {
            coords: Some((x, y)),
        };
        point.is_on_curve().then_some(point)
    }

    /// Point negation: `-(x, y) = (x, -y mod p)`. Test-only: used by the
    /// curve-law property tests, not by the handshake.
    #[cfg(test)]
    #[must_use]
    pub fn neg(&self) -> Self {
        match &self.coords {
            None => Self::INFINITY,
            Some((x, y)) => {
                let neg_y = fe(y).neg().retrieve();
                Self {
                    coords: Some((*x, neg_y)),
                }
            }
        }
    }

    /// Point doubling by the standard affine formula.
    #[must_use]
    pub fn double(&self) -> Self {
        let Some((x_u, y_u)) = &self.coords else {
            return Self::INFINITY;
        };
        let x = fe(x_u);
        let y = fe(y_u);

        // On a prime-order curve there is no point of order two, so the
        // inverse of 2y always exists for a valid point; the fail-closed
        // branch keeps a degenerate input from producing a wrong point.
        let two_y = y.add(&y);
        let Some(two_y_inv): Option<Fe> = Option::from(two_y.invert()) else {
            return Self::INFINITY;
        };

        let three_x_sq = x.square().mul(&fe_three());
        let lambda = three_x_sq.add(&fe_a()).mul(&two_y_inv);

        let two_x = x.add(&x);
        let x3 = lambda.square().sub(&two_x);
        let y3 = lambda.mul(&x.sub(&x3)).sub(&y);

        Self {
            coords: Some((x3.retrieve(), y3.retrieve())),
        }
    }

    /// Point addition, falling back to doubling when the points are
    /// equal and to infinity when they are inverses.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let Some((x1_u, y1_u)) = &self.coords else {
            return other.clone();
        };
        let Some((x2_u, y2_u)) = &other.coords else {
            return self.clone();
        };

        if x1_u == x2_u {
            if y1_u == y2_u {
                return self.double();
            }
            return Self::INFINITY;
        }

        let x1 = fe(x1_u);
        let y1 = fe(y1_u);
        let x2 = fe(x2_u);
        let y2 = fe(y2_u);

        let Some(dx_inv): Option<Fe> = Option::from(x2.sub(&x1).invert()) else {
            return Self::INFINITY;
        };
        let lambda = y2.sub(&y1).mul(&dx_inv);

        let x3 = lambda.square().sub(&x1).sub(&x2);
        let y3 = lambda.mul(&x1.sub(&x3)).sub(&y1);

        Self {
            coords: Some((x3.retrieve(), y3.retrieve())),
        }
    }

    /// Scalar multiplication by double-and-add. Not constant time; see
    /// the module documentation.
    #[must_use]
    pub fn scalar_mul(&self, scalar: &U384) -> Self {
        let bytes = scalar.to_be_bytes();
        let mut result = Self::INFINITY;
        let mut started = false;
        for &byte in bytes.iter() {
            for bit_index in (0_u32..u8::BITS).rev() {
                if started {
                    result = result.double();
                }
                let bit = (byte >> bit_index) & 1;
                if bit == 1 {
                    if started {
                        result = result.add(self);
                    } else {
                        result = self.clone();
                        started = true;
                    }
                }
            }
        }
        result
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        match (&self.coords, &other.coords) {
            (None, None) => Choice::from(1),
            (None, Some(_)) | (Some(_), None) => Choice::from(0),
            (Some((x1, y1)), Some((x2, y2))) => {
                let xe = x1.to_be_bytes().ct_eq(&x2.to_be_bytes());
                let ye = y1.to_be_bytes().ct_eq(&y2.to_be_bytes());
                xe & ye
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AffinePoint, COORD_LEN, SEC1_UNCOMPRESSED_LEN, n};
    use crypto_bigint::U384;
    use zeroize::Zeroize as _;

    /// High bit of the prime's leading byte: brainpoolP384r1's prime
    /// exceeds two to the three hundred eighty-third power.
    const HIGH_BIT: u8 = 0x80;
    /// Small scalar for the homomorphism test.
    const SCALAR_A: u64 = 0x1234_5678;
    /// Second small scalar for the homomorphism test.
    const SCALAR_B: u64 = 0x0FED_CBA9;
    /// The scalar two, for the doubling equivalence.
    const TWO: u32 = 2;
    /// The scalar three, for the double-plus-one equivalence.
    const THREE: u32 = 3;

    #[test]
    fn generator_is_on_curve() {
        assert!(AffinePoint::generator().is_on_curve());
        assert!(AffinePoint::INFINITY.is_on_curve());
    }

    #[test]
    fn generator_round_trips_through_sec1() {
        let g = AffinePoint::generator();
        let encoded = g.encode_uncompressed().expect("generator encodes");
        assert_eq!(encoded.as_bytes().len(), SEC1_UNCOMPRESSED_LEN);
        assert_eq!(encoded.as_bytes().len(), 1 + COORD_LEN + COORD_LEN);
        let decoded = AffinePoint::decode_uncompressed(encoded.as_bytes())
            .expect("encoded generator decodes");
        assert_eq!(decoded, g);
    }

    #[test]
    fn a_coordinate_at_the_prime_is_rejected() {
        // A coordinate equal to p is a non-canonical field element and must
        // be refused at decode, before the on-curve check could reduce it.
        let prime_bytes = super::PRIME.get_copy().to_be_bytes();
        let mut encoding = [0_u8; SEC1_UNCOMPRESSED_LEN];
        encoding[0] = super::SEC1_UNCOMPRESSED_TAG;
        encoding[1..1 + COORD_LEN].copy_from_slice(&prime_bytes);
        encoding[1 + COORD_LEN..].copy_from_slice(&prime_bytes);
        assert!(AffinePoint::decode_uncompressed(&encoding).is_none());
    }

    #[test]
    fn negation_is_involutive() {
        let g = AffinePoint::generator();
        assert_eq!(g.neg().neg(), g);
        assert!(g.add(&g.neg()).is_infinity());
    }

    #[test]
    fn doubling_matches_addition() {
        let g = AffinePoint::generator();
        let doubled = g.double();
        assert!(doubled.is_on_curve());
        let differs_from_generator = doubled != g;
        assert!(differs_from_generator);
        assert_eq!(g.add(&g), doubled);
    }

    #[test]
    fn scalar_mul_small_values() {
        let g = AffinePoint::generator();
        assert_eq!(g.scalar_mul(&U384::ONE), g);
        assert_eq!(g.scalar_mul(&U384::from(TWO)), g.double());
        assert_eq!(g.scalar_mul(&U384::from(THREE)), g.double().add(&g));
    }

    #[test]
    fn affine_point_zeroize_clears_both_coordinates() {
        let mut point = AffinePoint::generator();
        assert!(point.coords.is_some());
        point.zeroize();
        assert!(point.coords.is_none());
        assert!(point.is_infinity());
    }

    #[test]
    fn prime_leading_byte_has_high_bit_set() {
        assert!(super::PRIME.get_copy().to_be_bytes()[0] >= HIGH_BIT);
    }

    /// The subgroup-order identity: the single strongest property test
    /// for a curve implementation.
    #[test]
    fn generator_times_order_is_infinity() {
        assert!(AffinePoint::generator().scalar_mul(&n()).is_infinity());
    }

    /// The group homomorphism catches additive errors the order test
    /// alone would not.
    #[test]
    fn scalar_mul_is_homomorphic() {
        let g = AffinePoint::generator();
        let a = U384::from(SCALAR_A);
        let b = U384::from(SCALAR_B);
        let sum = a.wrapping_add(&b);
        assert_eq!(g.scalar_mul(&sum), g.scalar_mul(&a).add(&g.scalar_mul(&b)));
    }
}
