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

//! Synthetic keys, certificates and CMS structures for tests.
//!
//! Compiled for this crate's tests and behind the `testkit` feature,
//! which only dev-dependencies enable. Every ECDSA key is derived from
//! an ASCII seed with the verifier's own curve arithmetic
//! ([`crate::ecdsa`]) and signs with RFC 6979 deterministic nonces;
//! the one RSA key is the published RFC 9500 test key `testRSA2048`.
//! Every byte of structure is assembled from the named tag and field
//! constants below. Nothing here is a real identity.

use crate::ecdsa::signing::SigningKey;
use crate::oid::{Oid, known};
use crate::rsa::signing::RsaSigningKey;
use crate::signed_data::HashAlgorithm;
use crate::x509::{Certificate, DateTime};
use refineid_ber::{BerTlv, Sequence};

/// Universal BOOLEAN.
pub const BOOLEAN: u8 = 0x01;
/// Universal INTEGER.
pub const INTEGER: u8 = 0x02;
/// Universal BIT STRING.
pub const BIT_STRING: u8 = 0x03;
/// Universal OCTET STRING.
pub const OCTET_STRING: u8 = 0x04;
/// Universal NULL.
pub const NULL: u8 = 0x05;
/// Universal OBJECT IDENTIFIER.
pub const OBJECT_IDENTIFIER: u8 = 0x06;
/// Universal ENUMERATED.
pub const ENUMERATED: u8 = 0x0A;
/// Universal `UTF8String`.
pub const UTF8_STRING: u8 = 0x0C;
/// Universal `PrintableString`.
pub const PRINTABLE_STRING: u8 = 0x13;
/// Universal `UTCTime`.
pub const UTC_TIME: u8 = 0x17;
/// Universal `GeneralizedTime`.
pub const GENERALIZED_TIME: u8 = 0x18;
/// Universal SEQUENCE.
pub const SEQUENCE: u8 = 0x30;
/// Universal SET.
pub const SET: u8 = 0x31;
/// Context-specific primitive `[0]`.
pub const CONTEXT_0_PRIMITIVE: u8 = 0x80;
/// Context-specific constructed `[0]`.
pub const CONTEXT_0: u8 = 0xA0;
/// Context-specific constructed `[1]`.
pub const CONTEXT_1: u8 = 0xA1;
/// Context-specific constructed `[2]`.
pub const CONTEXT_2: u8 = 0xA2;
/// Context-specific constructed `[3]`: TBS `extensions`.
pub const CONTEXT_3: u8 = 0xA3;
/// DER BOOLEAN TRUE (X.690 sec.11.1).
pub const DER_TRUE: u8 = 0xFF;
/// BIT STRING leading octet: no unused bits.
pub const NO_UNUSED_BITS: u8 = 0x00;
/// X.509 `Version` v3, encoded as INTEGER 2 (RFC 5280 sec.4.1).
pub const X509_VERSION_3: u8 = 0x02;
/// `SignerInfo` version 1: issuer and serial (RFC 5652 sec.5.3).
pub const SIGNER_INFO_VERSION: u8 = 0x01;
/// `SignedData` version 3 (RFC 5652 sec.5.1), the version a signer
/// identified by issuer and serial writes for any `eContentType`
/// once `crls` may hold other revocation formats.
pub const SIGNED_DATA_VERSION: u8 = 0x03;
/// Key Usage `keyCertSign` and `cRLSign` (RFC 5280 sec.4.2.1.3):
/// bits 5 and 6 of the first octet.
pub const KEY_USAGE_CA: u8 = 0x06;
/// Unused bits after `cRLSign`, the last named bit set.
pub const KEY_USAGE_CA_UNUSED: u8 = 0x01;
/// Key Usage `keyCertSign` alone (RFC 5280 sec.4.2.1.3): bit 5.
pub const KEY_USAGE_CERT_SIGN: u8 = 0x04;
/// Unused bits after `keyCertSign`.
pub const KEY_USAGE_CERT_SIGN_UNUSED: u8 = 0x02;
/// Key Usage `digitalSignature` (RFC 5280 sec.4.2.1.3): bit 0.
pub const KEY_USAGE_DIGITAL_SIGNATURE: u8 = 0x80;
/// Unused bits after `digitalSignature`.
pub const KEY_USAGE_DIGITAL_SIGNATURE_UNUSED: u8 = 0x07;

/// The top bit of an INTEGER's first content octet, which marks a
/// negative value (X.690 sec.8.3.3).
pub const INTEGER_SIGN_BIT: u8 = 0x80;
/// The octet prepended to a magnitude whose top bit is set, so the
/// INTEGER stays positive.
pub const INTEGER_SIGN_PAD: u8 = 0x00;

/// RFC 9500 sec.2.1, `testRSA2048` in encoded form: the base64 body of
/// the PKCS#1 `RSAPrivateKey` the RFC prints, its armour lines left
/// out. The key is published so that tests need not invent one.
const RFC9500_TEST_RSA_2048: &str = concat!(
    "MIIEowIB", "AAKCAQEA", "sPnoGUOn", "rpiSqt4X", "ynxA+HRP", "7S+BSObI", "6qJ7fQAV", "SPtRkqso",
    "tWxQYLEY", "zNEx5ZSH", "TGypibVs", "JylvCfuT", "oDTfMul8", "b/CZjP2O", "b0LdpYrN", "H6l5hvFE",
    "89FU1nZQ", "F15oVLOp", "UgA7wGiH", "uEVawrGf", "ey92UE68", "mOyUVXGw", "eJIVDdxq", "dMoPvNNU",
    "l86BU02v", "lBiESxOu", "ox+dWmuV", "V7vfYZ79", "Toh/LUK4", "3YvJh+rh", "v4nKuF7i", "HjVjBd9s",
    "B6iDjj70", "HFldzOQ9", "r8SRI+9N", "irupPTkF", "5AKNe6kU", "hKJ1luB7", "S27ZkvB3", "tSTT3P59",
    "3VVJvnzO", "jaA1z6Cz", "+4+eRvcy", "sqhrRgFl", "wI9TEwID", "AQABAoIB", "AEEYiyDP", "29vCzx/+",
    "dS3LqnI5", "BjUuJhXU", "nc6AWX/P", "CgVAO+8A", "+gZRgvct", "7PtZb0sM", "6P9ZcLrw", "eomlGezI",
    "FrL0/6xQ", "aa8bBr/v", "e/a8155O", "gcjFo6fZ", "Ew3Dz7ra", "5fbSiPmu", "4/b/kvrg", "+Br1l77J",
    "aun6uUAs", "1f5B9wW+", "vbR7tzbT", "/mxaUeDi", "BzKpe15G", "wcvbJtdI", "VMa2YErt", "Rjc1/5B2",
    "BGVXyvlJ", "v0SIlcIE", "MsHgnAFO", "p1ZgQ08a", "DzvilLq8", "XVMOahAh", "P1O2A3X8", "hKdXPyrx",
    "IVWE9bS9", "ptTo+eF6", "eNl+d7ht", "pKGEZHUx", "inoQpWEB", "Tv+iOoHs", "VunkEJ3v", "jLP3lyI/",
    "fY0NQ1EC", "gYEA3RBX", "AjgvIys2", "gfU3keIm", "F8e/TprL", "ge1I2vbW", "mV2j6rZC", "g5r/AS0u",
    "pii5CvJ5", "/T5vfJPN", "gPBy8B/y", "RDs+6PJO", "1GmnlhOk", "G9JAIPkv", "0RBZvR0P", "MBtbp6nT",
    "Y3yo1lwa", "mBVBfY6r", "c0sLTzos", "Zh2aGoLz", "rHNMQFMG", "aauORzBF", "pY5lU50C", "gYEAzPHl",
    "u5DI6Xge", "p1vr8QvC", "UuEesCOg", "Jg8Yh1Uq", "VoY/SmQh", "6MYAv1I9", "bLGwrb3W", "W/7kqIoD",
    "fj0aQV5b", "uVZI2loM", "omtU9KY5", "SFIsPV+J", "uUpy7/+V", "E01ZQM5F", "dY8wiYCQ", "iVZYju9X",
    "Wz5LxMNo", "z+gT7pwl", "LCsC4N+R", "8aoBk404", "aF1gum8C", "gYAJ7VTq", "7Zj4TFV7", "Soa/T1eE",
    "k9y8a+kd", "oYk3BASp", "CHJ29M5R", "2KEA7YV9", "wrBklHTz", "8VzSTFTb", "KHEQ5W5c", "sAhoL5Fo",
    "qoHzFFi3", "Qx7MHESQ", "b9qHyolH", "EMNx6Qds", "HUn7rlEn", "aTTyrXh3", "ifQtD6C0", "yTmFXUIS",
    "CW9wKApO", "rnyKJ9nI", "0HcuZQKB", "gQCMtoV6", "e9VGX4AE", "fpuHvAAn", "MYQFgeBi", "YTkBKltQ",
    "XwozhH63", "uMMomUmt", "SG87Sz1T", "mrXadjAh", "y8gsG6I0", "pWaN7QgB", "uFnzQ/HO", "kwTm+qKw",
    "AsrZt4ze", "XNwsH7QX", "HEJCFnCm", "qw9QzEoZ", "TrNtHJHp", "NboBuVnY", "coueZEJr", "P8OnUG3r",
    "UjmopwKB", "gAqB2KYY", "MUqAOvYc", "BnEfLDmy", "Zv9BTVNH", "bR2lKkMY", "qv5LlvDa", "BxVfilE0",
    "2riO4p6B", "aAdvzXjK", "eRrGNEKo", "HNBpOSfY", "COM16NjL", "8hIZB1Ca", "V3WbT5oY", "+jp7Mzd5",
    "7d56RZOE", "+ERK2uz/", "7JX9VSsM", "/LbH9pJi", "bd4e8mik", "DS9ntciq", "OH/3",
);

/// The base64 alphabet (RFC 4648 sec.4).
const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Bits one base64 character carries.
const BASE64_BITS: u32 = 6;
/// The base64 padding character.
const BASE64_PAD: u8 = b'=';
/// Bits in one octet.
const OCTET_BITS: u32 = 8;
/// Position of `n` in `RSAPrivateKey` (RFC 8017 appendix A.1.2),
/// after `version`.
const RSA_PRIVATE_KEY_MODULUS: usize = 1;
/// Position of `publicExponent`.
const RSA_PRIVATE_KEY_PUBLIC_EXPONENT: usize = 2;
/// Position of `privateExponent`.
const RSA_PRIVATE_KEY_PRIVATE_EXPONENT: usize = 3;

/// Divisor for the two-digit `UTCTime` year.
const CENTURY: u16 = 100;
/// The year every fixture instant falls in.
const FIXTURE_YEAR: u16 = 2026;
/// The month every fixture instant falls in.
const FIXTURE_MONTH: u8 = 6;
/// Hour of every fixture instant.
const FIXTURE_HOUR: u8 = 12;

/// Encode one TLV. Fixture values stay far below the DER length
/// bound, so encoding cannot fail.
#[must_use]
pub fn tlv(tag: u8, value: impl AsRef<[u8]>) -> Vec<u8> {
    refineid_ber::tlv(tag, value).expect("fixture TLV encodes")
}

/// Noon on `day` of the fixture month.
///
/// # Panics
/// When `day` is not a day of the fixture month.
#[must_use]
pub fn day(day: u8) -> DateTime {
    DateTime::new(FIXTURE_YEAR, FIXTURE_MONTH, day, FIXTURE_HOUR, 0, 0).expect("fixture day")
}

/// The two curves the verifier accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCurve {
    /// NIST P-256, signing with SHA-256.
    P256,
    /// NIST P-384, signing with SHA-384.
    P384,
}

/// What a [`TestKey`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestKeyKind {
    /// An ECDSA key on this curve.
    Ecdsa(TestCurve),
    /// The RFC 9500 `testRSA2048` key, signing RSASSA-PKCS1-v1_5.
    Rsa,
}

/// The private half of a [`TestKey`].
#[derive(Debug, Clone)]
enum KeyMaterial {
    /// An ECDSA key.
    Ecdsa {
        /// The signing key.
        key: SigningKey,
        /// Which curve it is on.
        curve: TestCurve,
    },
    /// An RSA key.
    Rsa(RsaSigningKey),
}

/// A test signing key: ECDSA derived from an ASCII seed, or the
/// published RFC 9500 RSA key.
#[derive(Debug, Clone)]
pub struct TestKey {
    /// The key.
    material: KeyMaterial,
}

impl TestKey {
    /// The key on `curve` derived from `seed`; the same seed gives the
    /// same key.
    #[must_use]
    pub fn derive(curve: TestCurve, seed: &[u8]) -> Self {
        let curve_oid = match curve {
            TestCurve::P256 => known::SECP256R1,
            TestCurve::P384 => known::SECP384R1,
        };
        let hash = match curve {
            TestCurve::P256 => HashAlgorithm::Sha256,
            TestCurve::P384 => HashAlgorithm::Sha384,
        };
        Self {
            material: KeyMaterial::Ecdsa {
                key: SigningKey::derive(curve_oid, hash, seed),
                curve,
            },
        }
    }

    /// The RFC 9500 sec.2.1 key `testRSA2048`.
    ///
    /// # Panics
    /// Never: the constant is the RFC's key.
    #[must_use]
    pub fn rsa_2048() -> Self {
        let der = base64_decode(RFC9500_TEST_RSA_2048);
        let key = BerTlv::<Sequence>::parse(&der).expect("RSAPrivateKey is a SEQUENCE");
        let integers: Vec<&[u8]> = key
            .iter_children()
            .map(|field| magnitude(field.expect("RSAPrivateKey field").value()))
            .collect();
        let field = |index: usize| *integers.get(index).expect("RSAPrivateKey field present");
        let key = RsaSigningKey::from_parts(
            field(RSA_PRIVATE_KEY_MODULUS),
            field(RSA_PRIVATE_KEY_PUBLIC_EXPONENT),
            field(RSA_PRIVATE_KEY_PRIVATE_EXPONENT),
        )
        .expect("the RFC 9500 key is an RSA key");
        Self {
            material: KeyMaterial::Rsa(key),
        }
    }

    /// What the key is.
    #[must_use]
    pub const fn kind(&self) -> TestKeyKind {
        match &self.material {
            KeyMaterial::Ecdsa { curve, .. } => TestKeyKind::Ecdsa(*curve),
            KeyMaterial::Rsa(_) => TestKeyKind::Rsa,
        }
    }

    /// The hash this key signs with by default: the curve's for
    /// ECDSA, SHA-256 for RSA.
    #[must_use]
    pub const fn hash(&self) -> HashAlgorithm {
        match self.kind() {
            TestKeyKind::Ecdsa(TestCurve::P256) | TestKeyKind::Rsa => HashAlgorithm::Sha256,
            TestKeyKind::Ecdsa(TestCurve::P384) => HashAlgorithm::Sha384,
        }
    }

    /// The `SubjectPublicKeyInfo` DER: `id-ecPublicKey` with a named
    /// curve (RFC 5480 sec.2), or `rsaEncryption` with NULL
    /// parameters (RFC 3279 sec.2.3.1).
    #[must_use]
    pub fn spki(&self) -> Vec<u8> {
        match &self.material {
            KeyMaterial::Ecdsa { key, curve } => {
                let curve = match curve {
                    TestCurve::P256 => known::SECP256R1,
                    TestCurve::P384 => known::SECP384R1,
                };
                let mut algorithm = tlv(OBJECT_IDENTIFIER, known::EC_PUBLIC_KEY.as_bytes());
                algorithm.extend_from_slice(&tlv(OBJECT_IDENTIFIER, curve.as_bytes()));
                let mut body = tlv(SEQUENCE, algorithm);
                body.extend_from_slice(&bit_string(key.public_point().as_bytes()));
                tlv(SEQUENCE, body)
            }
            KeyMaterial::Rsa(key) => {
                let mut algorithm = tlv(OBJECT_IDENTIFIER, known::RSA_ENCRYPTION.as_bytes());
                algorithm.extend_from_slice(&tlv(NULL, []));
                let mut public = positive_integer(key.modulus().as_bytes());
                public.extend_from_slice(&positive_integer(key.exponent().as_bytes()));
                let mut body = tlv(SEQUENCE, algorithm);
                body.extend_from_slice(&bit_string(&tlv(SEQUENCE, public)));
                tlv(SEQUENCE, body)
            }
        }
    }

    /// The signature over `message` under [`Self::hash`]: DER ECDSA,
    /// or RSASSA-PKCS1-v1_5.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_with(self.hash(), message)
    }

    /// The signature over `message` hashed with `hash`: DER ECDSA, or
    /// RSASSA-PKCS1-v1_5.
    #[must_use]
    pub fn sign_with(&self, hash: HashAlgorithm, message: &[u8]) -> Vec<u8> {
        match &self.material {
            KeyMaterial::Ecdsa { key, .. } => key.sign(hash, message).into_bytes(),
            KeyMaterial::Rsa(key) => key.sign_pkcs1v15(hash, message),
        }
    }

    /// The signature over `message` under [`Self::hash`] in the form
    /// a card returns it: the fixed-width `r || s` for ECDSA, the
    /// PKCS#1 value for RSA.
    #[must_use]
    pub fn sign_raw(&self, message: &[u8]) -> Vec<u8> {
        match &self.material {
            KeyMaterial::Ecdsa { key, .. } => key.sign_raw(self.hash(), message),
            KeyMaterial::Rsa(key) => key.sign_pkcs1v15(self.hash(), message),
        }
    }

    /// The RSASSA-PSS signature over `message` with SHA-256, MGF1
    /// with SHA-256 and the 32-octet `salt` (RFC 8017 sec.8.1);
    /// `None` for an ECDSA key.
    #[must_use]
    pub fn sign_pss_sha256(&self, message: &[u8], salt: &[u8; PSS_SALT_LEN]) -> Option<Vec<u8>> {
        match &self.material {
            KeyMaterial::Ecdsa { .. } => None,
            KeyMaterial::Rsa(key) => Some(key.sign_pss_sha256(message, salt)),
        }
    }

    /// The signature algorithm OID of [`Self::sign`].
    #[must_use]
    pub const fn signature_oid(&self) -> Oid<'static> {
        match self.kind() {
            TestKeyKind::Ecdsa(TestCurve::P256) => known::ECDSA_WITH_SHA256,
            TestKeyKind::Ecdsa(TestCurve::P384) => known::ECDSA_WITH_SHA384,
            TestKeyKind::Rsa => known::SHA256_WITH_RSA,
        }
    }

    /// The `AlgorithmIdentifier` of [`Self::sign`]: parameters absent
    /// for ECDSA (RFC 5758 sec.3.2), NULL for RSA (RFC 4055 sec.5).
    #[must_use]
    pub fn algorithm_identifier(&self) -> Vec<u8> {
        let mut body = tlv(OBJECT_IDENTIFIER, self.signature_oid().as_bytes());
        if self.kind() == TestKeyKind::Rsa {
            body.extend_from_slice(&tlv(NULL, []));
        }
        tlv(SEQUENCE, body)
    }
}

/// Salt length of the RSA-PSS profile [`TestKey::sign_pss_sha256`]
/// signs: the SHA-256 output length.
pub const PSS_SALT_LEN: usize = refineid_digest::SHA256_LEN;

/// `text` decoded from base64 (RFC 4648 sec.4) without padding
/// checks: fixture text only.
fn base64_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for character in text
        .bytes()
        .take_while(|character| *character != BASE64_PAD)
    {
        let value = BASE64_ALPHABET
            .iter()
            .position(|symbol| *symbol == character)
            .and_then(|position| u32::try_from(position).ok())
            .expect("fixture text is base64");
        accumulator = (accumulator << BASE64_BITS) | value;
        bits += BASE64_BITS;
        if bits >= OCTET_BITS {
            bits -= OCTET_BITS;
            out.extend(u8::try_from((accumulator >> bits) & u32::from(u8::MAX)));
        }
    }
    out
}

/// An INTEGER's content octets without the sign pad.
fn magnitude(value: &[u8]) -> &[u8] {
    match value {
        [INTEGER_SIGN_PAD, rest @ ..] if !rest.is_empty() => rest,
        _ => value,
    }
}

/// The DER INTEGER of the non-negative `magnitude`, sign-padded when
/// its top bit is set.
#[must_use]
pub fn positive_integer(magnitude: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(magnitude.len().saturating_add(1));
    if magnitude
        .first()
        .is_some_and(|first| first & INTEGER_SIGN_BIT != 0)
    {
        value.push(INTEGER_SIGN_PAD);
    }
    value.extend_from_slice(magnitude);
    tlv(INTEGER, value)
}

/// A SHA-2 `AlgorithmIdentifier` with absent parameters (RFC 5754
/// sec.2).
#[must_use]
pub fn digest_algorithm_identifier(hash: HashAlgorithm) -> Vec<u8> {
    tlv(SEQUENCE, tlv(OBJECT_IDENTIFIER, hash.oid().as_bytes()))
}

/// A BIT STRING with no unused bits around `bits`.
#[must_use]
pub fn bit_string(bits: &[u8]) -> Vec<u8> {
    let mut body = vec![NO_UNUSED_BITS];
    body.extend_from_slice(bits);
    tlv(BIT_STRING, body)
}

/// A `Name` holding one common name.
#[must_use]
pub fn name(common_name: &str) -> Vec<u8> {
    let mut attribute = tlv(OBJECT_IDENTIFIER, known::COMMON_NAME.as_bytes());
    attribute.extend_from_slice(&tlv(UTF8_STRING, common_name.as_bytes()));
    tlv(SEQUENCE, tlv(SET, tlv(SEQUENCE, attribute)))
}

/// A `Name` holding one relative distinguished name per entry of
/// `attributes`, each an attribute type, its string tag and its value.
#[must_use]
pub fn name_of(attributes: &[(Oid<'_>, u8, &str)]) -> Vec<u8> {
    let mut rdns = Vec::new();
    for (oid, tag, value) in attributes {
        let mut attribute = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
        attribute.extend_from_slice(&tlv(*tag, value.as_bytes()));
        rdns.extend_from_slice(&tlv(SET, tlv(SEQUENCE, attribute)));
    }
    tlv(SEQUENCE, rdns)
}

/// A `UTCTime` TLV (RFC 5280 sec.4.1.2.5.1).
#[must_use]
pub fn utc_time(time: DateTime) -> Vec<u8> {
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        time.year() % CENTURY,
        time.month(),
        time.day(),
        time.hour(),
        time.minutes(),
        time.seconds()
    );
    tlv(UTC_TIME, text.as_bytes())
}

/// A `GeneralizedTime` TLV (RFC 5280 sec.4.1.2.5.2).
#[must_use]
pub fn generalized_time(time: DateTime) -> Vec<u8> {
    let text = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minutes(),
        time.seconds()
    );
    tlv(GENERALIZED_TIME, text.as_bytes())
}

/// One `Extension`.
#[must_use]
pub fn extension(oid: Oid<'_>, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut body = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
    if critical {
        body.extend_from_slice(&tlv(BOOLEAN, [DER_TRUE]));
    }
    body.extend_from_slice(&tlv(OCTET_STRING, value));
    tlv(SEQUENCE, body)
}

/// Critical basic constraints asserting `cA`.
#[must_use]
pub fn ca_basic_constraints() -> Vec<u8> {
    extension(
        known::BASIC_CONSTRAINTS,
        true,
        &tlv(SEQUENCE, tlv(BOOLEAN, [DER_TRUE])),
    )
}

/// A critical Key Usage whose named-bit octet is `bits` with `unused`
/// trailing bits.
#[must_use]
pub fn key_usage(unused: u8, bits: u8) -> Vec<u8> {
    extension(known::KEY_USAGE, true, &tlv(BIT_STRING, [unused, bits]))
}

/// The extensions of a CA: critical basic constraints `cA`, and
/// critical Key Usage `keyCertSign` + `cRLSign`.
#[must_use]
pub fn ca_extensions() -> Vec<Vec<u8>> {
    vec![
        ca_basic_constraints(),
        key_usage(KEY_USAGE_CA_UNUSED, KEY_USAGE_CA),
    ]
}

/// A critical Extended Key Usage holding `purpose` alone.
#[must_use]
pub fn extended_key_usage(purpose: Oid<'_>) -> Vec<u8> {
    extension(
        known::EXT_KEY_USAGE,
        true,
        &tlv(SEQUENCE, tlv(OBJECT_IDENTIFIER, purpose.as_bytes())),
    )
}

/// The extensions of a TSA: critical EKU `id-kp-timeStamping` alone
/// (RFC 3161 sec.2.3).
#[must_use]
pub fn timestamping_extensions() -> Vec<Vec<u8>> {
    vec![extended_key_usage(known::KP_TIME_STAMPING)]
}

/// What one certificate says about itself.
#[derive(Debug, Clone)]
pub struct CertificateSpec<'a> {
    /// Serial number, with the top bit clear so the one-octet INTEGER
    /// stays positive.
    pub serial: u8,
    /// Subject common name.
    pub subject: &'a str,
    /// Issuer common name.
    pub issuer: &'a str,
    /// Start of validity.
    pub not_before: DateTime,
    /// End of validity.
    pub not_after: DateTime,
    /// Complete `Extension` encodings; none for an end entity
    /// without extensions.
    pub extensions: Vec<Vec<u8>>,
}

/// The `TBSCertificate` of `spec` for `subject_key`, its `signature`
/// field naming `issuer_key`'s algorithm.
#[must_use]
pub fn tbs_certificate(
    spec: &CertificateSpec<'_>,
    subject_key: &TestKey,
    issuer_key: &TestKey,
) -> Vec<u8> {
    tbs_certificate_named(spec, &name(spec.subject), subject_key, issuer_key)
}

/// As [`tbs_certificate`], with the complete subject `Name` DER in
/// place of `spec.subject`.
#[must_use]
pub fn tbs_certificate_named(
    spec: &CertificateSpec<'_>,
    subject: &[u8],
    subject_key: &TestKey,
    issuer_key: &TestKey,
) -> Vec<u8> {
    let mut tbs = tlv(CONTEXT_0, tlv(INTEGER, [X509_VERSION_3]));
    tbs.extend_from_slice(&tlv(INTEGER, [spec.serial]));
    tbs.extend_from_slice(&issuer_key.algorithm_identifier());
    tbs.extend_from_slice(&name(spec.issuer));
    let mut validity = utc_time(spec.not_before);
    validity.extend_from_slice(&utc_time(spec.not_after));
    tbs.extend_from_slice(&tlv(SEQUENCE, validity));
    tbs.extend_from_slice(subject);
    tbs.extend_from_slice(&subject_key.spki());
    if !spec.extensions.is_empty() {
        tbs.extend_from_slice(&tlv(CONTEXT_3, tlv(SEQUENCE, spec.extensions.concat())));
    }
    tlv(SEQUENCE, tbs)
}

/// A certificate for `subject_key`, signed by `issuer_key`.
#[must_use]
pub fn certificate(
    spec: &CertificateSpec<'_>,
    subject_key: &TestKey,
    issuer_key: &TestKey,
) -> Vec<u8> {
    signed(&tbs_certificate(spec, subject_key, issuer_key), issuer_key)
}

/// A certificate for `subject_key` whose subject is the `Name` DER
/// `subject`, signed by `issuer_key`.
#[must_use]
pub fn certificate_named(
    spec: &CertificateSpec<'_>,
    subject: &[u8],
    subject_key: &TestKey,
    issuer_key: &TestKey,
) -> Vec<u8> {
    signed(
        &tbs_certificate_named(spec, subject, subject_key, issuer_key),
        issuer_key,
    )
}

/// `SEQUENCE { tbs, signatureAlgorithm, signature }`, the shape of a
/// certificate, a CRL and a `BasicOCSPResponse` without certs.
#[must_use]
pub fn signed(tbs: &[u8], key: &TestKey) -> Vec<u8> {
    tlv(SEQUENCE, signed_body(tbs, key))
}

/// The contents of [`signed`].
#[must_use]
pub fn signed_body(tbs: &[u8], key: &TestKey) -> Vec<u8> {
    let mut body = tbs.to_vec();
    body.extend_from_slice(&key.algorithm_identifier());
    body.extend_from_slice(&bit_string(&key.sign(tbs)));
    body
}

/// One `Attribute` with one already-encoded value.
#[must_use]
pub fn attribute(oid: Oid<'_>, value: &[u8]) -> Vec<u8> {
    let mut body = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
    body.extend_from_slice(&tlv(SET, value));
    tlv(SEQUENCE, body)
}

/// The DER `SET OF Attribute` that is signed, in DER set order.
#[must_use]
pub fn attribute_set(attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = attributes.to_vec();
    sorted.sort_unstable();
    tlv(SET, sorted.concat())
}

/// The `contentType` and `messageDigest` attributes binding `content`
/// of type `content_type` under `hash`.
#[must_use]
pub fn content_attributes(
    content_type: Oid<'_>,
    hash: HashAlgorithm,
    content: &[u8],
) -> Vec<Vec<u8>> {
    vec![
        attribute(
            known::CONTENT_TYPE,
            &tlv(OBJECT_IDENTIFIER, content_type.as_bytes()),
        ),
        attribute(
            known::MESSAGE_DIGEST,
            &tlv(OCTET_STRING, hash.digest(content)),
        ),
    ]
}

/// The parts of a hand-assembled `SignedData` with one `SignerInfo`.
#[derive(Debug, Clone)]
pub struct CmsParts<'a> {
    /// `eContentType`.
    pub econtent_type: Oid<'a>,
    /// `eContent`, when attached.
    pub econtent: Option<Vec<u8>>,
    /// `digestAlgorithm` `AlgorithmIdentifier`, used in the
    /// `SignedData` set and the `SignerInfo`.
    pub digest_algorithm: Vec<u8>,
    /// Signed attributes in their signed `SET` form; `None` signs the
    /// attached content directly.
    pub signed_attributes: Option<Vec<u8>>,
    /// The signing key.
    pub key: &'a TestKey,
    /// The signer certificate.
    pub signer: &'a [u8],
    /// `SignedData.certificates`.
    pub certificates: Vec<Vec<u8>>,
    /// Encoded `RevocationInfoChoice` entries of `SignedData.crls`.
    pub revocation_info: Vec<Vec<u8>>,
    /// Encoded unsigned `Attribute`s.
    pub unsigned_attributes: Vec<Vec<u8>>,
    /// `signatureAlgorithm`; `None` takes the key's own.
    pub signature_algorithm: Option<Vec<u8>>,
    /// The signature value; `None` signs with the key under the
    /// key's hash.
    pub signature: Option<Vec<u8>>,
}

impl<'a> CmsParts<'a> {
    /// An attached `id-data` signature over `content` by `key` with the
    /// certificate `signer`, its hash the key's, carrying the
    /// `contentType` and `messageDigest` attributes and the signer
    /// certificate.
    #[must_use]
    pub fn attached(key: &'a TestKey, signer: &'a [u8], content: &[u8]) -> Self {
        let mut parts = Self::detached(key, signer, content);
        parts.econtent = Some(content.to_vec());
        parts
    }

    /// As [`Self::attached`], with the content left out.
    #[must_use]
    pub fn detached(key: &'a TestKey, signer: &'a [u8], content: &[u8]) -> Self {
        Self {
            econtent_type: known::DATA,
            econtent: None,
            digest_algorithm: digest_algorithm_identifier(key.hash()),
            signed_attributes: Some(attribute_set(&content_attributes(
                known::DATA,
                key.hash(),
                content,
            ))),
            key,
            signer,
            certificates: vec![signer.to_vec()],
            revocation_info: Vec::new(),
            unsigned_attributes: Vec::new(),
            signature_algorithm: None,
            signature: None,
        }
    }
}

/// A `ContentInfo`-wrapped `SignedData` assembled from `parts`.
///
/// # Panics
/// When `parts.signer` is not a certificate.
#[must_use]
pub fn cms(parts: &CmsParts<'_>) -> Vec<u8> {
    let signer = Certificate::from_der(parts.signer).expect("signer parses");
    let mut sid = signer.issuer.as_der().to_vec();
    sid.extend_from_slice(&tlv(INTEGER, signer.serial_der));
    let covered = parts
        .signed_attributes
        .clone()
        .or_else(|| parts.econtent.clone())
        .unwrap_or_default();
    let signature = parts
        .signature
        .clone()
        .unwrap_or_else(|| parts.key.sign(&covered));
    let mut signer_info = tlv(INTEGER, [SIGNER_INFO_VERSION]);
    signer_info.extend_from_slice(&tlv(SEQUENCE, sid));
    signer_info.extend_from_slice(&parts.digest_algorithm);
    if let Some(attributes) = &parts.signed_attributes {
        let mut tagged = attributes.clone();
        if let Some(first) = tagged.first_mut() {
            *first = CONTEXT_0;
        }
        signer_info.extend_from_slice(&tagged);
    }
    signer_info.extend_from_slice(
        &parts
            .signature_algorithm
            .clone()
            .unwrap_or_else(|| parts.key.algorithm_identifier()),
    );
    signer_info.extend_from_slice(&tlv(OCTET_STRING, signature));
    if !parts.unsigned_attributes.is_empty() {
        signer_info.extend_from_slice(&tlv(CONTEXT_1, parts.unsigned_attributes.concat()));
    }

    let mut encapsulated = tlv(OBJECT_IDENTIFIER, parts.econtent_type.as_bytes());
    if let Some(econtent) = &parts.econtent {
        encapsulated.extend_from_slice(&tlv(CONTEXT_0, tlv(OCTET_STRING, econtent)));
    }
    let mut body = tlv(INTEGER, [SIGNED_DATA_VERSION]);
    body.extend_from_slice(&tlv(SET, &parts.digest_algorithm));
    body.extend_from_slice(&tlv(SEQUENCE, encapsulated));
    if !parts.certificates.is_empty() {
        body.extend_from_slice(&tlv(CONTEXT_0, parts.certificates.concat()));
    }
    if !parts.revocation_info.is_empty() {
        body.extend_from_slice(&tlv(CONTEXT_1, parts.revocation_info.concat()));
    }
    body.extend_from_slice(&tlv(SET, tlv(SEQUENCE, signer_info)));
    let mut content_info = tlv(OBJECT_IDENTIFIER, known::SIGNED_DATA.as_bytes());
    content_info.extend_from_slice(&tlv(CONTEXT_0, tlv(SEQUENCE, body)));
    tlv(SEQUENCE, content_info)
}
