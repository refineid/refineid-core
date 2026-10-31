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
//! which only dev-dependencies enable. Every key is derived from an
//! ASCII seed with the verifier's own curve arithmetic
//! ([`crate::ecdsa`]), every signature uses RFC 6979 deterministic
//! nonces, and every byte of structure is assembled from the named
//! tag and field constants below. Nothing here is a real identity.

use crate::ecdsa::signing::SigningKey;
use crate::oid::{Oid, known};
use crate::signed_data::HashAlgorithm;
use crate::x509::{Certificate, DateTime};

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

/// A test ECDSA key derived from an ASCII seed.
#[derive(Debug, Clone)]
pub struct TestKey {
    /// The signing key.
    key: SigningKey,
    /// Which curve it is on.
    curve: TestCurve,
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
            key: SigningKey::derive(curve_oid, hash, seed),
            curve,
        }
    }

    /// The curve the key is on.
    #[must_use]
    pub const fn curve(&self) -> TestCurve {
        self.curve
    }

    /// The hash this key signs with by default.
    #[must_use]
    pub const fn hash(&self) -> HashAlgorithm {
        match self.curve {
            TestCurve::P256 => HashAlgorithm::Sha256,
            TestCurve::P384 => HashAlgorithm::Sha384,
        }
    }

    /// The `SubjectPublicKeyInfo` DER (RFC 5480 sec.2).
    #[must_use]
    pub fn spki(&self) -> Vec<u8> {
        let curve = match self.curve {
            TestCurve::P256 => known::SECP256R1,
            TestCurve::P384 => known::SECP384R1,
        };
        let mut algorithm = tlv(OBJECT_IDENTIFIER, known::EC_PUBLIC_KEY.as_bytes());
        algorithm.extend_from_slice(&tlv(OBJECT_IDENTIFIER, curve.as_bytes()));
        let mut body = tlv(SEQUENCE, algorithm);
        body.extend_from_slice(&bit_string(self.key.public_point().as_bytes()));
        tlv(SEQUENCE, body)
    }

    /// The DER ECDSA signature over `message` under [`Self::hash`].
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_with(self.hash(), message)
    }

    /// The DER ECDSA signature over `message` hashed with `hash`.
    #[must_use]
    pub fn sign_with(&self, hash: HashAlgorithm, message: &[u8]) -> Vec<u8> {
        self.key.sign(hash, message).into_bytes()
    }

    /// The signature algorithm OID of [`Self::sign`].
    #[must_use]
    pub const fn signature_oid(&self) -> Oid<'static> {
        match self.curve {
            TestCurve::P256 => known::ECDSA_WITH_SHA256,
            TestCurve::P384 => known::ECDSA_WITH_SHA384,
        }
    }

    /// The `AlgorithmIdentifier` of [`Self::sign`], parameters absent
    /// (RFC 5758 sec.3.2).
    #[must_use]
    pub fn algorithm_identifier(&self) -> Vec<u8> {
        tlv(
            SEQUENCE,
            tlv(OBJECT_IDENTIFIER, self.signature_oid().as_bytes()),
        )
    }
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
    let mut tbs = tlv(CONTEXT_0, tlv(INTEGER, [X509_VERSION_3]));
    tbs.extend_from_slice(&tlv(INTEGER, [spec.serial]));
    tbs.extend_from_slice(&issuer_key.algorithm_identifier());
    tbs.extend_from_slice(&name(spec.issuer));
    let mut validity = utc_time(spec.not_before);
    validity.extend_from_slice(&utc_time(spec.not_after));
    tbs.extend_from_slice(&tlv(SEQUENCE, validity));
    tbs.extend_from_slice(&name(spec.subject));
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
