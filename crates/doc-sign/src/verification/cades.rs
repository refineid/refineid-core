// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Verifying one CMS `SignedData` in the `CAdES` profile.
//!
//! [`CadesSignature::parse`] reads the structure once through
//! [`refineid_cms`]'s border, selects the signer certificate and
//! gathers the validation material the structure carries;
//! [`CadesSignature::verify`] judges it against the signed content and
//! reports the facts separately: whether the content is the one
//! signed, whether the signature and its certificate binding hold, and
//! which signature timestamps there are, each with the octets its
//! imprint must digest. Timestamp tokens are verified by the caller.
//!
//! # Conformance
//!
//! - RFC 5652: `SignedData` with one `SignerInfo`, and the signature
//!   over the DER `SET OF` signed attributes (sec.5.4). The digest and
//!   signature algorithms, their parameters, the fit of the key to the
//!   scheme and the shape of the signature value are refined by
//!   [`refineid_cms::signed_data`].
//! - `ETSI EN 319 122-1` V1.3.1 clause 5.1: `content-type` is `id-data`
//!   and `message-digest` equals the digest of the signed content.
//! - `ETSI EN 319 122-1` V1.3.1 clause 5.2.2 and RFC 5035: the ESS
//!   `signing-certificate` or `signing-certificate-v2` attribute binds
//!   the signer certificate. `ETSI EN 319 142-2` V1.2.1 clause 4.2.3
//!   c) ignores that reference in the plain CMS profile, so the caller
//!   says whether it is required ([`EssBinding`]).
//! - `ETSI EN 319 122-1` V1.3.1 clause 5.3: each `signature-time-stamp`
//!   token's `messageImprint` is computed over the octets of
//!   `SignerInfo.signature`. No other attribute counts as a signature
//!   timestamp.
//! - `ETSI EN 319 122-1` V1.3.1 clause 5.5.3 and RFC 5126 sec.6.4.1:
//!   `archive-time-stamp-v3` and `archive-time-stamp` (v2) attributes
//!   are counted, not verified.
//! - `ETSI EN 319 122-2` level LT: the validation material travels in
//!   `SignedData.certificates` and `SignedData.crls`, OCSP responses as
//!   `id-ri-ocsp-response` (RFC 5940).

use crate::ber::BerTlvAny;
use crate::cades::DigestAlgorithm;
use crate::cms::{CmsAttribute, CmsError, OwnedSignedData, RevocationInfoChoice, SignedData};
use crate::timestamp::{
    TimestampError, select_signer_certificate, verify_signing_certificate_attribute,
};
use crate::validation::ValidationMaterial;
use refineid_cms::oid::{Oid, known};
use refineid_cms::x509::OwnedCert;

/// Why a structure is not a `CAdES` signature this reader verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CadesReadError {
    /// The bytes are not a CMS `SignedData` with exactly one
    /// `SignerInfo` whose algorithms the CMS border accepts.
    Cms(CmsError),
    /// The `SignerInfo` carries no signed attributes, which
    /// `ETSI EN 319 122-1` clause 5.1 makes mandatory.
    NoSignedAttributes,
    /// No embedded certificate matches the `SignerIdentifier`.
    SignerCertificateMissing,
    /// More than one distinct embedded certificate matches the
    /// `SignerIdentifier`.
    SignerCertificateAmbiguous,
}

impl core::fmt::Display for CadesReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cms(error) => write!(f, "not a supported CMS signature: {error}"),
            Self::NoSignedAttributes => f.write_str("the signer has no signed attributes"),
            Self::SignerCertificateMissing => f.write_str("the signer certificate is not embedded"),
            Self::SignerCertificateAmbiguous => {
                f.write_str("several embedded certificates match the signer")
            }
        }
    }
}

impl core::error::Error for CadesReadError {}

/// The digest of content signed outside the structure, under a named
/// algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigest {
    /// The algorithm the digest was computed under.
    algorithm: DigestAlgorithm,
    /// The digest, the algorithm's length.
    value: Vec<u8>,
}

impl ContentDigest {
    /// The digest of `content` under `algorithm`.
    #[must_use]
    pub fn of(algorithm: DigestAlgorithm, content: &[u8]) -> Self {
        Self {
            algorithm,
            value: algorithm.digest(content),
        }
    }
}

/// Where the signed content is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content<'a> {
    /// `eContent` is inside the structure.
    Attached,
    /// The content is outside the structure; the caller digested it
    /// under [`CadesSignature::digest_algorithm`].
    Detached {
        /// The digest of the external content.
        digest: &'a ContentDigest,
    },
}

/// Whether the ESS signing-certificate attribute must bind the signer
/// certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EssBinding {
    /// `CAdES` and `PAdES` baseline: the attribute must be present and
    /// hash the signer certificate.
    Required,
    /// The plain CMS profile of `ETSI EN 319 142-2` clause 4.2.3 c): the
    /// attribute is not consulted.
    NotRequired,
}

/// One `signature-time-stamp` token and the octets its imprint must
/// digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadesTimestamp {
    /// The RFC 3161 `TimeStampToken`, DER, for the timestamp verifier.
    token: Vec<u8>,
    /// `SignerInfo.signature`.
    imprint_input: Vec<u8>,
}

impl CadesTimestamp {
    /// The RFC 3161 `TimeStampToken`, DER, for the timestamp verifier.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// The octets the token's message imprint must digest: the
    /// `SignerInfo.signature` value (`ETSI EN 319 122-1` clause 5.3).
    #[must_use]
    pub fn imprint_input(&self) -> &[u8] {
        &self.imprint_input
    }
}

/// The facts [`CadesSignature::verify`] establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadesVerdict {
    /// The `message-digest` attribute equals the digest of the content.
    pub document_intact: bool,
    /// The signature verifies over the signed attributes under the
    /// signer key, `content-type` is `id-data`, and, when required, the
    /// ESS attribute binds the signer certificate.
    pub signature_valid: bool,
    /// The `signature-time-stamp` tokens, in encoded order.
    pub signature_timestamps: Vec<CadesTimestamp>,
    /// How many `archive-time-stamp-v3` and `archive-time-stamp` (v2)
    /// tokens are present; they are not verified.
    pub archive_timestamps_present: usize,
}

/// One parsed `CAdES` signature: the structure, its signer certificate
/// and the material it embeds.
#[derive(Debug, Clone)]
pub struct CadesSignature {
    /// The structure, accepted by the CMS border.
    signed_data: OwnedSignedData,
    /// `SignerInfo.digestAlgorithm`.
    digest_algorithm: DigestAlgorithm,
    /// The embedded certificate the `SignerIdentifier` selects.
    signer_certificate: OwnedCert,
    /// Chain certificates and revocation answers from the structure.
    embedded_material: ValidationMaterial,
    /// Whether a `signing-time` signed attribute is present.
    has_signing_time: bool,
}

impl CadesSignature {
    /// Parse `cms` and select its signer certificate.
    ///
    /// # Errors
    /// [`CadesReadError`] when the structure is not a one-signer
    /// `SignedData` the CMS border accepts (SHA-256, SHA-384 or SHA-512
    /// digests only), carries no signed attributes, or does not embed
    /// its signer certificate exactly once.
    pub fn parse(cms: &[u8]) -> Result<Self, CadesReadError> {
        let signed_data = OwnedSignedData::from_der(cms).map_err(CadesReadError::Cms)?;
        let (digest_algorithm, signer_certificate, embedded_material, has_signing_time) = {
            let signed = signed_data.view();
            let signer = signed.signer();
            if signer.signed_attributes_der().is_none() {
                return Err(CadesReadError::NoSignedAttributes);
            }
            let digest_algorithm = DigestAlgorithm::from_cms(signer.digest_algorithm());
            let signer_certificate =
                select_signer_certificate(&signed).map_err(|error| match error {
                    TimestampError::AmbiguousTsaCertificate => {
                        CadesReadError::SignerCertificateAmbiguous
                    }
                    _ => CadesReadError::SignerCertificateMissing,
                })?;
            let material = embedded_material(&signed, signer_certificate.as_der());
            let signing_time = signer
                .signed_attributes()
                .iter()
                .any(|attribute| attribute.oid == known::SIGNING_TIME);
            (digest_algorithm, signer_certificate, material, signing_time)
        };
        Ok(Self {
            signed_data,
            digest_algorithm,
            signer_certificate,
            embedded_material,
            has_signing_time,
        })
    }

    /// `SignerInfo.digestAlgorithm`, under which the content is
    /// digested.
    #[must_use]
    pub const fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    /// The embedded certificate the `SignerIdentifier` selects.
    #[must_use]
    pub const fn signer_certificate(&self) -> &OwnedCert {
        &self.signer_certificate
    }

    /// The validation material the structure carries: the embedded
    /// certificates other than the signer's, the CRLs, and the
    /// `id-ri-ocsp-response` entries of `SignedData.crls`.
    #[must_use]
    pub const fn embedded_material(&self) -> &ValidationMaterial {
        &self.embedded_material
    }

    /// Whether a `signing-time` signed attribute is present.
    #[must_use]
    pub const fn has_signing_time_attribute(&self) -> bool {
        self.has_signing_time
    }

    /// Whether the structure carries its content as `eContent`.
    #[must_use]
    pub fn content_attached(&self) -> bool {
        self.signed_data.view().econtent().is_some()
    }

    /// Judge the signature against `content`.
    #[must_use]
    pub fn verify(&self, content: Content<'_>, ess: EssBinding) -> CadesVerdict {
        let signed = self.signed_data.view();
        let signer = signed.signer();
        let content_digest = match (content, signed.econtent()) {
            (Content::Attached, Some(econtent)) => Some(self.digest_algorithm.digest(econtent)),
            (Content::Detached { digest }, None) => {
                (digest.algorithm == self.digest_algorithm).then(|| digest.value.clone())
            }
            (Content::Attached, None) | (Content::Detached { .. }, Some(_)) => None,
        };
        let document_intact =
            content_digest.is_some_and(|digest| signer.message_digest() == Some(digest.as_slice()));
        let certificate = self.signer_certificate.view();
        let ess_binds = match ess {
            EssBinding::Required => {
                verify_signing_certificate_attribute(&signed, &certificate).is_ok()
            }
            EssBinding::NotRequired => true,
        };
        let signature_valid = signed.econtent_type() == known::DATA
            && ess_binds
            && signed.verify_signer_signature(certificate.spki).is_ok();
        let signature_timestamps = attribute_values(
            signer.unsigned_attributes(),
            known::SIGNATURE_TIME_STAMP_TOKEN,
        )
        .into_iter()
        .map(|token| CadesTimestamp {
            token: token.to_vec(),
            imprint_input: signer.signature().to_vec(),
        })
        .collect();
        let archive_timestamps_present =
            [known::ARCHIVE_TIME_STAMP_V2, known::ARCHIVE_TIME_STAMP_V3]
                .into_iter()
                .map(|oid| attribute_values(signer.unsigned_attributes(), oid).len())
                .sum();
        CadesVerdict {
            document_intact,
            signature_valid,
            signature_timestamps,
            archive_timestamps_present,
        }
    }
}

/// The parseable embedded certificates other than `signer_der`, and
/// the CRLs and OCSP responses of `SignedData.crls`. Other revocation
/// formats are left out.
fn embedded_material(signed: &SignedData<'_>, signer_der: &[u8]) -> ValidationMaterial {
    let mut material = ValidationMaterial::default();
    for der in signed.certificates() {
        if *der != signer_der
            && OwnedCert::from_der(der).is_ok()
            && material
                .certificates
                .iter()
                .all(|seen| seen.as_slice() != *der)
        {
            material.certificates.push(der.to_vec());
        }
    }
    for choice in signed.revocation_info() {
        match *choice {
            RevocationInfoChoice::Crl(der) => material.crls.push(der.to_vec()),
            RevocationInfoChoice::Other { format, info_der } => {
                if format == known::OCSP_RESPONSE_REVOCATION_INFO {
                    material.ocsp_responses.push(info_der.to_vec());
                }
            }
        }
    }
    material
}

/// The complete DER of every value of every attribute of type `oid`.
/// A value set that does not parse to its end counts its unreadable
/// tail as one value, so it is reported as present and fails to
/// verify.
fn attribute_values<'a>(attributes: &[CmsAttribute<'a>], oid: Oid<'_>) -> Vec<&'a [u8]> {
    let mut values = Vec::new();
    for attribute in attributes.iter().filter(|attribute| attribute.oid == oid) {
        let mut rest = attribute.values_der;
        while !rest.is_empty() {
            let Ok(value) = BerTlvAny::parse(rest) else {
                values.push(rest);
                break;
            };
            let (value_der, tail) = rest.split_at(value.size().min(rest.len()));
            values.push(value_der);
            rest = tail;
        }
    }
    values
}
