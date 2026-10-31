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
//! - `ETSI EN 319 122-1` V1.3.1 clauses 5.5.2 and 5.5.3: each
//!   `archive-time-stamp-v3` attribute holds exactly one value, and its
//!   token carries one `ats-hash-index-v3`
//!   unsigned attribute; every hash it lists must be the hash, under
//!   its `hashIndAlgorithm`, of a certificate, a revocation value or an
//!   unsigned attribute value present in the signature, and the token's
//!   imprint is computed over the `eContentType`, the hash of the
//!   signed data, the `SignerInfo` fields `version` through `signature`
//!   and the index, in that order. The token is verified by the caller.
//! - RFC 5126 sec.6.4.1: `archive-time-stamp` (v2) attributes are
//!   counted, not verified.
//! - `ETSI EN 319 122-2` level LT: the validation material travels in
//!   `SignedData.certificates` and `SignedData.crls`, OCSP responses as
//!   `id-ri-ocsp-response` (RFC 5940).

use crate::ber::{BerTlv, BerTlvAny, BerTlvIter, OctetString, Oid as OidTag, Sequence};
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

/// Where the signed content is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content<'a> {
    /// `eContent` is inside the structure.
    Attached,
    /// The content is outside the structure: the octets the signature
    /// claims to cover.
    Detached {
        /// The external content.
        content: &'a [u8],
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

/// What an `archive-time-stamp-v3` token must imprint (`ETSI EN 319
/// 122-1` clause 5.5.3): the `eContentType`, the hash of the signed
/// data, the `SignerInfo` fields `version` through `signature` and the
/// token's `ATSHashIndexV3`, each as encoded, in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveImprint {
    /// `hashIndAlgorithm`, which must also be the token's imprint
    /// algorithm (clause 5.5.2).
    algorithm: DigestAlgorithm,
    /// The octets the imprint digests.
    input: Vec<u8>,
}

impl ArchiveImprint {
    /// The digest the token's `messageImprint` must equal when it names
    /// `algorithm`; `None` for an algorithm other than the index's
    /// `hashIndAlgorithm`, which no token may imprint under.
    #[must_use]
    pub fn digest(&self, algorithm: DigestAlgorithm) -> Option<Vec<u8>> {
        (algorithm == self.algorithm).then(|| algorithm.digest(&self.input))
    }
}

/// One `archive-time-stamp-v3` token whose `ats-hash-index-v3` names
/// only values the signature carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveTimestampV3 {
    /// The RFC 3161 `TimeStampToken`, DER, for the timestamp verifier.
    token: Vec<u8>,
    /// What its imprint must digest.
    imprint: ArchiveImprint,
}

impl ArchiveTimestampV3 {
    /// The RFC 3161 `TimeStampToken`, DER, for the timestamp verifier.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// What the token's message imprint must digest.
    #[must_use]
    pub const fn imprint(&self) -> &ArchiveImprint {
        &self.imprint
    }
}

/// One archive timestamp attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CadesArchiveTimestamp {
    /// One `archive-time-stamp-v3` attribute: its token ready to
    /// verify, or the reason it cannot be valid: the attribute holds
    /// more than one value, or the token's `ats-hash-index-v3` is
    /// absent, repeated or malformed ([`TimestampError::Malformed`]), or names a value
    /// the signature does not carry ([`TimestampError::ImprintMismatch`]).
    V3(Result<ArchiveTimestampV3, TimestampError>),
    /// An `archive-time-stamp` (v2, RFC 5126 sec.6.4.1), counted and not
    /// verified.
    V2,
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
    /// The `archive-time-stamp-v3` and `archive-time-stamp` (v2)
    /// tokens, in encoded order.
    pub archive_timestamps: Vec<CadesArchiveTimestamp>,
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
        let certificate = self.signer_certificate.view();
        let judged = signed.judge(
            certificate.spki,
            match content {
                Content::Attached => None,
                Content::Detached { content } => Some(content),
            },
        );
        let ess_binds = match ess {
            EssBinding::Required => {
                verify_signing_certificate_attribute(&signed, &certificate).is_ok()
            }
            EssBinding::NotRequired => true,
        };
        let document_intact = judged.content_intact;
        let signature_valid =
            signed.econtent_type() == known::DATA && ess_binds && judged.signature.is_ok();
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
        let signed_content = match content {
            Content::Attached => signed.econtent().unwrap_or_default(),
            Content::Detached { content } => content,
        };
        let mut archive_timestamps = Vec::new();
        for attribute in signer.unsigned_attributes() {
            let v3 = attribute.oid == known::ARCHIVE_TIME_STAMP_V3;
            if !v3 && attribute.oid != known::ARCHIVE_TIME_STAMP_V2 {
                continue;
            }
            let values = split_values(attribute.values_der);
            if !v3 {
                archive_timestamps.extend(values.iter().map(|_| CadesArchiveTimestamp::V2));
                continue;
            }
            archive_timestamps.push(CadesArchiveTimestamp::V3(match values.as_slice() {
                [token] => archive_timestamp_v3(&signed, signed_content, token),
                _ => Err(MALFORMED_ARCHIVE_ATTRIBUTE),
            }));
        }
        CadesVerdict {
            document_intact,
            signature_valid,
            signature_timestamps,
            archive_timestamps,
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
            RevocationInfoChoice::OcspResponse(der) => material.ocsp_responses.push(der.to_vec()),
            RevocationInfoChoice::Other { .. } => {}
        }
    }
    material
}

/// The complete DER of every value of every attribute of type `oid`.
fn attribute_values<'a>(attributes: &[CmsAttribute<'a>], oid: Oid<'_>) -> Vec<&'a [u8]> {
    attributes
        .iter()
        .filter(|attribute| attribute.oid == oid)
        .flat_map(|attribute| split_values(attribute.values_der))
        .collect()
}

/// The complete DER of every value in the contents of one attribute's
/// `SET OF AttributeValue`. A value whose TLV does not parse, or
/// declares more octets than remain, makes the whole unread tail one
/// value, so it is reported as present and fails to verify; no value
/// is ever cut short.
fn split_values(values_der: &[u8]) -> Vec<&[u8]> {
    let mut values = Vec::new();
    let mut rest = values_der;
    while !rest.is_empty() {
        let Some((value_der, tail)) = BerTlvAny::parse(rest)
            .ok()
            .and_then(|value| rest.split_at_checked(value.size()))
        else {
            values.push(rest);
            break;
        };
        values.push(value_der);
        rest = tail;
    }
    values
}

/// Why an `archive-time-stamp-v3` attribute holding other than exactly
/// one value is refused (`ETSI EN 319 122-1` clause 5.5.3).
const MALFORMED_ARCHIVE_ATTRIBUTE: TimestampError =
    TimestampError::Malformed("archive-time-stamp-v3 holds more than one value");

/// Why an `ats-hash-index-v3` does not read.
const MALFORMED_HASH_INDEX: TimestampError = TimestampError::Malformed("ats-hash-index-v3");

/// The `archive-time-stamp-v3` value `token` of the signature `signed`
/// over `signed_content`, with what its imprint must digest, once its
/// `ats-hash-index-v3` is validated (`ETSI EN 319 122-1` clause 5.5.2):
/// the token carries exactly one such attribute with exactly one
/// value, an `ATSHashIndexV3` under a digest this crate computes, and
/// every hash it lists matches a `CertificateChoices` of
/// `SignedData.certificates`, a `RevocationInfoChoice` of
/// `SignedData.crls`, or an `attrType` followed by one of its values
/// among the signer's unsigned attributes.
fn archive_timestamp_v3(
    signed: &SignedData<'_>,
    signed_content: &[u8],
    token: &[u8],
) -> Result<ArchiveTimestampV3, TimestampError> {
    let token_data = SignedData::parse(token)
        .map_err(|_ignored| TimestampError::Malformed("token is not CMS SignedData"))?;
    let indexes = attribute_values(
        token_data.signer().unsigned_attributes(),
        known::ATS_HASH_INDEX_V3,
    );
    let [index_der] = indexes.as_slice() else {
        return Err(MALFORMED_HASH_INDEX);
    };
    let index = HashIndex::parse(index_der).ok_or(MALFORMED_HASH_INDEX)?;
    let algorithm = index.algorithm;
    let signer = signed.signer();
    let certificates: Vec<Vec<u8>> = signed
        .certificates()
        .iter()
        .map(|der| algorithm.digest(der))
        .collect();
    let revocation: Vec<Vec<u8>> = signed
        .revocation_info_der()
        .iter()
        .map(|der| algorithm.digest(der))
        .collect();
    let attributes: Vec<Vec<u8>> = signer
        .unsigned_attributes()
        .iter()
        .flat_map(|attribute| {
            split_values(attribute.values_der)
                .into_iter()
                .map(move |value| algorithm.digest(&[attribute.type_der, value].concat()))
        })
        .collect();
    let certificates_present = all_present(&index.certificates, &certificates);
    let revocation_present = all_present(&index.revocation, &revocation);
    let attributes_present = all_present(&index.unsigned_attributes, &attributes);
    if !(certificates_present && revocation_present && attributes_present) {
        return Err(TimestampError::ImprintMismatch);
    }
    let mut input = signed.econtent_type_der().to_vec();
    input.extend_from_slice(&algorithm.digest(signed_content));
    input.extend_from_slice(signer.archive_fields_der());
    input.extend_from_slice(index_der);
    Ok(ArchiveTimestampV3 {
        token: token.to_vec(),
        imprint: ArchiveImprint { algorithm, input },
    })
}

/// Whether every hash in `listed` is one of `candidates`.
fn all_present(listed: &[&[u8]], candidates: &[Vec<u8>]) -> bool {
    listed.iter().all(|hash| {
        candidates
            .iter()
            .any(|candidate| candidate.as_slice() == *hash)
    })
}

/// One `ATSHashIndexV3` (`ETSI EN 319 122-1` clause 5.5.2), its hash
/// lists borrowed from the encoding.
struct HashIndex<'a> {
    /// `hashIndAlgorithm`.
    algorithm: DigestAlgorithm,
    /// `certificatesHashIndex`.
    certificates: Vec<&'a [u8]>,
    /// `crlsHashIndex`.
    revocation: Vec<&'a [u8]>,
    /// `unsignedAttrValuesHashIndex`.
    unsigned_attributes: Vec<&'a [u8]>,
}

impl<'a> HashIndex<'a> {
    /// Read `der` as exactly one `ATSHashIndexV3`: an
    /// `AlgorithmIdentifier` naming SHA-256, SHA-384 or SHA-512, then
    /// three `SEQUENCE OF OCTET STRING`, each hash the algorithm's
    /// length. `None` for anything else.
    fn parse(der: &'a [u8]) -> Option<Self> {
        let outer = BerTlv::<Sequence>::parse(der).ok()?;
        if outer.size() != der.len() {
            return None;
        }
        let mut fields = outer.iter_children();
        let algorithm_identifier = fields.next()?.ok()?.expect::<Sequence>().ok()?;
        let oid = algorithm_identifier
            .iter_children()
            .next()?
            .ok()?
            .expect::<OidTag>()
            .ok()?;
        let algorithm = DigestAlgorithm::from_oid(Oid::new(oid.value()).ok()?)?;
        let mut list = || -> Option<Vec<&'a [u8]>> {
            let list = fields.next()?.ok()?.expect::<Sequence>().ok()?;
            BerTlvIter::new(list.value())
                .map(|hash| {
                    let hash = hash.ok()?.expect::<OctetString>().ok()?.value();
                    (hash.len() == algorithm.digest_len()).then_some(hash)
                })
                .collect()
        };
        let certificates = list()?;
        let revocation = list()?;
        let unsigned_attributes = list()?;
        if fields.next().is_some() {
            return None;
        }
        Some(Self {
            algorithm,
            certificates,
            revocation,
            unsigned_attributes,
        })
    }
}
