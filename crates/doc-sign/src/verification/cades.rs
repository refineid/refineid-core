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

use std::collections::{HashMap, HashSet};

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
/// 122-1` clause 5.5.3), in its four parts, concatenated in this order
/// only when hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveImprint {
    /// `hashIndAlgorithm`, which must also be the token's imprint
    /// algorithm (clause 5.5.2).
    algorithm: DigestAlgorithm,
    /// Item 1: the `eContentType` TLV as encoded.
    content_type: Vec<u8>,
    /// Item 2: the hash of the signed data under `algorithm`.
    content_hash: Vec<u8>,
    /// Item 3: the `SignerInfo` fields `version` through `signature`,
    /// as encoded.
    signer_fields: Vec<u8>,
    /// Item 4: the `ATSHashIndexV3` as encoded.
    index: Vec<u8>,
}

impl ArchiveImprint {
    /// The digest the token's `messageImprint` must equal when it names
    /// `algorithm`; `None` for an algorithm other than the index's
    /// `hashIndAlgorithm`, which no token may imprint under.
    #[must_use]
    pub fn digest(&self, algorithm: DigestAlgorithm) -> Option<Vec<u8>> {
        (algorithm == self.algorithm).then(|| {
            algorithm.digest(
                &[
                    self.content_type.as_slice(),
                    &self.content_hash,
                    &self.signer_fields,
                    &self.index,
                ]
                .concat(),
            )
        })
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
    /// The validation material the index lists: the certificates other
    /// than the signer's and the revocation values of the signature
    /// whose hashes it carries. Only this material is protected by the
    /// token (clause 5.5.2).
    covered: ValidationMaterial,
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

    /// The certificates and revocation values the token's index lists:
    /// the material whose existence at the token's time it proves.
    #[must_use]
    pub const fn covered(&self) -> &ValidationMaterial {
        &self.covered
    }
}

/// One archive timestamp attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CadesArchiveTimestamp {
    /// One `archive-time-stamp-v3` attribute: its token ready to
    /// verify, or the reason it cannot be valid: the attribute holds
    /// more than one value, or the token's `ats-hash-index-v3` is
    /// absent, repeated or malformed, or the signature carries no
    /// content to hash ([`TimestampError::Malformed`]), or the index
    /// names a value the signature does not carry
    /// ([`TimestampError::ImprintMismatch`]).
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
            Content::Attached => signed.econtent(),
            Content::Detached { content } => Some(content),
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
                [] => Err(TimestampError::Malformed(
                    "archive-time-stamp-v3 holds no value",
                )),
                [token] => archive_timestamp_v3(
                    &signed,
                    signed_content,
                    self.signer_certificate.as_der(),
                    token,
                ),
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
        match choice.choice() {
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
/// is ever cut short. Every step consumes at least one octet, so the
/// walk ends.
fn split_values(values_der: &[u8]) -> Vec<&[u8]> {
    let mut values = Vec::new();
    let mut rest = values_der;
    while !rest.is_empty() {
        let Some((value_der, tail)) = BerTlvAny::parse(rest)
            .ok()
            .and_then(|value| rest.split_at_checked(value.size()))
            .filter(|(value_der, _tail)| !value_der.is_empty())
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

/// The universal tag of ASN.1 `NULL` (X.690 sec.8.8).
const NULL_TAG: u16 = 0x05;

/// Most hashes one list of an `ats-hash-index-v3` may carry; a real
/// signature carries a few dozen values at most.
const MAX_HASH_INDEX_ENTRIES: usize = 4096;

/// The `archive-time-stamp-v3` value `token` of the signature `signed`
/// over `signed_content`, whose signer certificate is `signer_der`,
/// with what its imprint must digest and the material it covers, once
/// its `ats-hash-index-v3` is validated (`ETSI EN 319 122-1` clause
/// 5.5.2): the token carries exactly one such attribute with exactly
/// one value, an `ATSHashIndexV3` under a digest this crate computes,
/// and every hash it lists matches a complete `CertificateChoices` TLV
/// of `SignedData.certificates`, a complete `RevocationInfoChoice` TLV
/// of `SignedData.crls`, or an `attrType` TLV followed by one value TLV
/// among the signer's unsigned attributes, each as encoded. The CMS
/// border admits only the `certificate` choice of `CertificateChoices`,
/// so every entry present is hashed. A present value the index does not
/// list did not exist when the token was requested, as this token's
/// own attribute value and any later archive timestamp's, or is not
/// protected by it; such material is left out of [`ArchiveTimestampV3::covered`].
fn archive_timestamp_v3(
    signed: &SignedData<'_>,
    signed_content: Option<&[u8]>,
    signer_der: &[u8],
    token: &[u8],
) -> Result<ArchiveTimestampV3, TimestampError> {
    let signed_content = signed_content.ok_or(TimestampError::Malformed(
        "archive-time-stamp-v3 over a signature without its content",
    ))?;
    let token_data = SignedData::parse(token)
        .map_err(|_ignored| TimestampError::Malformed("token is not CMS SignedData"))?;
    let indexes = attribute_values(
        token_data.signer().unsigned_attributes(),
        known::ATS_HASH_INDEX_V3,
    );
    let index_der = match indexes.as_slice() {
        [] => return Err(TimestampError::Malformed("ats-hash-index-v3 absent")),
        [index_der] => *index_der,
        _ => return Err(TimestampError::Malformed("ats-hash-index-v3 repeated")),
    };
    let index = HashIndex::parse(index_der).ok_or(MALFORMED_HASH_INDEX)?;
    let algorithm = index.algorithm;
    let signer = signed.signer();
    let hash = |octets: &[u8]| algorithm.digest(octets);
    let certificates: HashMap<Vec<u8>, &[u8]> = signed
        .certificates()
        .iter()
        .map(|der| (hash(der), *der))
        .collect();
    let revocation: HashMap<Vec<u8>, RevocationInfoChoice<'_>> = signed
        .revocation_info()
        .iter()
        .map(|entry| (hash(entry.encoded().as_bytes()), entry.choice()))
        .collect();
    let attributes: HashSet<Vec<u8>> = signer
        .unsigned_attributes()
        .iter()
        .flat_map(|attribute| {
            split_values(attribute.values_der)
                .into_iter()
                .map(move |value| {
                    algorithm.digest(&[attribute.type_der.as_bytes(), value].concat())
                })
        })
        .collect();
    let present = index
        .certificates
        .iter()
        .all(|listed| certificates.contains_key(*listed))
        && index
            .revocation
            .iter()
            .all(|listed| revocation.contains_key(*listed))
        && index
            .unsigned_attributes
            .iter()
            .all(|listed| attributes.contains(*listed));
    if !present {
        return Err(TimestampError::ImprintMismatch);
    }
    let mut covered = ValidationMaterial::default();
    for listed in &index.certificates {
        if let Some(der) = certificates.get(*listed)
            && *der != signer_der
            && OwnedCert::from_der(der).is_ok()
            && !covered
                .certificates
                .iter()
                .any(|seen| seen.as_slice() == *der)
        {
            covered.certificates.push(der.to_vec());
        }
    }
    for listed in &index.revocation {
        match revocation.get(*listed) {
            Some(RevocationInfoChoice::Crl(der)) => covered.crls.push(der.to_vec()),
            Some(RevocationInfoChoice::OcspResponse(der)) => {
                covered.ocsp_responses.push(der.to_vec());
            }
            Some(RevocationInfoChoice::Other { .. }) | None => {}
        }
    }
    Ok(ArchiveTimestampV3 {
        token: token.to_vec(),
        imprint: ArchiveImprint {
            algorithm,
            content_type: signed.econtent_type_der().as_bytes().to_vec(),
            content_hash: algorithm.digest(signed_content),
            signer_fields: signer.archive_fields().as_bytes().to_vec(),
            index: index_der.to_vec(),
        },
        covered,
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
    /// `AlgorithmIdentifier` naming SHA-256, SHA-384 or SHA-512 with its
    /// parameters absent or NULL (RFC 5754 sec.2) and nothing else, then
    /// three `SEQUENCE OF OCTET STRING`, each hash a primitive OCTET
    /// STRING of the algorithm's length and each list at most
    /// [`MAX_HASH_INDEX_ENTRIES`] long. `None` for anything else.
    fn parse(der: &'a [u8]) -> Option<Self> {
        let outer = BerTlv::<Sequence>::parse(der).ok()?;
        if outer.size() != der.len() {
            return None;
        }
        let mut fields = outer.iter_children();
        let algorithm_identifier = fields.next()?.ok()?.expect::<Sequence>().ok()?;
        let mut parts = algorithm_identifier.iter_children();
        let oid = parts.next()?.ok()?.expect::<OidTag>().ok()?;
        let algorithm = DigestAlgorithm::from_oid(Oid::new(oid.value()).ok()?)?;
        match parts.next() {
            None => {}
            Some(parameters) => {
                let parameters = parameters.ok()?;
                (parameters.tag() == NULL_TAG && parameters.value().is_empty()).then_some(())?;
                if parts.next().is_some() {
                    return None;
                }
            }
        }
        let mut list = || -> Option<Vec<&'a [u8]>> {
            let list = fields.next()?.ok()?.expect::<Sequence>().ok()?;
            let hashes: Option<Vec<&'a [u8]>> = BerTlvIter::new(list.value())
                .take(MAX_HASH_INDEX_ENTRIES.saturating_add(1))
                .map(|hash| {
                    // The universal OCTET STRING tag is the primitive form.
                    let hash = hash.ok()?.expect::<OctetString>().ok()?.value();
                    (hash.len() == algorithm.digest_len()).then_some(hash)
                })
                .collect();
            hashes.filter(|hashes| hashes.len() <= MAX_HASH_INDEX_ENTRIES)
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

#[cfg(test)]
mod tests {
    use super::{
        CadesArchiveTimestamp, CadesSignature, Content, EssBinding, TimestampError, split_values,
    };
    use crate::testkit::{
        CertificateSpec, CmsParts, SEQUENCE, TestCurve, TestKey, attribute, certificate, cms, day,
        tlv,
    };
    use refineid_cms::oid::known;

    /// Serial of the fixture signer.
    const SERIAL: u8 = 1;
    /// Day the fixture signer's validity starts.
    const FIRST_DAY: u8 = 1;
    /// Day it ends.
    const LAST_DAY: u8 = 28;

    #[test]
    fn values_split_whole_and_the_walk_ends() {
        assert!(split_values(b"").is_empty());
        let first = tlv(SEQUENCE, b"first");
        let second = tlv(SEQUENCE, b"second");
        let both = [first.clone(), second.clone()].concat();
        assert_eq!(split_values(&both), [first.as_slice(), second.as_slice()]);
        let torn = [first.as_slice(), b"x"].concat();
        assert_eq!(
            split_values(&torn),
            [first.as_slice(), b"x".as_slice()],
            "an unreadable tail is one value, and the walk stops there"
        );
    }

    #[test]
    fn an_archive_timestamp_over_absent_content_is_refused() {
        let key = TestKey::derive(TestCurve::P256, b"archive content signer");
        let der = certificate(
            &CertificateSpec {
                serial: SERIAL,
                subject: "Archive Content Signer",
                issuer: "Archive Content Signer",
                not_before: day(FIRST_DAY),
                not_after: day(LAST_DAY),
                extensions: Vec::new(),
            },
            &key,
            &key,
        );
        let mut parts = CmsParts::detached(&key, &der, b"content");
        parts.unsigned_attributes = vec![attribute(
            known::ARCHIVE_TIME_STAMP_V3,
            &tlv(SEQUENCE, b"token"),
        )];
        let signature = CadesSignature::parse(&cms(&parts)).expect("parses");
        let verdict = signature.verify(Content::Attached, EssBinding::NotRequired);
        assert_eq!(
            verdict.archive_timestamps,
            [CadesArchiveTimestamp::V3(Err(TimestampError::Malformed(
                "archive-time-stamp-v3 over a signature without its content"
            )))]
        );
    }
}
