// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Reading the `XAdES` signatures an `ASiC-E` or `BDOC` container
//! carries in `META-INF/*signatures*.xml`.
//!
//! Each `ds:Signature` is read once into the facts verification needs:
//! the canonical `ds:SignedInfo`, every `ds:Reference` with the octets
//! it digests, the signature value, the signer certificate and the
//! `SigningCertificate` digest that binds it, the signature timestamps
//! with the canonical `ds:SignatureValue` they imprint, and the
//! validation material in the unsigned properties.
//! [`XadesSignature::verify`] then judges the references and the
//! signature value against the container. Timestamp tokens are handed
//! out with their imprint input for the caller's timestamp verifier.
//!
//! Canonicalisation is [`crate::verification::xml`]'s Exclusive XML
//! Canonicalization. [`crate::xades`] writes its signed subtrees
//! already in that form; other producers do not, and are canonicalised
//! here before digesting. A signature whose `ds:SignedInfo` names
//! another canonicalisation is reported unsupported; a reference whose
//! transform is not exclusive canonicalisation cannot be recomputed and
//! leaves the document not intact.
//!
//! # Conformance
//!
//! - W3C XML Signature Syntax and Processing 1.1
//!   <https://www.w3.org/TR/xmldsig-core1/>: sec.3.2 core validation,
//!   sec.4.4 `SignedInfo`, sec.4.4.3 `Reference` and same-document
//!   URIs (a bare-name reference drops comment nodes, sec.4.4.3.3),
//!   sec.6.4 the `RSAwithSHA*` and `ECDSAwithSHA*` signature value
//!   forms.
//! - RFC 6931: the `xmldsig-more` digest and signature identifiers,
//!   among them sec.2.3.10 `sha256-rsa-MGF1`.
//! - `ETSI EN 319 132-1` V1.3.1: sec.4.3 the `SignedProperties`
//!   reference and its `Type`, sec.5.2.2 `SigningCertificateV2`,
//!   sec.5.3 `SignatureTimeStamp` over the canonicalised
//!   `ds:SignatureValue` element, sec.5.4 `CertificateValues` and
//!   `RevocationValues`, sec.5.5 `ArchiveTimeStamp`.
//! - `ETSI EN 319 162-1` V1.1.1 clause A.4: reference URIs resolve
//!   against the container root.

use crate::asic::NAMESPACE_ASIC;
use crate::base64;
use crate::validation::ValidationMaterial;
use crate::verification::asic::{AsicContainer, Entry, uri_names};
use crate::verification::xml::{
    ATTRIBUTE_ID, Comments, ElementRef, InclusivePrefixes, XmlDocument, XmlError,
};
use crate::xades::{
    CANONICALIZATION_EXCLUSIVE, DIGEST_METHOD_SHA256, DIGEST_METHOD_SHA384, DIGEST_METHOD_SHA512,
    NAMESPACE_DSIG, NAMESPACE_XADES, SIGNATURE_METHOD_ECDSA_SHA256, SIGNATURE_METHOD_ECDSA_SHA384,
    SIGNATURE_METHOD_RSA_SHA256, SIGNATURE_METHOD_RSA_SHA384, TYPE_SIGNED_PROPERTIES,
};
use refineid_cms::x509::{MessageSignatureAlgorithm, OwnedCert};
use refineid_digest::{SHA256_LEN, SHA384_LEN, SHA512_LEN, Sha256, Sha384, Sha512};

/// `XAdES` 1.4.1 namespace, home of `ArchiveTimeStamp` (`ETSI EN
/// 319 132-1` sec.4.2).
const NAMESPACE_XADES_141: &str = "http://uri.etsi.org/01903/v1.4.1#";

/// Exclusive canonicalisation with comments (W3C xml-exc-c14n sec.4).
const CANONICALIZATION_EXCLUSIVE_COMMENTS: &str =
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

/// RSA PKCS#1 v1.5 with SHA-512 (RFC 6931 sec.2.3.2).
const SIGNATURE_METHOD_RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

/// ECDSA with SHA-512 (RFC 6931 sec.2.3.6).
const SIGNATURE_METHOD_ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";

/// RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a salt of the
/// digest's length (RFC 6931 sec.2.3.10, RFC 8017 sec.8.1).
const SIGNATURE_METHOD_RSA_PSS_SHA256: &str =
    "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";

/// `asic:XAdESSignatures`, the root of a signature file (EN 319 162-1
/// annex A.5).
const ELEMENT_XADES_SIGNATURES: &str = "XAdESSignatures";

/// `ds:Signature`.
const ELEMENT_SIGNATURE: &str = "Signature";

/// `ds:SignedInfo`.
const ELEMENT_SIGNED_INFO: &str = "SignedInfo";

/// `ds:SignatureValue`.
const ELEMENT_SIGNATURE_VALUE: &str = "SignatureValue";

/// `ds:CanonicalizationMethod`.
const ELEMENT_CANONICALIZATION_METHOD: &str = "CanonicalizationMethod";

/// `ds:SignatureMethod`.
const ELEMENT_SIGNATURE_METHOD: &str = "SignatureMethod";

/// `ds:Reference`.
const ELEMENT_REFERENCE: &str = "Reference";

/// `ds:Transforms`.
const ELEMENT_TRANSFORMS: &str = "Transforms";

/// `ds:Transform`.
const ELEMENT_TRANSFORM: &str = "Transform";

/// `ds:DigestMethod`.
const ELEMENT_DIGEST_METHOD: &str = "DigestMethod";

/// `ds:DigestValue`.
const ELEMENT_DIGEST_VALUE: &str = "DigestValue";

/// `ds:KeyInfo`.
const ELEMENT_KEY_INFO: &str = "KeyInfo";

/// `ds:X509Data`.
const ELEMENT_X509_DATA: &str = "X509Data";

/// `ds:X509Certificate`.
const ELEMENT_X509_CERTIFICATE: &str = "X509Certificate";

/// `ds:Object`.
const ELEMENT_OBJECT: &str = "Object";

/// `xades:QualifyingProperties`.
const ELEMENT_QUALIFYING_PROPERTIES: &str = "QualifyingProperties";

/// `xades:SignedProperties`.
const ELEMENT_SIGNED_PROPERTIES: &str = "SignedProperties";

/// `xades:SignedSignatureProperties`.
const ELEMENT_SIGNED_SIGNATURE_PROPERTIES: &str = "SignedSignatureProperties";

/// `xades:SigningCertificateV2`.
const ELEMENT_SIGNING_CERTIFICATE_V2: &str = "SigningCertificateV2";

/// `xades:SigningCertificate`.
const ELEMENT_SIGNING_CERTIFICATE: &str = "SigningCertificate";

/// `xades:Cert`.
const ELEMENT_CERT: &str = "Cert";

/// `xades:CertDigest`.
const ELEMENT_CERT_DIGEST: &str = "CertDigest";

/// `xades:UnsignedProperties`.
const ELEMENT_UNSIGNED_PROPERTIES: &str = "UnsignedProperties";

/// `xades:UnsignedSignatureProperties`.
const ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES: &str = "UnsignedSignatureProperties";

/// `xades:SignatureTimeStamp`.
const ELEMENT_SIGNATURE_TIMESTAMP: &str = "SignatureTimeStamp";

/// `xades:EncapsulatedTimeStamp`.
const ELEMENT_ENCAPSULATED_TIMESTAMP: &str = "EncapsulatedTimeStamp";

/// `xades:ArchiveTimeStamp`, in the 1.4.1 namespace or the 1.3.2 one.
const ELEMENT_ARCHIVE_TIMESTAMP: &str = "ArchiveTimeStamp";

/// `xades:CertificateValues`.
const ELEMENT_CERTIFICATE_VALUES: &str = "CertificateValues";

/// `xades:EncapsulatedX509Certificate`.
const ELEMENT_ENCAPSULATED_CERTIFICATE: &str = "EncapsulatedX509Certificate";

/// `xades:RevocationValues`.
const ELEMENT_REVOCATION_VALUES: &str = "RevocationValues";

/// `xades:CRLValues`.
const ELEMENT_CRL_VALUES: &str = "CRLValues";

/// `xades:EncapsulatedCRLValue`.
const ELEMENT_ENCAPSULATED_CRL: &str = "EncapsulatedCRLValue";

/// `xades:OCSPValues`.
const ELEMENT_OCSP_VALUES: &str = "OCSPValues";

/// `xades:EncapsulatedOCSPValue`.
const ELEMENT_ENCAPSULATED_OCSP: &str = "EncapsulatedOCSPValue";

/// `ec:InclusiveNamespaces`, in the exclusive canonicalisation
/// namespace (xml-exc-c14n sec.4).
const ELEMENT_INCLUSIVE_NAMESPACES: &str = "InclusiveNamespaces";

/// The attribute of `ec:InclusiveNamespaces` listing its prefixes.
const ATTRIBUTE_PREFIX_LIST: &str = "PrefixList";

/// The attribute every algorithm-naming element carries.
const ATTRIBUTE_ALGORITHM: &str = "Algorithm";

/// A reference's target.
const ATTRIBUTE_URI: &str = "URI";

/// A reference's declared type.
const ATTRIBUTE_TYPE: &str = "Type";

/// Marks a same-document reference (XML Signature 1.1 sec.4.4.3.3).
const FRAGMENT_MARK: char = '#';

/// Why a signature file yielded no signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XadesReadError {
    /// The file is not XML this reader accepts.
    Xml(XmlError),
    /// A signature file holds no `ds:Signature`.
    NoSignature,
    /// A `ds:Signature` lacks a part every signature has, or carries
    /// one that does not decode.
    Malformed(&'static str),
}

impl core::fmt::Display for XadesReadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Xml(error) => write!(f, "signature file: {error}"),
            Self::NoSignature => f.write_str("the signature file holds no signature"),
            Self::Malformed(what) => write!(f, "malformed XAdES signature: {what}"),
        }
    }
}

impl core::error::Error for XadesReadError {}

/// The digest algorithms a reference may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestMethod {
    /// `SHA-256`.
    Sha256,
    /// `SHA-384`.
    Sha384,
    /// `SHA-512`.
    Sha512,
}

impl DigestMethod {
    /// The method a `DigestMethod` `Algorithm` names; `None` for
    /// `SHA-1` and anything unknown.
    pub(crate) fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            DIGEST_METHOD_SHA256 => Some(Self::Sha256),
            DIGEST_METHOD_SHA384 => Some(Self::Sha384),
            DIGEST_METHOD_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The digest of `input`.
    pub(crate) fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::of(input).as_bytes().to_vec(),
            Self::Sha384 => Sha384::of(input).as_bytes().to_vec(),
            Self::Sha512 => Sha512::of(input).as_bytes().to_vec(),
        }
    }

    /// The length of a digest under this method.
    const fn len(self) -> usize {
        match self {
            Self::Sha256 => SHA256_LEN,
            Self::Sha384 => SHA384_LEN,
            Self::Sha512 => SHA512_LEN,
        }
    }
}

/// A `ds:DigestValue` under a known `ds:DigestMethod`, its length the
/// method's.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DigestValue {
    /// The method.
    method: DigestMethod,
    /// The value, [`DigestMethod::len`] octets.
    value: Vec<u8>,
}

impl DigestValue {
    /// Read the `ds:DigestMethod` and `ds:DigestValue` children of
    /// `parent`. `Ok(None)` when the method is unknown, so the digest
    /// cannot be recomputed.
    fn read(parent: ElementRef<'_>, what: &'static str) -> Result<Option<Self>, XadesReadError> {
        let text = parent
            .child(NAMESPACE_DSIG, ELEMENT_DIGEST_VALUE)
            .ok_or(XadesReadError::Malformed(what))?
            .text();
        let value =
            base64::decode_wrapped(&text).map_err(|_ignored| XadesReadError::Malformed(what))?;
        let Some(method) = parent
            .child(NAMESPACE_DSIG, ELEMENT_DIGEST_METHOD)
            .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
            .and_then(DigestMethod::from_uri)
        else {
            return Ok(None);
        };
        if value.len() != method.len() {
            return Err(XadesReadError::Malformed(what));
        }
        Ok(Some(Self { method, value }))
    }

    /// Whether `input` digests to this value.
    fn matches(&self, input: &[u8]) -> bool {
        self.method.digest(input) == self.value
    }
}

/// The signature algorithm a `SignatureMethod` `Algorithm` names.
fn signature_method(uri: &str) -> Option<MessageSignatureAlgorithm> {
    match uri {
        SIGNATURE_METHOD_RSA_SHA256 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha256),
        SIGNATURE_METHOD_RSA_SHA384 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha384),
        SIGNATURE_METHOD_RSA_SHA512 => Some(MessageSignatureAlgorithm::RsaPkcs1Sha512),
        SIGNATURE_METHOD_RSA_PSS_SHA256 => Some(MessageSignatureAlgorithm::RsaPssSha256),
        SIGNATURE_METHOD_ECDSA_SHA256 => Some(MessageSignatureAlgorithm::EcdsaSha256Raw),
        SIGNATURE_METHOD_ECDSA_SHA384 => Some(MessageSignatureAlgorithm::EcdsaSha384Raw),
        SIGNATURE_METHOD_ECDSA_SHA512 => Some(MessageSignatureAlgorithm::EcdsaSha512Raw),
        _ => None,
    }
}

/// The comment mode an exclusive canonicalisation identifier names;
/// `None` for every other canonicalisation.
fn exclusive_mode(uri: &str) -> Option<Comments> {
    match uri {
        CANONICALIZATION_EXCLUSIVE => Some(Comments::Omitted),
        CANONICALIZATION_EXCLUSIVE_COMMENTS => Some(Comments::Retained),
        _ => None,
    }
}

/// The exclusive canonicalisation `method` names: its comment mode, and
/// the prefixes of the one `ec:InclusiveNamespaces` child it may carry
/// (xml-exc-c14n sec.4). `None` for another canonicalisation, any other
/// child, or a `PrefixList` that does not parse.
fn exclusive_method(method: ElementRef<'_>) -> Option<(Comments, InclusivePrefixes)> {
    let comments = method
        .attribute(ATTRIBUTE_ALGORITHM)
        .and_then(exclusive_mode)?;
    let mut children = method.children();
    let prefixes = match (children.next(), children.next()) {
        (None, _) => InclusivePrefixes::default(),
        (Some(child), None)
            if child.is(CANONICALIZATION_EXCLUSIVE, ELEMENT_INCLUSIVE_NAMESPACES) =>
        {
            InclusivePrefixes::parse(child.attribute(ATTRIBUTE_PREFIX_LIST)?)?
        }
        _ => return None,
    };
    Some((comments, prefixes))
}

/// What a reference digests.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// A container entry, by the URI that names it.
    DataFile(String),
    /// A same-document element, already canonicalised.
    Canonical(Vec<u8>),
    /// Nothing this verifier can recompute.
    Unresolvable,
}

/// One `ds:Reference`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reference {
    /// What it digests.
    target: Target,
    /// The digest, under a method this verifier accepts.
    digest: DigestValue,
    /// Whether it is the `SignedProperties` reference and resolves to
    /// this signature's own `xades:SignedProperties`.
    signed_properties: bool,
}

/// What the signed properties say about the signer certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SignerBinding {
    /// Neither `SigningCertificateV2` nor `SigningCertificate`.
    Absent,
    /// The property names its certificate under a digest method this
    /// verifier does not accept.
    Unverifiable,
    /// The digest of the signer certificate.
    Digest(DigestValue),
}

/// One `EncapsulatedTimeStamp` of a `SignatureTimeStamp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureTimestamp {
    /// The RFC 3161 token.
    token: Vec<u8>,
    /// The canonicalised `ds:SignatureValue` it must imprint.
    imprint_input: Option<Vec<u8>>,
}

impl SignatureTimestamp {
    /// The RFC 3161 `TimeStampToken`, DER, for the timestamp verifier.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// The octets the token's message imprint must digest: the
    /// `ds:SignatureValue` element under the exclusive canonicalisation
    /// the timestamp names (EN 319 132-1 sec.5.3). `None` when it names
    /// another canonicalisation, or none, which leaves the inclusive
    /// default this verifier does not compute.
    #[must_use]
    pub fn imprint_input(&self) -> Option<&[u8]> {
        self.imprint_input.as_deref()
    }
}

/// A signature feature this verifier does not implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XadesUnsupported {
    /// `ds:SignedInfo` names a canonicalisation other than Exclusive
    /// XML Canonicalization 1.0, or one with children other than an
    /// `InclusiveNamespaces` prefix list.
    SignedInfoCanonicalization,
    /// `ds:SignatureMethod` names an algorithm this verifier does not
    /// verify: SHA-1, MD5, DSA or any other.
    SignatureAlgorithm,
    /// A `ds:DigestMethod` of a reference or of the signing-certificate
    /// binding names an algorithm this verifier does not compute.
    DigestAlgorithm,
    /// A reference carries more than one transform, a transform other
    /// than exclusive canonicalisation, or a transform over a data
    /// file: a chain of octet streams (XML Signature 1.1 sec.4.4.3.3)
    /// this verifier does not model.
    TransformChain,
}

/// The judgement on a signature this verifier supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XadesJudgement {
    /// Every reference recomputed and matched.
    document_intact: bool,
    /// The value verifies and the signer is bound.
    signature_valid: bool,
    /// `SignatureTimeStamp` tokens present.
    signature_timestamps_present: usize,
    /// `ArchiveTimeStamp` elements present.
    archive_timestamps_present: usize,
}

impl XadesJudgement {
    /// Every reference recomputed and matched, the `SignedProperties`
    /// reference among them, and every data file in the container
    /// covered by a reference.
    #[must_use]
    pub const fn document_intact(&self) -> bool {
        self.document_intact
    }

    /// The signature value verifies over the canonical `ds:SignedInfo`
    /// under the signer certificate, and the signed properties carry a
    /// `SigningCertificateV2` or `SigningCertificate` whose digest
    /// matches that certificate. The property is mandatory at every
    /// baseline level (`ETSI EN 319 132-1` sec.5.2.2), so a signature
    /// without it is not valid.
    #[must_use]
    pub const fn signature_valid(&self) -> bool {
        self.signature_valid
    }

    /// How many `SignatureTimeStamp` tokens the signature carries; see
    /// [`XadesSignature::signature_timestamps`].
    #[must_use]
    pub const fn signature_timestamps_present(&self) -> usize {
        self.signature_timestamps_present
    }

    /// How many `ArchiveTimeStamp` elements the signature carries.
    #[must_use]
    pub const fn archive_timestamps_present(&self) -> usize {
        self.archive_timestamps_present
    }
}

/// The verdict on one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XadesVerdict {
    /// The signature uses a feature this verifier does not implement
    /// and is not judged.
    Unsupported(XadesUnsupported),
    /// The signature was judged.
    Judged(XadesJudgement),
}

/// One `ds:Signature`, read into the facts verification needs.
#[derive(Debug, Clone)]
pub struct XadesSignature {
    /// The signer certificate.
    signer: Option<OwnedCert>,
    /// Every `X509Certificate` and `EncapsulatedX509Certificate`.
    embedded_certificates: Vec<Vec<u8>>,
    /// `CertificateValues` and `RevocationValues`.
    material: ValidationMaterial,
    /// Why the signature cannot be judged, when it cannot.
    unsupported: Option<XadesUnsupported>,
    /// The canonical `ds:SignedInfo`; empty when unsupported.
    signed_info: Vec<u8>,
    /// The signature algorithm, when one this verifier accepts.
    signature_method: Option<MessageSignatureAlgorithm>,
    /// The decoded `SignatureValue`.
    signature_value: Vec<u8>,
    /// Every `ds:Reference`, in order.
    references: Vec<Reference>,
    /// The `SigningCertificate` binding.
    binding: SignerBinding,
    /// Every `SignatureTimeStamp` token.
    signature_timestamps: Vec<SignatureTimestamp>,
    /// How many `ArchiveTimeStamp` elements are present.
    archive_timestamps: usize,
}

/// Read every `ds:Signature` in the container's signature files: in
/// each file, the root itself, or the children of an
/// `asic:XAdESSignatures` root. Each signature is its own result: one
/// that lacks `ds:SignedInfo`, a decodable `ds:SignatureValue`, a
/// readable digest or a parseable signer certificate is an `Err` beside
/// the others.
///
/// # Errors
/// [`XadesReadError`] when a file is not accepted XML or holds no
/// signature.
pub fn signatures(
    container: &AsicContainer,
) -> Result<Vec<Result<XadesSignature, XadesReadError>>, XadesReadError> {
    let mut all = Vec::new();
    for file in container.xades_signature_files() {
        all.extend(file_signatures(file)?);
    }
    Ok(all)
}

/// Every `ds:Signature` in one signature file, each read on its own so
/// one malformed signature leaves the others readable.
fn file_signatures(
    file: &Entry,
) -> Result<Vec<Result<XadesSignature, XadesReadError>>, XadesReadError> {
    let document = XmlDocument::parse(file.content().to_vec()).map_err(XadesReadError::Xml)?;
    let root = document.root();
    let elements: Vec<ElementRef<'_>> = if root.is(NAMESPACE_DSIG, ELEMENT_SIGNATURE) {
        vec![root]
    } else if root.is(NAMESPACE_ASIC, ELEMENT_XADES_SIGNATURES) {
        root.children_named(NAMESPACE_DSIG, ELEMENT_SIGNATURE)
            .collect()
    } else {
        Vec::new()
    };
    if elements.is_empty() {
        return Err(XadesReadError::NoSignature);
    }
    Ok(elements
        .into_iter()
        .map(|element| XadesSignature::read(&document, element))
        .collect())
}

impl XadesSignature {
    /// Read one `ds:Signature`.
    fn read(document: &XmlDocument, signature: ElementRef<'_>) -> Result<Self, XadesReadError> {
        let signed_info = signature
            .child(NAMESPACE_DSIG, ELEMENT_SIGNED_INFO)
            .ok_or(XadesReadError::Malformed("no SignedInfo"))?;
        let signature_value_element = signature
            .child(NAMESPACE_DSIG, ELEMENT_SIGNATURE_VALUE)
            .ok_or(XadesReadError::Malformed("no SignatureValue"))?;
        let signature_value = base64::decode_wrapped(&signature_value_element.text())
            .map_err(|_ignored| XadesReadError::Malformed("SignatureValue is not base64"))?;

        let qualifying = signature
            .children_named(NAMESPACE_DSIG, ELEMENT_OBJECT)
            .find_map(|object| object.child(NAMESPACE_XADES, ELEMENT_QUALIFYING_PROPERTIES));
        let signed_properties = qualifying
            .and_then(|properties| properties.child(NAMESPACE_XADES, ELEMENT_SIGNED_PROPERTIES));
        let unsigned = qualifying
            .and_then(|properties| properties.child(NAMESPACE_XADES, ELEMENT_UNSIGNED_PROPERTIES))
            .and_then(|properties| {
                properties.child(NAMESPACE_XADES, ELEMENT_UNSIGNED_SIGNATURE_PROPERTIES)
            });

        let mut material = ValidationMaterial::default();
        let mut signature_timestamps = Vec::new();
        let mut archive_timestamps = 0_usize;
        if let Some(unsigned) = unsigned {
            read_unsigned(
                unsigned,
                signature_value_element,
                &mut material,
                &mut signature_timestamps,
            )?;
            archive_timestamps = unsigned
                .children()
                .filter(|child| {
                    child.is(NAMESPACE_XADES_141, ELEMENT_ARCHIVE_TIMESTAMP)
                        || child.is(NAMESPACE_XADES, ELEMENT_ARCHIVE_TIMESTAMP)
                })
                .count();
        }

        let binding = match signed_properties
            .and_then(|properties| {
                properties.child(NAMESPACE_XADES, ELEMENT_SIGNED_SIGNATURE_PROPERTIES)
            })
            .and_then(|properties| {
                properties
                    .child(NAMESPACE_XADES, ELEMENT_SIGNING_CERTIFICATE_V2)
                    .or_else(|| properties.child(NAMESPACE_XADES, ELEMENT_SIGNING_CERTIFICATE))
            }) {
            None => SignerBinding::Absent,
            Some(property) => read_cert_digest(property)?
                .map_or(SignerBinding::Unverifiable, SignerBinding::Digest),
        };

        let key_info_certificates: Vec<Vec<u8>> = signature
            .child(NAMESPACE_DSIG, ELEMENT_KEY_INFO)
            .into_iter()
            .flat_map(|key_info| key_info.children_named(NAMESPACE_DSIG, ELEMENT_X509_DATA))
            .flat_map(|data| data.children_named(NAMESPACE_DSIG, ELEMENT_X509_CERTIFICATE))
            .map(|certificate| base64::decode_wrapped(&certificate.text()))
            .collect::<Result<_, _>>()
            .map_err(|_ignored| XadesReadError::Malformed("X509Certificate is not base64"))?;
        let signer = select_signer(&key_info_certificates, &material.certificates, &binding)?;
        let mut unsupported = None;
        if binding == SignerBinding::Unverifiable {
            unsupported = Some(XadesUnsupported::DigestAlgorithm);
        }
        let mut embedded_certificates = key_info_certificates;
        embedded_certificates.extend(material.certificates.iter().cloned());

        let canonicalization = signed_info
            .child(NAMESPACE_DSIG, ELEMENT_CANONICALIZATION_METHOD)
            .ok_or(XadesReadError::Malformed("no CanonicalizationMethod"))?;
        if canonicalization.attribute(ATTRIBUTE_ALGORITHM).is_none() {
            return Err(XadesReadError::Malformed(
                "CanonicalizationMethod without an Algorithm",
            ));
        }
        let signature_method = signed_info
            .child(NAMESPACE_DSIG, ELEMENT_SIGNATURE_METHOD)
            .and_then(|method| method.attribute(ATTRIBUTE_ALGORITHM))
            .and_then(signature_method);
        let signed_info_bytes = match exclusive_method(canonicalization) {
            Some((comments, prefixes)) => signed_info.canonicalize_with(comments, &prefixes),
            None => {
                unsupported = Some(XadesUnsupported::SignedInfoCanonicalization);
                Vec::new()
            }
        };
        if signature_method.is_none() {
            unsupported.get_or_insert(XadesUnsupported::SignatureAlgorithm);
        }

        let mut references = Vec::new();
        for reference in signed_info.children_named(NAMESPACE_DSIG, ELEMENT_REFERENCE) {
            match read_reference(document, reference, signed_properties)? {
                Ok(reference) => references.push(reference),
                Err(feature) => {
                    unsupported.get_or_insert(feature);
                }
            }
        }

        Ok(Self {
            signer,
            embedded_certificates,
            material,
            unsupported,
            signed_info: signed_info_bytes,
            signature_method,
            signature_value,
            references,
            binding,
            signature_timestamps,
            archive_timestamps,
        })
    }

    /// The signer certificate: the certificate the
    /// `SigningCertificate` digest names, among the `ds:KeyInfo` and
    /// `CertificateValues` certificates; without a binding, the first
    /// `ds:KeyInfo` certificate. `None` when the binding names a
    /// certificate the signature does not carry.
    #[must_use]
    pub const fn signer_certificate(&self) -> Option<&OwnedCert> {
        self.signer.as_ref()
    }

    /// Every `ds:X509Certificate`, then every `CertificateValues`
    /// certificate, as DER, for the caller's path builder.
    #[must_use]
    pub fn embedded_certificates(&self) -> &[Vec<u8>] {
        &self.embedded_certificates
    }

    /// The `CertificateValues` certificates and the `RevocationValues`
    /// CRLs and OCSP responses.
    #[must_use]
    pub const fn embedded_material(&self) -> &ValidationMaterial {
        &self.material
    }

    /// The profile feature this verifier does not implement, when the
    /// signature uses one.
    #[must_use]
    pub const fn unsupported(&self) -> Option<XadesUnsupported> {
        self.unsupported
    }

    /// Every `SignatureTimeStamp` token, with the octets its imprint
    /// must digest.
    #[must_use]
    pub fn signature_timestamps(&self) -> &[SignatureTimestamp] {
        &self.signature_timestamps
    }

    /// Judge the signature against `container`.
    #[must_use]
    pub fn verify(&self, container: &AsicContainer) -> XadesVerdict {
        if let Some(unsupported) = self.unsupported {
            return XadesVerdict::Unsupported(unsupported);
        }
        XadesVerdict::Judged(XadesJudgement {
            document_intact: self.document_intact(container),
            signature_valid: self.signature_valid(),
            signature_timestamps_present: self.signature_timestamps.len(),
            archive_timestamps_present: self.archive_timestamps,
        })
    }

    /// Every reference matches, one covers the signed properties, and
    /// every data file is covered.
    fn document_intact(&self, container: &AsicContainer) -> bool {
        let every_reference_matches = !self.references.is_empty()
            && self.references.iter().all(|reference| {
                let digest = &reference.digest;
                match &reference.target {
                    Target::DataFile(uri) => container
                        .data_files()
                        .iter()
                        .find(|entry| uri_names(uri, entry.name()))
                        .is_some_and(|entry| digest.matches(entry.content())),
                    Target::Canonical(octets) => digest.matches(octets),
                    Target::Unresolvable => false,
                }
            });
        let properties_covered = self
            .references
            .iter()
            .any(|reference| reference.signed_properties);
        let files_covered = container.data_files().iter().all(|entry| {
            self.references.iter().any(|reference| {
                matches!(&reference.target, Target::DataFile(uri) if uri_names(uri, entry.name()))
            })
        });
        every_reference_matches && properties_covered && files_covered
    }

    /// The signature verifies and the mandatory signer binding is
    /// present and holds (EN 319 132-1 sec.5.2.2).
    fn signature_valid(&self) -> bool {
        let (Some(algorithm), Some(signer)) = (self.signature_method, &self.signer) else {
            return false;
        };
        let verifies = signer
            .view()
            .spki
            .verify_message_signature(algorithm, &self.signed_info, &self.signature_value)
            .is_ok();
        let bound = match &self.binding {
            SignerBinding::Digest(digest) => digest.matches(signer.as_der()),
            SignerBinding::Absent | SignerBinding::Unverifiable => false,
        };
        verifies && bound
    }
}

/// Read `xades:UnsignedSignatureProperties`: the signature timestamps
/// and the validation material.
fn read_unsigned(
    unsigned: ElementRef<'_>,
    signature_value: ElementRef<'_>,
    material: &mut ValidationMaterial,
    timestamps: &mut Vec<SignatureTimestamp>,
) -> Result<(), XadesReadError> {
    /// Decode every child `name` of `parent` as base64.
    fn encapsulated(
        parent: ElementRef<'_>,
        name: &'static str,
    ) -> Result<Vec<Vec<u8>>, XadesReadError> {
        parent
            .children_named(NAMESPACE_XADES, name)
            .map(|value| base64::decode_wrapped(&value.text()))
            .collect::<Result<_, _>>()
            .map_err(|_ignored| XadesReadError::Malformed("encapsulated value is not base64"))
    }

    for timestamp in unsigned.children_named(NAMESPACE_XADES, ELEMENT_SIGNATURE_TIMESTAMP) {
        // Without a CanonicalizationMethod the XML Signature default,
        // inclusive Canonical XML 1.0, applies (EN 319 132-1 sec.5.3),
        // which this verifier does not compute.
        let imprint_input = timestamp
            .child(NAMESPACE_DSIG, ELEMENT_CANONICALIZATION_METHOD)
            .and_then(exclusive_method)
            .map(|(comments, prefixes)| signature_value.canonicalize_with(comments, &prefixes));
        for token in encapsulated(timestamp, ELEMENT_ENCAPSULATED_TIMESTAMP)? {
            timestamps.push(SignatureTimestamp {
                token,
                imprint_input: imprint_input.clone(),
            });
        }
    }
    for values in unsigned.children_named(NAMESPACE_XADES, ELEMENT_CERTIFICATE_VALUES) {
        material
            .certificates
            .extend(encapsulated(values, ELEMENT_ENCAPSULATED_CERTIFICATE)?);
    }
    for values in unsigned.children_named(NAMESPACE_XADES, ELEMENT_REVOCATION_VALUES) {
        for crls in values.children_named(NAMESPACE_XADES, ELEMENT_CRL_VALUES) {
            material
                .crls
                .extend(encapsulated(crls, ELEMENT_ENCAPSULATED_CRL)?);
        }
        for responses in values.children_named(NAMESPACE_XADES, ELEMENT_OCSP_VALUES) {
            material
                .ocsp_responses
                .extend(encapsulated(responses, ELEMENT_ENCAPSULATED_OCSP)?);
        }
    }
    Ok(())
}

/// Read the first `xades:Cert/xades:CertDigest` of a signing
/// certificate property: in `SigningCertificateV2` and
/// `SigningCertificate` alike the first `Cert` names the signer.
fn read_cert_digest(property: ElementRef<'_>) -> Result<Option<DigestValue>, XadesReadError> {
    const MALFORMED: &str = "SigningCertificate without a readable CertDigest";
    let digest = property
        .child(NAMESPACE_XADES, ELEMENT_CERT)
        .and_then(|cert| cert.child(NAMESPACE_XADES, ELEMENT_CERT_DIGEST))
        .ok_or(XadesReadError::Malformed(MALFORMED))?;
    DigestValue::read(digest, MALFORMED)
}

/// Pick the signer: the candidate the binding digest names, else the
/// first `ds:KeyInfo` certificate.
fn select_signer(
    key_info: &[Vec<u8>],
    certificate_values: &[Vec<u8>],
    binding: &SignerBinding,
) -> Result<Option<OwnedCert>, XadesReadError> {
    let der = match binding {
        SignerBinding::Digest(digest) => key_info
            .iter()
            .chain(certificate_values)
            .find(|der| digest.matches(der)),
        SignerBinding::Absent | SignerBinding::Unverifiable => Some(key_info.first().ok_or(
            XadesReadError::Malformed("no signer certificate in KeyInfo"),
        )?),
    };
    der.map(|der| {
        OwnedCert::from_der(der)
            .map_err(|_ignored| XadesReadError::Malformed("signer certificate does not parse"))
    })
    .transpose()
}

/// Read one `ds:Reference` into what it digests; `Ok(Err(feature))`
/// when it uses a feature this verifier does not implement.
fn read_reference(
    document: &XmlDocument,
    reference: ElementRef<'_>,
    signed_properties: Option<ElementRef<'_>>,
) -> Result<Result<Reference, XadesUnsupported>, XadesReadError> {
    let Some(digest) = DigestValue::read(reference, "Reference without a readable DigestValue")?
    else {
        return Ok(Err(XadesUnsupported::DigestAlgorithm));
    };
    let uri = reference.attribute(ATTRIBUTE_URI).unwrap_or_default();
    let claims_properties = reference.attribute(ATTRIBUTE_TYPE) == Some(TYPE_SIGNED_PROPERTIES);

    // At most one transform, and that one exclusive canonicalisation:
    // anything else chains octet streams this verifier does not model.
    let transforms: Vec<ElementRef<'_>> = reference
        .child(NAMESPACE_DSIG, ELEMENT_TRANSFORMS)
        .into_iter()
        .flat_map(ElementRef::children)
        .collect();
    let canonicalization = match transforms.as_slice() {
        [] => None,
        [transform] if transform.is(NAMESPACE_DSIG, ELEMENT_TRANSFORM) => {
            match exclusive_method(*transform) {
                Some(method) => Some(method),
                None => return Ok(Err(XadesUnsupported::TransformChain)),
            }
        }
        _ => return Ok(Err(XadesUnsupported::TransformChain)),
    };

    let mut resolves_to_properties = false;
    let target = if let Some(id) = uri.strip_prefix(FRAGMENT_MARK) {
        // A bare-name reference `#id` yields the element's subtree with
        // every comment node deleted (XML Signature 1.1 sec.4.4.3.3),
        // so a `WithComments` transform after it has no comment to
        // keep; only `#xpointer(id('id'))` retains them, and that form
        // does not resolve here. Without a transform the node set would
        // be serialised by inclusive Canonical XML. The reader refuses
        // a repeated `Id`, so at most one element matches.
        match (
            document
                .elements()
                .find(|element| element.attribute(ATTRIBUTE_ID) == Some(id)),
            canonicalization,
        ) {
            (Some(element), Some((_comments, prefixes))) => {
                resolves_to_properties = signed_properties == Some(element);
                if claims_properties && !resolves_to_properties {
                    Target::Unresolvable
                } else {
                    Target::Canonical(element.canonicalize_with(Comments::Omitted, &prefixes))
                }
            }
            _ => Target::Unresolvable,
        }
    } else if canonicalization.is_some() {
        return Ok(Err(XadesUnsupported::TransformChain));
    } else if uri.is_empty() || claims_properties {
        Target::Unresolvable
    } else {
        Target::DataFile(uri.to_owned())
    };
    Ok(Ok(Reference {
        target,
        digest,
        signed_properties: claims_properties && resolves_to_properties,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        CANONICALIZATION_EXCLUSIVE, CANONICALIZATION_EXCLUSIVE_COMMENTS, NAMESPACE_DSIG,
        NAMESPACE_XADES, NAMESPACE_XADES_141, XadesJudgement, XadesReadError, XadesSignature,
        XadesUnsupported, XadesVerdict, signatures,
    };
    use crate::asic::{DataObject, xades_container};
    use crate::base64;
    use crate::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime};
    use crate::validation::ValidationMaterial;
    use crate::verification::asic::AsicContainer;
    use crate::verification::exactly;
    use crate::verification::xml::{Comments, XmlDocument, XmlError};
    use crate::xades::{SIGNATURE_METHOD_RSA_SHA256, SignaturePlan, plan};
    use refineid_cms::testkit::{self as kit, TestCurve, TestKey};
    use refineid_cms::x509::OwnedCert;

    /// A certificate to name as the signer. Only its bytes matter here:
    /// they are parsed and digested, and nothing is signed with it.
    const CERTIFICATE_DER: &[u8] =
        include_bytes!("../../test-vectors/fineid-intermediate-01-citizen-g4e.der");

    /// Stands in for the signature value; it verifies under no key.
    const UNSIGNED_VALUE: &[u8] = b"not a signature value";

    /// A synthetic claimed signing time.
    const SIGNING_TIME: SigningTime = SigningTime {
        year: 2001,
        month: 2,
        day: 3,
        hour: 4,
        minute: 5,
        second: 6,
    };

    /// The first synthetic timestamp token.
    const FIRST_TOKEN: &[u8] = b"first timestamp token";

    /// The second synthetic timestamp token.
    const SECOND_TOKEN: &[u8] = b"second timestamp token";

    /// Inclusive Canonical XML 1.1, a canonicalisation this reader does
    /// not compute.
    const CANONICALIZATION_INCLUSIVE_11: &str = "http://www.w3.org/2006/12/xml-c14n11";

    /// Where the wrapped-value fixture breaks its base64 line.
    const WRAP_COLUMN: usize = 8;

    /// RSA with SHA-1 (RFC 3075), which this reader does not accept.
    const SIGNATURE_METHOD_RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    /// The SHA-1 digest identifier, which this reader does not accept.
    const DIGEST_METHOD_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

    fn objects() -> Vec<DataObject> {
        vec![
            DataObject {
                name: "dossier.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: b"a declaration of a means of cryptology".to_vec(),
            },
            DataObject {
                name: "annex one.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"annex, completed".to_vec(),
            },
        ]
    }

    /// The writer's plan over [`objects`], naming [`CERTIFICATE_DER`].
    fn signature_plan() -> SignaturePlan {
        let certificate = crate::test_support::parse_certificate_for_test(CERTIFICATE_DER);
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(SIGNING_TIME),
        };
        plan(&objects(), &parameters).expect("plan")
    }

    /// The writer's signature file, carrying `timestamps` and
    /// `material`.
    fn document_with(timestamps: &[Vec<u8>], material: &ValidationMaterial) -> String {
        String::from_utf8(signature_plan().finish(UNSIGNED_VALUE, timestamps, material))
            .expect("utf-8")
    }

    /// The writer's signature file with no unsigned properties.
    fn document() -> String {
        document_with(&[], &ValidationMaterial::default())
    }

    /// `signature_xml` in a container holding `objects`.
    fn container(objects: &[DataObject], signature_xml: &str) -> AsicContainer {
        let archive = xades_container(objects, signature_xml.as_bytes()).expect("fits");
        AsicContainer::parse(&archive).expect("container reads")
    }

    /// The one signature of `signature_xml`, and its container.
    fn read(objects: &[DataObject], signature_xml: &str) -> (AsicContainer, XadesSignature) {
        let container = container(objects, signature_xml);
        let mut read = signatures(&container).expect("signature file reads");
        let signature = read
            .pop()
            .expect("one signature")
            .expect("the signature reads");
        assert!(read.is_empty(), "exactly one signature");
        (container, signature)
    }

    /// The judgement on `signature_xml` over `objects`.
    fn judged(objects: &[DataObject], signature_xml: &str) -> XadesJudgement {
        let (container, signature) = read(objects, signature_xml);
        supported(signature.verify(&container))
    }

    /// The judgement a supported signature's verdict carries.
    fn supported(verdict: XadesVerdict) -> XadesJudgement {
        match verdict {
            XadesVerdict::Judged(judgement) => Some(judgement),
            XadesVerdict::Unsupported(_) => None,
        }
        .expect("the signature is supported")
    }

    /// The element of `document` from `open` through `close`.
    fn element<'a>(document: &'a str, open: &str, close: &str) -> &'a str {
        let start = document.find(open).expect("element");
        let end = document.find(close).expect("end tag") + close.len();
        &document[start..end]
    }

    /// The base64 SHA-256 of `octets`, as the writer spells a digest.
    fn digest(octets: &[u8]) -> String {
        base64::encode(&DigestAlgorithm::Sha256.digest(octets))
    }

    /// Rewrite `document`'s `SignedProperties` with `properties` and its
    /// `SignedInfo` with `signed_info`, recomputing the properties
    /// digest over the canonical form of the edited properties, so only
    /// the edits differ from a document the writer produced. Nothing is
    /// re-signed.
    fn redigest(
        document: &str,
        properties: impl Fn(&str) -> String,
        signed_info: impl Fn(&str) -> String,
    ) -> String {
        let old_properties = element(
            document,
            "<xades:SignedProperties",
            "</xades:SignedProperties>",
        );
        let old_signed_info = element(document, "<ds:SignedInfo", "</ds:SignedInfo>");
        let new_properties = properties(old_properties);
        let canonical_properties = XmlDocument::parse(new_properties.clone().into_bytes())
            .expect("properties parse")
            .root()
            .canonicalize(Comments::Omitted);
        let new_signed_info = signed_info(&old_signed_info.replace(
            &digest(old_properties.as_bytes()),
            &digest(&canonical_properties),
        ));
        document
            .replace(old_properties, &new_properties)
            .replace(old_signed_info, &new_signed_info)
    }

    #[test]
    fn the_writers_signature_reads_and_its_references_resolve() {
        let (container, signature) = read(&objects(), &document());
        assert_eq!(signature.unsupported(), None);
        assert_eq!(
            signature.signer_certificate().map(OwnedCert::as_der),
            Some(CERTIFICATE_DER)
        );
        assert_eq!(signature.embedded_certificates(), [CERTIFICATE_DER]);
        assert!(signature.embedded_material().is_empty());
        assert!(signature.signature_timestamps().is_empty());
        let judgement = supported(signature.verify(&container));
        assert!(judgement.document_intact());
        assert!(
            !judgement.signature_valid(),
            "the placeholder value verifies under no key"
        );
        assert_eq!(judgement.signature_timestamps_present(), 0);
        assert_eq!(judgement.archive_timestamps_present(), 0);
    }

    #[test]
    fn a_modified_data_file_breaks_the_document() {
        let mut changed = objects();
        changed[0].content = b"a different declaration".to_vec();
        assert!(!judged(&changed, &document()).document_intact());
    }

    #[test]
    fn an_unreferenced_data_file_breaks_the_document() {
        let mut extended = objects();
        extended.push(DataObject {
            name: "smuggled.txt".to_owned(),
            mime_type: "text/plain".to_owned(),
            content: b"not signed".to_vec(),
        });
        assert!(!judged(&extended, &document()).document_intact());
    }

    #[test]
    fn removed_signed_properties_break_the_document() {
        let document = document();
        let properties = element(
            &document,
            "<xades:SignedProperties",
            "</xades:SignedProperties>",
        );
        let stripped = document.replace(properties, "");
        assert!(!judged(&objects(), &stripped).document_intact());
    }

    #[test]
    fn a_signed_properties_reference_to_another_element_is_not_intact() {
        let document = document();
        let value = element(&document, "<ds:SignatureValue", "</ds:SignatureValue>");
        let canonical_value = XmlDocument::parse(value.as_bytes().to_vec())
            .expect("parses")
            .root()
            .canonicalize(Comments::Omitted);
        let properties = element(
            &document,
            "<xades:SignedProperties",
            "</xades:SignedProperties>",
        );
        let pointed = document
            .replace("URI=\"#SIG-1-SIGNEDPROPS\"", "URI=\"#SIG-1-SIGVAL\"")
            .replace(&digest(properties.as_bytes()), &digest(&canonical_value));
        assert!(!judged(&objects(), &pointed).document_intact());
    }

    /// A bare-name reference drops comments before its transforms run
    /// (XML Signature 1.1 sec.4.4.3.3), so a `WithComments` transform
    /// over a `SignedProperties` holding a comment digests the
    /// comment-free form, and the document is intact.
    #[test]
    fn a_with_comments_transform_on_a_bare_name_reference_digests_without_comments() {
        let open = "<xades:SignedSignatureProperties>";
        let with_comment = redigest(
            &document(),
            |properties| properties.replacen(open, &format!("{open}<!-- a note -->"), 1),
            |signed_info| {
                signed_info.replace(
                    &format!("<ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\">"),
                    &format!("<ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE_COMMENTS}\">"),
                )
            },
        );
        assert!(with_comment.contains("<!-- a note -->"));
        assert!(with_comment.contains(CANONICALIZATION_EXCLUSIVE_COMMENTS));

        // The comment would change the digest if it were kept.
        let parsed = XmlDocument::parse(with_comment.clone().into_bytes()).expect("parses");
        let properties = parsed
            .elements()
            .find(|element| element.is(NAMESPACE_XADES, "SignedProperties"))
            .expect("properties");
        assert!(
            properties.canonicalize(Comments::Retained)
                != properties.canonicalize(Comments::Omitted)
        );
        assert!(judged(&objects(), &with_comment).document_intact());
    }

    #[test]
    fn a_transform_chain_the_reader_does_not_model_is_unsupported() {
        let transform = format!("<ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\">");
        let inclusive = document().replace(
            &transform,
            &format!("<ds:Transform Algorithm=\"{CANONICALIZATION_INCLUSIVE_11}\">"),
        );
        let doubled = document().replace(
            &format!("{transform}</ds:Transform>"),
            &format!("{transform}</ds:Transform>{transform}</ds:Transform>"),
        );
        assert!(doubled != document());
        for chained in [inclusive, doubled] {
            let (container, signature) = read(&objects(), &chained);
            assert_eq!(
                signature.verify(&container),
                XadesVerdict::Unsupported(XadesUnsupported::TransformChain)
            );
        }
    }

    #[test]
    fn an_algorithm_the_reader_does_not_accept_is_unsupported() {
        let document = document();
        let signed_info = element(&document, "<ds:SignedInfo", "</ds:SignedInfo>");
        let sha1 = document.replacen(
            signed_info,
            &signed_info.replacen(crate::xades::DIGEST_METHOD_SHA256, DIGEST_METHOD_SHA1, 1),
            1,
        );
        let (container, signature) = read(&objects(), &sha1);
        assert_eq!(
            signature.verify(&container),
            XadesVerdict::Unsupported(XadesUnsupported::DigestAlgorithm)
        );
        let rsa_sha1 = document.replacen(
            crate::xades::SIGNATURE_METHOD_RSA_SHA256,
            SIGNATURE_METHOD_RSA_SHA1,
            1,
        );
        assert!(rsa_sha1 != document);
        let (container, signature) = read(&objects(), &rsa_sha1);
        assert_eq!(
            signature.verify(&container),
            XadesVerdict::Unsupported(XadesUnsupported::SignatureAlgorithm)
        );
    }

    /// The writer's `SignedInfo`, respelled as another producer might:
    /// declarations on an ancestor, an unused declaration, attributes
    /// reordered and single-quoted, self-closed elements, whitespace
    /// inside tags. Canonicalisation lands on the writer's bytes, and
    /// the references still resolve.
    #[test]
    fn a_respelled_signed_info_canonicalises_to_the_writers_bytes() {
        let plan = signature_plan();
        let canonical = core::str::from_utf8(plan.signed_info()).expect("utf-8");
        let respelled = respell(canonical);
        assert!(respelled.contains(" />"), "self-closed elements");
        assert!(
            respelled.contains("URI='dossier.pdf'"),
            "reordered attributes"
        );
        assert!(
            !respelled.contains("xmlns:ds"),
            "declaration moved to an ancestor"
        );
        let wrapper = format!(
            "<outer xmlns:ds=\"{NAMESPACE_DSIG}\" xmlns:unused=\"urn:unused\">{respelled}</outer>"
        );
        let document = XmlDocument::parse(wrapper.into_bytes()).expect("parses");
        let signed_info = document.root().children().next().expect("SignedInfo");
        assert_eq!(
            signed_info.canonicalize(Comments::Omitted),
            plan.signed_info()
        );

        let file = self::document().replace(canonical, &respelled);
        assert!(judged(&objects(), &file).document_intact());
    }

    /// Respell canonical `SignedInfo` text without changing its
    /// canonical form.
    fn respell(canonical: &str) -> String {
        let declaration = format!(" xmlns:ds=\"{NAMESPACE_DSIG}\"");
        let mut text = canonical.replacen(&declaration, "", 1);
        for element in [
            "CanonicalizationMethod",
            "SignatureMethod",
            "DigestMethod",
            "Transform",
        ] {
            text = text.replace(&format!("></ds:{element}>"), " />");
        }
        text = text.replace(
            "<ds:Reference Id=\"SIG-1-REF-0\" URI=\"dossier.pdf\">",
            "<ds:Reference\n  URI='dossier.pdf'\tId = 'SIG-1-REF-0' >",
        );
        text.replace("<ds:SignedInfo>", "<ds:SignedInfo >")
    }

    /// Each `SignatureTimeStamp` token comes out with the canonical
    /// `SignatureValue` it must imprint; one naming no canonicalisation
    /// has no imprint input; an `ArchiveTimeStamp` is counted apart.
    #[test]
    fn signature_timestamps_are_collected_with_their_imprint_input() {
        let tokens = vec![FIRST_TOKEN.to_vec(), SECOND_TOKEN.to_vec()];
        let document = document_with(&tokens, &ValidationMaterial::default());
        let unnamed = format!(
            "<xades:SignatureTimeStamp><xades:EncapsulatedTimeStamp>{}\
             </xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>\n",
            base64::encode(b"unnamed canonicalisation")
        );
        let archive = format!(
            "<xades141:ArchiveTimeStamp xmlns:xades141=\"{NAMESPACE_XADES_141}\">\
             <ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/>\
             <xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp>\
             </xades141:ArchiveTimeStamp>\n</xades:UnsignedSignatureProperties>",
            base64::encode(FIRST_TOKEN)
        );
        let extended = document.replace(
            "</xades:UnsignedSignatureProperties>",
            &format!("{unnamed}{archive}"),
        );

        let (container, signature) = read(&objects(), &extended);
        let expected = SignaturePlan::signature_value_element(UNSIGNED_VALUE);
        let collected = signature.signature_timestamps();
        let [first, second, unnamed] = exactly(collected, "three signature timestamps");
        assert_eq!(first.token(), FIRST_TOKEN);
        assert_eq!(second.token(), SECOND_TOKEN);
        assert_eq!(first.imprint_input(), Some(expected.as_bytes()));
        assert_eq!(second.imprint_input(), Some(expected.as_bytes()));
        assert_eq!(unnamed.imprint_input(), None);
        let judgement = supported(signature.verify(&container));
        assert!(judgement.document_intact());
        assert_eq!(judgement.signature_timestamps_present(), collected.len());
        assert_eq!(judgement.archive_timestamps_present(), 1);
    }

    #[test]
    fn validation_material_is_read_from_the_unsigned_properties() {
        let material = ValidationMaterial {
            certificates: vec![b"issuer certificate".to_vec()],
            ocsp_responses: vec![b"ocsp response".to_vec()],
            crls: vec![b"crl".to_vec()],
        };
        let (_container, signature) = read(&objects(), &document_with(&[], &material));
        assert_eq!(signature.embedded_material(), &material);
        assert_eq!(
            signature.embedded_certificates(),
            [CERTIFICATE_DER, b"issuer certificate".as_slice()]
        );
    }

    #[test]
    fn another_signed_info_canonicalisation_is_unsupported() {
        let method =
            format!("<ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\">");
        let inclusive = document().replacen(
            &method,
            &format!("<ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_INCLUSIVE_11}\">"),
            1,
        );
        let (container, signature) = read(&objects(), &inclusive);
        assert_eq!(
            signature.verify(&container),
            XadesVerdict::Unsupported(XadesUnsupported::SignedInfoCanonicalization)
        );

        let prefix_list = document().replacen(
            &format!("{method}</ds:CanonicalizationMethod>"),
            &format!(
                "{method}<ec:InclusiveNamespaces xmlns:ec=\"{CANONICALIZATION_EXCLUSIVE}\" \
                 PrefixList=\"ds\"/></ds:CanonicalizationMethod>"
            ),
            1,
        );
        let (container, signature) = read(&objects(), &prefix_list);
        assert!(
            matches!(signature.verify(&container), XadesVerdict::Judged(_)),
            "a prefix list is read and applied"
        );

        let other_child = document().replacen(
            &format!("{method}</ds:CanonicalizationMethod>"),
            &format!("{method}<other/></ds:CanonicalizationMethod>"),
            1,
        );
        let (container, signature) = read(&objects(), &other_child);
        assert_eq!(
            signature.verify(&container),
            XadesVerdict::Unsupported(XadesUnsupported::SignedInfoCanonicalization)
        );
    }

    #[test]
    fn a_file_without_a_signature_is_refused() {
        let container = container(&objects(), "<other/>");
        assert_eq!(
            signatures(&container).err(),
            Some(XadesReadError::NoSignature)
        );
    }

    #[test]
    fn a_repeated_id_is_refused() {
        let repeated = document().replace("Id=\"SIG-1-REF-1\"", "Id=\"SIG-1-REF-0\"");
        let container = container(&objects(), &repeated);
        assert_eq!(
            signatures(&container).err(),
            Some(XadesReadError::Xml(XmlError::Malformed("duplicate Id")))
        );
    }

    #[test]
    fn a_certificate_digest_of_the_wrong_length_is_malformed() {
        let document = document();
        let certificate_digest = digest(CERTIFICATE_DER);
        let truncated = document.replace(&certificate_digest, &base64::encode(b"short"));
        assert!(truncated.as_str() != document);
        let container = container(&objects(), &truncated);
        let read = signatures(&container).expect("the file reads");
        let [only] = exactly(&read, "one signature");
        assert_eq!(
            only.as_ref().err(),
            Some(&XadesReadError::Malformed(
                "SigningCertificate without a readable CertDigest"
            ))
        );
    }

    /// One malformed signature leaves the others in the same file
    /// readable.
    #[test]
    fn a_malformed_signature_does_not_hide_its_neighbours() {
        let document = document();
        let signature = element(&document, "<ds:Signature", "</ds:Signature>");
        let neighbour = signature
            .replace("SIG-1", "SIG-2")
            .replace(&digest(CERTIFICATE_DER), &base64::encode(b"short"));
        let file = document.replacen(signature, &format!("{signature}{neighbour}"), 1);
        let container = container(&objects(), &file);
        let read = signatures(&container).expect("the file reads");
        let [first, second] = exactly(&read, "two signatures");
        assert!(first.is_ok());
        assert!(matches!(second, Err(XadesReadError::Malformed(_))));
    }

    #[test]
    fn a_signature_value_wrapped_over_lines_decodes() {
        let encoded = base64::encode(UNSIGNED_VALUE);
        let (head, tail) = encoded.split_at(WRAP_COLUMN);
        let wrapped = document().replace(&encoded, &format!("{head}\n{tail}"));
        assert!(judged(&objects(), &wrapped).document_intact());
    }

    /// A synthetic signing time, inside every kit certificate's validity.
    const KIT_SIGNING_TIME: SigningTime = SigningTime {
        year: 2026,
        month: 6,
        day: KIT_SIGNED_DAY,
        hour: KIT_HOUR,
        minute: 0,
        second: 0,
    };

    /// The day kit certificates start.
    const KIT_FIRST_DAY: u8 = 1;
    /// The day kit signatures and timestamps are made.
    const KIT_SIGNED_DAY: u8 = 10;
    /// The day kit certificates end.
    const KIT_LAST_DAY: u8 = 28;
    /// The hour of every kit instant.
    const KIT_HOUR: u8 = 12;
    /// Serial of the kit signer.
    const KIT_SIGNER_SERIAL: u8 = 1;
    /// Serial of the kit TSA.
    const KIT_TSA_SERIAL: u8 = 2;
    /// The salt of the kit RSA-PSS signature.
    const KIT_PSS_SALT: &[u8; kit::PSS_SALT_LEN] = b"synthetic RSA-PSS salt, 32 bytes";

    /// A self-issued kit certificate named `common_name` for `key`.
    fn kit_certificate(key: &TestKey, common_name: &str, extensions: Vec<Vec<u8>>) -> Vec<u8> {
        kit::certificate(
            &kit::CertificateSpec {
                serial: KIT_SIGNER_SERIAL,
                subject: common_name,
                issuer: common_name,
                not_before: kit::day(KIT_FIRST_DAY),
                not_after: kit::day(KIT_LAST_DAY),
                extensions,
            },
            key,
            key,
        )
    }

    /// The writer's signature file over [`objects`], really signed by
    /// `key` under `certificate`, with `timestamps` over its value.
    fn signed_document(
        key: &TestKey,
        certificate: &[u8],
        timestamps: impl FnOnce(&[u8]) -> Vec<Vec<u8>>,
    ) -> String {
        let owned = OwnedCert::from_der(certificate).expect("kit certificate parses");
        let view = owned.view();
        let parameters = SignerParameters {
            certificate: &view,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: crate::testkit::cades_algorithm(key),
            signing_time: Some(KIT_SIGNING_TIME),
        };
        let plan = plan(&objects(), &parameters).expect("plan");
        let value = key.sign_raw(plan.signed_info());
        let tokens = timestamps(&value);
        String::from_utf8(plan.finish(&value, &tokens, &ValidationMaterial::default()))
            .expect("utf-8")
    }

    /// `document` with its `SignatureValue` replaced by `sign` over the
    /// canonical `SignedInfo` the document now carries.
    fn resign(document: &str, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> String {
        let parsed = XmlDocument::parse(document.as_bytes().to_vec()).expect("parses");
        let signed_info = parsed
            .elements()
            .find(|element| element.is(NAMESPACE_DSIG, "SignedInfo"))
            .expect("SignedInfo")
            .canonicalize(Comments::Omitted);
        let value = element(document, "<ds:SignatureValue", "</ds:SignatureValue>");
        let open_end = value.find('>').expect("start tag ends") + 1;
        let text = &value[open_end..value.len() - "</ds:SignatureValue>".len()];
        document.replace(text, &base64::encode(&sign(&signed_info)))
    }

    /// `document` with one octet of its signature value changed.
    fn flipped(document: &str) -> String {
        let value = element(document, "<ds:SignatureValue", "</ds:SignatureValue>");
        let open_end = value.find('>').expect("start tag ends") + 1;
        let text = &value[open_end..value.len() - "</ds:SignatureValue>".len()];
        let mut octets = base64::decode_wrapped(text).expect("base64");
        let last = octets.last_mut().expect("a signature value");
        *last = last.wrapping_add(1);
        document.replace(text, &base64::encode(&octets))
    }

    /// A P-256 kit key and its certificate.
    fn ecdsa_signer() -> (TestKey, Vec<u8>) {
        let key = TestKey::derive(TestCurve::P256, b"xades signer");
        let certificate = kit_certificate(&key, "XAdES ECDSA Signer", Vec::new());
        (key, certificate)
    }

    /// The RFC 9500 RSA key and its certificate.
    fn rsa_signer() -> (TestKey, Vec<u8>) {
        let key = TestKey::rsa_2048();
        let certificate = kit_certificate(&key, "XAdES RSA Signer", Vec::new());
        (key, certificate)
    }

    #[test]
    fn our_rsa_signature_is_intact_and_valid() {
        let (key, certificate) = rsa_signer();
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let judgement = judged(&objects(), &document);
        assert!(judgement.document_intact());
        assert!(judgement.signature_valid());
    }

    #[test]
    fn a_sha_512_reference_recomputes() {
        let (key, certificate) = ecdsa_signer();
        let owned = OwnedCert::from_der(&certificate).expect("kit certificate parses");
        let view = owned.view();
        let parameters = SignerParameters {
            certificate: &view,
            digest_algorithm: DigestAlgorithm::Sha512,
            signature_algorithm: crate::testkit::cades_algorithm(&key),
            signing_time: Some(KIT_SIGNING_TIME),
        };
        let plan = plan(&objects(), &parameters).expect("plan");
        let value = key.sign_raw(plan.signed_info());
        let document = String::from_utf8(plan.finish(&value, &[], &ValidationMaterial::default()))
            .expect("utf-8");
        assert!(document.contains(super::DIGEST_METHOD_SHA512));
        let judgement = judged(&objects(), &document);
        assert!(judgement.document_intact());
        assert!(judgement.signature_valid());

        let mut changed = objects();
        changed[0].content = b"a different declaration".to_vec();
        assert!(!judged(&changed, &document).document_intact());
    }

    #[test]
    fn our_ecdsa_signature_is_intact_and_valid() {
        let (key, certificate) = ecdsa_signer();
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let (container, signature) = read(&objects(), &document);
        assert_eq!(
            signature.signer_certificate().map(OwnedCert::as_der),
            Some(certificate.as_slice())
        );
        let judgement = supported(signature.verify(&container));
        assert!(judgement.document_intact());
        assert!(judgement.signature_valid());
    }

    #[test]
    fn a_third_party_rsa_pss_signature_verifies() {
        let (key, certificate) = rsa_signer();
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let pss = document.replacen(
            SIGNATURE_METHOD_RSA_SHA256,
            super::SIGNATURE_METHOD_RSA_PSS_SHA256,
            1,
        );
        let pss = resign(&pss, |signed_info| {
            key.sign_pss_sha256(signed_info, KIT_PSS_SALT)
                .expect("an RSA key signs PSS")
        });
        let judgement = judged(&objects(), &pss);
        assert!(judgement.document_intact());
        assert!(judgement.signature_valid());

        // A PKCS#1 value under the PSS identifier does not verify.
        let mislabelled = document.replacen(
            SIGNATURE_METHOD_RSA_SHA256,
            super::SIGNATURE_METHOD_RSA_PSS_SHA256,
            1,
        );
        let mislabelled = resign(&mislabelled, |signed_info| key.sign(signed_info));
        assert!(!judged(&objects(), &mislabelled).signature_valid());
    }

    #[test]
    fn a_flipped_signature_byte_is_not_valid() {
        let (key, certificate) = ecdsa_signer();
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let judgement = judged(&objects(), &flipped(&document));
        assert!(judgement.document_intact());
        assert!(!judgement.signature_valid());
    }

    #[test]
    fn a_binding_naming_another_certificate_is_not_valid() {
        let (key, certificate) = ecdsa_signer();
        let other = kit_certificate(&key, "Another Holder", Vec::new());
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let rebound = redigest(
            &document,
            |properties| properties.replace(&digest(&certificate), &digest(&other)),
            |signed_info| signed_info.to_owned(),
        );
        let rebound = resign(&rebound, |signed_info| key.sign_raw(signed_info));
        let (container, signature) = read(&objects(), &rebound);
        assert_eq!(
            signature.signer_certificate(),
            None,
            "a binding naming no carried certificate selects no signer"
        );
        let judgement = supported(signature.verify(&container));
        assert!(judgement.document_intact());
        assert!(!judgement.signature_valid());
    }

    #[test]
    fn a_missing_signing_certificate_is_not_valid() {
        let (key, certificate) = ecdsa_signer();
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let unbound = redigest(
            &document,
            |properties| {
                let binding = element(
                    properties,
                    "<xades:SigningCertificateV2>",
                    "</xades:SigningCertificateV2>",
                );
                properties.replace(binding, "")
            },
            |signed_info| signed_info.to_owned(),
        );
        assert!(!unbound.contains("SigningCertificate"));
        let unbound = resign(&unbound, |signed_info| key.sign_raw(signed_info));
        let judgement = judged(&objects(), &unbound);
        assert!(judgement.document_intact());
        assert!(!judgement.signature_valid());
    }

    #[test]
    fn signature_timestamps_verify_and_archive_timestamps_are_counted() {
        let (key, certificate) = ecdsa_signer();
        let tsa_key = TestKey::derive(TestCurve::P256, b"xades tsa");
        let tsa = kit::certificate(
            &kit::CertificateSpec {
                serial: KIT_TSA_SERIAL,
                subject: "XAdES Time Stamping Unit",
                issuer: "XAdES Time Stamping Unit",
                not_before: kit::day(KIT_FIRST_DAY),
                not_after: kit::day(KIT_LAST_DAY),
                extensions: kit::timestamping_extensions(),
            },
            &tsa_key,
            &tsa_key,
        );
        let document = signed_document(&key, &certificate, |value| {
            vec![crate::testkit::timestamp_token(
                &tsa,
                &tsa_key,
                DigestAlgorithm::Sha256,
                &SignaturePlan::timestamp_digest(value, DigestAlgorithm::Sha256),
                kit::day(KIT_SIGNED_DAY),
            )]
        });
        let archive = format!(
            "<xades141:ArchiveTimeStamp xmlns:xades141=\"{NAMESPACE_XADES_141}\">\
             <ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/>\
             <xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp>\
             </xades141:ArchiveTimeStamp>\n</xades:UnsignedSignatureProperties>",
            base64::encode(FIRST_TOKEN)
        );
        let archived = document.replace("</xades:UnsignedSignatureProperties>", &archive);
        let (container, signature) = read(&objects(), &archived);
        let [timestamp] = exactly(signature.signature_timestamps(), "one signature timestamp");
        let input = timestamp
            .imprint_input()
            .expect("exclusive canonicalisation");
        let verified =
            crate::timestamp::verify_token(timestamp.token(), |algorithm| algorithm.digest(input))
                .expect("the signature timestamp verifies");
        assert_eq!(verified.generated_at(), kit::day(KIT_SIGNED_DAY));
        let judgement = supported(signature.verify(&container));
        assert!(judgement.signature_valid());
        assert_eq!(judgement.signature_timestamps_present(), 1);
        assert_eq!(judgement.archive_timestamps_present(), 1);
    }

    #[test]
    fn a_modified_data_file_leaves_the_signature_valid() {
        let (key, certificate) = ecdsa_signer();
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let mut changed = objects();
        changed[0].content = b"a different declaration".to_vec();
        let judgement = judged(&changed, &document);
        assert!(!judgement.document_intact());
        assert!(judgement.signature_valid());
    }

    #[test]
    fn a_respelled_signed_info_still_verifies() {
        let (key, certificate) = ecdsa_signer();
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let canonical = element(&document, "<ds:SignedInfo", "</ds:SignedInfo>").to_owned();
        let respelled = document.replace(&canonical, &respell(&canonical));
        assert!(respelled != document);
        let judgement = judged(&objects(), &respelled);
        assert!(judgement.document_intact());
        assert!(judgement.signature_valid());
    }

    #[test]
    fn a_with_comments_reference_resigned_verifies() {
        let (key, certificate) = ecdsa_signer();
        let document = signed_document(&key, &certificate, |_value| Vec::new());
        let open = "<xades:SignedSignatureProperties>";
        let with_comment = redigest(
            &document,
            |properties| properties.replacen(open, &format!("{open}<!-- a note -->"), 1),
            |signed_info| {
                signed_info.replace(
                    &format!("<ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\">"),
                    &format!("<ds:Transform Algorithm=\"{CANONICALIZATION_EXCLUSIVE_COMMENTS}\">"),
                )
            },
        );
        assert!(!judged(&objects(), &with_comment).signature_valid());
        let resigned = resign(&with_comment, |signed_info| key.sign_raw(signed_info));
        let judgement = judged(&objects(), &resigned);
        assert!(judgement.document_intact());
        assert!(judgement.signature_valid());
    }
}
