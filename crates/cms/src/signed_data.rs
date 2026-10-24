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

//! CMS `SignedData` parser (RFC 5652), scoped to one-signer
//! verification.
//!
//! Surface:
//!
//! - [`SignedData::parse`] -- accepts either the bare
//!   `SignedData` SEQUENCE or the outer `ContentInfo`-wrapped
//!   form.
//! - [`SignedData`] holds the encapsulated content
//!   (`econtent_der`), the embedded certificates, and the sole
//!   signerInfo's signature material.
//! - [`SignedData::verify`] verifies the signerInfo's signature
//!   against a supplied signer public key. Handles
//!   both the "signedAttrs present" path (sign over DER(SET OF
//!   attrs)) and the "signedAttrs absent" path (sign over
//!   eContent directly).
//!
//! Not in scope: countersignatures and non-X.509 certificate
//! choices. Multiple signerInfos are rejected because every
//! caller in this crate verifies one unambiguous signer.

use refineid_ber::{
    BerTag, BerTlv, BerTlvAny, BerTlvIter, Integer, OctetString, Oid, Sequence, Set,
};

/// `[0] EXPLICIT` (the constructed context-class tag, number 0).
///
/// The CMS context-specific wrapper used in
/// `ContentInfo.content`, `SignedData.certificates`, and
/// `SignerInfo.signedAttrs` (RFC 5652 §3 / §5). The byte is
/// the same in all three contexts; the parent structure
/// decides the semantic.
#[derive(Debug, Clone, Copy)]
pub struct Asn1ContentExplicit0;
impl BerTag for Asn1ContentExplicit0 {
    const TAG: u16 = 0xA0;
}

/// `[1] IMPLICIT` (the constructed context-class tag, number 1).
#[derive(Debug, Clone, Copy)]
struct Asn1ContentImplicit1;
impl BerTag for Asn1ContentImplicit1 {
    const TAG: u16 = 0xA1;
}

/// `SignerIdentifier.subjectKeyIdentifier [0] IMPLICIT OCTET STRING`.
#[derive(Debug, Clone, Copy)]
struct SignerSubjectKeyIdentifier;
impl BerTag for SignerSubjectKeyIdentifier {
    const TAG: u16 = 0x80;
}
use crate::container::{EcdsaDer, RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512, Signature};
use crate::ecdsa::{self, EcdsaError};
use crate::oid::known;
use crate::rsa::{RsaPublicKey, RsaVerifyError, verify_pkcs1v15_sha384, verify_pkcs1v15_sha512};
use crate::x509::{X509Error, extract_rsa_public_key};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

// OID values are the typed `oid::known` constants (single source of
// truth); CMS compares them at the byte level via `.as_bytes()`.

// ----- Hash algorithm dispatch -----

/// Hash algorithm dispatch for CMS signer verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (OID `2.16.840.1.101.3.4.2.1`).
    Sha256,
    /// SHA-384 (OID `2.16.840.1.101.3.4.2.2`).
    Sha384,
    /// SHA-512 (OID `2.16.840.1.101.3.4.2.3`).
    Sha512,
}

impl HashAlgorithm {
    /// Decode an OID body into the typed enum. `None` for any
    /// OID that isn't one of the three SHA-2 variants refineid
    /// supports.
    #[must_use]
    pub fn from_oid(oid: crate::oid::Oid<'_>) -> Option<Self> {
        match oid.as_bytes() {
            v if v == known::SHA256.as_bytes() => Some(Self::Sha256),
            v if v == known::SHA384.as_bytes() => Some(Self::Sha384),
            v if v == known::SHA512.as_bytes() => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Compute the digest of `data` under this algorithm.
    /// Returns the raw output bytes (32 / 48 / 64 bytes
    /// respectively).
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let bytes = data;
        match self {
            Self::Sha256 => {
                let mut h = Sha256::new();
                h.update(bytes);
                h.finalize().to_vec()
            }
            Self::Sha384 => {
                let mut h = Sha384::new();
                h.update(bytes);
                h.finalize().to_vec()
            }
            Self::Sha512 => {
                let mut h = Sha512::new();
                h.update(bytes);
                h.finalize().to_vec()
            }
        }
    }

    /// Human-readable label ("SHA-256" / "SHA-384" / "SHA-512")
    /// used for diagnostic output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
}

// ----- SignedData public surface -----

/// Error returned from the CMS parser / verifier.
///
/// Variant sizes differ deliberately: `UnexpectedStructure` carries
/// a 16-byte `&'static str` fat pointer while the other payload
/// variants stay near pointer size. Boxing the static-str pointer
/// would add an indirection without meaningfully shrinking the
/// type's stack footprint, and the message-naming-the-shape pattern
/// is consistent with `X509Error` / `EmrtdError` elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsError {
    /// BER / TLV decode failure during structural parse.
    Ber(refineid_ber::BerError),
    /// Structural shape mismatch (wrong tag, wrong nesting,
    /// missing required field). Tier 0 `&'static str` from a
    /// fixed compile-time set naming the unexpected sub-shape.
    UnexpectedStructure(&'static str),
    /// `digestAlgorithm` OID didn't match the SHA-2 variants
    /// refineid supports ([`HashAlgorithm`]).
    UnsupportedDigestAlgorithm,
    /// `signatureAlgorithm` OID didn't match the RSA / ECDSA
    /// variants refineid supports.
    UnsupportedSignatureAlgorithm,
    /// Signer cert exists but its SPKI didn't parse into a
    /// supported RSA / ECDSA key.
    BadSignerKey,
    /// `messageDigest` signed attribute didn't equal
    /// `Hash(eContent)`. Signature wasn't verified after this
    /// check failed (one of two PA preconditions per RFC 5652).
    SignerHashMismatch,
    /// RSA signature verification (against the signer's
    /// PKCS#1 v1.5 key) failed.
    Rsa(RsaVerifyError),
    /// ECDSA signature verification (against the signer's
    /// SEC1 uncompressed point) failed.
    Ecdsa(EcdsaError),
}

impl From<refineid_ber::BerError> for CmsError {
    fn from(e: refineid_ber::BerError) -> Self {
        Self::Ber(e)
    }
}

impl From<X509Error> for CmsError {
    fn from(_e: X509Error) -> Self {
        Self::UnexpectedStructure("x509 sub-parse failed")
    }
}

impl core::fmt::Display for CmsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ber(e) => write!(f, "CMS BER: {e}"),
            Self::UnexpectedStructure(s) => write!(f, "CMS: {s}"),
            Self::UnsupportedDigestAlgorithm => write!(f, "CMS: unsupported digest algorithm"),
            Self::UnsupportedSignatureAlgorithm => {
                write!(f, "CMS: unsupported signature algorithm")
            }
            Self::BadSignerKey => write!(f, "CMS: signer key did not parse as RSA"),
            Self::SignerHashMismatch => write!(f, "CMS: messageDigest attr != hash(eContent)"),
            Self::Rsa(e) => write!(f, "CMS: RSA verify: {e}"),
            Self::Ecdsa(e) => write!(f, "CMS: ECDSA verify: {e}"),
        }
    }
}

impl core::error::Error for CmsError {}

/// Parsed subset of a CMS `SignedData` value sufficient for
/// one-signer verification.
#[derive(Debug, Clone)]
pub struct SignedData<'a> {
    /// Inner `EncapsulatedContentInfo.eContentType` OID.
    /// Typed via [`crate::oid::Oid`] -- the BER parser validates
    /// the OID structure at the trust boundary, so consumers
    /// never compare against arbitrary `&[u8]`.
    pub econtent_type_oid: crate::oid::Oid<'a>,
    /// Inner `eContent` OCTET STRING value bytes.
    pub econtent_der: &'a [u8],
    /// Embedded certificates (typically the signer certificate
    /// and its issuers). Each entry is the raw DER of one cert
    /// SEQUENCE.
    pub certificates_der: Vec<&'a [u8]>,
    /// The sole signerInfo's fields.
    pub signer: SignerInfo<'a>,
}

/// CMS `SignerIdentifier` (RFC 5652 sec.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerIdentifier<'a> {
    /// Issuer `Name` DER and certificate serial-number INTEGER body.
    IssuerAndSerialNumber {
        /// Full DER encoding of the issuer `Name`.
        issuer_der: &'a [u8],
        /// INTEGER value bytes of the certificate serial number.
        serial_number: &'a [u8],
    },
    /// Subject-key-identifier extension value.
    SubjectKeyIdentifier(&'a [u8]),
}

/// A structurally validated CMS attribute retained for profile-specific
/// consumers such as RFC 3161 ESS certificate binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedAttribute<'a> {
    /// Attribute type OID.
    pub oid: crate::oid::Oid<'a>,
    /// Contents of the attribute's `SET OF AttributeValue`.
    pub values_der: &'a [u8],
}

/// Parsed subset of CMS `SignerInfo` (RFC 5652 §5.3) required
/// to verify a signature against the embedded signer cert.
#[derive(Debug, Clone)]
pub struct SignerInfo<'a> {
    /// Certificate identifier carried by the signerInfo.
    pub signer_identifier: SignerIdentifier<'a>,
    /// `digestAlgorithm` OID body. Typed via [`crate::oid::Oid`].
    pub digest_algorithm_oid: crate::oid::Oid<'a>,
    /// `signatureAlgorithm` OID body. Typed via [`crate::oid::Oid`].
    pub signature_algorithm_oid: crate::oid::Oid<'a>,
    /// Signature value bytes (raw, no BIT STRING wrapper).
    pub signature: &'a [u8],
    /// If `signedAttrs` was present, the DER bytes of the
    /// **re-tagged** `SET OF Attribute` -- exactly the data the
    /// signature was computed over (RFC 5652 sec.5.4). `None`
    /// means "signature was computed directly over eContent".
    pub signed_data_to_verify: Option<Vec<u8>>,
    /// Signed attributes, in their encoded order. Empty when the
    /// signerInfo has no signed attributes.
    pub signed_attributes: Vec<SignedAttribute<'a>>,
    /// `messageDigest` attribute value, when `signedAttrs` was
    /// present. Used to cross-check that the signer's commitment
    /// to the eContent hash matches what we'd compute ourselves.
    pub message_digest: Option<&'a [u8]>,
}

/// Owning wrapper around a parsed CMS `SignedData`.
///
/// Same pattern as [`crate::x509::OwnedCert`]: holds the input DER
/// plus a re-parseable view. Public entry point under
/// typing-discipline rule D; free `parse_signed_data` is
/// `pub(crate)` because it returns a borrowed view tied to the
/// input.
#[derive(Debug, Clone)]
pub struct OwnedSignedData {
    /// `der` field.
    der: Vec<u8>,
}

impl OwnedSignedData {
    /// Parse `der` as a CMS `SignedData` (accepting the
    /// bare-SEQUENCE and ContentInfo-wrapped forms), allocating an
    /// owned copy.
    ///
    /// # Errors
    /// [`CmsError`] from the CMS parser.
    pub fn from_der(der: &[u8]) -> Result<Self, CmsError> {
        let bytes = der.as_ref().to_vec();
        // Validate-only parse: the borrowed `SignedData` is
        // discarded immediately; we'll re-parse on every `view()`
        // call so the borrowed shape stays tied to `self.der`.
        // Explicit `drop` (instead of `let _ =`) names what's
        // happening to the value owning the certificate-slice
        // `Vec` and the SignerInfo allocations.
        drop(SignedData::parse(&bytes)?);
        Ok(Self { der: bytes })
    }

    /// Re-parse the owned DER and hand back the borrowed view.
    ///
    /// # Performance
    /// Parses the DER on **every call** (O(n) in the DER length). For
    /// repeated field access bind the view once (`let sd = owned.view();`)
    /// and reuse it, rather than calling `view()` per field.
    ///
    /// # Panics
    /// Never -- [`from_der`] validated at construction.
    ///
    /// [`from_der`]: Self::from_der.
    #[must_use]
    pub fn view(&self) -> SignedData<'_> {
        SignedData::parse(&self.der)
            .expect("OwnedSignedData: from_der validated DER at construction")
    }

    /// Raw DER bytes.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

impl<'a> SignedData<'a> {
    /// Parse a CMS `SignedData` from raw DER (RFC 5652 §5.1).
    /// Accepts:
    ///   1. Bare `SignedData` SEQUENCE,
    ///   2. `ContentInfo` wrapping `SignedData` (RFC 5652 §3).
    ///
    /// The detection is by the outer tag byte; the function never
    /// touches the inner certificate / signature material beyond
    /// borrowing slices from `input` (lifetime-tied output).
    pub fn parse(input: &'a [u8]) -> Result<Self, CmsError> {
        // `split_first` fuses the empty-input check and the first-byte
        // peek into one pattern, leaving no bare indexing on `input[0]`.
        let Some((&first, _rest)) = input.split_first() else {
            return Err(CmsError::UnexpectedStructure("empty input"));
        };
        let signed_data_body = match u16::from(first) {
            // SEQUENCE -- either ContentInfo or a bare SignedData.
            <Sequence as BerTag>::TAG => {
                let outer =
                    CmsHelpers::parse_exact::<Sequence>(input, "trailing bytes after CMS value")?;
                let mut it = BerTlvIter::new(outer.value());
                let first_any = it.next().ok_or(CmsError::UnexpectedStructure("empty"))??;
                if first_any.tag() == <Oid as BerTag>::TAG {
                    CmsHelpers::decode_content_info(&ContentInfoDer { input })?
                } else {
                    // A bare SignedData starts with its INTEGER version;
                    // ContentInfo starts with an OID.
                    outer.value()
                }
            }
            _ => return Err(CmsError::UnexpectedStructure("unknown wrapper tag")),
        };
        CmsHelpers::parse_signed_data_body(&SignedDataBody {
            body: signed_data_body,
        })
    }
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CmsHelpers;

/// `ContentInfo` DER wrapper for CMS parser helpers.
struct ContentInfoDer<'a> {
    /// `ContentInfo` DER bytes.
    input: &'a [u8],
}

/// `SignedData` body bytes.
struct SignedDataBody<'a> {
    /// Inner `SignedData` `SEQUENCE` value bytes.
    body: &'a [u8],
}

/// `SignerInfo` body bytes.
struct SignerInfoBody<'a> {
    /// Inner `SignerInfo` `SEQUENCE` value bytes.
    body: &'a [u8],
}

/// Parsed mandatory fields from a signed-attribute set.
struct ParsedSignedAttributes<'a> {
    /// All attributes, retained for profile-specific validation.
    attributes: Vec<SignedAttribute<'a>>,
    /// Unique `contentType` value.
    content_type: Option<crate::oid::Oid<'a>>,
    /// Unique `messageDigest` value.
    message_digest: Option<&'a [u8]>,
}

impl CmsHelpers {
    /// Parse one typed TLV and reject any bytes after it.
    fn parse_exact<'a, T: BerTag>(
        input: &'a [u8],
        trailing: &'static str,
    ) -> Result<BerTlv<'a, T>, CmsError> {
        let tlv = BerTlv::<T>::parse(input)?;
        if tlv.size() != input.len() {
            return Err(CmsError::UnexpectedStructure(trailing));
        }
        Ok(tlv)
    }

    /// `decode_content_info` associated function.
    fn decode_content_info<'a>(content_info: &ContentInfoDer<'a>) -> Result<&'a [u8], CmsError> {
        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        let outer =
            Self::parse_exact::<Sequence>(content_info.input, "trailing bytes after ContentInfo")?;
        let mut it = BerTlvIter::new(outer.value());
        let oid = it
            .next()
            .ok_or(CmsError::UnexpectedStructure("ContentInfo missing OID"))??
            .expect::<Oid>()
            .or(Err(CmsError::UnexpectedStructure(
                "ContentInfo OID malformed",
            )))?;
        crate::oid::Oid::new(oid.value()).or(Err(CmsError::UnexpectedStructure(
            "ContentInfo OID malformed",
        )))?;
        if oid.value() != known::SIGNED_DATA.as_bytes() {
            return Err(CmsError::UnexpectedStructure("ContentInfo not SignedData"));
        }
        let explicit = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "ContentInfo missing [0] EXPLICIT",
            ))??
            .expect::<Asn1ContentExplicit0>()
            .or(Err(CmsError::UnexpectedStructure(
                "ContentInfo content tag not [0] EXPLICIT",
            )))?;
        if it.next().is_some() {
            return Err(CmsError::UnexpectedStructure(
                "ContentInfo has trailing fields",
            ));
        }
        let inner_sd = Self::parse_exact::<Sequence>(
            explicit.value(),
            "trailing bytes in ContentInfo content",
        )?;
        Ok(inner_sd.value())
    }

    /// `parse_signed_data_body` associated function.
    ///
    /// Deliberately one long function: the `SignedData` grammar is
    /// kept in field order so the ordering and one-signer invariants
    /// remain auditable top to bottom.
    fn parse_signed_data_body<'a>(
        signed_data: &SignedDataBody<'a>,
    ) -> Result<SignedData<'a>, CmsError> {
        let mut it = BerTlvIter::new(signed_data.body);
        let version = it
            .next()
            .ok_or(CmsError::UnexpectedStructure("SignedData missing version"))??
            .expect::<Integer>()
            .or(Err(CmsError::UnexpectedStructure(
                "SignedData version not INTEGER",
            )))?;
        if version.value().is_empty() {
            return Err(CmsError::UnexpectedStructure("SignedData version is empty"));
        }

        let digest_algorithms = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "SignedData missing digestAlgorithms",
            ))??
            .expect::<Set>()
            .or(Err(CmsError::UnexpectedStructure(
                "SignedData digestAlgorithms not SET",
            )))?;
        let digest_algorithm_oids = Self::parse_digest_algorithms(digest_algorithms.value())?;

        let encap = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "SignedData missing encapContentInfo",
            ))??
            .expect::<Sequence>()
            .or(Err(CmsError::UnexpectedStructure(
                "encapContentInfo not SEQUENCE",
            )))?;
        let mut e_it = BerTlvIter::new(encap.value());
        let econtent_type = e_it
            .next()
            .ok_or(CmsError::UnexpectedStructure("encap missing eContentType"))??
            .expect::<Oid>()
            .or(Err(CmsError::UnexpectedStructure("eContentType not OID")))?;
        let econtent_type_oid = crate::oid::Oid::new(econtent_type.value()).or(Err(
            CmsError::UnexpectedStructure("eContentType OID malformed"),
        ))?;
        // `eContent [0] EXPLICIT` is optional: absent means the
        // detached form, where the caller supplies the content by
        // overwriting `econtent_der` before `verify` (the `ASiC`
        // verifier does this with the manifest bytes). Until then
        // the field reads empty, and `verify` fails closed on any
        // signature whose messageDigest does not match empty input.
        let econtent_der = match e_it.next() {
            None => b"".as_slice(),
            Some(field) => {
                let explicit = field?.expect::<Asn1ContentExplicit0>().or(Err(
                    CmsError::UnexpectedStructure("eContent is not [0] EXPLICIT"),
                ))?;
                if e_it.next().is_some() {
                    return Err(CmsError::UnexpectedStructure(
                        "encapContentInfo has trailing fields",
                    ));
                }
                let econtent_octet = Self::parse_exact::<OctetString>(
                    explicit.value(),
                    "trailing bytes in eContent",
                )?;
                econtent_octet.value()
            }
        };

        let mut remaining = Vec::new();
        for tlv in it {
            remaining.push(tlv?);
        }

        let mut field_index = 0_usize;
        let mut certificates_der = Vec::new();
        if remaining
            .get(field_index)
            .is_some_and(|field| field.tag() == <Asn1ContentExplicit0 as BerTag>::TAG)
        {
            let certificates = remaining
                .get(field_index)
                .ok_or(CmsError::UnexpectedStructure("certificates missing"))?;
            certificates_der = Self::parse_certificates(certificates.value())?;
            field_index = field_index.saturating_add(1);
        }
        if remaining
            .get(field_index)
            .is_some_and(|field| field.tag() == <Asn1ContentImplicit1 as BerTag>::TAG)
        {
            let crls = remaining
                .get(field_index)
                .ok_or(CmsError::UnexpectedStructure("crls missing"))?;
            Self::validate_nonempty_tlv_stream(crls.value(), "empty crls field")?;
            field_index = field_index.saturating_add(1);
        }

        let signer_infos = remaining
            .get(field_index)
            .ok_or(CmsError::UnexpectedStructure(
                "SignedData missing signerInfos",
            ))?
            .expect::<Set>()
            .or(Err(CmsError::UnexpectedStructure(
                "SignedData signerInfos not SET",
            )))?;
        field_index = field_index.saturating_add(1);
        if field_index != remaining.len() {
            return Err(CmsError::UnexpectedStructure(
                "SignedData has trailing or out-of-order fields",
            ));
        }

        let mut signers = BerTlvIter::new(signer_infos.value());
        let signer_tlv = signers
            .next()
            .ok_or(CmsError::UnexpectedStructure("signerInfos is empty"))??
            .expect::<Sequence>()
            .or(Err(CmsError::UnexpectedStructure(
                "signerInfo not SEQUENCE",
            )))?;
        match signers.next() {
            None => {}
            Some(Ok(_extra)) => {
                return Err(CmsError::UnexpectedStructure(
                    "SignedData must contain exactly one signerInfo",
                ));
            }
            Some(Err(error)) => return Err(error.into()),
        }
        let signer = Self::parse_signer_info(
            &SignerInfoBody {
                body: signer_tlv.value(),
            },
            econtent_type_oid,
        )?;
        if !digest_algorithm_oids.contains(&signer.digest_algorithm_oid) {
            return Err(CmsError::UnexpectedStructure(
                "signer digestAlgorithm absent from SignedData set",
            ));
        }

        Ok(SignedData {
            econtent_type_oid,
            econtent_der,
            certificates_der,
            signer,
        })
    }

    /// Parse and validate every `AlgorithmIdentifier` in the digest set.
    fn parse_digest_algorithms(
        digest_algorithms: &[u8],
    ) -> Result<Vec<crate::oid::Oid<'_>>, CmsError> {
        let mut algorithms = Vec::new();
        for algorithm in BerTlvIter::new(digest_algorithms) {
            let algorithm =
                algorithm?
                    .expect::<Sequence>()
                    .or(Err(CmsError::UnexpectedStructure(
                        "digestAlgorithms entry not SEQUENCE",
                    )))?;
            algorithms.push(Self::parse_algorithm_identifier(algorithm)?);
        }
        if algorithms.is_empty() {
            return Err(CmsError::UnexpectedStructure("digestAlgorithms is empty"));
        }
        Ok(algorithms)
    }

    /// Parse an `AlgorithmIdentifier` and reject extra children.
    fn parse_algorithm_identifier(
        algorithm: BerTlv<'_, Sequence>,
    ) -> Result<crate::oid::Oid<'_>, CmsError> {
        let mut it = algorithm.iter_children();
        let oid = it
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "AlgorithmIdentifier missing OID",
            ))??
            .expect::<Oid>()
            .or(Err(CmsError::UnexpectedStructure(
                "AlgorithmIdentifier algorithm not OID",
            )))?;
        let oid = crate::oid::Oid::new(oid.value()).or(Err(CmsError::UnexpectedStructure(
            "AlgorithmIdentifier OID malformed",
        )))?;
        if let Some(parameters) = it.next() {
            parameters?;
            if let Some(extra) = it.next() {
                extra?;
                return Err(CmsError::UnexpectedStructure(
                    "AlgorithmIdentifier has trailing fields",
                ));
            }
        }
        Ok(oid)
    }

    /// Collect direct X.509 `Certificate` choices and reject every other
    /// `CertificateChoices` alternative rather than silently truncating.
    fn parse_certificates(certificates: &[u8]) -> Result<Vec<&[u8]>, CmsError> {
        if certificates.is_empty() {
            return Err(CmsError::UnexpectedStructure("empty certificates field"));
        }
        let mut result = Vec::new();
        let mut cursor = 0_usize;
        while cursor < certificates.len() {
            let tail = certificates
                .get(cursor..)
                .ok_or(CmsError::UnexpectedStructure("certificate cursor invalid"))?;
            let certificate = BerTlvAny::parse(tail)?;
            if certificate.tag() != <Sequence as BerTag>::TAG {
                return Err(CmsError::UnexpectedStructure(
                    "unsupported CMS CertificateChoices entry",
                ));
            }
            let end = cursor.saturating_add(certificate.size());
            let certificate_der = certificates
                .get(cursor..end)
                .ok_or(CmsError::UnexpectedStructure("certificate truncated"))?;
            result.push(certificate_der);
            cursor = end;
        }
        Ok(result)
    }

    /// Require a constructed IMPLICIT field to contain complete TLVs.
    fn validate_nonempty_tlv_stream(values: &[u8], empty: &'static str) -> Result<(), CmsError> {
        let mut count = 0_usize;
        for value in BerTlvIter::new(values) {
            value?;
            count = count.saturating_add(1);
        }
        if count == 0 {
            return Err(CmsError::UnexpectedStructure(empty));
        }
        Ok(())
    }

    /// `parse_signer_info` associated function.
    fn parse_signer_info<'a>(
        signer_info: &SignerInfoBody<'a>,
        expected_content_type: crate::oid::Oid<'a>,
    ) -> Result<SignerInfo<'a>, CmsError> {
        let mut children = BerTlvIter::new(signer_info.body);
        let version = children
            .next()
            .ok_or(CmsError::UnexpectedStructure("signerInfo missing version"))??
            .expect::<Integer>()
            .or(Err(CmsError::UnexpectedStructure(
                "signerInfo version not INTEGER",
            )))?;
        let sid = children
            .next()
            .ok_or(CmsError::UnexpectedStructure("signerInfo missing sid"))??;
        let signer_identifier = Self::parse_signer_identifier(sid, version.value())?;

        let digest_alg_seq = children
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "signerInfo missing digestAlgorithm",
            ))??
            .expect::<Sequence>()
            .or(Err(CmsError::UnexpectedStructure(
                "digestAlgorithm not SEQUENCE",
            )))?;
        let digest_algorithm_oid = Self::parse_algorithm_identifier(digest_alg_seq)?;

        let after_digest = children.next().ok_or(CmsError::UnexpectedStructure(
            "signerInfo missing signature material",
        ))??;
        let (signed_attrs_value, signature_algorithm) =
            if after_digest.tag() == <Asn1ContentExplicit0 as BerTag>::TAG {
                let signature_algorithm = children.next().ok_or(
                    CmsError::UnexpectedStructure("signerInfo missing signatureAlgorithm"),
                )??;
                (Some(after_digest.value()), signature_algorithm)
            } else {
                (None, after_digest)
            };
        let sig_alg_seq =
            signature_algorithm
                .expect::<Sequence>()
                .or(Err(CmsError::UnexpectedStructure(
                    "signatureAlgorithm not SEQUENCE",
                )))?;
        let signature_algorithm_oid = Self::parse_algorithm_identifier(sig_alg_seq)?;
        let sig_octet = children
            .next()
            .ok_or(CmsError::UnexpectedStructure(
                "signerInfo missing signature material",
            ))??
            .expect::<OctetString>()
            .or(Err(CmsError::UnexpectedStructure(
                "signature not OCTET STRING",
            )))?;
        let signature = sig_octet.value();

        if let Some(unsigned_attrs) = children.next() {
            let unsigned_attrs = unsigned_attrs?;
            if unsigned_attrs.tag() != <Asn1ContentImplicit1 as BerTag>::TAG {
                return Err(CmsError::UnexpectedStructure(
                    "signerInfo trailing field is not unsignedAttrs",
                ));
            }
            let _discarded = Self::parse_attributes(unsigned_attrs.value(), false)?;
        }
        if children.next().is_some() {
            return Err(CmsError::UnexpectedStructure(
                "signerInfo has trailing fields",
            ));
        }

        // signedAttrs handling: per RFC 5652 sec.5.4, when present the
        // signature is over DER(SET OF signed_attrs). The [0] IMPLICIT
        // tag is re-encoded as a SET (the universal SET tag) for
        // digest purposes.
        let (signed_data_to_verify, signed_attributes, message_digest) =
            if let Some(attrs_value) = signed_attrs_value {
                // Re-encode as SET: tag + length + value, with the
                // tag byte drawn from `Set::TAG` (the named universal
                // SET tag constant); `to_be_bytes()` lets us grab the
                // low byte directly without a fallible
                // `u8::try_from(u16)`.
                let [_high, set_tag_lo] = <Set as BerTag>::TAG.to_be_bytes();
                let rebuilt = refineid_ber::tlv(set_tag_lo, attrs_value).or(Err(
                    CmsError::UnexpectedStructure("signedAttrs exceed the DER length bound"),
                ))?;
                let parsed = Self::parse_attributes(attrs_value, true)?;
                if parsed.content_type != Some(expected_content_type) {
                    return Err(CmsError::UnexpectedStructure(
                        "signed contentType does not match eContentType",
                    ));
                }
                (Some(rebuilt), parsed.attributes, parsed.message_digest)
            } else {
                (None, Vec::new(), None)
            };
        Ok(SignerInfo {
            signer_identifier,
            digest_algorithm_oid,
            signature_algorithm_oid,
            signature,
            signed_data_to_verify,
            signed_attributes,
            message_digest,
        })
    }

    /// Parse a CMS `SignerIdentifier` and enforce its version coupling.
    fn parse_signer_identifier<'a>(
        sid: BerTlvAny<'a>,
        version: &[u8],
    ) -> Result<SignerIdentifier<'a>, CmsError> {
        const VERSION_ISSUER_AND_SERIAL: u8 = 1;
        const VERSION_SUBJECT_KEY_IDENTIFIER: u8 = 3;

        if sid.tag() == <Sequence as BerTag>::TAG {
            if version != [VERSION_ISSUER_AND_SERIAL] {
                return Err(CmsError::UnexpectedStructure(
                    "issuerAndSerialNumber signerInfo version is not 1",
                ));
            }
            let sid = sid.expect::<Sequence>()?;
            let mut it = sid.iter_children();
            let issuer = it
                .next()
                .ok_or(CmsError::UnexpectedStructure("sid missing issuer"))??
                .expect::<Sequence>()
                .or(Err(CmsError::UnexpectedStructure(
                    "sid issuer is not Name SEQUENCE",
                )))?;
            let serial = it
                .next()
                .ok_or(CmsError::UnexpectedStructure("sid missing serialNumber"))??
                .expect::<Integer>()
                .or(Err(CmsError::UnexpectedStructure(
                    "sid serialNumber not INTEGER",
                )))?;
            if serial.value().is_empty() || it.next().is_some() {
                return Err(CmsError::UnexpectedStructure(
                    "issuerAndSerialNumber malformed",
                ));
            }
            let issuer_der = sid
                .value()
                .get(..issuer.size())
                .ok_or(CmsError::UnexpectedStructure("sid issuer truncated"))?;
            Ok(SignerIdentifier::IssuerAndSerialNumber {
                issuer_der,
                serial_number: serial.value(),
            })
        } else if sid.tag() == <SignerSubjectKeyIdentifier as BerTag>::TAG {
            if version != [VERSION_SUBJECT_KEY_IDENTIFIER] {
                return Err(CmsError::UnexpectedStructure(
                    "subjectKeyIdentifier signerInfo version is not 3",
                ));
            }
            let sid = sid.expect::<SignerSubjectKeyIdentifier>()?;
            if sid.value().is_empty() {
                return Err(CmsError::UnexpectedStructure(
                    "subjectKeyIdentifier is empty",
                ));
            }
            Ok(SignerIdentifier::SubjectKeyIdentifier(sid.value()))
        } else {
            Err(CmsError::UnexpectedStructure(
                "unsupported SignerIdentifier choice",
            ))
        }
    }

    /// Parse an Attribute set. Signed attributes require exactly one
    /// `contentType` and one `messageDigest`, each with one typed value.
    fn parse_attributes(
        attrs_value: &[u8],
        require_mandatory_signed: bool,
    ) -> Result<ParsedSignedAttributes<'_>, CmsError> {
        let mut attributes = Vec::new();
        let mut content_type = None;
        let mut message_digest = None;

        for attr in BerTlvIter::new(attrs_value) {
            let attr = attr?
                .expect::<Sequence>()
                .or(Err(CmsError::UnexpectedStructure("attribute not SEQUENCE")))?;
            let mut it = attr.iter_children();
            let oid = it
                .next()
                .ok_or(CmsError::UnexpectedStructure("attribute missing OID"))??
                .expect::<Oid>()
                .or(Err(CmsError::UnexpectedStructure("attribute type not OID")))?;
            let oid = crate::oid::Oid::new(oid.value()).or(Err(CmsError::UnexpectedStructure(
                "attribute OID malformed",
            )))?;
            let values = it
                .next()
                .ok_or(CmsError::UnexpectedStructure("attribute missing values"))??
                .expect::<Set>()
                .or(Err(CmsError::UnexpectedStructure(
                    "attribute values not SET",
                )))?;
            if it.next().is_some() {
                return Err(CmsError::UnexpectedStructure(
                    "attribute has trailing fields",
                ));
            }
            Self::validate_nonempty_tlv_stream(values.value(), "attribute value set is empty")?;

            if require_mandatory_signed && oid == known::CONTENT_TYPE {
                if content_type.is_some() {
                    return Err(CmsError::UnexpectedStructure(
                        "duplicate signed contentType attribute",
                    ));
                }
                let value = Self::parse_exact::<Oid>(
                    values.value(),
                    "contentType attribute has multiple values",
                )?;
                content_type = Some(crate::oid::Oid::new(value.value()).or(Err(
                    CmsError::UnexpectedStructure("contentType attribute OID malformed"),
                ))?);
            } else if require_mandatory_signed && oid == known::MESSAGE_DIGEST {
                if message_digest.is_some() {
                    return Err(CmsError::UnexpectedStructure(
                        "duplicate signed messageDigest attribute",
                    ));
                }
                let value = Self::parse_exact::<OctetString>(
                    values.value(),
                    "messageDigest attribute has multiple values",
                )?;
                message_digest = Some(value.value());
            }
            attributes.push(SignedAttribute {
                oid,
                values_der: values.value(),
            });
        }

        if require_mandatory_signed && content_type.is_none() {
            return Err(CmsError::UnexpectedStructure(
                "signedAttrs missing contentType",
            ));
        }
        if require_mandatory_signed && message_digest.is_none() {
            return Err(CmsError::UnexpectedStructure(
                "signedAttrs missing messageDigest",
            ));
        }
        Ok(ParsedSignedAttributes {
            attributes,
            content_type,
            message_digest,
        })
    }
}

impl SignedData<'_> {
    /// Verify the signerInfo's signature against `signer_spki_der`
    /// (the signer certificate's SPKI). When `signedAttrs` was present, also
    /// verifies that the `messageDigest` attribute matches
    /// `hash(eContent)`.
    ///
    /// # Errors
    /// Cross-check failure, unsupported algorithm, or RSA
    /// verifier rejection.
    pub fn verify(&self, signer_spki_der: &[u8]) -> Result<(), CmsError> {
        let digest_alg = HashAlgorithm::from_oid(self.signer.digest_algorithm_oid)
            .ok_or(CmsError::UnsupportedDigestAlgorithm)?;

        // Signed attributes are only safe when they bind the eContent.
        // The parser enforces this invariant; keep the check here too so
        // callers constructing the public struct cannot bypass it.
        if self.signer.signed_data_to_verify.is_some() {
            let md = self
                .signer
                .message_digest
                .ok_or(CmsError::UnexpectedStructure(
                    "signedAttrs missing messageDigest",
                ))?;
            let expected = digest_alg.digest(self.econtent_der);
            if expected != md {
                return Err(CmsError::SignerHashMismatch);
            }
        }

        // The data we actually verify with the signature is
        // either the re-tagged signedAttrs SET (when present),
        // or eContent directly.
        let payload: &[u8] = self
            .signer
            .signed_data_to_verify
            .as_deref()
            .unwrap_or(self.econtent_der);

        verify_dispatch(&SignatureDispatch {
            sig_alg_oid: self.signer.signature_algorithm_oid,
            digest_alg_fallback: digest_alg,
            signer_spki_der,
            payload,
            signature: self.signer.signature,
        })
    }
}

// `known::EC_PUBLIC_KEY` is *sometimes* the signatureAlgorithm OID in
// a signerInfo -- the hash then comes from the signerInfo's
// digestAlgorithm (handled via the `digest_alg_fallback` arm below).

/// Inputs for CMS signer signature verification.
struct SignatureDispatch<'a> {
    /// Signature algorithm OID.
    sig_alg_oid: crate::oid::Oid<'a>,
    /// Digest algorithm from `SignerInfo`.
    digest_alg_fallback: HashAlgorithm,
    /// Signer SPKI DER.
    signer_spki_der: &'a [u8],
    /// Payload covered by the signature.
    payload: &'a [u8],
    /// Signature bytes.
    signature: &'a [u8],
}

/// RSA signature verification input.
struct RsaVerifyInput<'a> {
    /// RSA public key.
    key: &'a RsaPublicKey,
    /// Hash algorithm selected by CMS.
    hash: HashAlgorithm,
    /// Payload covered by the signature.
    payload: &'a [u8],
    /// Signature bytes.
    signature: &'a [u8],
}

/// Verify a `SignerInfo` signature, dispatching on the signature
/// algorithm OID over the prehashed `payload`.
///
/// RFC 5652 §5.4 (message-digest computation) and RFC 5754 (RSA /
/// ECDSA signature algorithms). The `digest_alg_fallback` is used
/// when the signature OID is the bare key-type OID (`id-ecPublicKey`
/// or `rsaEncryption`) -- some signers encode it that way (OpenSSL
/// emits the bare `rsaEncryption`) and the digest is taken from `signerInfo.digestAlgorithm`.
///
/// Returns `Err(UnsupportedSignatureAlgorithm)` when the OID is
/// outside the SHA-256/384/512 × RSA-PKCS1v15/ECDSA matrix this
/// build supports; no PSS, no DSA, no Ed25519 here.
fn verify_dispatch(input: &SignatureDispatch<'_>) -> Result<(), CmsError> {
    // RSA-PKCS1v15 path.
    let hash_for_rsa = match input.sig_alg_oid.as_bytes() {
        v if v == known::SHA256_WITH_RSA.as_bytes() => Some(HashAlgorithm::Sha256),
        v if v == known::SHA384_WITH_RSA.as_bytes() => Some(HashAlgorithm::Sha384),
        v if v == known::SHA512_WITH_RSA.as_bytes() => Some(HashAlgorithm::Sha512),
        v if v == known::RSA_ENCRYPTION.as_bytes() => Some(input.digest_alg_fallback),
        _ => None,
    };
    if let Some(hash) = hash_for_rsa {
        let key = extract_rsa_public_key(input.signer_spki_der).ok_or(CmsError::BadSignerKey)?;
        return rsa_verify_with_hash(&RsaVerifyInput {
            key: &key,
            hash,
            payload: input.payload,
            signature: input.signature,
        });
    }
    // ECDSA path.
    let hash_for_ecdsa = match input.sig_alg_oid.as_bytes() {
        v if v == known::ECDSA_WITH_SHA256.as_bytes() => Some(HashAlgorithm::Sha256),
        v if v == known::ECDSA_WITH_SHA384.as_bytes() => Some(HashAlgorithm::Sha384),
        v if v == known::ECDSA_WITH_SHA512.as_bytes() => Some(HashAlgorithm::Sha512),
        v if v == known::EC_PUBLIC_KEY.as_bytes() => Some(input.digest_alg_fallback),
        _ => None,
    };
    if let Some(hash) = hash_for_ecdsa {
        let (curve, pubkey) =
            ecdsa::extract_ec_pubkey(input.signer_spki_der).ok_or(CmsError::BadSignerKey)?;
        let digest = hash.digest(input.payload);
        let sig = Signature::<EcdsaDer>::new(input.signature.to_vec());
        return ecdsa::verify_prehashed(&curve, &pubkey, &sig, &digest).map_err(CmsError::Ecdsa);
    }
    Err(CmsError::UnsupportedSignatureAlgorithm)
}

/// Verify an RSASSA-PKCS1-v1_5 signature with a runtime-chosen
/// hash algorithm.
///
/// RFC 8017 §8.2.2 (RSASSA-PKCS1-V1_5-VERIFY). The
/// hash-algorithm-id step uses `HashAlgorithm` as a typed proxy
/// so the verify path cannot mismatch SHA-256 emsa with SHA-384
/// modulus padding etc. Returns `CmsError::BadRsaSignature` on
/// verification failure rather than panicking, so a single bad
/// signer info never aborts a multi-signer CMS verify.
fn rsa_verify_with_hash(input: &RsaVerifyInput<'_>) -> Result<(), CmsError> {
    // The hash-algorithm marker comes from the BER
    // `signatureAlgorithm` OID -- known only at runtime, so the
    // typed wrapper is built here. One allocation per signature
    // is well-amortised against a CMS verify's other cost
    // (modular exponentiation).
    let res = match input.hash {
        HashAlgorithm::Sha256 => {
            let sig = Signature::<RsaPkcs1Sha256>::new(input.signature.to_vec());
            input.key.verify_pkcs1v15_sha256(input.payload, &sig)
        }
        HashAlgorithm::Sha384 => {
            let sig = Signature::<RsaPkcs1Sha384>::new(input.signature.to_vec());
            verify_pkcs1v15_sha384(input.key, input.payload, &sig)
        }
        HashAlgorithm::Sha512 => {
            let sig = Signature::<RsaPkcs1Sha512>::new(input.signature.to_vec());
            verify_pkcs1v15_sha512(input.key, input.payload, &sig)
        }
    };
    res.map_err(CmsError::Rsa)
}

#[cfg(test)]
mod tests {

    use super::{
        Asn1ContentExplicit0, CmsError, CmsHelpers, HashAlgorithm, OwnedSignedData, SignedData,
        SignerIdentifier, SignerInfo,
    };
    use crate::oid::{Oid, known};
    use crate::x509::Certificate;
    use refineid_ber::{
        BerTag, BerTlv, BerTlvIter, Integer, OctetString, Oid as BerOid, Sequence, Set,
    };
    use refineid_digest::{SHA256_LEN, SHA384_LEN, SHA512_LEN};

    /// Infallible fixture encoder: test values stay far below the DER
    /// length bound, so the encode error cannot occur here.
    fn tlv(tag: u8, value: impl AsRef<[u8]>) -> Vec<u8> {
        refineid_ber::tlv(tag, value).expect("fixture tlv encodes")
    }

    /// The single identifier octet of the typed tag `T` -- fixtures
    /// are assembled from the same named `BerTag::TAG` constants the
    /// parser trusts. Every tag these fixtures use is in X.690
    /// low-tag-number form, so the high byte is always zero.
    fn tag_byte<T: BerTag>() -> u8 {
        let [high, low] = <T as BerTag>::TAG.to_be_bytes();
        assert_eq!(high, 0, "fixture tags are single-byte");
        low
    }

    // ----- Named fixture values (RFC 5652 / ICAO 9303 spec numbers) -----

    /// `SignedData.version` INTEGER body: v1 -- RFC 5652 sec.5.1's
    /// value when eContentType is id-data and every signerInfo is
    /// version 1, the shape `minimal_signed_data` builds.
    const SIGNED_DATA_VERSION_V1: [u8; 1] = [1];

    /// `SignedData.version` INTEGER body: v3 -- RFC 5652 sec.5.1's
    /// value when eContentType is not id-data (as with
    /// [`FIXTURE_ECONTENT_TYPE`]).
    const SIGNED_DATA_VERSION_V3: [u8; 1] = [3];

    /// `2.23.136.1.1.1` -- id-icao-mrtd-security-ldsSecurityObject
    /// (ICAO Doc 9303-10), the eContentType the committed CMS
    /// fixtures were signed with (`openssl cms -econtent_type`).
    const FIXTURE_ECONTENT_TYPE: Oid<'static> =
        Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap("2.23.136.1.1.1").as_bytes());

    /// `SignerInfo.version` INTEGER body: 1, mandated by RFC 5652
    /// sec.5.3 for the issuerAndSerialNumber sid choice.
    const SIGNER_INFO_VERSION_V1: [u8; 1] = [1];

    /// Two signerInfos -- the smallest count the exactly-one-signer
    /// rule must reject (RFC 5652 permits many; this crate does not).
    const TWO_SIGNER_INFOS: usize = 2;

    /// Bytes that are no supported hash-algorithm OID body --
    /// `HashAlgorithm::from_oid` must map them to `None`.
    const NOT_AN_OID: &[u8] = &[0x01, 0x02, 0x03];

    /// Filler bytes with no BER structure at all --
    /// `OwnedSignedData` must reject them at construction.
    const NOT_CMS_DER: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

    // Committed CMS / SPKI fixtures. Generated offline with OpenSSL
    // 3.x (refineid-cms never generates keys; the verifier is
    // verify-only by design). The signed eContent is a minimal eMRTD
    // LDSSecurityObject carrying two DataGroupHash entries (DG1, DG2):
    //
    //   # lds.der: version 0, SHA-256, DG1 = SHA256("refineid-test-DG1"),
    //   #          DG2 = SHA256("refineid-test-DG2")
    //   openssl genrsa -out k.pem 2048
    //   openssl req -x509 -new -key k.pem -out c.pem -sha256 -subj /CN=...
    //   openssl cms -sign -in lds.der -signer c.pem -inkey k.pem \
    //       -outform DER -nodetach -binary -md sha256 \
    //       -econtent_type 2.23.136.1.1.1 -out cms.der
    //   openssl x509 -in c.pem -noout -pubkey | openssl pkey -pubin -outform DER
    //
    // The EC fixture is the same flow over prime256v1; the -noattr
    // fixture drops signedAttrs so the signature is over eContent
    // directly (signatureAlgorithm = rsaEncryption).
    // RSA-2048/SHA-256 CMS SignedData, signedAttrs present; eContent is the LDSSecurityObject (1549 bytes).
    const RSA_CMS_HEX: &str = "\
        3082060906092a864886f70d010702a08205fa308205f6020103310d300b0609\
        60864801650304020130700606678108010101a06604643062020100300d0609\
        6086480165030402010500304e3025020101042040d486fedd456ab92c4d02b2\
        704362570c096df55f421fee53945e70c6831bfd3025020102042072fc7341e3\
        f5f8935e96be104329ea083e88d8f009bcb46a340be9968902c008a082032530\
        82032130820209a00302010202141abbaecfaf492906d7fc069b27857f73ee21\
        0b4b300d06092a864886f70d01010b05003020311e301c06035504030c155265\
        46696e65494420546573742044534320525341301e170d323630363238313532\
        3834385a170d3336303632353135323834385a3020311e301c06035504030c15\
        526546696e6549442054657374204453432052534130820122300d06092a8648\
        86f70d01010105000382010f003082010a0282010100ed28349290c82f3dd487\
        1eff7b2ec12d057a9d2dc9ba566cd8ce23a0b5fc559ce4456738e2b69b57fd56\
        f84d0f6a5ca91f22d36a3a64864c0c3c50f0d96af2a18ecd5a7c1f934c2f3638\
        5264d867982f70487004cd5105d16cd47a7ec61c204a37d947c5d997ebf8e1ef\
        f6581823b15d753123991b308669ec5633214e7d75b35fbbdb937c6782f6e406\
        aed8edca9b5a028297891acad926fecb3adaa806daaf0bf886bb16c667762269\
        c9ecf3f6edd3398d151cbbe8f1b50ba6b4f4365451ad21fbc4804ff2bc406d61\
        db7041239b7bf53c4bfc5724302c2b392530e9b56c57c4d6072528fa2b3f95ed\
        90d6144869d5c5e9f48f74da2b1babed1d9d2bb2ef130203010001a353305130\
        1d0603551d0e04160414e5c676464f2bbed52b1298910619a21cde4f372a301f\
        0603551d23041830168014e5c676464f2bbed52b1298910619a21cde4f372a30\
        0f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003\
        82010100773ea57116db9ed8a192ce9c79faa1f6628b1d948f8d98aebb1a14fe\
        c50c931d89afbf74fd8f7890461231d1c29dfae7b4abfe71e7414a6b09191f69\
        608d940b9735fb3064152349f793ef0acc89a30bdf41383762cba983f0d4248a\
        67867cb7fce688a0a34454a2653648eeedd9b20b03bc73cd19df061cf3e045e1\
        26c3eb25aa529c872134bfa1c4057f3fd4177983ea2a7608d8ea413846d3c9f0\
        c0bb2f304246bbaaeb99c77fb761a711d630dea9dd37b8619a3030b47cdcc948\
        15f4baa7bf471fe4c5371ebe77e7e99d161eb5bf3a16802622899c8a3c07f45c\
        e1f9bded56c3e3b14e9201be3d585573af6a3441c0dbe94378e6fd9a984cbc3d\
        f865f8f1318202453082024102010130383020311e301c06035504030c155265\
        46696e6549442054657374204453432052534102141abbaecfaf492906d7fc06\
        9b27857f73ee210b4b300b0609608648016503040201a081e1301506092a8648\
        86f70d01090331080606678108010101301c06092a864886f70d010905310f17\
        0d3236303632383135323834385a302f06092a864886f70d01090431220420b4\
        f0af7f043f5d2153918add8d1aeee3214894d7d086ddec9332a3a6524989d230\
        7906092a864886f70d01090f316c306a300b060960864801650304012a300b06\
        09608648016503040116300b0609608648016503040102300a06082a864886f7\
        0d0307300e06082a864886f70d030202020080300d06082a864886f70d030202\
        0140300706052b0e030207300d06082a864886f70d0302020128300d06092a86\
        4886f70d010101050004820100515a1e751b91741f1c30ee975c3c7c84b94a2d\
        6b7f44bbd7edacaba05e39f7a116905c4d0c097ca694119542f43b3e9c28e84a\
        c4ded455743185b90122ad8b9e802b2cdf80f6c4f8be4dc9eeefcd72a679688d\
        9a6e0de0c0401d4a71f2b36edb763ab42b7cc8738b52f92a3b2f8f69b318d44e\
        0a53df2a5afead31394a89419a535a3656e0b4dfdbf585d0bceb04fdc258987a\
        afa1d3e2f49273c257dcb638b78c106ed077554742a2450a04a610f0e9104510\
        bec7224c82b5d65442376ff4a746ccd879056ee3347e02ceadf2f89cecc7d2b2\
        6613fd61ac2e60db8d4039844238e15e5e76de70305e2624d429ecf66c193b99\
        dda4b5a213bde6bd9e531be4d8";

    // SubjectPublicKeyInfo of the RSA signer that signed RSA_CMS_HEX (294 bytes).
    const RSA_SPKI_HEX: &str = "\
        30820122300d06092a864886f70d01010105000382010f003082010a02820101\
        00ed28349290c82f3dd4871eff7b2ec12d057a9d2dc9ba566cd8ce23a0b5fc55\
        9ce4456738e2b69b57fd56f84d0f6a5ca91f22d36a3a64864c0c3c50f0d96af2\
        a18ecd5a7c1f934c2f36385264d867982f70487004cd5105d16cd47a7ec61c20\
        4a37d947c5d997ebf8e1eff6581823b15d753123991b308669ec5633214e7d75\
        b35fbbdb937c6782f6e406aed8edca9b5a028297891acad926fecb3adaa806da\
        af0bf886bb16c667762269c9ecf3f6edd3398d151cbbe8f1b50ba6b4f4365451\
        ad21fbc4804ff2bc406d61db7041239b7bf53c4bfc5724302c2b392530e9b56c\
        57c4d6072528fa2b3f95ed90d6144869d5c5e9f48f74da2b1babed1d9d2bb2ef\
        130203010001";

    // RSA CMS with NO signedAttrs (signature over eContent; sig-alg = rsaEncryption) (1321 bytes).
    const RSA_CMS_NOATTR_HEX: &str = "\
        3082052506092a864886f70d010702a082051630820512020103310d300b0609\
        60864801650304020130700606678108010101a06604643062020100300d0609\
        6086480165030402010500304e3025020101042040d486fedd456ab92c4d02b2\
        704362570c096df55f421fee53945e70c6831bfd3025020102042072fc7341e3\
        f5f8935e96be104329ea083e88d8f009bcb46a340be9968902c008a082032530\
        82032130820209a00302010202141abbaecfaf492906d7fc069b27857f73ee21\
        0b4b300d06092a864886f70d01010b05003020311e301c06035504030c155265\
        46696e65494420546573742044534320525341301e170d323630363238313532\
        3834385a170d3336303632353135323834385a3020311e301c06035504030c15\
        526546696e6549442054657374204453432052534130820122300d06092a8648\
        86f70d01010105000382010f003082010a0282010100ed28349290c82f3dd487\
        1eff7b2ec12d057a9d2dc9ba566cd8ce23a0b5fc559ce4456738e2b69b57fd56\
        f84d0f6a5ca91f22d36a3a64864c0c3c50f0d96af2a18ecd5a7c1f934c2f3638\
        5264d867982f70487004cd5105d16cd47a7ec61c204a37d947c5d997ebf8e1ef\
        f6581823b15d753123991b308669ec5633214e7d75b35fbbdb937c6782f6e406\
        aed8edca9b5a028297891acad926fecb3adaa806daaf0bf886bb16c667762269\
        c9ecf3f6edd3398d151cbbe8f1b50ba6b4f4365451ad21fbc4804ff2bc406d61\
        db7041239b7bf53c4bfc5724302c2b392530e9b56c57c4d6072528fa2b3f95ed\
        90d6144869d5c5e9f48f74da2b1babed1d9d2bb2ef130203010001a353305130\
        1d0603551d0e04160414e5c676464f2bbed52b1298910619a21cde4f372a301f\
        0603551d23041830168014e5c676464f2bbed52b1298910619a21cde4f372a30\
        0f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003\
        82010100773ea57116db9ed8a192ce9c79faa1f6628b1d948f8d98aebb1a14fe\
        c50c931d89afbf74fd8f7890461231d1c29dfae7b4abfe71e7414a6b09191f69\
        608d940b9735fb3064152349f793ef0acc89a30bdf41383762cba983f0d4248a\
        67867cb7fce688a0a34454a2653648eeedd9b20b03bc73cd19df061cf3e045e1\
        26c3eb25aa529c872134bfa1c4057f3fd4177983ea2a7608d8ea413846d3c9f0\
        c0bb2f304246bbaaeb99c77fb761a711d630dea9dd37b8619a3030b47cdcc948\
        15f4baa7bf471fe4c5371ebe77e7e99d161eb5bf3a16802622899c8a3c07f45c\
        e1f9bded56c3e3b14e9201be3d585573af6a3441c0dbe94378e6fd9a984cbc3d\
        f865f8f1318201613082015d02010130383020311e301c06035504030c155265\
        46696e6549442054657374204453432052534102141abbaecfaf492906d7fc06\
        9b27857f73ee210b4b300b0609608648016503040201300d06092a864886f70d\
        010101050004820100c50f17039d657b9db4409440fb31dd8a533536d531f24a\
        1a178ba3aa68f6b9d244ab90334b17ed5d6f9fbd1447457767aff5df575f7078\
        5b7da4e074b894d38bd031fdb832f3f5b849e56b422f761e5e7d90a09de3c355\
        c07401c30f3b93b847331c58fce3a7fa7d528047c26cd501703890fbf1749366\
        44f0a629bc8f92c5b27387a0c471a143a699b44f26d52599ccdcbc98138021a9\
        f9da851b537d6a3742a9aea9f8c21e2f0f25fce140d06e5cc292e9ba44411877\
        51b757982fb02400debe82f44284afe38acbfa82a73a2a01bf55d6183dc379ab\
        30f8d4431d11aad7c4e093745b3637c5750e23abb9e74b702168c132a927be11\
        822c4f64257fc36736";

    // ECDSA P-256/SHA-256 CMS SignedData, signedAttrs present (960 bytes).
    const EC_CMS_HEX: &str = "\
        308203bc06092a864886f70d010702a08203ad308203a9020103310d300b0609\
        60864801650304020130700606678108010101a06604643062020100300d0609\
        6086480165030402010500304e3025020101042040d486fedd456ab92c4d02b2\
        704362570c096df55f421fee53945e70c6831bfd3025020102042072fc7341e3\
        f5f8935e96be104329ea083e88d8f009bcb46a340be9968902c008a082019730\
        82019330820139a003020102021471a3c90d57ff365af954e6298b760e8b68a5\
        36c9300a06082a8648ce3d040302301f311d301b06035504030c14526546696e\
        654944205465737420445343204543301e170d3236303632383135323834385a\
        170d3336303632353135323834385a301f311d301b06035504030c1452654669\
        6e6549442054657374204453432045433059301306072a8648ce3d020106082a\
        8648ce3d03010703420004c82edd70fc6c5829254ff642c69c483feca07c0f57\
        d5b5cd4bad59712052f4d553093ef81441b72a492198db93b5d58883510913a7\
        fd0753e78ba5a9c42f9e2fa3533051301d0603551d0e04160414e7c57be92206\
        76dada052580999f3f92c82de40a301f0603551d23041830168014e7c57be922\
        0676dada052580999f3f92c82de40a300f0603551d130101ff040530030101ff\
        300a06082a8648ce3d0403020348003045022100dd757be3366a3347f052e80d\
        b4f4214967d9ec1cf17b2999345e2654da98c48302206ff6106e4bb18565c328\
        d450380776cecb39ad07cc3a1de9065b9807d042374031820186308201820201\
        013037301f311d301b06035504030c14526546696e6549442054657374204453\
        43204543021471a3c90d57ff365af954e6298b760e8b68a536c9300b06096086\
        48016503040201a081e1301506092a864886f70d010903310806066781080101\
        01301c06092a864886f70d010905310f170d3236303632383135323834385a30\
        2f06092a864886f70d01090431220420b4f0af7f043f5d2153918add8d1aeee3\
        214894d7d086ddec9332a3a6524989d2307906092a864886f70d01090f316c30\
        6a300b060960864801650304012a300b0609608648016503040116300b060960\
        8648016503040102300a06082a864886f70d0307300e06082a864886f70d0302\
        02020080300d06082a864886f70d0302020140300706052b0e030207300d0608\
        2a864886f70d0302020128300a06082a8648ce3d040302044730450221009ca7\
        26305b257a65ed479616b39b82d90d80e29ede124348caa561157599805c0220\
        20f1188ac93ef8dcfb94db3fb4e5288d57db45f5ad6cdf857003d68a7b5f903c";

    // SubjectPublicKeyInfo of the EC P-256 signer that signed EC_CMS_HEX (91 bytes).
    const EC_SPKI_HEX: &str = "\
        3059301306072a8648ce3d020106082a8648ce3d03010703420004c82edd70fc\
        6c5829254ff642c69c483feca07c0f57d5b5cd4bad59712052f4d553093ef814\
        41b72a492198db93b5d58883510913a7fd0753e78ba5a9c42f9e2f";

    // A different RSA-2048 SPKI -- proves RSA signature rejection (294 bytes).
    const WRONG_RSA_SPKI_HEX: &str = "\
        30820122300d06092a864886f70d01010105000382010f003082010a02820101\
        00abe40664ffc72005ead92adb2cb06e5d5361c97dca0e3cb286de58c3e3af3f\
        401e918d6f55fb529924c1099938a037a0561dc1280ee7f2b25d998441d9dd30\
        cbbd635ebf7232a32cb827d5c9d3f232f3c0deba3249dcbbb0084ddd002a7516\
        7202f6a2f482e63bb335214510bb42b2243303c99ce9b671ec99cf829d1c3f93\
        b063825dc0de0c11cc0da4150509239017019f7880da2b4579b3b0a03a26ea2d\
        1db411a0628aa76e11bb19cdc1a80fb240f7eab5e35bf4bbb78a49da8622f4f5\
        73c371e8e244548ead4eac1ad79a72f43e2fef3d69e4c7742e5e8c084536bdc8\
        639b0b22c847f8294212d1ab4583cdf55e84abbcb9a68ab87353ee6413412ade\
        0d0203010001";

    // A different EC P-256 SPKI -- proves ECDSA signature rejection (91 bytes).
    const WRONG_EC_SPKI_HEX: &str = "\
        3059301306072a8648ce3d020106082a8648ce3d030107034200042d1a8cbccb\
        a942554de9f257947076b516026918bc8402f49399a1eee633d2410aeee5d913\
        a24df630c8c709e50355160ba0997e872cc2106b1dba79a002ba7a";

    // Decode a (possibly whitespace-wrapped) hex fixture.
    fn unhex(hex_fixture: &str) -> Vec<u8> {
        let cleaned: String = hex_fixture
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        hex::decode(cleaned).expect("fixture hex decodes")
    }

    // Build a synthetic SignedData for verify() error-path tests (the
    // struct fields are public). signedAttrs are treated as absent
    // unless message_digest is Some.
    fn synthetic<'a>(
        econtent: &'a [u8],
        digest_oid: &'a [u8],
        sig_oid: &'a [u8],
        message_digest: Option<&'a [u8]>,
        signature: &'a [u8],
    ) -> SignedData<'a> {
        SignedData {
            econtent_type_oid: FIXTURE_ECONTENT_TYPE,
            econtent_der: econtent,
            certificates_der: Vec::new(),
            signer: SignerInfo {
                signer_identifier: SignerIdentifier::SubjectKeyIdentifier(b"synthetic"),
                digest_algorithm_oid: Oid::new(digest_oid).expect("digest OID well-formed"),
                signature_algorithm_oid: Oid::new(sig_oid).expect("sig OID well-formed"),
                signature,
                signed_data_to_verify: None,
                signed_attributes: Vec::new(),
                message_digest,
            },
        }
    }

    /// Minimal structurally valid signerInfo, for parser cardinality
    /// and attribute-invariant tests that do not exercise crypto.
    fn minimal_signer_info() -> Vec<u8> {
        // sid: empty issuer Name SEQUENCE plus serial INTEGER 1 (any
        // nonempty INTEGER body satisfies the parser).
        let mut sid = tlv(tag_byte::<Sequence>(), b"");
        sid.extend_from_slice(&tlv(tag_byte::<Integer>(), [1_u8]));
        let mut body = tlv(tag_byte::<Integer>(), SIGNER_INFO_VERSION_V1);
        body.extend_from_slice(&tlv(tag_byte::<Sequence>(), sid));
        body.extend_from_slice(&tlv(
            tag_byte::<Sequence>(),
            tlv(tag_byte::<BerOid>(), known::SHA256.as_bytes()),
        ));
        body.extend_from_slice(&tlv(
            tag_byte::<Sequence>(),
            tlv(tag_byte::<BerOid>(), known::SHA256_WITH_RSA.as_bytes()),
        ));
        body.extend_from_slice(&tlv(tag_byte::<OctetString>(), b"signature"));
        tlv(tag_byte::<Sequence>(), body)
    }

    /// Minimal bare `SignedData` carrying `signer_count` identical
    /// `SignerInfo` values.
    fn minimal_signed_data(signer_count: usize) -> Vec<u8> {
        let mut encap = tlv(tag_byte::<BerOid>(), known::DATA.as_bytes());
        encap.extend_from_slice(&tlv(
            tag_byte::<Asn1ContentExplicit0>(),
            tlv(tag_byte::<OctetString>(), b"content"),
        ));
        let mut body = tlv(tag_byte::<Integer>(), SIGNED_DATA_VERSION_V1);
        body.extend_from_slice(&tlv(
            tag_byte::<Set>(),
            tlv(
                tag_byte::<Sequence>(),
                tlv(tag_byte::<BerOid>(), known::SHA256.as_bytes()),
            ),
        ));
        body.extend_from_slice(&tlv(tag_byte::<Sequence>(), encap));
        let mut signers = Vec::new();
        for _ in 0..signer_count {
            signers.extend_from_slice(&minimal_signer_info());
        }
        body.extend_from_slice(&tlv(tag_byte::<Set>(), signers));
        tlv(tag_byte::<Sequence>(), body)
    }

    /// Encode one CMS Attribute with one already-encoded value.
    fn attribute(oid: Oid<'_>, value: &[u8]) -> Vec<u8> {
        let mut body = tlv(tag_byte::<BerOid>(), oid.as_bytes());
        body.extend_from_slice(&tlv(tag_byte::<Set>(), value));
        tlv(tag_byte::<Sequence>(), body)
    }

    /// `ContentInfo` fixture bytes.
    #[derive(Clone, Copy)]
    struct ContentInfoFixture<'a> {
        /// `ContentInfo` DER bytes.
        der: &'a [u8],
    }

    // Extract the inner SignedData SEQUENCE TLV from a ContentInfo-
    // wrapped CMS (so the bare-SEQUENCE wrapper path can be exercised).
    fn inner_signed_data_seq(content_info: ContentInfoFixture<'_>) -> Vec<u8> {
        let ci = BerTlv::<Sequence>::parse(content_info.der).expect("ContentInfo SEQUENCE");
        let mut it = BerTlvIter::new(ci.value());
        let _oid = it
            .next()
            .expect("contentType present")
            .expect("contentType TLV");
        let explicit = it
            .next()
            .expect("[0] EXPLICIT present")
            .expect("[0] EXPLICIT TLV");
        explicit.value().to_vec()
    }

    // ----- HashAlgorithm dispatch -----

    #[test]
    fn hash_algorithm_from_oid_maps_sha2_only() {
        assert_eq!(
            HashAlgorithm::from_oid(known::SHA256),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            HashAlgorithm::from_oid(known::SHA384),
            Some(HashAlgorithm::Sha384)
        );
        assert_eq!(
            HashAlgorithm::from_oid(known::SHA512),
            Some(HashAlgorithm::Sha512)
        );
        // A valid OID that is not one of the three SHA-2 variants.
        assert_eq!(HashAlgorithm::from_oid(known::RSA_ENCRYPTION), None);
        let other_oid = crate::oid::Oid::new(NOT_AN_OID).expect("valid OID encoding");
        assert_eq!(HashAlgorithm::from_oid(other_oid), None);
        // Empty slice is rejected at the Oid constructor boundary.
        assert!(crate::oid::Oid::new(b"").is_err());
    }

    #[test]
    fn hash_algorithm_digest_known_answers() {
        // NIST FIPS 180-4 known-answer vectors for the input "abc".
        assert_eq!(
            HashAlgorithm::Sha256.digest(b"abc"),
            unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            HashAlgorithm::Sha384.digest(b"abc"),
            unhex(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            )
        );
        assert_eq!(
            HashAlgorithm::Sha512.digest(b"abc"),
            unhex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        // Output widths.
        assert_eq!(HashAlgorithm::Sha256.digest(b"").len(), SHA256_LEN);
        assert_eq!(HashAlgorithm::Sha384.digest(b"").len(), SHA384_LEN);
        assert_eq!(HashAlgorithm::Sha512.digest(b"").len(), SHA512_LEN);
    }

    #[test]
    fn hash_algorithm_label() {
        assert_eq!(HashAlgorithm::Sha256.label(), "SHA-256");
        assert_eq!(HashAlgorithm::Sha384.label(), "SHA-384");
        assert_eq!(HashAlgorithm::Sha512.label(), "SHA-512");
    }

    // ----- parse_signed_data: wrappers -----

    #[test]
    fn parses_contentinfo_wrapped_rsa() {
        let der = unhex(RSA_CMS_HEX);
        let sd = SignedData::parse(&der).expect("parse RSA CMS");
        assert_eq!(sd.econtent_type_oid, FIXTURE_ECONTENT_TYPE);
        // eContent is the embedded LDSSecurityObject SEQUENCE.
        assert_eq!(sd.econtent_der.first(), Some(&tag_byte::<Sequence>()));
        // Exactly the signer certificate was embedded.
        assert_eq!(sd.certificates_der.len(), 1);
        let cert = sd.certificates_der.first().expect("one cert");
        assert_eq!(cert.first(), Some(&tag_byte::<Sequence>()));
        // signedAttrs present: both algorithm OIDs and the
        // messageDigest commitment decoded. OpenSSL emits the bare
        // rsaEncryption OID as the SignerInfo signatureAlgorithm
        // (RFC 5754); the digest comes from digestAlgorithm.
        assert_eq!(
            sd.signer.digest_algorithm_oid.as_bytes(),
            known::SHA256.as_bytes()
        );
        assert_eq!(
            sd.signer.signature_algorithm_oid.as_bytes(),
            known::RSA_ENCRYPTION.as_bytes()
        );
        assert!(sd.signer.signed_data_to_verify.is_some());
        // messageDigest attr == SHA-256(eContent).
        let md = sd.signer.message_digest.expect("messageDigest present");
        assert_eq!(md, HashAlgorithm::Sha256.digest(sd.econtent_der).as_slice());
    }

    #[test]
    fn both_wrappings_decode_to_same_signeddata() {
        let content_info = unhex(RSA_CMS_HEX);
        let bare = inner_signed_data_seq(ContentInfoFixture { der: &content_info });

        let from_ci = SignedData::parse(&content_info).expect("ContentInfo");
        let from_bare = SignedData::parse(&bare).expect("bare SignedData");

        assert_eq!(from_bare.econtent_der, from_ci.econtent_der);
        assert_eq!(from_bare.signer.signature, from_ci.signer.signature);
        assert_eq!(
            from_bare.signer.message_digest,
            from_ci.signer.message_digest
        );
        assert_eq!(
            from_bare.econtent_type_oid.as_bytes(),
            from_ci.econtent_type_oid.as_bytes()
        );
    }

    // ----- parse_signed_data: structural rejection -----

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(
            SignedData::parse(b""),
            Err(CmsError::UnexpectedStructure("empty input"))
        ));
    }

    #[test]
    fn rejects_unknown_wrapper_tag() {
        // A leading INTEGER tag is not a SEQUENCE.
        let input = tlv(tag_byte::<Integer>(), [0_u8]);
        assert!(matches!(
            SignedData::parse(&input),
            Err(CmsError::UnexpectedStructure("unknown wrapper tag"))
        ));
    }

    #[test]
    fn rejects_bytes_after_complete_cms_value() {
        let mut der = unhex(RSA_CMS_HEX);
        der.push(0);
        assert!(matches!(
            SignedData::parse(&der),
            Err(CmsError::UnexpectedStructure(
                "trailing bytes after CMS value"
            ))
        ));
    }

    #[test]
    fn requires_exactly_one_signer_info() {
        SignedData::parse(&minimal_signed_data(1)).expect("one signer is accepted");
        assert!(matches!(
            SignedData::parse(&minimal_signed_data(0)),
            Err(CmsError::UnexpectedStructure("signerInfos is empty"))
        ));
        assert!(matches!(
            SignedData::parse(&minimal_signed_data(TWO_SIGNER_INFOS)),
            Err(CmsError::UnexpectedStructure(
                "SignedData must contain exactly one signerInfo"
            ))
        ));
    }

    #[test]
    fn rejects_empty_sequence() {
        let input = tlv(tag_byte::<Sequence>(), b"");
        assert!(matches!(
            SignedData::parse(&input),
            Err(CmsError::UnexpectedStructure("empty"))
        ));
    }

    #[test]
    fn accepts_detached_encap_content_info() {
        // SignedData whose encapContentInfo carries eContentType but
        // no eContent OCTET STRING: the detached form. The failure
        // must move past the encap stage (missing signerInfos, not
        // missing eContent); the full detached round trip -- parse,
        // supply external content, verify -- is covered by the
        // `asic_verify` openssl interop test.
        let encap = tlv(
            tag_byte::<Sequence>(),
            tlv(tag_byte::<BerOid>(), FIXTURE_ECONTENT_TYPE.as_bytes()),
        );
        let mut body = tlv(tag_byte::<Integer>(), SIGNED_DATA_VERSION_V3);
        body.extend_from_slice(&tlv(
            tag_byte::<Set>(),
            tlv(
                tag_byte::<Sequence>(),
                tlv(tag_byte::<BerOid>(), known::SHA256.as_bytes()),
            ),
        ));
        body.extend_from_slice(&encap);
        let sd_seq = tlv(tag_byte::<Sequence>(), &body);
        assert!(matches!(
            SignedData::parse(&sd_seq),
            Err(CmsError::UnexpectedStructure(
                "SignedData missing signerInfos"
            ))
        ));
    }

    // ----- parse_signer_info: signedAttrs present vs absent -----

    #[test]
    fn signer_info_without_signed_attrs() {
        // -noattr fixture: no signedAttrs, so signing is over eContent
        // directly and signatureAlgorithm is the bare rsaEncryption OID.
        let der = unhex(RSA_CMS_NOATTR_HEX);
        let sd = SignedData::parse(&der).expect("parse");
        assert!(sd.signer.signed_data_to_verify.is_none());
        assert!(sd.signer.message_digest.is_none());
        assert_eq!(
            sd.signer.digest_algorithm_oid.as_bytes(),
            known::SHA256.as_bytes()
        );
        assert_eq!(
            sd.signer.signature_algorithm_oid.as_bytes(),
            known::RSA_ENCRYPTION.as_bytes()
        );
    }

    #[test]
    fn signer_identifier_is_retained_for_certificate_selection() {
        let der = unhex(RSA_CMS_HEX);
        let sd = SignedData::parse(&der).expect("parse");
        let cert = Certificate::from_der(
            sd.certificates_der
                .first()
                .copied()
                .expect("embedded certificate"),
        )
        .expect("certificate parses");
        assert_eq!(
            sd.signer.signer_identifier,
            SignerIdentifier::IssuerAndSerialNumber {
                issuer_der: cert.issuer.as_der(),
                serial_number: cert.serial_der,
            }
        );
    }

    #[test]
    fn signed_attributes_require_unique_content_type_and_message_digest() {
        let content_type = attribute(
            known::CONTENT_TYPE,
            &tlv(tag_byte::<BerOid>(), known::DATA.as_bytes()),
        );
        // A one-byte stand-in digest: the attribute-shape checks
        // never hash anything.
        let message_digest = attribute(
            known::MESSAGE_DIGEST,
            &tlv(tag_byte::<OctetString>(), [1_u8]),
        );

        let mut valid = content_type.clone();
        valid.extend_from_slice(&message_digest);
        CmsHelpers::parse_attributes(&valid, true).expect("mandatory attributes present");

        assert!(matches!(
            CmsHelpers::parse_attributes(&content_type, true),
            Err(CmsError::UnexpectedStructure(
                "signedAttrs missing messageDigest"
            ))
        ));

        let mut duplicate = valid;
        duplicate.extend_from_slice(&message_digest);
        assert!(matches!(
            CmsHelpers::parse_attributes(&duplicate, true),
            Err(CmsError::UnexpectedStructure(
                "duplicate signed messageDigest attribute"
            ))
        ));
    }

    // ----- SignedData::verify: positive -----

    #[test]
    fn verify_rsa_with_signed_attrs() {
        let der = unhex(RSA_CMS_HEX);
        let spki = unhex(RSA_SPKI_HEX);
        let sd = SignedData::parse(&der).expect("parse");
        sd.verify(&spki).expect("RSA signature verifies");
    }

    #[test]
    fn verify_ecdsa_with_signed_attrs() {
        let der = unhex(EC_CMS_HEX);
        let spki = unhex(EC_SPKI_HEX);
        let sd = SignedData::parse(&der).expect("parse");
        sd.verify(&spki).expect("ECDSA signature verifies");
    }

    #[test]
    fn verify_rsa_without_signed_attrs() {
        // Exercises the payload = eContent branch and the rsaEncryption
        // -> digestAlgorithm fallback inside verify_dispatch.
        let der = unhex(RSA_CMS_NOATTR_HEX);
        let spki = unhex(RSA_SPKI_HEX);
        let sd = SignedData::parse(&der).expect("parse");
        sd.verify(&spki)
            .expect("RSA signature over eContent verifies");
    }

    // ----- SignedData::verify: negative -----

    #[test]
    fn verify_rejects_wrong_rsa_key() {
        let der = unhex(RSA_CMS_HEX);
        let wrong = unhex(WRONG_RSA_SPKI_HEX);
        let sd = SignedData::parse(&der).expect("parse");
        let err = sd.verify(&wrong).expect_err("wrong RSA key must fail");
        assert!(matches!(err, CmsError::Rsa(_)), "got {err:?}");
    }

    #[test]
    fn verify_rejects_wrong_ecdsa_key() {
        let der = unhex(EC_CMS_HEX);
        let wrong = unhex(WRONG_EC_SPKI_HEX);
        let sd = SignedData::parse(&der).expect("parse");
        let err = sd.verify(&wrong).expect_err("wrong EC key must fail");
        assert!(matches!(err, CmsError::Ecdsa(_)), "got {err:?}");
    }

    #[test]
    fn verify_rejects_mismatched_key_type() {
        // RSA-signed CMS against an EC SPKI -> RSA key extraction fails
        // -> BadSignerKey (and the symmetric EC-against-RSA case).
        let rsa = unhex(RSA_CMS_HEX);
        let ec = unhex(EC_CMS_HEX);
        let rsa_spki = unhex(RSA_SPKI_HEX);
        let ec_spki = unhex(EC_SPKI_HEX);
        let rsa_sd = SignedData::parse(&rsa).expect("parse rsa");
        let ec_sd = SignedData::parse(&ec).expect("parse ec");
        assert!(matches!(
            rsa_sd.verify(&ec_spki),
            Err(CmsError::BadSignerKey)
        ));
        assert!(matches!(
            ec_sd.verify(&rsa_spki),
            Err(CmsError::BadSignerKey)
        ));
    }

    #[test]
    fn verify_rejects_tampered_econtent() {
        // signedAttrs commit to messageDigest = hash(eContent); swap
        // eContent and the cross-check fails before any signature math.
        let der = unhex(RSA_CMS_HEX);
        let spki = unhex(RSA_SPKI_HEX);
        let mut sd = SignedData::parse(&der).expect("parse");
        sd.econtent_der = b"tampered LDS content -- not what was signed";
        assert!(matches!(
            sd.verify(&spki),
            Err(CmsError::SignerHashMismatch)
        ));
    }

    #[test]
    fn verify_rejects_signed_attributes_without_message_digest() {
        let der = unhex(RSA_CMS_HEX);
        let spki = unhex(RSA_SPKI_HEX);
        let mut sd = SignedData::parse(&der).expect("parse");
        sd.signer.message_digest = None;
        assert!(matches!(
            sd.verify(&spki),
            Err(CmsError::UnexpectedStructure(
                "signedAttrs missing messageDigest"
            ))
        ));
    }

    #[test]
    fn verify_rejects_unsupported_digest_algorithm() {
        // digestAlgorithm OID is rsaEncryption -- not a SHA-2 variant.
        let sd = synthetic(
            b"x",
            known::RSA_ENCRYPTION.as_bytes(),
            known::SHA256_WITH_RSA.as_bytes(),
            None,
            b"",
        );
        assert!(matches!(
            sd.verify(b""),
            Err(CmsError::UnsupportedDigestAlgorithm)
        ));
    }

    #[test]
    fn verify_rejects_unsupported_signature_algorithm() {
        // Valid SHA-256 digest OID, but a digest OID sits in the
        // signatureAlgorithm slot -- outside the RSA/ECDSA matrix.
        let sd = synthetic(
            b"x",
            known::SHA256.as_bytes(),
            known::SHA256.as_bytes(),
            None,
            b"",
        );
        assert!(matches!(
            sd.verify(b""),
            Err(CmsError::UnsupportedSignatureAlgorithm)
        ));
    }

    // ----- Owned wrappers -----

    #[test]
    fn owned_signed_data_roundtrips() {
        let der = unhex(RSA_CMS_HEX);
        let owned = OwnedSignedData::from_der(&der).expect("construct");
        assert_eq!(owned.as_der(), der.as_slice());
        let view = owned.view();
        assert_eq!(view.econtent_type_oid, FIXTURE_ECONTENT_TYPE);
        assert_eq!(view.certificates_der.len(), 1);
    }

    #[test]
    fn owned_signed_data_rejects_garbage() {
        OwnedSignedData::from_der(NOT_CMS_DER).expect_err("garbage bytes are not SignedData");
    }

    // ----- CmsError Display -----

    #[test]
    fn cms_error_display_strings() {
        assert_eq!(
            CmsError::from(refineid_ber::BerError::Empty).to_string(),
            "CMS BER: BER: empty input"
        );
        assert_eq!(
            CmsError::UnexpectedStructure("bad shape").to_string(),
            "CMS: bad shape"
        );
        assert_eq!(
            CmsError::UnsupportedDigestAlgorithm.to_string(),
            "CMS: unsupported digest algorithm"
        );
        assert_eq!(
            CmsError::UnsupportedSignatureAlgorithm.to_string(),
            "CMS: unsupported signature algorithm"
        );
        assert_eq!(
            CmsError::BadSignerKey.to_string(),
            "CMS: signer key did not parse as RSA"
        );
        assert_eq!(
            CmsError::SignerHashMismatch.to_string(),
            "CMS: messageDigest attr != hash(eContent)"
        );
    }

    #[test]
    fn cms_error_display_wraps_crypto_errors() {
        // Capture the real Rsa / Ecdsa variants from wrong-key verifies
        // and confirm the wrapper prefixes.
        let rsa_der = unhex(RSA_CMS_HEX);
        let rsa_err = SignedData::parse(&rsa_der)
            .expect("parse")
            .verify(&unhex(WRONG_RSA_SPKI_HEX))
            .expect_err("wrong key");
        assert!(
            rsa_err.to_string().starts_with("CMS: RSA verify:"),
            "{rsa_err}"
        );
        let ec_der = unhex(EC_CMS_HEX);
        let ec_err = SignedData::parse(&ec_der)
            .expect("parse")
            .verify(&unhex(WRONG_EC_SPKI_HEX))
            .expect_err("wrong key");
        assert!(
            ec_err.to_string().starts_with("CMS: ECDSA verify:"),
            "{ec_err}"
        );
    }
}
