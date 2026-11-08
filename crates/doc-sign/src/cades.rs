//! `CAdES`-B `SignedData`, signed by a card that holds the key.
//!
//! [`refineid_cms`] reads a `SignedData`; this writes one. The two are
//! separate because they have opposite problems. The reader is handed a
//! finished structure and must not trust it. The writer must produce
//! bytes another implementation will verify, and gets no second chance:
//! a signature over the wrong octets is indistinguishable from a
//! tampered document.
//!
//! # Why the API is in two halves
//!
//! The signature comes from the card, which is on the other side of a
//! PIN prompt and an APDU exchange. So the structure cannot be built in
//! one call: [`signed_attributes`] produces exactly the octets to be
//! hashed and sent to PSO:CDS, and [`signed_data`] takes the signature
//! back and assembles the result. Nothing in between touches a key.
//!
//! # The trap in RFC 5652 section 5.4
//!
//! `signedAttrs` appears in `SignerInfo` under an implicit `[0]` tag
//! (`0xA0`), but the octets that get signed are the *same attributes
//! re-tagged as a universal SET* (`0x31`). Sign the `0xA0` form and
//! every verifier rejects it. [`ToBeSigned`] therefore hands out the
//! `0x31` form and [`signed_data`] re-tags for the structure, so the
//! two can never be confused at a call site.
//!
//! # Conformance
//!
//! - RFC 5652 (CMS): `SignedData`, `SignerInfo`, `Attribute`.
//! - RFC 5035 (ESS): `SigningCertificateV2`, mandatory for `CAdES`.
//! - ETSI EN 319 122-1 (`CAdES`): the baseline B-B profile is
//!   `content-type` + `message-digest` + `signing-time` +
//!   `signing-certificate-v2`, which is what this builds.
//!
//! Long-term levels (B-T and up) add a timestamp token as an unsigned
//! attribute. Not built here: a timestamp needs a TSA round trip, which
//! is a network operation and belongs above this module.

use crate::ber::tlv;
use crate::digest::{Sha256, Sha384, Sha512};
use crate::validation::ValidationMaterial;
use refineid_cms::oid;
use refineid_cms::x509::Certificate;

/// Universal SEQUENCE (`0x30`).
const TAG_SEQUENCE: u8 = 0x30;

/// Universal SET / SET OF (`0x31`). Also the tag the signed attributes
/// carry while being signed, per RFC 5652 section 5.4.
const TAG_SET: u8 = 0x31;

/// Universal OBJECT IDENTIFIER (`0x06`).
const TAG_OID: u8 = 0x06;

/// Universal OCTET STRING (`0x04`).
const TAG_OCTET_STRING: u8 = 0x04;

/// Universal INTEGER (`0x02`).
const TAG_INTEGER: u8 = 0x02;

/// Universal `UTCTime` (`0x17`).
const TAG_UTC_TIME: u8 = 0x17;

/// Context-specific constructed `[1]` (`0xA1`), the implicit tag on
/// `unsignedAttrs` in `SignerInfo`.
const TAG_CONTEXT_1: u8 = 0xA1;

/// Context-specific constructed `[0]` (`0xA0`).
///
/// Three different things in this file wear this tag: the explicit
/// wrapper around `SignedData` in `ContentInfo`, the implicit
/// `certificates` field, and the implicit `signedAttrs` field. The
/// parent structure decides which; the byte is the same.
const TAG_CONTEXT_0: u8 = 0xA0;

/// CMS version 1: `SignerInfo` identified by issuer and serial, and an
/// `eContentType` of `id-data` (RFC 5652 section 5.1).
const CMS_VERSION_V1: u8 = 0x01;

/// CMS version 5, required once `certificates` or `crls` carries an
/// entry of the `other` choice (RFC 5652 section 5.1).
const CMS_VERSION_V5: u8 = 0x05;

/// Which digest the content and the attributes are hashed under.
///
/// FINEID cards sign SHA-256 under RSA and both SHA-256 and SHA-384
/// under ECDSA; SHA-512 is read in documents other signers make.
/// Nothing here offers MD5 or SHA-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-384 (FIPS 180-4).
    Sha384,
    /// SHA-512 (FIPS 180-4).
    Sha512,
}

impl DigestAlgorithm {
    /// Digest of `input` under this algorithm.
    #[must_use]
    pub fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::of(input).as_bytes().to_vec(),
            Self::Sha384 => Sha384::of(input).as_bytes().to_vec(),
            Self::Sha512 => Sha512::of(input).as_bytes().to_vec(),
        }
    }

    /// The digest algorithm `oid` names, `None` for any other than
    /// SHA-256, SHA-384 and SHA-512 (OIDs from RFC 5754 sec.2).
    #[must_use]
    pub fn from_oid(oid: oid::Oid<'_>) -> Option<Self> {
        if oid == oid::known::SHA256 {
            Some(Self::Sha256)
        } else if oid == oid::known::SHA384 {
            Some(Self::Sha384)
        } else if oid == oid::known::SHA512 {
            Some(Self::Sha512)
        } else {
            None
        }
    }

    /// Output length in octets (FIPS 180-4 sec.1).
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => crate::digest::SHA256_LEN,
            Self::Sha384 => crate::digest::SHA384_LEN,
            Self::Sha512 => crate::digest::SHA512_LEN,
        }
    }

    /// The digest algorithm a CMS `SignerInfo` names, whose border
    /// admits the SHA-2 algorithms only.
    #[must_use]
    pub const fn from_cms(algorithm: refineid_cms::signed_data::HashAlgorithm) -> Self {
        match algorithm {
            refineid_cms::signed_data::HashAlgorithm::Sha256 => Self::Sha256,
            refineid_cms::signed_data::HashAlgorithm::Sha384 => Self::Sha384,
            refineid_cms::signed_data::HashAlgorithm::Sha512 => Self::Sha512,
        }
    }

    /// The OID for this digest algorithm.
    #[must_use]
    pub(crate) const fn oid(self) -> oid::Oid<'static> {
        match self {
            Self::Sha256 => oid::known::SHA256,
            Self::Sha384 => oid::known::SHA384,
            Self::Sha512 => oid::known::SHA512,
        }
    }

    /// The `AlgorithmIdentifier` SEQUENCE for this digest.
    ///
    /// The parameters field is absent rather than NULL: RFC 5754
    /// section 2 requires the absent form for the SHA-2 family, and
    /// some verifiers reject the NULL form.
    pub(crate) fn algorithm_identifier(self) -> Vec<u8> {
        let oid_der = match self {
            Self::Sha256 => tlv(TAG_OID, oid::known::SHA256.as_bytes()),
            Self::Sha384 => tlv(TAG_OID, oid::known::SHA384.as_bytes()),
            Self::Sha512 => tlv(TAG_OID, oid::known::SHA512.as_bytes()),
        };
        tlv(TAG_SEQUENCE, &oid_der)
    }
}

/// Which signature the card will produce over the attribute digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017).
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384 (RFC 8017).
    RsaPkcs1Sha384,
    /// ECDSA with SHA-256 (FIPS 186-4).
    EcdsaSha256,
    /// ECDSA with SHA-384 (FIPS 186-4).
    EcdsaSha384,
}

impl SignatureAlgorithm {
    /// The digest this signature is computed over.
    #[must_use]
    pub const fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::RsaPkcs1Sha256 | Self::EcdsaSha256 => DigestAlgorithm::Sha256,
            Self::RsaPkcs1Sha384 | Self::EcdsaSha384 => DigestAlgorithm::Sha384,
        }
    }

    /// The `AlgorithmIdentifier` SEQUENCE for `signatureAlgorithm`.
    ///
    /// RSA carries an explicit NULL parameter (RFC 8017 appendix A.2.4);
    /// ECDSA omits parameters entirely (RFC 5758 section 3.2). The
    /// difference is not cosmetic -- verifiers check it.
    fn algorithm_identifier(self) -> Vec<u8> {
        match self {
            Self::RsaPkcs1Sha256 => Self::rsa_identifier(oid::known::SHA256_WITH_RSA),
            Self::RsaPkcs1Sha384 => Self::rsa_identifier(oid::known::SHA384_WITH_RSA),
            Self::EcdsaSha256 => tlv(
                TAG_SEQUENCE,
                &tlv(TAG_OID, oid::known::ECDSA_WITH_SHA256.as_bytes()),
            ),
            Self::EcdsaSha384 => tlv(
                TAG_SEQUENCE,
                &tlv(TAG_OID, oid::known::ECDSA_WITH_SHA384.as_bytes()),
            ),
        }
    }

    /// An RSA `AlgorithmIdentifier`: OID plus the mandatory NULL.
    fn rsa_identifier(algorithm: oid::Oid<'_>) -> Vec<u8> {
        let mut body = tlv(TAG_OID, algorithm.as_bytes());
        // NULL is tag 0x05, length 0. Written as a literal pair rather
        // than through `tlv` because there is no value to pass.
        body.extend_from_slice(&[0x05, 0x00]);
        tlv(TAG_SEQUENCE, &body)
    }
}

/// Whether the signed content travels inside the structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encapsulation {
    /// `eContent` omitted. The verifier is given the document
    /// separately -- what `PAdES` and `ASiC` both need, because the
    /// document is the PDF or the container entry itself.
    Detached,
    /// `eContent` carried inside the `SignedData`. Self-contained, at
    /// the cost of storing the document twice if it is also kept
    /// alongside.
    Attached,
}

/// The exact octets the card must sign.
///
/// Carries the DER SET (`0x31`) form, which is what RFC 5652
/// section 5.4 signs -- not the `[0]` implicit form the same attributes
/// wear inside `SignerInfo`. Keeping the two apart in the type system
/// is the point of this wrapper existing at all.
#[derive(Debug, Clone)]
pub struct ToBeSigned {
    /// Attributes as a universal SET, ready to hash.
    der: Vec<u8>,
}

impl ToBeSigned {
    /// The octets to hash and send to the card.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.der
    }

    /// The digest the card signs, under `algorithm`.
    #[must_use]
    pub fn digest(&self, algorithm: DigestAlgorithm) -> Vec<u8> {
        algorithm.digest(&self.der)
    }
}

/// Signing time, as the `UTCTime` CMS wants.
///
/// `YYMMDDHHMMSSZ`, which is what RFC 5652 section 11.3 requires for
/// years before 2050. The caller supplies the parts rather than a clock:
/// this crate has no ambient time source, and a signature's claimed time
/// is the caller's assertion to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningTime {
    /// Year, four digits. Must be 1950..=2049 for the `UTCTime` form.
    pub year: u16,
    /// Month, 1..=12.
    pub month: u8,
    /// Day of month, 1..=31.
    pub day: u8,
    /// Hour, 0..=23.
    pub hour: u8,
    /// Minute, 0..=59.
    pub minute: u8,
    /// Second, 0..=59.
    pub second: u8,
}

impl SigningTime {
    /// Claimed signing time read from the system clock (UTC).
    ///
    /// The GUI and CLI layers call this at click time so the
    /// service core stays deterministic. Before the epoch the
    /// clock reads zero and this reports the epoch itself.
    #[must_use]
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self::from_unix_secs(secs)
    }

    /// Calendar fields for `secs` past the Unix epoch (UTC).
    ///
    /// Howard Hinnant's days-to-civil algorithm (public domain):
    /// the day count walks the 400-year Gregorian cycle, so leap
    /// years need no table. Field widths always fit for any clock
    /// value a live system reports; the fallbacks only exist to
    /// keep the conversion total.
    #[must_use]
    pub fn from_unix_secs(secs: u64) -> Self {
        const DAYS_TO_CIVIL_SHIFT: u64 = 719_468;
        const DAYS_PER_ERA: u64 = 146_097;
        const MONTHS_SHIFT: u64 = 153;
        const SECS_PER_DAY: u64 = 86_400;
        let days = secs / SECS_PER_DAY;
        let day_secs = secs % SECS_PER_DAY;
        let z = days + DAYS_TO_CIVIL_SHIFT;
        let era = z / DAYS_PER_ERA;
        let day_of_era = z - era * DAYS_PER_ERA;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let mut year = year_of_era + era * 400;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_prime = (5 * day_of_year + 2) / MONTHS_SHIFT;
        let day = day_of_year - (MONTHS_SHIFT * month_prime + 2) / 5 + 1;
        let month = if month_prime < 10 {
            month_prime + 3
        } else {
            month_prime - 9
        };
        if month <= 2 {
            year += 1;
        }
        Self {
            year: u16::try_from(year).unwrap_or(1970),
            month: u8::try_from(month).unwrap_or(1),
            day: u8::try_from(day).unwrap_or(1),
            hour: u8::try_from(day_secs / 3600).unwrap_or(0),
            minute: u8::try_from(day_secs / 60 % 60).unwrap_or(0),
            second: u8::try_from(day_secs % 60).unwrap_or(0),
        }
    }

    /// Lowest year the `UTCTime` two-digit form can express unambiguously.
    const UTC_TIME_FIRST_YEAR: u16 = 1950;

    /// First year that needs `GeneralizedTime` instead.
    const UTC_TIME_LAST_YEAR: u16 = 2050;

    /// Century divisor for the two-digit year.
    const YEAR_MODULO: u16 = 100;

    /// The `UTCTime` body, or `None` outside the representable range.
    fn to_utc_time(self) -> Option<Vec<u8>> {
        if self.year < Self::UTC_TIME_FIRST_YEAR || self.year >= Self::UTC_TIME_LAST_YEAR {
            return None;
        }
        let two_digit_year = self.year % Self::YEAR_MODULO;
        let mut text = Vec::with_capacity(13);
        Self::push_pair(&mut text, two_digit_year);
        Self::push_pair(&mut text, u16::from(self.month));
        Self::push_pair(&mut text, u16::from(self.day));
        Self::push_pair(&mut text, u16::from(self.hour));
        Self::push_pair(&mut text, u16::from(self.minute));
        Self::push_pair(&mut text, u16::from(self.second));
        text.push(b'Z');
        Some(text)
    }

    /// Two zero-padded ASCII digits of `value`.
    fn push_pair(out: &mut Vec<u8>, value: u16) {
        /// Radix for the decimal pair.
        const TEN: u16 = 10;
        let tens = (value / TEN) % TEN;
        let units = value % TEN;
        // `u8::try_from` cannot fail: both operands are < 10 by the
        // modulo above.
        out.push(b'0'.saturating_add(tens as u8));
        out.push(b'0'.saturating_add(units as u8));
    }
}

/// What the signature is being made over and by whom.
#[derive(Debug, Clone, Copy)]
pub struct SignerParameters<'a> {
    /// The signer's certificate, DER, as read from the card.
    pub certificate: &'a Certificate<'a>,
    /// Digest for the content and the attributes.
    pub digest_algorithm: DigestAlgorithm,
    /// Signature the card will produce.
    pub signature_algorithm: SignatureAlgorithm,
    /// Claimed signing time, if one is asserted.
    pub signing_time: Option<SigningTime>,
}

/// Build the signed attributes for one signer.
///
/// `content_digest` is the digest of the document under
/// `parameters.digest_algorithm` -- of the PDF byte ranges for `PAdES`,
/// of the container entry for `ASiC`, of the file for a detached
/// signature. This function never sees the document itself.
///
/// The four attributes are the `CAdES` B-B set. They are emitted in DER
/// SET order, which is ascending by encoded octets rather than by OID
/// value or by any order chosen here (X.690 section 11.6). A SET that is
/// merely in a sensible order is not DER and verifiers do reject it.
#[must_use]
pub fn signed_attributes(parameters: &SignerParameters<'_>, content_digest: &[u8]) -> ToBeSigned {
    let mut attributes: Vec<Vec<u8>> = Vec::with_capacity(4);

    attributes.push(attribute(
        oid::known::CONTENT_TYPE,
        tlv(TAG_OID, oid::known::DATA.as_bytes()),
    ));
    attributes.push(attribute(
        oid::known::MESSAGE_DIGEST,
        tlv(TAG_OCTET_STRING, content_digest),
    ));
    if let Some(time) = parameters.signing_time.and_then(SigningTime::to_utc_time) {
        attributes.push(attribute(
            crate::oids::SIGNING_TIME,
            tlv(TAG_UTC_TIME, &time),
        ));
    }
    attributes.push(attribute(
        crate::oids::SIGNING_CERTIFICATE_V2,
        signing_certificate_v2(parameters),
    ));

    attributes.sort_unstable();
    let mut body = Vec::new();
    for attribute_der in attributes {
        body.extend_from_slice(&attribute_der);
    }
    ToBeSigned {
        der: tlv(TAG_SET, &body),
    }
}

/// One `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }`.
fn attribute(attribute_type: oid::Oid<'_>, value_der: Vec<u8>) -> Vec<u8> {
    let mut body = tlv(TAG_OID, attribute_type.as_bytes());
    body.extend_from_slice(&tlv(TAG_SET, &value_der));
    tlv(TAG_SEQUENCE, &body)
}

/// `SigningCertificateV2` (RFC 5035 section 3), binding the signature to
/// the exact certificate that made it.
///
/// Without it a signature can be replayed against a different
/// certificate carrying the same key, which is why `CAdES` makes it
/// mandatory rather than optional.
///
/// `issuerSerial` is omitted. It is OPTIONAL in the ASN.1 and the
/// `certHash` already pins the certificate uniquely; including it would
/// add a second, weaker identifier that has to agree with the first.
fn signing_certificate_v2(parameters: &SignerParameters<'_>) -> Vec<u8> {
    let cert_hash = parameters
        .digest_algorithm
        .digest(parameters.certificate.raw_der);

    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256,
    //                            certHash OCTET STRING, ... }
    // The DEFAULT must be omitted when it is the value, per DER.
    let mut cert_id_body = Vec::new();
    if parameters.digest_algorithm != DigestAlgorithm::Sha256 {
        cert_id_body.extend_from_slice(&parameters.digest_algorithm.algorithm_identifier());
    }
    cert_id_body.extend_from_slice(&tlv(TAG_OCTET_STRING, &cert_hash));
    let cert_id = tlv(TAG_SEQUENCE, &cert_id_body);

    // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
    tlv(TAG_SEQUENCE, &tlv(TAG_SEQUENCE, &cert_id))
}

/// Convert a raw `r || s` ECDSA signature to the DER form CMS carries.
///
/// FINEID cards return the raw pair -- 96 bytes for P-384, per S1 v4.2
/// sec.3.8.3 -- and CMS wants `SEQUENCE { r INTEGER, s INTEGER }`. The
/// mismatch is silent in the worst way: the raw bytes go into the
/// `signature` OCTET STRING happily and produce a structure that every
/// verifier rejects for a reason that points nowhere near the encoding.
///
/// The card never returns DER, so nothing here tries to recognise it:
/// a pair whose first bytes happen to spell a SEQUENCE tag and a
/// plausible length is still a pair and is split like any other.
///
/// The reverse conversion, for XML signatures, is
/// [`crate::xades::ecdsa_signature_to_xml`]. Cards need this one;
/// signers that already produce DER need that one.
///
/// Returns `None` unless `raw` is an even, non-empty number of bytes.
#[must_use]
pub fn ecdsa_signature_to_cms(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return None;
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    let mut body = der_integer(r);
    body.extend_from_slice(&der_integer(s));
    Some(tlv(TAG_SEQUENCE, &body))
}

/// One coordinate as a DER INTEGER.
///
/// Two adjustments, both required by X.690 sec.8.3 and both a common
/// source of signatures that verify in one library and not another:
/// leading zero octets are stripped because DER INTEGERs are minimal,
/// and a zero octet is then prepended when the top bit is set, because
/// without it the value would read as negative.
fn der_integer(coordinate: &[u8]) -> Vec<u8> {
    // All zero falls back to a single `0x00`: a DER INTEGER always has
    // at least one content octet.
    let magnitude = coordinate.iter().position(|byte| *byte != 0).map_or_else(
        || &[0][..],
        |first| coordinate.get(first..).unwrap_or_default(),
    );
    let mut value = Vec::with_capacity(magnitude.len().saturating_add(1));
    if magnitude.first().is_some_and(|byte| *byte & 0x80 != 0) {
        value.push(0);
    }
    value.extend_from_slice(magnitude);
    tlv(TAG_INTEGER, &value)
}

/// Assemble the finished `ContentInfo`-wrapped `SignedData`.
///
/// `signature` is what the card returned for
/// `signed_attributes(..).digest(..)`. `content` is the document, needed
/// only for [`Encapsulation::Attached`]; detached signatures ignore it.
///
/// The `attributes` are re-tagged from SET to implicit `[0]` here, which
/// is the one place in this module allowed to do that.
#[must_use]
pub fn signed_data(
    parameters: &SignerParameters<'_>,
    attributes: &ToBeSigned,
    signature: &[u8],
    encapsulation: Encapsulation,
    content: &[u8],
    material: &ValidationMaterial,
    timestamps: &[Vec<u8>],
) -> Vec<u8> {
    let signature = SignatureParts {
        parameters,
        attributes,
        signature,
        material,
        timestamps,
    };
    signature.assemble(encapsulation, content, &[])
}

/// The input of an `archive-time-stamp-v3` over the signature
/// [`signed_data`] builds from the same arguments, and the
/// `ats-hash-index-v3` it is computed with (`ETSI EN 319 122-1`
/// V1.3.1 clauses 5.5.2 and 5.5.3), both under `algorithm`.
///
/// `content` is the signed document, attached or not: item 2 of the
/// input is its hash.
#[must_use]
pub fn archive_input_v3(
    parameters: &SignerParameters<'_>,
    attributes: &ToBeSigned,
    signature: &[u8],
    content: &[u8],
    material: &ValidationMaterial,
    timestamps: &[Vec<u8>],
    algorithm: DigestAlgorithm,
) -> ArchiveInputV3 {
    SignatureParts {
        parameters,
        attributes,
        signature,
        material,
        timestamps,
    }
    .archive_input(content, algorithm)
}

/// [`signed_data`] with an `archive-time-stamp-v3` attribute: `token`
/// is an RFC 3161 token over [`ArchiveInputV3::input`] of the same
/// arguments, and the attribute carries it with that input's
/// `ats-hash-index-v3` added to the token's own unsigned attributes, as
/// clause 5.5.3 requires.
///
/// `None` when `token` is not a `ContentInfo` holding a `SignedData`
/// with one `SignerInfo` in DER.
#[must_use]
#[expect(
    clippy::too_many_arguments,
    reason = "the signature's parts, its document, and the archive token"
)]
pub fn signed_data_archived(
    parameters: &SignerParameters<'_>,
    attributes: &ToBeSigned,
    signature: &[u8],
    encapsulation: Encapsulation,
    content: &[u8],
    material: &ValidationMaterial,
    timestamps: &[Vec<u8>],
    token: &[u8],
    algorithm: DigestAlgorithm,
) -> Option<Vec<u8>> {
    let parts = SignatureParts {
        parameters,
        attributes,
        signature,
        material,
        timestamps,
    };
    let archive = parts.archive_input(content, algorithm);
    let indexed = with_unsigned_attribute(
        token,
        &attribute(oid::known::ATS_HASH_INDEX_V3, archive.index),
    )?;
    Some(parts.assemble(
        encapsulation,
        content,
        &[attribute(oid::known::ARCHIVE_TIME_STAMP_V3, indexed)],
    ))
}

/// What an `archive-time-stamp-v3` token imprints, and the
/// `ats-hash-index-v3` that goes into the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveInputV3 {
    /// Items 1 to 4 of clause 5.5.3, concatenated.
    input: Vec<u8>,
    /// The `ATSHashIndexV3`, DER.
    index: Vec<u8>,
}

impl ArchiveInputV3 {
    /// The octets the token's message imprint digests.
    #[must_use]
    pub fn input(&self) -> &[u8] {
        &self.input
    }
}

/// Everything a signature is assembled from, once the card has signed.
struct SignatureParts<'a> {
    /// The signer.
    parameters: &'a SignerParameters<'a>,
    /// The signed attributes.
    attributes: &'a ToBeSigned,
    /// The signature value, DER for ECDSA.
    signature: &'a [u8],
    /// The validation material for `certificates` and `crls`.
    material: &'a ValidationMaterial,
    /// The signature timestamp tokens.
    timestamps: &'a [Vec<u8>],
}

impl SignatureParts<'_> {
    /// `SignedData.certificates` entries, in DER SET order.
    ///
    /// The signer's certificate, then whatever completes the chain. A
    /// verifier that has to fetch an issuer is a verifier that stops
    /// working the day the fetch does. `certificates [0] IMPLICIT
    /// CertificateSet` is a SET OF, so DER orders it by encoding rather
    /// than by the order the chain was walked in (X.690 sec.11.6).
    fn certificates(&self) -> Vec<Vec<u8>> {
        let mut certificates: Vec<Vec<u8>> = vec![self.parameters.certificate.raw_der.to_vec()];
        certificates.extend(self.material.certificates.iter().cloned());
        certificates.sort_unstable();
        certificates.dedup();
        certificates
    }

    /// `SignedData.crls` entries, in DER SET order. A CRL goes in as
    /// itself; an OCSP response has no CHOICE of its own and travels
    /// wrapped as `other`, per RFC 5940.
    fn revocation_choices(&self) -> Vec<Vec<u8>> {
        let mut choices = Vec::new();
        for crl in &self.material.crls {
            choices.push(crl.clone());
        }
        for response in &self.material.ocsp_responses {
            // `other [1] IMPLICIT OtherRevocationInfoFormat`. IMPLICIT
            // replaces the SEQUENCE tag with the `[1]` -- it does not
            // wrap it. Writing `[1] { SEQUENCE { .. } }` is one layer
            // too many, and a parser reading the contents as an OID
            // meets a SEQUENCE tag and gives up.
            let mut other = tlv(
                TAG_OID,
                crate::oids::OCSP_RESPONSE_REVOCATION_INFO.as_bytes(),
            );
            other.extend_from_slice(response);
            choices.push(tlv(TAG_CONTEXT_1, &other));
        }
        // DER SET OF, so ordered by encoding rather than by the order
        // the responders answered in.
        choices.sort_unstable();
        choices.dedup();
        choices
    }

    /// The signature timestamp attributes, one instance per token.
    ///
    /// One attribute instance per token rather than one attribute
    /// holding several values: `EN 319 122-1` says several instances of
    /// signature-time-stamp may occur, from different TSAs, and that is
    /// the shape validators look for. Each token attests the same
    /// signature, so they are alternatives rather than a sequence -- one
    /// surviving is enough.
    fn timestamp_attributes(&self) -> Vec<Vec<u8>> {
        self.timestamps
            .iter()
            .map(|token| attribute(crate::oids::SIGNATURE_TIME_STAMP_TOKEN, token.clone()))
            .collect()
    }

    /// `SignerInfo` from `version` to `signature`, the fields item 3 of
    /// `ETSI EN 319 122-1` clause 5.5.3 archives.
    fn signer_fields(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&tlv(TAG_INTEGER, &[CMS_VERSION_V1]));
        body.extend_from_slice(&issuer_and_serial(self.parameters.certificate));
        body.extend_from_slice(&self.parameters.digest_algorithm.algorithm_identifier());

        // The SET tag the attributes were signed under becomes the
        // implicit [0] the structure carries. Same contents, same
        // length; only the first octet differs.
        let mut tagged_attributes = self.attributes.as_bytes().to_vec();
        if let Some(first) = tagged_attributes.first_mut() {
            *first = TAG_CONTEXT_0;
        }
        body.extend_from_slice(&tagged_attributes);

        body.extend_from_slice(&self.parameters.signature_algorithm.algorithm_identifier());
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, self.signature));
        body
    }

    /// Items 1 to 4 of `ETSI EN 319 122-1` V1.3.1 clause 5.5.3 under
    /// `algorithm`, with the `ATSHashIndexV3` of clause 5.5.2: the hash
    /// of every `certificates` and `crls` entry and of every unsigned
    /// attribute value with its `attrType`, as each is encoded.
    fn archive_input(&self, content: &[u8], algorithm: DigestAlgorithm) -> ArchiveInputV3 {
        let hashes = |items: Vec<Vec<u8>>| {
            let mut list = Vec::new();
            for item in items {
                list.extend_from_slice(&tlv(TAG_OCTET_STRING, &algorithm.digest(&item)));
            }
            tlv(TAG_SEQUENCE, &list)
        };
        let attribute_values = self
            .timestamps
            .iter()
            .map(|token| {
                let mut value = tlv(TAG_OID, crate::oids::SIGNATURE_TIME_STAMP_TOKEN.as_bytes());
                value.extend_from_slice(token);
                value
            })
            .collect();
        let mut index = algorithm.algorithm_identifier();
        index.extend_from_slice(&hashes(self.certificates()));
        index.extend_from_slice(&hashes(self.revocation_choices()));
        index.extend_from_slice(&hashes(attribute_values));
        let index = tlv(TAG_SEQUENCE, &index);

        let mut input = tlv(TAG_OID, oid::known::DATA.as_bytes());
        input.extend_from_slice(&algorithm.digest(content));
        input.extend_from_slice(&self.signer_fields());
        input.extend_from_slice(&index);
        ArchiveInputV3 { input, index }
    }

    /// The `ContentInfo`, its `SignerInfo` carrying the signature
    /// timestamps and `more_unsigned` as unsigned attributes.
    fn assemble(
        &self,
        encapsulation: Encapsulation,
        content: &[u8],
        more_unsigned: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut signed_data_body = Vec::new();

        // RFC 5652 sec.5.1: the version is 5 once `crls` carries
        // anything of the `other` choice, which an OCSP response is.
        // Leaving it at 1 produces a structure a strict parser rejects.
        let version = if self.material.ocsp_responses.is_empty() {
            CMS_VERSION_V1
        } else {
            CMS_VERSION_V5
        };
        signed_data_body.extend_from_slice(&tlv(TAG_INTEGER, &[version]));
        signed_data_body.extend_from_slice(&tlv(
            TAG_SET,
            &self.parameters.digest_algorithm.algorithm_identifier(),
        ));
        signed_data_body.extend_from_slice(&encapsulated_content(encapsulation, content));
        signed_data_body.extend_from_slice(&tlv(TAG_CONTEXT_0, &self.certificates().concat()));
        let choices = self.revocation_choices();
        if !choices.is_empty() {
            signed_data_body.extend_from_slice(&tlv(TAG_CONTEXT_1, &choices.concat()));
        }

        let mut signer_info = self.signer_fields();
        // `unsignedAttrs [1] IMPLICIT`, after the signature because it
        // is computed over it. A timestamp cannot live among the signed
        // attributes for the same reason a photograph cannot contain
        // the camera that took it.
        let mut unsigned = self.timestamp_attributes();
        unsigned.extend(more_unsigned.iter().cloned());
        // DER SET OF is ordered by encoding (X.690 sec.11.6).
        unsigned.sort_unstable();
        unsigned.dedup();
        if !unsigned.is_empty() {
            signer_info.extend_from_slice(&tlv(TAG_CONTEXT_1, &unsigned.concat()));
        }
        signed_data_body.extend_from_slice(&tlv(TAG_SET, &tlv(TAG_SEQUENCE, &signer_info)));

        let signed_data_der = tlv(TAG_SEQUENCE, &signed_data_body);

        // ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT }
        let mut content_info = tlv(TAG_OID, oid::known::SIGNED_DATA.as_bytes());
        content_info.extend_from_slice(&tlv(TAG_CONTEXT_0, &signed_data_der));
        tlv(TAG_SEQUENCE, &content_info)
    }
}

/// `token`, a `ContentInfo` holding a `SignedData` with one
/// `SignerInfo`, with `attribute` added to that `SignerInfo`'s unsigned
/// attributes in DER SET order. Every other octet is kept as the
/// authority encoded it, so its signature over the signed attributes
/// still verifies. `None` for any other shape, or one not in DER
/// definite lengths.
fn with_unsigned_attribute(token: &[u8], attribute: &[u8]) -> Option<Vec<u8>> {
    /// The complete TLVs inside `value`, which must tile it exactly.
    fn children(value: &[u8]) -> Option<Vec<&[u8]>> {
        let mut out = Vec::new();
        let mut rest = value;
        while !rest.is_empty() {
            let size = crate::ber::BerTlvAny::parse(rest).ok()?.size();
            let (child, tail) = rest.split_at_checked(size)?;
            if child.is_empty() {
                return None;
            }
            out.push(child);
            rest = tail;
        }
        Some(out)
    }
    /// The value of `der`, a single TLV tagged `tag` spanning it.
    fn value_of(der: &[u8], tag: u8) -> Option<&[u8]> {
        let parsed = crate::ber::BerTlvAny::parse(der).ok()?;
        (parsed.size() == der.len() && parsed.tag() == u16::from(tag)).then(|| parsed.value())
    }

    let content_info = children(value_of(token, TAG_SEQUENCE)?)?;
    let [content_type, wrapped] = content_info.as_slice() else {
        return None;
    };
    let signed_data = value_of(value_of(wrapped, TAG_CONTEXT_0)?, TAG_SEQUENCE)?;
    let mut fields = children(signed_data)?;
    let signer_infos = children(value_of(fields.pop()?, TAG_SET)?)?;
    let [signer_info] = signer_infos.as_slice() else {
        return None;
    };
    let mut signer_fields = children(value_of(signer_info, TAG_SEQUENCE)?)?;
    let mut unsigned: Vec<Vec<u8>> = match signer_fields.last() {
        Some(last) if last.first() == Some(&TAG_CONTEXT_1) => {
            let existing = children(value_of(last, TAG_CONTEXT_1)?)?
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect();
            signer_fields.pop();
            existing
        }
        _ => Vec::new(),
    };
    unsigned.push(attribute.to_vec());
    unsigned.sort_unstable();
    let mut signer_body = signer_fields.concat();
    signer_body.extend_from_slice(&tlv(TAG_CONTEXT_1, &unsigned.concat()));
    let mut signed_body = fields.concat();
    signed_body.extend_from_slice(&tlv(TAG_SET, &tlv(TAG_SEQUENCE, &signer_body)));
    let mut outer = content_type.to_vec();
    outer.extend_from_slice(&tlv(TAG_CONTEXT_0, &tlv(TAG_SEQUENCE, &signed_body)));
    Some(tlv(TAG_SEQUENCE, &outer))
}

/// `EncapsulatedContentInfo`: the type, and the content when attached.
fn encapsulated_content(encapsulation: Encapsulation, content: &[u8]) -> Vec<u8> {
    let mut body = tlv(TAG_OID, oid::known::DATA.as_bytes());
    if encapsulation == Encapsulation::Attached {
        body.extend_from_slice(&tlv(TAG_CONTEXT_0, &tlv(TAG_OCTET_STRING, content)));
    }
    tlv(TAG_SEQUENCE, &body)
}

/// `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`.
///
/// Both come from the parsed certificate as raw DER, so the issuer name
/// is byte-identical to the one in the certificate. Re-encoding a name
/// is how signatures stop verifying: two DER encodings of the "same"
/// name are not the same octets.
fn issuer_and_serial(certificate: &Certificate<'_>) -> Vec<u8> {
    let mut body = certificate.issuer.as_der().to_vec();
    // `serial_der` is the INTEGER *value* octets -- no tag, no length --
    // because the parser preserves any leading sign byte for OCSP and
    // CRL comparison. It has to be re-wrapped here, and writing it raw
    // produces a structure OpenSSL rejects at exactly this offset.
    body.extend_from_slice(&tlv(TAG_INTEGER, certificate.serial_der.as_bytes()));
    tlv(TAG_SEQUENCE, &body)
}

#[cfg(test)]
mod tests {
    use crate::validation::ValidationMaterial;
    /// `other [1] IMPLICIT OtherRevocationInfoFormat` replaces the
    /// SEQUENCE tag rather than wrapping it. The wrapped form is
    /// well-formed DER that parses as far as the `[1]`, then hands a
    /// SEQUENCE tag to something expecting an OID -- so a validator
    /// throws rather than reporting an invalid signature. Two of them
    /// answered HTTP 500 before this was right.
    #[test]
    fn an_ocsp_response_is_tagged_implicitly_not_wrapped() {
        let certificate = crate::test_support::parse_certificate_for_test(fixture_certificate());
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: None,
        };
        let attributes = signed_attributes(&parameters, &[0x11; 32]);
        // A stand-in response: a SEQUENCE the encoder must not add a
        // second SEQUENCE in front of.
        let response = vec![0x30, 0x03, 0x02, 0x01, 0x07];
        let material = ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: vec![response],
            crls: Vec::new(),
        };
        let cms = signed_data(
            &parameters,
            &attributes,
            &[0xAA_u8; 384],
            Encapsulation::Detached,
            &[],
            &material,
            &[],
        );

        // `A1` then the OID, with no `30` in between.
        let oid = [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x10, 0x02];
        let at = cms
            .windows(oid.len())
            .position(|window| window == oid)
            .expect("the RFC 5940 OID must be present");
        assert_eq!(
            cms[at - 2],
            0xA1,
            "the OID must sit directly inside the [1] tag, not behind a SEQUENCE"
        );

        // And the version rises to 5, as RFC 5652 sec.5.1 requires once
        // anything of the `other` choice is present.
        assert!(
            cms.windows(3).any(|w| w == [0x02, 0x01, 0x05]),
            "CMS version must be 5 when crls carries an OCSP response"
        );
    }

    /// The two encodings of one ECDSA signature, and the round trip
    /// between them. A card hands out the raw pair; CMS wants DER; XML
    /// wants the raw pair back. Getting either direction wrong produces
    /// a document that is well-formed and unverifiable.
    #[test]
    fn raw_ecdsa_becomes_der_and_back() {
        use crate::xades::ecdsa_signature_to_xml;

        // r has its top bit set, so DER must prepend a zero octet; s
        // has leading zeros, which DER must strip.
        let raw = [0xFF, 0x01, 0x02, 0x03, 0x00, 0x00, 0x0A, 0x0B];
        let der = super::ecdsa_signature_to_cms(&raw).expect("der");
        assert_eq!(
            der,
            vec![
                0x30, 0x0B, // SEQUENCE, 11 bytes: a 7-byte r and a 4-byte s
                0x02, 0x05, 0x00, 0xFF, 0x01, 0x02, 0x03, // r, sign byte added
                0x02, 0x02, 0x0A, 0x0B, // s, leading zeros stripped
            ]
        );
        // Back to the fixed-width form the card produced.
        assert_eq!(
            ecdsa_signature_to_xml(&der, raw.len() / 2).expect("raw"),
            raw.to_vec()
        );

        // A zero coordinate still needs one content octet.
        let zero = super::ecdsa_signature_to_cms(&[0x00, 0x00]).expect("der");
        assert_eq!(zero, vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);

        // An odd length cannot be split into two coordinates.
        assert_eq!(super::ecdsa_signature_to_cms(&[0x01, 0x02, 0x03]), None);
        assert_eq!(super::ecdsa_signature_to_cms(&[]), None);
    }

    /// The card returns only the raw pair (FINEID S1 v4.2 sec.3.8.3), so
    /// a pair whose leading bytes spell a SEQUENCE header is split like
    /// any other instead of being passed through as DER.
    #[test]
    fn a_raw_pair_that_starts_like_a_der_sequence_is_still_split() {
        use crate::xades::ecdsa_signature_to_xml;

        /// A P-384 `r || s` pair (FINEID S1 v4.2 sec.3.8.3).
        const P384_RAW_SIGNATURE_LEN: usize = 96;
        /// Long-form length with one following octet (X.690 sec.8.1.3.5).
        const DER_LONG_FORM_ONE_BYTE: u8 = 0x81;
        /// Long-form length with two following octets (X.690 sec.8.1.3.5).
        const DER_LONG_FORM_TWO_BYTES: u8 = 0x82;
        /// Short-form length (X.690 sec.8.1.3.4) equal to the bytes after
        /// a tag and one length octet.
        const DER_SHORT_LENGTH_OF_REMAINDER: u8 = (P384_RAW_SIGNATURE_LEN - 2) as u8;
        /// Bytes after a tag, a long-form marker and one length octet.
        const DER_ONE_BYTE_LENGTH_OF_REMAINDER: u8 = (P384_RAW_SIGNATURE_LEN - 3) as u8;
        /// Bytes after a tag, a long-form marker and two length octets,
        /// as the high and low octet of a two-octet length.
        const DER_TWO_BYTE_LENGTH_OF_REMAINDER: [u8; 2] = [0, (P384_RAW_SIGNATURE_LEN - 4) as u8];

        let short_form = [super::TAG_SEQUENCE, DER_SHORT_LENGTH_OF_REMAINDER];
        let one_byte_form = [
            super::TAG_SEQUENCE,
            DER_LONG_FORM_ONE_BYTE,
            DER_ONE_BYTE_LENGTH_OF_REMAINDER,
        ];
        let two_byte_form = [
            super::TAG_SEQUENCE,
            DER_LONG_FORM_TWO_BYTES,
            DER_TWO_BYTE_LENGTH_OF_REMAINDER[0],
            DER_TWO_BYTE_LENGTH_OF_REMAINDER[1],
        ];

        for header in [&short_form[..], &one_byte_form[..], &two_byte_form[..]] {
            let mut raw = vec![0_u8; P384_RAW_SIGNATURE_LEN];
            raw[..header.len()].copy_from_slice(header);
            raw[P384_RAW_SIGNATURE_LEN - 1] = 1;

            let der = super::ecdsa_signature_to_cms(&raw).expect("der");
            assert_ne!(der, raw, "header {header:?} was passed through as DER");
            assert_eq!(der.first(), Some(&super::TAG_SEQUENCE));
            assert_eq!(
                ecdsa_signature_to_xml(&der, P384_RAW_SIGNATURE_LEN / 2).expect("raw"),
                raw,
                "header {header:?} did not survive the round trip"
            );
        }
    }

    use super::{
        DigestAlgorithm, Encapsulation, SignatureAlgorithm, SignerParameters, SigningTime,
        signed_attributes, signed_data,
    };

    /// Universal SET, the tag the attributes are signed under.
    const TAG_SET: u8 = 0x31;

    /// Implicit `[0]`, the tag they wear inside `SignerInfo`.
    const TAG_CONTEXT_0: u8 = 0xA0;

    /// A fixed signing time, so the attribute bytes are deterministic
    /// and a fixture signature stays valid.
    const FIXED_TIME: SigningTime = SigningTime {
        year: 2026,
        month: 8,
        day: 3,
        hour: 12,
        minute: 0,
        second: 0,
    };

    /// A committed FINEID intermediate, used only as a well-formed
    /// certificate to encode issuer/serial and hash. Nothing here
    /// verifies against its key.
    fn fixture_certificate() -> &'static [u8] {
        include_bytes!("../test-vectors/fineid-intermediate-01-citizen-g4e.der")
    }

    /// Walk consecutive TLVs, returning each element's whole encoding.
    fn elements(mut body: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        while !body.is_empty() {
            let (header, length) = length_at(body);
            let total = header + length;
            out.push(&body[..total]);
            body = &body[total..];
        }
        out
    }

    /// Header size and value length of the TLV at the front of `der`.
    fn length_at(der: &[u8]) -> (usize, usize) {
        /// Long-form marker bit.
        const LONG_FORM: u8 = 0x80;
        /// Mask for the count of length octets in the long form.
        const COUNT_MASK: u8 = 0x7F;
        let first = der[1];
        if first & LONG_FORM == 0 {
            return (2, usize::from(first));
        }
        let count = usize::from(first & COUNT_MASK);
        let mut length = 0_usize;
        for byte in &der[2..2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (2 + count, length)
    }

    #[test]
    fn signs_the_set_form_not_the_context_form() {
        let der = fixture_certificate();
        let certificate = crate::test_support::parse_certificate_for_test(der);
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(FIXED_TIME),
        };
        let attributes = signed_attributes(&parameters, &[0x11_u8; 32]);

        // What the card signs must be the universal SET.
        assert_eq!(attributes.as_bytes()[0], TAG_SET);

        // What the structure carries must be the implicit [0], and
        // must be otherwise byte-identical: same length, same body.
        let assembled = signed_data(
            &parameters,
            &attributes,
            &[0xAA_u8; 384],
            Encapsulation::Detached,
            &[],
            &ValidationMaterial::default(),
            &[],
        );
        let signed_form = attributes.as_bytes();
        let mut carried_form = signed_form.to_vec();
        carried_form[0] = TAG_CONTEXT_0;
        assert!(
            assembled
                .windows(carried_form.len())
                .any(|window| window == carried_form.as_slice()),
            "SignerInfo must carry the [0] re-tagging of the signed SET"
        );
        assert!(
            !assembled
                .windows(signed_form.len())
                .any(|window| window == signed_form),
            "the universal SET form must not appear in the structure"
        );
    }

    #[test]
    fn attributes_are_in_der_set_order() {
        let der = fixture_certificate();
        let certificate = crate::test_support::parse_certificate_for_test(der);
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(FIXED_TIME),
        };
        let attributes = signed_attributes(&parameters, &[0x22_u8; 32]);

        let (header, _) = length_at(attributes.as_bytes());
        let members = elements(&attributes.as_bytes()[header..]);
        assert_eq!(members.len(), 4, "content-type, digest, time, cert-v2");

        // X.690 sec.11.6: a DER SET OF is sorted by encoded octets.
        let mut sorted = members.clone();
        sorted.sort_unstable();
        assert_eq!(members, sorted, "SET OF members must be in DER order");
    }

    #[test]
    fn omitting_signing_time_drops_the_attribute() {
        let der = fixture_certificate();
        let certificate = crate::test_support::parse_certificate_for_test(der);
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: None,
        };
        let attributes = signed_attributes(&parameters, &[0x33_u8; 32]);
        let (header, _) = length_at(attributes.as_bytes());
        assert_eq!(elements(&attributes.as_bytes()[header..]).len(), 3);
    }

    #[test]
    fn detached_omits_econtent_and_attached_carries_it() {
        let der = fixture_certificate();
        let certificate = crate::test_support::parse_certificate_for_test(der);
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(FIXED_TIME),
        };
        let attributes = signed_attributes(&parameters, &[0x44_u8; 32]);
        let document = b"declaration of a means of cryptology";

        let detached = signed_data(
            &parameters,
            &attributes,
            &[0xBB_u8; 384],
            Encapsulation::Detached,
            document,
            &ValidationMaterial::default(),
            &[],
        );
        let attached = signed_data(
            &parameters,
            &attributes,
            &[0xBB_u8; 384],
            Encapsulation::Attached,
            document,
            &ValidationMaterial::default(),
            &[],
        );
        assert!(
            !detached
                .windows(document.len())
                .any(|window| window == document),
            "a detached signature must not carry the document"
        );
        assert!(
            attached
                .windows(document.len())
                .any(|window| window == document),
            "an attached signature must carry the document"
        );
    }
}

/// End-to-end interoperability against OpenSSL.
///
/// Structural tests prove the encoder agrees with its author. These
/// prove it agrees with an independent implementation, which is the
/// only thing that matters for a signature format: the verifier is
/// never us.
///
/// Ignored by default because they shell out to `openssl`. Run with:
///
/// ```text
/// cargo test -p refineid-lib-core --lib sign::cades::openssl -- --ignored
/// ```
#[cfg(test)]
mod openssl_interop {
    use crate::validation::ValidationMaterial;
    use std::process::Command;

    use super::{
        DigestAlgorithm, Encapsulation, SignatureAlgorithm, SignerParameters, SigningTime,
        signed_attributes, signed_data,
    };

    /// Runs a command, returning stdout and failing loudly otherwise.
    fn run(program: &str, args: &[&str]) -> Vec<u8> {
        let output = Command::new(program)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("{program} not runnable: {error}"));
        assert!(
            output.status.success(),
            "{program} {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[test]
    #[ignore = "requires the openssl binary"]
    fn openssl_verifies_an_attached_signature() {
        let dir = std::env::temp_dir().join("refineid-cades-interop");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();

        // A throwaway signer. The card is simulated by asking OpenSSL
        // to raw-sign the same digest the card would be given.
        run("openssl", &["genrsa", "-out", &path("key.pem"), "3072"]);
        run(
            "openssl",
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                &path("key.pem"),
                "-out",
                &path("cert.pem"),
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=RefineID CAdES interop",
            ],
        );
        run(
            "openssl",
            &[
                "x509",
                "-in",
                &path("cert.pem"),
                "-outform",
                "DER",
                "-out",
                &path("cert.der"),
            ],
        );

        let cert_der = std::fs::read(path("cert.der")).expect("cert der");
        let certificate = crate::test_support::parse_certificate_for_test(&cert_der);
        let document = b"RefineID -- declaration of a means of cryptology";

        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(SigningTime {
                year: 2026,
                month: 8,
                day: 3,
                hour: 12,
                minute: 0,
                second: 0,
            }),
        };

        let content_digest = parameters.digest_algorithm.digest(document);
        let attributes = signed_attributes(&parameters, &content_digest);

        // What the card would be handed. Signed here by OpenSSL over
        // the same octets, using PKCS#1 v1.5 with SHA-256.
        std::fs::write(path("tbs.der"), attributes.as_bytes()).expect("write tbs");
        run(
            "openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                &path("key.pem"),
                "-out",
                &path("sig.bin"),
                &path("tbs.der"),
            ],
        );
        let signature = std::fs::read(path("sig.bin")).expect("signature");

        let cms = signed_data(
            &parameters,
            &attributes,
            &signature,
            Encapsulation::Attached,
            document,
            &ValidationMaterial::default(),
            &[],
        );
        std::fs::write(path("out.p7s"), &cms).expect("write cms");

        // The verdict that counts.
        run(
            "openssl",
            &[
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                &path("out.p7s"),
                "-CAfile",
                &path("cert.pem"),
                "-purpose",
                "any",
                "-out",
                &path("recovered.bin"),
            ],
        );
        let recovered = std::fs::read(path("recovered.bin")).expect("recovered content");
        assert_eq!(recovered, document, "OpenSSL recovered the signed content");
    }

    #[test]
    #[ignore = "requires the openssl binary"]
    fn openssl_verifies_a_detached_signature() {
        let dir = std::env::temp_dir().join("refineid-cades-interop-detached");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();

        run("openssl", &["genrsa", "-out", &path("key.pem"), "3072"]);
        run(
            "openssl",
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                &path("key.pem"),
                "-out",
                &path("cert.pem"),
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=RefineID CAdES detached",
            ],
        );
        run(
            "openssl",
            &[
                "x509",
                "-in",
                &path("cert.pem"),
                "-outform",
                "DER",
                "-out",
                &path("cert.der"),
            ],
        );

        let cert_der = std::fs::read(path("cert.der")).expect("cert der");
        let certificate = crate::test_support::parse_certificate_for_test(&cert_der);
        let document = b"detached over the document, as PAdES and ASiC need";
        std::fs::write(path("doc.bin"), document).expect("write doc");

        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: None,
        };
        let content_digest = parameters.digest_algorithm.digest(document);
        let attributes = signed_attributes(&parameters, &content_digest);
        std::fs::write(path("tbs.der"), attributes.as_bytes()).expect("write tbs");
        run(
            "openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                &path("key.pem"),
                "-out",
                &path("sig.bin"),
                &path("tbs.der"),
            ],
        );
        let signature = std::fs::read(path("sig.bin")).expect("signature");

        let cms = signed_data(
            &parameters,
            &attributes,
            &signature,
            Encapsulation::Detached,
            &[],
            &ValidationMaterial::default(),
            &[],
        );
        std::fs::write(path("out.p7s"), &cms).expect("write cms");

        run(
            "openssl",
            &[
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                &path("out.p7s"),
                "-content",
                &path("doc.bin"),
                "-CAfile",
                &path("cert.pem"),
                "-purpose",
                "any",
                "-out",
                &path("/dev/null"),
            ],
        );
    }

    #[test]
    fn unix_epoch_is_1970_01_01() {
        let time = SigningTime::from_unix_secs(0);
        assert_eq!(
            (
                time.year,
                time.month,
                time.day,
                time.hour,
                time.minute,
                time.second
            ),
            (1970, 1, 1, 0, 0, 0)
        );
    }

    #[test]
    fn known_dates_round_trip_through_civil() {
        // 2026-01-01 00:00:00 UTC.
        let time = SigningTime::from_unix_secs(1_767_225_600);
        assert_eq!(
            (
                time.year,
                time.month,
                time.day,
                time.hour,
                time.minute,
                time.second
            ),
            (2026, 1, 1, 0, 0, 0)
        );
        // 2024-02-29 12:34:56 UTC: leap day plus a time of day.
        let time = SigningTime::from_unix_secs(1_709_210_096);
        assert_eq!(
            (
                time.year,
                time.month,
                time.day,
                time.hour,
                time.minute,
                time.second
            ),
            (2024, 2, 29, 12, 34, 56)
        );
    }
}
