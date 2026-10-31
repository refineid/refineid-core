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

//! Minimal X.509 CRL (Certificate Revocation List) parser,
//! scoped to revocation checking.
//!
//! Given the DER bytes of an RFC 5280 `CertificateList`, exposes
//! the issuer DN, `thisUpdate`, optional `nextUpdate`, and a
//! `Crl::find_serial` lookup over the revoked-cert list. The parser
//! does **not** verify the CRL's signature -- that ties to the issuer
//! trust store and lives a layer up.
//!
//! A [`Crl`] exists only for a *complete* list: one whose absence of a
//! serial means "not revoked by this issuer". The parser refuses a
//! delta CRL (RFC 5280 sec.5.2.4), a CRL scoped by an issuing
//! distribution point (sec.5.2.5), any critical CRL or entry extension
//! this reader does not process (sec.5.2, sec.5.3), and a revoked list
//! with an entry that does not decode.
//!
//! Per-entry extensions: the `reasonCode` extension (OID
//! `2.5.29.21`) is parsed and surfaced as
//! [`RevokedEntry::reason`]. Non-critical extensions at either level
//! say nothing about which certificates the list covers and are
//! passed over.
//!
//! Decoded with the `der` / `x509-cert` `RustCrypto` stack and reuses
//! the time parser from [`crate::x509`]. The module ships in full;
//! the higher-level revocation flow that wires it in is queued.

use crate::identity::CertSerial;
use refineid_cms::oid::Oid;
use refineid_cms::x509::{Certificate, DateTime, X509Error, extract_key_usage};
use spki::der::asn1::{AnyRef, ObjectIdentifier};
use spki::der::{Decode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _};
use x509_cert::crl::RevokedCert;
use x509_cert::ext::{Extension, Extensions};

/// The unused-bits octet a DER signature BIT STRING carries: a
/// signature is whole octets, so none of its bits are unused
/// (X.690 sec.8.6.2.2).
pub(crate) const SIGNATURE_BIT_STRING_UNUSED_BITS: u8 = 0;

/// The signature octets of a signature BIT STRING's value: its
/// unused-bits octet must be [`SIGNATURE_BIT_STRING_UNUSED_BITS`] and
/// at least one octet must follow. `what` names the field in the error.
pub(crate) fn signature_octets<'a>(
    bit_string_value: &'a [u8],
    what: &'static str,
) -> Result<&'a [u8], X509Error> {
    match bit_string_value {
        [SIGNATURE_BIT_STRING_UNUSED_BITS, octets @ ..] if !octets.is_empty() => Ok(octets),
        _ => Err(X509Error::UnexpectedStructure(what)),
    }
}

/// The `Version` value of a v2 CRL (RFC 5280 sec.5.1.2.1: `v2(1)`).
/// A v1 CRL omits the field and carries no extensions at either level
/// (sec.5.1.2.6, sec.5.1.2.7).
const CRL_VERSION_2: u8 = 1;

/// Why bytes are not a complete CRL this reader can answer from.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlError {
    /// The DER does not have the `CertificateList` shape (RFC 5280
    /// sec.5.1), or a field inside it does not decode.
    Malformed(X509Error),
    /// The CRL carries `deltaCRLIndicator` (RFC 5280 sec.5.2.4): it
    /// lists only changes since a base CRL.
    Delta,
    /// The CRL carries `issuingDistributionPoint` (RFC 5280
    /// sec.5.2.5): it covers only one partition of the issuer's
    /// certificates, which no caller here names.
    Scoped,
    /// A critical CRL extension this reader does not process (RFC
    /// 5280 sec.5.2: such a CRL MUST NOT be used).
    UnsupportedCriticalExtension,
    /// A critical CRL entry extension this reader does not process
    /// (RFC 5280 sec.5.3: such a CRL MUST NOT be used).
    UnsupportedCriticalEntryExtension,
}

impl From<X509Error> for CrlError {
    #[inline]
    fn from(error: X509Error) -> Self {
        Self::Malformed(error)
    }
}

impl core::fmt::Display for CrlError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Malformed(ref error) => write!(f, "{error}"),
            Self::Delta => f.write_str("a delta CRL is not a complete list"),
            Self::Scoped => {
                f.write_str("a CRL scoped by an issuing distribution point is not a complete list")
            }
            Self::UnsupportedCriticalExtension => f.write_str("unsupported critical CRL extension"),
            Self::UnsupportedCriticalEntryExtension => {
                f.write_str("unsupported critical CRL entry extension")
            }
        }
    }
}

impl core::error::Error for CrlError {}

/// `id-ce-cRLReasons` (RFC 5280 sec.5.3.1) -- the per-entry
/// `reasonCode` extension OID.
const OID_CRL_REASONS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");

/// `CRLReason` ENUMERATED (RFC 5280 sec.5.3.1).
///
/// Shared by the CRL per-entry `reasonCode` extension and OCSP
/// `RevokedInfo` (RFC 6960 sec.4.2.1 reuses the same ENUMERATED). A
/// closed set: an unassigned code (the reserved `7`, or anything out
/// of range) is treated as "no recognised reason" at the parse
/// boundary -- the cert is still revoked, the reason is simply
/// absent. `Display` renders `<name> (<0xNN>)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlReason {
    /// `0` -- no specific reason given.
    Unspecified,
    /// `1` -- the private key is suspected compromised.
    KeyCompromise,
    /// `2` -- the issuing CA's key is suspected compromised.
    CaCompromise,
    /// `3` -- the subject's affiliation changed.
    AffiliationChanged,
    /// `4` -- replaced by a newer cert (DVV uses this on FINEID
    /// card swaps).
    Superseded,
    /// `5` -- the cert is no longer needed.
    CessationOfOperation,
    /// `6` -- temporarily suspended (certificateHold).
    CertificateHold,
    /// `8` -- remove from a delta-CRL.
    RemoveFromCrl,
    /// `9` -- a privilege in the cert was withdrawn.
    PrivilegeWithdrawn,
    /// `10` -- the attribute-authority key is compromised.
    AaCompromise,
}

impl CrlReason {
    /// Map a `CRLReason` ENUMERATED byte to its variant. `None` for
    /// the reserved `7` or any out-of-range code (treated as "no
    /// recognised reason" -- see the type docs).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            _ => return None,
        })
    }

    /// The on-wire ENUMERATED code for this reason.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::RemoveFromCrl => 8,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }
}

impl core::fmt::Display for CrlReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match *self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::CaCompromise => "cACompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::CertificateHold => "certificateHold",
            Self::RemoveFromCrl => "removeFromCRL",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
            Self::AaCompromise => "aACompromise",
        };
        write!(f, "{name} ({:#04x})", self.code())
    }
}

/// A complete X.509 v2 CRL, parsed enough to check whether a given
/// cert serial is on the revocation list.
///
/// Trust by construction: `Crl::parse` is the only constructor and
/// it refuses every CRL that is not a complete list for its issuer
/// (see the module documentation), so a serial absent from a `Crl`
/// is not revoked by that issuer as of `this_update`.
#[non_exhaustive]
#[derive(Debug, Clone)]
#[expect(
    clippy::partial_pub_fields,
    reason = "the parsed-once typed values (raw_der, tbs_der, signature_alg_oid, ...) are intentionally pub for read; revoked_seq_value is intentionally private because it requires the typed `revoked_certificates()` iterator accessor below to be walked.  Making all-public would expose the iterator-only field to direct walking that bypasses BER-typed parsing; making all-private would force ceremony on every typed-value reader."
)]
pub struct Crl<'a> {
    /// Full CRL DER bytes (outer `SEQUENCE` and downward).
    pub raw_der: &'a [u8],
    /// `tbsCertList` SEQUENCE bytes including outer tag + length
    /// -- exactly the bytes covered by the CRL signature.
    pub tbs_der: &'a [u8],
    /// `issuer` Distinguished Name (the whole `Name` SEQUENCE,
    /// outer tag/length included). Typed [`crate::x509::Name`] so a
    /// CRL's issuer pairs against a cert's issuer with the same
    /// byte-exact `==` the rest of chain building uses.
    pub issuer: crate::x509::Name<'a>,
    /// `thisUpdate` -- timestamp at which the CRL is current
    /// per RFC 5280 §5.1.2.4.
    pub this_update: DateTime,
    /// `nextUpdate` -- timestamp at which the issuer commits to
    /// publishing the next CRL per RFC 5280 §5.1.2.5. `None` for
    /// CRLs without the optional field.
    pub next_update: Option<DateTime>,
    /// Value bytes of the `revokedCertificates` SEQUENCE -- a
    /// sequence of `RevokedCertificate` SEQUENCEs, every one of which
    /// decoded at parse. `None` if the CRL declares no revoked
    /// entries (the field is OPTIONAL).
    revoked_seq_value: Option<&'a [u8]>,
    /// Signature algorithm OID body (the value of the `06 LL`
    /// TLV inside the outer `signatureAlgorithm`).
    pub signature_alg_oid: Oid<'a>,
    /// Outer signature BIT STRING value with its zero unused-bits
    /// leading byte stripped.
    pub signature_bits: &'a [u8],
}

impl Crl<'_> {
    /// Verify the CRL signature against the issuer's SPKI.
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    /// As for `x509::verify_tbs_signature`.
    #[inline]
    pub fn verify_signature(
        &self,
        issuer_spki: &crate::x509::SpkiDer<'_>,
    ) -> Result<(), crate::x509::VerifyError> {
        crate::x509::verify_tbs_signature(crate::x509::TbsSignature {
            tbs_der: self.tbs_der,
            signature_alg_oid: self.signature_alg_oid,
            signature_bits: self.signature_bits,
            issuer_spki: *issuer_spki,
        })
    }
}

/// Why a parsed CRL could not be bound to its claimed issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlVerifyError {
    /// The CRL issuer name is not the issuer certificate's subject
    /// name (RFC 5280 sec.5.1.2.3).
    IssuerNameMismatch,
    /// The issuer certificate has no parseable Key Usage or does not
    /// assert `cRLSign` (RFC 5280 sec.4.2.1.3).
    IssuerNotAuthorized,
    /// The CRL signature did not verify under the issuer key.
    Signature(crate::x509::VerifyError),
}

impl core::fmt::Display for CrlVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IssuerNameMismatch => {
                f.write_str("CRL issuer name does not match issuer certificate")
            }
            Self::IssuerNotAuthorized => {
                f.write_str("issuer certificate Key Usage does not authorize cRLSign")
            }
            Self::Signature(why) => write!(f, "CRL signature: {why}"),
        }
    }
}

impl core::error::Error for CrlVerifyError {}

/// A [`Crl`] whose issuer identity, `cRLSign` authorization, and
/// signature have been verified against an issuer certificate.
///
/// Trust by construction (see `doc/typing-discipline.md`): the only
/// production constructor is [`VerifiedCrl::verify`], so holding this
/// type is proof the CRL is the issuer's.
/// [`crate::revocation::check_against_crl`] takes a `VerifiedCrl`, so
/// a CRL's revocation list cannot be consulted without a checked
/// signature -- the same gate as [`crate::ocsp::VerifiedOcspResponse`].
#[derive(Debug, Clone)]
pub struct VerifiedCrl<'a> {
    /// The verified CRL.
    crl: Crl<'a>,
}

impl<'a> VerifiedCrl<'a> {
    /// Bind `crl` to `issuer`: the CRL issuer must be the issuer's
    /// subject, the issuer's Key Usage must assert `cRLSign`, and the
    /// CRL signature must verify under the issuer's key. The only
    /// production door to a verified CRL.
    ///
    /// # Errors
    /// [`CrlVerifyError`] when the name, authorization, or signature
    /// check fails.
    pub fn verify(crl: &Crl<'a>, issuer: Certificate<'_>) -> Result<Self, CrlVerifyError> {
        if crl.issuer != issuer.subject {
            return Err(CrlVerifyError::IssuerNameMismatch);
        }
        let authorized = issuer
            .extensions
            .and_then(extract_key_usage)
            .is_some_and(|usage| usage.crl_sign);
        if !authorized {
            return Err(CrlVerifyError::IssuerNotAuthorized);
        }
        crl.verify_signature(&issuer.spki)
            .map_err(CrlVerifyError::Signature)?;
        Ok(Self { crl: crl.clone() })
    }

    /// Borrow the verified CRL. `pub(crate)`: reachable only on a
    /// verified CRL, and only within the crate's revocation logic --
    /// so any revocation-list read is downstream of a checked
    /// signature.
    #[inline]
    #[must_use]
    pub(crate) const fn as_crl(&self) -> &Crl<'a> {
        &self.crl
    }

    /// Test-only: wrap a CRL *without* verifying its signature, to
    /// exercise revocation-status logic in isolation. `#[cfg(test)]`-
    /// gated, so the production "only door is `verify`" guarantee is
    /// unaffected.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_unverified_for_test(crl: Crl<'a>) -> Self {
        Self { crl }
    }
}

/// One entry in `revokedCertificates`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    /// The revoked cert's serial number.
    pub serial: CertSerial,
    /// `revocationDate` per RFC 5280 §5.3.1.
    pub revocation_date: DateTime,
    /// `CRLReason` from the `reasonCode` per-entry extension (OID
    /// 2.5.29.21) when present and recognised. `None` when the
    /// issuer didn't include the extension (or used an unassigned
    /// code).
    pub reason: Option<CrlReason>,
}

/// Owning wrapper around a parsed X.509 CRL.
///
/// Same pattern as [`crate::x509::OwnedCert`]: holds the CRL's
/// DER bytes plus a re-parseable view. Public entry point under
/// typing-discipline rule D; free `parse_crl` is `pub(crate)`
/// because it returns a borrowed view tied to the input.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct OwnedCrl {
    /// DER-encoded `CertificateList` SEQUENCE bytes (RFC 5280
    /// §5.1). Stored verbatim so re-parsing and signature
    /// re-verification both work; the parser view inside
    /// `OwnedCrl` borrows back into this buffer.
    der: Vec<u8>,
}

impl OwnedCrl {
    /// Parse `der` as an X.509 v2 CRL, allocating an owned copy
    /// of the bytes so the resulting wrapper is independent of
    /// the input borrow.
    ///
    /// # Errors
    /// [`CrlError`] from the CRL parser.
    #[inline]
    pub fn from_der(der: &[u8]) -> Result<Self, CrlError> {
        let bytes = der.to_vec();
        Crl::parse(&bytes)?;
        Ok(Self { der: bytes })
    }

    /// Re-parse the owned DER and hand back the borrowed view.
    ///
    /// # Performance
    /// Parses the DER on **every call** (O(n) in the DER length). For
    /// repeated field access bind the view once (`let crl = owned.view();`)
    /// and reuse it, rather than calling `view()` per field.
    ///
    /// # Panics
    /// Never -- [`from_der`] validated at construction.
    ///
    /// [`from_der`]: Self::from_der
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "Invariant: `from_der` parsed the same bytes and returned `Ok` before constructing `Self`; the bytes are owned and immutable, so re-parse cannot fail."
    )]
    #[inline]
    pub fn view(&self) -> Crl<'_> {
        Crl::parse(&self.der).expect("OwnedCrl: from_der validated DER at construction")
    }

    /// Raw DER bytes the wrapper owns.
    #[inline]
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Verify the CRL signature against the issuer's SPKI. See
    /// [`Crl::verify_signature`].
    ///
    /// # Errors
    /// As for [`Crl::verify_signature`].
    #[inline]
    pub fn verify_signature(
        &self,
        issuer_spki: &crate::x509::SpkiDer<'_>,
    ) -> Result<(), crate::x509::VerifyError> {
        self.view().verify_signature(issuer_spki)
    }
}

impl<'a> Crl<'a> {
    /// Parse a `CertificateList` DER blob.
    ///
    /// # Errors
    /// [`CrlError::Malformed`] for any der decode failure, or a shape
    /// that doesn't look like `CertificateList ::= SEQUENCE {
    /// TBSCertList, AlgorithmIdentifier, BIT STRING }`; the other
    /// [`CrlError`] variants for a CRL that is not a complete list.
    #[inline]
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, CrlError> {
        // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
        //                                signatureValue BIT STRING }
        let outer = AnyRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL not a TLV"))?;
        if outer.tag() != Tag::Sequence {
            return Err(X509Error::UnexpectedStructure("CRL not SEQUENCE").into());
        }
        let mut reader = SliceReader::new(outer.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL body"))?;

        // tbsCertList -- the exact bytes the signature covers.
        let tbs_der = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList"))?;

        // signatureAlgorithm AlgorithmIdentifier -- carry the OID body
        // (the value of its `06 LL` TLV), borrowed from the input, and
        // the whole TLV for the comparison with tbsCertList.signature.
        let sig_alg_der = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signatureAlgorithm"))?;
        let sig_alg = AnyRef::from_der(sig_alg_der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signatureAlgorithm"))?;
        let mut alg_reader = SliceReader::new(sig_alg.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signatureAlgorithm body"))?;
        let alg_oid =
            AnyRef::from_der(alg_reader.tlv_bytes().map_err(|_ignored| {
                X509Error::UnexpectedStructure("CRL signatureAlgorithm OID")
            })?)
            .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signatureAlgorithm OID"))?;
        if alg_oid.tag() != Tag::ObjectIdentifier {
            return Err(X509Error::UnexpectedStructure("CRL signatureAlgorithm OID").into());
        }
        let signature_alg_oid = Oid::new(alg_oid.value()).or(Err(
            X509Error::UnexpectedStructure("CRL signatureAlgorithm OID malformed"),
        ))?;

        // signatureValue BIT STRING -- whole octets behind a zero
        // unused-bits byte.
        let sig_bits = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signature"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("CRL signature"))?;
        if sig_bits.tag() != Tag::BitString {
            return Err(X509Error::UnexpectedStructure("CRL signature not BIT STRING").into());
        }
        let signature_bits = signature_octets(sig_bits.value(), "CRL signature BIT STRING")?;

        let parsed = parse_tbs_cert_list(tbs_der, der, signature_alg_oid, signature_bits)?;
        // RFC 5280 sec.5.1.1.2: signatureAlgorithm MUST contain the same
        // algorithm identifier as tbsCertList.signature.
        if parsed.tbs_signature_algorithm_der != sig_alg_der {
            return Err(X509Error::UnexpectedStructure(
                "CRL signatureAlgorithm differs from tbsCertList.signature",
            )
            .into());
        }
        Ok(parsed.crl)
    }
}

/// Decode a `TBSCertList` SEQUENCE into a borrowing [`Crl`].
///
/// RFC 5280 §5.1.2 -- `TBSCertList` is the part of a CRL covered
/// by the issuer's signature. `tbs_der` is the un-tagged
/// SEQUENCE bytes; `raw` is the full CRL DER (for signature
/// verification reference); `signature_alg_oid` and
/// `signature_bits` are the outer wrapper's fields, already
/// validated by the caller to match the TBS's `signature` field.
///
/// The function does not verify the signature; it only parses
/// the TBS payload. Signature verification lives on
/// [`VerifiedCrl::verify`] in this module.
fn parse_tbs_cert_list<'a>(
    tbs_der: &'a [u8],
    raw: &'a [u8],
    signature_alg_oid: Oid<'a>,
    signature_bits: &'a [u8],
) -> Result<ParsedTbsCertList<'a>, CrlError> {
    // TBSCertList ::= SEQUENCE {
    //     version                 INTEGER OPTIONAL,
    //     signature               AlgorithmIdentifier,
    //     issuer                  Name,
    //     thisUpdate              Time,
    //     nextUpdate              Time OPTIONAL,
    //     revokedCertificates     SEQUENCE OF ... OPTIONAL,
    //     crlExtensions           [0] EXPLICIT Extensions OPTIONAL
    // }
    // crlExtensions [0] EXPLICIT, matched as a value rather than as
    // a pattern so the tag number stays one expression.
    const CRL_EXTENSIONS_TAG: Tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(0),
    };

    let tbs = AnyRef::from_der(tbs_der)
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList not a TLV"))?;
    if tbs.tag() != Tag::Sequence {
        return Err(X509Error::UnexpectedStructure("tbsCertList not SEQUENCE").into());
    }
    let mut reader = SliceReader::new(tbs.value())
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList body"))?;

    // version INTEGER OPTIONAL, then signature AlgorithmIdentifier.
    // Read the first field: if it is the version INTEGER, the
    // signature is the next field; otherwise this field WAS the
    // signature (version absent) and is already consumed.
    let first_der = reader
        .tlv_bytes()
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList version/signature"))?;
    let first = AnyRef::from_der(first_der)
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList version/signature"))?;
    let is_v2 = first.tag() == Tag::Integer;
    let tbs_signature_algorithm_der = if is_v2 {
        if first.decode_as::<u8>().ok() != Some(CRL_VERSION_2) {
            return Err(X509Error::UnexpectedStructure("tbsCertList version").into());
        }
        reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList signature"))?
    } else {
        first_der
    };

    // issuer Name -- exact bytes (byte-exact for OCSP issuer match).
    let issuer_dn_der = reader
        .tlv_bytes()
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList issuer"))?;

    // thisUpdate Time -- decoded by x509-cert (UTCTime /
    // GeneralizedTime choice + RFC 5280 YY normalisation).
    let this_update = x509_cert::time::Time::from_der(
        reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList thisUpdate"))?,
    )
    .map_err(|_ignored| X509Error::InvalidTime)?
    .to_date_time();

    // Optional nextUpdate (Time) / revokedCertificates (SEQUENCE) /
    // crlExtensions ([0] EXPLICIT), each at most once and in this
    // order: `seen` is how many of the three positions are behind.
    let mut next_update: Option<DateTime> = None;
    let mut revoked_seq_value: Option<&[u8]> = None;
    let mut seen = TrailingField::Start;
    while !reader.is_finished() {
        let field_tlv = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList trailing field"))?;
        let any = AnyRef::from_der(field_tlv)
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertList trailing field"))?;
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "der's Tag enum is large and open-ended; only the three TBSCertList trailing-field tags are valid here, and any other tag is a structural error"
        )]
        match any.tag() {
            Tag::UtcTime | Tag::GeneralizedTime => {
                seen = seen.advance_to(TrailingField::NextUpdate)?;
                next_update = Some(
                    x509_cert::time::Time::from_der(field_tlv)
                        .map_err(|_ignored| X509Error::InvalidTime)?
                        .to_date_time(),
                );
            }
            Tag::Sequence => {
                seen = seen.advance_to(TrailingField::RevokedCertificates)?;
                check_revoked_entries(any.value(), is_v2)?;
                revoked_seq_value = Some(any.value());
            }
            tag if tag == CRL_EXTENSIONS_TAG => {
                seen = seen.advance_to(TrailingField::CrlExtensions)?;
                if !is_v2 {
                    return Err(X509Error::UnexpectedStructure("crlExtensions in a v1 CRL").into());
                }
                check_crl_extensions(any.value())?;
            }
            _ => return Err(X509Error::UnexpectedStructure("unexpected CRL field").into()),
        }
    }

    Ok(ParsedTbsCertList {
        crl: Crl {
            raw_der: raw,
            tbs_der,
            issuer: crate::x509::Name::try_from(issuer_dn_der)?,
            this_update,
            next_update,
            revoked_seq_value,
            signature_alg_oid,
            signature_bits,
        },
        tbs_signature_algorithm_der,
    })
}

/// A parsed `TBSCertList` and the exact `signature`
/// `AlgorithmIdentifier` it carries, for the RFC 5280 sec.5.1.1.2
/// comparison against the outer `signatureAlgorithm`.
struct ParsedTbsCertList<'a> {
    /// The CRL view.
    crl: Crl<'a>,
    /// `tbsCertList.signature`, tag and length included.
    tbs_signature_algorithm_der: &'a [u8],
}

/// The optional trailing fields of `TBSCertList`, in their order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TrailingField {
    /// None read yet.
    Start,
    /// `nextUpdate`.
    NextUpdate,
    /// `revokedCertificates`.
    RevokedCertificates,
    /// `crlExtensions`.
    CrlExtensions,
}

impl TrailingField {
    /// Move past `next`, which must come after every field read so far.
    fn advance_to(self, next: Self) -> Result<Self, X509Error> {
        if next > self {
            Ok(next)
        } else {
            Err(X509Error::UnexpectedStructure(
                "tbsCertList field repeated or out of order",
            ))
        }
    }
}

/// Refuse a CRL that is not a complete list for its issuer, or that
/// carries a critical extension: this reader processes none, so a
/// critical one means the CRL MUST NOT be used (RFC 5280 sec.5.2).
///
/// `extensions` is the value of the `[0] EXPLICIT` wrapper: the
/// `Extensions` SEQUENCE (RFC 5280 sec.5.1.2.7).
fn check_crl_extensions(extensions: &[u8]) -> Result<(), CrlError> {
    let extensions = Extensions::from_der(extensions)
        .map_err(|_ignored| X509Error::UnexpectedStructure("crlExtensions"))?;
    for extension in &extensions {
        let oid = extension.extn_id.as_bytes();
        if oid == crate::oids::DELTA_CRL_INDICATOR.as_bytes() {
            return Err(CrlError::Delta);
        }
        if oid == crate::oids::ISSUING_DISTRIBUTION_POINT.as_bytes() {
            return Err(CrlError::Scoped);
        }
        if extension.critical {
            return Err(CrlError::UnsupportedCriticalExtension);
        }
    }
    Ok(())
}

/// Decode every `revokedCertificates` entry, refusing the CRL when one
/// does not decode, carries extensions in a v1 CRL (`is_v2` false,
/// RFC 5280 sec.5.1.2.6), or carries a critical extension other than
/// `reasonCode` (sec.5.3). `body` is the SEQUENCE OF's value.
fn check_revoked_entries(body: &[u8], is_v2: bool) -> Result<(), CrlError> {
    let mut reader = SliceReader::new(body)
        .map_err(|_ignored| X509Error::UnexpectedStructure("revokedCertificates"))?;
    while !reader.is_finished() {
        let revoked = RevokedCert::<x509_cert::certificate::Rfc5280>::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("revokedCertificates entry"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("revokedCertificates entry"))?;
        if !is_v2 && revoked.crl_entry_extensions.is_some() {
            return Err(X509Error::UnexpectedStructure("crlEntryExtensions in a v1 CRL").into());
        }
        if revoked
            .crl_entry_extensions
            .iter()
            .flatten()
            .any(|extension| extension.critical && extension.extn_id != OID_CRL_REASONS)
        {
            return Err(CrlError::UnsupportedCriticalEntryExtension);
        }
    }
    Ok(())
}

impl<'a> Crl<'a> {
    /// Lazily iterate the revoked-certificate entries. [`Crl::parse`]
    /// decoded every entry, so the walk reaches the end of the list.
    #[inline]
    #[must_use]
    pub(crate) fn entries(&self) -> RevokedIter<'a> {
        RevokedIter {
            reader: self
                .revoked_seq_value
                .and_then(|body| SliceReader::new(body).ok()),
        }
    }

    /// Walk the CRL's revoked entries looking for `serial`. Returns
    /// the matching entry or `None` when the serial isn't listed.
    #[inline]
    #[must_use]
    pub(crate) fn find_serial(&self, serial: &CertSerial) -> Option<RevokedEntry> {
        self.entries().find(|entry| &entry.serial == serial)
    }
}

/// Iterator yielded by `Crl::entries`.
#[non_exhaustive]
#[derive(Debug)]
pub struct RevokedIter<'a> {
    /// Reader over the `revokedCertificates SEQUENCE OF` body; each
    /// `next()` decodes one `RevokedCert`. `None` when the CRL lists
    /// no revoked certs.
    reader: Option<SliceReader<'a>>,
}

impl Iterator for RevokedIter<'_> {
    type Item = RevokedEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = self.reader.as_mut()?;
        if reader.is_finished() {
            return None;
        }
        // Peel one RevokedCert TLV and decode it with the typed
        // x509-cert structure -- trust the type for field validation.
        let revoked =
            RevokedCert::<x509_cert::certificate::Rfc5280>::from_der(reader.tlv_bytes().ok()?)
                .ok()?;
        let serial = CertSerial::from_bytes(revoked.serial_number.as_bytes().to_vec());
        let revocation_date = revoked.revocation_date.to_date_time();
        let reason = revoked
            .crl_entry_extensions
            .as_deref()
            .and_then(RevokedIter::find_reason_code);
        Some(RevokedEntry {
            serial,
            revocation_date,
            reason,
        })
    }
}

impl RevokedIter<'_> {
    /// Find the `reasonCode` extension (OID 2.5.29.21) among an
    /// entry's `crlEntryExtensions` and decode its ENUMERATED value
    /// into a [`CrlReason`]. `None` if absent, unrecognised, or
    /// malformed.
    fn find_reason_code(extensions: &[Extension]) -> Option<CrlReason> {
        let reason_ext = extensions
            .iter()
            .find(|ext| ext.extn_id == OID_CRL_REASONS)?;
        // extnValue OCTET STRING wraps the `CRLReason` ENUMERATED.
        let inner = AnyRef::from_der(reason_ext.extn_value.as_bytes()).ok()?;
        if inner.tag() != Tag::Enumerated {
            return None;
        }
        let value = inner.value();
        if value.len() == 1 {
            value.first().copied().and_then(CrlReason::from_code)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{Crl, CrlError, CrlReason, RevokedEntry, X509Error};
    use crate::identity::CertSerial;
    use core::str::FromStr as _;
    use refineid_cms::oid::Oid;
    use spki::AlgorithmIdentifierOwned;
    use spki::der::Encode as _;
    use spki::der::asn1::{Any, BitString, ObjectIdentifier, OctetString, UtcTime};
    use spki::der::{DateTime, Decode as _, Reader as _, SliceReader, Tag};
    use x509_cert::certificate::Version;
    use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::Time;

    /// One revoked-cert row for [`build_crl`], in our domain types.
    struct RevokedFixture {
        /// The revoked cert's serial number.
        serial: CertSerial,
        /// When it was revoked.
        revoked_at: DateTime,
        /// Optional `CRLReason`.
        reason: Option<CrlReason>,
    }

    /// A distinct cert serial for fixtures. The value is arbitrary
    /// -- only its uniqueness matters, since the CRL logic keys on
    /// serial *equality*, not on any particular serial.
    fn fixture_serial(n: u8) -> CertSerial {
        CertSerial::from_bytes(vec![n])
    }

    /// Wrap a [`DateTime`] as a `UTCTime`-encoded `Time` for the
    /// x509-cert CRL encoder.
    fn as_utc(dt: DateTime) -> Time {
        Time::UtcTime(UtcTime::from_date_time(dt).expect("fixture date in the UTCTime window"))
    }

    /// A `UTCTime` at the given civil-time components.
    fn at(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Time {
        as_utc(DateTime::new(year, month, day, hour, minute, second).expect("valid fixture date"))
    }

    /// Build a CRL DER blob from typed fixtures via x509-cert's
    /// `CertificateList` encoder -- no hand-assembled ASN.1 bytes.
    fn build_crl(entries: &[RevokedFixture], with_next_update: bool) -> Vec<u8> {
        build_crl_with(CrlShape {
            entries,
            with_next_update,
            ..CrlShape::default()
        })
    }

    /// What [`build_crl_with`] varies beyond the revoked rows.
    #[derive(Default)]
    struct CrlShape<'a> {
        /// The revoked rows.
        entries: &'a [RevokedFixture],
        /// Whether `nextUpdate` is present.
        with_next_update: bool,
        /// `crlExtensions`, when present.
        crl_extensions: Option<Vec<Extension>>,
        /// Extensions every revoked row carries besides `reasonCode`.
        entry_extensions: Vec<Extension>,
        /// The signature BIT STRING's unused-bits count.
        unused_bits: u8,
    }

    /// Build a CRL DER blob of `shape` via x509-cert's encoder.
    fn build_crl_with(shape: CrlShape<'_>) -> Vec<u8> {
        let CrlShape {
            entries,
            with_next_update,
            crl_extensions,
            entry_extensions,
            unused_bits,
        } = shape;
        let sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: None,
        };
        let revoked: Vec<RevokedCert> = entries
            .iter()
            .map(|e| RevokedCert {
                serial_number: SerialNumber::new(e.serial.as_bytes())
                    .expect("fixture serial encodes"),
                revocation_date: as_utc(e.revoked_at),
                crl_entry_extensions: {
                    let mut extensions = entry_extensions.clone();
                    extensions.extend(e.reason.map(|r| {
                        let enumerated = Any::new(Tag::Enumerated, vec![r.code()])
                            .expect("reason code fits an ENUMERATED");
                        extension_with(
                            super::OID_CRL_REASONS,
                            false,
                            &enumerated.to_der().expect("ENUMERATED encodes to DER"),
                        )
                    }));
                    (!extensions.is_empty()).then_some(extensions)
                },
            })
            .collect();
        let tbs = TbsCertList {
            version: Version::V2,
            signature: sig_alg.clone(),
            issuer: Name::from_str("CN=Issuer").expect("issuer name parses"),
            this_update: at(2026, 5, 20, 12, 0, 0),
            next_update: with_next_update.then(|| at(2026, 6, 20, 12, 0, 0)),
            revoked_certificates: (!revoked.is_empty()).then_some(revoked),
            crl_extensions,
        };
        CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::new(unused_bits, b"sig").expect("signature bits encode"),
        }
        .to_der()
        .expect("fixture CRL encodes to DER")
    }

    #[test]
    fn parses_crl_with_next_update_and_revoked_list() {
        let serial_a = fixture_serial(1);
        let serial_b = fixture_serial(2);
        let der = build_crl(
            &[
                RevokedFixture {
                    serial: serial_a.clone(),
                    revoked_at: DateTime::new(2026, 1, 1, 0, 0, 0).expect("valid"),
                    reason: None,
                },
                RevokedFixture {
                    serial: serial_b.clone(),
                    revoked_at: DateTime::new(2026, 3, 15, 10, 30, 0).expect("valid"),
                    reason: None,
                },
            ],
            true,
        );
        let crl = Crl::parse(&der).expect("parses");
        assert_eq!(
            crl.this_update,
            DateTime::new(2026, 5, 20, 12, 0, 0).expect("valid")
        );
        assert_eq!(
            crl.next_update,
            Some(DateTime::new(2026, 6, 20, 12, 0, 0).expect("valid"))
        );
        let entries: Vec<RevokedEntry> = crl.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].serial, serial_a);
        assert_eq!(entries[1].serial, serial_b);
        assert_eq!(entries[1].revocation_date.month(), 3);
    }

    #[test]
    fn find_serial_returns_entry_when_present() {
        let serial = fixture_serial(3);
        let der = build_crl(
            &[RevokedFixture {
                serial: serial.clone(),
                revoked_at: DateTime::new(2026, 2, 1, 8, 0, 0).expect("valid"),
                reason: None,
            }],
            true,
        );
        let crl = Crl::parse(&der).expect("parses");
        let entry = crl.find_serial(&serial).expect("found");
        assert_eq!(entry.revocation_date.year(), 2026);
        assert_eq!(entry.revocation_date.month(), 2);
        assert_eq!(entry.revocation_date.day(), 1);
        assert!(entry.reason.is_none());
        let absent = fixture_serial(9);
        assert!(crl.find_serial(&absent).is_none());
    }

    #[test]
    fn handles_crl_without_next_update() {
        let serial = fixture_serial(4);
        let der = build_crl(
            &[RevokedFixture {
                serial: serial.clone(),
                revoked_at: DateTime::new(2026, 1, 1, 0, 0, 0).expect("valid"),
                reason: None,
            }],
            false,
        );
        let crl = Crl::parse(&der).expect("parses");
        assert!(crl.next_update.is_none());
        assert!(crl.find_serial(&serial).is_some());
    }

    #[test]
    fn handles_empty_revocation_list() {
        let der = build_crl(&[], true);
        let crl = Crl::parse(&der).expect("parses");
        assert_eq!(crl.entries().count(), 0);
        // The list is empty, so a lookup for any serial must miss.
        let any_serial = fixture_serial(9);
        assert!(crl.find_serial(&any_serial).is_none());
    }

    #[test]
    fn rejects_non_sequence_outer() {
        // A bare INTEGER TLV: a valid DER element that is not the
        // CertificateList SEQUENCE the parser requires.
        let bad = Any::new(Tag::Integer, vec![5])
            .expect("INTEGER fixture builds")
            .to_der()
            .expect("INTEGER fixture encodes to DER");
        let err = Crl::parse(&bad).expect_err("non-SEQUENCE outer is rejected");
        assert!(matches!(
            err,
            CrlError::Malformed(X509Error::UnexpectedStructure(_))
        ));
    }

    /// reasonCode = superseded (RFC 5280 sec.5.3.1) -- DVV uses this
    /// on FINEID card swaps.
    #[test]
    fn find_serial_surfaces_superseded_reason() {
        let serial = fixture_serial(5);
        let der = build_crl(
            &[RevokedFixture {
                serial: serial.clone(),
                revoked_at: DateTime::new(2026, 5, 21, 5, 42, 53).expect("valid"),
                reason: Some(CrlReason::Superseded),
            }],
            true,
        );
        let crl = Crl::parse(&der).expect("parses");
        let entry = crl.find_serial(&serial).expect("found");
        assert_eq!(entry.reason, Some(CrlReason::Superseded));
    }

    #[test]
    fn crl_reason_renders_name_and_code() {
        assert_eq!(CrlReason::Superseded.to_string(), "superseded (0x04)");
        assert_eq!(CrlReason::from_code(7), None);
    }

    /// An extension whose `extnValue` wraps `value_der`.
    fn extension_with(extn_id: ObjectIdentifier, critical: bool, value_der: &[u8]) -> Extension {
        Extension {
            extn_id,
            critical,
            extn_value: OctetString::new(value_der.to_vec()).expect("value fits an OCTET STRING"),
        }
    }

    /// The crate's OID constant as the encoder's identifier type.
    fn identifier(oid: Oid<'static>) -> ObjectIdentifier {
        ObjectIdentifier::from_bytes(oid.as_bytes()).expect("crate OID constants are well formed")
    }

    /// An extension `oid` carrying an INTEGER, as `cRLNumber` and
    /// `deltaCRLIndicator` (`BaseCRLNumber`) do.
    fn integer_extension(oid: Oid<'static>, critical: bool) -> Extension {
        let number: u32 = 1;
        extension_with(
            identifier(oid),
            critical,
            &number.to_der().expect("INTEGER encodes"),
        )
    }

    /// An extension `oid` carrying an empty SEQUENCE, which is an
    /// `IssuingDistributionPoint` with every field at its default.
    fn sequence_extension(oid: ObjectIdentifier, critical: bool) -> Extension {
        let empty = Any::new(Tag::Sequence, Vec::new()).expect("empty SEQUENCE builds");
        extension_with(oid, critical, &empty.to_der().expect("SEQUENCE encodes"))
    }

    /// An extension this reader does not know: X.509's
    /// `expiredCertsOnCRL`, which issuers publish non-critical.
    fn unlisted_extension(critical: bool) -> Extension {
        sequence_extension(
            ObjectIdentifier::new_unwrap(UNLISTED_EXTENSION_OID),
            critical,
        )
    }

    /// `expiredCertsOnCRL` (ITU-T X.509 sec.9.6.2.9).
    const UNLISTED_EXTENSION_OID: &str = "2.5.29.60";

    /// `certificateIssuer`, the indirect-CRL entry extension (RFC
    /// 5280 sec.5.3.3), which MUST be critical.
    const CERTIFICATE_ISSUER_OID: &str = "2.5.29.29";

    /// A CRL with one revoked row and `crl_extensions`.
    fn crl_with_extensions(crl_extensions: Vec<Extension>) -> Vec<u8> {
        build_crl_with(CrlShape {
            entries: &[revoked_row()],
            with_next_update: true,
            crl_extensions: Some(crl_extensions),
            ..CrlShape::default()
        })
    }

    /// One revoked row without a reason.
    fn revoked_row() -> RevokedFixture {
        RevokedFixture {
            serial: fixture_serial(6),
            revoked_at: DateTime::new(2026, 1, 1, 0, 0, 0).expect("valid"),
            reason: None,
        }
    }

    #[test]
    fn delta_crl_is_refused() {
        for critical in [true, false] {
            let der = crl_with_extensions(vec![integer_extension(
                crate::oids::DELTA_CRL_INDICATOR,
                critical,
            )]);
            assert_eq!(Crl::parse(&der).err(), Some(CrlError::Delta));
        }
    }

    #[test]
    fn scoped_crl_is_refused() {
        for critical in [true, false] {
            let der = crl_with_extensions(vec![sequence_extension(
                identifier(crate::oids::ISSUING_DISTRIBUTION_POINT),
                critical,
            )]);
            assert_eq!(Crl::parse(&der).err(), Some(CrlError::Scoped));
        }
    }

    #[test]
    fn unknown_critical_extension_is_refused() {
        let der = crl_with_extensions(vec![unlisted_extension(true)]);
        assert_eq!(
            Crl::parse(&der).err(),
            Some(CrlError::UnsupportedCriticalExtension)
        );
        let der = crl_with_extensions(vec![unlisted_extension(false)]);
        Crl::parse(&der).expect("the same extension non-critical is passed over");
    }

    #[test]
    fn crl_number_and_aki_parse() {
        let key_identifier =
            OctetString::new(b"key".to_vec()).expect("key identifier fits an OCTET STRING");
        let aki = Any::new(
            Tag::Sequence,
            Any::new(
                Tag::ContextSpecific {
                    constructed: false,
                    number: spki::der::TagNumber(0),
                },
                key_identifier.as_bytes().to_vec(),
            )
            .expect("keyIdentifier builds")
            .to_der()
            .expect("keyIdentifier encodes"),
        )
        .expect("AuthorityKeyIdentifier builds");
        let der = crl_with_extensions(vec![
            extension_with(
                identifier(crate::oids::AUTHORITY_KEY_IDENTIFIER),
                false,
                &aki.to_der().expect("AuthorityKeyIdentifier encodes"),
            ),
            integer_extension(crate::oids::CRL_NUMBER, false),
            unlisted_extension(false),
        ]);
        let crl = Crl::parse(&der).expect("a complete CRL with non-critical extensions parses");
        assert!(crl.find_serial(&fixture_serial(6)).is_some());
    }

    #[test]
    fn critical_profile_extensions_are_refused() {
        for oid in [
            crate::oids::CRL_NUMBER,
            crate::oids::AUTHORITY_KEY_IDENTIFIER,
            crate::oids::FRESHEST_CRL,
        ] {
            let der = crl_with_extensions(vec![sequence_extension(identifier(oid), true)]);
            assert_eq!(
                Crl::parse(&der).err(),
                Some(CrlError::UnsupportedCriticalExtension)
            );
        }
        let der = crl_with_extensions(vec![sequence_extension(
            identifier(crate::oids::FRESHEST_CRL),
            false,
        )]);
        Crl::parse(&der).expect("a non-critical freshestCRL leaves the list complete");
    }

    /// `der` as a v1 CRL: its `version` field removed.
    fn without_version(der: &[u8]) -> Vec<u8> {
        with_tbs_fields(der, |fields| {
            fields.remove(0);
        })
    }

    #[test]
    fn v1_crl_without_extensions_parses() {
        let der = without_version(&build_crl(&[revoked_row()], true));
        let crl = Crl::parse(&der).expect("a v1 CRL without extensions parses");
        assert!(crl.find_serial(&fixture_serial(6)).is_some());
    }

    #[test]
    fn v1_crl_with_extensions_is_refused() {
        let with_crl_extensions = without_version(&crl_with_extensions(vec![integer_extension(
            crate::oids::CRL_NUMBER,
            false,
        )]));
        let rows = [RevokedFixture {
            reason: Some(CrlReason::KeyCompromise),
            ..revoked_row()
        }];
        let with_entry_extensions = without_version(&build_crl(&rows, true));
        for der in [with_crl_extensions, with_entry_extensions] {
            assert!(matches!(
                Crl::parse(&der),
                Err(CrlError::Malformed(X509Error::UnexpectedStructure(_)))
            ));
        }
    }

    #[test]
    fn version_other_than_v2_is_refused() {
        let v1_explicit = Version::V1.to_der().expect("Version encodes");
        let der = with_tbs_fields(&build_crl(&[revoked_row()], true), |fields| {
            fields[0] = v1_explicit;
        });
        assert!(matches!(
            Crl::parse(&der),
            Err(CrlError::Malformed(X509Error::UnexpectedStructure(_)))
        ));
    }

    #[test]
    fn critical_entry_extension_is_refused() {
        let rows = [RevokedFixture {
            reason: Some(CrlReason::KeyCompromise),
            ..revoked_row()
        }];
        let shape = |critical| CrlShape {
            entries: &rows,
            with_next_update: true,
            entry_extensions: vec![sequence_extension(
                ObjectIdentifier::new_unwrap(CERTIFICATE_ISSUER_OID),
                critical,
            )],
            ..CrlShape::default()
        };
        assert_eq!(
            Crl::parse(&build_crl_with(shape(true))).err(),
            Some(CrlError::UnsupportedCriticalEntryExtension)
        );
        let crl_der = build_crl_with(shape(false));
        let crl = Crl::parse(&crl_der).expect("a non-critical entry extension is passed over");
        let entry = crl.find_serial(&fixture_serial(6)).expect("found");
        assert_eq!(entry.reason, Some(CrlReason::KeyCompromise));
    }

    #[test]
    fn nonzero_unused_bits_is_refused() {
        let der = build_crl_with(CrlShape {
            with_next_update: true,
            unused_bits: 1,
            ..CrlShape::default()
        });
        assert!(matches!(
            Crl::parse(&der),
            Err(CrlError::Malformed(X509Error::UnexpectedStructure(_)))
        ));
    }

    #[test]
    fn signature_octets_need_zero_unused_bits_and_content() {
        let unused = super::SIGNATURE_BIT_STRING_UNUSED_BITS;
        assert_eq!(
            super::signature_octets(&[unused, b's'], "test"),
            Ok(&b"s"[..])
        );
        assert!(super::signature_octets(&[unused], "test").is_err());
        assert!(super::signature_octets(&[], "test").is_err());
        assert!(super::signature_octets(&[unused + 1, b's'], "test").is_err());
    }

    /// The top-level TLVs of a SEQUENCE's value.
    fn sequence_fields(der: &[u8]) -> Vec<Vec<u8>> {
        let outer = Any::from_der(der).expect("a SEQUENCE");
        let mut reader = SliceReader::new(outer.value()).expect("SEQUENCE body");
        let mut fields = Vec::new();
        while !reader.is_finished() {
            fields.push(reader.tlv_bytes().expect("a field").to_vec());
        }
        fields
    }

    /// A SEQUENCE whose value is `fields` in order.
    fn sequence_of(fields: &[Vec<u8>]) -> Vec<u8> {
        Any::new(Tag::Sequence, fields.concat())
            .expect("SEQUENCE builds")
            .to_der()
            .expect("SEQUENCE encodes")
    }

    /// `der` with its `tbsCertList` fields rewritten by `edit`.
    fn with_tbs_fields(der: &[u8], edit: impl FnOnce(&mut Vec<Vec<u8>>)) -> Vec<u8> {
        let mut outer = sequence_fields(der);
        let mut tbs = sequence_fields(&outer[0]);
        edit(&mut tbs);
        outer[0] = sequence_of(&tbs);
        sequence_of(&outer)
    }

    #[test]
    fn repeated_revoked_list_is_refused() {
        let der = build_crl(&[revoked_row()], true);
        // version, signature, issuer, thisUpdate, nextUpdate, revoked.
        let revoked_at = 5;
        let empty_list = sequence_of(&[]);
        let doubled = with_tbs_fields(&der, |fields| fields.push(empty_list));
        let listed = with_tbs_fields(&der, |fields| fields.truncate(revoked_at + 1));
        Crl::parse(&listed).expect("the unedited fields parse");
        assert!(matches!(
            Crl::parse(&doubled),
            Err(CrlError::Malformed(X509Error::UnexpectedStructure(_)))
        ));
    }

    #[test]
    fn next_update_after_revoked_list_is_refused() {
        let der = build_crl(&[revoked_row()], true);
        // version, signature, issuer, thisUpdate, nextUpdate, revoked.
        let next_update_at = 4;
        let reordered = with_tbs_fields(&der, |fields| {
            fields.swap(next_update_at, next_update_at + 1)
        });
        assert!(matches!(
            Crl::parse(&reordered),
            Err(CrlError::Malformed(X509Error::UnexpectedStructure(_)))
        ));
    }

    #[test]
    fn undecodable_revoked_entry_is_refused() {
        let der = build_crl(&[revoked_row()], true);
        let revoked_at = 5;
        let tbs = sequence_fields(&sequence_fields(&der)[0]);
        let rows = sequence_fields(&tbs[revoked_at]);
        // A row of only a serial: no revocationDate.
        let row = sequence_of(&[sequence_fields(&rows[0]).remove(0)]);
        let truncated = with_tbs_fields(&der, |fields| {
            fields[revoked_at] = sequence_of(&[row]);
        });
        assert!(matches!(
            Crl::parse(&truncated),
            Err(CrlError::Malformed(X509Error::UnexpectedStructure(_)))
        ));
    }
}

#[cfg(test)]
mod issuer_binding_tests {
    use super::{CrlError, CrlVerifyError, OwnedCrl, VerifiedCrl, X509Error};
    use crate::testkit::{self, CertificateSpec, TestCurve, TestKey};
    use refineid_cms::x509::OwnedCert;

    /// Name of the issuing CA.
    const CA: &str = "Test CRL Issuer";
    /// Serial of the CA certificate.
    const CA_SERIAL: u8 = 2;
    /// Serial a fixture CRL lists.
    const REVOKED_SERIAL: u8 = 4;
    /// First validity day of the CA certificate.
    const VALID_FROM: u8 = 1;
    /// Day the CRL is issued, and the entry revoked.
    const THIS_UPDATE: u8 = 10;
    /// Day the next CRL is due.
    const NEXT_UPDATE: u8 = 17;
    /// Last validity day of the CA certificate.
    const VALID_TO: u8 = 28;

    /// A CA certificate for `key` with `extensions`.
    fn ca(key: &TestKey, extensions: Vec<Vec<u8>>) -> OwnedCert {
        OwnedCert::from_der(&testkit::certificate(
            &CertificateSpec {
                serial: CA_SERIAL,
                subject: CA,
                issuer: CA,
                not_before: testkit::day(VALID_FROM),
                not_after: testkit::day(VALID_TO),
                extensions,
            },
            key,
            key,
        ))
        .expect("CA certificate parses")
    }

    /// A CRL named for `issuer`, signed by `key`.
    fn crl(issuer: &str, key: &TestKey) -> OwnedCrl {
        OwnedCrl::from_der(&testkit::crl(
            issuer,
            key,
            testkit::day(THIS_UPDATE),
            Some(testkit::day(NEXT_UPDATE)),
            &[REVOKED_SERIAL],
            testkit::day(THIS_UPDATE),
        ))
        .expect("kit CRL parses")
    }

    #[test]
    fn a_crl_binds_to_the_issuer_that_signed_it() {
        let key = TestKey::derive(TestCurve::P384, b"crl issuer");
        let issuer = ca(&key, testkit::ca_extensions());
        let list = crl(CA, &key);
        let view = list.view();
        let verified =
            VerifiedCrl::verify(&view, issuer.view()).expect("the issuer's CRL verifies");
        assert_eq!(verified.as_crl().entries().count(), 1);
    }

    #[test]
    fn a_crl_naming_another_issuer_is_refused() {
        let key = TestKey::derive(TestCurve::P384, b"crl issuer");
        let issuer = ca(&key, testkit::ca_extensions());
        let list = crl("Test Other Issuer", &key);
        assert_eq!(
            VerifiedCrl::verify(&list.view(), issuer.view()).map(|_verified| ()),
            Err(CrlVerifyError::IssuerNameMismatch)
        );
    }

    #[test]
    fn an_issuer_without_crl_sign_is_refused() {
        let key = TestKey::derive(TestCurve::P384, b"crl issuer");
        let issuer = ca(
            &key,
            vec![
                testkit::ca_basic_constraints(),
                testkit::key_usage(
                    testkit::KEY_USAGE_CERT_SIGN_UNUSED,
                    testkit::KEY_USAGE_CERT_SIGN,
                ),
            ],
        );
        let without_key_usage = ca(&key, vec![testkit::ca_basic_constraints()]);
        let list = crl(CA, &key);
        for refused in [issuer, without_key_usage] {
            assert_eq!(
                VerifiedCrl::verify(&list.view(), refused.view()).map(|_verified| ()),
                Err(CrlVerifyError::IssuerNotAuthorized)
            );
        }
    }

    #[test]
    fn a_crl_signed_by_another_key_is_refused() {
        let key = TestKey::derive(TestCurve::P384, b"crl issuer");
        let other = TestKey::derive(TestCurve::P384, b"crl impostor");
        let issuer = ca(&key, testkit::ca_extensions());
        let list = crl(CA, &other);
        assert!(matches!(
            VerifiedCrl::verify(&list.view(), issuer.view()),
            Err(CrlVerifyError::Signature(_))
        ));
    }

    #[test]
    fn the_outer_algorithm_must_equal_the_tbs_one() {
        let key = TestKey::derive(TestCurve::P256, b"crl issuer");
        let other = TestKey::derive(TestCurve::P384, b"crl other algorithm");
        let tbs = testkit::tbs_cert_list(
            CA,
            &key,
            testkit::day(THIS_UPDATE),
            Some(testkit::day(NEXT_UPDATE)),
            &[],
            testkit::day(THIS_UPDATE),
        );
        let mut body = tbs.clone();
        body.extend_from_slice(&other.algorithm_identifier());
        body.extend_from_slice(&testkit::bit_string(&key.sign(&tbs)));
        let der = testkit::tlv(testkit::SEQUENCE, body);
        assert_eq!(
            OwnedCrl::from_der(&der).map(|_list| ()),
            Err(CrlError::Malformed(X509Error::UnexpectedStructure(
                "CRL signatureAlgorithm differs from tbsCertList.signature"
            )))
        );
    }
}
