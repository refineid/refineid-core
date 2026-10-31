// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Verifying a signed document: a PDF carrying `PAdES` signatures, an
//! `ASiC-E` or `BDOC` container carrying `XAdES` or `CAdES` signatures,
//! or a CMS file with attached content.
//!
//! [`DocumentFile::from_file`] is the border for the file, [`TrustAnchors`]
//! for what the relying party trusts, and the caller's `now` for the
//! clock. [`verify`] reads every signature and every piece of
//! validation evidence the file carries and returns a [`DocumentReport`]:
//! one [`SignatureRow`] per signature found, each either judged into
//! independent facts or marked unsupported, and one
//! [`DocumentTimestampReport`] per PDF document timestamp. The design
//! is `doc/architecture/document-verification.md`.
//!
//! The verifier does no network access. A shell that wants a live
//! revocation answer for a signature the file says nothing about asks
//! for one itself and hands it to [`DocumentReport::with_live_revocation`],
//! which applies it only where the file left revocation unavailable on
//! a verified chain.
//!
//! Each reader below is the single border for its format: it checks
//! every structural rule its specification states and hands out typed
//! facts.
//!
//! # Conformance
//!
//! - `ETSI EN 319 102-1` V1.3.1 clause 5.4: a time-stamp token is
//!   validated as a signature whose signer chains to a time-stamping
//!   anchor at the token's time; clause 5.6.2: the validation time is
//!   the earliest proven existence, and a revocation after it leaves
//!   the signature valid.
//! - `ETSI EN 319 142-1` V1.2.1 clause 5.4.2 (the `/DSS` feeds the
//!   evidence pool), clause 5.4.3 (a document timestamp proves the
//!   existence of every signature its range covers) and table 1 (a
//!   `PAdES` baseline signature carries no `signing-time` attribute).
//! - `ETSI EN 319 142-2` V1.2.1 clause 4.2.3: `adbe.pkcs7.detached`
//!   without the ESS binding, and annex A.4: serial signatures, each
//!   against its own byte range.
//! - `ETSI EN 319 122-1` V1.3.1 clause 5.5.3 and `ETSI EN 319 132-1`
//!   V1.3.1 clause 5.5.2: an anchored archive timestamp proves the
//!   existence of the signature with its validation material.
//! - ISO 32000-1 sec.12.8.2.2 and sec.12.8.2.4: a later revision that
//!   changes more than signatures, document timestamps and validation
//!   material leaves the document not intact.
//! - `ETSI EN 319 162-1` V1.1.1 annex A: `XAdES` signature files and
//!   `CAdES` signatures over an `ASiCManifest`.

pub mod asic;
pub mod cades;
pub mod pdf;
pub mod revision;
pub mod trust;
pub mod xades;
pub mod xml;

use crate::ber::{BerTag, Sequence};
use crate::identity::Peuin;
use crate::timestamp::{TimestampError, verify_token};
use crate::x509_ext::NameExt;
use refineid_cms::x509::{DateTime, OwnedCert};

use self::asic::{AsicContainer, AsicReadError};
use self::cades::{CadesReadError, CadesSignature, Content, EssBinding};
use self::pdf::{ByteRange, PdfDocument, PdfReadError, SignatureKind, SubFilter};
pub use self::revision::{DocumentChange, Revision};
use self::trust::judge;
pub use self::trust::{
    AnchorError, AnchorRole, CertificationPath, GrantedPeriod, MaterialPool, Revocation,
    TrustAnchor, TrustAnchors,
};
use self::xades::{XadesReadError, XadesUnsupported, XadesVerdict};

/// A file by what its first bytes announce, each the complete file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileContent {
    /// A PDF.
    Pdf(Vec<u8>),
    /// A ZIP archive, read as an `ASiC` container.
    Zip(Vec<u8>),
    /// A DER SEQUENCE, read as a CMS `ContentInfo`.
    Der(Vec<u8>),
}

/// One file of a known shape: a PDF, a ZIP archive, or a DER SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentFile {
    /// The file, by its shape.
    content: FileContent,
}

impl DocumentFile {
    /// Accept the complete contents of one file when it starts as a PDF
    /// (ISO 32000-1 sec.7.5.2), a ZIP archive (`ETSI EN 319 162-1`
    /// clause A.1), or a DER SEQUENCE (RFC 5652 sec.3).
    ///
    /// # Errors
    /// [`DocumentFailure::NotASignedDocument`] for anything else.
    pub fn from_file(bytes: Vec<u8>) -> Result<Self, DocumentFailure> {
        let content = if pdf::starts_as_pdf(&bytes) {
            FileContent::Pdf(bytes)
        } else if asic::starts_as_zip(&bytes) {
            FileContent::Zip(bytes)
        } else if bytes.first().copied().map(u16::from) == Some(<Sequence as BerTag>::TAG) {
            FileContent::Der(bytes)
        } else {
            return Err(DocumentFailure::NotASignedDocument);
        };
        Ok(Self { content })
    }
}

/// The holder a signer certificate names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerIdentity {
    /// The subject's `commonName` as the certificate carries it, else
    /// the whole subject as RFC 4514 writes it.
    name: String,
    /// The Finnish electronic user identifier.
    identifier: Option<Peuin>,
}

impl SignerIdentity {
    /// The holder `certificate`'s subject names: its `commonName`
    /// exactly as encoded, neither recomposed from other attributes nor
    /// case-changed, or the whole subject as RFC 4514 sec.2 writes it
    /// when there is no `commonName`; and the `serialNumber` attribute
    /// when it has the shape of a Finnish electronic user identifier.
    #[must_use]
    pub fn of(certificate: &OwnedCert) -> Self {
        let subject = certificate.view().subject;
        let name = subject.common_name().map_or_else(
            || subject.rfc4514().unwrap_or_default(),
            |name| name.as_str().to_owned(),
        );
        Self {
            name,
            identifier: subject.peuin(),
        }
    }

    /// The subject's `commonName` verbatim, else the RFC 4514 subject;
    /// empty when the subject is an empty name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The Finnish electronic user identifier from the subject's
    /// `serialNumber`, on certificates issued to a person; for machine
    /// use, and not part of [`Self::name`].
    #[must_use]
    pub const fn identifier(&self) -> Option<&Peuin> {
        self.identifier.as_ref()
    }
}

/// The authority behind a timestamp token that verifies: the token's
/// signer and the certification path judged above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimestampAuthority {
    /// The certificate that signed the token.
    signer: OwnedCert,
    /// The path above it to a time-stamping anchor, or as far as the
    /// evidence reaches.
    chain: CertificationPath,
}

impl TimestampAuthority {
    /// The certificate that signed the token.
    #[must_use]
    pub const fn signer(&self) -> &OwnedCert {
        &self.signer
    }

    /// The certification path above the token's signer, judged at the
    /// token's time: anchored, its issuer first and the time-stamping
    /// anchor last, or partial.
    #[must_use]
    pub const fn chain(&self) -> &CertificationPath {
        &self.chain
    }
}

/// What one RFC 3161 timestamp token was found to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampReport {
    /// The token verifies, imprints what it should, and its authority
    /// chains to a time-stamping anchor granted at `time`: it proves
    /// the signed data existed then.
    Anchored {
        /// `genTime`.
        time: DateTime,
        /// The token's signer and its path to the anchor.
        authority: TimestampAuthority,
    },
    /// The token verifies and imprints what it should, but its
    /// authority is not anchored: `time` is what the token claims and
    /// proves nothing.
    Claimed {
        /// `genTime`.
        time: DateTime,
        /// The token's signer and its path as far as it was built.
        authority: TimestampAuthority,
    },
    /// The token does not verify, or imprints other data.
    Invalid(TimestampError),
    /// The token is not judged: an `XAdES` timestamp under a
    /// canonicalisation this verifier does not compute, an archive
    /// timestamp of a form this verifier does not judge, or a PDF
    /// document timestamp whose range does not end a revision.
    Unsupported,
}

impl TimestampReport {
    /// The time the token proves: its `genTime` when it verifies and is
    /// anchored.
    #[must_use]
    pub const fn proven_time(&self) -> Option<DateTime> {
        match self {
            Self::Anchored { time, .. } => Some(*time),
            Self::Claimed { .. } | Self::Invalid(_) | Self::Unsupported => None,
        }
    }

    /// Whether the token verifies, anchored or not.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Anchored { .. } | Self::Claimed { .. })
    }

    /// The token's signer and path, when the token verifies.
    #[must_use]
    pub const fn authority(&self) -> Option<&TimestampAuthority> {
        match self {
            Self::Anchored { authority, .. } | Self::Claimed { authority, .. } => Some(authority),
            Self::Invalid(_) | Self::Unsupported => None,
        }
    }
}

/// The form an archive timestamp takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveForm {
    /// A `CAdES` `archive-time-stamp-v3` (`ETSI EN 319 122-1` clause
    /// 5.5.3), judged.
    CadesV3,
    /// A `CAdES` `archive-time-stamp` (RFC 5126 sec.6.4.1), counted and
    /// reported [`TimestampReport::Unsupported`].
    CadesV2,
    /// An `XAdES` `ArchiveTimeStamp` (`ETSI EN 319 132-1` clause 5.5.2),
    /// judged when it is in the 1.4.1 namespace and its time-stamped
    /// properties share its parent; reported
    /// [`TimestampReport::Unsupported`] otherwise.
    Xades,
}

/// One archive timestamp of a signature: a timestamp over the
/// signature and its validation material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveTimestampReport {
    /// The form it takes.
    form: ArchiveForm,
    /// What the token was found to be.
    timestamp: TimestampReport,
}

impl ArchiveTimestampReport {
    /// The form it takes.
    #[must_use]
    pub const fn form(&self) -> ArchiveForm {
        self.form
    }

    /// What the token was found to be.
    #[must_use]
    pub const fn timestamp(&self) -> &TimestampReport {
        &self.timestamp
    }
}

/// One judged signature's facts.
#[derive(Debug, Clone)]
pub struct SignatureReport {
    /// The holder the signer certificate names.
    signer: SignerIdentity,
    /// The signer certificate.
    signer_certificate: OwnedCert,
    /// The certification path above the signer, anchored at the
    /// validation time or partial.
    chain: CertificationPath,
    /// Every byte the signature claims to cover digests to the value it
    /// states, and no later revision changes what was signed.
    document_intact: bool,
    /// The signature verifies under the signer's key, bound as the
    /// profile requires.
    signature_valid: bool,
    /// The earliest time an anchored timestamp proves.
    proof_of_existence: Option<DateTime>,
    /// The signature's own timestamps, in encoded order.
    timestamps: Vec<TimestampReport>,
    /// The archive timestamps, in encoded order.
    archive_timestamps: Vec<ArchiveTimestampReport>,
    /// When the chain and revocation were judged.
    validation_time: DateTime,
    /// The revocation status of the path.
    revocation: Revocation,
    /// What the revisions after the signed one do to the document.
    revision: Revision,
}

impl SignatureReport {
    /// The holder the signer certificate names.
    #[must_use]
    pub const fn signer(&self) -> &SignerIdentity {
        &self.signer
    }

    /// The signer certificate.
    #[must_use]
    pub const fn signer_certificate(&self) -> &OwnedCert {
        &self.signer_certificate
    }

    /// The certification path above the signer, its issuer first:
    /// [`CertificationPath::Anchored`], ending in the certificate-issuing
    /// anchor, when [`Self::chain_verified`]; otherwise
    /// [`CertificationPath::Partial`], as far as the evidence reaches.
    #[must_use]
    pub const fn chain(&self) -> &CertificationPath {
        &self.chain
    }

    /// Every byte the signature claims to cover digests to the value
    /// the signature states, for a container every data file is
    /// covered, and for a PDF no later revision changes what was signed
    /// ([`Self::revision`]).
    #[must_use]
    pub const fn document_intact(&self) -> bool {
        self.document_intact
    }

    /// The signature verifies under the signer's key with the binding
    /// the profile requires, and a `PAdES` baseline signature carries no
    /// `signing-time` attribute.
    #[must_use]
    pub const fn signature_valid(&self) -> bool {
        self.signature_valid
    }

    /// A path from the signer to a certificate-issuing anchor granted at
    /// [`Self::validation_time`], every certificate below the anchor
    /// valid at that time.
    #[must_use]
    pub const fn chain_verified(&self) -> bool {
        self.chain.is_anchored()
    }

    /// The earliest time an anchored timestamp proves: a signature
    /// timestamp, an archive timestamp, or a document timestamp whose
    /// range covers this signature.
    #[must_use]
    pub const fn proof_of_existence(&self) -> Option<DateTime> {
        self.proof_of_existence
    }

    /// The signature's own timestamps, in encoded order.
    #[must_use]
    pub fn timestamps(&self) -> &[TimestampReport] {
        &self.timestamps
    }

    /// The archive timestamps, in encoded order.
    #[must_use]
    pub fn archive_timestamps(&self) -> &[ArchiveTimestampReport] {
        &self.archive_timestamps
    }

    /// The proof of existence, else the `now` the caller passed: the
    /// time the chain and revocation were judged at.
    #[must_use]
    pub const fn validation_time(&self) -> DateTime {
        self.validation_time
    }

    /// The revocation status of the path at the validation time.
    #[must_use]
    pub const fn revocation(&self) -> Revocation {
        self.revocation
    }

    /// What the revisions after the one the signature covers do to
    /// the document: none follow, they only add signatures, document
    /// timestamps and validation material, or they change what was
    /// signed, which also makes [`Self::document_intact`] false. Always
    /// [`Revision::WholeDocument`] outside a PDF.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Whether the signature is valid: the document is intact, the
    /// signature is valid, the chain is verified, and no revocation
    /// before the proof of existence is known (any revocation, without
    /// a proof). A timestamp that does not verify is reported and
    /// decides nothing: it sits in unprotected attributes anyone can
    /// append to.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.document_intact
            && self.signature_valid
            && self.chain.is_anchored()
            && !self.revocation.revoked_before(self.proof_of_existence)
    }

    /// This report with `answer`, a revocation answer the shell fetched
    /// and judged at its own `now`, in place of an unavailable status.
    /// The answer is taken only when the file left revocation
    /// [`Revocation::Unavailable`] and the chain is verified; otherwise
    /// the report is returned unchanged.
    #[must_use]
    pub const fn with_live_revocation(mut self, answer: Revocation) -> Self {
        if self.chain.is_anchored() && matches!(self.revocation, Revocation::Unavailable) {
            self.revocation = answer;
        }
        self
    }
}

/// Why a signature was not judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedSignature {
    /// A PDF signature dictionary under a subfilter other than
    /// `ETSI.CAdES.detached` and `adbe.pkcs7.detached`.
    PdfSubFilter,
    /// A PDF signature whose `/ByteRange` does not end where a revision
    /// ends, so it signs part of one.
    PdfRangeNotARevision,
    /// A CMS signature this verifier does not read.
    Cms(CadesReadError),
    /// A `CAdES` signature in a container that no `ASiCManifest` names.
    CadesWithoutManifest,
    /// An `XAdES` signature using a feature this verifier does not
    /// implement.
    Xades(XadesUnsupported),
    /// The container's `XAdES` signature files could not be read.
    XadesFile(XadesReadError),
    /// One `XAdES` signature lacks a part every signature has, or
    /// carries one that does not decode.
    XadesMalformed(XadesReadError),
    /// An `XAdES` signature whose signing-certificate binding names a
    /// certificate it does not carry, so it has no signer to judge.
    XadesSignerNotCarried,
    /// An `XAdES` counter-signature nested more than
    /// [`MAX_COUNTER_SIGNATURE_DEPTH`] levels below the signature over
    /// the document.
    CounterSignatureTooDeep,
}

/// Most levels of `XAdES` counter-signatures judged below a signature
/// over the document: a counter-signature, its counter-signature, and
/// so on. EN 319 132-1 clause 5.2.7.2 allows chains of any length; a
/// real one has one or two levels, and the bound keeps a hostile file
/// from making the report as deep as its XML.
pub const MAX_COUNTER_SIGNATURE_DEPTH: usize = 4;

/// What became of one signature found in the document.
#[derive(Debug, Clone)]
pub enum SignatureOutcome {
    /// The signature was judged.
    Judged(SignatureReport),
    /// The signature was found and not judged.
    Unsupported(UnsupportedSignature),
}

/// One signature found in the document.
#[derive(Debug, Clone)]
pub struct SignatureRow {
    /// Whether it was judged, and the facts or the reason.
    outcome: SignatureOutcome,
    /// The row of the signature whose `ds:SignatureValue` this one
    /// counter-signs, for an `XAdES` counter-signature.
    counter_signs: Option<usize>,
}

impl SignatureRow {
    /// A judged signature that counter-signs nothing.
    const fn judged(report: SignatureReport) -> Self {
        Self {
            outcome: SignatureOutcome::Judged(report),
            counter_signs: None,
        }
    }

    /// A signature found and not judged, that counter-signs nothing.
    const fn unsupported(reason: UnsupportedSignature) -> Self {
        Self {
            outcome: SignatureOutcome::Unsupported(reason),
            counter_signs: None,
        }
    }

    /// This row as the counter-signature of the signature at `row`.
    fn counter_signing(self, row: Option<usize>) -> Self {
        Self {
            counter_signs: row,
            ..self
        }
    }

    /// Whether the signature was judged, and the facts or the reason.
    #[must_use]
    pub const fn outcome(&self) -> &SignatureOutcome {
        &self.outcome
    }

    /// The index in [`DocumentReport::rows`] of the signature whose
    /// `ds:SignatureValue` this one counter-signs (`ETSI EN 319 132-1`
    /// clause 5.2.7); always an earlier row. `None` for a signature
    /// over the document itself.
    #[must_use]
    pub const fn counter_signs(&self) -> Option<usize> {
        self.counter_signs
    }

    /// Whether the signature was judged and is valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match &self.outcome {
            SignatureOutcome::Judged(report) => report.is_valid(),
            SignatureOutcome::Unsupported(_) => false,
        }
    }
}

/// One PDF document timestamp (`ETSI EN 319 142-1` clause 5.4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentTimestampReport {
    /// What the token was found to be.
    timestamp: TimestampReport,
    /// One past the last byte its range covers.
    covers: usize,
}

impl DocumentTimestampReport {
    /// What the token was found to be.
    #[must_use]
    pub const fn timestamp(&self) -> &TimestampReport {
        &self.timestamp
    }

    /// One past the last byte its range covers: the revisions it
    /// timestamps end at or before this offset.
    #[must_use]
    pub const fn covers(&self) -> usize {
        self.covers
    }
}

/// The verification of one document.
#[derive(Debug, Clone)]
pub struct DocumentReport {
    /// Every signature found, in document order.
    rows: Vec<SignatureRow>,
    /// Every PDF document timestamp, in document order.
    document_timestamps: Vec<DocumentTimestampReport>,
    /// When the anchors' lists were fetched.
    anchors_fetched_at: Option<DateTime>,
}

impl DocumentReport {
    /// Every signature found, in document order.
    #[must_use]
    pub fn rows(&self) -> &[SignatureRow] {
        &self.rows
    }

    /// Every PDF document timestamp, in document order.
    #[must_use]
    pub fn document_timestamps(&self) -> &[DocumentTimestampReport] {
        &self.document_timestamps
    }

    /// When the lists the anchors came from were fetched; `None` for
    /// anchors from no list.
    #[must_use]
    pub const fn anchors_fetched_at(&self) -> Option<DateTime> {
        self.anchors_fetched_at
    }

    /// Whether the document is valid: it has at least one signature
    /// over the document itself, and every such signature was judged
    /// and is valid. A document timestamp that does not verify, and an
    /// `XAdES` counter-signature of any verdict, are reported and decide
    /// nothing: both sit in unsigned material anyone can append to.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let mut signatures = self
            .rows
            .iter()
            .filter(|row| row.counter_signs.is_none())
            .peekable();
        signatures.peek().is_some() && signatures.all(SignatureRow::is_valid)
    }

    /// This report with live revocation answers: `ask` is called for
    /// each judged signature whose revocation the file left unavailable
    /// on a verified chain, and its answer applied as by
    /// [`SignatureReport::with_live_revocation`].
    #[must_use]
    pub fn with_live_revocation(
        mut self,
        mut ask: impl FnMut(&SignatureReport) -> Revocation,
    ) -> Self {
        for row in &mut self.rows {
            if let SignatureOutcome::Judged(report) = &mut row.outcome
                && report.chain.is_anchored()
                && report.revocation == Revocation::Unavailable
            {
                report.revocation = ask(report);
            }
        }
        self
    }
}

/// Why the file was unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// The PDF structure does not parse.
    Pdf(PdfReadError),
    /// The container structure does not parse.
    Container(AsicReadError),
}

/// Which profile the file uses that this verifier does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedProfile {
    /// A PDF feature outside the verifier: encryption, a stream filter,
    /// a bound.
    Pdf(PdfReadError),
    /// A ZIP feature outside the `ASiC` profile, or an archive that is
    /// not an `ASiC-E` or `BDOC` container.
    Container(AsicReadError),
    /// A DER file that is not a CMS signature this verifier reads.
    Cms(CadesReadError),
    /// A CMS signature whose content is not attached.
    DetachedCms,
}

/// Why a file yielded no report. A negative verdict is a report, not
/// one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentFailure {
    /// Neither a PDF, a ZIP archive nor a DER structure.
    NotASignedDocument,
    /// A file of a known kind whose structure does not parse.
    Unreadable(Unreadable),
    /// The file parses and carries no signature.
    NoSignatures,
    /// The file uses a profile this verifier does not implement.
    UnsupportedProfile(UnsupportedProfile),
}

impl core::fmt::Display for DocumentFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotASignedDocument => f.write_str("not a signed document"),
            Self::Unreadable(Unreadable::Pdf(error)) => write!(f, "unreadable: {error}"),
            Self::Unreadable(Unreadable::Container(error)) => write!(f, "unreadable: {error}"),
            Self::NoSignatures => f.write_str("the document carries no signatures"),
            Self::UnsupportedProfile(UnsupportedProfile::Pdf(error)) => {
                write!(f, "unsupported: {error}")
            }
            Self::UnsupportedProfile(UnsupportedProfile::Container(error)) => {
                write!(f, "unsupported: {error}")
            }
            Self::UnsupportedProfile(UnsupportedProfile::Cms(error)) => {
                write!(f, "unsupported: {error}")
            }
            Self::UnsupportedProfile(UnsupportedProfile::DetachedCms) => {
                f.write_str("unsupported: the CMS signature does not carry its content")
            }
        }
    }
}

impl core::error::Error for DocumentFailure {}

/// Verify every signature of `file` under `anchors`, with `now` as the
/// validation time of a signature that proves no earlier existence.
///
/// # Errors
/// [`DocumentFailure`] when there is nothing to judge: the PDF or
/// container does not parse or uses an unsupported profile, carries no
/// signature, or the DER file is not a CMS signature with attached
/// content. A negative verdict is a report.
pub fn verify(
    file: &DocumentFile,
    anchors: &TrustAnchors,
    now: DateTime,
) -> Result<DocumentReport, DocumentFailure> {
    let context = Context { anchors, now };
    let (rows, document_timestamps) = match &file.content {
        FileContent::Pdf(bytes) => context.verify_pdf(bytes)?,
        FileContent::Zip(bytes) => (context.verify_asic(bytes)?, Vec::new()),
        FileContent::Der(bytes) => (vec![context.verify_attached_cms(bytes)?], Vec::new()),
    };
    if rows.is_empty() {
        return Err(DocumentFailure::NoSignatures);
    }
    Ok(DocumentReport {
        rows,
        document_timestamps,
        anchors_fetched_at: anchors.fetched_at(),
    })
}

/// What every judgement in one verification consults.
struct Context<'a> {
    /// The anchors.
    anchors: &'a TrustAnchors,
    /// The caller's clock.
    now: DateTime,
}

/// What a format reader established about one signature, before its
/// timestamps, chain and revocation are judged.
struct Facts {
    /// The signer certificate.
    signer: OwnedCert,
    /// Whether every covered byte digests to the stated value.
    document_intact: bool,
    /// Whether the signature verifies, bound as required.
    signature_valid: bool,
    /// The signature's own timestamps.
    timestamps: Vec<Timestamp>,
    /// The archive timestamps, each with its form.
    archive_timestamps: Vec<(ArchiveForm, Timestamp)>,
    /// Proven times of the document timestamps covering the signature.
    covering_proofs: Vec<DateTime>,
    /// What the revisions after the signed one do to the document.
    revision: Revision,
    /// The evidence for this signature: the document's, the
    /// signature's own, and the anchors' certificates.
    pool: MaterialPool,
}

/// One timestamp as a reader found it.
enum Timestamp {
    /// A token and what its imprint must digest.
    Token {
        /// The token DER.
        token: Vec<u8>,
        /// What it imprints.
        imprint: Imprint,
    },
    /// A token whose imprinted octets this verifier does not compute.
    Uncomputable,
    /// A token found not valid before it is verified: an archive
    /// timestamp whose hash index does not hold.
    Refused(TimestampError),
}

/// What a token's message imprint must digest.
enum Imprint {
    /// These octets, under the token's own imprint algorithm.
    Octets(Vec<u8>),
    /// An `archive-time-stamp-v3` input, under its index's algorithm.
    Archive(cades::ArchiveImprint),
}

impl Imprint {
    /// The digest a token imprinting under `algorithm` must carry; an
    /// archive input under another algorithm than its index's matches
    /// no token.
    fn digest(&self, algorithm: crate::cades::DigestAlgorithm) -> Vec<u8> {
        match self {
            Self::Octets(octets) => algorithm.digest(octets),
            Self::Archive(imprint) => imprint.digest(algorithm).unwrap_or_default(),
        }
    }
}

impl Context<'_> {
    /// A pool holding the anchors' certificates.
    fn anchor_pool(&self) -> MaterialPool {
        let mut pool = MaterialPool::new();
        pool.add_anchors(self.anchors);
        pool
    }

    /// Judge one token: [`verify_token`] for the token itself, then its
    /// authority against the time-stamping anchors at the token's time.
    /// A revocation of the authority at or before that time unanchors
    /// it.
    fn judge_token(
        &self,
        token: &[u8],
        imprint_of: impl FnOnce(crate::cades::DigestAlgorithm) -> Vec<u8>,
        pool: &MaterialPool,
    ) -> TimestampReport {
        let verified = match verify_token(token, imprint_of) {
            Ok(verified) => verified,
            Err(error) => return TimestampReport::Invalid(error),
        };
        let mut pool = pool.clone();
        for certificate in verified.embedded_certificates() {
            pool.add_certificate(certificate.clone());
        }
        pool.add_material(verified.embedded_revocation());
        let time = verified.generated_at();
        let chain = judge(
            verified.signer_certificate(),
            &pool,
            self.anchors,
            AnchorRole::TimeStamping,
            trust::When {
                at: time,
                now: self.now,
            },
        );
        let anchored = chain.path.is_anchored();
        let authority = TimestampAuthority {
            signer: verified.signer_certificate().clone(),
            chain: chain.path,
        };
        if anchored && !chain.revocation.revoked_before(Some(time)) {
            TimestampReport::Anchored { time, authority }
        } else {
            TimestampReport::Claimed { time, authority }
        }
    }

    /// Turn one signature's facts into a report: its timestamps judged,
    /// the proof of existence taken from the anchored ones, and the
    /// chain and revocation judged at the validation time.
    fn report(&self, facts: Facts) -> SignatureReport {
        let judge_one = |timestamp: &Timestamp| match timestamp {
            Timestamp::Token { token, imprint } => {
                self.judge_token(token, |algorithm| imprint.digest(algorithm), &facts.pool)
            }
            Timestamp::Uncomputable => TimestampReport::Unsupported,
            Timestamp::Refused(error) => TimestampReport::Invalid(*error),
        };
        let timestamps: Vec<TimestampReport> = facts.timestamps.iter().map(judge_one).collect();
        let archive_timestamps: Vec<ArchiveTimestampReport> = facts
            .archive_timestamps
            .iter()
            .map(|(form, timestamp)| ArchiveTimestampReport {
                form: *form,
                timestamp: judge_one(timestamp),
            })
            .collect();
        let proof_of_existence = timestamps
            .iter()
            .chain(archive_timestamps.iter().map(|archive| &archive.timestamp))
            .filter_map(TimestampReport::proven_time)
            .chain(facts.covering_proofs.iter().copied())
            .min();
        let validation_time = proof_of_existence.unwrap_or(self.now);
        let chain = judge(
            &facts.signer,
            &facts.pool,
            self.anchors,
            AnchorRole::CertificateIssuing,
            trust::When {
                at: validation_time,
                now: self.now,
            },
        );
        SignatureReport {
            signer: SignerIdentity::of(&facts.signer),
            signer_certificate: facts.signer,
            chain: chain.path,
            document_intact: facts.document_intact
                && !matches!(facts.revision, Revision::ChangedAfterSigning(_)),
            signature_valid: facts.signature_valid,
            proof_of_existence,
            timestamps,
            archive_timestamps,
            validation_time,
            revocation: chain.revocation,
            revision: facts.revision,
        }
    }

    /// Judge every signature dictionary and document timestamp of a PDF.
    fn verify_pdf(
        &self,
        bytes: &[u8],
    ) -> Result<(Vec<SignatureRow>, Vec<DocumentTimestampReport>), DocumentFailure> {
        let document = PdfDocument::parse(bytes).map_err(|error| match error {
            PdfReadError::NotAPdf => DocumentFailure::NotASignedDocument,
            PdfReadError::Malformed(_) => DocumentFailure::Unreadable(Unreadable::Pdf(error)),
            PdfReadError::Unsupported(_) => {
                DocumentFailure::UnsupportedProfile(UnsupportedProfile::Pdf(error))
            }
        })?;
        let mut base = self.anchor_pool();
        base.add_material(document.validation_store());

        let stamps: Vec<(DocumentTimestampReport, ByteRange)> = document
            .signatures()
            .iter()
            .filter(|found| found.kind() == SignatureKind::DocumentTimestamp)
            .map(|found| {
                let range = found.byte_range();
                let timestamp = if found.ends_revision() {
                    self.judge_token(
                        found.cms(),
                        |algorithm| document.digest(&range, algorithm),
                        &base,
                    )
                } else {
                    TimestampReport::Unsupported
                };
                (
                    DocumentTimestampReport {
                        timestamp,
                        covers: range.end(),
                    },
                    range,
                )
            })
            .collect();

        let mut rows = Vec::new();
        for found in document.signatures() {
            let ess = match found.kind() {
                SignatureKind::Signature(SubFilter::EtsiCadesDetached) => EssBinding::Required,
                SignatureKind::Signature(SubFilter::AdbePkcs7Detached) => EssBinding::NotRequired,
                SignatureKind::Signature(SubFilter::EtsiRfc3161 | SubFilter::Other) => {
                    rows.push(SignatureRow::unsupported(
                        UnsupportedSignature::PdfSubFilter,
                    ));
                    continue;
                }
                SignatureKind::DocumentTimestamp => continue,
            };
            let Some(revision) = found.revision() else {
                rows.push(SignatureRow::unsupported(
                    UnsupportedSignature::PdfRangeNotARevision,
                ));
                continue;
            };
            let signature = match CadesSignature::parse(found.cms()) {
                Ok(signature) => signature,
                Err(error) => {
                    rows.push(SignatureRow::unsupported(UnsupportedSignature::Cms(error)));
                    continue;
                }
            };
            let range = found.byte_range();
            let signed_octets = document.signed_octets(&range);
            let verdict = signature.verify(
                Content::Detached {
                    content: &signed_octets,
                },
                ess,
            );
            let baseline_time_attribute =
                ess == EssBinding::Required && signature.has_signing_time_attribute();
            let mut pool = base.clone();
            pool.add_material(signature.embedded_material());
            let covering_proofs = stamps
                .iter()
                .filter(|(_, stamp_range)| stamp_range.hole().start >= range.end())
                .filter_map(|(stamp, _)| stamp.timestamp.proven_time())
                .collect();
            rows.push(SignatureRow::judged(self.report(Facts {
                signer: signature.signer_certificate().clone(),
                document_intact: verdict.document_intact,
                signature_valid: verdict.signature_valid && !baseline_time_attribute,
                timestamps: cades_timestamps(&verdict.signature_timestamps),
                archive_timestamps: cades_archive_timestamps(verdict.archive_timestamps),
                covering_proofs,
                revision,
                pool,
            })));
        }
        Ok((rows, stamps.into_iter().map(|(stamp, _)| stamp).collect()))
    }

    /// Judge every signature of an `ASiC-E` or `BDOC` container: the
    /// `XAdES` signature files and the `CAdES` signatures with their
    /// manifests.
    fn verify_asic(&self, bytes: &[u8]) -> Result<Vec<SignatureRow>, DocumentFailure> {
        let container = AsicContainer::parse(bytes).map_err(|error| match error {
            AsicReadError::NotAZip => DocumentFailure::NotASignedDocument,
            AsicReadError::Malformed(_)
            | AsicReadError::NoDataObjects
            | AsicReadError::ManifestConflict => {
                DocumentFailure::Unreadable(Unreadable::Container(error))
            }
            AsicReadError::Unsupported(_)
            | AsicReadError::MissingMimetype
            | AsicReadError::UnknownMimetype
            | AsicReadError::UnexpectedMetadata => {
                DocumentFailure::UnsupportedProfile(UnsupportedProfile::Container(error))
            }
        })?;
        let mut rows = Vec::new();
        if !container.xades_signature_files().is_empty() {
            match xades::signatures(&container) {
                Err(error) => rows.push(SignatureRow::unsupported(
                    UnsupportedSignature::XadesFile(error),
                )),
                Ok(signatures) => {
                    for signature in &signatures {
                        self.push_xades_rows(&container, signature, &[], &mut rows);
                    }
                }
            }
        }
        for entry in container.cades_signatures() {
            rows.push(self.asic_cades_row(&container, entry));
        }
        Ok(rows)
    }

    /// The row of one `XAdES` signature, then the rows of its
    /// counter-signatures, each naming the row it counter-signs.
    /// `enclosing` holds the signatures this one is nested in, the
    /// outermost first, each with its row; the last is the one it
    /// counter-signs. Past [`MAX_COUNTER_SIGNATURE_DEPTH`] levels a
    /// counter-signature is an unsupported row and its own
    /// counter-signatures are not read.
    fn push_xades_rows(
        &self,
        container: &AsicContainer,
        signature: &Result<xades::XadesSignature, XadesReadError>,
        enclosing: &[(usize, &xades::XadesSignature)],
        rows: &mut Vec<SignatureRow>,
    ) {
        let row = rows.len();
        let counter_signs = enclosing.last().map(|(row, _)| *row);
        if enclosing.len() > MAX_COUNTER_SIGNATURE_DEPTH {
            rows.push(
                SignatureRow::unsupported(UnsupportedSignature::CounterSignatureTooDeep)
                    .counter_signing(counter_signs),
            );
            return;
        }
        match signature {
            Ok(signature) => {
                let outer: Vec<&xades::XadesSignature> =
                    enclosing.iter().map(|(_, outer)| *outer).collect();
                rows.push(
                    self.xades_row(container, signature, &outer)
                        .counter_signing(counter_signs),
                );
                let mut nested = enclosing.to_vec();
                nested.push((row, signature));
                for counter_signature in signature.counter_signatures() {
                    self.push_xades_rows(container, counter_signature, &nested, rows);
                }
            }
            Err(error) => rows.push(
                SignatureRow::unsupported(UnsupportedSignature::XadesMalformed(*error))
                    .counter_signing(counter_signs),
            ),
        }
    }

    /// The row of one `XAdES` signature. A counter-signature's evidence
    /// includes that of every signature in `enclosing`, the signatures
    /// it is nested in, whose `CertificateValues` and `RevocationValues`
    /// may carry the counter-signer's path (`ETSI EN 319 132-1` clause
    /// 5.4.2).
    fn xades_row(
        &self,
        container: &AsicContainer,
        signature: &xades::XadesSignature,
        enclosing: &[&xades::XadesSignature],
    ) -> SignatureRow {
        let judgement = match signature.verify(container) {
            XadesVerdict::Unsupported(unsupported) => {
                return SignatureRow::unsupported(UnsupportedSignature::Xades(unsupported));
            }
            XadesVerdict::Judged(judgement) => judgement,
        };
        let Some(signer) = signature.signer_certificate() else {
            return SignatureRow::unsupported(UnsupportedSignature::XadesSignerNotCarried);
        };
        let mut pool = self.anchor_pool();
        pool.add_material(signature.embedded_material());
        pool.add_certificate_ders(signature.embedded_certificates());
        for outer in enclosing {
            pool.add_material(outer.embedded_material());
            pool.add_certificate_ders(outer.embedded_certificates());
        }
        let timestamps = signature
            .signature_timestamps()
            .iter()
            .map(|timestamp| match timestamp.imprint_input() {
                Some(input) => Timestamp::Token {
                    token: timestamp.token().to_vec(),
                    imprint: Imprint::Octets(input.to_vec()),
                },
                None => Timestamp::Uncomputable,
            })
            .collect();
        let archive_timestamps = signature
            .archive_timestamps(container)
            .into_iter()
            .map(|archive| {
                let timestamp = match archive.imprint_input() {
                    Some(input) => Timestamp::Token {
                        token: archive.token().to_vec(),
                        imprint: Imprint::Octets(input.to_vec()),
                    },
                    None => Timestamp::Uncomputable,
                };
                (ArchiveForm::Xades, timestamp)
            })
            .collect();
        SignatureRow::judged(self.report(Facts {
            signer: signer.clone(),
            document_intact: judgement.document_intact(),
            signature_valid: judgement.signature_valid(),
            timestamps,
            archive_timestamps,
            covering_proofs: Vec::new(),
            revision: Revision::WholeDocument,
            pool,
        }))
    }

    /// The row of one `CAdES` signature over an `ASiCManifest`.
    fn asic_cades_row(&self, container: &AsicContainer, entry: &asic::CadesEntry) -> SignatureRow {
        let signature = match CadesSignature::parse(entry.signature().content()) {
            Ok(signature) => signature,
            Err(error) => return SignatureRow::unsupported(UnsupportedSignature::Cms(error)),
        };
        let Some(manifest) = entry.manifest() else {
            return SignatureRow::unsupported(UnsupportedSignature::CadesWithoutManifest);
        };
        let verdict = signature.verify(
            Content::Detached {
                content: manifest.content(),
            },
            EssBinding::Required,
        );
        let mut pool = self.anchor_pool();
        pool.add_material(signature.embedded_material());
        SignatureRow::judged(self.report(Facts {
            signer: signature.signer_certificate().clone(),
            document_intact: verdict.document_intact && container.manifest_intact(entry),
            signature_valid: verdict.signature_valid,
            timestamps: cades_timestamps(&verdict.signature_timestamps),
            archive_timestamps: cades_archive_timestamps(verdict.archive_timestamps),
            covering_proofs: Vec::new(),
            revision: Revision::WholeDocument,
            pool,
        }))
    }

    /// Judge a CMS file carrying its content as `eContent`
    /// (`ETSI EN 319 122-1`).
    fn verify_attached_cms(&self, bytes: &[u8]) -> Result<SignatureRow, DocumentFailure> {
        let signature = CadesSignature::parse(bytes)
            .map_err(|error| DocumentFailure::UnsupportedProfile(UnsupportedProfile::Cms(error)))?;
        if !signature.content_attached() {
            return Err(DocumentFailure::UnsupportedProfile(
                UnsupportedProfile::DetachedCms,
            ));
        }
        let verdict = signature.verify(Content::Attached, EssBinding::Required);
        let mut pool = self.anchor_pool();
        pool.add_material(signature.embedded_material());
        Ok(SignatureRow::judged(self.report(Facts {
            signer: signature.signer_certificate().clone(),
            document_intact: verdict.document_intact,
            signature_valid: verdict.signature_valid,
            timestamps: cades_timestamps(&verdict.signature_timestamps),
            archive_timestamps: cades_archive_timestamps(verdict.archive_timestamps),
            covering_proofs: Vec::new(),
            revision: Revision::WholeDocument,
            pool,
        })))
    }
}

/// The `CAdES` signature timestamps as the report judges them.
fn cades_timestamps(timestamps: &[cades::CadesTimestamp]) -> Vec<Timestamp> {
    timestamps
        .iter()
        .map(|timestamp| Timestamp::Token {
            token: timestamp.token().to_vec(),
            imprint: Imprint::Octets(timestamp.imprint_input().to_vec()),
        })
        .collect()
}

/// The `CAdES` archive timestamps as the report judges them.
fn cades_archive_timestamps(
    timestamps: Vec<cades::CadesArchiveTimestamp>,
) -> Vec<(ArchiveForm, Timestamp)> {
    timestamps
        .into_iter()
        .map(|timestamp| match timestamp {
            cades::CadesArchiveTimestamp::V3(Ok(archive)) => (
                ArchiveForm::CadesV3,
                Timestamp::Token {
                    token: archive.token().to_vec(),
                    imprint: Imprint::Archive(archive.imprint().clone()),
                },
            ),
            cades::CadesArchiveTimestamp::V3(Err(error)) => {
                (ArchiveForm::CadesV3, Timestamp::Refused(error))
            }
            cades::CadesArchiveTimestamp::V2 => (ArchiveForm::CadesV2, Timestamp::Uncomputable),
        })
        .collect()
}

#[cfg(test)]
mod tests;

/// The elements of `items` as an array of the length the caller's
/// pattern names, for tests that destructure a result.
#[cfg(test)]
fn exactly<'a, T, const N: usize>(items: &'a [T], what: &str) -> &'a [T; N] {
    items.try_into().expect(what)
}
