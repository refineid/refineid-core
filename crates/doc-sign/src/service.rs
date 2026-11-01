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

//! The document-signing service: what a signature request is, how a
//! signed document is finished and how the signing is reported,
//! independent of the device that holds the private key.
//!
//! Two devices sign. A card in this computer's reader is driven by
//! `reader`, behind the `pcsc` feature; the paired phone's card by
//! [`crate::remote`]. Both plan the document around the signing
//! certificate (`document_signer`, `load_data_objects`), verify the
//! device's signature against that certificate
//! (`verify_against_certificate`) and finish on one path
//! (`finish_document`): the timestamps, the long-term material, the
//! archive timestamp and the output file. A platform with its own card
//! session builds without `pcsc` and brings its signature to that same
//! finish.
//!
//! [`SignErrorKind`] names the failures of this shared part; a device's
//! own failures live in its module.

use core::fmt;
use std::path::{Path, PathBuf};

use crate::asic::DataObject;
use crate::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime};
use crate::digest::Sha256;
use crate::document::{DocumentError, DocumentPlan, Format};
use crate::identity::CommonName;
use crate::pades::SignatureMetadata;
use crate::pin::PinRole;
use crate::remote::{DocumentName, PhoneCertificateError, PhoneRefusal};
use crate::rng;
use crate::signed_name::{BestSignatureTime, PendingSignedName};
use crate::timestamp::{self, TimestampError, VerifiedTimestampToken};
use crate::uri::{Scheme, Uri};
use crate::validation::ValidationMaterial;
use refineid_cms::x509::{
    Certificate, DateTime, EcCurve, MessageSignatureAlgorithm, OwnedCert, PublicKeyAlgorithm,
};
use zeroize::Zeroizing;

use crate::material::{ChainAnchor, ChainStart, MaterialError, NoncePolicy, now_date_time};

#[cfg(feature = "pcsc")]
pub mod reader;

/// Maximum tolerated difference between this host and a live TSA.
///
/// A nonce proves that a response belongs to this request, but does not
/// make an authority's asserted time sensible. A newly requested token
/// outside this window must not choose the certificate-validation instant.
const MAX_TIMESTAMP_CLOCK_SKEW: core::time::Duration = core::time::Duration::from_mins(5);

/// Initial wait after a transient timestamp-authority failure.
const TIMESTAMP_RETRY_INITIAL_DELAY: core::time::Duration = core::time::Duration::from_secs(1);
/// Ceiling for repeated timestamp-authority retries.
const TIMESTAMP_RETRY_MAX_DELAY: core::time::Duration = core::time::Duration::from_mins(1);
/// Most attempts made against one authority before giving up.
///
/// With the doubling schedule above this spends a little over two
/// minutes waiting; an authority still down after that is reported
/// rather than waited on, because the reader session stays open for
/// the whole wait.
const TIMESTAMP_RETRY_MAX_ATTEMPTS: u32 = 8;
/// Most time spent waiting on one authority across all attempts.
///
/// Same allowance as `MAX_TIMESTAMP_CLOCK_SKEW`: a holder with a card
/// in the reader waits no longer than that for an attested time.
const TIMESTAMP_RETRY_TOTAL_BUDGET: core::time::Duration = core::time::Duration::from_mins(5);

/// Candidate EU-qualified timestamp endpoints used by first-party clients.
///
/// Whoever configures an authority answers for it: every returned
/// token is cryptographically verified against the request digest and
/// nonce, and nothing beyond that is checked about the operator.
pub const EU_QUALIFIED_TIMESTAMP_AUTHORITIES: &[&str] = &[DEFAULT_TIMESTAMP_AUTHORITY];

/// The timestamp authority used when the operator configures none.
///
/// The Sectigo qualified endpoint, shared by every first-party
/// `RefineID` client and documented at
/// <https://www.sectigo.com/resource-library/time-stamping-server>.
pub const DEFAULT_TIMESTAMP_AUTHORITY: &str = "http://timestamp.sectigo.com/qualified";

/// HTTP Basic credentials for one explicitly configured timestamp authority.
///
/// Both fields and the derived authorization header are zeroized on drop. The
/// custom [`Debug`] implementation deliberately exposes neither field.
#[derive(Clone)]
pub struct TimestampCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl TimestampCredentials {
    /// Construct credentials supplied by an interactive caller.
    ///
    /// # Errors
    /// An empty username or a username containing the Basic-auth separator is
    /// rejected before any network request is attempted.
    pub fn new(username: String, password: String) -> Result<Self, &'static str> {
        let username = Zeroizing::new(username);
        let password = Zeroizing::new(password);
        if username.is_empty() {
            return Err("timestamp username is empty");
        }
        if username.contains(':') {
            return Err("timestamp username cannot contain ':'");
        }
        Ok(Self { username, password })
    }

    fn authorization_header(&self) -> Zeroizing<String> {
        let mut plain = Zeroizing::new(Vec::with_capacity(
            self.username.len() + 1 + self.password.len(),
        ));
        plain.extend_from_slice(self.username.as_bytes());
        plain.push(b':');
        plain.extend_from_slice(self.password.as_bytes());
        let encoded = Zeroizing::new(crate::base64::encode(&plain));
        let mut header = Zeroizing::new(String::with_capacity(6 + encoded.len()));
        header.push_str("Basic ");
        header.push_str(&encoded);
        header
    }

    fn with_authorization_header<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        let header = self.authorization_header();
        operation(header.as_str())
    }
}

impl fmt::Debug for TimestampCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TimestampCredentials(REDACTED)")
    }
}

/// Which on-card key signs (FINEID S1 v4.2 §3.5): the key, the PIN
/// that gates it, and the certificate its public key pairs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignSlot {
    /// The authentication key: key reference `KeyRef::Auth`, gated by
    /// PIN 1, certificate EF.4331.
    Authentication,
    /// The qualified-signature key: key reference `KeyRef::Sign`, gated
    /// by PIN 2, certificate EF.4332.
    Qualified,
}

impl SignSlot {
    /// The PIN the key's VERIFY presents.
    #[must_use]
    pub const fn pin_role(self) -> PinRole {
        match self {
            Self::Authentication => PinRole::Pin1,
            Self::Qualified => PinRole::Pin2,
        }
    }

    /// The PIN's name as the activation letter prints it.
    #[must_use]
    pub const fn pin_label(self) -> &'static str {
        match self {
            Self::Authentication => "PIN1",
            Self::Qualified => "PIN2",
        }
    }

    /// The key's name in reports and errors.
    #[must_use]
    pub const fn key_label(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Qualified => "qualified-signature",
        }
    }
}

/// A document signature rather than a bare one: the format and level
/// asked for, and what the signature records.
///
/// Carried by the reader path's options when the operator asked for a
/// format rather than raw signature bytes, and by every document the
/// phone signs ([`crate::remote::PhoneSignOptions`]). The difference
/// reaches all the way into the card session: a document signature
/// covers a structure that names the signing certificate, so it cannot
/// be built until the certificate has been read off the card.
#[derive(Debug, Clone)]
pub struct DocumentRequest {
    /// Which format to produce.
    pub format: Format,
    /// Files beyond the primary input. Only the container formats
    /// accept any; the rest refuse a set rather than sign the first.
    pub additional_inputs: Vec<PathBuf>,
    /// Claimed signing time, supplied by the caller.
    ///
    /// Read from the clock in the CLI layer rather than here, so this
    /// module stays deterministic and the claim stays the caller's to
    /// make.
    pub signing_time: SigningTime,
    /// What to record in the signature. Used by `PAdES` only.
    pub metadata: SignatureMetadata,
    /// Add an archive timestamp over the finished document, raising it
    /// to level LTA.
    ///
    /// This implies [`Self::long_term`] even when a direct API caller
    /// leaves that field false: an archive timestamp is added only
    /// after complete LT material has been collected and embedded.
    ///
    /// Implemented for `PAdES` and `ASiC-E` with `CAdES`. Standalone
    /// `CAdES`, `XAdES`, and `ASiC-E` with `XAdES` need different
    /// archive constructions that are not implemented yet.
    pub archive: bool,
    /// Collect and embed the chain and revocation answers, raising the
    /// signature to level LT.
    ///
    /// Costs a handful of network round trips at signing time and buys
    /// a signature that still checks when the responder is gone.
    /// [`Self::archive`] always enables this operation too.
    pub long_term: bool,
    /// URLs of RFC 3161 Time Stamp Authorities, when the signature is
    /// to carry an attested time rather than a claimed one.
    ///
    /// Empty leaves the signature at baseline level `B`: the time in it
    /// is the signer's word. More than one is allowed and they are
    /// alternatives, not a sequence -- each attests the same signature,
    /// so the signature keeps a proven time for as long as any one of
    /// them is still trusted.
    pub timestamp_authorities: Vec<String>,
    /// Optional credentials for the sole configured timestamp authority.
    ///
    /// Credentials are deliberately limited to one authority so they can
    /// never be replayed to a fallback host.
    pub timestamp_credentials: Option<TimestampCredentials>,
}

impl DocumentRequest {
    /// Whether this request must collect and embed complete LT material.
    ///
    /// Kept at the API boundary rather than only in CLI argument
    /// normalization: callers may construct this public type directly,
    /// and LTA without the preceding LT evidence is not a valid level.
    const fn requires_long_term_material(&self) -> bool {
        self.long_term || self.archive
    }

    /// Reject an impossible requested level before opening a reader or
    /// asking for a PIN. Archive still normalizes to LT through
    /// [`Self::requires_long_term_material`]; this only catches missing
    /// authorities and formats whose archive construction is absent.
    pub(crate) fn validate_signing_policy(&self) -> Result<(), SignErrorKind> {
        if self.requires_long_term_material() && self.timestamp_authorities.is_empty() {
            return Err(SignErrorKind::Timestamp(
                "LT and LTA signatures need at least one timestamp authority".to_owned(),
            ));
        }
        if self.timestamp_credentials.is_some() {
            if self.timestamp_authorities.len() != 1 {
                return Err(SignErrorKind::Timestamp(
                    "timestamp credentials require exactly one authority".to_owned(),
                ));
            }
            let authority = Uri::parse(self.timestamp_authorities[0].clone())
                .map_err(|error| SignErrorKind::Timestamp(error.to_string()))?;
            if authority.scheme() != Scheme::Https {
                return Err(SignErrorKind::Timestamp(
                    "timestamp credentials require HTTPS".to_owned(),
                ));
            }
        }
        if self.archive && !matches!(self.format, Format::Pades | Format::AsicECades) {
            return Err(SignErrorKind::Document(DocumentError::ArchiveUnsupported));
        }
        Ok(())
    }
}

/// Where a signing writes its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignOutput {
    /// This path, created or replaced.
    At(PathBuf),
    /// The default signed-document name, carrying the signature's
    /// best-signature-time once the signature exists. Created new: it
    /// never replaces an existing file.
    SignedName(PendingSignedName),
}

impl SignOutput {
    /// The path, given the signature's best-signature-time.
    #[must_use]
    pub fn path(&self, best: Option<BestSignatureTime>) -> PathBuf {
        match self {
            Self::At(path) => path.clone(),
            Self::SignedName(pending) => pending.path(best),
        }
    }

    /// Write `bytes` to [`Self::path`] and return that path.
    pub(crate) fn write(
        &self,
        best: Option<BestSignatureTime>,
        bytes: &[u8],
    ) -> Result<PathBuf, SignErrorKind> {
        use std::io::Write as _;
        let path = self.path(best);
        let written = match self {
            Self::At(_) => std::fs::write(&path, bytes),
            Self::SignedName(_) => std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .and_then(|mut file| file.write_all(bytes)),
        };
        match written {
            Ok(()) => Ok(path),
            Err(source) => Err(SignErrorKind::SignatureWrite { path, source }),
        }
    }
}

/// Where the private-key operation ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningDevice {
    /// A card in this computer's reader, named as PC/SC names the
    /// reader.
    Reader(String),
    /// The card held by the paired phone, reached over RAPP.
    PairedPhone,
}

impl fmt::Display for SigningDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reader(name) => write!(f, "reader: {name}"),
            Self::PairedPhone => f.write_str("signed on: the paired phone"),
        }
    }
}

/// One document's or one bare signature's worth of sign output.
#[derive(Debug, Clone)]
pub struct SignReport {
    /// Where the private-key operation ran.
    pub device: SigningDevice,
    /// Which key signed.
    pub slot: SignSlot,
    /// Length of the input file in bytes.
    pub input_len: u64,
    /// SHA-256 of the input.
    pub input_sha256: Sha256,
    /// Where the signature was written.
    pub signature_path: PathBuf,
    /// Where the cert DER was written, when `save_cert` was set.
    pub cert_path: Option<PathBuf>,
    /// Signature length in bytes (384 for RSA-3072, 96 for P-384).
    pub signature_len: usize,
    /// How many timestamp tokens were actually obtained.
    ///
    /// This includes the outer archive timestamp for an LTA document,
    /// in addition to the signature timestamps. It is a token count,
    /// not a count of distinct authorities: one authority may issue
    /// both kinds of token.
    pub timestamps: usize,
    /// The earliest `genTime` of the validated signature timestamps,
    /// the signature's best-signature-time (ETSI EN 319 102-1 clause
    /// 5.5); `None` without one, when a default name carries the clock.
    pub best_signature_time: Option<BestSignatureTime>,
    /// Size of the file that was written.
    ///
    /// Equal to `signature_len` for a bare sign, and the size of the
    /// finished document otherwise -- which is the number an operator
    /// looking at `--out` expects to see.
    pub output_len: usize,
    /// Subject CN of the on-card cert, when we could parse it.
    pub cert_subject_cn: Option<CommonName>,
    /// PIN retries reported by the card when VERIFY succeeded
    /// without an explicit retry counter. `None` means the card
    /// returned plain `0x9000` (no count surfaced).
    pub pin_retries_after: Option<u8>,
    /// Local-verify outcome.
    ///
    /// Whether refineid re-verified the card-produced signature
    /// against the on-card cert's public key before returning.
    /// Distinguishes "verified ok", "verified failed", and
    /// "skipped" (e.g. ECDSA local verify not yet wired) so the
    /// CLI exit-status and the human report don't conflate the
    /// three.
    pub local_verify: LocalVerifyOutcome,
}

/// Whether refineid re-verified the on-card signature against
/// the cert's public key before reporting success.
#[derive(Debug, Clone)]
pub enum LocalVerifyOutcome {
    /// `verify_pkcs1v15_sha256(pubkey, input, signature)` (RSA
    /// path) or the equivalent ECDSA verify returned `Ok(())`.
    Ok,
    /// Local verify ran and rejected the signature. The carried
    /// string is the diagnostic from the lower-level verifier.
    Failed(String),
    /// Local verify was not performed for this signature. Used
    /// today for the ECDSA-P384 chain (the raw-r||s -> DER
    /// conversion + pub exposure of the verify primitives are
    /// the follow-on commit). Tier 0 `&'static str`; describes
    /// why the skip happened.
    Skipped(&'static str),
}

impl LocalVerifyOutcome {
    /// `true` iff the variant is [`LocalVerifyOutcome::Ok`].
    /// Used by the CLI to map the verify result onto an exit
    /// status without losing the distinction between Failed and
    /// Skipped (both are not-Ok, but only Failed is a sign-flow
    /// failure).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// `true` iff the variant is [`LocalVerifyOutcome::Failed`].
    /// Distinguishes the "verify rejected the signature" case
    /// from [`LocalVerifyOutcome::Skipped`] (verify not run).
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

impl fmt::Display for LocalVerifyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Failed(s) => write!(f, "FAILED: {s}"),
            Self::Skipped(reason) => write!(f, "skipped ({reason})"),
        }
    }
}

/// Why a document was not signed, whichever device holds the key.
///
/// The failures of the service's shared part: the request, the
/// document's format and its pairing with the signing certificate, the
/// timestamps and the long-term material, the input and output files,
/// and the paired phone's answers. A device's own failures -- the
/// reader, the card, the PIN -- belong to the device's module;
/// `reader::ReaderSignError` carries this type in its `Document`
/// variant.
#[derive(Debug)]
pub enum SignErrorKind {
    /// The requested document format could not be built. Raised
    /// before the card signs anything, except for the PDF
    /// "signature did not fit" case, which is only knowable after.
    Document(DocumentError),
    /// A visible signature was asked of a format other than `PAdES`;
    /// refused before PIN verification.
    VisibleSignatureFormat,
    /// The slot's certificate uses a key this crate can build a
    /// document signature with, but whose digest pairing is not one
    /// the formats name.
    UnsupportedDocumentKey(SignSlot),
    /// The chain or revocation answers for one certificate path could
    /// not be collected, or a verified answer says a certificate on it
    /// is revoked ([`MaterialError::Revoked`]).
    ///
    /// Raised rather than falling back to a shorter-lived signature: a
    /// caller who asked for LT and silently got T would not be able to
    /// tell from the output.
    Material {
        /// Whose certificate path the material was collected for.
        path: MaterialPath,
        /// What went wrong while collecting.
        error: MaterialError,
    },
    /// The Time Stamp Authority could not be reached or refused.
    ///
    /// Raised rather than silently dropping the token: a caller who
    /// asked for an attested time and got a claimed one would not be
    /// able to tell from the output.
    Timestamp(String),
    /// Input file I/O failure (`NotFound`, `PermissionDenied`, ...).
    InputRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Signature output I/O failure.
    SignatureWrite {
        /// Filesystem path the write was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// The paired phone answered the signing or the certificate read
    /// with a refusal; nothing was written.
    Phone(PhoneRefusal),
    /// The certificate the paired phone returned is not a
    /// qualified-signature certificate this flow can sign with;
    /// refused before any digest went to the phone.
    PhoneCertificate(PhoneCertificateError),
    /// The paired phone returned a different number of signatures than
    /// the batch had documents; nothing was written.
    PhoneSignatureCount {
        /// Documents in the batch.
        expected: usize,
        /// Signatures the phone returned.
        got: usize,
    },
    /// A signature the paired phone returned does not verify against
    /// the phone's certificate over that document's signed octets;
    /// nothing was written.
    PhoneSignatureInvalid {
        /// The document whose signature failed.
        document: DocumentName,
        /// The verifier's diagnostic.
        detail: String,
    },
    /// A document's name, as the phone would show it to the holder,
    /// is empty or longer than RAPP v26.10.29 section 9.3 allows;
    /// refused before any digest went to the phone.
    DocumentNameLength,
    /// The phone path was given no document to sign.
    NoDocuments,
}

impl fmt::Display for SignErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Document(e) => write!(f, "{e}"),
            Self::VisibleSignatureFormat => {
                f.write_str("visible signature: supported only for PAdES")
            }
            Self::UnsupportedDocumentKey(slot) => write!(
                f,
                "the {} certificate's key type cannot produce a document signature",
                slot.key_label()
            ),
            Self::Material { path, error } => match path {
                MaterialPath::Signer => write!(f, "validation material: signer path: {error}"),
                MaterialPath::SignatureTimestamp { authority } => write!(
                    f,
                    "timestamp: {NO_SIGNATURE_TIMESTAMP} -- {authority}: {SIGNATURE_TIMESTAMP_WITHOUT_EVIDENCE}: {error}"
                ),
                MaterialPath::ArchiveTimestamp { authority } => write!(
                    f,
                    "timestamp: {NO_ARCHIVE_TIMESTAMP} -- {authority} {ARCHIVE_TIMESTAMP_WITHOUT_EVIDENCE} ({error}), trying the next"
                ),
            },
            Self::Timestamp(detail) => write!(f, "timestamp: {detail}"),
            Self::InputRead { path, source } => {
                write!(f, "read input {}: {source}", path.display())
            }
            Self::SignatureWrite { path, source } => {
                write!(f, "write signature {}: {source}", path.display())
            }
            Self::Phone(refusal) => write!(f, "phone: {refusal}"),
            Self::PhoneCertificate(error) => write!(f, "phone certificate: {error}"),
            Self::PhoneSignatureCount { expected, got } => write!(
                f,
                "the phone returned {got} signatures for {expected} documents"
            ),
            Self::PhoneSignatureInvalid { document, detail } => write!(
                f,
                "the phone's signature of {} does not verify: {detail}",
                document.as_str()
            ),
            Self::DocumentNameLength => write!(
                f,
                "the document name does not fit the phone's consent display"
            ),
            Self::NoDocuments => f.write_str("no document to sign"),
        }
    }
}

impl core::error::Error for SignErrorKind {}

/// Whose certificate path a [`SignErrorKind::Material`] failure was
/// collected for.
///
/// A timestamp authority's path fails the signing only when it was the
/// sole authority configured: of several, one whose evidence fails is
/// skipped, and losing all of them is a [`SignErrorKind::Timestamp`]
/// that lists each refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterialPath {
    /// The signer certificate's path, up to a pinned root.
    Signer,
    /// The path of the authority that answered for a signature
    /// timestamp, anchored on the certificates its token carries.
    SignatureTimestamp {
        /// The authority's address, as the request named it.
        authority: String,
    },
    /// The path of the authority that answered for the archive
    /// timestamp, anchored on the certificates its token carries.
    ArchiveTimestamp {
        /// The authority's address, as the request named it.
        authority: String,
    },
}

/// Why every signature timestamp authority's answer was lost.
const NO_SIGNATURE_TIMESTAMP: &str = "no timestamp authority produced an acceptable token, so the signature would carry no attested time";
/// Why one signature timestamp token was refused for its evidence.
const SIGNATURE_TIMESTAMP_WITHOUT_EVIDENCE: &str = "returned a cryptographically valid token, but complete current validation evidence for its chain could not be collected";
/// Why every archive timestamp authority's answer was lost.
const NO_ARCHIVE_TIMESTAMP: &str = "no authority produced an acceptable archive timestamp";
/// Why one archive timestamp token was refused for its evidence.
const ARCHIVE_TIMESTAMP_WITHOUT_EVIDENCE: &str =
    "returned an archive timestamp without complete current validation evidence";

/// The one authority a request names, when it names exactly one.
///
/// Its failures are the signing's own: no alternative is left to try.
fn sole_authority(authorities: &[String]) -> Option<&str> {
    match authorities {
        [only] => Some(only.as_str()),
        _ => None,
    }
}

/// Why a timestamp token's own certificate path or its evidence was
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TimestampEvidenceError {
    /// The token embeds no certificate to anchor its path on.
    NoEmbeddedCertificate,
    /// No path verifies within the token's embedded chain.
    EmbeddedPath(MaterialError),
    /// The path's chain or current revocation evidence could not be
    /// collected, or says a certificate on it is revoked.
    Material(MaterialError),
}

impl fmt::Display for TimestampEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEmbeddedCertificate => {
                f.write_str("the token embeds no certificate usable as its chain anchor")
            }
            Self::EmbeddedPath(error) => {
                write!(
                    f,
                    "no valid path within the token's embedded chain: {error}"
                )
            }
            Self::Material(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for TimestampEvidenceError {}

/// Why an archive timestamp token was not selected.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ArchiveTimestampRefusal {
    /// The token's path or its current evidence was refused.
    Evidence(TimestampEvidenceError),
    /// The token's verified path is empty.
    EmptyPath,
    /// A certificate on the token's path is not in the validation
    /// store the token covers.
    PathNotCovered,
}

impl fmt::Display for ArchiveTimestampRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence(error) => write!(f, "{error}"),
            Self::EmptyPath => {
                f.write_str("outer timestamp has an empty authenticated certificate path")
            }
            Self::PathNotCovered => f.write_str(
                "outer timestamp certificate path is not byte-for-byte covered by embedded LT material",
            ),
        }
    }
}

impl core::error::Error for ArchiveTimestampRefusal {}

/// Verify a card's signature over `signed_octets` against the public
/// key of the certificate that names the card's key, before anything
/// built on the signature is finished or written. A local card's
/// signature and a paired phone's go through this one check.
pub(crate) fn verify_against_certificate(
    cert: &Certificate<'_>,
    algorithm: MessageSignatureAlgorithm,
    signed_octets: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    cert.spki
        .verify_message_signature(algorithm, signed_octets, signature)
        .map_err(|e| format!("{e}"))
}

/// Refuse a visible mark on a format other than `PAdES`.
///
/// Runs before PIN verification, so a misplaced mark cannot consume a
/// PIN retry.
pub(crate) fn ensure_visible_signature_format(
    request: &DocumentRequest,
) -> Result<(), SignErrorKind> {
    if request.metadata.visible_signature.is_some() && request.format != Format::Pades {
        return Err(SignErrorKind::VisibleSignatureFormat);
    }
    Ok(())
}

/// Ask a Time Stamp Authority to attest the signature's time.
///
/// The digest goes over the signature value as the format will store
/// it, which [`DocumentPlan::timestamp_digest`] works out; this only
/// carries it there and back.
fn fetch_timestamp(
    url: &str,
    credentials: Option<&TimestampCredentials>,
    retry_transient: bool,
    plan: &DocumentPlan,
    parameters: &SignerParameters<'_>,
    signature: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<VerifiedTimestampToken, SignErrorKind> {
    /// A timestamp token with the TSA's certificate in it. Comfortably
    /// above what any TSA returns, and a bound rather than a promise.
    const MAX_RESPONSE: usize = 64 * 1024;
    /// Nonce width. RFC 3161 sets no size; 64 bits is what the TSA
    /// needs to tell one request from another.
    const NONCE_BYTES: usize = 8;

    // What gets timestamped depends on the format, so the plan is
    // asked rather than assumed.
    let digest = plan
        .timestamp_digest(parameters, signature, algorithm)
        .map_err(SignErrorKind::Document)?;
    let nonce = rng::array::<NONCE_BYTES>()
        .map_err(|e| SignErrorKind::Timestamp(format!("no random nonce: {e}")))?;
    let timestamp_query_der = timestamp::request(&digest, algorithm, Some(&nonce), true);

    let uri =
        Uri::parse(url.to_owned()).map_err(|e| SignErrorKind::Timestamp(format!("{url}: {e}")))?;
    let requested_at = now_date_time();
    let response = post_timestamp_query(
        &uri,
        &timestamp_query_der,
        MAX_RESPONSE,
        credentials,
        retry_transient,
    )
    .map_err(|e| SignErrorKind::Timestamp(format!("POST {url}: {e}")))?;
    let received_at = now_date_time();

    // Bound to this request: the digest we sent and the nonce we drew.
    // Authenticated transport alone would still not prove that a valid
    // old token answered this particular request.
    let token = timestamp::verified_token(&response, &digest, algorithm, Some(&nonce))
        .map_err(|e: TimestampError| SignErrorKind::Timestamp(format!("{e}")))?;
    require_live_timestamp_time(&token, requested_at, received_at)?;
    Ok(token)
}

fn post_timestamp_query(
    uri: &Uri,
    timestamp_query_der: &[u8],
    max_response: usize,
    credentials: Option<&TimestampCredentials>,
    retry_transient: bool,
) -> Result<Vec<u8>, crate::http::HttpError> {
    if !retry_transient {
        return post_timestamp_query_once(uri, timestamp_query_der, max_response, credentials);
    }
    retry_timestamp_query(
        || post_timestamp_query_once(uri, timestamp_query_der, max_response, credentials),
        |attempt, delay, error| {
            eprintln!(
                "timestamp authority temporarily unavailable ({error}); attempt {attempt} of \
                 {TIMESTAMP_RETRY_MAX_ATTEMPTS}, retrying in {} seconds",
                delay.as_secs()
            );
            std::thread::sleep(delay);
        },
    )
}

fn post_timestamp_query_once(
    uri: &Uri,
    timestamp_query_der: &[u8],
    max_response: usize,
    credentials: Option<&TimestampCredentials>,
) -> Result<Vec<u8>, crate::http::HttpError> {
    credentials.map_or_else(
        || {
            crate::http::post_authority(
                uri,
                "application/timestamp-query",
                timestamp_query_der,
                max_response,
                None,
            )
        },
        |credentials| {
            credentials.with_authorization_header(|header| {
                crate::http::post_authority(
                    uri,
                    "application/timestamp-query",
                    timestamp_query_der,
                    max_response,
                    Some(header),
                )
            })
        },
    )
}

/// Repeats `post` on transient authority failures with a doubling delay.
///
/// The loop stops at `TIMESTAMP_RETRY_MAX_ATTEMPTS` attempts or when the
/// next wait would push the accumulated waiting past
/// `TIMESTAMP_RETRY_TOTAL_BUDGET`, whichever comes first, and returns the
/// last transient error unchanged. `wait` receives the number of the
/// attempt that just failed, the delay before the next one, and the
/// error.
fn retry_timestamp_query<T>(
    mut post: impl FnMut() -> Result<T, crate::http::HttpError>,
    mut wait: impl FnMut(u32, core::time::Duration, &crate::http::HttpError),
) -> Result<T, crate::http::HttpError> {
    let mut delay = TIMESTAMP_RETRY_INITIAL_DELAY;
    let mut waited = core::time::Duration::ZERO;
    let mut attempts: u32 = 0;
    loop {
        attempts = attempts.saturating_add(1);
        match post() {
            Ok(response) => return Ok(response),
            Err(error) if error.is_retryable_authority_failure() => {
                let next_waited = waited.saturating_add(delay);
                if attempts >= TIMESTAMP_RETRY_MAX_ATTEMPTS
                    || next_waited > TIMESTAMP_RETRY_TOTAL_BUDGET
                {
                    return Err(error);
                }
                wait(attempts, delay, &error);
                waited = next_waited;
                delay = delay
                    .checked_mul(2)
                    .unwrap_or(TIMESTAMP_RETRY_MAX_DELAY)
                    .min(TIMESTAMP_RETRY_MAX_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

const fn retry_transient_authority_failures(authority_count: usize) -> bool {
    authority_count == 1
}

/// Require a nonce-bound response to describe the exchange that just ran.
fn require_live_timestamp_time(
    token: &VerifiedTimestampToken,
    requested_at: DateTime,
    received_at: DateTime,
) -> Result<(), SignErrorKind> {
    let earliest = requested_at
        .unix_duration()
        .saturating_sub(MAX_TIMESTAMP_CLOCK_SKEW);
    let latest = received_at
        .unix_duration()
        .saturating_add(MAX_TIMESTAMP_CLOCK_SKEW);
    let generated = token.generated_at().unix_duration();
    if generated < earliest || generated > latest {
        return Err(SignErrorKind::Timestamp(format!(
            "authenticated genTime {} is outside this request's clock-skew window",
            token.generated_at()
        )));
    }
    Ok(())
}

struct CollectedTimestamps {
    tokens: Vec<VerifiedTimestampToken>,
    material: ValidationMaterial,
}

/// Obtain and verify every signature timestamp that remains usable.
///
/// Authorities are alternatives: a refused answer is reported and
/// skipped, while loss of every requested answer is fatal. The
/// authority itself is trusted as configured -- whoever names one
/// answers for it. LT/LTA additionally collects chain and current
/// revocation evidence for each retained token, anchored on the
/// certificates the token itself carries.
fn collect_document_timestamps(
    request: &DocumentRequest,
    authorities: &[String],
    plan: &DocumentPlan,
    parameters: &SignerParameters<'_>,
    signature_bytes: &[u8],
) -> Result<CollectedTimestamps, SignErrorKind> {
    let keep_material = request.requires_long_term_material();
    let credentials = request.timestamp_credentials.as_ref();
    let mut tokens = Vec::with_capacity(authorities.len());
    let mut material = ValidationMaterial::default();
    let mut refusals = Vec::new();
    for url in authorities {
        let token = match fetch_timestamp(
            url,
            credentials,
            retry_transient_authority_failures(authorities.len()),
            plan,
            parameters,
            signature_bytes,
            parameters.digest_algorithm,
        ) {
            Ok(token) => token,
            Err(why) => {
                refusals.push(format!("{url}: {why}"));
                continue;
            }
        };
        if keep_material {
            match timestamp_validation_material(&token) {
                Ok(evidence) => merge_material(&mut material, evidence),
                Err(TimestampEvidenceError::Material(error))
                    if sole_authority(authorities).is_some() =>
                {
                    return Err(SignErrorKind::Material {
                        path: MaterialPath::SignatureTimestamp {
                            authority: url.clone(),
                        },
                        error,
                    });
                }
                Err(why) => {
                    refusals.push(format!(
                        "{url}: {SIGNATURE_TIMESTAMP_WITHOUT_EVIDENCE}: {why}"
                    ));
                    continue;
                }
            }
        }
        tokens.push(token);
    }
    if (!authorities.is_empty() || keep_material) && tokens.is_empty() {
        let detail = if refusals.is_empty() {
            "no timestamp authority was configured".to_owned()
        } else {
            refusals.join("; ")
        };
        return Err(SignErrorKind::Timestamp(format!(
            "{NO_SIGNATURE_TIMESTAMP} -- {detail}"
        )));
    }
    for refusal in &refusals {
        eprintln!("timestamp authority declined, continuing without it -- {refusal}");
    }
    Ok(CollectedTimestamps { tokens, material })
}

/// Finish one document from the signature its signer returned: the
/// one path after the private-key operation, whether a card in this
/// computer's reader or the paired phone's card signed.
///
/// The signature has already been verified against `cert`'s public
/// key over [`DocumentPlan::to_be_signed`]. The signer parameters are
/// rebuilt from `cert` exactly as the plan was built, so the finished
/// structure names the digest and algorithm the signature carries.
pub(crate) fn finish_document(
    request: &DocumentRequest,
    plan: DocumentPlan,
    cert: &OwnedCert,
    slot: SignSlot,
    signature_bytes: &[u8],
) -> Result<AssembledDocument, SignErrorKind> {
    let view = cert.view();
    let parameters = document_signer(&view, view.spki.algorithm(), slot, request.signing_time)?;
    assemble_document(request, plan, &parameters, signature_bytes, cert.as_der())
}

/// Fetch the timestamps and evidence a document signature asked for,
/// then assemble it.
///
/// Everything here needs the network and the signature both, so it can
/// only run once the signer has answered; it runs with no card session
/// held.
fn assemble_document(
    request: &DocumentRequest,
    plan: DocumentPlan,
    parameters: &SignerParameters<'_>,
    signature_bytes: &[u8],
    leaf_der: &[u8],
) -> Result<AssembledDocument, SignErrorKind> {
    // The timestamp is over the signature, so it can only be
    // fetched now.
    let authorities = request.timestamp_authorities.as_slice();
    let CollectedTimestamps {
        tokens,
        material: mut timestamp_material,
    } = collect_document_timestamps(request, authorities, &plan, parameters, signature_bytes)?;
    let keep_material = request.requires_long_term_material();
    let material = if keep_material {
        // The tokens go in too, so the store answers for the
        // authorities that attested the time as well as for the
        // signer. The archive timestamp below cannot add new evidence
        // after this store is written without changing the bytes it
        // signs. It must therefore reuse a TSA path already frozen here;
        // selection checks that exact coverage and revalidates current
        // evidence before accepting the outer token. A later archive
        // revision is where refreshed evidence for that token belongs.
        let signer_anchors: Vec<&[u8]> = crate::trust::PINNED_ROOT_DER
            .iter()
            .map(|(_label, der)| *der)
            .collect();
        let reference_time = tokens
            .iter()
            .map(|token| token.generated_at())
            .min()
            .unwrap_or_else(now_date_time);
        let signer_material = crate::material::collect_chains(&[ChainStart {
            leaf_der,
            reference_time,
            anchor: ChainAnchor::Approved(&signer_anchors),
            nonce_policy: NoncePolicy::RequireEcho,
            include_leaf: false,
            include_anchor: true,
        }])
        .map_err(|error| SignErrorKind::Material {
            path: MaterialPath::Signer,
            error,
        })?;
        merge_material(&mut timestamp_material, signer_material);
        timestamp_material
    } else {
        ValidationMaterial::default()
    };
    let token_bytes: Vec<Vec<u8>> = tokens.iter().map(|token| token.token().to_vec()).collect();
    // ASiC-E CAdES archives through a second manifest and a
    // timestamp over it, not through the signature, so it
    // branches here rather than after assembly.
    if request.archive
        && let Some(manifest) =
            plan.archive_manifest(parameters, signature_bytes, parameters.digest_algorithm)
    {
        let digest = parameters.digest_algorithm.digest(&manifest);
        let token = first_answering_token(
            authorities,
            request.timestamp_credentials.as_ref(),
            &digest,
            parameters.digest_algorithm,
            &material,
        )?;
        let archived = plan
            .finish_archived(
                parameters,
                signature_bytes,
                &token_bytes,
                &material,
                &manifest,
                token.token(),
            )
            .map_err(SignErrorKind::Document)?;
        return Ok(AssembledDocument::new(archived, &tokens, true));
    }
    let document = plan
        .finish(parameters, signature_bytes, &token_bytes, &material)
        .map_err(SignErrorKind::Document)?;
    // The archive timestamp goes over the finished document,
    // validation store and all, so it can only be taken once
    // everything else is in place.
    let (bytes, archive_timestamp_obtained) = if request.archive {
        (
            archive_timestamp(
                &document,
                authorities,
                request.timestamp_credentials.as_ref(),
                parameters.digest_algorithm,
                &material,
            )?,
            true,
        )
    } else {
        (document, false)
    };
    Ok(AssembledDocument::new(
        bytes,
        &tokens,
        archive_timestamp_obtained,
    ))
}

/// A finished document and what its timestamps established.
pub(crate) struct AssembledDocument {
    /// The document.
    pub(crate) bytes: Vec<u8>,
    /// Timestamp tokens obtained, the archive timestamp included.
    pub(crate) timestamps: usize,
    /// The earliest validated signature timestamp's `genTime`.
    pub(crate) best_signature_time: Option<BestSignatureTime>,
}

impl AssembledDocument {
    /// `bytes`, timestamped by `signature_timestamps` and, when
    /// `archive_timestamp_obtained`, an archive timestamp.
    fn new(
        bytes: Vec<u8>,
        signature_timestamps: &[VerifiedTimestampToken],
        archive_timestamp_obtained: bool,
    ) -> Self {
        Self {
            bytes,
            timestamps: reported_timestamp_tokens(
                signature_timestamps.len(),
                archive_timestamp_obtained,
            ),
            best_signature_time: BestSignatureTime::of_signature_timestamps(signature_timestamps),
        }
    }
}

fn reported_timestamp_tokens(
    signature_timestamps: usize,
    archive_timestamp_obtained: bool,
) -> usize {
    signature_timestamps.saturating_add(usize::from(archive_timestamp_obtained))
}

/// One RFC 3161 token from one authority, over `digest`.
///
/// The nonce is checked back, so an answer replayed from an earlier
/// exchange is refused rather than accepted as fresh.
fn request_token(
    url: &str,
    credentials: Option<&TimestampCredentials>,
    retry_transient: bool,
    digest: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<VerifiedTimestampToken, SignErrorKind> {
    /// Nonce width, as for the signature timestamps.
    const NONCE_BYTES: usize = 8;
    /// Cap on the authority's answer.
    const MAX_RESPONSE: usize = 64 * 1024;

    let nonce = rng::array::<NONCE_BYTES>()
        .map_err(|e| SignErrorKind::Timestamp(format!("no random nonce: {e}")))?;
    let timestamp_query_der = timestamp::request(digest, algorithm, Some(&nonce), true);
    let uri =
        Uri::parse(url.to_owned()).map_err(|e| SignErrorKind::Timestamp(format!("{url}: {e}")))?;
    let requested_at = now_date_time();
    let response = post_timestamp_query(
        &uri,
        &timestamp_query_der,
        MAX_RESPONSE,
        credentials,
        retry_transient,
    )
    .map_err(|e| SignErrorKind::Timestamp(format!("POST {url}: {e}")))?;
    let received_at = now_date_time();
    let token = timestamp::verified_token(&response, digest, algorithm, Some(&nonce))
        .map_err(|e: TimestampError| SignErrorKind::Timestamp(format!("{e}")))?;
    require_live_timestamp_time(&token, requested_at, received_at)?;
    Ok(token)
}

/// Wrap `pdf` in a `PAdES` document timestamp.
///
/// A further revision whose `/Contents` is an RFC 3161 token over the
/// whole file, this dictionary included. It attests that the signature
/// and the evidence beside it existed intact at a time a third party
/// vouches for -- which is what makes the evidence archivable rather
/// than merely present.
fn archive_timestamp(
    pdf: &[u8],
    urls: &[String],
    credentials: Option<&TimestampCredentials>,
    algorithm: DigestAlgorithm,
    covered_material: &ValidationMaterial,
) -> Result<Vec<u8>, SignErrorKind> {
    /// Room for the token. Generous: a token with the authority's
    /// certificate chain in it runs to a few kilobytes.
    const CAPACITY: usize = 16_384;
    let placeholder = crate::pades::prepare_document_timestamp(pdf, CAPACITY)
        .map_err(|e| SignErrorKind::Document(DocumentError::Pdf(e)))?;
    let token = first_answering_token(
        urls,
        credentials,
        &placeholder.digest(algorithm),
        algorithm,
        covered_material,
    )?;
    placeholder
        .finish(token.token())
        .map_err(|e| SignErrorKind::Document(DocumentError::Pdf(e)))
}

/// A token from the first authority that answers.
///
/// An archive timestamp is one token, not a set: the PDF revision has a
/// single `/Contents` and the `ASiC` archive manifest names a single
/// file. The authorities are tried in the order given, so put the one
/// most trusted first; a refusal moves to the next rather than ending
/// the signing, and only silence from all of them is fatal.
fn first_answering_token(
    urls: &[String],
    credentials: Option<&TimestampCredentials>,
    digest: &[u8],
    algorithm: DigestAlgorithm,
    covered_material: &ValidationMaterial,
) -> Result<VerifiedTimestampToken, SignErrorKind> {
    let mut refusals = Vec::new();
    for url in urls {
        match request_token(
            url,
            credentials,
            retry_transient_authority_failures(urls.len()),
            digest,
            algorithm,
        ) {
            Ok(token) => {
                match authenticate_archive_timestamp(&token, covered_material) {
                    Ok(()) => {}
                    Err(ArchiveTimestampRefusal::Evidence(TimestampEvidenceError::Material(
                        error,
                    ))) if sole_authority(urls).is_some() => {
                        return Err(SignErrorKind::Material {
                            path: MaterialPath::ArchiveTimestamp {
                                authority: url.clone(),
                            },
                            error,
                        });
                    }
                    Err(why) => {
                        refusals.push(format!(
                            "{url} {ARCHIVE_TIMESTAMP_WITHOUT_EVIDENCE} ({why}), trying the next"
                        ));
                        continue;
                    }
                }
                for refusal in &refusals {
                    eprintln!("archive timestamp: {refusal}");
                }
                return Ok(token);
            }
            Err(why) => refusals.push(format!("{url} declined ({why}), trying the next")),
        }
    }
    Err(SignErrorKind::Timestamp(if urls.is_empty() {
        "an archive timestamp needs an authority".to_owned()
    } else {
        format!("{NO_ARCHIVE_TIMESTAMP} -- {}", refusals.join("; "))
    }))
}

/// Prove the outer timestamp has complete current validation evidence
/// before selecting it.
///
/// The returned evidence is deliberately only an acceptance gate. It
/// cannot be embedded in the revision the token signs without changing
/// those signed bytes; a later archive revision is where evidence for
/// the preceding outer timestamp belongs.
fn authenticate_archive_timestamp(
    token: &VerifiedTimestampToken,
    covered_material: &ValidationMaterial,
) -> Result<(), ArchiveTimestampRefusal> {
    authenticate_archive_timestamp_with(token, covered_material, timestamp_validation_material)
}

fn authenticate_archive_timestamp_with<F>(
    token: &VerifiedTimestampToken,
    covered_material: &ValidationMaterial,
    collect_evidence: F,
) -> Result<(), ArchiveTimestampRefusal>
where
    F: FnOnce(&VerifiedTimestampToken) -> Result<ValidationMaterial, TimestampEvidenceError>,
{
    let path = embedded_timestamp_path(token).map_err(ArchiveTimestampRefusal::Evidence)?;
    require_archive_path_covered(&path, covered_material)?;
    let _verified_current_evidence =
        collect_evidence(token).map_err(ArchiveTimestampRefusal::Evidence)?;
    Ok(())
}

/// Require every certificate verified for the outer token to be
/// inside the LT store that token is about to cover.
///
/// Exact DER comparison includes the TSA leaf, intermediates, and the
/// chain's anchor. A signer rotation after the inner signature
/// timestamps were collected therefore moves to the next authority
/// instead of producing an archive whose path is outside its signed
/// validation store.
fn require_archive_path_covered(
    path: &[Vec<u8>],
    covered_material: &ValidationMaterial,
) -> Result<(), ArchiveTimestampRefusal> {
    if path.is_empty() {
        return Err(ArchiveTimestampRefusal::EmptyPath);
    }
    if path
        .iter()
        .all(|certificate| covered_material.certificates.contains(certificate))
    {
        return Ok(());
    }
    Err(ArchiveTimestampRefusal::PathNotCovered)
}

/// The token's certificate path, verified from its signer certificate
/// through the token's embedded certificates to one of them.
///
/// The authority is trusted as configured -- whoever names one answers
/// for it -- so no trusted list or pinned root gates it
/// ([`ChainAnchor::Configured`]). What is still verified is internal
/// consistency: names, signatures, validity windows and roles along
/// the embedded chain.
fn embedded_timestamp_path(
    token: &VerifiedTimestampToken,
) -> Result<Vec<Vec<u8>>, TimestampEvidenceError> {
    let embedded = embedded_certificate_ders(token);
    if embedded.is_empty() {
        return Err(TimestampEvidenceError::NoEmbeddedCertificate);
    }
    crate::material::verify_chain_to_anchor(
        token.signer_certificate().as_der(),
        token.generated_at(),
        ChainAnchor::Configured(&embedded),
        &embedded,
    )
    .map_err(TimestampEvidenceError::EmbeddedPath)
}

/// The certificates the token embeds, as DER.
fn embedded_certificate_ders(token: &VerifiedTimestampToken) -> Vec<&[u8]> {
    token
        .embedded_certificates()
        .iter()
        .map(OwnedCert::as_der)
        .collect()
}

/// Collect chain and current revocation evidence for one token,
/// anchored on the certificates the token itself carries.
///
/// LT and LTA retain the result for their validation store; level T
/// has no store and skips this entirely.
fn timestamp_validation_material(
    token: &VerifiedTimestampToken,
) -> Result<ValidationMaterial, TimestampEvidenceError> {
    let embedded = embedded_certificate_ders(token);
    if embedded.is_empty() {
        return Err(TimestampEvidenceError::NoEmbeddedCertificate);
    }
    crate::material::collect_chains_with_candidates(
        &[ChainStart {
            leaf_der: token.signer_certificate().as_der(),
            reference_time: token.generated_at(),
            anchor: ChainAnchor::Configured(&embedded),
            nonce_policy: NoncePolicy::AllowMissingEcho,
            include_leaf: true,
            include_anchor: true,
        }],
        &embedded,
    )
    .map_err(TimestampEvidenceError::Material)
}

/// Merge independently authenticated evidence without storing the same
/// DER object more than once.
fn merge_material(into: &mut ValidationMaterial, from: ValidationMaterial) {
    merge_unique(&mut into.certificates, from.certificates);
    merge_unique(&mut into.ocsp_responses, from.ocsp_responses);
    merge_unique(&mut into.crls, from.crls);
}

fn merge_unique(into: &mut Vec<Vec<u8>>, from: Vec<Vec<u8>>) {
    for item in from {
        if !into.contains(&item) {
            into.push(item);
        }
    }
}

/// The signer parameters a document signature is built from.
///
/// Digest and signature algorithm are taken from the certificate
/// rather than chosen: the card will sign with the key the
/// certificate names, under the one chain `sign_dispatch_by_alg`
/// drives for that key shape. Naming a different digest here would
/// produce a structure that claims one thing and carries another.
pub(crate) const fn document_signer<'a>(
    cert: &'a Certificate<'a>,
    cert_algorithm: PublicKeyAlgorithm,
    slot: SignSlot,
    signing_time: SigningTime,
) -> Result<SignerParameters<'a>, SignErrorKind> {
    let (digest_algorithm, signature_algorithm) = match cert_algorithm {
        PublicKeyAlgorithm::Rsa { .. } => {
            (DigestAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1Sha256)
        }
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
            (DigestAlgorithm::Sha384, SignatureAlgorithm::EcdsaSha384)
        }
        PublicKeyAlgorithm::Ec(_) | PublicKeyAlgorithm::Other => {
            return Err(SignErrorKind::UnsupportedDocumentKey(slot));
        }
    };
    Ok(SignerParameters {
        certificate: cert,
        digest_algorithm,
        signature_algorithm,
        signing_time: Some(signing_time),
    })
}

/// Read every file the request covers, in the order it named them.
///
/// The primary input is already in memory, so it is reused rather
/// than read twice; a container that signed a file which changed
/// between the two reads would attest something that never existed.
pub(crate) fn load_data_objects(
    input: &Path,
    request: &DocumentRequest,
    input_bytes: &[u8],
) -> Result<Vec<DataObject>, SignErrorKind> {
    let mut objects = vec![data_object(input, input_bytes.to_vec())];
    for path in &request.additional_inputs {
        let content = std::fs::read(path).map_err(|source| SignErrorKind::InputRead {
            path: path.clone(),
            source,
        })?;
        objects.push(data_object(path, content));
    }
    Ok(objects)
}

/// Name and media type for one file inside a container.
///
/// The name is the file name alone: a container entry called
/// `/home/someone/dossier.pdf` would leak a path and break the
/// archive layout both.
fn data_object(path: &Path, content: Vec<u8>) -> DataObject {
    let name = path
        .file_name()
        .map_or_else(|| "file".to_owned(), |n| n.to_string_lossy().into_owned());
    DataObject {
        mime_type: media_type_for(path).to_owned(),
        name,
        content,
    }
}

/// Media type guessed from the extension.
///
/// A guess is all this can be, and it is recorded in the signature,
/// so the fallback is the honest one rather than a plausible one.
fn media_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .as_deref()
    {
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("xml") => "text/xml",
        Some("html" | "htm") => "text/html",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("odt") => "application/vnd.oasis.opendocument.text",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        _ => "application/octet-stream",
    }
}

impl fmt::Display for SignReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.device)?;
        writeln!(f, "key: {}", self.slot.key_label())?;
        if let Some(cn) = &self.cert_subject_cn {
            writeln!(f, "cert subject CN: {cn}")?;
        }
        writeln!(f, "input length: {} bytes", self.input_len)?;
        writeln!(f, "input sha256: {}", self.input_sha256)?;
        writeln!(
            f,
            "output: {} ({} bytes)",
            self.signature_path.display(),
            self.output_len
        )?;
        // Named separately from the file size, which for a document
        // format is the whole document rather than the signature.
        writeln!(f, "card signature: {} bytes", self.signature_len)?;
        // How many tokens were obtained, including the outer archive
        // timestamp. This is deliberately not called an authority
        // count because one authority may issue both kinds of token.
        if self.timestamps > 0 {
            writeln!(f, "timestamp tokens obtained: {}", self.timestamps)?;
        }
        if let Some(p) = &self.cert_path {
            writeln!(f, "cert DER: {}", p.display())?;
        }
        if let Some(r) = self.pin_retries_after {
            writeln!(f, "{} retries after verify: {r}", self.slot.pin_label())?;
        }
        writeln!(
            f,
            "local verify (against on-card {} cert pubkey): {}",
            self.slot.key_label(),
            self.local_verify,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};
    use crate::x509_ext::NameExt as _;

    #[test]
    fn timestamp_credentials_are_encoded_and_redacted() -> TestResult {
        let user = "test-user";
        // Derived fixture password: deterministic for the vector,
        // but not a literal credential a scanner could mistake
        // for a real secret.
        let pass = crate::base64::encode(Sha256::of(b"redaction-fixture").as_bytes());
        let credentials =
            TimestampCredentials::new(user.to_owned(), pass.clone()).map_err(str::to_owned)?;
        let expected_header = format!(
            "Basic {}",
            crate::base64::encode(format!("{user}:{pass}").as_bytes())
        );
        check(
            &credentials.authorization_header().as_str(),
            &expected_header.as_str(),
            "RFC 7617 Basic header",
        )?;
        check_true(
            !format!("{credentials:?}").contains(user)
                && !format!("{credentials:?}").contains(pass.as_str()),
            "credential debug output is redacted",
        )
    }

    #[test]
    fn timestamp_retry_uses_capped_exponential_backoff_until_success() {
        assert!(retry_transient_authority_failures(1));
        assert!(!retry_transient_authority_failures(2));
        let mut attempts = 0_u32;
        let mut delays = Vec::new();
        let token = retry_timestamp_query(
            || {
                attempts = attempts.saturating_add(1);
                if attempts < TIMESTAMP_RETRY_MAX_ATTEMPTS {
                    Err(too_many_requests())
                } else {
                    Ok("timestamp")
                }
            },
            |attempt, delay, _error| delays.push((attempt, delay)),
        )
        .expect("the last permitted attempt succeeds");
        assert_eq!(token, "timestamp");
        assert_eq!(attempts, TIMESTAMP_RETRY_MAX_ATTEMPTS);
        let expected_delays = [1, 2, 4, 8, 16, 32, 60].map(core::time::Duration::from_secs);
        let expected: Vec<_> = (1_u32..).zip(expected_delays).collect();
        assert_eq!(delays, expected);
    }

    fn too_many_requests() -> crate::http::HttpError {
        crate::http::HttpError::HttpStatus {
            code: 429,
            reason: "Too Many Requests".to_owned(),
            location: None,
        }
    }

    fn service_unavailable() -> crate::http::HttpError {
        crate::http::HttpError::HttpStatus {
            code: 503,
            reason: "Service Unavailable".to_owned(),
            location: None,
        }
    }

    #[test]
    fn timestamp_retry_gives_up_after_the_attempt_bound() {
        let mut attempts = 0_u32;
        let mut waits = 0_u32;
        let error = retry_timestamp_query(
            || {
                attempts = attempts.saturating_add(1);
                Err::<(), _>(service_unavailable())
            },
            |_attempt, _delay, _error| waits = waits.saturating_add(1),
        )
        .expect_err("an authority that never answers is reported");
        assert!(matches!(
            error,
            crate::http::HttpError::HttpStatus { code: 503, .. }
        ));
        assert_eq!(attempts, TIMESTAMP_RETRY_MAX_ATTEMPTS);
        assert_eq!(waits, TIMESTAMP_RETRY_MAX_ATTEMPTS - 1);
    }

    #[test]
    fn timestamp_retry_gives_up_when_the_budget_would_be_exceeded() {
        let mut delays = Vec::new();
        retry_timestamp_query(
            || Err::<(), _>(service_unavailable()),
            |_attempt, delay, _error| delays.push(delay),
        )
        .expect_err("an authority that never answers is reported");
        let waited = delays
            .iter()
            .fold(core::time::Duration::ZERO, |sum, delay| {
                sum.saturating_add(*delay)
            });
        assert!(waited <= TIMESTAMP_RETRY_TOTAL_BUDGET);
        assert!(
            delays
                .iter()
                .all(|delay| *delay <= TIMESTAMP_RETRY_MAX_DELAY)
        );
    }

    #[test]
    fn timestamp_retry_does_not_repeat_authentication_failure() {
        let mut attempts = 0_u8;
        let error = retry_timestamp_query(
            || {
                attempts = attempts.saturating_add(1);
                Err::<(), _>(crate::http::HttpError::HttpStatus {
                    code: 401,
                    reason: "Unauthorized".to_owned(),
                    location: None,
                })
            },
            |_attempt, _delay, _error| panic!("permanent failure must not wait"),
        )
        .expect_err("authentication failure is permanent");
        assert!(matches!(
            error,
            crate::http::HttpError::HttpStatus { code: 401, .. }
        ));
        assert_eq!(attempts, 1);
    }

    // ---- LocalVerifyOutcome: is_ok / is_failed keep "rejected"
    // and "not run" distinct, because the CLI maps only Failed to
    // a sign-flow failure. ----

    #[test]
    fn local_verify_predicates_separate_ok_failed_skipped() -> TestResult {
        check_true(LocalVerifyOutcome::Ok.is_ok(), "Ok.is_ok")?;
        check_true(!LocalVerifyOutcome::Ok.is_failed(), "Ok.is_failed")?;

        let failed = LocalVerifyOutcome::Failed("nope".to_owned());
        check_true(!failed.is_ok(), "Failed.is_ok")?;
        check_true(failed.is_failed(), "Failed.is_failed")?;

        let skipped = LocalVerifyOutcome::Skipped("ECDSA verify not wired");
        check_true(!skipped.is_ok(), "Skipped.is_ok")?;
        check_true(!skipped.is_failed(), "Skipped.is_failed")
    }

    #[test]
    fn local_verify_display() -> TestResult {
        check(&LocalVerifyOutcome::Ok.to_string(), &"ok".to_owned(), "ok")?;
        check(
            &LocalVerifyOutcome::Failed("bad sig".to_owned()).to_string(),
            &"FAILED: bad sig".to_owned(),
            "failed",
        )?;
        check(
            &LocalVerifyOutcome::Skipped("p384").to_string(),
            &"skipped (p384)".to_owned(),
            "skipped",
        )
    }

    fn pades_request() -> DocumentRequest {
        DocumentRequest {
            format: Format::Pades,
            additional_inputs: Vec::new(),
            signing_time: SigningTime {
                year: 2026,
                month: 8,
                day: 4,
                hour: 12,
                minute: 0,
                second: 0,
            },
            metadata: SignatureMetadata::default(),
            archive: false,
            long_term: false,
            timestamp_authorities: Vec::new(),
            timestamp_credentials: None,
        }
    }

    #[test]
    fn visible_signature_is_refused_outside_pades() -> TestResult {
        let mut request = pades_request();
        request.metadata.visible_signature = Some(crate::pades::VisibleSignature::verification(
            crate::pades::StampLanguage::Finnish,
        ));
        check_true(
            ensure_visible_signature_format(&request).is_ok(),
            "PAdES carries the visible mark",
        )?;
        request.format = Format::CadesDetached;
        check_true(
            matches!(
                ensure_visible_signature_format(&request),
                Err(SignErrorKind::VisibleSignatureFormat)
            ),
            "a format without a page refuses the visible mark",
        )
    }

    #[test]
    fn archive_request_implies_lt_material_for_direct_api_callers() -> TestResult {
        let mut request = DocumentRequest {
            archive: true,
            ..pades_request()
        };
        check_true(
            request.requires_long_term_material(),
            "archive implies complete LT collection independently of CLI normalization",
        )?;
        check_true(
            request.validate_signing_policy().is_err(),
            "missing archive authority is rejected before card access",
        )?;
        request
            .timestamp_authorities
            .push("https://tsa.example/qualified".to_owned());
        check_true(
            request.validate_signing_policy().is_ok(),
            "archive with authority is normalized to LT",
        )?;
        // Derived fixture password: deterministic for the vector,
        // but not a literal credential a scanner could mistake
        // for a real secret.
        let fixture_pass = crate::base64::encode(Sha256::of(b"policy-fixture").as_bytes());
        request.timestamp_credentials = Some(
            TimestampCredentials::new("user".to_owned(), fixture_pass).map_err(str::to_owned)?,
        );
        check_true(
            request.validate_signing_policy().is_ok(),
            "one HTTPS authority may carry credentials",
        )?;
        request.timestamp_authorities[0] = "http://tsa.example/qualified".to_owned();
        check_true(
            request.validate_signing_policy().is_err(),
            "credential transport is rejected before card access",
        )?;
        request.timestamp_authorities[0] = "https://tsa.example/qualified".to_owned();
        request.timestamp_credentials = None;
        request.format = Format::Cades;
        check_true(
            matches!(
                request.validate_signing_policy(),
                Err(SignErrorKind::Document(DocumentError::ArchiveUnsupported))
            ),
            "unsupported archive format rejected before card access",
        )
    }

    #[test]
    fn successful_archive_timestamp_is_included_in_reported_token_count() -> TestResult {
        check(
            &reported_timestamp_tokens(2, true),
            &3_usize,
            "two signature timestamps and one archive timestamp",
        )?;
        check(
            &reported_timestamp_tokens(2, false),
            &2_usize,
            "signature timestamps without archive",
        )
    }

    fn self_anchored_token_fixture() -> Result<VerifiedTimestampToken, Box<dyn core::error::Error>>
    {
        let signer_der = crate::trust::PINNED_TSA_ROOT_DER
            .first()
            .map(|(_label, der)| *der)
            .ok_or("missing test trust anchor")?;
        let signer = OwnedCert::from_der(signer_der)?;
        let generated_at = signer.view().not_before;
        Ok(VerifiedTimestampToken::from_parts_for_test(
            vec![1],
            signer.clone(),
            vec![signer.clone()],
            generated_at,
        ))
    }

    #[test]
    fn embedded_path_terminates_at_the_tokens_self_issued_certificate() -> TestResult {
        let token = self_anchored_token_fixture()?;
        let path = embedded_timestamp_path(&token)?;
        check(
            &path,
            &vec![token.signer_certificate().as_der().to_vec()],
            "the embedded self-issued signer terminates the path",
        )
    }

    #[test]
    fn sectigo_timestamp_path_runs_as_deep_as_the_token_embeds() -> TestResult {
        const SECTIGO_TEST_VALIDITY_INSTANT: u64 = 1_700_000_000;
        let signer_der =
            include_bytes!("../test-vectors/sectigo-qualified-tsa-signer-3.der").to_vec();
        let ca_der = include_bytes!("../test-vectors/sectigo-qualified-tsa-ca-r35.der").to_vec();
        let root_der = crate::trust::PINNED_TSA_ROOT_DER
            .first()
            .ok_or("pinned TSA root missing")?
            .1;
        let signer = OwnedCert::from_der(&signer_der)?;
        let ca = OwnedCert::from_der(&ca_der)?;
        let root = OwnedCert::from_der(root_der)?;
        let generated_at = DateTime::from_unix_duration(core::time::Duration::from_secs(
            SECTIGO_TEST_VALIDITY_INSTANT,
        ))?;
        let token = VerifiedTimestampToken::from_parts_for_test(
            vec![1],
            signer.clone(),
            vec![signer.clone(), ca.clone()],
            generated_at,
        );
        check(
            &embedded_timestamp_path(&token)?,
            &vec![signer_der.clone(), ca_der.clone()],
            "without an embedded root the path stops at the embedded CA",
        )?;
        let token = VerifiedTimestampToken::from_parts_for_test(
            vec![1],
            signer.clone(),
            vec![signer, ca, root],
            generated_at,
        );
        check(
            &embedded_timestamp_path(&token)?,
            &vec![signer_der, ca_der, root_der.to_vec()],
            "an embedded self-issued root ends the path",
        )
    }

    #[test]
    fn archive_rejects_a_token_without_current_complete_evidence() -> TestResult {
        let token = self_anchored_token_fixture()?;
        let covered_material = ValidationMaterial {
            certificates: vec![token.signer_certificate().as_der().to_vec()],
            ..ValidationMaterial::default()
        };
        let unavailable =
            MaterialError::Revocation("current validation evidence unavailable".to_owned());
        let error = authenticate_archive_timestamp_with(&token, &covered_material, |_token| {
            Err(TimestampEvidenceError::Material(unavailable.clone()))
        })
        .err()
        .ok_or("archive token unexpectedly survived missing validation evidence")?;
        check(
            &error,
            &ArchiveTimestampRefusal::Evidence(TimestampEvidenceError::Material(unavailable)),
            "archive evidence failure",
        )
    }

    #[test]
    fn archive_path_must_be_frozen_in_the_covered_lt_store() -> TestResult {
        let leaf = b"archive-tsa-leaf".to_vec();
        let identity = b"archive-tsa-service-identity".to_vec();
        let covered_material = ValidationMaterial {
            certificates: vec![leaf.clone(), identity.clone()],
            ..ValidationMaterial::default()
        };
        check(
            &require_archive_path_covered(&[leaf, identity.clone()], &covered_material),
            &Ok(()),
            "covered archive path",
        )?;

        let rotated = b"rotated-archive-tsa-leaf".to_vec();
        let error = require_archive_path_covered(&[rotated, identity], &covered_material)
            .err()
            .ok_or("rotated outer timestamp path unexpectedly passed LT coverage")?;
        check(
            &error,
            &ArchiveTimestampRefusal::PathNotCovered,
            "rotated path is rejected",
        )
    }

    #[test]
    fn validation_material_merge_deduplicates_each_der_collection() -> TestResult {
        let mut material = ValidationMaterial {
            certificates: vec![vec![1]],
            ocsp_responses: vec![vec![2]],
            crls: vec![vec![3]],
        };
        merge_material(
            &mut material,
            ValidationMaterial {
                certificates: vec![vec![1], vec![4]],
                ocsp_responses: vec![vec![2], vec![5]],
                crls: vec![vec![3], vec![6]],
            },
        );
        check(
            &material,
            &ValidationMaterial {
                certificates: vec![vec![1], vec![4]],
                ocsp_responses: vec![vec![2], vec![5]],
                crls: vec![vec![3], vec![6]],
            },
            "merged material",
        )
    }

    #[test]
    fn live_timestamp_time_is_bounded_by_the_exchange() -> TestResult {
        let requested_at =
            DateTime::from_unix_duration(core::time::Duration::from_secs(1_700_000_000))?;
        let received_at =
            DateTime::from_unix_duration(core::time::Duration::from_secs(1_700_000_030))?;
        let signer = self_anchored_token_fixture()?.signer_certificate().clone();
        let token_at = |seconds| -> Result<VerifiedTimestampToken, Box<dyn core::error::Error>> {
            Ok(VerifiedTimestampToken::from_parts_for_test(
                Vec::new(),
                signer.clone(),
                Vec::new(),
                DateTime::from_unix_duration(core::time::Duration::from_secs(seconds))?,
            ))
        };

        require_live_timestamp_time(&token_at(1_699_999_700)?, requested_at, received_at)?;
        require_live_timestamp_time(&token_at(1_700_000_330)?, requested_at, received_at)?;
        check_true(
            require_live_timestamp_time(&token_at(1_699_999_699)?, requested_at, received_at)
                .is_err(),
            "materially backdated token rejected",
        )?;
        check_true(
            require_live_timestamp_time(&token_at(1_700_000_331)?, requested_at, received_at)
                .is_err(),
            "future token rejected",
        )
    }

    #[test]
    #[ignore = "needs the live Sectigo qualified timestamp service"]
    fn live_sectigo_timestamp_response_verifies_directly() -> TestResult {
        let digest = DigestAlgorithm::Sha384.digest(b"RefineID Sectigo interoperability probe");
        let token = request_token(
            "http://timestamp.sectigo.com/qualified",
            None,
            false,
            &digest,
            DigestAlgorithm::Sha384,
        )?;
        check_true(!token.token().is_empty(), "timestamp token returned")?;
        check_true(
            !token.signer_certificate().as_der().is_empty(),
            "timestamp signer certificate authenticated",
        )?;
        check_true(
            token.embedded_certificates().len() >= 2,
            "timestamp signer chain retained",
        )?;
        let path = embedded_timestamp_path(&token)?;
        check_true(!path.is_empty(), "timestamp path verified")?;
        let material = timestamp_validation_material(&token)?;
        check_true(
            !material.certificates.is_empty(),
            "timestamp path and LT evidence collected",
        )
    }

    #[test]
    #[ignore = "needs live timestamp authorities and revocation services"]
    fn live_qualified_timestamp_and_lt_evidence_probe() -> TestResult {
        let digest = [0_u8; 32];
        let mut successes = 0_usize;
        let mut failures = Vec::new();
        for url in [DEFAULT_TIMESTAMP_AUTHORITY] {
            let token = match request_token(url, None, false, &digest, DigestAlgorithm::Sha256) {
                Ok(token) => token,
                Err(error) => {
                    failures.push(format!("{url}: {error}"));
                    continue;
                }
            };
            if let Err(error) = embedded_timestamp_path(&token) {
                failures.push(format!("{url}: path: {error}"));
                continue;
            }
            match timestamp_validation_material(&token) {
                Ok(material) if !material.certificates.is_empty() => {
                    successes = successes.saturating_add(1);
                }
                Ok(_empty) => failures.push(format!("{url}: LT material was empty")),
                Err(error) => failures.push(format!("{url}: LT evidence: {error}")),
            }
        }
        for failure in &failures {
            eprintln!("{failure}");
        }
        check_true(
            successes > 0,
            "at least one configured authority produced a token with complete LT evidence",
        )
    }

    #[test]
    fn material_display_names_the_path() -> TestResult {
        let error = MaterialError::Revocation("responder unreachable".to_owned());
        let authority = "https://tsa.example".to_owned();
        let material = |path| SignErrorKind::Material {
            path,
            error: error.clone(),
        };
        check(
            &material(MaterialPath::Signer).to_string(),
            &"validation material: signer path: revocation: responder unreachable".to_owned(),
            "signer path",
        )?;
        check(
            &material(MaterialPath::SignatureTimestamp {
                authority: authority.clone(),
            })
            .to_string(),
            &format!(
                "timestamp: {NO_SIGNATURE_TIMESTAMP} -- {authority}: {SIGNATURE_TIMESTAMP_WITHOUT_EVIDENCE}: revocation: responder unreachable"
            ),
            "signature timestamp path",
        )?;
        check(
            &material(MaterialPath::ArchiveTimestamp {
                authority: authority.clone(),
            })
            .to_string(),
            &format!(
                "timestamp: {NO_ARCHIVE_TIMESTAMP} -- {authority} {ARCHIVE_TIMESTAMP_WITHOUT_EVIDENCE} (revocation: responder unreachable), trying the next"
            ),
            "archive timestamp path",
        )
    }

    #[test]
    fn io_error_display_includes_path() -> TestResult {
        let err = SignErrorKind::InputRead {
            path: PathBuf::from("/tmp/msg"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        };
        let s = err.to_string();
        check_true(s.contains("/tmp/msg"), "io error path")?;
        check_true(s.contains("no such file"), "io error source")
    }

    // ---- SignReport Display ----

    fn sample_report(cn: Option<CommonName>) -> SignReport {
        SignReport {
            device: SigningDevice::Reader("OMNIKEY 5422".to_owned()),
            slot: SignSlot::Qualified,
            input_len: 11,
            input_sha256: Sha256::of(b"hello world"),
            signature_path: PathBuf::from("/tmp/out.sig"),
            cert_path: Some(PathBuf::from("/tmp/out.crt")),
            signature_len: 384,
            timestamps: 0,
            best_signature_time: None,
            output_len: 384,
            cert_subject_cn: cn,
            pin_retries_after: None,
            local_verify: LocalVerifyOutcome::Ok,
        }
    }

    #[test]
    fn sign_report_display_renders_all_present_fields() -> TestResult {
        // Pull a real CommonName off a bundled cert rather than
        // constructing one (the field is private to lib-core).
        let cert = OwnedCert::from_der(
            include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der").as_slice(),
        )
        .map_err(|e| format!("parse anchor: {e}"))?;
        let cn = cert.view().subject.common_name();
        check_true(cn.is_some(), "anchor has a CN")?;

        let s = sample_report(cn).to_string();
        check_true(s.contains("reader: OMNIKEY 5422"), "reader line")?;
        check_true(s.contains("key: qualified-signature"), "key line")?;
        check_true(s.contains("cert subject CN: DVV"), "subject cn line")?;
        check_true(s.contains("input length: 11 bytes"), "input length")?;
        check_true(s.contains("input sha256: "), "input sha256")?;
        check_true(
            s.contains("output: /tmp/out.sig (384 bytes)"),
            "output line",
        )?;
        check_true(
            s.contains("card signature: 384 bytes"),
            "card signature line",
        )?;
        check_true(s.contains("cert DER: /tmp/out.crt"), "cert der line")?;
        check_true(
            s.contains("local verify (against on-card qualified-signature cert pubkey): ok"),
            "local verify line",
        )
    }

    #[test]
    fn sign_report_labels_timestamp_tokens_without_calling_them_authorities() -> TestResult {
        let mut report = sample_report(None);
        report.timestamps = 2;
        let rendered = report.to_string();
        check_true(
            rendered.contains("timestamp tokens obtained: 2"),
            "inner and archive token count",
        )?;
        check_true(
            !rendered.contains("timestamp authorities"),
            "token count is not mislabeled as distinct authorities",
        )
    }

    #[test]
    fn sign_report_display_omits_absent_optionals() -> TestResult {
        // No CN, no saved cert, no retry counter -> those lines
        // are skipped entirely.
        let s = sample_report(None).to_string();
        check_true(!s.contains("cert subject CN:"), "no cn line")?;
        // cert_path is Some in sample_report; flip it for this case.
        let mut report = sample_report(None);
        report.cert_path = None;
        let s2 = report.to_string();
        check_true(!s2.contains("cert DER:"), "no cert der line")?;
        check_true(!s2.contains("retries after verify"), "no retry line")
    }

    #[test]
    fn each_slot_names_its_own_pin() -> TestResult {
        check(
            &SignSlot::Authentication.pin_role(),
            &PinRole::Pin1,
            "auth PIN",
        )?;
        check(&SignSlot::Qualified.pin_role(), &PinRole::Pin2, "sign PIN")
    }

    // ---- Output: a default name never replaces a file. ----

    fn pending_name(
        dir: &std::path::Path,
    ) -> Result<PendingSignedName, Box<dyn core::error::Error>> {
        Ok(PendingSignedName::new(
            vec![dir.join("report.pdf")],
            Format::Pades,
            crate::testkit::day(1),
        ))
    }

    #[test]
    fn a_default_name_never_replaces_an_existing_file() -> TestResult {
        let dir = crate::test_util::TempDir::new("signed-name-taken")?;
        let output = SignOutput::SignedName(pending_name(dir.path())?);
        let taken = output.path(None);
        std::fs::write(&taken, b"earlier")?;
        let refused = output.write(None, b"signed");
        check_true(
            matches!(
                &refused,
                Err(SignErrorKind::SignatureWrite { path, source })
                    if *path == taken && source.kind() == std::io::ErrorKind::AlreadyExists
            ),
            "refused",
        )?;
        check(
            &std::fs::read(&taken)?,
            &b"earlier".to_vec(),
            "left as it was",
        )
    }

    #[test]
    fn a_default_name_is_written_when_free_and_a_given_path_is_replaced() -> TestResult {
        let dir = crate::test_util::TempDir::new("signed-name-free")?;
        let output = SignOutput::SignedName(pending_name(dir.path())?);
        let written = output.write(None, b"signed")?;
        check(&written, &output.path(None), "the default name")?;
        check(&std::fs::read(&written)?, &b"signed".to_vec(), "written")?;
        let given = SignOutput::At(written.clone());
        check(&given.write(None, b"again")?, &written, "the given path")?;
        check(&std::fs::read(&written)?, &b"again".to_vec(), "replaced")
    }
}
