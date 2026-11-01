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

//! `refineid card sign-auth` + `refineid card sign-qualified`.
//!
//! SHA-256 the input file, VERIFY the appropriate PIN, drive the
//! SHA-256+RSA-PKCS1v15 sign chain against the chosen FINEID key
//! slot, write the raw 384-byte RSA signature to disk, and
//! locally verify it against the public key in the on-card cert.
//!
//! - `sign-auth`: VERIFY PIN1, sign with the **auth key** (key
//!   ref `0x01`), verify against the EF.4331 cert.
//! - `sign-qualified`: VERIFY PIN2, sign with the **qualified-
//!   signature key** (key ref `0x02`), verify against the
//!   EF.4332 cert. PIN2 has a 6-digit floor (FINEID S1 v4.2 §3.5).
//!
//! Both paths share the same option / report / error types and a
//! shared internal driver (`sign_qualified`) so the wire
//! choreography stays in lockstep.

use core::fmt;
use std::path::PathBuf;

use crate::asic::DataObject;
use crate::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime};
use crate::digest::Sha256;
use crate::document::{self, DocumentError, DocumentPlan, Format};
use crate::identity::{CommonName, TokenSerial, render_token_serial};
use crate::pades::SignatureMetadata;
use crate::pin::{PinBytes, PinEntryError, PinPolicyReason, PinRole, PinSource};
use crate::rng;
use crate::signed_name::{BestSignatureTime, PendingSignedName};
use crate::timestamp::{self, TimestampError, VerifiedTimestampToken};
use crate::uri::{Scheme, Uri};
use crate::validation::ValidationMaterial;
use crate::x509_ext::NameExt;
use refineid_apdu::command::{
    CommandHeader, CredentialBody, CredentialCommand, UnvalidatedCredentialBlock,
};
use refineid_apdu::status_word::StatusWord;
use refineid_apdu::{ApduClass, CardTransport};
use refineid_auth::{
    PinOps as _, PinReferenceScheme, PinSlot, RetryFloorRefusal, VerifyOutcome, check_retry_floor,
    classify_verify_sw,
};
use refineid_cms::x509::{
    Certificate, DateTime, EcCurve, MessageSignatureAlgorithm, OwnedCert, PublicKeyAlgorithm,
};
use refineid_digest::Sha384 as CoreSha384;
use refineid_pace::{self, Can, PaceError, SmTransport, run_pace_with_can};
use refineid_pcsc::{
    PcscCard, PcscError, PcscTransactionCard, ReaderAccessCap, ReaderBackend,
    ReaderBackendOps as _, ReaderFilter, ReaderPickError,
};
use refineid_pkcs15::Pkcs15Ops as _;
use refineid_pkcs15::{CertSlot, Pkcs15Error, UnvalidatedCertificate};
use refineid_sign::{KeyRef, SignError, SignOps as _, SignScheme};
use zeroize::Zeroizing;

use crate::material::{ChainAnchor, ChainStart, NoncePolicy, now_date_time};

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
    /// The key reference `MSE:SET DST` names for the key; a report's
    /// [`SignReport::slot`] gives the one it signed with.
    #[must_use]
    pub const fn key_ref(self) -> KeyRef {
        match self {
            Self::Authentication => KeyRef::Auth,
            Self::Qualified => KeyRef::Sign,
        }
    }

    /// The PIN that gates the key.
    const fn pin_slot(self) -> PinSlot {
        match self {
            Self::Authentication => PinSlot::Pin1,
            Self::Qualified => PinSlot::Pin2,
        }
    }

    /// The certificate whose public key pairs with the key, read once
    /// at session start and reused by the local verify.
    const fn cert_slot(self) -> CertSlot {
        match self {
            Self::Authentication => CertSlot::Authentication,
            Self::Qualified => CertSlot::Signature,
        }
    }

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

/// Why the flow refuses to VERIFY when the card in the reader after the
/// PIN prompt is not the card checked before it.
pub const CARD_CHANGED_DURING_PROMPT: &str = "the card changed while the PIN was entered";

/// A document signature rather than a bare one.
///
/// Present in [`SignOptions`] when the operator asked for a format
/// rather than raw signature bytes. The difference reaches all the way
/// into the card session: a document signature covers a structure that
/// names the signing certificate, so it cannot be built until the
/// certificate has been read off the card.
#[derive(Debug, Clone)]
pub struct DocumentRequest {
    /// Which format to produce.
    pub format: Format,
    /// Files beyond [`SignOptions::input`]. Only the container formats
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
    /// Full PKCS#15 serial of the card the operator was shown, when a
    /// trusted inspection view captured one. Verified against the live
    /// card before PIN verification, whatever the format, so a card
    /// swap cannot spend the PIN on an undisplayed identity. `None`
    /// only for flows that sign whichever card is present (the CLI).
    pub expected_serial: Option<TokenSerial>,
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
    fn validate_signing_policy(&self) -> Result<(), SignErrorKind> {
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

/// Inputs.
#[derive(Debug)]
pub struct SignOptions {
    /// Filesystem path to the message bytes to sign. Loaded
    /// whole-file; the SHA-256 hash is computed inside refineid
    /// and sent to the card via `PSO:HASH` per FINEID S1
    /// v4.2 §3.5.
    pub input: PathBuf,
    /// Where the raw signature, or the finished document when
    /// [`Self::document`] is set, is written.
    pub output: SignOutput,
    /// Which key signs.
    pub slot: SignSlot,
    /// Optional output path for the DER bytes of the on-card cert
    /// that produced the signature. Pairs the signature with the
    /// cert it can be verified against -- enables offline
    /// third-party verify with no card.
    pub save_cert: Option<PathBuf>,
    /// Optional substring match against reader names. Required
    /// when more than one card is present; the picker errors
    /// out rather than guess.
    pub reader_filter: Option<String>,
    /// Card Access Number for the contactless interface, where
    /// the card seals PKCS#15 behind PACE. `None` on the contact
    /// interface. When the seal is hit and this is `None`, the
    /// flow fails with [`SignErrorKind::NeedCan`] so the CLI can
    /// prompt and retry. Never logged.
    pub can: Option<Can>,
    /// Produce a signed document rather than raw signature bytes.
    ///
    /// `None` keeps the original behaviour: `--out` receives the
    /// signature the card computed over the input file, and nothing
    /// else.
    pub document: Option<DocumentRequest>,
}

/// Where [`SignOptions`] writes its result.
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
    fn write(
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

/// One reader's worth of sign output.
#[derive(Debug, Clone)]
pub struct SignReport {
    /// PC/SC reader name the sign APDU chain landed against.
    /// Tier 0 `String` from `ReaderId::as_str().to_owned()`.
    pub reader: String,
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

/// Error returned from the sign entrypoints.
///
/// Card-side outcomes that don't preclude further action
/// (wrong-PIN with retries left, etc.) are folded into
/// `PinRejected`; cryptographic and transport failures use
/// the per-stage variants.
#[derive(Debug)]
pub enum SignErrorKind {
    /// Reader-selection failure (none / multiple / bad filter).
    ReaderPick(ReaderPickError),
    /// The requested document format could not be built. Raised
    /// before the card signs anything, except for the PDF
    /// "signature did not fit" case, which is only knowable after.
    Document(DocumentError),
    /// A visible signature was asked of a format other than `PAdES`;
    /// refused before PIN verification.
    VisibleSignatureFormat,
    /// The live card is not the card the operator was shown; refused
    /// before PIN verification.
    DisplayedCard(String),
    /// The slot's certificate uses a key this crate can build a
    /// document signature with, but whose digest pairing is not one
    /// the formats name.
    UnsupportedDocumentKey(SignSlot),
    /// The chain or revocation answers could not be collected.
    ///
    /// Raised rather than falling back to a shorter-lived signature: a
    /// caller who asked for LT and silently got T would not be able to
    /// tell from the output.
    Material(String),
    /// The Time Stamp Authority could not be reached or refused.
    ///
    /// Raised rather than silently dropping the token: a caller who
    /// asked for an attested time and got a claimed one would not be
    /// able to tell from the output.
    Timestamp(String),
    /// PC/SC connect / transmit error.
    Pcsc(PcscError),
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
    /// VERIFY of the slot's PIN returned a non-Ok outcome.
    PinRejected {
        /// Which key's PIN the VERIFY targeted.
        slot: SignSlot,
        /// Card-side outcome (`WrongPin{retries}`, `Locked`,
        /// `AuthenticationFailed`, ...).
        outcome: VerifyOutcome,
    },
    /// The card's retry counter for the slot's PIN is at or below the
    /// shared retry floor, blocked, or unreadable, so no VERIFY was
    /// sent. The counter is unaffected.
    RetryFloor(RetryFloorRefusal),
    /// The PIN entry produced no PIN; nothing was sent to the card.
    PinEntry(PinEntryError),
    /// Local-policy rejection (PIN length / non-digit) before any
    /// APDU went out. Counter is unaffected.
    PinPolicy {
        /// Which key's PIN was refused.
        slot: SignSlot,
        /// Specific local-policy failure (e.g. `TooShort`,
        /// `NonDigit`).
        reason: PinPolicyReason,
    },
    /// Card returned an unexpected status word at one of the
    /// sign-chain stages.
    SignSw {
        /// Pipeline stage label (e.g. "MSE:SET DST",
        /// "PSO:HASH", "PSO:Compute Digital Signature"). Tier 0
        /// `&'static str` from a fixed compile-time set.
        stage: &'static str,
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        /// Tier 0 `u16` -- the typed projection is `StatusWord`
        /// from `lib-core::apdu`; this field carries the raw
        /// wire value for the diagnostic.
        sw: u16,
    },
    /// Card returned a signature with the wrong length (e.g. an
    /// ECDSA card on this RSA-pinned path).
    UnexpectedSignatureLength(usize),
    /// Signing input cannot be represented by the card command.
    InputTooLong(usize),
    /// The on-card cert is missing or unparseable.
    CertUnavailable {
        /// Which key's certificate was read.
        slot: SignSlot,
        /// Human-readable detail from the cert reader / parser.
        /// Tier 0 `String`; presentational.
        detail: String,
    },
    /// Cert was readable but its public key type is not supported
    /// (not RSA, not ECDSA P-384, or uses explicit EC params).
    UnsupportedKeyType(SignSlot),
    /// Cert carries an EC key on a curve other than secp384r1.
    /// The Newer-scheme sign chain handles only secp384r1 + SHA-384
    /// (S4-1 v4.2 §4.2); the other supported curve OIDs land here
    /// rather than at the wire layer where the card would reject
    /// the algRef byte.
    UnsupportedCurve {
        /// Which key's certificate carried the curve.
        slot: SignSlot,
        /// Curve the cert was issued on.
        curve: EcCurve,
    },
    /// Cert + signature parsed but local PKCS1v15-SHA256 verify
    /// failed -- card returned a signature that doesn't match the
    /// on-card public key over our input.
    LocalVerifyFailed(String),
    /// Lower-level transport / APDU failure not covered by the
    /// per-stage variants. Tier 0 `String`; presentational copy
    /// of the upstream error.
    Transport(String),
    /// The card sealed PKCS#15 behind PACE (contactless
    /// interface) and no CAN was provided to open it.
    NeedCan,
    /// PACE failed with the wrong-CAN signature: card-reported
    /// authentication failure or a mutual-auth tag mismatch.
    BadCan,
    /// PACE establishment failed for a non-CAN reason. Tier 0
    /// `String`; presentational copy of the upstream error.
    Pace(String),
}

impl fmt::Display for SignErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
            Self::PinEntry(error) => write!(f, "{error}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::Document(e) => write!(f, "{e}"),
            Self::VisibleSignatureFormat => {
                f.write_str("visible signature: supported only for PAdES")
            }
            Self::DisplayedCard(detail) => write!(f, "displayed card: {detail}"),
            Self::Material(detail) => write!(f, "validation material: {detail}"),
            Self::Timestamp(detail) => write!(f, "timestamp: {detail}"),
            Self::UnsupportedDocumentKey(slot) => write!(
                f,
                "the {} certificate's key type cannot produce a document signature",
                slot.key_label()
            ),
            Self::InputRead { path, source } => {
                write!(f, "read input {}: {source}", path.display())
            }
            Self::SignatureWrite { path, source } => {
                write!(f, "write signature {}: {source}", path.display())
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::WrongPin { retries_left },
            } => {
                write!(
                    f,
                    "{} rejected (wrong PIN, {retries_left} retries left)",
                    slot.pin_label()
                )
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::Locked,
            } => {
                write!(
                    f,
                    "{} is blocked -- card needs a PUK unblock",
                    slot.pin_label()
                )
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::Other(sw),
            } => {
                let sw_val = sw.as_u16();
                write!(
                    f,
                    "{} verify: unexpected SW={sw_val:#06X}",
                    slot.pin_label()
                )
            }
            Self::PinRejected {
                outcome: VerifyOutcome::Ok,
                ..
            } => write!(f, "internal: PinRejected(Ok) is not an error state"),
            Self::PinPolicy { slot, reason } => {
                write!(f, "{} rejected locally: {reason}", slot.pin_label())
            }
            Self::SignSw { stage, sw } => {
                write!(f, "sign chain failed at {stage}: SW={sw:#06X}")
            }
            Self::UnexpectedSignatureLength(n) => {
                write!(
                    f,
                    "card returned {n}-byte signature; expected 384 (RSA-3072)"
                )
            }
            Self::InputTooLong(n) => {
                write!(f, "{n}-byte signing input exceeds the card command length")
            }
            Self::CertUnavailable { slot, detail } => {
                write!(
                    f,
                    "{} cert unavailable for local verify: {detail}",
                    slot.key_label()
                )
            }
            Self::UnsupportedKeyType(slot) => {
                write!(
                    f,
                    "{} cert has an unsupported key type (not RSA, not ECDSA P-384, or explicit EC params)",
                    slot.key_label()
                )
            }
            Self::UnsupportedCurve { slot, curve } => {
                write!(
                    f,
                    "{} cert is EC on {} ({}-bit); refineid currently only signs ECDSA on secp384r1",
                    slot.key_label(),
                    curve.label(),
                    curve.bits()
                )
            }
            Self::LocalVerifyFailed(s) => write!(f, "local verify failed: {s}"),
            Self::Transport(s) => write!(f, "transport: {s}"),
            Self::NeedCan => write!(
                f,
                "contactless card: the PKCS#15 application is sealed behind \
                 PACE; provide the CAN (six digits printed on the card front) \
                 via --can or the prompt"
            ),
            Self::BadCan => write!(f, "PACE failed: the CAN did not match the card"),
            Self::Pace(s) => write!(f, "PACE: {s}"),
        }
    }
}

impl core::error::Error for SignErrorKind {}

impl From<PcscError> for SignErrorKind {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for SignErrorKind {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// Drive the sign chain for `slot` on the first reader with a
/// card. `options` is taken by value so the embedded
/// [`PinBytes`] drops (and zeroes) when this function returns,
/// regardless of branch.
///
/// # Errors
/// PC/SC enumeration / connect failure, PIN policy / verify
/// failure, sign-chain SW failure, signature-length mismatch,
/// cert read or parse failure, local-verify failure, or
/// input / output I/O failure.
// sign_with_slot is a flat sequence of open -> read input -> hash
// -> read cert -> VERIFY PIN -> sign chain -> local verify ->
// write. Splitting into helpers would just shuttle locals across
// boundaries; the body reads top-to-bottom as one operation.
/// Organizational PIN minimum length (S4-2 v4.0 §4.2).
const ORGANIZATIONAL_PIN_MIN_LENGTH: usize = 4;
/// Organizational PIN stored (padded) length.
const ORGANIZATIONAL_PIN_STORED_LENGTH: usize = 8;

/// Organizational length window plus ASCII-digit shape. A
/// rejection here doesn't burn a card-side retry counter slot.
fn validate_org_pin_policy(slot: SignSlot, ascii: &[u8]) -> Result<(), SignErrorKind> {
    if ascii.len() < ORGANIZATIONAL_PIN_MIN_LENGTH || ascii.len() > ORGANIZATIONAL_PIN_STORED_LENGTH
    {
        return Err(SignErrorKind::PinPolicy {
            slot,
            reason: PinPolicyReason::WrongLength {
                min: ORGANIZATIONAL_PIN_MIN_LENGTH,
                max: ORGANIZATIONAL_PIN_STORED_LENGTH,
            },
        });
    }
    if ascii.iter().any(|b| !b.is_ascii_digit()) {
        return Err(SignErrorKind::PinPolicy {
            slot,
            reason: PinPolicyReason::NonDigit,
        });
    }
    Ok(())
}

/// Ask the card which reference numbering it speaks.
///
/// A VERIFY status probe against an absent reference answers
/// `SW=6A88` without touching any retry counter, so the probe
/// costs one command and no risk.
fn resolve_pin_reference_scheme<T: CardTransport>(
    transport: &mut T,
) -> Result<PinReferenceScheme, SignErrorKind> {
    transport
        .resolve_pin_reference_scheme()
        .map_err(|e| SignErrorKind::Transport(format!("{e}")))
}

/// VERIFY `pin` for `slot` under the resolved `scheme`.
///
/// The citizen path sends 12-byte padded credential command;
/// the organizational path sends unpadded digits capped at 8 bytes.
fn verify_pin_with_scheme<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    scheme: PinReferenceScheme,
    pin: &PinBytes,
) -> Result<VerifyOutcome, SignErrorKind> {
    let digits = pin.as_bytes();
    if scheme == PinReferenceScheme::Organizational {
        validate_org_pin_policy(slot, digits)?;
    }
    let header = CommandHeader {
        class: ApduClass::Plain,
        instruction: 0x20, // INS VERIFY
        p1: 0x00,
        p2: scheme.reference(slot.pin_slot()),
    };
    let mut block = UnvalidatedCredentialBlock::zeroed();
    block.buffer().fill(0x00);
    let total = match scheme {
        PinReferenceScheme::Citizen => {
            let copy_len = digits.len().min(12);
            block.buffer()[..copy_len].copy_from_slice(&digits[..copy_len]);
            12
        }
        PinReferenceScheme::Organizational => {
            let copy_len = digits.len().min(ORGANIZATIONAL_PIN_STORED_LENGTH);
            block.buffer()[..copy_len].copy_from_slice(&digits[..copy_len]);
            copy_len
        }
    };
    block.set_filled(total);
    let body = CredentialBody::from_block(block)
        .map_err(|e| SignErrorKind::Transport(format!("assemble credential body: {e}")))?;
    let command = CredentialCommand::assemble(header, body);
    let response = transport
        .transmit_credential(command)
        .map_err(|e| SignErrorKind::Transport(format!("{e}")))?
        .into_response()
        .map_err(|outcome| SignErrorKind::Transport(format!("{outcome}")))?;
    Ok(classify_verify_sw(response.status_word()))
}

/// Dispatch the per-cert sign chain: RSA (PKCS#1 v1.5 SHA-256) or
/// ECDSA P-384 SHA-384, returning the raw signature bytes plus the
/// local-verify outcome. Unsupported curves / non-RSA SPKIs raise
/// the typed error kind without doing any APDU.
fn sign_dispatch_by_alg<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    scheme: PinReferenceScheme,
    cert: &Certificate<'_>,
    cert_algorithm: PublicKeyAlgorithm,
    input_bytes: &[u8],
    input_sha256: Sha256,
) -> Result<(Vec<u8>, LocalVerifyOutcome), SignErrorKind> {
    let sign_scheme = match scheme {
        PinReferenceScheme::Citizen => SignScheme::Citizen,
        PinReferenceScheme::Organizational => SignScheme::Organizational,
    };
    match cert_algorithm {
        PublicKeyAlgorithm::Rsa { .. } => {
            let core_digest = *input_sha256.as_bytes();
            let signature = transport
                .sign_prehashed_sha256_rsa(sign_scheme, slot.key_ref(), core_digest)
                .map_err(sign_err_to_kind)?;
            let verify = match cert.spki.verify_message_signature(
                MessageSignatureAlgorithm::RsaPkcs1Sha256,
                input_bytes,
                signature.as_bytes(),
            ) {
                Ok(()) => LocalVerifyOutcome::Ok,
                Err(e) => {
                    return Err(SignErrorKind::LocalVerifyFailed(format!("{e}")));
                }
            };
            Ok((signature.into_bytes(), verify))
        }
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
            let hash_sha384 = CoreSha384::of(input_bytes);
            let signature = transport
                .sign_prehashed_sha384_ecdsa(sign_scheme, slot.key_ref(), *hash_sha384.as_bytes())
                .map_err(sign_err_to_kind)?;
            let verify = match cert.spki.verify_message_signature(
                MessageSignatureAlgorithm::EcdsaSha384Raw,
                input_bytes,
                signature.as_bytes(),
            ) {
                Ok(()) => LocalVerifyOutcome::Ok,
                Err(e) => {
                    return Err(SignErrorKind::LocalVerifyFailed(format!("{e}")));
                }
            };
            Ok((signature.into_bytes(), verify))
        }
        PublicKeyAlgorithm::Ec(curve) => Err(SignErrorKind::UnsupportedCurve { slot, curve }),
        PublicKeyAlgorithm::Other => Err(SignErrorKind::UnsupportedKeyType(slot)),
    }
}

/// A card session the signing flow drives: a reset in place, which
/// PACE starts from, and one PIN-bearing transaction ended with a card
/// reset.
pub trait SigningSession: CardTransport + Sized {
    /// The transport the PIN sequence's body receives.
    type Sequence<'a>: CardTransport;

    /// Reset the card in place, returning it to its post-ATR state.
    ///
    /// # Errors
    /// The backend's reset failure.
    fn reset_card(&mut self) -> Result<(), PcscError>;

    /// Run `body` inside one transaction that ends with a card reset,
    /// consuming the session.
    ///
    /// # Errors
    /// The backend's failure to begin or to end the transaction.
    fn pin_sequence<R>(
        self,
        body: impl for<'a> FnOnce(Self::Sequence<'a>) -> R,
    ) -> Result<R, PcscError>;
}

impl SigningSession for PcscCard {
    type Sequence<'a> = PcscTransactionCard<'a, 'a>;

    fn reset_card(&mut self) -> Result<(), PcscError> {
        self.reset()
    }

    fn pin_sequence<R>(
        self,
        body: impl for<'a> FnOnce(Self::Sequence<'a>) -> R,
    ) -> Result<R, PcscError> {
        Self::pin_sequence(self, |card: PcscTransactionCard<'_, '_>| body(card))
    }
}

/// Drive the full sign flow for `options.slot` on the one reader with a
/// card.
///
/// FINEID S1 v4.2 §3.5 + §3.6 + §3.7. Steps:
///
///   1. Open a PIN-sequence session against the picked reader; on the
///      contactless interface, establish PACE from `options.can`.
///   2. Select the FINEID PKCS#15 application, read the slot's
///      certificate, bind the document to it and to the displayed
///      card, and check the PIN's retry counter against the floor.
///   3. Ask `pin` for the PIN -- only now, with the card in hand and
///      its counter served -- holding no transaction while it asks.
///   4. Inside one transaction that ends with a card reset: refuse when
///      the card is not the one checked before the prompt, check the
///      counter again, VERIFY, run MSE:SET DST -> PSO:HASH -> PSO:CDS,
///      and verify the signature locally (Rule E7).
///   5. Assemble the document and fetch its timestamps with the card
///      session closed, and write the output.
///
/// A PIN that did not end in a signature is forgotten by `pin`
/// ([`PinSource::forget`]), so a source shared across documents asks
/// again rather than present it twice.
///
/// # Errors
/// Every failure surfaces as [`SignErrorKind`]: reader / card /
/// PIN failures, sign-chain SW failures, cert or TSA failures,
/// and input / output I/O failures.
pub fn sign<B>(
    backend: &B,
    mut options: SignOptions,
    pin: &mut dyn PinSource,
) -> Result<SignReport, SignErrorKind>
where
    B: ReaderBackend<Error = PcscError>,
    B::Transport: SigningSession,
{
    if let Some(request) = options.document.as_ref() {
        request.validate_signing_policy()?;
    }
    let reader_id =
        backend.pick_single_reader(options.reader_filter.as_deref().map(ReaderFilter::new))?;

    let input_bytes = std::fs::read(&options.input).map_err(|source| SignErrorKind::InputRead {
        path: options.input.clone(),
        source,
    })?;
    // `Vec<u8>::len()` is bounded by available RAM; `usize`-to-`u64`
    // is a widening conversion on every target we ship (32-bit
    // `usize` fits in `u64`; 64-bit `usize` IS `u64`).
    let input_len: u64 = u64::try_from(input_bytes.len()).unwrap_or(u64::MAX);
    let input_sha256 = Sha256::of(&input_bytes);
    let slot = options.slot;

    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::PinSequence)?;

    // SELECT the FINEID PKCS#15 application first: the slot's cert
    // lives under it, and the card needs it active before the cert can
    // be selected from the post-ATR state.
    //
    // Over the contactless interface the card refuses every
    // pre-PACE command with SW 6982 -- PKCS#15 only opens inside
    // a PACE secure channel keyed from the CAN. On that answer,
    // establish PACE and run the identical chain through the SM
    // wrapper: the ops traits are generic over `CardTransport`
    // and `SmTransport` is one, so the chain code is shared. The
    // sign key's access condition is plain CHV with no interface
    // restriction (FINEID S4-1 v4.2 s8.1.7-9), which is what
    // licenses contactless signing at all.
    let on_card = match transport.select_pkcs15_application() {
        Ok(()) => {
            let prepared = prepare_on_card(&mut transport, &options, &input_bytes)?;
            let presented = present_pin(pin, slot, |pin_bytes| {
                transport.pin_sequence(|mut card| {
                    commit_in_transaction(
                        &mut card,
                        slot,
                        &prepared,
                        pin_bytes,
                        &input_bytes,
                        input_sha256,
                    )
                })?
            });
            finish_on_card(prepared, presented?)
        }
        Err(Pkcs15Error::Status(StatusWord::SecurityNotSatisfied)) => {
            let Some(can) = options.can.take() else {
                return Err(SignErrorKind::NeedCan);
            };
            // Start PACE from a clean card. The reset clears two
            // states that otherwise make PACE fail for reasons
            // that have nothing to do with the CAN the operator
            // typed: the probe SELECT above (which left the card
            // outside MF, so MSE:Set AT answers SW=0x6999), and a
            // CAN suspended by an earlier failed PACE, which the
            // card reports exactly like a wrong CAN until it is
            // reset (BSI TR-03110-3 §2.4).
            transport
                .reset_card()
                .map_err(|e| SignErrorKind::Pace(format!("reset before PACE: {e}")))?;
            // PACE's MSE:Set AT is only accepted in MF context: the
            // reset lands the card there already; selecting MF makes
            // the requirement explicit and survives a backend whose
            // reset leaves selection elsewhere.
            transport
                .select_mf()
                .map_err(|e| SignErrorKind::Pace(format!("SELECT MF before PACE: {e}")))?;
            let session =
                run_pace_with_can(&mut transport, can).map_err(|e| pace_err_to_kind(&e))?;
            let mut sm = SmTransport::new(transport, session);
            sm.select_pkcs15_application()
                .map_err(|e| SignErrorKind::CertUnavailable {
                    slot,
                    detail: format!("select pkcs15 app under SM: {e}"),
                })?;
            let prepared = prepare_on_card(&mut sm, &options, &input_bytes)?;
            // The secure channel's keys and counter carry into the
            // transaction: the card is not reset between the two.
            let (transport, session) = sm.into_parts();
            let presented = present_pin(pin, slot, |pin_bytes| {
                transport.pin_sequence(|card| {
                    let mut sm = SmTransport::new(card, session);
                    commit_in_transaction(
                        &mut sm,
                        slot,
                        &prepared,
                        pin_bytes,
                        &input_bytes,
                        input_sha256,
                    )
                })?
            });
            finish_on_card(prepared, presented?)
        }
        Err(e) => {
            return Err(SignErrorKind::CertUnavailable {
                slot,
                detail: format!("select pkcs15 app: {e}"),
            });
        }
    };
    let chain = finish_signature(&options, on_card)?;

    let signature_len = chain.signature_bytes.len();
    let output_len = chain.output_bytes.len();
    let signature_path = options
        .output
        .write(chain.best_signature_time, &chain.output_bytes)?;

    let cert_path = if let Some(path) = &options.save_cert {
        std::fs::write(path, chain.cert_der.as_bytes()).map_err(|source| {
            SignErrorKind::SignatureWrite {
                path: path.clone(),
                source,
            }
        })?;
        Some(path.clone())
    } else {
        None
    };

    Ok(SignReport {
        reader: reader_id.as_str().to_owned(),
        slot,
        input_len,
        input_sha256,
        signature_path,
        cert_path,
        signature_len,
        timestamps: chain.timestamps,
        best_signature_time: chain.best_signature_time,
        output_len,
        cert_subject_cn: chain.cert_subject_cn,
        pin_retries_after: chain.pin_retries_after,
        local_verify: chain.local_verify,
    })
}

/// Ask `pin` for `slot`'s PIN and hand it to `verify`. Unless the card
/// signed, the source forgets the PIN: one the card refused, one typed
/// for a card that has since changed, or one whose sequence failed
/// before or after VERIFY is never presented again.
fn present_pin(
    pin: &mut dyn PinSource,
    slot: SignSlot,
    verify: impl FnOnce(&PinBytes) -> Result<Committed, SignErrorKind>,
) -> Result<Committed, SignErrorKind> {
    let outcome = verify(pin.pin(slot.pin_role()).map_err(SignErrorKind::PinEntry)?);
    if outcome.is_err() {
        pin.forget();
    }
    outcome
}

/// The PIN transaction's body on either interface: select the PKCS#15
/// application -- the preparation ran outside the transaction, and the
/// context VERIFY relies on is established inside it -- then
/// [`commit_on_card`].
fn commit_in_transaction<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    prepared: &Prepared,
    pin: &PinBytes,
    input_bytes: &[u8],
    input_sha256: Sha256,
) -> Result<Committed, SignErrorKind> {
    transport
        .select_pkcs15_application()
        .map_err(|e| SignErrorKind::CertUnavailable {
            slot,
            detail: format!("select pkcs15 app: {e}"),
        })?;
    commit_on_card(transport, slot, prepared, pin, input_bytes, input_sha256)
}

/// What the card established before the PIN prompt: the slot's
/// certificate, the document bound to it, the PIN reference numbering
/// and the card's serial.
struct Prepared {
    /// DER of the slot cert.
    cert_der: UnvalidatedCertificate,
    /// The same certificate, parsed.
    cert_owned: OwnedCert,
    /// The half-built document the signature completes, when a format
    /// was asked for.
    plan: Option<DocumentPlan>,
    /// The PIN reference numbering the card declared.
    scheme: PinReferenceScheme,
    /// The serial EF.TokenInfo named before the prompt.
    serial: Option<TokenSerial>,
}

/// What VERIFY and the sign chain produced.
struct Committed {
    /// Retry count surfaced by a non-Ok VERIFY status word.
    pin_retries_after: Option<u8>,
    /// Raw signature bytes off the card.
    signature_bytes: Vec<u8>,
    /// Rule E7 local-verify outcome.
    local_verify: LocalVerifyOutcome,
}

/// The card-facing preparation both interface paths share once the
/// PKCS#15 application is selected on `transport`: cert read + parse,
/// the document bound to the cert and the displayed card, the PIN
/// reference numbering, and the retry floor. Runs before the PIN is
/// asked for, so a missing cert, a swapped card, a malformed request
/// or a counter below the floor ends the flow without a prompt.
fn prepare_on_card<T: CardTransport>(
    transport: &mut T,
    options: &SignOptions,
    input_bytes: &[u8],
) -> Result<Prepared, SignErrorKind> {
    let slot = options.slot;
    let cert_der = transport
        .read_certificate(slot.cert_slot())
        .or_else(|_| {
            let alt = match slot.cert_slot() {
                CertSlot::Authentication => CertSlot::AuthenticationAlt,
                CertSlot::Signature => CertSlot::SignatureAlt,
                other => other,
            };
            transport.read_certificate(alt)
        })
        .map_err(|e| SignErrorKind::CertUnavailable {
            slot,
            detail: format!("read: {e}"),
        })?;
    let cert_owned =
        OwnedCert::from_der(cert_der.as_bytes()).map_err(|e| SignErrorKind::CertUnavailable {
            slot,
            detail: format!("parse: {e}"),
        })?;

    // What the card will sign, for a document: a structure built around
    // the certificate just read -- CAdES signed attributes, or a
    // canonical ds:SignedInfo -- which is why this cannot happen before
    // the card is open.
    let plan = match options.document {
        None => None,
        Some(ref request) => {
            ensure_displayed_card(transport, request)?;
            let cert = cert_owned.view();
            let parameters =
                document_signer(&cert, cert.spki.algorithm(), slot, request.signing_time)?;
            let objects = load_data_objects(options, request, input_bytes)?;
            ensure_visible_signature_format(request)?;
            Some(
                document::plan(request.format, objects, &parameters, &request.metadata)
                    .map_err(SignErrorKind::Document)?,
            )
        }
    };

    // The reference numbering is the card's to declare (citizen
    // S1 v4.2 vs organizational S4-2 v4.0), resolved by
    // counter-safe probes before any PIN is asked for.
    let scheme = resolve_pin_reference_scheme(transport)?;
    check_slot_retry_floor(transport, slot, scheme)?;
    let serial = live_token_serial(transport)?;
    Ok(Prepared {
        cert_der,
        cert_owned,
        plan,
        scheme,
        serial,
    })
}

/// Refuse when the slot's PIN counter is below the shared retry floor.
fn check_slot_retry_floor<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    scheme: PinReferenceScheme,
) -> Result<(), SignErrorKind> {
    let status = transport
        .pin_status_with_scheme(scheme, slot.pin_slot())
        .map_err(|e| SignErrorKind::Transport(format!("{e}")))?;
    check_retry_floor(slot.pin_slot().into(), status).map_err(SignErrorKind::RetryFloor)
}

/// VERIFY and the sign chain, inside the PIN transaction.
///
/// The prompt is the one moment the card is out of the flow's hands,
/// so the card that answers VERIFY must be the card prepared: its
/// serial is read again and compared, and its counter checked against
/// the floor again, before the PIN is sent.
fn commit_on_card<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    prepared: &Prepared,
    pin: &PinBytes,
    input_bytes: &[u8],
    input_sha256: Sha256,
) -> Result<Committed, SignErrorKind> {
    if live_token_serial(transport)? != prepared.serial {
        return Err(SignErrorKind::DisplayedCard(
            CARD_CHANGED_DURING_PROMPT.to_owned(),
        ));
    }
    check_slot_retry_floor(transport, slot, prepared.scheme)?;
    let outcome = verify_pin_with_scheme(transport, slot, prepared.scheme, pin)?;
    let pin_retries_after = match outcome {
        VerifyOutcome::Ok => None,
        rejected @ (VerifyOutcome::WrongPin { .. }
        | VerifyOutcome::Locked
        | VerifyOutcome::Other(_)) => {
            return Err(SignErrorKind::PinRejected {
                slot,
                outcome: rejected,
            });
        }
    };

    let signed_octets: &[u8] = prepared
        .plan
        .as_ref()
        .map_or(input_bytes, DocumentPlan::to_be_signed);
    // The RSA path signs this digest; the ECDSA path recomputes its
    // own SHA-384 from the same octets. Both stay in step with the
    // digest named in `document_signer`.
    let signed_sha256 = match prepared.plan {
        None => input_sha256,
        Some(_) => Sha256::of(signed_octets),
    };

    // Branch on cert public-key shape per FINEID S4-1 v4.2 §4.2:
    // Older-scheme cards have an RSA-3072 key; Newer-scheme cards
    // have ECC P-384 (secp384r1) + SHA-384. The PSO chain selects the
    // right algRef, the right PSO:HASH hash size, and the right
    // signature-length expectation for each.
    let cert = prepared.cert_owned.view();
    let (signature_bytes, local_verify) = sign_dispatch_by_alg(
        transport,
        slot,
        prepared.scheme,
        &cert,
        cert.spki.algorithm(),
        signed_octets,
        signed_sha256,
    )?;
    Ok(Committed {
        pin_retries_after,
        signature_bytes,
        local_verify,
    })
}

/// The card's part of the signature, once the transaction has ended.
fn finish_on_card(prepared: Prepared, committed: Committed) -> CardSignOutput {
    CardSignOutput {
        cert_der: prepared.cert_der,
        cert_owned: prepared.cert_owned,
        pin_retries_after: committed.pin_retries_after,
        signature_bytes: committed.signature_bytes,
        local_verify: committed.local_verify,
        plan: prepared.plan,
    }
}

/// What the card produced inside the PIN sequence: everything
/// [`finish_signature`] needs once the card session is closed.
struct CardSignOutput {
    /// DER of the slot cert that produced the signature.
    cert_der: UnvalidatedCertificate,
    /// The same certificate, parsed, for the assembly parameters.
    cert_owned: OwnedCert,
    /// Retry count surfaced by a non-Ok VERIFY status word.
    pin_retries_after: Option<u8>,
    /// Raw signature bytes off the card.
    signature_bytes: Vec<u8>,
    /// Rule E7 local-verify outcome.
    local_verify: LocalVerifyOutcome,
    /// The half-built document the signature completes, when a
    /// format was asked for.
    plan: Option<DocumentPlan>,
}

/// Output of [`finish_signature`]: what [`sign`] still needs once the
/// document is assembled.
struct SignChainOutput {
    /// DER of the slot cert that produced the signature.
    cert_der: UnvalidatedCertificate,
    /// Subject CN for the report.
    cert_subject_cn: Option<CommonName>,
    /// Retry count surfaced by a non-Ok VERIFY status word; see
    /// [`SignReport::pin_retries_after`].
    pin_retries_after: Option<u8>,
    /// Raw signature bytes off the card.
    signature_bytes: Vec<u8>,
    /// Timestamp tokens actually obtained.
    timestamps: usize,
    /// The earliest validated signature timestamp's `genTime`.
    best_signature_time: Option<BestSignatureTime>,
    /// What gets written to the output: the raw signature for a bare
    /// sign, or the finished document when a format was asked for.
    output_bytes: Vec<u8>,
    /// Rule E7 local-verify outcome.
    local_verify: LocalVerifyOutcome,
}

/// Complete the signature once the card session is closed.
///
/// The local verify inside the PIN sequence proved the card signed
/// what was asked. Only now is it worth assembling, because assembly
/// can still fail -- a CAdES that outgrew the hole reserved in a
/// PDF -- and because assembly fetches timestamps from the network,
/// which never happens while the reader is held.
fn finish_signature(
    options: &SignOptions,
    on_card: CardSignOutput,
) -> Result<SignChainOutput, SignErrorKind> {
    let CardSignOutput {
        cert_der,
        cert_owned,
        pin_retries_after,
        signature_bytes,
        local_verify,
        plan,
    } = on_card;
    let cert = cert_owned.view();
    let cert_subject_cn = cert.subject.common_name();
    let assembled = match (options.document.as_ref(), plan) {
        (Some(request), Some(plan)) => {
            let parameters = document_signer(
                &cert,
                cert.spki.algorithm(),
                options.slot,
                request.signing_time,
            )?;
            assemble_document(options, plan, &parameters, &signature_bytes, &cert_der)?
        }
        (None, _) | (Some(_), None) => AssembledDocument {
            bytes: signature_bytes.clone(),
            timestamps: 0,
            best_signature_time: None,
        },
    };

    Ok(SignChainOutput {
        cert_der,
        cert_subject_cn,
        pin_retries_after,
        signature_bytes,
        timestamps: assembled.timestamps,
        best_signature_time: assembled.best_signature_time,
        output_bytes: assembled.bytes,
        local_verify,
    })
}

/// Refuse a visible mark on a format other than `PAdES`.
///
/// Runs before PIN verification, so a misplaced mark cannot consume a
/// PIN retry.
fn ensure_visible_signature_format(request: &DocumentRequest) -> Result<(), SignErrorKind> {
    if request.metadata.visible_signature.is_some() && request.format != Format::Pades {
        return Err(SignErrorKind::VisibleSignatureFormat);
    }
    Ok(())
}

/// Refuse to sign when the live card is not the one the operator saw.
///
/// Runs before PIN verification for every document request carrying a
/// displayed serial, whatever the format produces.
fn ensure_displayed_card<T: CardTransport>(
    transport: &mut T,
    request: &DocumentRequest,
) -> Result<(), SignErrorKind> {
    let Some(expected) = request.expected_serial.as_ref() else {
        return Ok(());
    };
    let live = live_token_serial(transport)?;
    ensure_expected_serial(expected, live.as_ref())
}

/// The serial of the card in the reader, as EF.TokenInfo names it.
fn live_token_serial<T: CardTransport>(
    transport: &mut T,
) -> Result<Option<TokenSerial>, SignErrorKind> {
    let token = transport.read_token_info().map_err(|error| {
        SignErrorKind::DisplayedCard(format!("cannot re-read EF.TokenInfo: {error}"))
    })?;
    Ok(token.serial_number_hex().cloned().map(render_token_serial))
}

fn ensure_expected_serial(
    expected: &TokenSerial,
    live: Option<&TokenSerial>,
) -> Result<(), SignErrorKind> {
    match live {
        Some(live) if live == expected => Ok(()),
        Some(_different) => Err(SignErrorKind::DisplayedCard(
            "the card in the reader is not the card displayed by the application".to_owned(),
        )),
        None => Err(SignErrorKind::DisplayedCard(
            "the card does not publish a PKCS#15 serial for session binding".to_owned(),
        )),
    }
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
    request: Option<&DocumentRequest>,
    authorities: &[String],
    plan: &DocumentPlan,
    parameters: &SignerParameters<'_>,
    signature_bytes: &[u8],
) -> Result<CollectedTimestamps, SignErrorKind> {
    let keep_material = request.is_some_and(DocumentRequest::requires_long_term_material);
    let credentials = request.and_then(|request| request.timestamp_credentials.as_ref());
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
                Err(why) => {
                    refusals.push(format!(
                        "{url}: returned a cryptographically valid token, but complete current validation evidence for its chain could not be collected: {why}"
                    ));
                    continue;
                }
            }
        }
        tokens.push(token);
    }
    if (!authorities.is_empty()
        || request.is_some_and(DocumentRequest::requires_long_term_material))
        && tokens.is_empty()
    {
        let detail = if refusals.is_empty() {
            "no timestamp authority was configured".to_owned()
        } else {
            refusals.join("; ")
        };
        return Err(SignErrorKind::Timestamp(format!(
            "no timestamp authority produced an acceptable token, so the signature would carry no attested time -- {detail}"
        )));
    }
    for refusal in &refusals {
        eprintln!("timestamp authority declined, continuing without it -- {refusal}");
    }
    Ok(CollectedTimestamps { tokens, material })
}

/// Fetch the timestamps and evidence a document signature asked for,
/// then assemble it.
///
/// Everything here needs the network and the signature both, so it can
/// only run once the card has answered -- and it runs with the card
/// still held, because the signer parameters borrow a certificate that
/// lives only for this session.
fn assemble_document(
    options: &SignOptions,
    plan: DocumentPlan,
    parameters: &SignerParameters<'_>,
    signature_bytes: &[u8],
    cert_der: &UnvalidatedCertificate,
) -> Result<AssembledDocument, SignErrorKind> {
    // The timestamp is over the signature, so it can only be
    // fetched now. That is a network round trip with the card
    // still held exclusively; the alternative is dropping the
    // card and re-reading the certificate to rebuild
    // `parameters`, which trades a held reader for a second
    // card session.
    let request = options.document.as_ref();
    let authorities = options
        .document
        .as_ref()
        .map(|request| request.timestamp_authorities.as_slice())
        .unwrap_or_default();
    let CollectedTimestamps {
        tokens,
        material: mut timestamp_material,
    } = collect_document_timestamps(request, authorities, &plan, parameters, signature_bytes)?;
    let keep_material = request.is_some_and(DocumentRequest::requires_long_term_material);
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
            leaf_der: cert_der.as_bytes(),
            reference_time,
            anchor: ChainAnchor::Approved(&signer_anchors),
            nonce_policy: NoncePolicy::RequireEcho,
            include_leaf: false,
            include_anchor: true,
        }])
        .map_err(|e| SignErrorKind::Material(format!("signer path: {e}")))?;
        merge_material(&mut timestamp_material, signer_material);
        timestamp_material
    } else {
        ValidationMaterial::default()
    };
    let token_bytes: Vec<Vec<u8>> = tokens.iter().map(|token| token.token().to_vec()).collect();
    // ASiC-E CAdES archives through a second manifest and a
    // timestamp over it, not through the signature, so it
    // branches here rather than after assembly.
    if request.is_some_and(|r| r.archive)
        && let Some(manifest) =
            plan.archive_manifest(parameters, signature_bytes, parameters.digest_algorithm)
    {
        let digest = parameters.digest_algorithm.digest(&manifest);
        let token = first_answering_token(
            authorities,
            request.and_then(|request| request.timestamp_credentials.as_ref()),
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
    let (bytes, archive_timestamp_obtained) = if request.is_some_and(|r| r.archive) {
        (
            archive_timestamp(
                &document,
                authorities,
                request.and_then(|request| request.timestamp_credentials.as_ref()),
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
struct AssembledDocument {
    /// The document.
    bytes: Vec<u8>,
    /// Timestamp tokens obtained, the archive timestamp included.
    timestamps: usize,
    /// The earliest validated signature timestamp's `genTime`.
    best_signature_time: Option<BestSignatureTime>,
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
                if let Err(why) = authenticate_archive_timestamp(&token, covered_material) {
                    refusals.push(format!(
                        "{url} returned an archive timestamp without complete current validation evidence ({why}), trying the next"
                    ));
                    continue;
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
        format!(
            "no authority produced an acceptable archive timestamp -- {}",
            refusals.join("; ")
        )
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
) -> Result<(), String> {
    authenticate_archive_timestamp_with(token, covered_material, timestamp_validation_material)
}

fn authenticate_archive_timestamp_with<F>(
    token: &VerifiedTimestampToken,
    covered_material: &ValidationMaterial,
    collect_evidence: F,
) -> Result<(), String>
where
    F: FnOnce(&VerifiedTimestampToken) -> Result<ValidationMaterial, String>,
{
    let path = embedded_timestamp_path(token)?;
    require_archive_path_covered(&path, covered_material)?;
    let _verified_current_evidence = collect_evidence(token)?;
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
) -> Result<(), String> {
    if path.is_empty() {
        return Err("outer timestamp has an empty authenticated certificate path".to_owned());
    }
    if path
        .iter()
        .all(|certificate| covered_material.certificates.contains(certificate))
    {
        return Ok(());
    }
    Err(
        "outer timestamp certificate path is not byte-for-byte covered by embedded LT material"
            .to_owned(),
    )
}

/// The token's certificate path, verified from its signer certificate
/// through the token's embedded certificates to one of them.
///
/// The authority is trusted as configured -- whoever names one answers
/// for it -- so no trusted list or pinned root gates it
/// ([`ChainAnchor::Configured`]). What is still verified is internal
/// consistency: names, signatures, validity windows and roles along
/// the embedded chain.
fn embedded_timestamp_path(token: &VerifiedTimestampToken) -> Result<Vec<Vec<u8>>, String> {
    let embedded = embedded_certificate_ders(token);
    if embedded.is_empty() {
        return Err("the token embeds no certificate usable as its chain anchor".to_owned());
    }
    crate::material::verify_chain_to_anchor(
        token.signer_certificate().as_der(),
        token.generated_at(),
        ChainAnchor::Configured(&embedded),
        &embedded,
    )
    .map_err(|e| format!("no valid path within the token's embedded chain: {e}"))
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
) -> Result<ValidationMaterial, String> {
    let embedded = embedded_certificate_ders(token);
    if embedded.is_empty() {
        return Err("the token embeds no certificate usable as its chain anchor".to_owned());
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
    .map_err(|e| e.to_string())
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
const fn document_signer<'a>(
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
fn load_data_objects(
    options: &SignOptions,
    request: &DocumentRequest,
    input_bytes: &[u8],
) -> Result<Vec<DataObject>, SignErrorKind> {
    let mut objects = vec![data_object(&options.input, input_bytes.to_vec())];
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
fn data_object(path: &std::path::Path, content: Vec<u8>) -> DataObject {
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
fn media_type_for(path: &std::path::Path) -> &'static str {
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

/// Hoist [`pace::PaceError`] onto [`SignErrorKind`], with the
/// same wrong-CAN classification `emrtd::read_personal_data`
/// applies: a card-reported authentication failure or a
/// mutual-auth tag mismatch both mean the CAN-derived key
/// disagreed with the card.
fn pace_err_to_kind<TE: fmt::Display>(e: &PaceError<TE>) -> SignErrorKind {
    match e {
        PaceError::Status(_, sw) if *sw == StatusWord::AuthenticationFailed => {
            SignErrorKind::BadCan
        }
        PaceError::AuthMismatch => SignErrorKind::BadCan,
        _ => SignErrorKind::Pace(format!("{e}")),
    }
}

/// Hoist [`SignError`] variants onto [`SignErrorKind`].
fn sign_err_to_kind<TE: fmt::Display>(e: SignError<TE>) -> SignErrorKind {
    match e {
        SignError::Transport(t) => SignErrorKind::Transport(format!("{t}")),
        SignError::Outcome(outcome) => SignErrorKind::Transport(format!("{outcome}")),
        SignError::Status(stage, sw) => SignErrorKind::SignSw {
            stage,
            sw: sw.as_u16(),
        },
        SignError::Command(err) => SignErrorKind::Transport(format!("{err}")),
        SignError::UnexpectedSignatureLength { got, .. } => {
            SignErrorKind::UnexpectedSignatureLength(got)
        }
    }
}

impl fmt::Display for SignReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        writeln!(
            f,
            "key: {} (key ref {:#04X})",
            self.slot.key_label(),
            self.slot.key_ref().as_byte()
        )?;
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
    use refineid_apdu::PinRetries;

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
            expected_serial: None,
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
    fn signing_is_bound_to_the_displayed_card() -> TestResult {
        let displayed = TokenSerial::new("displayed-card".to_owned());
        let same = TokenSerial::new("displayed-card".to_owned());
        let replacement = TokenSerial::new("replacement-card".to_owned());
        ensure_expected_serial(&displayed, Some(&same))?;
        check_true(
            ensure_expected_serial(&displayed, Some(&replacement)).is_err(),
            "card swap is refused",
        )?;
        check_true(
            ensure_expected_serial(&displayed, None).is_err(),
            "missing live serial is refused",
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
        let error = authenticate_archive_timestamp_with(&token, &covered_material, |_token| {
            Err("current validation evidence unavailable".to_owned())
        })
        .err()
        .ok_or("archive token unexpectedly survived missing validation evidence")?;
        check(
            &error,
            &"current validation evidence unavailable".to_owned(),
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
        check_true(
            error.contains("not byte-for-byte covered"),
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

    // ---- SignErrorKind Display: each arm renders an
    // operator-facing line; the PIN arms also pivot on the slot
    // label and the VerifyOutcome shape. ----

    fn pin_retries(n: u8) -> Result<PinRetries, Box<dyn core::error::Error>> {
        PinRetries::from_nibble(n).ok_or_else(|| "bad nibble".into())
    }

    #[test]
    fn pin_rejected_display_renders_the_pin_and_outcome() -> TestResult {
        let wrong = SignErrorKind::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::WrongPin {
                retries_left: pin_retries(2)?,
            },
        }
        .to_string();
        check_true(wrong.contains("PIN2"), "wrong-pin label")?;
        check_true(wrong.contains("wrong PIN"), "wrong-pin reason")?;
        check_true(wrong.contains("retries left"), "wrong-pin counter")?;

        let locked = SignErrorKind::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::Locked,
        }
        .to_string();
        check_true(locked.contains("PIN2"), "locked label")?;
        check_true(locked.contains("blocked"), "locked reason")?;

        let other = SignErrorKind::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::Other(StatusWord::Other(0x6A88)),
        }
        .to_string();
        check_true(other.contains("0x6A88"), "other sw rendered")?;

        // The internal "can't happen" arm still renders a line
        // rather than panicking.
        let internal = SignErrorKind::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::Ok,
        }
        .to_string();
        check_true(internal.contains("internal"), "ok-outcome guard")
    }

    #[test]
    fn sign_chain_and_crypto_error_display() -> TestResult {
        check_true(
            SignErrorKind::PinPolicy {
                slot: SignSlot::Qualified,
                reason: PinPolicyReason::NonDigit,
            }
            .to_string()
            .contains("PIN2 rejected locally"),
            "pin policy",
        )?;
        check_true(
            SignErrorKind::SignSw {
                stage: "PSO:HASH",
                sw: 0x6A80,
            }
            .to_string()
            .contains("PSO:HASH: SW=0x6A80"),
            "sign sw stage + sw",
        )?;
        check_true(
            SignErrorKind::UnexpectedSignatureLength(256)
                .to_string()
                .contains("256-byte signature; expected 384"),
            "bad sig length",
        )?;
        check_true(
            SignErrorKind::CertUnavailable {
                slot: SignSlot::Qualified,
                detail: "read: timeout".to_owned(),
            }
            .to_string()
            .contains("qualified-signature cert unavailable for local verify: read: timeout"),
            "cert unavailable",
        )?;
        check_true(
            SignErrorKind::UnsupportedKeyType(SignSlot::Qualified)
                .to_string()
                .contains("qualified-signature cert has an unsupported key type"),
            "unsupported key type",
        )?;
        check_true(
            SignErrorKind::UnsupportedCurve {
                slot: SignSlot::Qualified,
                curve: EcCurve::Secp256r1,
            }
            .to_string()
            .contains("only signs ECDSA on secp384r1"),
            "unsupported curve",
        )?;
        check_true(
            SignErrorKind::LocalVerifyFailed("digest mismatch".to_owned())
                .to_string()
                .contains("local verify failed: digest mismatch"),
            "local verify failed",
        )?;
        check_true(
            SignErrorKind::Transport("reader vanished".to_owned())
                .to_string()
                .contains("transport: reader vanished"),
            "transport",
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

    // ---- sign_err_to_kind: lib-core SignError -> client
    // SignErrorKind, shared by the RSA and ECDSA branches. ----

    #[test]
    fn sign_err_to_kind_maps_each_variant() -> TestResult {
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::Transport("boom")),
                SignErrorKind::Transport(_)
            ),
            "transport",
        )?;
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::Status(
                    "PSO:CDS",
                    StatusWord::from_u16(0x6982)
                )),
                SignErrorKind::SignSw {
                    stage: "PSO:CDS",
                    sw: 0x6982
                }
            ),
            "sw",
        )?;
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::UnexpectedSignatureLength {
                    got: 48,
                    expected: 384
                }),
                SignErrorKind::UnexpectedSignatureLength(48)
            ),
            "unexpected length",
        )
    }

    // ---- SignReport Display ----

    fn sample_report(cn: Option<CommonName>) -> SignReport {
        SignReport {
            reader: "OMNIKEY 5422".to_owned(),
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
        check_true(
            s.contains("key: qualified-signature (key ref 0x02)"),
            "key line with key ref",
        )?;
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
    fn each_slot_names_its_own_key_pin_and_certificate() -> TestResult {
        check(
            &SignSlot::Authentication.key_ref(),
            &KeyRef::Auth,
            "auth key",
        )?;
        check(&SignSlot::Qualified.key_ref(), &KeyRef::Sign, "sign key")?;
        check(
            &SignSlot::Authentication.pin_role(),
            &PinRole::Pin1,
            "auth PIN",
        )?;
        check(&SignSlot::Qualified.pin_role(), &PinRole::Pin2, "sign PIN")?;
        check(
            &SignSlot::Authentication.cert_slot(),
            &CertSlot::Authentication,
            "auth cert",
        )?;
        check(
            &SignSlot::Qualified.cert_slot(),
            &CertSlot::Signature,
            "sign cert",
        )
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

    // ---- The flow on a synthetic card: the PIN is asked for only once
    // the card is found and its counter served, the card is bound
    // across the prompt, and a refused PIN is forgotten. ----

    mod synthetic_card {
        use core::cell::{Cell, RefCell};
        use std::rc::Rc;

        use refineid_apdu::iso7816::{ReadBinary, SelectByAidNoFci};
        use refineid_apdu::{
            CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
            TransportOutcome,
        };
        use refineid_auth::verify::VERIFY_INS;
        use refineid_auth::{PinReferenceScheme, PinSlot};
        use refineid_ber::{BerEncoder, BerTag, Integer, OctetString, Sequence};
        use refineid_pcsc::{
            PcscError, ReaderAccessCap, ReaderBackend, ReaderId, ReaderInfo, ReaderPickError,
        };
        use refineid_pkcs15::EF_TOKEN_INFO_FID;
        use refineid_sign::RSA_3072_SIG_BYTES;
        use refineid_sign::commands::{MSE_INS, PSO_CDS_P1, PSO_INS};

        use super::super::{
            CARD_CHANGED_DURING_PROMPT, Sha256, SignErrorKind, SignOptions, SignOutput, SignReport,
            SignSlot, SigningSession, commit_in_transaction, prepare_on_card, sign,
        };
        use crate::pin::{PinBytes, PinEntryError, PinRole, PinSource, PromptedPin};
        use crate::test_util::{TempDir, TestResult, check, check_true};
        use crate::testkit::{
            CertificateSpec, FIXTURE_LAST_DAY, TestCurve, TestKey, certificate, day,
        };

        /// Synthetic reader name.
        const SYNTHETIC_READER: &str = "Synthetic Card Reader";
        /// Offset of INS in a command APDU (ISO 7816-4 s5.1).
        const INS_INDEX: usize = 1;
        /// Offset of P1 in a command APDU (ISO 7816-4 s5.1).
        const P1_INDEX: usize = 2;
        /// Offset of P2 in a command APDU (ISO 7816-4 s5.1).
        const P2_INDEX: usize = 3;
        /// Length of the CLA INS P1 P2 header (ISO 7816-4 s5.1).
        const HEADER_LEN: usize = 4;
        /// Offset of a short command's data field: the header and `Lc`.
        const DATA_INDEX: usize = HEADER_LEN + 1;
        /// Fill byte of the card's synthetic signature.
        const ANSWER_FILL: u8 = b'S';
        /// A PIN counter the retry floor serves (five, four or three).
        const TRIES_SERVED: u8 = 5;
        /// A PIN counter the retry floor refuses (two, one or none).
        const TRIES_BELOW_FLOOR: u8 = 2;
        /// The counter a refused VERIFY reports.
        const TRIES_AFTER_WRONG: u8 = 4;
        /// The certificate the card holds in every slot: a public root
        /// standing in for the card's own.
        const CERTIFICATE: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der");
        /// `TokenInfo.version` of the synthetic card.
        const TOKEN_INFO_VERSION: u8 = 0;
        /// The synthetic card's serial, and the one a swapped card has.
        const SERIAL: &[u8] = b"SYNTHETIC0001";
        const OTHER_SERIAL: &[u8] = b"SYNTHETIC0002";
        /// A synthetic PIN in the shape every PIN role accepts.
        const SYNTHETIC_PIN: &[u8] = b"123456";
        /// Synthetic message to sign.
        const MESSAGE: &[u8] = b"synthetic message";
        /// Seed of the signing card's synthetic key.
        const SIGNING_SEED: &[u8] = b"synthetic signing card";
        /// Serial and name of the signing card's certificate.
        const CERTIFICATE_SERIAL: u8 = 1;
        const SIGNER_NAME: &str = "Synthetic Signer";
        /// First day of the certificate's validity.
        const FIRST_DAY: u8 = 1;

        /// What the card serves on READ BINARY.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Selected {
            Certificate,
            TokenInfo,
        }

        /// The card's state, shared by every session the backend opens.
        #[derive(Debug)]
        struct State {
            certificate: Vec<u8>,
            signature: Vec<u8>,
            tries: PinRetries,
            verify_answer: StatusWord,
            swapped: Cell<bool>,
            selected: Cell<Selected>,
            credentials: RefCell<Vec<u8>>,
            instructions: RefCell<Vec<u8>>,
        }

        #[derive(Debug, Clone)]
        struct SyntheticCard(Rc<State>);

        impl SyntheticCard {
            fn new(tries: u8, verify_answer: StatusWord) -> Result<Self, &'static str> {
                Self::holding(
                    CERTIFICATE.to_vec(),
                    vec![ANSWER_FILL; RSA_3072_SIG_BYTES],
                    tries,
                    verify_answer,
                )
            }

            /// A card whose key signs [`MESSAGE`] so the local verify
            /// passes: a synthetic P-384 key and its own certificate.
            fn signing() -> Result<Self, &'static str> {
                let key = TestKey::derive(TestCurve::P384, SIGNING_SEED);
                let spec = CertificateSpec {
                    serial: CERTIFICATE_SERIAL,
                    subject: SIGNER_NAME,
                    issuer: SIGNER_NAME,
                    not_before: day(FIRST_DAY),
                    not_after: day(FIXTURE_LAST_DAY),
                    extensions: Vec::new(),
                };
                Self::holding(
                    certificate(&spec, &key, &key),
                    key.sign_raw(MESSAGE),
                    TRIES_SERVED,
                    StatusWord::Success,
                )
            }

            fn holding(
                certificate: Vec<u8>,
                signature: Vec<u8>,
                tries: u8,
                verify_answer: StatusWord,
            ) -> Result<Self, &'static str> {
                Ok(Self(Rc::new(State {
                    certificate,
                    signature,
                    tries: PinRetries::from_nibble(tries).ok_or("not a counter value")?,
                    verify_answer,
                    swapped: Cell::new(false),
                    selected: Cell::new(Selected::Certificate),
                    credentials: RefCell::new(Vec::new()),
                    instructions: RefCell::new(Vec::new()),
                })))
            }

            fn served() -> Result<Self, &'static str> {
                Self::new(TRIES_SERVED, StatusWord::Success)
            }

            /// The P2 byte of every credential command the card saw.
            fn credential_references(&self) -> Vec<u8> {
                self.0.credentials.borrow().clone()
            }

            fn token_info(&self) -> Vec<u8> {
                let serial = if self.0.swapped.get() {
                    OTHER_SERIAL
                } else {
                    SERIAL
                };
                let tag = |tag: u16| u8::try_from(tag).unwrap_or_default();
                let mut inner = BerEncoder::default();
                let _version = inner.push_tlv(tag(<Integer as BerTag>::TAG), [TOKEN_INFO_VERSION]);
                let _serial = inner.push_tlv(tag(<OctetString as BerTag>::TAG), serial);
                let mut outer = BerEncoder::default();
                let _sequence = outer.push_tlv(tag(<Sequence as BerTag>::TAG), inner.finish());
                outer.finish()
            }

            /// The INS byte of every command the card saw, in order.
            fn instructions(&self) -> Vec<u8> {
                self.0.instructions.borrow().clone()
            }

            fn answer(&self, apdu: &[u8]) -> ResponseApdu {
                let ins = apdu.get(INS_INDEX).copied();
                self.0
                    .instructions
                    .borrow_mut()
                    .push(ins.unwrap_or_default());
                if ins == Some(VERIFY_INS) {
                    return respond(
                        Vec::new(),
                        StatusWord::PinIncorrect {
                            retries: self.0.tries,
                        },
                    );
                }
                if ins == Some(SelectByAidNoFci::INS) {
                    let token_info = apdu.get(DATA_INDEX..) == Some(EF_TOKEN_INFO_FID.as_bytes());
                    self.0.selected.set(if token_info {
                        Selected::TokenInfo
                    } else {
                        Selected::Certificate
                    });
                    return respond(Vec::new(), StatusWord::Success);
                }
                if ins == Some(ReadBinary::INS) {
                    return self.read_binary(apdu);
                }
                if ins == Some(PSO_INS) && apdu.get(P1_INDEX) == Some(&PSO_CDS_P1) {
                    return respond(self.0.signature.clone(), StatusWord::Success);
                }
                if ins == Some(PSO_INS) || ins == Some(MSE_INS) {
                    return respond(Vec::new(), StatusWord::Success);
                }
                respond(Vec::new(), StatusWord::FileNotFound)
            }

            fn read_binary(&self, apdu: &[u8]) -> ResponseApdu {
                let (Some(&high), Some(&low), Some(&le)) =
                    (apdu.get(P1_INDEX), apdu.get(P2_INDEX), apdu.last())
                else {
                    return respond(Vec::new(), StatusWord::FileNotFound);
                };
                let file = match self.0.selected.get() {
                    Selected::Certificate => self.0.certificate.clone(),
                    Selected::TokenInfo => self.token_info(),
                };
                let offset = usize::from(u16::from_be_bytes([high, low]));
                let end = offset.saturating_add(usize::from(le)).min(file.len());
                let body = file.get(offset..end).map_or_else(Vec::new, <[u8]>::to_vec);
                respond(body, StatusWord::Success)
            }
        }

        fn respond(body: Vec<u8>, status: StatusWord) -> ResponseApdu {
            let [sw1, sw2] = status.as_u16().to_be_bytes();
            ResponseApdu { body, sw1, sw2 }
        }

        impl CardTransport for SyntheticCard {
            type Error = PcscError;

            fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
                Ok(TransportOutcome::Response(self.answer(command.as_bytes())))
            }

            fn transmit_credential(
                &mut self,
                command: CredentialCommand,
            ) -> Result<TransportOutcome, Self::Error> {
                let (ins, reference) = command.expose_wire(|wire| {
                    (wire.get(INS_INDEX).copied(), wire.get(P2_INDEX).copied())
                });
                self.0
                    .instructions
                    .borrow_mut()
                    .push(ins.unwrap_or_default());
                self.0
                    .credentials
                    .borrow_mut()
                    .push(reference.unwrap_or_default());
                Ok(TransportOutcome::Response(respond(
                    Vec::new(),
                    self.0.verify_answer,
                )))
            }
        }

        impl SigningSession for SyntheticCard {
            type Sequence<'a> = Self;

            fn reset_card(&mut self) -> Result<(), PcscError> {
                Ok(())
            }

            fn pin_sequence<R>(
                self,
                body: impl for<'a> FnOnce(Self::Sequence<'a>) -> R,
            ) -> Result<R, PcscError> {
                Ok(body(self))
            }
        }

        /// Readers and the card in them.
        struct SyntheticBackend {
            readers: Vec<ReaderInfo>,
            card: SyntheticCard,
        }

        impl SyntheticBackend {
            fn one_reader(card_present: bool, card: SyntheticCard) -> Self {
                Self {
                    readers: vec![ReaderInfo {
                        id: ReaderId::new(SYNTHETIC_READER.to_owned()),
                        card_present,
                        card_events: 0,
                    }],
                    card,
                }
            }
        }

        impl ReaderBackend for SyntheticBackend {
            type Transport = SyntheticCard;
            type Error = PcscError;

            fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
                Ok(self.readers.clone())
            }

            fn card_events(&self, _reader: &ReaderId) -> Result<u32, Self::Error> {
                Ok(0)
            }

            fn open_exclusive(
                &self,
                _reader: &ReaderId,
                _access: ReaderAccessCap,
            ) -> Result<Self::Transport, Self::Error> {
                Ok(self.card.clone())
            }
        }

        /// A boxed PIN prompt.
        type Prompt = Box<dyn FnMut(PinRole) -> Result<PinBytes, PinEntryError>>;

        /// A PIN source that counts its prompts and runs `during` inside
        /// each one.
        fn counting(during: impl Fn() + 'static) -> (PromptedPin<Prompt>, Rc<Cell<usize>>) {
            let asked = Rc::new(Cell::new(0_usize));
            let counter = Rc::clone(&asked);
            let source = PromptedPin::new(Box::new(move |_role| {
                counter.set(counter.get().saturating_add(1));
                during();
                PinBytes::new(SYNTHETIC_PIN.to_vec()).map_err(PinEntryError::NotAPin)
            }) as Prompt);
            (source, asked)
        }

        fn sign_on(
            backend: &SyntheticBackend,
            slot: SignSlot,
            pin: &mut dyn PinSource,
        ) -> Result<Result<SignReport, SignErrorKind>, Box<dyn core::error::Error>> {
            let dir = TempDir::new("sign-pin-late")?;
            let input = dir.write("message.txt", MESSAGE)?;
            let options = SignOptions {
                input,
                output: SignOutput::At(dir.path().join("signature.bin")),
                slot,
                save_cert: None,
                reader_filter: None,
                can: None,
                document: None,
            };
            Ok(sign(backend, options, pin))
        }

        /// The synthetic card cannot make a signature that verifies, so a
        /// flow that got past VERIFY ends at local verify.
        fn passed_verify(result: &Result<SignReport, SignErrorKind>) -> bool {
            matches!(
                result,
                Err(SignErrorKind::LocalVerifyFailed(_)
                    | SignErrorKind::UnexpectedSignatureLength(_))
            )
        }

        #[test]
        fn no_reader_fails_before_the_pin_is_asked() -> TestResult {
            let backend = SyntheticBackend {
                readers: Vec::new(),
                card: SyntheticCard::served()?,
            };
            let (mut pin, asked) = counting(|| {});
            let result = sign_on(&backend, SignSlot::Qualified, &mut pin)?;
            check_true(
                matches!(
                    result,
                    Err(SignErrorKind::ReaderPick(ReaderPickError::NoReaders))
                ),
                "no readers",
            )?;
            check(&asked.get(), &0, "prompts")
        }

        #[test]
        fn no_card_fails_before_the_pin_is_asked() -> TestResult {
            let backend = SyntheticBackend::one_reader(false, SyntheticCard::served()?);
            let (mut pin, asked) = counting(|| {});
            let result = sign_on(&backend, SignSlot::Qualified, &mut pin)?;
            check_true(
                matches!(
                    result,
                    Err(SignErrorKind::ReaderPick(ReaderPickError::NoCardPresent))
                ),
                "no card",
            )?;
            check(&asked.get(), &0, "prompts")
        }

        #[test]
        fn retry_floor_refuses_before_the_pin_is_asked() -> TestResult {
            let card = SyntheticCard::new(TRIES_BELOW_FLOOR, StatusWord::Success)?;
            let backend = SyntheticBackend::one_reader(true, card.clone());
            let (mut pin, asked) = counting(|| {});
            let result = sign_on(&backend, SignSlot::Qualified, &mut pin)?;
            check_true(
                matches!(result, Err(SignErrorKind::RetryFloor(_))),
                "retry floor",
            )?;
            check(&asked.get(), &0, "prompts")?;
            check(&card.credential_references().len(), &0, "no VERIFY")
        }

        #[test]
        fn a_served_card_asks_for_the_pin_once_and_verifies_the_slots_pin() -> TestResult {
            for (slot, pin_slot) in [
                (SignSlot::Qualified, PinSlot::Pin2),
                (SignSlot::Authentication, PinSlot::Pin1),
            ] {
                let card = SyntheticCard::served()?;
                let backend = SyntheticBackend::one_reader(true, card.clone());
                let (mut pin, asked) = counting(|| {});
                let result = sign_on(&backend, slot, &mut pin)?;
                check_true(passed_verify(&result), "flow passed VERIFY")?;
                check(&asked.get(), &1, "prompts")?;
                check(
                    &card.credential_references(),
                    &vec![PinReferenceScheme::Citizen.reference(pin_slot)],
                    "one VERIFY of the slot's PIN",
                )?;
            }
            Ok(())
        }

        #[test]
        fn a_card_changed_during_the_prompt_is_refused_before_verify() -> TestResult {
            let card = SyntheticCard::served()?;
            let backend = SyntheticBackend::one_reader(true, card.clone());
            let swapped = Rc::clone(&card.0);
            let (mut pin, asked) = counting(move || swapped.swapped.set(true));
            let result = sign_on(&backend, SignSlot::Qualified, &mut pin)?;
            check_true(
                matches!(
                    &result,
                    Err(SignErrorKind::DisplayedCard(detail))
                        if detail == CARD_CHANGED_DURING_PROMPT
                ),
                "card changed",
            )?;
            check(&asked.get(), &1, "prompts")?;
            check(&card.credential_references().len(), &0, "no VERIFY")
        }

        #[test]
        fn one_source_asks_once_for_several_documents() -> TestResult {
            let card = SyntheticCard::signing()?;
            let backend = SyntheticBackend::one_reader(true, card.clone());
            let (mut pin, asked) = counting(|| {});
            for _document in 0..2 {
                let report = sign_on(&backend, SignSlot::Qualified, &mut pin)??;
                check_true(report.local_verify.is_ok(), "signed and verified")?;
            }
            check(&asked.get(), &1, "asked once")?;
            check(
                &card.credential_references().len(),
                &2,
                "VERIFY per document",
            )
        }

        #[test]
        fn a_pin_typed_for_a_swapped_card_is_never_presented() -> TestResult {
            let card = SyntheticCard::served()?;
            let backend = SyntheticBackend::one_reader(true, card.clone());
            let swapped = Rc::clone(&card.0);
            let (mut pin, asked) = counting(move || swapped.swapped.set(true));
            let refused = sign_on(&backend, SignSlot::Qualified, &mut pin)?;
            check_true(
                matches!(&refused, Err(SignErrorKind::DisplayedCard(_))),
                "card changed",
            )?;
            let second = sign_on(&backend, SignSlot::Qualified, &mut pin)?;
            check_true(passed_verify(&second), "the new card is signed with")?;
            check(&asked.get(), &2, "asked again for the new card")?;
            check(
                &card.credential_references().len(),
                &1,
                "one VERIFY, with the PIN typed for the new card",
            )
        }

        #[test]
        fn a_pin_held_for_one_slot_is_not_given_to_the_other() -> TestResult {
            let card = SyntheticCard::signing()?;
            let backend = SyntheticBackend::one_reader(true, card.clone());
            let (mut pin, asked) = counting(|| {});
            for slot in [SignSlot::Qualified, SignSlot::Authentication] {
                let report = sign_on(&backend, slot, &mut pin)??;
                check_true(report.local_verify.is_ok(), "signed and verified")?;
            }
            check(&asked.get(), &2, "asked for each slot's PIN")?;
            check(
                &card.credential_references(),
                &vec![
                    PinReferenceScheme::Citizen.reference(PinSlot::Pin2),
                    PinReferenceScheme::Citizen.reference(PinSlot::Pin1),
                ],
                "each VERIFY targets its own slot",
            )
        }

        #[test]
        fn the_pin_transaction_selects_the_application_before_verify() -> TestResult {
            let dir = TempDir::new("sign-select-first")?;
            let input = dir.write("message.txt", MESSAGE)?;
            let options = SignOptions {
                input,
                output: SignOutput::At(dir.path().join("signature.bin")),
                slot: SignSlot::Qualified,
                save_cert: None,
                reader_filter: None,
                can: None,
                document: None,
            };
            let mut card = SyntheticCard::served()?;
            let prepared = prepare_on_card(&mut card, &options, MESSAGE)?;
            card.0.instructions.borrow_mut().clear();
            let pin = PinBytes::new(SYNTHETIC_PIN.to_vec())?;
            let committed = commit_in_transaction(
                &mut card,
                SignSlot::Qualified,
                &prepared,
                &pin,
                MESSAGE,
                Sha256::of(MESSAGE),
            );
            check_true(
                matches!(
                    committed,
                    Err(SignErrorKind::LocalVerifyFailed(_)
                        | SignErrorKind::UnexpectedSignatureLength(_))
                ),
                "passed VERIFY",
            )?;
            let instructions = card.instructions();
            check(
                &instructions.first().copied(),
                &Some(SelectByAidNoFci::INS),
                "the transaction opens with a SELECT",
            )?;
            let verify = instructions
                .iter()
                .rposition(|ins| *ins == VERIFY_INS)
                .ok_or("no VERIFY")?;
            check_true(verify > 0, "VERIFY after the SELECT")
        }

        #[test]
        fn a_refused_pin_is_asked_again_for_the_next_document() -> TestResult {
            let wrong = StatusWord::PinIncorrect {
                retries: PinRetries::from_nibble(TRIES_AFTER_WRONG).ok_or("counter")?,
            };
            let card = SyntheticCard::new(TRIES_SERVED, wrong)?;
            let backend = SyntheticBackend::one_reader(true, card);
            let (mut pin, asked) = counting(|| {});
            for _document in 0..2 {
                let result = sign_on(&backend, SignSlot::Qualified, &mut pin)?;
                check_true(
                    matches!(result, Err(SignErrorKind::PinRejected { .. })),
                    "PIN refused",
                )?;
            }
            check(&asked.get(), &2, "asked again after the refusal")
        }
    }
}
