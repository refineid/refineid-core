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

//! Signing with a card in this computer's reader.
//!
//! The one part of the service that needs PC/SC. The reader is picked
//! and the card session opened -- through PACE from the CAN on the
//! contactless interface -- the slot's certificate is read and the
//! document planned around it, the PIN is asked for and VERIFYed inside
//! one transaction that ends with a card reset, and the card's
//! signature is verified against that certificate before the document
//! is finished on the service's shared path.
//!
//! [`ReaderSignError`] names what fails here; what fails in the shared
//! part arrives as [`ReaderSignError::Document`].

use core::fmt;
use std::path::PathBuf;

use super::{
    AssembledDocument, DocumentRequest, LocalVerifyOutcome, SignErrorKind, SignOutput, SignReport,
    SignSlot, SigningDevice, document_signer, ensure_visible_signature_format, finish_document,
    load_data_objects, verify_against_certificate,
};
use crate::digest::Sha256;
use crate::document::{self, DocumentPlan};
use crate::identity::{CommonName, TokenSerial, render_token_serial};
use crate::pin::{PinBytes, PinEntryError, PinPolicyReason, PinRole, PinSource};
use crate::signed_name::BestSignatureTime;
use crate::x509_ext::NameExt;
use refineid_apdu::CardTransport;
use refineid_apdu::status_word::StatusWord;
use refineid_auth::credentials::{PIN_MAX_LENGTH, PIN1_MIN_LENGTH, PIN2_MIN_LENGTH};
use refineid_auth::{
    CredentialInputError, Pin1, Pin2, PinOps as _, PinReferenceScheme, PinSlot, RetryFloorRefusal,
    UnvalidatedSecret, VerifyOutcome, check_retry_floor,
};
use refineid_cms::x509::{
    Certificate, EcCurve, MessageSignatureAlgorithm, OwnedCert, PublicKeyAlgorithm,
};
use refineid_digest::Sha384 as CoreSha384;
use refineid_pace::{Can, PaceError, SmTransport, run_pace_with_can};
use refineid_pcsc::{
    PcscCard, PcscError, PcscTransactionCard, ReaderAccessCap, ReaderBackend,
    ReaderBackendOps as _, ReaderFilter, ReaderPickError,
};
use refineid_pkcs15::Pkcs15Ops as _;
use refineid_pkcs15::{CertSlot, Pkcs15Error, UnvalidatedCertificate};
use refineid_sign::{KeyRef, SignError, SignOps as _, SignScheme};

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
}

/// Why the flow refuses to VERIFY when the card in the reader after the
/// PIN prompt is not the card checked before it.
pub const CARD_CHANGED_DURING_PROMPT: &str = "the card changed while the PIN was entered";

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
    /// flow fails with [`ReaderSignError::NeedCan`] so the CLI can
    /// prompt and retry. Never logged.
    pub can: Option<Can>,
    /// The serial of the card the operator was shown, as EF.TokenInfo
    /// names it, when a trusted inspection view captured one. Compared
    /// with the card in the reader before the PIN is asked for and
    /// again inside the PIN transaction, so a card swap cannot spend
    /// the PIN on an undisplayed identity. `None` signs whichever card
    /// is present (the CLI).
    pub expected_serial: Option<TokenSerial>,
    /// Produce a signed document rather than raw signature bytes.
    ///
    /// `None` keeps the original behaviour: `--out` receives the
    /// signature the card computed over the input file, and nothing
    /// else.
    pub document: Option<DocumentRequest>,
}

/// Why the card in this computer's reader did not sign.
///
/// The reader, the card session, the PIN and the sign chain have their
/// own variants. What fails in the service's shared part -- the
/// request, the document, the timestamps, the files -- arrives as
/// [`Self::Document`], the same [`SignErrorKind`] the phone path
/// reports. Card-side outcomes that don't preclude further action
/// (wrong PIN with retries left, etc.) are folded into
/// [`Self::PinRejected`].
#[derive(Debug)]
pub enum ReaderSignError {
    /// Reader-selection failure (none / multiple / bad filter).
    ReaderPick(ReaderPickError),
    /// PC/SC connect / transmit error.
    Pcsc(PcscError),
    /// The live card is not the card the operator was shown; refused
    /// before PIN verification.
    DisplayedCard(String),
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
        /// "PSO:HASH", "PSO:Compute Digital Signature").
        stage: &'static str,
        /// Card-returned status word per ISO 7816-4 §5.1.3, as the
        /// raw wire value for the diagnostic.
        sw: u16,
    },
    /// Card returned a signature with the wrong length (e.g. an
    /// ECDSA card on this RSA-pinned path).
    UnexpectedSignatureLength(usize),
    /// The on-card cert is missing or unparseable.
    CertUnavailable {
        /// Which key's certificate was read.
        slot: SignSlot,
        /// Human-readable detail from the cert reader / parser.
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
    /// Cert + signature parsed but the local verify failed -- the card
    /// returned a signature that doesn't match the on-card public key
    /// over our input.
    LocalVerifyFailed(String),
    /// Lower-level transport / APDU failure not covered by the
    /// per-stage variants.
    Transport(String),
    /// The card sealed PKCS#15 behind PACE (contactless
    /// interface) and no CAN was provided to open it.
    NeedCan,
    /// PACE failed with the wrong-CAN signature: card-reported
    /// authentication failure or a mutual-auth tag mismatch.
    BadCan,
    /// PACE establishment failed for a non-CAN reason.
    Pace(String),
    /// The document's own failure, as the shared part of the service
    /// reports it: the request, the format, the certificate pairing,
    /// a timestamp authority, the long-term material, the input or
    /// the output file.
    Document(SignErrorKind),
}

impl fmt::Display for ReaderSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::DisplayedCard(detail) => write!(f, "displayed card: {detail}"),
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
            Self::PinEntry(error) => write!(f, "{error}"),
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
            Self::Document(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for ReaderSignError {}

impl From<PcscError> for ReaderSignError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for ReaderSignError {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

impl From<SignErrorKind> for ReaderSignError {
    fn from(e: SignErrorKind) -> Self {
        Self::Document(e)
    }
}

/// The local-policy refusal for a PIN that is not a valid `slot` PIN.
/// Nothing has been sent to the card, so no retry is spent.
fn pin_policy_refusal(slot: SignSlot, error: CredentialInputError) -> ReaderSignError {
    let reason = match error {
        CredentialInputError::NonDigit { .. } => PinPolicyReason::NonDigit,
        CredentialInputError::WrongLength {
            expected_min,
            expected_max,
            ..
        } => PinPolicyReason::WrongLength {
            min: expected_min,
            max: expected_max,
        },
        CredentialInputError::Empty { .. } => PinPolicyReason::WrongLength {
            min: match slot.pin_role() {
                PinRole::Pin1 => PIN1_MIN_LENGTH,
                PinRole::Pin2 => PIN2_MIN_LENGTH,
            },
            max: PIN_MAX_LENGTH,
        },
    };
    ReaderSignError::PinPolicy { slot, reason }
}

/// Ask the card which reference numbering it speaks.
///
/// A VERIFY status probe against an absent reference answers
/// `SW=6A88` without touching any retry counter, so the probe
/// costs one command and no risk.
fn resolve_pin_reference_scheme<T: CardTransport>(
    transport: &mut T,
) -> Result<PinReferenceScheme, ReaderSignError> {
    transport
        .resolve_pin_reference_scheme()
        .map_err(|e| ReaderSignError::Transport(format!("{e}")))
}

/// VERIFY `pin` for `slot` under the resolved `scheme`.
///
/// The typed digits become the slot's [`Pin1`] or [`Pin2`], so a PIN
/// outside that role's bounds is refused before any command. The citizen
/// card is sent the padded stored-length block, the organization card
/// the bare typed digits.
fn verify_pin_with_scheme<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    scheme: PinReferenceScheme,
    pin: &PinBytes,
) -> Result<VerifyOutcome, ReaderSignError> {
    let secret = || UnvalidatedSecret::from_owned_bytes(pin.as_bytes().to_vec());
    let verified = match slot.pin_role() {
        PinRole::Pin1 => {
            let pin1 = Pin1::reconstruct(secret()).map_err(|e| pin_policy_refusal(slot, e))?;
            transport.verify_pin1_with_scheme(scheme, pin1)
        }
        PinRole::Pin2 => {
            let pin2 = Pin2::reconstruct(secret()).map_err(|e| pin_policy_refusal(slot, e))?;
            transport.verify_pin2_with_scheme(scheme, pin2)
        }
    };
    verified.map_err(|e| ReaderSignError::Transport(format!("{e}")))
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
) -> Result<(Vec<u8>, LocalVerifyOutcome), ReaderSignError> {
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
            verify_against_certificate(
                cert,
                MessageSignatureAlgorithm::RsaPkcs1Sha256,
                input_bytes,
                signature.as_bytes(),
            )
            .map_err(ReaderSignError::LocalVerifyFailed)?;
            Ok((signature.into_bytes(), LocalVerifyOutcome::Ok))
        }
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
            let hash_sha384 = CoreSha384::of(input_bytes);
            let signature = transport
                .sign_prehashed_sha384_ecdsa(sign_scheme, slot.key_ref(), *hash_sha384.as_bytes())
                .map_err(sign_err_to_kind)?;
            verify_against_certificate(
                cert,
                MessageSignatureAlgorithm::EcdsaSha384Raw,
                input_bytes,
                signature.as_bytes(),
            )
            .map_err(ReaderSignError::LocalVerifyFailed)?;
            Ok((signature.into_bytes(), LocalVerifyOutcome::Ok))
        }
        PublicKeyAlgorithm::Ec(curve) => Err(ReaderSignError::UnsupportedCurve { slot, curve }),
        PublicKeyAlgorithm::Other => Err(ReaderSignError::UnsupportedKeyType(slot)),
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
/// Every failure surfaces as [`ReaderSignError`]: the reader, card,
/// PIN and sign-chain failures as its own variants, and the document's
/// own -- format, certificate pairing, timestamp, material, input and
/// output -- as [`ReaderSignError::Document`].
pub fn sign<B>(
    backend: &B,
    mut options: SignOptions,
    pin: &mut dyn PinSource,
) -> Result<SignReport, ReaderSignError>
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
                return Err(ReaderSignError::NeedCan);
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
                .map_err(|e| ReaderSignError::Pace(format!("reset before PACE: {e}")))?;
            // PACE's MSE:Set AT is only accepted in MF context: the
            // reset lands the card there already; selecting MF makes
            // the requirement explicit and survives a backend whose
            // reset leaves selection elsewhere.
            transport
                .select_mf()
                .map_err(|e| ReaderSignError::Pace(format!("SELECT MF before PACE: {e}")))?;
            let session =
                run_pace_with_can(&mut transport, can).map_err(|e| pace_err_to_kind(&e))?;
            let mut sm = SmTransport::new(transport, session);
            sm.select_pkcs15_application()
                .map_err(|e| ReaderSignError::CertUnavailable {
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
            return Err(ReaderSignError::CertUnavailable {
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
        device: SigningDevice::Reader(reader_id.as_str().to_owned()),
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
    verify: impl FnOnce(&PinBytes) -> Result<Committed, ReaderSignError>,
) -> Result<Committed, ReaderSignError> {
    let outcome = verify(
        pin.pin(slot.pin_role())
            .map_err(ReaderSignError::PinEntry)?,
    );
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
) -> Result<Committed, ReaderSignError> {
    transport
        .select_pkcs15_application()
        .map_err(|e| ReaderSignError::CertUnavailable {
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
) -> Result<Prepared, ReaderSignError> {
    let slot = options.slot;
    ensure_displayed_card(transport, options.expected_serial.as_ref())?;
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
        .map_err(|e| ReaderSignError::CertUnavailable {
            slot,
            detail: format!("read: {e}"),
        })?;
    let cert_owned =
        OwnedCert::from_der(cert_der.as_bytes()).map_err(|e| ReaderSignError::CertUnavailable {
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
            let cert = cert_owned.view();
            let parameters =
                document_signer(&cert, cert.spki.algorithm(), slot, request.signing_time)?;
            let objects = load_data_objects(&options.input, request, input_bytes)?;
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
) -> Result<(), ReaderSignError> {
    let status = transport
        .pin_status_with_scheme(scheme, slot.pin_slot())
        .map_err(|e| ReaderSignError::Transport(format!("{e}")))?;
    check_retry_floor(slot.pin_slot().into(), status).map_err(ReaderSignError::RetryFloor)
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
) -> Result<Committed, ReaderSignError> {
    if live_token_serial(transport)? != prepared.serial {
        return Err(ReaderSignError::DisplayedCard(
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
            return Err(ReaderSignError::PinRejected {
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
) -> Result<SignChainOutput, ReaderSignError> {
    let CardSignOutput {
        cert_der,
        cert_owned,
        pin_retries_after,
        signature_bytes,
        local_verify,
        plan,
    } = on_card;
    let cert_subject_cn = cert_owned.view().subject.common_name();
    let assembled = match (options.document.as_ref(), plan) {
        (Some(request), Some(plan)) => {
            finish_document(request, plan, &cert_owned, options.slot, &signature_bytes)?
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

/// Refuse to sign when the live card is not the one the operator saw.
///
/// Runs before PIN verification whenever a displayed serial was given,
/// for a bare signature and a document alike.
fn ensure_displayed_card<T: CardTransport>(
    transport: &mut T,
    expected: Option<&TokenSerial>,
) -> Result<(), ReaderSignError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let live = live_token_serial(transport)?;
    ensure_expected_serial(expected, live.as_ref())
}

/// The serial of the card in the reader, as EF.TokenInfo names it.
fn live_token_serial<T: CardTransport>(
    transport: &mut T,
) -> Result<Option<TokenSerial>, ReaderSignError> {
    let token = transport.read_token_info().map_err(|error| {
        ReaderSignError::DisplayedCard(format!("cannot re-read EF.TokenInfo: {error}"))
    })?;
    Ok(token.serial_number_hex().cloned().map(render_token_serial))
}

fn ensure_expected_serial(
    expected: &TokenSerial,
    live: Option<&TokenSerial>,
) -> Result<(), ReaderSignError> {
    match live {
        Some(live) if live == expected => Ok(()),
        Some(_different) => Err(ReaderSignError::DisplayedCard(
            "the card in the reader is not the card displayed by the application".to_owned(),
        )),
        None => Err(ReaderSignError::DisplayedCard(
            "the card does not publish a PKCS#15 serial for session binding".to_owned(),
        )),
    }
}

/// Hoist [`PaceError`] onto [`ReaderSignError`], with the
/// same wrong-CAN classification `emrtd::read_personal_data`
/// applies: a card-reported authentication failure or a
/// mutual-auth tag mismatch both mean the CAN-derived key
/// disagreed with the card.
fn pace_err_to_kind<TE: fmt::Display>(e: &PaceError<TE>) -> ReaderSignError {
    match e {
        PaceError::Status(_, sw) if *sw == StatusWord::AuthenticationFailed => {
            ReaderSignError::BadCan
        }
        PaceError::AuthMismatch => ReaderSignError::BadCan,
        _ => ReaderSignError::Pace(format!("{e}")),
    }
}

/// Hoist [`SignError`] variants onto [`ReaderSignError`].
fn sign_err_to_kind<TE: fmt::Display>(e: SignError<TE>) -> ReaderSignError {
    match e {
        SignError::Transport(t) => ReaderSignError::Transport(format!("{t}")),
        SignError::Outcome(outcome) => ReaderSignError::Transport(format!("{outcome}")),
        SignError::Status(stage, sw) => ReaderSignError::SignSw {
            stage,
            sw: sw.as_u16(),
        },
        SignError::Command(err) => ReaderSignError::Transport(format!("{err}")),
        SignError::UnexpectedSignatureLength { got, .. } => {
            ReaderSignError::UnexpectedSignatureLength(got)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};
    use refineid_apdu::PinRetries;

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

    // ---- ReaderSignError Display: each arm renders an
    // operator-facing line; the PIN arms also pivot on the slot
    // label and the VerifyOutcome shape. ----

    fn pin_retries(n: u8) -> Result<PinRetries, Box<dyn core::error::Error>> {
        PinRetries::from_nibble(n).ok_or_else(|| "bad nibble".into())
    }

    #[test]
    fn pin_rejected_display_renders_the_pin_and_outcome() -> TestResult {
        let wrong = ReaderSignError::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::WrongPin {
                retries_left: pin_retries(2)?,
            },
        }
        .to_string();
        check_true(wrong.contains("PIN2"), "wrong-pin label")?;
        check_true(wrong.contains("wrong PIN"), "wrong-pin reason")?;
        check_true(wrong.contains("retries left"), "wrong-pin counter")?;

        let locked = ReaderSignError::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::Locked,
        }
        .to_string();
        check_true(locked.contains("PIN2"), "locked label")?;
        check_true(locked.contains("blocked"), "locked reason")?;

        let other = ReaderSignError::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::Other(StatusWord::Other(0x6A88)),
        }
        .to_string();
        check_true(other.contains("0x6A88"), "other sw rendered")?;

        // The internal "can't happen" arm still renders a line
        // rather than panicking.
        let internal = ReaderSignError::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::Ok,
        }
        .to_string();
        check_true(internal.contains("internal"), "ok-outcome guard")
    }

    #[test]
    fn sign_chain_and_crypto_error_display() -> TestResult {
        check_true(
            ReaderSignError::PinPolicy {
                slot: SignSlot::Qualified,
                reason: PinPolicyReason::NonDigit,
            }
            .to_string()
            .contains("PIN2 rejected locally"),
            "pin policy",
        )?;
        check_true(
            ReaderSignError::SignSw {
                stage: "PSO:HASH",
                sw: 0x6A80,
            }
            .to_string()
            .contains("PSO:HASH: SW=0x6A80"),
            "sign sw stage + sw",
        )?;
        check_true(
            ReaderSignError::UnexpectedSignatureLength(256)
                .to_string()
                .contains("256-byte signature; expected 384"),
            "bad sig length",
        )?;
        check_true(
            ReaderSignError::CertUnavailable {
                slot: SignSlot::Qualified,
                detail: "read: timeout".to_owned(),
            }
            .to_string()
            .contains("qualified-signature cert unavailable for local verify: read: timeout"),
            "cert unavailable",
        )?;
        check_true(
            ReaderSignError::UnsupportedKeyType(SignSlot::Qualified)
                .to_string()
                .contains("qualified-signature cert has an unsupported key type"),
            "unsupported key type",
        )?;
        check_true(
            ReaderSignError::UnsupportedCurve {
                slot: SignSlot::Qualified,
                curve: EcCurve::Secp256r1,
            }
            .to_string()
            .contains("only signs ECDSA on secp384r1"),
            "unsupported curve",
        )?;
        check_true(
            ReaderSignError::LocalVerifyFailed("digest mismatch".to_owned())
                .to_string()
                .contains("local verify failed: digest mismatch"),
            "local verify failed",
        )?;
        check_true(
            ReaderSignError::Transport("reader vanished".to_owned())
                .to_string()
                .contains("transport: reader vanished"),
            "transport",
        )
    }

    // ---- sign_err_to_kind: SignError -> ReaderSignError, shared by
    // the RSA and ECDSA branches. ----

    #[test]
    fn sign_err_to_kind_maps_each_variant() -> TestResult {
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::Transport("boom")),
                ReaderSignError::Transport(_)
            ),
            "transport",
        )?;
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::Status(
                    "PSO:CDS",
                    StatusWord::from_u16(0x6982)
                )),
                ReaderSignError::SignSw {
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
                ReaderSignError::UnexpectedSignatureLength(48)
            ),
            "unexpected length",
        )
    }

    #[test]
    fn each_slot_names_its_own_key_and_certificate() -> TestResult {
        check(
            &SignSlot::Authentication.key_ref(),
            &KeyRef::Auth,
            "auth key",
        )?;
        check(&SignSlot::Qualified.key_ref(), &KeyRef::Sign, "sign key")?;
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
            CARD_CHANGED_DURING_PROMPT, ReaderSignError, Sha256, SignOptions, SignOutput,
            SignReport, SignSlot, SigningSession, commit_in_transaction, prepare_on_card, sign,
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
        const CERTIFICATE: &[u8] = include_bytes!("../../trust-anchors/dvv-gov-root-ca-g3-rsa.der");
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
        ) -> Result<Result<SignReport, ReaderSignError>, Box<dyn core::error::Error>> {
            let dir = TempDir::new("sign-pin-late")?;
            let input = dir.write("message.txt", MESSAGE)?;
            let options = SignOptions {
                input,
                output: SignOutput::At(dir.path().join("signature.bin")),
                slot,
                save_cert: None,
                reader_filter: None,
                can: None,
                expected_serial: None,
                document: None,
            };
            Ok(sign(backend, options, pin))
        }

        /// The synthetic card cannot make a signature that verifies, so a
        /// flow that got past VERIFY ends at local verify.
        fn passed_verify(result: &Result<SignReport, ReaderSignError>) -> bool {
            matches!(
                result,
                Err(ReaderSignError::LocalVerifyFailed(_)
                    | ReaderSignError::UnexpectedSignatureLength(_))
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
                    Err(ReaderSignError::ReaderPick(ReaderPickError::NoReaders))
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
                    Err(ReaderSignError::ReaderPick(ReaderPickError::NoCardPresent))
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
                matches!(result, Err(ReaderSignError::RetryFloor(_))),
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
                    Err(ReaderSignError::DisplayedCard(detail))
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
                matches!(&refused, Err(ReaderSignError::DisplayedCard(_))),
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
                expected_serial: None,
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
                    Err(ReaderSignError::LocalVerifyFailed(_)
                        | ReaderSignError::UnexpectedSignatureLength(_))
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
                    matches!(result, Err(ReaderSignError::PinRejected { .. })),
                    "PIN refused",
                )?;
            }
            check(&asked.get(), &2, "asked again after the refusal")
        }
    }

    // ---- Signing VERIFY wire: the slot's PIN role bounds the typed
    // digits, and the organization card is sent them bare. ----
    mod verify_wire {
        use refineid_apdu::{
            CardTransport, CommandApdu, CredentialCommand, ResponseApdu, StatusWord,
            TransportOutcome,
        };
        use refineid_auth::credentials::{PIN_MAX_LENGTH, PIN2_MIN_LENGTH};
        use refineid_auth::{PinReferenceScheme, PinSlot};

        use super::super::{ReaderSignError, SignSlot, verify_pin_with_scheme};
        use crate::pin::{PinBytes, PinPolicyReason};
        use crate::test_util::{TestResult, check, check_true};

        /// Offset of P2 in a command APDU (ISO 7816-4 s5.1).
        const P2_INDEX: usize = 3;
        /// Offset of `Lc` in a short command APDU (ISO 7816-4 s5.1).
        const LC_INDEX: usize = 4;
        /// Offset of a short command's data field: the header and `Lc`.
        const DATA_INDEX: usize = LC_INDEX + 1;
        /// A PIN at the longest length either role accepts.
        const LONGEST_PIN: &[u8] = b"135792468024";

        /// Records every credential command's wire and accepts it.
        #[derive(Default)]
        struct Recorder {
            commands: Vec<Vec<u8>>,
        }

        impl CardTransport for Recorder {
            type Error = String;

            fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
                self.commands.push(command.as_bytes().to_vec());
                Ok(TransportOutcome::Response(success()))
            }

            fn transmit_credential(
                &mut self,
                command: CredentialCommand,
            ) -> Result<TransportOutcome, Self::Error> {
                self.commands.push(command.expose_wire(<[u8]>::to_vec));
                Ok(TransportOutcome::Response(success()))
            }
        }

        fn success() -> ResponseApdu {
            let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
            ResponseApdu {
                body: Vec::new(),
                sw1,
                sw2,
            }
        }

        #[test]
        fn organization_signing_verify_sends_a_twelve_digit_pin_unpadded() -> TestResult {
            check(&LONGEST_PIN.len(), &PIN_MAX_LENGTH, "fixture length")?;
            for (slot, pin_slot) in [
                (SignSlot::Qualified, PinSlot::Pin2),
                (SignSlot::Authentication, PinSlot::Pin1),
            ] {
                let mut card = Recorder::default();
                let pin = PinBytes::new(LONGEST_PIN.to_vec())?;
                let scheme = PinReferenceScheme::Organizational;
                verify_pin_with_scheme(&mut card, slot, scheme, &pin)?;
                let [wire] = card.commands.as_slice() else {
                    return Err("one VERIFY".into());
                };
                check(
                    &wire.get(P2_INDEX).copied(),
                    &Some(scheme.reference(pin_slot)),
                    "organization reference",
                )?;
                check(
                    &wire.get(LC_INDEX).copied().map(usize::from),
                    &Some(LONGEST_PIN.len()),
                    "Lc is the typed length",
                )?;
                check(&wire.get(DATA_INDEX..), &Some(LONGEST_PIN), "bare digits")?;
            }
            Ok(())
        }

        #[test]
        fn a_pin2_below_the_minimum_is_refused_before_any_command() -> TestResult {
            for scheme in [
                PinReferenceScheme::Citizen,
                PinReferenceScheme::Organizational,
            ] {
                let mut card = Recorder::default();
                let short = PinBytes::new(LONGEST_PIN[..PIN2_MIN_LENGTH - 1].to_vec())?;
                let refused =
                    verify_pin_with_scheme(&mut card, SignSlot::Qualified, scheme, &short);
                check_true(
                    matches!(
                        refused,
                        Err(ReaderSignError::PinPolicy {
                            slot: SignSlot::Qualified,
                            reason: PinPolicyReason::WrongLength {
                                min: PIN2_MIN_LENGTH,
                                max: PIN_MAX_LENGTH,
                            },
                        })
                    ),
                    "PIN 2 policy refusal",
                )?;
                check_true(card.commands.is_empty(), "no command sent")?;
            }
            Ok(())
        }

        #[test]
        fn a_thirteen_digit_pin_never_becomes_a_pin() -> TestResult {
            let mut longer = LONGEST_PIN.to_vec();
            longer.extend_from_slice(&LONGEST_PIN[..1]);
            check(&longer.len(), &(PIN_MAX_LENGTH + 1), "fixture length")?;
            check_true(PinBytes::new(longer).is_err(), "refused at entry")
        }
    }
}
