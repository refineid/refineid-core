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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! PKCS#15 file-system access on FINEID and Estonian eID cards.
//!
//! The operations layer on any [`CardTransport`]: a plain transport on
//! the contact interface, or a secure-messaging transport once PACE has
//! produced session keys. Certificate files are not PIN-protected;
//! every command issued here is replay-safe.

use core::fmt;

use refineid_apdu::iso7816::{
    AbsolutePath, DirectOffset15, ReadBinary, ReadBinaryOffset, SelectByAidNoFci, SelectEfNoFci,
    SelectFile, SelectFileResponseMode, SelectFileTarget,
};
use refineid_apdu::{
    Aid, AidError, ApduClass, CardTransport, CommandApdu, CommandDataError, CommandHeader, FileId,
    ResponseApdu, StatusWord, TransportOutcome,
};
use refineid_x509::UnvalidatedCertificate;

use crate::aod::{AuthenticationObjects, AuthenticationObjectsRead};
use crate::directory::{
    ApplicationDirectory, ApplicationDirectoryRead, ApplicationLabel,
    AuthenticationCredentialLookup, CertificateDirectory, CertificateDirectoryRead,
    CertificateRead, CredentialDirectory, DerCertificate, DirectoryLookup,
    DiscoveredAuthenticationProfile, DiscoveredQualifiedSignatureProfile, EF_DIR_FID, EF_ODF_FID,
    ESTONIAN_EID_APPLICATION_LABEL, FileContent, FileEnd, ObjectClass, ObjectDirectory,
    ObjectDirectoryRead, Pkcs15Path, PrivateKeyDirectory, PrivateKeyDirectoryRead,
    QualifiedSignatureCredentialLookup,
};

/// The PKCS#15 application identifier the FINEID card publishes per
/// FINEID S4-2 section 3.1. It is the registered application provider
/// identifier -- the opaque five-byte RID `A0 00 00 00 63` that ISO
/// 7816-5 assigns to PKCS#15 -- followed by the ASCII application name
/// `PKCS-15`, written below as character literals.
pub const PKCS15_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x00, 0x63, b'P', b'K', b'C', b'S', b'-', b'1', b'5',
];

// Compile-time guard: an accidental edit taking the AID outside the ISO
// 7816-5 length range fails the build instead of a runtime path.
const _PKCS15_AID_LENGTH_GUARD: () =
    assert!(PKCS15_AID.len() >= Aid::MIN_LENGTH && PKCS15_AID.len() <= Aid::MAX_LENGTH);

/// The DF.ESIGN application identifier, ASCII `E.SIGN`, published by
/// FINEID S4-2 v4.0 section 4.6.21 for the organizational card's
/// qualified-signature directory.
pub const ESIGN_AID: &[u8] = b"E.SIGN";

// Compile-time guard: keep the published directory name inside the
// ISO 7816-5 AID length range accepted by the typed SELECT builder.
const _ESIGN_AID_LENGTH_GUARD: () =
    assert!(ESIGN_AID.len() >= Aid::MIN_LENGTH && ESIGN_AID.len() <= Aid::MAX_LENGTH);

/// EF.4331, the authentication certificate, per FINEID S4-2 section 3.
pub const EF_AUTH_CERT_FID: FileId = FileId::from_u16(0x4331);
/// EF.4332, the qualified-signature certificate.
pub const EF_SIGN_CERT_FID: FileId = FileId::from_u16(0x4332);
/// EF.4333, the second authentication slot on dual-algorithm cards.
pub const EF_AUTH_CERT_ALT_FID: FileId = FileId::from_u16(0x4333);
/// DF.DD, the Estonian personal-data directory on the 2025 platform.
pub const DF_ESTONIAN_PERSONAL_DATA_FID: FileId = FileId::from_u16(0xDFDD);
/// DF.AWP (`ADF1`), the EstEID 2025 authentication certificate directory
/// (`GED24035_015` section 8.5).
pub const DF_ESTONIAN_AWP_FID: FileId = FileId::from_u16(0xADF1);
/// DF.QSCD (`ADF2`), the EstEID 2025 qualified-signature certificate
/// directory (`GED24035_015` section 8.5).
pub const DF_ESTONIAN_QSCD_FID: FileId = FileId::from_u16(0xADF2);
/// EF.3411 under `ADF1`, the EstEID 2025 authentication certificate
/// (`GED24035_015` section 8.5).
pub const EF_ESTONIAN_2025_AUTH_CERT_FID: FileId = FileId::from_u16(0x3411);
/// EF.3421 under `ADF2`, the EstEID 2025 qualified-signature certificate
/// (`GED24035_015` section 8.5).
pub const EF_ESTONIAN_2025_SIGN_CERT_FID: FileId = FileId::from_u16(0x3421);
/// EF.5007 under DF.DD, PD7 Document number on the 2025 platform: the
/// number the card body prints, as plain ASCII with no TLV wrapper
/// (GED24035, section 6.1). Readable without a PIN.
pub const EF_ESTONIAN_DOCUMENT_NUMBER_FID: FileId = FileId::from_u16(0x5007);
/// EF.D003, the document-number file on the earlier platforms: a DER
/// TLV directly under the MF (ID1 Developer Guide 2019, section 6.1).
pub const EF_ESTONIAN_DOCUMENT_NUMBER_LEGACY_FID: FileId = FileId::from_u16(0xD003);
/// EF.4334, the on-card root CA certificate; lives directly under the
/// MF.
pub const EF_ROOT_CA_FID: FileId = FileId::from_u16(0x4334);
/// EF.4335, the second qualified-signature slot.
pub const EF_SIGN_CERT_ALT_FID: FileId = FileId::from_u16(0x4335);
/// EF.4336, the on-card issuing intermediate CA certificate; lives
/// directly under the MF.
pub const EF_ISSUING_CA_ECC_FID: FileId = FileId::from_u16(0x4336);
/// PKCS#15 EF.TokenInfo: card label, manufacturer, and serial.
pub const EF_TOKEN_INFO_FID: FileId = FileId::from_u16(0x5032);
/// DF.ESIGN's file identifier, the citizen-card signature-directory
/// fallback when the card does not publish the organizational
/// [`ESIGN_AID`] name.
pub const DF_ESIGN_FID: FileId = FileId::from_u16(0x5016);

/// Where a slot lives in the card's file tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotPath {
    /// Direct child of the PKCS#15 application DF.
    UnderPkcs15App,
    /// Lives under the signature directory beneath the MF.
    UnderEsignDirectory,
    /// Lives directly under the MF.
    UnderMf,
}

/// One slot in the FINEID certificate directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSlot {
    /// Authentication certificate (EF.4331): TLS client
    /// authentication and related use.
    Authentication,
    /// Qualified-signature certificate (EF.4332).
    Signature,
    /// Second authentication slot (EF.4333); the algorithm is not fixed
    /// by the slot, so consumers parse the DER to see what is there.
    AuthenticationAlt,
    /// On-card copy of the issuing root CA (EF.4334); algorithm varies
    /// by card generation.
    RootCa,
    /// Second qualified-signature slot (EF.4335).
    SignatureAlt,
    /// On-card issuing intermediate CA (EF.4336); the certificate that
    /// chains the authentication leaf toward the root, published so a
    /// TLS client can send the full chain (FINEID S2 section 5.1,
    /// S4-1 v4.2 section 8.1.16).
    IssuingCaEcc,
}

impl CertSlot {
    /// This slot's two-byte file identifier.
    #[must_use]
    pub const fn fid(self) -> FileId {
        match self {
            Self::Authentication => EF_AUTH_CERT_FID,
            Self::Signature => EF_SIGN_CERT_FID,
            Self::AuthenticationAlt => EF_AUTH_CERT_ALT_FID,
            Self::RootCa => EF_ROOT_CA_FID,
            Self::SignatureAlt => EF_SIGN_CERT_ALT_FID,
            Self::IssuingCaEcc => EF_ISSUING_CA_ECC_FID,
        }
    }

    /// Human-readable label for report output and error messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Authentication => "authentication (EF.4331)",
            Self::Signature => "qualified signature (EF.4332)",
            Self::AuthenticationAlt => "authentication, alt slot (EF.4333)",
            Self::RootCa => "on-card issuing root CA (EF.4334)",
            Self::SignatureAlt => "qualified signature, alt slot (EF.4335)",
            Self::IssuingCaEcc => "issuing intermediate CA (EF.4336)",
        }
    }

    /// Directory location of this slot's EF, per FINEID S4-1 section 8.1
    /// and FINEID S4-2 v4.0 section 4.6:
    /// the authentication certificate sits directly under the PKCS#15
    /// application, the signature and alternate slots under the
    /// signature directory, and the CA copies under the MF.
    const fn path(self) -> SlotPath {
        match self {
            Self::Authentication => SlotPath::UnderPkcs15App,
            Self::Signature | Self::AuthenticationAlt | Self::SignatureAlt => {
                SlotPath::UnderEsignDirectory
            }
            Self::RootCa | Self::IssuingCaEcc => SlotPath::UnderMf,
        }
    }

    /// `true` when reaching this slot walks out to the MF.
    ///
    /// This matters over a PACE secure channel: selecting the MF tears
    /// the channel down on FINEID cards, observed on production
    /// hardware, so the next wrapped command fails with a
    /// secure-messaging status and the session is lost. Contactless
    /// callers skip these slots; only
    /// [`CertSlot::Authentication`] stays inside the PKCS#15
    /// application.
    #[must_use]
    pub const fn requires_mf_traversal(self) -> bool {
        !matches!(self.path(), SlotPath::UnderPkcs15App)
    }

    /// Number of slots [`CertSlot::all`] probes.
    pub const PROBED_SLOTS: usize = 5;

    /// The certificate slots a FINEID card may publish, in directory
    /// order. Callers probe each; an absent slot answers SELECT with
    /// [`StatusWord::FileNotFound`], which is "not provisioned", not an
    /// error.
    #[must_use]
    pub const fn all() -> [Self; Self::PROBED_SLOTS] {
        [
            Self::Authentication,
            Self::Signature,
            Self::AuthenticationAlt,
            Self::RootCa,
            Self::SignatureAlt,
        ]
    }
}

/// Bytes requested per READ BINARY. Short-APDU responses top out at
/// 256 bytes and CCID readers move at most their declared message
/// length, so 223 leaves headroom for status words and transport
/// framing on every reader while nearly halving round trips against
/// the 128-byte FINEID published examples. The same ceiling keeps a
/// secure-messaging span inside one short-APDU response, so protected
/// reads never fragment. Cards that honor less answer short reads or
/// wrong-Le, which the read loops and the transport already absorb.
const READ_CHUNK: u8 = 0xDF;
/// `Le = 0` asks for the full 256-byte short-response window; some cards
/// answer a shorter request over a small EF with end-of-file and no data.
const READ_LE_256: u8 = 0x00;
/// One extra byte requested past a valid document number so an overlong
/// EF.5007 is observed and rejected rather than truncated.
const OVERLONG_PROBE_SLACK: usize = 1;
/// Read cap for plain-ASCII EF.5007: one byte past a valid document number.
const DOCUMENT_NUMBER_PROBE_CAP: usize = crate::DOCUMENT_NUMBER_CHARS + OVERLONG_PROBE_SLACK;

/// Hard cap on one object read. FINEID certificates are under two
/// kibibytes; a sixteen-kibibyte ceiling leaves room for variants while
/// bounding a runaway read.
pub const MAX_OBJECT_BYTES: usize = 0x4000;

/// The DER length field was malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MalformedDerLength;

/// Total encoded length of the single-byte-tag DER object at the start
/// of `prefix`, once its complete length field is present. `Ok(None)`
/// means the header is not complete yet.
fn der_object_total_length(prefix: &[u8]) -> Result<Option<usize>, MalformedDerLength> {
    /// Tag byte plus the first length octet.
    const TAG_AND_FIRST_LENGTH_OCTET: usize = 2;
    /// Long-form length octets supported here, matching the bounded
    /// subset FINEID objects use.
    const MAXIMUM_LENGTH_OCTETS: usize = 2;
    /// Bit distinguishing the long form in the first length octet.
    const LONG_FORM_MASK: u8 = 0x80;
    /// Low bits of the first length octet carrying the octet count.
    const LENGTH_COUNT_MASK: u8 = 0x7F;

    if prefix.len() < TAG_AND_FIRST_LENGTH_OCTET {
        return Ok(None);
    }
    let first = prefix[1];
    if first & LONG_FORM_MASK == 0 {
        return TAG_AND_FIRST_LENGTH_OCTET
            .checked_add(usize::from(first))
            .map(Some)
            .ok_or(MalformedDerLength);
    }

    let octet_count = usize::from(first & LENGTH_COUNT_MASK);
    if octet_count == 0 || octet_count > MAXIMUM_LENGTH_OCTETS {
        return Err(MalformedDerLength);
    }
    let header_len = TAG_AND_FIRST_LENGTH_OCTET
        .checked_add(octet_count)
        .ok_or(MalformedDerLength)?;
    if prefix.len() < header_len {
        return Ok(None);
    }

    let mut content_len = 0_usize;
    for byte in &prefix[TAG_AND_FIRST_LENGTH_OCTET..header_len] {
        content_len = content_len
            .checked_shl(u8::BITS)
            .and_then(|length| length.checked_add(usize::from(*byte)))
            .ok_or(MalformedDerLength)?;
    }
    header_len
        .checked_add(content_len)
        .map(Some)
        .ok_or(MalformedDerLength)
}

/// Error returned from PKCS#15 reads.
#[derive(Debug)]
pub enum Pkcs15Error<E> {
    /// Adapter-level transport failure.
    Transport(E),
    /// Transport-level state transition instead of a response.
    Outcome(TransportOutcome),
    /// Card returned a non-success status word.
    Status(StatusWord),
    /// An AID constant fell outside the ISO 7816-5 length range; kept
    /// as a typed path even though the compile-time guards on
    /// [`PKCS15_AID`] and [`ESIGN_AID`] make it unreachable.
    Aid(AidError),
    /// A typed command rejected its data field; unreachable for the
    /// two-byte file identifiers issued here, kept fail-closed.
    Command(CommandDataError),
    /// A read returned no bytes.
    Empty,
    /// The object exceeds [`MAX_OBJECT_BYTES`].
    TooLarge,
    /// A read-and-parse step received bytes the parser could not decode;
    /// the label names the element that failed.
    InvalidData(&'static str),
}

impl<E: fmt::Display> fmt::Display for Pkcs15Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "PKCS#15 transport: {e}"),
            Self::Outcome(outcome) => write!(f, "PKCS#15 transport state: {outcome}"),
            Self::Status(sw) => write!(f, "PKCS#15: card returned {sw}"),
            Self::Aid(e) => write!(f, "PKCS#15: AID constant rejected: {e}"),
            Self::Command(e) => write!(f, "PKCS#15: command rejected its data: {e}"),
            Self::Empty => f.write_str("PKCS#15: read returned no bytes"),
            Self::TooLarge => {
                write!(f, "PKCS#15: object exceeds {MAX_OBJECT_BYTES} bytes")
            }
            Self::InvalidData(what) => write!(f, "PKCS#15: malformed {what}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display + 'static> core::error::Error for Pkcs15Error<E> {}

/// Transmit one replay-safe command and demand a real response.
fn exchange<T: CardTransport + ?Sized>(
    transport: &mut T,
    command: &CommandApdu,
) -> Result<ResponseApdu, Pkcs15Error<T::Error>> {
    transport
        .transmit(command)
        .map_err(Pkcs15Error::Transport)?
        .into_response()
        .map_err(Pkcs15Error::Outcome)
}

/// Issue each SELECT variant in order until one succeeds; FINEID card
/// generations disagree on which variants they accept.
fn select_with_variants<T: CardTransport + ?Sized, I>(
    transport: &mut T,
    variants: I,
) -> Result<(), Pkcs15Error<T::Error>>
where
    I: IntoIterator<Item = CommandApdu>,
{
    let mut last = StatusWord::Other(0);
    for command in variants {
        let response = exchange(transport, &command)?;
        if response.is_ok() {
            return Ok(());
        }
        last = response.status_word();
    }
    Err(Pkcs15Error::Status(last))
}

/// P1: select a child DF under the current DF, a FINEID S1 v4.2
/// section 3.2.2 mode the typed SELECT builder does not model.
const P1_SELECT_CHILD_DF: u8 = 0x01;
/// P1: select a DF or MF by name; some FINEID variants accept the MF
/// identifier through this mode.
const P1_SELECT_BY_NAME: u8 = 0x04;
/// P1: select by relative path from the current DF (ISO/IEC 7816-4
/// table 39).
const P1_SELECT_PATH_FROM_CURRENT_DF: u8 = 0x09;
/// P2: return no response data, shared with the typed SELECT builder.
const P2_NO_RESPONSE_DATA: u8 = SelectFileResponseMode::None.as_p2();
/// Single-octet READ BINARY probe used at [`MAX_OBJECT_BYTES`] to
/// distinguish an exact-cap file from an incomplete read.
const ONE_BYTE_EOF_PROBE: u8 = 1;

/// Whether a SELECT status word signals a security-channel refusal
/// that must propagate immediately instead of triggering a fallback
/// SELECT variant.
const fn stops_select_fallback(sw: StatusWord) -> bool {
    matches!(
        sw,
        StatusWord::SecurityNotSatisfied | StatusWord::SmDataObjectsIncorrect
    )
}

/// Build the relative-path SELECT variant from the current DF, with no
/// response data.
fn select_relative_path_variant<E>(steps: &[FileId]) -> Result<CommandApdu, Pkcs15Error<E>> {
    let mut data = Vec::with_capacity(steps.len().saturating_mul(FileId::LENGTH));
    for fid in steps {
        data.extend_from_slice(fid.as_bytes());
    }
    CommandApdu::case_3(
        CommandHeader {
            class: ApduClass::Plain,
            instruction: SelectFile::INS,
            p1: P1_SELECT_PATH_FROM_CURRENT_DF,
            p2: P2_NO_RESPONSE_DATA,
        },
        &data,
    )
    .map_err(Pkcs15Error::Command)
}

/// Build the absolute-path SELECT variant without response data
/// (ISO/IEC 7816-4 P1=08, P2=0C).
fn select_path_no_fci_variant(path: &AbsolutePath) -> CommandApdu {
    SelectFile {
        class: ApduClass::Plain,
        target: SelectFileTarget::AbsolutePath(path.clone()),
        response_mode: SelectFileResponseMode::None,
    }
    .into_apdu()
}

/// Build the by-name SELECT variant carrying a file identifier as the
/// name.
fn select_by_name_variant<E>(fid: FileId) -> Result<CommandApdu, Pkcs15Error<E>> {
    CommandApdu::case_3(
        CommandHeader {
            class: ApduClass::Plain,
            instruction: SelectFile::INS,
            p1: P1_SELECT_BY_NAME,
            p2: P2_NO_RESPONSE_DATA,
        },
        fid.as_bytes(),
    )
    .map_err(Pkcs15Error::Command)
}

/// Build the child-DF SELECT variant.
fn select_child_df_variant<E>(fid: FileId) -> Result<CommandApdu, Pkcs15Error<E>> {
    CommandApdu::case_3(
        CommandHeader {
            class: ApduClass::Plain,
            instruction: SelectFile::INS,
            p1: P1_SELECT_CHILD_DF,
            p2: P2_NO_RESPONSE_DATA,
        },
        fid.as_bytes(),
    )
    .map_err(Pkcs15Error::Command)
}

/// Build the full-path SELECT variant: every file identifier in
/// `path` is one step from the MF, sent in a single Case 4 command
/// requesting the FCP template.
fn select_path_variant(path: &AbsolutePath) -> CommandApdu {
    SelectFile {
        class: ApduClass::Plain,
        target: SelectFileTarget::AbsolutePath(path.clone()),
        response_mode: SelectFileResponseMode::Fcp,
    }
    .into_apdu()
}

/// Build the any-file-by-identifier SELECT variant.
fn select_any_by_fid_variant(fid: FileId) -> CommandApdu {
    SelectFile {
        class: ApduClass::Plain,
        target: SelectFileTarget::AnyByFileId(Some(fid)),
        response_mode: SelectFileResponseMode::None,
    }
    .into_apdu()
}

/// PKCS#15 file-system operations, layered as default methods on every
/// [`CardTransport`].
pub trait Pkcs15Ops: CardTransport {
    /// SELECT any application by AID, with no response data.
    ///
    /// # Errors
    ///
    /// Transport failures or a non-success status word.
    fn select_application(&mut self, aid: &Aid) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let command = SelectByAidNoFci { aid: aid.clone() }.into_apdu();
        let response = exchange(self, &command)?;
        if !response.is_ok() {
            return Err(Pkcs15Error::Status(response.status_word()));
        }
        Ok(())
    }

    /// SELECT the standard PKCS#15 application by [`PKCS15_AID`], with
    /// no response data.
    ///
    /// # Errors
    ///
    /// Transport failures or a non-success status word.
    fn select_pkcs15_application(&mut self) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let aid = Aid::from_slice(PKCS15_AID).map_err(Pkcs15Error::Aid)?;
        self.select_application(&aid)
    }

    /// SELECT an EF by file identifier, with no response data. Tries
    /// the EF-under-current-DF shape first, then the any-file shape;
    /// card generations disagree on which they accept.
    ///
    /// # Errors
    ///
    /// Transport failures, or the last non-success status word when
    /// every variant is rejected.
    fn select_ef(&mut self, fid: FileId) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let variants = [
            SelectEfNoFci { fid }.into_apdu(),
            select_any_by_fid_variant(fid),
        ];
        select_with_variants(self, variants)
    }

    /// SELECT the MF. Tries the by-identifier shape, then the by-name
    /// shape some variants require after a deep DF selection.
    ///
    /// # Errors
    ///
    /// Transport failures, or the last non-success status word when
    /// every variant is rejected.
    fn select_mf(&mut self) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let variants = [
            select_any_by_fid_variant(FileId::MF),
            select_by_name_variant(FileId::MF)?,
        ];
        select_with_variants(self, variants)
    }

    /// SELECT a child DF under the current DF. Tries the child-DF
    /// shape, then the any-file shape.
    ///
    /// # Errors
    ///
    /// Transport failures, or the last non-success status word when
    /// every variant is rejected.
    fn select_child_df(&mut self, fid: FileId) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let variants = [
            select_child_df_variant(fid)?,
            select_any_by_fid_variant(fid),
        ];
        select_with_variants(self, variants)
    }

    /// SELECT a file by its full path, one two-byte file identifier per
    /// step from the MF, in a single command. The returned FCP is read
    /// and discarded.
    ///
    /// # Errors
    ///
    /// Transport failures, or a non-success status word.
    fn select_path(&mut self, path: &AbsolutePath) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let command = select_path_variant(path);
        let response = exchange(self, &command)?;
        if response.is_ok() {
            Ok(())
        } else {
            Err(Pkcs15Error::Status(response.status_word()))
        }
    }

    /// SELECT the signature directory beneath the MF.
    ///
    /// Organizational cards publish the directory by the
    /// [`ESIGN_AID`] name. Citizen cards accept the
    /// [`DF_ESIGN_FID`] file identifier instead. The name is tried
    /// first because an organizational card can acknowledge a
    /// file-identifier SELECT without making DF.ESIGN current.
    ///
    /// # Errors
    ///
    /// Transport failures, or the last non-success status word when
    /// the named and file-identifier variants are all rejected.
    fn select_esign_directory(&mut self) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        self.select_mf()?;
        let aid = Aid::from_slice(ESIGN_AID).map_err(Pkcs15Error::Aid)?;
        let variants = [
            SelectByAidNoFci { aid }.into_apdu(),
            select_child_df_variant(DF_ESIGN_FID)?,
            select_any_by_fid_variant(DF_ESIGN_FID),
        ];
        select_with_variants(self, variants)
    }

    /// READ BINARY the currently selected EF in chunks until the end
    /// marker, a short read, or the cap.
    ///
    /// # Errors
    ///
    /// Transport failures, a non-success status word other than the
    /// end-of-file marker, an empty result, or a read past the cap.
    fn read_binary_to_end(
        &mut self,
        expected_size: Option<usize>,
    ) -> Result<Vec<u8>, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let cap = expected_size
            .unwrap_or(MAX_OBJECT_BYTES)
            .min(MAX_OBJECT_BYTES);
        let mut collected = Vec::with_capacity(cap);
        let mut offset: usize = 0;
        while offset < cap {
            let remaining = cap.checked_sub(offset).ok_or(Pkcs15Error::TooLarge)?;
            let want_usize = remaining.min(usize::from(READ_CHUNK));
            let want = u8::try_from(want_usize).map_err(|_| Pkcs15Error::TooLarge)?;
            let response = read_chunk_with_eof_retry(self, offset, want)?;
            let end_of_file = matches!(response.status_word(), StatusWord::EndOfFile);
            if !response.is_ok() && !end_of_file {
                return Err(Pkcs15Error::Status(response.status_word()));
            }
            let body_len = response.body.len();
            collected.extend_from_slice(&response.body);
            if collected.len() >= cap {
                collected.truncate(cap);
                break;
            }
            if body_len == 0 || body_len < usize::from(want) || end_of_file {
                break;
            }
            offset = offset.checked_add(body_len).ok_or(Pkcs15Error::TooLarge)?;
        }
        if collected.is_empty() {
            return Err(Pkcs15Error::Empty);
        }
        if collected.len() > MAX_OBJECT_BYTES {
            return Err(Pkcs15Error::TooLarge);
        }
        Ok(collected)
    }

    /// Read exactly one DER object from the currently selected EF.
    ///
    /// The first chunk supplies the DER header; once the declared total
    /// length is known, the final read requests exactly the remaining
    /// bytes. This avoids both trailing EF padding and cards that
    /// reject an overlong final read instead of returning a partial
    /// body.
    ///
    /// A chunk may also carry more bytes than requested: the T=0 layer
    /// answers a 61xx status by fetching the card's pending count,
    /// which under secure messaging accounts the protected framing and
    /// can exceed the requested length. The loop advances by the actual
    /// body length and truncates at the declared DER total, so the
    /// surplus is consumed, never skipped or re-read.
    ///
    /// # Errors
    ///
    /// Transport failures, an unexpected status word, malformed or
    /// truncated DER, an empty response, or a declared object above the
    /// cap.
    fn read_binary_der_object(
        &mut self,
        what: &'static str,
    ) -> Result<Vec<u8>, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let mut collected: Vec<u8> = Vec::new();
        let mut total_length: Option<usize> = None;

        loop {
            let cap = total_length.unwrap_or(MAX_OBJECT_BYTES);
            if collected.len() >= cap {
                collected.truncate(cap);
                return Ok(collected);
            }

            let remaining = cap
                .checked_sub(collected.len())
                .ok_or(Pkcs15Error::TooLarge)?;
            let want_usize = remaining.min(usize::from(READ_CHUNK));
            let want = u8::try_from(want_usize).map_err(|_| Pkcs15Error::TooLarge)?;
            let response = read_chunk_with_eof_retry(self, collected.len(), want)?;
            let end_of_file = matches!(response.status_word(), StatusWord::EndOfFile);
            if !response.is_ok() && !end_of_file {
                return Err(Pkcs15Error::Status(response.status_word()));
            }
            if response.body.is_empty() {
                return if collected.is_empty() {
                    Err(Pkcs15Error::Empty)
                } else {
                    Err(Pkcs15Error::InvalidData(what))
                };
            }

            let body_len = response.body.len();
            collected.extend_from_slice(&response.body);

            if total_length.is_none() {
                let parsed = der_object_total_length(&collected)
                    .map_err(|MalformedDerLength| Pkcs15Error::InvalidData(what))?;
                if let Some(total) = parsed {
                    if total > MAX_OBJECT_BYTES {
                        return Err(Pkcs15Error::TooLarge);
                    }
                    total_length = Some(total);
                }
            }

            if let Some(total) = total_length
                && collected.len() >= total
            {
                collected.truncate(total);
                return Ok(collected);
            }

            if body_len < usize::from(want) || end_of_file {
                return Err(Pkcs15Error::InvalidData(what));
            }
        }
    }

    /// Read one certificate slot, routing through the SELECT chain its
    /// directory position requires.
    ///
    /// # Errors
    ///
    /// Any underlying SELECT or read failure. An absent slot surfaces
    /// as [`StatusWord::FileNotFound`], which callers treat as "not
    /// provisioned".
    fn read_certificate(
        &mut self,
        slot: CertSlot,
    ) -> Result<UnvalidatedCertificate, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = match slot.path() {
            SlotPath::UnderPkcs15App => {
                self.select_pkcs15_application()?;
                self.select_ef(slot.fid())?;
                self.read_binary_der_object(slot.label())?
            }
            SlotPath::UnderEsignDirectory => {
                self.select_esign_directory()?;
                self.select_ef(slot.fid())?;
                self.read_binary_der_object(slot.label())?
            }
            SlotPath::UnderMf => {
                self.select_mf()?;
                self.select_ef(slot.fid())?;
                self.read_binary_der_object(slot.label())?
            }
        };
        Ok(UnvalidatedCertificate::new(bytes))
    }

    /// SELECT a file addressed by a parsed [`Pkcs15Path`].
    ///
    /// For an MF-rooted path (`3F00/...`), tries ISO/IEC 7816-4
    /// absolute-path SELECT (`P1=08`, no-FCI then FCP) before falling
    /// back to step-by-step MF -> child-DF -> EF selection for cards
    /// that do not implement `P1=08`. For a relative path, selects a
    /// direct child EF or tries relative-path SELECT (`P1=09`) with
    /// step-by-step fallback.
    ///
    /// # Errors
    ///
    /// Transport failures, security-channel refusals, an MF-only path,
    /// or the card's status word when every SELECT shape fails.
    fn select_pkcs15_path(&mut self, path: &Pkcs15Path) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        if path.is_absolute_from_mf() {
            let tail = path
                .steps()
                .get(1..)
                .filter(|steps| !steps.is_empty())
                .ok_or(Pkcs15Error::InvalidData("PKCS#15 path"))?;
            let absolute = AbsolutePath::new(tail.to_vec())
                .map_err(|_path_err| Pkcs15Error::InvalidData("PKCS#15 path"))?;
            let mut last_status = None;
            for command in [
                select_path_no_fci_variant(&absolute),
                select_path_variant(&absolute),
            ] {
                let response = exchange(self, &command)?;
                if response.is_ok() {
                    return Ok(());
                }
                let sw = response.status_word();
                if stops_select_fallback(sw) {
                    return Err(Pkcs15Error::Status(sw));
                }
                last_status = Some(sw);
            }
            if let Some((file, parents)) = tail.split_last() {
                self.select_mf()?;
                for &df in parents {
                    self.select_child_df(df)?;
                }
                return self.select_ef(*file);
            }
            return Err(Pkcs15Error::Status(
                last_status.unwrap_or(StatusWord::FileNotFound),
            ));
        }

        if path.parents().is_empty() {
            return self.select_ef(path.file());
        }
        let command = select_relative_path_variant(path.steps())?;
        let response = exchange(self, &command)?;
        if response.is_ok() {
            return Ok(());
        }
        let sw = response.status_word();
        if stops_select_fallback(sw) {
            return Err(Pkcs15Error::Status(sw));
        }
        for &df in path.parents() {
            self.select_child_df(df)?;
        }
        self.select_ef(path.file())
    }

    /// READ BINARY the currently selected EF until the card confirms
    /// end of file or [`MAX_OBJECT_BYTES`] is reached.
    ///
    /// End of file is [`FileEnd::Confirmed`] only when the card itself
    /// reports it (`6282` EndOfFile, `6B00` WrongParametersP1P2 with
    /// an empty body, or an empty `9000` response). A short `9000`
    /// chunk continues reading so cards that cap a single response
    /// below `READ_CHUNK` are never silently truncated.
    ///
    /// # Errors
    ///
    /// Transport failures, transport state transitions, or unexpected
    /// card status words.
    fn read_binary_confirmed(&mut self) -> Result<FileContent, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let mut collected = Vec::new();
        while collected.len() < MAX_OBJECT_BYTES {
            let remaining = MAX_OBJECT_BYTES
                .checked_sub(collected.len())
                .ok_or(Pkcs15Error::TooLarge)?;
            let want_usize = remaining.min(usize::from(READ_CHUNK));
            let want = u8::try_from(want_usize).map_err(|_| Pkcs15Error::TooLarge)?;
            let response = read_chunk_with_eof_retry(self, collected.len(), want)?;
            match response.status_word() {
                StatusWord::EndOfFile => {
                    if collected.len().saturating_add(response.body.len()) > MAX_OBJECT_BYTES {
                        let take = MAX_OBJECT_BYTES.saturating_sub(collected.len());
                        collected.extend_from_slice(&response.body[..take]);
                        return Ok(FileContent::from_read(collected, FileEnd::Incomplete));
                    }
                    collected.extend_from_slice(&response.body);
                    return Ok(FileContent::from_read(collected, FileEnd::Confirmed));
                }
                StatusWord::WrongParametersP1P2 if response.body.is_empty() => {
                    return Ok(FileContent::from_read(collected, FileEnd::Confirmed));
                }
                StatusWord::Success => {
                    if response.body.is_empty() {
                        return Ok(FileContent::from_read(collected, FileEnd::Confirmed));
                    }
                    if collected.len().saturating_add(response.body.len()) > MAX_OBJECT_BYTES {
                        let take = MAX_OBJECT_BYTES.saturating_sub(collected.len());
                        collected.extend_from_slice(&response.body[..take]);
                        return Ok(FileContent::from_read(collected, FileEnd::Incomplete));
                    }
                    collected.extend_from_slice(&response.body);
                }
                other => return Err(Pkcs15Error::Status(other)),
            }
        }
        let probe = read_chunk(self, MAX_OBJECT_BYTES, ONE_BYTE_EOF_PROBE)?;
        match probe.status_word() {
            StatusWord::WrongParametersP1P2 if probe.body.is_empty() => {
                Ok(FileContent::from_read(collected, FileEnd::Confirmed))
            }
            StatusWord::EndOfFile | StatusWord::Success if probe.body.is_empty() => {
                Ok(FileContent::from_read(collected, FileEnd::Confirmed))
            }
            StatusWord::EndOfFile | StatusWord::Success => {
                Ok(FileContent::from_read(collected, FileEnd::Incomplete))
            }
            other => Err(Pkcs15Error::Status(other)),
        }
    }

    /// Select and read a file named by `path`, applying any PKCS#15
    /// `(index, length)` byte slice carried by the path.
    ///
    /// # Errors
    ///
    /// Selection or read failures, or an out-of-bounds / incomplete
    /// path slice.
    fn read_pkcs15_path(
        &mut self,
        path: &Pkcs15Path,
    ) -> Result<FileContent, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        self.select_pkcs15_path(path)?;
        let content = self.read_binary_confirmed()?;
        content
            .apply_path_slice(path.slice())
            .ok_or(Pkcs15Error::InvalidData("PKCS#15 path slice"))
    }

    /// Read and validate EF.DIR (`3F00/2F00`).
    ///
    /// # Errors
    ///
    /// Selection or read failures, or an incomplete / malformed EF.DIR.
    fn read_application_directory(
        &mut self,
    ) -> Result<ApplicationDirectory, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        self.select_mf()?;
        self.select_ef(EF_DIR_FID)?;
        let content = self.read_binary_confirmed()?;
        match ApplicationDirectory::of(content) {
            ApplicationDirectoryRead::Parsed(directory) => Ok(directory),
            ApplicationDirectoryRead::Incomplete | ApplicationDirectoryRead::Malformed => {
                Err(Pkcs15Error::InvalidData("EF.DIR"))
            }
        }
    }

    /// Read and validate EF.ODF (`5031`) under `aid`.
    ///
    /// # Errors
    ///
    /// Selection or read failures, or an incomplete / malformed EF.ODF.
    fn read_object_directory(
        &mut self,
        aid: &Aid,
    ) -> Result<ObjectDirectory, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        self.select_application(aid)?;
        self.select_ef(EF_ODF_FID)?;
        let content = self.read_binary_confirmed()?;
        match ObjectDirectory::of(content) {
            ObjectDirectoryRead::Parsed(directory) => Ok(directory),
            ObjectDirectoryRead::Incomplete | ObjectDirectoryRead::Malformed => {
                Err(Pkcs15Error::InvalidData("EF.ODF"))
            }
        }
    }

    /// Read and validate an EF.CDF file at `path`.
    ///
    /// # Errors
    ///
    /// Selection or read failures, or an incomplete / malformed EF.CDF.
    fn read_certificate_directory_at(
        &mut self,
        path: &Pkcs15Path,
    ) -> Result<CertificateDirectory, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let content = self.read_pkcs15_path(path)?;
        match CertificateDirectory::of(content) {
            CertificateDirectoryRead::Parsed(directory) => Ok(directory),
            CertificateDirectoryRead::Incomplete | CertificateDirectoryRead::Malformed => {
                Err(Pkcs15Error::InvalidData("EF.CDF"))
            }
        }
    }

    /// Read and validate an EF.PrKDF file at `path`.
    ///
    /// # Errors
    ///
    /// Selection or read failures, or an incomplete / malformed
    /// EF.PrKDF.
    fn read_private_key_directory_at(
        &mut self,
        path: &Pkcs15Path,
    ) -> Result<PrivateKeyDirectory, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let content = self.read_pkcs15_path(path)?;
        match PrivateKeyDirectory::of(content) {
            PrivateKeyDirectoryRead::Parsed(directory) => Ok(directory),
            PrivateKeyDirectoryRead::Incomplete | PrivateKeyDirectoryRead::Malformed => {
                Err(Pkcs15Error::InvalidData("EF.PrKDF"))
            }
        }
    }

    /// Read and validate an EF.AOD file at `path`.
    ///
    /// # Errors
    ///
    /// Selection or read failures, or an incomplete / malformed EF.AOD.
    fn read_authentication_objects_at(
        &mut self,
        path: &Pkcs15Path,
    ) -> Result<AuthenticationObjects, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let content = self.read_pkcs15_path(path)?;
        match AuthenticationObjects::of(content) {
            AuthenticationObjectsRead::Parsed(objects) => Ok(objects),
            AuthenticationObjectsRead::Incomplete | AuthenticationObjectsRead::Malformed(_) => {
                Err(Pkcs15Error::InvalidData("EF.AOD"))
            }
        }
    }

    /// Read and validate a complete single-SEQUENCE DER certificate at
    /// `path`.
    ///
    /// # Errors
    ///
    /// Selection or read failures, an incomplete read, or octets that
    /// are not exactly one minimal DER SEQUENCE.
    fn read_certificate_at(
        &mut self,
        path: &Pkcs15Path,
    ) -> Result<DerCertificate, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let content = self.read_pkcs15_path(path)?;
        match DerCertificate::of(content) {
            CertificateRead::Complete(certificate) => Ok(certificate),
            CertificateRead::Incomplete | CertificateRead::NotOneObject => {
                Err(Pkcs15Error::InvalidData("certificate"))
            }
        }
    }

    /// Look up the single AID published in EF.DIR under `label`.
    ///
    /// # Errors
    ///
    /// [`Pkcs15Error::Status`] with [`StatusWord::FileNotFound`] when
    /// EF.DIR or `label` is absent; [`Pkcs15Error::InvalidData`] when
    /// EF.DIR is incomplete, malformed, or publishes `label` more than
    /// once; or transport failures.
    fn discover_application_by_label(
        &mut self,
        label: &ApplicationLabel,
    ) -> Result<Aid, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let directory = self.read_application_directory()?;
        match directory.identifier_labelled(label) {
            DirectoryLookup::Identified(aid) => Ok(aid),
            DirectoryLookup::Absent => Err(Pkcs15Error::Status(StatusWord::FileNotFound)),
            DirectoryLookup::Ambiguous => Err(Pkcs15Error::InvalidData("EF.DIR")),
        }
    }

    /// Discover the authentication certificate path, key reference,
    /// EF.AOD path, PIN1 object, and optional PUK object for any
    /// ISO/IEC 7816-15 application identified by `aid`.
    ///
    /// Leaves `aid` selected on success.
    ///
    /// # Errors
    ///
    /// Selection, read, or validation failures across EF.ODF, EF.CDF,
    /// EF.PrKDF, or EF.AOD, or an absent / ambiguous authentication
    /// credential or PIN object.
    fn discover_authentication_profile(
        &mut self,
        aid: &Aid,
    ) -> Result<DiscoveredAuthenticationProfile, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let odf = self.read_object_directory(aid)?;
        let cdf_paths: Vec<Pkcs15Path> = odf
            .plain_file_paths(ObjectClass::Certificates)
            .ok_or(Pkcs15Error::InvalidData("EF.ODF"))?
            .into_iter()
            .cloned()
            .collect();
        let prkdf_paths: Vec<Pkcs15Path> = odf
            .plain_file_paths(ObjectClass::PrivateKeys)
            .ok_or(Pkcs15Error::InvalidData("EF.ODF"))?
            .into_iter()
            .cloned()
            .collect();
        let aod_paths: Vec<Pkcs15Path> = odf
            .plain_file_paths(ObjectClass::AuthObjects)
            .ok_or(Pkcs15Error::InvalidData("EF.ODF"))?
            .into_iter()
            .cloned()
            .collect();

        let mut cdfs = Vec::with_capacity(cdf_paths.len());
        for path in &cdf_paths {
            if !path.is_absolute_from_mf() {
                self.select_application(aid)?;
            }
            cdfs.push(self.read_certificate_directory_at(path)?);
        }
        let certificates = CertificateDirectory::merge(cdfs);

        let mut prkdfs = Vec::with_capacity(prkdf_paths.len());
        for path in &prkdf_paths {
            if !path.is_absolute_from_mf() {
                self.select_application(aid)?;
            }
            prkdfs.push(self.read_private_key_directory_at(path)?);
        }
        let private_keys = PrivateKeyDirectory::merge(prkdfs);

        let credentials = CredentialDirectory::of(&certificates, &private_keys)
            .map_err(|_pair_err| Pkcs15Error::InvalidData("credential directory"))?;
        let AuthenticationCredentialLookup::Unique(auth_cred) =
            credentials.unique_authentication_credential()
        else {
            return Err(Pkcs15Error::InvalidData("authentication credential"));
        };
        if !auth_cred.certificate().is_x509() {
            return Err(Pkcs15Error::InvalidData("authentication certificate"));
        }
        let auth_cert_path = auth_cred
            .path()
            .cloned()
            .ok_or(Pkcs15Error::InvalidData("authentication certificate path"))?;
        let auth_key_reference = auth_cred
            .key_reference()
            .ok_or(Pkcs15Error::InvalidData("authentication key reference"))?;
        let pin1_auth_id = auth_cred
            .key()
            .auth_id()
            .cloned()
            .ok_or(Pkcs15Error::InvalidData("authentication key authId"))?;

        let mut aod_files = Vec::with_capacity(aod_paths.len());
        let mut aod_list = Vec::with_capacity(aod_paths.len());
        for path in &aod_paths {
            if !path.is_absolute_from_mf() {
                self.select_application(aid)?;
            }
            let objects = self.read_authentication_objects_at(path)?;
            aod_files.push((path.clone(), objects.clone()));
            aod_list.push(objects);
        }
        let all_aod = AuthenticationObjects::merge(aod_list);
        let pin1 = all_aod
            .unique_by_auth_id(&pin1_auth_id)
            .cloned()
            .ok_or(Pkcs15Error::InvalidData("EF.AOD"))?;
        if pin1.flags().unblocking_password() {
            return Err(Pkcs15Error::InvalidData("EF.AOD"));
        }
        let aod_path = aod_files
            .into_iter()
            .find_map(|(path, objects)| objects.unique_by_auth_id(&pin1_auth_id).map(|_| path))
            .ok_or(Pkcs15Error::InvalidData("EF.AOD"))?;
        let puk = pin1.protecting_auth_id().and_then(|puk_id| {
            all_aod
                .unique_by_auth_id(puk_id)
                .filter(|object| object.flags().unblocking_password())
                .cloned()
        });

        self.select_application(aid)?;
        Ok(DiscoveredAuthenticationProfile::new(
            aid.clone(),
            auth_cert_path,
            auth_key_reference,
            aod_path,
            pin1_auth_id,
            pin1,
            puk,
        ))
    }

    /// Discover the Estonian eID authentication profile via EF.DIR
    /// (`"Estonian eID"`) followed by full ISO/IEC 7816-15 EF.ODF /
    /// EF.CDF / EF.PrKDF / EF.AOD resolution.
    ///
    /// # Errors
    ///
    /// [`Pkcs15Error::Status`] with [`StatusWord::FileNotFound`] when
    /// EF.DIR or the `"Estonian eID"` application is absent; otherwise
    /// as [`Self::discover_authentication_profile`].
    fn discover_estonian_authentication_profile(
        &mut self,
    ) -> Result<DiscoveredAuthenticationProfile, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let label = ApplicationLabel::try_from(ESTONIAN_EID_APPLICATION_LABEL)
            .map_err(|_empty| Pkcs15Error::InvalidData("EF.DIR"))?;
        let aid = self.discover_application_by_label(&label)?;
        self.discover_authentication_profile(&aid)
    }

    /// Discover the qualified-signature certificate path, key reference,
    /// EF.AOD path, PIN 2 object, and optional PUK object for any
    /// ISO/IEC 7816-15 application identified by `aid`.
    ///
    /// Leaves `aid` selected on success.
    ///
    /// # Errors
    ///
    /// Selection, read, or validation failures across EF.ODF, EF.CDF,
    /// EF.PrKDF, or EF.AOD, or an absent / ambiguous qualified-signature
    /// credential or PIN 2 object.
    fn discover_qualified_signature_profile(
        &mut self,
        aid: &Aid,
    ) -> Result<DiscoveredQualifiedSignatureProfile, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let odf = self.read_object_directory(aid)?;
        let cdf_paths: Vec<Pkcs15Path> = odf
            .plain_file_paths(ObjectClass::Certificates)
            .ok_or(Pkcs15Error::InvalidData("EF.ODF"))?
            .into_iter()
            .cloned()
            .collect();
        let prkdf_paths: Vec<Pkcs15Path> = odf
            .plain_file_paths(ObjectClass::PrivateKeys)
            .ok_or(Pkcs15Error::InvalidData("EF.ODF"))?
            .into_iter()
            .cloned()
            .collect();
        let aod_paths: Vec<Pkcs15Path> = odf
            .plain_file_paths(ObjectClass::AuthObjects)
            .ok_or(Pkcs15Error::InvalidData("EF.ODF"))?
            .into_iter()
            .cloned()
            .collect();

        let mut cdfs = Vec::with_capacity(cdf_paths.len());
        for path in &cdf_paths {
            if !path.is_absolute_from_mf() {
                self.select_application(aid)?;
            }
            cdfs.push(self.read_certificate_directory_at(path)?);
        }
        let certificates = CertificateDirectory::merge(cdfs);

        let mut prkdfs = Vec::with_capacity(prkdf_paths.len());
        for path in &prkdf_paths {
            if !path.is_absolute_from_mf() {
                self.select_application(aid)?;
            }
            prkdfs.push(self.read_private_key_directory_at(path)?);
        }
        let private_keys = PrivateKeyDirectory::merge(prkdfs);

        let credentials = CredentialDirectory::of(&certificates, &private_keys)
            .map_err(|_pair_err| Pkcs15Error::InvalidData("credential directory"))?;
        let QualifiedSignatureCredentialLookup::Unique(sign_cred) =
            credentials.unique_qualified_signature_credential()
        else {
            return Err(Pkcs15Error::InvalidData("qualified signature credential"));
        };
        if !sign_cred.certificate().is_x509() {
            return Err(Pkcs15Error::InvalidData("qualified signature certificate"));
        }
        let sign_cert_path = sign_cred.path().cloned().ok_or(Pkcs15Error::InvalidData(
            "qualified signature certificate path",
        ))?;
        let sign_key_reference = sign_cred.key_reference().ok_or(Pkcs15Error::InvalidData(
            "qualified signature key reference",
        ))?;
        let pin2_auth_id = sign_cred
            .key()
            .auth_id()
            .cloned()
            .ok_or(Pkcs15Error::InvalidData("qualified signature key authId"))?;

        let mut aod_files = Vec::with_capacity(aod_paths.len());
        let mut aod_list = Vec::with_capacity(aod_paths.len());
        for path in &aod_paths {
            if !path.is_absolute_from_mf() {
                self.select_application(aid)?;
            }
            let objects = self.read_authentication_objects_at(path)?;
            aod_files.push((path.clone(), objects.clone()));
            aod_list.push(objects);
        }
        let all_aod = AuthenticationObjects::merge(aod_list);
        let pin2 = all_aod
            .unique_by_auth_id(&pin2_auth_id)
            .cloned()
            .ok_or(Pkcs15Error::InvalidData("EF.AOD"))?;
        if pin2.flags().unblocking_password() {
            return Err(Pkcs15Error::InvalidData("EF.AOD"));
        }
        let aod_path = aod_files
            .into_iter()
            .find_map(|(path, objects)| objects.unique_by_auth_id(&pin2_auth_id).map(|_| path))
            .ok_or(Pkcs15Error::InvalidData("EF.AOD"))?;
        let puk = pin2.protecting_auth_id().and_then(|puk_id| {
            all_aod
                .unique_by_auth_id(puk_id)
                .filter(|object| object.flags().unblocking_password())
                .cloned()
        });

        self.select_application(aid)?;
        Ok(DiscoveredQualifiedSignatureProfile::new(
            aid.clone(),
            sign_cert_path,
            crate::directory::QualifiedKeyReference::of(sign_key_reference),
            aod_path,
            pin2_auth_id,
            pin2,
            puk,
        ))
    }

    /// Discover the Estonian eID qualified-signature profile via EF.DIR
    /// (`"Estonian eID"`) followed by full ISO/IEC 7816-15 EF.ODF /
    /// EF.CDF / EF.PrKDF / EF.AOD resolution.
    ///
    /// # Errors
    ///
    /// [`Pkcs15Error::Status`] with [`StatusWord::FileNotFound`] when
    /// EF.DIR or the `"Estonian eID"` application is absent; otherwise
    /// as [`Self::discover_qualified_signature_profile`].
    fn discover_estonian_qualified_signature_profile(
        &mut self,
    ) -> Result<DiscoveredQualifiedSignatureProfile, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let label = ApplicationLabel::try_from(ESTONIAN_EID_APPLICATION_LABEL)
            .map_err(|_empty| Pkcs15Error::InvalidData("EF.DIR"))?;
        let aid = self.discover_application_by_label(&label)?;
        self.discover_qualified_signature_profile(&aid)
    }

    /// Read and parse EF.AOD, the card's authentication objects, under
    /// the PKCS#15 application.
    ///
    /// Tries the FINEID identifier (EF.4401) first; when EF.4401
    /// answers [`StatusWord::FileNotFound`], reads EF.ODF (`5031`) and
    /// follows the `AuthObjects` path(s) the card publishes there.
    /// Leaves the PKCS#15 application DF active on success.
    ///
    /// # Errors
    ///
    /// SELECT or read failures, or a directory that does not decode.
    fn read_authentication_objects(
        &mut self,
    ) -> Result<AuthenticationObjects, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let aid = Aid::from_slice(PKCS15_AID).map_err(Pkcs15Error::Aid)?;
        self.select_application(&aid)?;
        match self.select_ef(crate::EF_AOD_FID) {
            Ok(()) => {
                let bytes = self.read_binary_to_end(None)?;
                return AuthenticationObjects::parse(&bytes)
                    .map_err(|_parse_error| Pkcs15Error::InvalidData("EF.AOD"));
            }
            Err(Pkcs15Error::Status(StatusWord::FileNotFound)) => {}
            Err(error) => return Err(error),
        }
        let odf = self.read_object_directory(&aid)?;
        let Some(paths) = odf.plain_file_paths(ObjectClass::AuthObjects) else {
            return Err(Pkcs15Error::Status(StatusWord::FileNotFound));
        };
        let owned_paths: Vec<Pkcs15Path> = paths.into_iter().cloned().collect();
        let mut aod_list = Vec::with_capacity(owned_paths.len());
        for path in &owned_paths {
            if !path.is_absolute_from_mf() {
                self.select_application(&aid)?;
            }
            aod_list.push(self.read_authentication_objects_at(path)?);
        }
        self.select_application(&aid)?;
        Ok(AuthenticationObjects::merge(aod_list))
    }

    /// Read and parse EF.TokenInfo under `aid`.
    ///
    /// # Errors
    ///
    /// SELECT or read failures, or a token-info file whose outer
    /// structure does not decode.
    fn read_token_info_in_application(
        &mut self,
        aid: &Aid,
    ) -> Result<crate::TokenInfo, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        self.select_application(aid)?;
        self.select_ef(EF_TOKEN_INFO_FID)?;
        let bytes = self.read_binary_der_object("EF.TokenInfo")?;
        crate::TokenInfo::parse(&bytes)
            .map_err(|_parse_error| Pkcs15Error::InvalidData("EF.TokenInfo"))
    }

    /// Read and parse EF.TokenInfo under the standard [`PKCS15_AID`].
    ///
    /// # Errors
    ///
    /// SELECT or read failures, or a token-info file whose outer
    /// structure does not decode.
    fn read_token_info(&mut self) -> Result<crate::TokenInfo, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let aid = Aid::from_slice(PKCS15_AID).map_err(Pkcs15Error::Aid)?;
        self.read_token_info_in_application(&aid)
    }

    /// Read the Estonian document number the card body prints. The
    /// 2025 platform keeps it as plain ASCII in EF.5007 under DF.DD;
    /// the earlier platforms keep a DER TLV in EF.D003 under the MF.
    /// Neither file needs a PIN.
    ///
    /// Both paths traverse out of the PKCS#15 application from the MF
    /// (absolute-path SELECT to DF.DD/EF.5007, or `select_mf` for
    /// EF.D003). Do not call this over a PACE secure channel where MF
    /// traversal tears down the channel, and re-select the PKCS#15
    /// application before issuing application-relative commands
    /// afterwards.
    ///
    /// # Errors
    ///
    /// SELECT or read failures, or a file whose bytes are not a
    /// document number. A card without either file answers SELECT with
    /// [`StatusWord::FileNotFound`].
    fn read_document_number(&mut self) -> Result<crate::DocumentNumber, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let current = AbsolutePath::new(vec![
            DF_ESTONIAN_PERSONAL_DATA_FID,
            EF_ESTONIAN_DOCUMENT_NUMBER_FID,
        ])
        .map_err(|_path_err| Pkcs15Error::InvalidData("EF.5007"))?;
        match self.select_path(&current) {
            Ok(()) => {
                let bytes = self.read_binary_to_end(Some(DOCUMENT_NUMBER_PROBE_CAP))?;
                return crate::DocumentNumber::from_ascii(&bytes)
                    .map_err(|_parse_error| Pkcs15Error::InvalidData("EF.5007"));
            }
            Err(
                error @ (Pkcs15Error::Transport(_)
                | Pkcs15Error::Outcome(_)
                | Pkcs15Error::Status(
                    StatusWord::SecurityNotSatisfied | StatusWord::SmDataObjectsIncorrect,
                )),
            ) => return Err(error),
            Err(Pkcs15Error::Status(_)) => {}
            Err(error) => return Err(error),
        }
        self.select_mf()?;
        self.select_ef(EF_ESTONIAN_DOCUMENT_NUMBER_LEGACY_FID)?;
        let bytes = self.read_binary_der_object("EF.D003")?;
        crate::DocumentNumber::parse_tlv(&bytes)
            .map_err(|_parse_error| Pkcs15Error::InvalidData("EF.D003"))
    }
}

impl<T: CardTransport + ?Sized> Pkcs15Ops for T {}

/// Issue one READ BINARY at `offset` for `want` bytes. If the card
/// answers a specific-length request (`want != 00`) with
/// [`StatusWord::EndOfFile`] and no body -- as observed on 2025
/// Estonian eID cards whenever fewer than `want` bytes remain at any
/// offset -- retry once at the same offset with [`READ_LE_256`], the
/// full short-response window.
fn read_chunk_with_eof_retry<T: CardTransport + ?Sized>(
    transport: &mut T,
    offset: usize,
    want: u8,
) -> Result<ResponseApdu, Pkcs15Error<T::Error>> {
    let response = read_chunk(transport, offset, want)?;
    if want != READ_LE_256
        && response.body.is_empty()
        && matches!(response.status_word(), StatusWord::EndOfFile)
    {
        return read_chunk(transport, offset, READ_LE_256);
    }
    Ok(response)
}

/// Issue one READ BINARY at `offset` for `want` bytes.
fn read_chunk<T: CardTransport + ?Sized>(
    transport: &mut T,
    offset: usize,
    want: u8,
) -> Result<ResponseApdu, Pkcs15Error<T::Error>> {
    let offset_wire = u16::try_from(offset).map_err(|_| Pkcs15Error::TooLarge)?;
    let direct = DirectOffset15::try_new(offset_wire).map_err(|_| Pkcs15Error::TooLarge)?;
    let command = ReadBinary {
        class: ApduClass::Plain,
        offset: ReadBinaryOffset::Direct(direct),
        le: want,
    }
    .into_apdu();
    exchange(transport, &command)
}
