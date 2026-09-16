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

//! PKCS#15 file-system access on the FINEID card.
//!
//! The operations layer on any [`CardTransport`]: a plain transport on
//! the contact interface, or a secure-messaging transport once PACE has
//! produced session keys. Certificate files are not PIN-protected;
//! every command issued here is replay-safe.

use core::fmt;

use refineid_apdu::iso7816::{
    DirectOffset15, ReadBinary, ReadBinaryOffset, SelectByAidNoFci, SelectEfNoFci, SelectFile,
    SelectFileResponseMode, SelectFileTarget,
};
use refineid_apdu::{
    Aid, AidError, ApduClass, CardTransport, CommandApdu, CommandDataError, CommandHeader, FileId,
    ResponseApdu, StatusWord, TransportOutcome,
};
use refineid_x509::UnvalidatedCertificate;

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
/// P2: return no response data, shared with the typed SELECT builder.
const P2_NO_RESPONSE_DATA: u8 = SelectFileResponseMode::None.as_p2();

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
    /// SELECT the PKCS#15 application by AID, with no response data.
    ///
    /// # Errors
    ///
    /// Transport failures or a non-success status word.
    fn select_pkcs15_application(&mut self) -> Result<(), Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        let aid = Aid::from_slice(PKCS15_AID).map_err(Pkcs15Error::Aid)?;
        let command = SelectByAidNoFci { aid }.into_apdu();
        let response = exchange(self, &command)?;
        if !response.is_ok() {
            return Err(Pkcs15Error::Status(response.status_word()));
        }
        Ok(())
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
            let response = read_chunk(self, offset, want)?;
            let end_of_file = matches!(response.status_word(), StatusWord::EndOfFile);
            if !response.is_ok() && !end_of_file {
                return Err(Pkcs15Error::Status(response.status_word()));
            }
            let body_len = response.body.len();
            collected.extend_from_slice(&response.body);
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
            let response = read_chunk(self, collected.len(), want)?;
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

    /// Read and parse EF.TokenInfo.
    ///
    /// # Errors
    ///
    /// SELECT or read failures, or a token-info file whose outer
    /// structure does not decode.
    fn read_token_info(&mut self) -> Result<crate::TokenInfo, Pkcs15Error<Self::Error>>
    where
        Self: Sized,
    {
        self.select_pkcs15_application()?;
        self.select_ef(EF_TOKEN_INFO_FID)?;
        let bytes = self.read_binary_der_object("EF.TokenInfo")?;
        crate::TokenInfo::parse(&bytes)
            .map_err(|_parse_error| Pkcs15Error::InvalidData("EF.TokenInfo"))
    }
}

impl<T: CardTransport + ?Sized> Pkcs15Ops for T {}

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
