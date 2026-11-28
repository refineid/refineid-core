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

//! VERIFY PIN1 and PIN2 against a FINEID or Estonian eID card.
//!
//! On a citizen card the typed PIN digits are right-padded with the pad
//! byte to the slot's stored length; on an organization card they travel
//! bare at their typed length. The Estonian eID uses its own AOD
//! references on the same padded twelve-byte block as a citizen card.
//! Either way they are shipped as a credential command, consumed exactly
//! once by the transport. Because `Pin1` and `Pin2` are
//! validated at construction, no local re-check is needed and the slot
//! is fixed by the argument type, so a PIN2 can never be sent to the
//! PIN1 slot.
//!
//! The counter-safe status probe (`VERIFY` with an empty data field)
//! reads the retry state without decrementing any counter, per FINEID
//! S1 v4.2 section 4.1.2. Every VERIFY that carries a PIN sends that
//! probe first and applies the retry floor
//! ([`crate::retry_risk::check_retry_floor`]) to its answer: refused at
//! one try left or an unreadable counter; sent otherwise, the card
//! answering for itself at zero or blocked. The primitive enforces the
//! rule itself, so no caller can spend a try by mistake; a caller that
//! has already read the counter for a purpose of its own may apply the
//! same rule first, to refuse before it asks for the PIN.

use core::fmt;

use refineid_apdu::{
    ApduClass, CREDENTIAL_BODY_MAX, CardTransport, CommandApdu, CommandHeader, CredentialBody,
    CredentialBodyError, CredentialCommand, PinRetries, StatusWord, TransportOutcome,
    UnvalidatedCredentialBlock,
};
use refineid_pkcs15::{PasswordLengthRange, PasswordObject};

use crate::credentials::{CredentialRole, Pin1, Pin2};
use crate::pin_lengths::PinLengthRefusal;
use crate::retry_risk::{FlooredCredential, RetryFloorRefusal, check_retry_floor_with_scheme};

/// Citizen-card PIN1 reference: the global authentication PIN (FINEID S1
/// v4.2 section 3.5.2).
pub const PIN1_REFERENCE: u8 = 0x11;
/// Citizen-card PIN2 reference: the local qualified-signature PIN (FINEID
/// S1 v4.2 section 3.5.2).
pub const PIN2_REFERENCE: u8 = 0x82;

/// Estonian eID PIN1 reference, from the card's EF.AOD (GED24035, the
/// Estonian eID developer guide, EF.AOD).
pub const PIN1_REFERENCE_ESTONIAN: u8 = 0x81;
/// Estonian eID PIN2 reference, from the card's EF.AOD.
pub const PIN2_REFERENCE_ESTONIAN: u8 = 0x82;
/// Estonian eID PUK reference, from the card's EF.AOD.
pub const PUK_REFERENCE_ESTONIAN: u8 = 0x83;

/// Organizational-card PIN1 reference: the PIN AUTH security-data-object
/// identifier (FINEID S4-2 v4.0 section 4.2).
pub const PIN1_REFERENCE_ORGANIZATIONAL: u8 = 0x03;
/// Organizational-card PIN2 reference: the PIN SIG security-data-object
/// identifier (FINEID S4-2 v4.0 section 4.2).
pub const PIN2_REFERENCE_ORGANIZATIONAL: u8 = 0x04;

/// Citizen-card PUK reference: the unblocking password's reference from
/// FINEID S4-1 v4.2 section 8.1.5 (EF.AOD). Used to read the PUK's state;
/// the citizen unblock command carries the PUK in its data field rather
/// than under this reference.
pub const PUK_REFERENCE: u8 = 0x83;
/// Organizational-card PUK reference: the PIN PUK security-data-object
/// identifier (FINEID S4-2 v4.0 section 4.3.2). The organizational
/// unblock verifies the PUK under this reference before the reset.
pub const PUK_REFERENCE_ORGANIZATIONAL: u8 = 0x12;

/// PIN attempts on the FINEID citizen and organizational profiles.
const FINEID_PIN_RETRY_LIMIT: u8 = 5;
/// PIN attempts on the Estonian eID profile.
const ESTONIAN_PIN_RETRY_LIMIT: u8 = 3;

/// VERIFY instruction byte (ISO 7816-4 section 7.5.6).
pub const VERIFY_INS: u8 = 0x20;
/// VERIFY P1 selecting the verify operation.
pub const VERIFY_P1: u8 = 0x00;

/// FINEID stored length for both PIN slots: the padded block length in
/// bytes (FINEID S1 v4.2 section 3.5).
pub const PIN_STORED_LENGTH: usize = 12;
/// FINEID S1 v4.2 section 3.5: the octet the cards accept to the right
/// of the typed digits.
pub const FINEID_PAD_OCTET: u8 = 0x00;

/// The byte the Estonian eID card accepts to the right of typed digits.
/// The card stores a twelve-byte credential block and accepts zero
/// padding after a shorter value.
pub const ESTONIAN_EID_PAD_OCTET: u8 = 0x00;

/// Number of credential blocks carried by a two-group management
/// command (CHANGE REFERENCE DATA or RESET RETRY COUNTER).
const TWO_CREDENTIAL_BLOCKS: usize = 2;

/// Maximum padded single-PIN block length supported by credential
/// commands (half of [`CREDENTIAL_BODY_MAX`] so both single-block
/// VERIFY and two-block CHANGE / UNBLOCK commands fit without
/// truncation).
pub const MAX_PADDED_PIN_BLOCK_LENGTH: usize = CREDENTIAL_BODY_MAX / TWO_CREDENTIAL_BLOCKS;

/// The octet a card expects to the right of the typed digits in a
/// credential block. Constructed only from specification constants or a
/// parsed EF.AOD [`PasswordObject`]; no caller supplies a bare octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinPadByte(u8);

impl PinPadByte {
    /// FINEID S1 v4.2 section 3.5.
    pub const FINEID: Self = Self(FINEID_PAD_OCTET);

    /// GED24035, the Estonian eID profile.
    pub const ESTONIAN_EID: Self = Self(ESTONIAN_EID_PAD_OCTET);

    /// Construct from the `padChar` published by a parsed EF.AOD
    /// [`PasswordObject`], or `None` when EF.AOD omitted `padChar`.
    #[must_use]
    pub const fn from_password_object(object: &PasswordObject) -> Option<Self> {
        match object.pad_char() {
            Some(octet) => Some(Self(octet)),
            None => None,
        }
    }

    /// The wire octet this profile fills with.
    #[must_use]
    pub const fn octet(self) -> u8 {
        self.0
    }
}

/// Wire encoding of one PIN or PUK block inside a credential APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinBlockEncoding {
    /// Bare typed digits at their own length (no padding).
    Bare,
    /// Typed digits right-padded with `pad` to `stored_length` octets.
    Padded {
        /// Stored block length in octets
        /// (`1..=MAX_PADDED_PIN_BLOCK_LENGTH`).
        stored_length: u8,
        /// Pad octet from the card's EF.AOD (or FINEID specification).
        pad: PinPadByte,
    },
}

/// Why a parsed EF.AOD [`PasswordObject`] could not be turned into
/// [`CardPinParameters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AodPinParametersError {
    /// `pwdFlags` set `needs-padding`, but EF.AOD omitted `padChar`.
    MissingPadChar,
    /// `pwdFlags` cleared `needs-padding`, yet EF.AOD still supplied
    /// `padChar`; refused rather than guessing whether to pad.
    ConflictingPaddingFlags,
    /// `storedLength` is zero, smaller than the accepted maximum digit
    /// length, or exceeds [`MAX_PADDED_PIN_BLOCK_LENGTH`].
    InvalidStoredLength {
        /// The `storedLength` published by the card.
        stored_length: u8,
    },
}

impl fmt::Display for AodPinParametersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPadChar => {
                f.write_str("EF.AOD password object sets needs-padding without padChar")
            }
            Self::ConflictingPaddingFlags => {
                f.write_str("EF.AOD password object clears needs-padding while publishing padChar")
            }
            Self::InvalidStoredLength { stored_length } => write!(
                f,
                "EF.AOD storedLength {stored_length} is incompatible with accepted length bounds"
            ),
        }
    }
}

impl core::error::Error for AodPinParametersError {}

/// Validated card-side wire parameters for one PIN or PUK object,
/// derived from the card's parsed EF.AOD [`PasswordObject`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardPinParameters {
    scheme: PinReferenceScheme,
    reference: u8,
    lengths: PasswordLengthRange,
    encoding: PinBlockEncoding,
}

impl CardPinParameters {
    /// Validate a parsed EF.AOD [`PasswordObject`] into wire-ready
    /// credential parameters for `scheme`.
    ///
    /// Fails closed if `needs-padding` is set without `padChar`, if
    /// `needs-padding` is clear while `padChar` is present, or if a
    /// padded `storedLength` is zero, shorter than `lengths.max()`, or
    /// above [`MAX_PADDED_PIN_BLOCK_LENGTH`].
    ///
    /// # Errors
    ///
    /// [`AodPinParametersError`] on missing, conflicting, or
    /// out-of-bounds padding attributes.
    pub fn from_aod(
        scheme: PinReferenceScheme,
        object: &PasswordObject,
    ) -> Result<Self, AodPinParametersError> {
        let encoding = if object.flags().needs_padding() {
            let Some(pad) = PinPadByte::from_password_object(object) else {
                return Err(AodPinParametersError::MissingPadChar);
            };
            let stored = usize::from(object.stored_length());
            if stored == 0
                || stored > MAX_PADDED_PIN_BLOCK_LENGTH
                || object.lengths().max() > stored
            {
                return Err(AodPinParametersError::InvalidStoredLength {
                    stored_length: object.stored_length(),
                });
            }
            PinBlockEncoding::Padded {
                stored_length: object.stored_length(),
                pad,
            }
        } else {
            if object.pad_char().is_some() {
                return Err(AodPinParametersError::ConflictingPaddingFlags);
            }
            PinBlockEncoding::Bare
        };
        Ok(Self {
            scheme,
            reference: object.reference(),
            lengths: object.lengths(),
            encoding,
        })
    }

    /// Retry-scale and protocol scheme associated with this card.
    #[must_use]
    pub const fn scheme(self) -> PinReferenceScheme {
        self.scheme
    }

    /// VERIFY / CHANGE / RESET P2 reference byte from EF.AOD.
    #[must_use]
    pub const fn reference(self) -> u8 {
        self.reference
    }

    /// Accepted digit-length range from EF.AOD.
    #[must_use]
    pub const fn lengths(self) -> PasswordLengthRange {
        self.lengths
    }

    /// Wire block encoding (padded with `storedLength` + `padChar`, or
    /// bare typed digits) from EF.AOD.
    #[must_use]
    pub const fn encoding(self) -> PinBlockEncoding {
        self.encoding
    }

    /// Verify that `digit_count` lies within [`Self::lengths`].
    ///
    /// # Errors
    ///
    /// [`PinLengthRefusal::OutsideAcceptedRange`] when `digit_count`
    /// falls outside the card's published range.
    pub const fn check_length(
        self,
        role: CredentialRole,
        digit_count: usize,
    ) -> Result<(), PinLengthRefusal> {
        if self.lengths.contains(digit_count) {
            Ok(())
        } else {
            Err(PinLengthRefusal::OutsideAcceptedRange {
                role,
                accepted: self.lengths,
            })
        }
    }
}

/// Which PIN slot a status probe targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSlot {
    /// PIN1: the authentication and digital-signature PIN.
    Pin1,
    /// PIN2: the qualified-signature PIN.
    Pin2,
}

impl PinSlot {
    /// The citizen-card VERIFY P2 reference byte for this slot.
    #[must_use]
    pub const fn reference(self) -> u8 {
        PinReferenceScheme::Citizen.reference(self)
    }
}

/// Which credential-reference numbering the card in session uses.
///
/// Citizen cards number their credentials as FINEID S1 v4.2 section
/// 3.5.2 reads; organizational cards number them by their FINEID S4-2
/// v4.0 section 4.2 security-data-object identifiers instead. The
/// Estonian eID numbers PIN1 by the reference its EF.AOD lists, over
/// the same twelve-byte padded credential block as a citizen card. The S4-2
/// v4.0 section 5.2 sample prints references that contradict the same
/// document's section 4.2 tables and shipped cards, so the numbering is
/// resolved by asking the card rather than trusting the sample; the
/// probe is counter-safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinReferenceScheme {
    /// FINEID S1 v4.2 numbering: the citizen cards.
    Citizen,
    /// FINEID S4-2 v4.0 numbering: the organizational cards.
    Organizational,
    /// Estonian eID numbering: EF.AOD references on a padded block.
    Estonian,
}

impl PinReferenceScheme {
    /// The VERIFY P2 reference byte for `slot` under this numbering.
    #[must_use]
    pub const fn reference(self, slot: PinSlot) -> u8 {
        match (self, slot) {
            (Self::Citizen, PinSlot::Pin1) => PIN1_REFERENCE,
            (Self::Citizen, PinSlot::Pin2) => PIN2_REFERENCE,
            (Self::Organizational, PinSlot::Pin1) => PIN1_REFERENCE_ORGANIZATIONAL,
            (Self::Organizational, PinSlot::Pin2) => PIN2_REFERENCE_ORGANIZATIONAL,
            (Self::Estonian, PinSlot::Pin1) => PIN1_REFERENCE_ESTONIAN,
            (Self::Estonian, PinSlot::Pin2) => PIN2_REFERENCE_ESTONIAN,
        }
    }

    /// The PUK reference byte under this numbering.
    #[must_use]
    pub const fn puk_reference(self) -> u8 {
        match self {
            Self::Citizen => PUK_REFERENCE,
            Self::Organizational => PUK_REFERENCE_ORGANIZATIONAL,
            Self::Estonian => PUK_REFERENCE_ESTONIAN,
        }
    }

    /// The pad byte this numbering uses to fill a padded credential block.
    #[must_use]
    pub const fn pad(self) -> PinPadByte {
        match self {
            Self::Citizen => PinPadByte::FINEID,
            Self::Organizational => PinPadByte::FINEID,
            Self::Estonian => PinPadByte::ESTONIAN_EID,
        }
    }

    /// The number of attempts a pristine PIN has under this numbering.
    #[must_use]
    pub const fn pin_retry_limit(self) -> u8 {
        match self {
            Self::Citizen | Self::Organizational => FINEID_PIN_RETRY_LIMIT,
            Self::Estonian => ESTONIAN_PIN_RETRY_LIMIT,
        }
    }
}

/// Outcome of a VERIFY round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The PIN was accepted; the card stays authenticated until a
    /// selection or reset clears the state.
    Ok,
    /// The PIN was wrong; `retries_left` attempts remain before the slot
    /// locks. Zero means the next failure locks it.
    WrongPin {
        /// Attempts remaining before the slot locks.
        retries_left: PinRetries,
    },
    /// The authentication method is blocked; only an unblock recovers
    /// it.
    Locked,
    /// Any other status word, surfaced as-is for the caller to map.
    Other(StatusWord),
}

/// Outcome of a counter-safe status probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// The PIN is already verified in this card session.
    Verified,
    /// The PIN is not verified; `retries` attempts remain.
    Remaining(PinRetries),
    /// Verification failed with no retry information.
    NoInfo,
    /// The PIN method is blocked or its usage counter is exhausted.
    Locked,
    /// Any other status word, surfaced as-is for the caller.
    Other(StatusWord),
}

/// A VERIFY-path failure.
#[derive(Debug)]
pub enum AuthError<E> {
    /// An adapter-level transport failure.
    Transport(E),
    /// A transport-level state transition instead of a response.
    Outcome(TransportOutcome),
    /// The credential command could not be assembled; unreachable for a
    /// validated PIN, kept fail-closed.
    Command(CredentialBodyError),
    /// The retry floor refused the credential before any command that
    /// carries it was sent. Every operation that presents a PIN, the
    /// PUK or an activation code reads that credential's counter itself
    /// and returns this at one try left or an unreadable counter.
    RetryFloor(RetryFloorRefusal),
    /// The card in session does not accept an entry's length; refused
    /// before any command that carries it was sent. Returned by the
    /// operations that take the card's
    /// [`crate::pin_lengths::CardPinLengths`].
    PinLength(PinLengthRefusal),
    /// The card requires changing its initial Signature PIN 2 before
    /// qualified signing is allowed (EstEID 2025, `GED24035_015`
    /// sections 3.1, 7.8.1 and 8.3.4); refused before any VERIFY
    /// carrying PIN 2 was sent.
    Pin2ChangeRequired,
    /// The requested PIN slot or operation is not supported in this
    /// application context under `scheme`; refused before any command
    /// that carries a credential was sent.
    UnsupportedSlot {
        /// Credential numbering resolved for the card.
        scheme: PinReferenceScheme,
        /// The PIN slot that cannot be addressed in this context.
        slot: PinSlot,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for AuthError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "auth transport: {e}"),
            Self::Outcome(outcome) => write!(f, "auth transport state: {outcome}"),
            Self::Command(e) => write!(f, "auth command: {e}"),
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
            Self::PinLength(refusal) => write!(f, "{refusal}"),
            Self::Pin2ChangeRequired => {
                f.write_str("Signature PIN 2 must be changed before signing documents")
            }
            Self::UnsupportedSlot { scheme, slot } => {
                write!(f, "auth: {slot:?} is not supported under {scheme:?}")
            }
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for AuthError<E> {}

/// Decode a VERIFY response status word into an outcome. Public so an
/// unrelated operation can classify a PIN-state status word it receives.
#[must_use]
pub const fn classify_verify_sw(sw: StatusWord) -> VerifyOutcome {
    match sw {
        StatusWord::Success => VerifyOutcome::Ok,
        StatusWord::PinIncorrect { retries } => VerifyOutcome::WrongPin {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            VerifyOutcome::Locked
        }
        other => VerifyOutcome::Other(other),
    }
}

/// Decode a status-probe response status word.
#[must_use]
pub const fn classify_pin_status_sw(sw: StatusWord) -> PinStatus {
    match sw {
        StatusWord::Success => PinStatus::Verified,
        StatusWord::PinIncorrect { retries } => PinStatus::Remaining(retries),
        StatusWord::AuthenticationFailed => PinStatus::NoInfo,
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            PinStatus::Locked
        }
        other => PinStatus::Other(other),
    }
}

/// Write each `(digits, encoding)` group into `out`, failing closed if
/// any padded group exceeds its `stored_length` or if the combined
/// length exceeds [`CREDENTIAL_BODY_MAX`].
pub(crate) fn write_credential_groups(
    groups: &[(&[u8], PinBlockEncoding)],
    out: &mut [u8; CREDENTIAL_BODY_MAX],
) -> Result<usize, CredentialBodyError> {
    out.fill(0);
    let mut total = 0_usize;
    for &(digits, encoding) in groups {
        match encoding {
            PinBlockEncoding::Padded { stored_length, pad } => {
                let block_len = usize::from(stored_length);
                if block_len == 0 {
                    return Err(CredentialBodyError::Empty);
                }
                if digits.len() > block_len {
                    return Err(CredentialBodyError::TooLong);
                }
                let end = total
                    .checked_add(block_len)
                    .filter(|&len| len <= CREDENTIAL_BODY_MAX)
                    .ok_or(CredentialBodyError::TooLong)?;
                out[total..end].fill(pad.octet());
                out[total..total + digits.len()].copy_from_slice(digits);
                total = end;
            }
            PinBlockEncoding::Bare => {
                let end = total
                    .checked_add(digits.len())
                    .filter(|&len| len <= CREDENTIAL_BODY_MAX)
                    .ok_or(CredentialBodyError::TooLong)?;
                out[total..end].copy_from_slice(digits);
                total = end;
            }
        }
    }
    Ok(total)
}

/// Stored length as a single octet for fixed-profile encoding.
const PIN_STORED_LENGTH_U8: u8 = 12;

/// Default block encoding for a fixed [`PinReferenceScheme`] and pad
/// byte.
const fn scheme_encoding(scheme: PinReferenceScheme, pad: PinPadByte) -> PinBlockEncoding {
    const { assert!(PIN_STORED_LENGTH_U8 as usize == PIN_STORED_LENGTH) };
    match scheme {
        PinReferenceScheme::Citizen | PinReferenceScheme::Estonian => PinBlockEncoding::Padded {
            stored_length: PIN_STORED_LENGTH_U8,
            pad,
        },
        PinReferenceScheme::Organizational => PinBlockEncoding::Bare,
    }
}

/// Largest credential body assembled in unit tests: two stored-length
/// blocks.
#[cfg(test)]
pub(crate) const CREDENTIAL_BODY_SCRATCH: usize = 2 * PIN_STORED_LENGTH;

#[cfg(test)]
pub(crate) fn write_credential_blocks(
    scheme: PinReferenceScheme,
    groups: &[&[u8]],
    pad: PinPadByte,
    out: &mut [u8; CREDENTIAL_BODY_MAX],
) -> Result<usize, CredentialBodyError> {
    const { assert!(CREDENTIAL_BODY_SCRATCH <= CREDENTIAL_BODY_MAX) };
    if groups.len() > TWO_CREDENTIAL_BLOCKS {
        return Err(CredentialBodyError::TooLong);
    }
    let encoding = scheme_encoding(scheme, pad);
    let mut pairs: [(&[u8], PinBlockEncoding); TWO_CREDENTIAL_BLOCKS] =
        [(&[], encoding), (&[], encoding)];
    for (slot, &group) in pairs.iter_mut().zip(groups.iter()) {
        *slot = (group, encoding);
    }
    write_credential_groups(&pairs[..groups.len()], out)
}

/// Assemble `(digits, encoding)` groups into one credential command
/// under `header`, transmit it once, and return the card's status word.
///
/// # Errors
///
/// [`AuthError`] on a command-assembly failure, a transport failure, or
/// a transport state transition.
pub(crate) fn credential_exchange_groups<T: CardTransport + ?Sized>(
    transport: &mut T,
    header: CommandHeader,
    groups: &[(&[u8], PinBlockEncoding)],
) -> Result<StatusWord, AuthError<T::Error>> {
    let mut block = UnvalidatedCredentialBlock::zeroed();
    let total = write_credential_groups(groups, block.buffer()).map_err(AuthError::Command)?;
    block.set_filled(total);
    let body = match CredentialBody::from_block(block) {
        Ok(body) => body,
        Err(error) => return Err(AuthError::Command(error)),
    };
    let command = CredentialCommand::assemble(header, body);
    let response = transport
        .transmit_credential(command)
        .map_err(AuthError::Transport)?
        .into_response()
        .map_err(AuthError::Outcome)?;
    Ok(response.status_word())
}

/// Assemble the credential blocks for `groups` into one credential
/// command under `header` and `scheme`, transmit it once, and return the
/// card's status word for the caller to classify.
///
/// # Errors
///
/// [`AuthError`] on a command-assembly failure, a transport failure, or a
/// transport state transition.
pub(crate) fn credential_exchange<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
    pad: PinPadByte,
    header: CommandHeader,
    groups: &[&[u8]],
) -> Result<StatusWord, AuthError<T::Error>> {
    let encoding = scheme_encoding(scheme, pad);
    let mut pairs: Vec<(&[u8], PinBlockEncoding)> = Vec::with_capacity(groups.len());
    for &group in groups {
        pairs.push((group, encoding));
    }
    credential_exchange_groups(transport, header, &pairs)
}

/// Apply the retry floor to `status`, the counter-safe reading of `slot`,
/// then assemble and send the VERIFY credential command for `slot` under
/// `scheme`, classifying the card's status word.
///
/// Crate-private on purpose: the only entries to a VERIFY are the typed
/// [`PinOps::verify_pin1`] and [`PinOps::verify_pin2`] family, which take a
/// validated [`Pin1`] or [`Pin2`] and read the counter first. There is no
/// public raw-digit VERIFY, so no caller outside this crate can present
/// arbitrary bytes as a PIN and spend a retry on them.
///
/// # Errors
///
/// [`AuthError::RetryFloor`] when `status` is one try left or carries no
/// readable counter; nothing is sent. [`AuthError`] on a command-assembly
/// failure, a transport failure, or a transport state transition.
pub(crate) fn verify_under_floor<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
    slot: PinSlot,
    status: PinStatus,
    digits: &[u8],
) -> Result<VerifyOutcome, AuthError<T::Error>> {
    check_retry_floor_with_scheme(slot.into(), status, scheme).map_err(AuthError::RetryFloor)?;
    let pin_is_blocked = matches!(status, PinStatus::Locked)
        || matches!(status, PinStatus::Remaining(retries) if retries.is_exhausted());
    if scheme == PinReferenceScheme::Estonian && slot == PinSlot::Pin2 && !pin_is_blocked {
        let record = crate::activation::read_pin_change_record_with_scheme(
            transport,
            scheme,
            PinSlot::Pin2,
        )?;
        if record == crate::activation::PinChangeRecord::Unchanged {
            return Err(AuthError::Pin2ChangeRequired);
        }
    }
    verify_digits(transport, scheme, slot, digits)
}

/// Assemble and send the VERIFY credential command for `slot` under
/// `scheme`, classifying the card's status word. The caller has applied
/// the retry floor to the slot's counter: [`verify_under_floor`] to the
/// probe's answer on a plain transport, the PIN 2 channel operation to
/// the channel's own record.
///
/// # Errors
///
/// [`AuthError`] on a command-assembly failure, a transport failure, or
/// a transport state transition.
pub(crate) fn verify_digits<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
    slot: PinSlot,
    digits: &[u8],
) -> Result<VerifyOutcome, AuthError<T::Error>> {
    let header = CommandHeader {
        class: ApduClass::Plain,
        instruction: VERIFY_INS,
        p1: VERIFY_P1,
        p2: scheme.reference(slot),
    };
    let status = credential_exchange(transport, scheme, scheme.pad(), header, &[digits])?;
    Ok(classify_verify_sw(status))
}

/// Send the counter-safe VERIFY status probe for a validated credential
/// reference byte and return the raw status word.
///
/// Crate-private so public callers reach status probes only through
/// typed [`PinReferenceScheme`]/[`PinSlot`] or [`CardPinParameters`]
/// borders.
pub(crate) fn probe_status_word_for_reference<T: CardTransport + ?Sized>(
    transport: &mut T,
    reference: u8,
) -> Result<StatusWord, AuthError<T::Error>> {
    let command = CommandApdu::case_1(CommandHeader {
        class: ApduClass::Plain,
        instruction: VERIFY_INS,
        p1: VERIFY_P1,
        p2: reference,
    });
    let response = transport
        .transmit(&command)
        .map_err(AuthError::Transport)?
        .into_response()
        .map_err(AuthError::Outcome)?;
    Ok(response.status_word())
}

/// PIN management operations, layered as default methods on every
/// [`CardTransport`].
///
/// Bring the trait into scope to use the methods; the blanket
/// implementation applies to every transport, so a plain contact
/// transport and a PACE secure-messaging transport both gain the same
/// PIN operations. The scheme-free entry points resolve the card's
/// credential numbering first; a caller that will issue several
/// operations resolves once with [`PinOps::resolve_pin_reference_scheme`]
/// and passes the result to the `_with_scheme` forms.
pub trait PinOps: CardTransport {
    /// VERIFY PIN1 (the authentication PIN), resolving the card's
    /// credential numbering first so an organizational card is not sent
    /// a citizen block. The one counter-safe probe that resolves the
    /// numbering also reads PIN 1's counter, to which the retry floor is
    /// applied before the PIN is sent. The PIN is consumed and its
    /// digits are zeroized.
    ///
    /// # Errors
    ///
    /// [`AuthError::RetryFloor`] when the card reports one try left or
    /// no readable counter; nothing carrying the PIN is sent.
    /// [`AuthError`] on a transport failure or state transition. A wrong
    /// PIN is not an error; it is [`VerifyOutcome::WrongPin`], and a
    /// blocked PIN is [`VerifyOutcome::Locked`], the card's own answer.
    fn verify_pin1(&mut self, pin: Pin1) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let (scheme, status) = self.pin1_status_and_scheme()?;
        verify_under_floor(self, scheme, PinSlot::Pin1, status, pin.digits())
    }

    /// VERIFY PIN2 (the qualified-signature PIN), resolving the numbering
    /// first.
    ///
    /// # Errors
    ///
    /// As [`PinOps::verify_pin1`].
    fn verify_pin2(&mut self, pin: Pin2) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let scheme = self.resolve_pin_reference_scheme()?;
        self.verify_pin2_with_scheme(scheme, pin)
    }

    /// VERIFY PIN1 under an explicit numbering: the counter-safe probe of
    /// PIN 1 under `scheme`, the retry floor on its answer, then the
    /// VERIFY carrying the PIN.
    ///
    /// # Errors
    ///
    /// As [`PinOps::verify_pin1`].
    fn verify_pin1_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
        pin: Pin1,
    ) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let status = self.pin_status_with_scheme(scheme, PinSlot::Pin1)?;
        verify_under_floor(self, scheme, PinSlot::Pin1, status, pin.digits())
    }

    /// VERIFY PIN2 under an explicit numbering: the counter-safe probe of
    /// PIN 2 under `scheme`, the retry floor on its answer, then the
    /// VERIFY carrying the PIN.
    ///
    /// On [`PinReferenceScheme::Estonian`] (EstEID 2025, `GED24035_015`
    /// sections 3.1, 7.8.1 and 8.3.4), PIN 2 lives in the shared PKCS#15
    /// eID application and is verified on a zero-padded block of stored
    /// length. When PIN 2 is neither blocked nor exhausted and passes the
    /// retry floor, the primitive reads PIN 2's counter-safe `DF 2F`
    /// changed flag before sending VERIFY and returns
    /// [`AuthError::Pin2ChangeRequired`] without spending a retry if the
    /// initial PIN 2 has not yet been changed.
    ///
    /// # Errors
    ///
    /// [`AuthError::Pin2ChangeRequired`] on EstEID 2025 when initial
    /// PIN 2 is unchanged; otherwise as [`PinOps::verify_pin1_with_scheme`].
    fn verify_pin2_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
        pin: Pin2,
    ) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let status = self.pin_status_with_scheme(scheme, PinSlot::Pin2)?;
        verify_under_floor(self, scheme, PinSlot::Pin2, status, pin.digits())
    }

    /// Whether the card enforces changing its initial PIN 2 before
    /// qualified signing is allowed (EstEID 2025, `GED24035_015`
    /// sections 3.1, 7.8.1 and 8.3.4).
    ///
    /// Sends no APDU for FINEID citizen or organizational cards,
    /// answering `Ok(false)`. On [`PinReferenceScheme::Estonian`],
    /// queries PIN 2's counter-safe PIN container and returns `Ok(true)`
    /// only when the changed-state object (`DF 2F`) explicitly reports
    /// unchanged ([`crate::activation::PinChangeRecord::Unchanged`]).
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn pin2_requires_change_before_signing_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
    ) -> Result<bool, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        if scheme != PinReferenceScheme::Estonian {
            return Ok(false);
        }
        let record =
            crate::activation::read_pin_change_record_with_scheme(self, scheme, PinSlot::Pin2)?;
        Ok(record == crate::activation::PinChangeRecord::Unchanged)
    }

    /// Whether the card enforces changing its initial PIN 2 before
    /// qualified signing is allowed, resolving the credential numbering
    /// first.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn pin2_requires_change_before_signing(&mut self) -> Result<bool, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let scheme = self.resolve_pin_reference_scheme()?;
        self.pin2_requires_change_before_signing_with_scheme(scheme)
    }

    /// Probe PIN1 retry state and resolve the card's credential numbering
    /// with counter-safe probes.
    ///
    /// Probes Citizen, then Organizational, then Estonian eID. A recognized
    /// PIN status settles the numbering immediately without spending a retry.
    /// A security-channel refusal (`SecurityNotSatisfied` or
    /// `SmDataObjectsIncorrect`, e.g. a contactless card before PACE) stops
    /// probing immediately rather than sending further probes. Any other
    /// unrecognized status word advances to the next profile, falling back
    /// to Citizen with the citizen probe's status when all three miss.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn pin1_status_and_scheme(
        &mut self,
    ) -> Result<(PinReferenceScheme, PinStatus), AuthError<Self::Error>>
    where
        Self: Sized,
    {
        const fn stops_scheme_probe(sw: StatusWord) -> bool {
            matches!(
                sw,
                StatusWord::SecurityNotSatisfied | StatusWord::SmDataObjectsIncorrect
            )
        }

        let citizen = self.probe_status_word(PinReferenceScheme::Citizen, PinSlot::Pin1)?;
        let citizen_status = classify_pin_status_sw(citizen);
        if !matches!(citizen_status, PinStatus::Other(_)) || stops_scheme_probe(citizen) {
            return Ok((PinReferenceScheme::Citizen, citizen_status));
        }
        for scheme in [
            PinReferenceScheme::Organizational,
            PinReferenceScheme::Estonian,
        ] {
            let sw = self.probe_status_word(scheme, PinSlot::Pin1)?;
            let status = classify_pin_status_sw(sw);
            if !matches!(status, PinStatus::Other(_)) {
                return Ok((scheme, status));
            }
            if stops_scheme_probe(sw) {
                return Ok((PinReferenceScheme::Citizen, status));
            }
        }
        Ok((PinReferenceScheme::Citizen, citizen_status))
    }

    /// Resolve the card's credential numbering with a counter-safe
    /// probe. The citizen numbering is tried first; a
    /// reference-not-found answer re-probes under the organizational
    /// numbering, then the Estonian eID numbering, and a recognized
    /// state there settles it. Nothing but the card is trusted, and no
    /// counter is touched.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn resolve_pin_reference_scheme(&mut self) -> Result<PinReferenceScheme, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        self.pin1_status_and_scheme().map(|(scheme, _)| scheme)
    }

    /// Probe the retry state of a slot without decrementing any counter,
    /// resolving the numbering first.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn pin_status(&mut self, slot: PinSlot) -> Result<PinStatus, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        if slot == PinSlot::Pin1 {
            self.pin1_status_and_scheme().map(|(_, status)| status)
        } else {
            let scheme = self.resolve_pin_reference_scheme()?;
            self.pin_status_with_scheme(scheme, slot)
        }
    }

    /// Probe the retry state of a slot under an explicit numbering.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn pin_status_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
        slot: PinSlot,
    ) -> Result<PinStatus, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        Ok(classify_pin_status_sw(
            self.probe_status_word(scheme, slot)?,
        ))
    }

    /// VERIFY PIN1 using validated card parameters derived from the
    /// card's parsed EF.AOD ([`CardPinParameters::from_aod`]).
    ///
    /// Checks `pin` against `parameters.lengths()`, probes the card's
    /// counter under `parameters.reference()`, enforces the retry floor
    /// on `parameters.scheme()`, and encodes the credential block using
    /// `parameters.encoding()` (`storedLength` + `padChar`, or bare
    /// typed digits).
    ///
    /// # Errors
    ///
    /// [`AuthError::PinLength`] when `pin` falls outside the card's
    /// EF.AOD length range, [`AuthError::RetryFloor`] when the retry
    /// floor refuses the attempt, or transport / command failures.
    fn verify_pin1_with_parameters(
        &mut self,
        parameters: &CardPinParameters,
        pin: Pin1,
    ) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        parameters
            .check_length(CredentialRole::Pin1, pin.digit_count())
            .map_err(AuthError::PinLength)?;
        let status = self.pin_status_for_parameters(parameters)?;
        check_retry_floor_with_scheme(FlooredCredential::Pin1, status, parameters.scheme())
            .map_err(AuthError::RetryFloor)?;
        let header = CommandHeader {
            class: ApduClass::Plain,
            instruction: VERIFY_INS,
            p1: VERIFY_P1,
            p2: parameters.reference(),
        };
        let sw =
            credential_exchange_groups(self, header, &[(pin.digits(), parameters.encoding())])?;
        Ok(classify_verify_sw(sw))
    }

    /// Probe the retry state of the credential described by
    /// `parameters` without decrementing any counter.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn pin_status_for_parameters(
        &mut self,
        parameters: &CardPinParameters,
    ) -> Result<PinStatus, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        Ok(classify_pin_status_sw(probe_status_word_for_reference(
            self,
            parameters.reference(),
        )?))
    }

    /// Send the counter-safe VERIFY status probe and return the raw
    /// status word.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn probe_status_word(
        &mut self,
        scheme: PinReferenceScheme,
        slot: PinSlot,
    ) -> Result<StatusWord, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        probe_status_word_for_reference(self, scheme.reference(slot))
    }
}

impl<T: CardTransport + ?Sized> PinOps for T {}

#[cfg(test)]
mod tests {
    use super::{
        AuthError, CREDENTIAL_BODY_MAX, CREDENTIAL_BODY_SCRATCH, PIN_STORED_LENGTH, PIN1_REFERENCE,
        PIN1_REFERENCE_ORGANIZATIONAL, PIN2_REFERENCE, PIN2_REFERENCE_ORGANIZATIONAL, PinOps,
        PinPadByte, PinReferenceScheme, PinSlot, PinStatus, VERIFY_INS, VERIFY_P1, VerifyOutcome,
        classify_pin_status_sw, classify_verify_sw, write_credential_blocks,
    };
    use crate::credentials::{PIN_MAX_LENGTH, Pin1, Pin2, UnvalidatedSecret};
    use crate::retry_risk::{FlooredCredential, RetryFloorRefusal};
    use refineid_apdu::{
        ApduClass, CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu,
        StatusWord, TransportOutcome,
    };

    /// A retry count for the classifier tests.
    const THREE_RETRIES: u8 = 3;
    /// Lowest retry count served by the retry floor.
    const RETRIES_FLOOR: u8 = 2;
    /// Retry count one wrong try from lockout (refused by the floor).
    const RETRIES_LOCKDOWN_IMMINENT: u8 = 1;
    /// Retry count of an exhausted PIN.
    const RETRIES_EXHAUSTED: u8 = 0;
    /// Length of the PIN fixture used in the block tests.
    const PIN_FIXTURE_LEN: usize = 4;
    /// Digits shared by the exact-wire tests.
    const WIRE_DIGITS: &[u8] = b"1234";
    /// A PIN at the longest length either role accepts.
    const LONGEST_DIGITS: &[u8] = b"135792468024";
    /// Length of a VERIFY header: class, instruction, P1, P2.
    const HEADER_LENGTH: usize = 4;

    /// A VERIFY header for `reference`, built from named constants so the
    /// wire tests carry no bare byte values.
    fn verify_header(reference: u8) -> [u8; HEADER_LENGTH] {
        [ApduClass::Plain.as_byte(), VERIFY_INS, VERIFY_P1, reference]
    }

    fn scripted_response(sw: StatusWord) -> ResponseApdu {
        let [sw1, sw2] = sw.as_u16().to_be_bytes();
        ResponseApdu {
            body: vec![],
            sw1,
            sw2,
        }
    }

    fn pin1(digits: &[u8]) -> Pin1 {
        Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(digits.to_vec()))
            .expect("valid PIN1 fixture")
    }

    fn pin2(digits: &[u8]) -> Pin2 {
        Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(digits.to_vec()))
            .expect("valid PIN2 fixture")
    }

    /// Records the last plain and credential wire the trait produced,
    /// answering every plain exchange (the counter-safe probe) with
    /// `probe_sw` and every credential exchange with `credential_sw`.
    struct WireRecorder {
        plain: Option<Vec<u8>>,
        plain_all: Vec<Vec<u8>>,
        credential: Option<Vec<u8>>,
        probe_sw: StatusWord,
        credential_sw: StatusWord,
    }

    impl WireRecorder {
        /// A card answering every exchange with `sw`.
        fn new(sw: StatusWord) -> Self {
            Self::answering(sw, sw)
        }

        /// A card answering the probe with `probe_sw` and the credential
        /// command with `credential_sw`.
        fn answering(probe_sw: StatusWord, credential_sw: StatusWord) -> Self {
            Self {
                plain: None,
                plain_all: Vec::new(),
                credential: None,
                probe_sw,
                credential_sw,
            }
        }
    }

    impl CardTransport for WireRecorder {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let wire = command.as_bytes().to_vec();
            self.plain_all.push(wire.clone());
            self.plain = Some(wire);
            Ok(TransportOutcome::Response(scripted_response(self.probe_sw)))
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.credential = Some(command.expose_wire(<[u8]>::to_vec));
            Ok(TransportOutcome::Response(scripted_response(
                self.credential_sw,
            )))
        }
    }

    /// A counter-safe probe answer at `count` tries left.
    fn counter(count: u8) -> StatusWord {
        StatusWord::PinIncorrect {
            retries: PinRetries::from_nibble(count).expect("fits a nibble"),
        }
    }

    /// VERIFY `slot`'s PIN under `scheme` against `transport`.
    fn verify_slot(
        transport: &mut WireRecorder,
        scheme: PinReferenceScheme,
        slot: PinSlot,
    ) -> Result<VerifyOutcome, AuthError<String>> {
        match slot {
            PinSlot::Pin1 => transport.verify_pin1_with_scheme(scheme, pin1(WIRE_DIGITS)),
            PinSlot::Pin2 => transport.verify_pin2_with_scheme(scheme, pin2(WIRE_DIGITS)),
        }
    }

    #[test]
    fn citizen_verify_probes_the_counter_then_ships_the_padded_block() {
        let mut transport = WireRecorder::new(StatusWord::Success);
        transport
            .verify_pin1_with_scheme(PinReferenceScheme::Citizen, pin1(WIRE_DIGITS))
            .expect("scripted verify succeeds");
        let mut expected = verify_header(PIN1_REFERENCE).to_vec();
        expected.push(PIN_STORED_LENGTH as u8);
        let mut block = WIRE_DIGITS.to_vec();
        block.resize(PIN_STORED_LENGTH, PinPadByte::FINEID.octet());
        expected.extend_from_slice(&block);
        assert_eq!(transport.credential.as_deref(), Some(expected.as_slice()));
        assert_eq!(
            transport.plain.as_deref(),
            Some(verify_header(PIN1_REFERENCE).as_slice()),
            "the only plain command is the counter-safe probe: no digits"
        );
    }

    #[test]
    fn a_verify_at_the_last_try_sends_only_the_probe() {
        // The caller has probed nothing; the primitive still refuses, so
        // no caller can spend the last try by mistake.
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            let mut transport =
                WireRecorder::answering(counter(RETRIES_LOCKDOWN_IMMINENT), StatusWord::Success);
            let refused = verify_slot(&mut transport, PinReferenceScheme::Citizen, slot);
            assert!(matches!(
                refused,
                Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
                    credential,
                    remaining,
                })) if credential == FlooredCredential::from(slot)
                    && remaining.get() == RETRIES_LOCKDOWN_IMMINENT
            ));
            let reference = PinReferenceScheme::Citizen.reference(slot);
            assert_eq!(
                transport.plain.as_deref(),
                Some(verify_header(reference).as_slice()),
                "the probe carries no data"
            );
            assert!(
                transport.credential.is_none(),
                "no VERIFY carrying digits reached the wire"
            );
        }
    }

    #[test]
    fn a_verify_at_an_unreadable_counter_sends_only_the_probe() {
        let mut transport =
            WireRecorder::answering(StatusWord::AuthenticationFailed, StatusWord::Success);
        let refused =
            transport.verify_pin1_with_scheme(PinReferenceScheme::Citizen, pin1(WIRE_DIGITS));
        assert!(matches!(
            refused,
            Err(AuthError::RetryFloor(
                RetryFloorRefusal::CounterUnreadable {
                    credential: FlooredCredential::Pin1
                }
            ))
        ));
        assert!(transport.credential.is_none());
    }

    #[test]
    fn a_verify_at_no_tries_left_or_blocked_goes_to_the_card() {
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            for probe in [
                counter(RETRIES_EXHAUSTED),
                StatusWord::AuthenticationBlocked,
            ] {
                let mut transport =
                    WireRecorder::answering(probe, StatusWord::AuthenticationBlocked);
                let outcome = verify_slot(&mut transport, PinReferenceScheme::Citizen, slot)
                    .expect("the card answers for itself");
                assert_eq!(outcome, VerifyOutcome::Locked);
                let wire = transport.credential.expect("the VERIFY was sent");
                assert_eq!(
                    wire.get(..verify_header(PIN1_REFERENCE).len()),
                    Some(verify_header(PinReferenceScheme::Citizen.reference(slot)).as_slice())
                );
            }
        }
    }

    #[test]
    fn a_verified_pin_and_three_or_two_tries_left_are_served() {
        for probe in [
            StatusWord::Success,
            counter(THREE_RETRIES),
            counter(RETRIES_FLOOR),
        ] {
            let mut transport = WireRecorder::answering(probe, StatusWord::Success);
            let outcome = transport
                .verify_pin2_with_scheme(PinReferenceScheme::Citizen, pin2(WIRE_DIGITS))
                .expect("served");
            assert_eq!(outcome, VerifyOutcome::Ok);
            assert!(transport.credential.is_some());
            assert_eq!(
                transport.plain.as_deref(),
                Some(verify_header(PIN2_REFERENCE).as_slice())
            );
        }
    }

    #[test]
    fn the_scheme_free_verify_floors_on_the_probe_that_resolves_the_numbering() {
        let mut transport =
            WireRecorder::answering(counter(RETRIES_LOCKDOWN_IMMINENT), StatusWord::Success);
        let refused = transport.verify_pin1(pin1(WIRE_DIGITS));
        assert!(matches!(
            refused,
            Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
                credential: FlooredCredential::Pin1,
                ..
            }))
        ));
        assert!(transport.credential.is_none());
    }

    #[test]
    fn organizational_verify_ships_the_bare_typed_digits_under_the_org_reference() {
        let mut transport = WireRecorder::new(StatusWord::Success);
        transport
            .verify_pin1_with_scheme(PinReferenceScheme::Organizational, pin1(WIRE_DIGITS))
            .expect("scripted verify succeeds");
        let mut expected = verify_header(PIN1_REFERENCE_ORGANIZATIONAL).to_vec();
        expected.push(WIRE_DIGITS.len() as u8);
        expected.extend_from_slice(WIRE_DIGITS);
        assert_eq!(transport.credential.as_deref(), Some(expected.as_slice()));
    }

    #[test]
    fn the_counter_safe_probe_sends_only_the_header() {
        let mut transport = WireRecorder::new(StatusWord::Success);
        transport
            .pin_status_with_scheme(PinReferenceScheme::Citizen, PinSlot::Pin1)
            .expect("scripted probe succeeds");
        assert_eq!(
            transport.plain.as_deref(),
            Some(verify_header(PIN1_REFERENCE).as_slice())
        );
        assert!(
            transport.credential.is_none(),
            "the counter-safe probe carries no credential"
        );
    }

    #[test]
    fn slot_references_are_distinct() {
        assert_eq!(PinSlot::Pin1.reference(), super::PIN1_REFERENCE);
        assert_eq!(PinSlot::Pin2.reference(), super::PIN2_REFERENCE);
        let distinct = PinSlot::Pin1.reference() != PinSlot::Pin2.reference();
        assert!(distinct);
    }

    #[test]
    fn scheme_references_differ_between_citizen_and_organizational() {
        assert_eq!(
            PinReferenceScheme::Citizen.reference(PinSlot::Pin1),
            super::PIN1_REFERENCE
        );
        assert_eq!(
            PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
            super::PIN1_REFERENCE_ORGANIZATIONAL
        );
        assert_eq!(
            PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
            super::PIN2_REFERENCE_ORGANIZATIONAL
        );
    }

    #[test]
    fn estonian_scheme_uses_the_aod_references_and_zero_pad() {
        assert_eq!(
            PinReferenceScheme::Estonian.reference(PinSlot::Pin1),
            super::PIN1_REFERENCE_ESTONIAN
        );
        assert_eq!(
            PinReferenceScheme::Estonian.reference(PinSlot::Pin2),
            super::PIN2_REFERENCE_ESTONIAN
        );
        assert_eq!(
            PinReferenceScheme::Estonian.puk_reference(),
            super::PUK_REFERENCE_ESTONIAN
        );
        assert_eq!(
            PinReferenceScheme::Estonian.pad().octet(),
            super::ESTONIAN_EID_PAD_OCTET
        );
    }

    #[test]
    fn citizen_block_pads_and_organizational_block_stays_typed_length() {
        let mut citizen = [PinPadByte::FINEID.octet(); CREDENTIAL_BODY_MAX];
        let citizen_total = write_credential_blocks(
            PinReferenceScheme::Citizen,
            &[b"1234"],
            PinPadByte::FINEID,
            &mut citizen,
        )
        .expect("valid citizen block");
        assert_eq!(citizen_total, PIN_STORED_LENGTH);
        assert_eq!(&citizen[..PIN_FIXTURE_LEN], b"1234");
        assert!(
            citizen[PIN_FIXTURE_LEN..PIN_STORED_LENGTH]
                .iter()
                .all(|&byte| byte == PinPadByte::FINEID.octet())
        );

        let mut organizational = [PinPadByte::FINEID.octet(); CREDENTIAL_BODY_MAX];
        let org_total = write_credential_blocks(
            PinReferenceScheme::Organizational,
            &[b"1234"],
            PinPadByte::FINEID,
            &mut organizational,
        )
        .expect("valid organizational block");
        assert_eq!(org_total, PIN_FIXTURE_LEN);
        assert_eq!(&organizational[..PIN_FIXTURE_LEN], b"1234");
    }

    #[test]
    fn a_two_block_citizen_body_pads_each_block_to_the_stored_length() {
        let mut body = [PinPadByte::FINEID.octet(); CREDENTIAL_BODY_MAX];
        let total = write_credential_blocks(
            PinReferenceScheme::Citizen,
            &[b"1234", b"567890"],
            PinPadByte::FINEID,
            &mut body,
        )
        .expect("valid two-block body");
        assert_eq!(total, CREDENTIAL_BODY_SCRATCH);
        assert_eq!(&body[..PIN_FIXTURE_LEN], b"1234");
        assert_eq!(
            &body[PIN_STORED_LENGTH..PIN_STORED_LENGTH + b"567890".len()],
            b"567890"
        );
    }

    #[test]
    fn organizational_verify_ships_a_twelve_digit_pin_unpadded() {
        assert_eq!(LONGEST_DIGITS.len(), PIN_MAX_LENGTH);
        let mut expected_pin1 = verify_header(PIN1_REFERENCE_ORGANIZATIONAL).to_vec();
        expected_pin1.push(LONGEST_DIGITS.len() as u8);
        expected_pin1.extend_from_slice(LONGEST_DIGITS);
        let mut transport = WireRecorder::new(StatusWord::Success);
        transport
            .verify_pin1_with_scheme(PinReferenceScheme::Organizational, pin1(LONGEST_DIGITS))
            .expect("scripted verify succeeds");
        assert_eq!(
            transport.credential.as_deref(),
            Some(expected_pin1.as_slice())
        );

        let mut expected_pin2 = verify_header(PIN2_REFERENCE_ORGANIZATIONAL).to_vec();
        expected_pin2.push(LONGEST_DIGITS.len() as u8);
        expected_pin2.extend_from_slice(LONGEST_DIGITS);
        let mut transport = WireRecorder::new(StatusWord::Success);
        transport
            .verify_pin2_with_scheme(PinReferenceScheme::Organizational, pin2(LONGEST_DIGITS))
            .expect("scripted verify succeeds");
        assert_eq!(
            transport.credential.as_deref(),
            Some(expected_pin2.as_slice())
        );
    }

    #[test]
    fn verify_classifier_covers_the_outcomes() {
        assert_eq!(classify_verify_sw(StatusWord::Success), VerifyOutcome::Ok);
        let three = PinRetries::from_nibble(THREE_RETRIES).expect("fits a nibble");
        assert_eq!(
            classify_verify_sw(StatusWord::PinIncorrect { retries: three }),
            VerifyOutcome::WrongPin {
                retries_left: three
            }
        );
        assert_eq!(
            classify_verify_sw(StatusWord::AuthenticationBlocked),
            VerifyOutcome::Locked
        );
        assert_eq!(
            classify_verify_sw(StatusWord::ReferenceDataInvalidated),
            VerifyOutcome::Locked
        );
        assert_eq!(
            classify_verify_sw(StatusWord::FileNotFound),
            VerifyOutcome::Other(StatusWord::FileNotFound)
        );
    }

    #[test]
    fn status_classifier_covers_the_states() {
        assert_eq!(
            classify_pin_status_sw(StatusWord::Success),
            PinStatus::Verified
        );
        let three = PinRetries::from_nibble(THREE_RETRIES).expect("fits a nibble");
        assert_eq!(
            classify_pin_status_sw(StatusWord::PinIncorrect { retries: three }),
            PinStatus::Remaining(three)
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::AuthenticationFailed),
            PinStatus::NoInfo
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::AuthenticationBlocked),
            PinStatus::Locked
        );
    }

    struct ScriptedProbes {
        steps: Vec<([u8; HEADER_LENGTH], StatusWord)>,
        cursor: usize,
    }

    impl ScriptedProbes {
        fn new(steps: Vec<([u8; HEADER_LENGTH], StatusWord)>) -> Self {
            Self { steps, cursor: 0 }
        }

        fn assert_drained(&self) {
            assert_eq!(self.cursor, self.steps.len());
        }
    }

    impl CardTransport for ScriptedProbes {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let (expected, sw) = self
                .steps
                .get(self.cursor)
                .ok_or_else(|| format!("unexpected probe at step {}", self.cursor))?;
            assert_eq!(command.as_bytes(), expected.as_slice());
            self.cursor += 1;
            Ok(TransportOutcome::Response(scripted_response(*sw)))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("no credential expected during probe test".to_owned())
        }
    }

    #[test]
    fn pin1_status_and_scheme_resolves_estonian_across_recognized_states() {
        /// ISO 7816-4 incorrect P1-P2 status word.
        const INCORRECT_P1_P2_SW: u16 = 0x6A86;
        let estonian_ref = PinReferenceScheme::Estonian.reference(PinSlot::Pin1);
        let three = PinRetries::from_nibble(THREE_RETRIES).expect("fits a nibble");
        for (miss_sw, estonian_sw, expected_status) in [
            (
                StatusWord::ReferenceDataNotFound,
                counter(THREE_RETRIES),
                PinStatus::Remaining(three),
            ),
            (
                StatusWord::from_u16(INCORRECT_P1_P2_SW),
                StatusWord::Success,
                PinStatus::Verified,
            ),
            (
                StatusWord::ReferenceDataNotFound,
                StatusWord::AuthenticationBlocked,
                PinStatus::Locked,
            ),
            (
                StatusWord::ReferenceDataNotFound,
                StatusWord::AuthenticationFailed,
                PinStatus::NoInfo,
            ),
        ] {
            let mut transport = ScriptedProbes::new(vec![
                (verify_header(PIN1_REFERENCE), miss_sw),
                (verify_header(PIN1_REFERENCE_ORGANIZATIONAL), miss_sw),
                (verify_header(estonian_ref), estonian_sw),
            ]);
            let resolved = transport
                .pin1_status_and_scheme()
                .expect("probe sequence succeeds");
            assert_eq!(resolved, (PinReferenceScheme::Estonian, expected_status));
            transport.assert_drained();
        }
    }

    #[test]
    fn pin1_status_and_scheme_stops_on_security_refusal_and_falls_back_on_all_miss() {
        let mut pre_pace = ScriptedProbes::new(vec![(
            verify_header(PIN1_REFERENCE),
            StatusWord::SecurityNotSatisfied,
        )]);
        assert_eq!(
            pre_pace.pin1_status_and_scheme().expect("stops cleanly"),
            (
                PinReferenceScheme::Citizen,
                PinStatus::Other(StatusWord::SecurityNotSatisfied),
            )
        );
        pre_pace.assert_drained();

        let estonian_ref = PinReferenceScheme::Estonian.reference(PinSlot::Pin1);
        let mut all_miss = ScriptedProbes::new(vec![
            (
                verify_header(PIN1_REFERENCE),
                StatusWord::ReferenceDataNotFound,
            ),
            (
                verify_header(PIN1_REFERENCE_ORGANIZATIONAL),
                StatusWord::ReferenceDataNotFound,
            ),
            (
                verify_header(estonian_ref),
                StatusWord::ReferenceDataNotFound,
            ),
        ]);
        assert_eq!(
            all_miss
                .pin1_status_and_scheme()
                .expect("falls back cleanly"),
            (
                PinReferenceScheme::Citizen,
                PinStatus::Other(StatusWord::ReferenceDataNotFound),
            )
        );
        all_miss.assert_drained();
    }

    #[test]
    fn estonian_verify_respects_the_three_try_scale_and_one_try_floor() {
        for served_tries in [THREE_RETRIES, RETRIES_FLOOR] {
            let mut served = WireRecorder::answering(counter(served_tries), StatusWord::Success);
            assert_eq!(
                served
                    .verify_pin1_with_scheme(PinReferenceScheme::Estonian, pin1(WIRE_DIGITS))
                    .expect("three and two tries are served"),
                VerifyOutcome::Ok
            );
            assert!(served.credential.is_some());
        }

        let mut refused =
            WireRecorder::answering(counter(RETRIES_LOCKDOWN_IMMINENT), StatusWord::Success);
        assert!(matches!(
            refused.verify_pin1_with_scheme(PinReferenceScheme::Estonian, pin1(WIRE_DIGITS)),
            Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
                credential: FlooredCredential::Pin1,
                remaining,
            })) if remaining.get() == RETRIES_LOCKDOWN_IMMINENT
        ));
        assert!(refused.credential.is_none());

        let above_estonian_limit = THREE_RETRIES + 1;
        let mut unreadable =
            WireRecorder::answering(counter(above_estonian_limit), StatusWord::Success);
        assert!(matches!(
            unreadable.verify_pin1_with_scheme(PinReferenceScheme::Estonian, pin1(WIRE_DIGITS)),
            Err(AuthError::RetryFloor(
                RetryFloorRefusal::CounterUnreadable {
                    credential: FlooredCredential::Pin1,
                }
            ))
        ));
        assert!(unreadable.credential.is_none());
    }

    #[test]
    fn estonian_verify_pin2_probes_and_ships_zero_padded_block_under_pin2_ref() {
        const FIVE_DIGIT_PIN2: &[u8] = b"12345";
        let mut transport = WireRecorder::answering(counter(THREE_RETRIES), StatusWord::Success);
        let outcome = transport
            .verify_pin2_with_scheme(PinReferenceScheme::Estonian, pin2(FIVE_DIGIT_PIN2))
            .expect("Estonian PIN2 verifies in shared PKCS#15 eID app");
        assert_eq!(outcome, VerifyOutcome::Ok);
        let pin2_ref = PinReferenceScheme::Estonian.reference(PinSlot::Pin2);
        assert_eq!(
            transport.plain_all.first().map(Vec::as_slice),
            Some(verify_header(pin2_ref).as_slice())
        );
        assert_eq!(
            transport.plain_all.get(1).and_then(|wire| wire.get(1)),
            Some(&crate::activation::GET_DATA_INS)
        );
        let mut expected = verify_header(pin2_ref).to_vec();
        expected.push(PIN_STORED_LENGTH as u8);
        let mut block = FIVE_DIGIT_PIN2.to_vec();
        block.resize(PIN_STORED_LENGTH, PinPadByte::ESTONIAN_EID.octet());
        expected.extend_from_slice(&block);
        assert_eq!(transport.credential.as_deref(), Some(expected.as_slice()));
    }
}

#[cfg(test)]
mod profile_pad_tests {
    use super::{
        CREDENTIAL_BODY_MAX, PIN_STORED_LENGTH, PinPadByte, PinReferenceScheme,
        write_credential_blocks,
    };

    /// The PIN1 fixture these tests assemble into a block; a test value,
    /// not a credential.
    const TEST_PIN1: &[u8] = b"1234";

    #[test]
    fn the_estonian_profile_pads_with_zero() {
        assert_eq!(
            PinPadByte::ESTONIAN_EID.octet(),
            super::ESTONIAN_EID_PAD_OCTET
        );
    }

    #[test]
    fn an_estonian_block_pads_with_its_profile_byte() {
        let mut body = [PinPadByte::FINEID.octet(); CREDENTIAL_BODY_MAX];
        let total = write_credential_blocks(
            PinReferenceScheme::Estonian,
            &[TEST_PIN1],
            PinPadByte::ESTONIAN_EID,
            &mut body,
        )
        .expect("valid Estonian block");
        assert_eq!(total, PIN_STORED_LENGTH);
        assert_eq!(&body[..TEST_PIN1.len()], TEST_PIN1);
        assert!(
            body[TEST_PIN1.len()..PIN_STORED_LENGTH]
                .iter()
                .all(|&byte| byte == PinPadByte::ESTONIAN_EID.octet())
        );
    }

    #[test]
    fn card_pin_parameters_enforce_aod_padding_and_drive_custom_wire_encoding() {
        use refineid_apdu::{
            ApduClass, CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu,
            StatusWord, TransportOutcome,
        };
        use refineid_ber::{BerEncoder, BerTag, BitString, Integer, OctetString, Sequence, tlv};
        use refineid_pkcs15::AuthenticationObjects;

        use super::{
            AodPinParametersError, CardPinParameters, PinBlockEncoding, PinOps, VERIFY_INS,
            VERIFY_P1, VerifyOutcome,
        };
        use crate::credentials::{Pin1, UnvalidatedSecret};

        const ENUMERATED_TAG: u8 = 0x0A;
        const TYPE_ATTRIBUTES_TAG: u8 = 0xA1;
        const PWD_REFERENCE_TAG: u8 = 0x80;
        const ASCII_NUMERIC: u8 = 1;
        const NEEDS_PADDING_FLAGS: &[u8] = &[0x04, 0xCC, 0x10];
        const BARE_FLAGS: &[u8] = &[0x00, 0x00];
        const CUSTOM_REF: u8 = 0x84;
        const CUSTOM_MIN: u8 = 5;
        const CUSTOM_STORED: u8 = 8;
        const CUSTOM_PAD: u8 = 0xFF;
        const OVERSIZED_STORED: u8 = 16;
        const THREE_TRIES: u8 = 3;
        const HEADER_AND_LC_LEN: usize = 5;
        const FIVE_DIGITS: &[u8] = b"54321";
        const FOUR_DIGITS: &[u8] = b"1234";
        const UNSIGNED_PREFIX: u8 = 0x00;

        let build_aod = |flags: &[u8], min: u8, stored: u8, pad: Option<u8>| {
            let mut attrs = BerEncoder::default();
            attrs
                .push_tlv(
                    u8::try_from(<BitString as BerTag>::TAG).expect("fits"),
                    flags,
                )
                .expect("encodes");
            attrs
                .push_tlv(ENUMERATED_TAG, [ASCII_NUMERIC])
                .expect("encodes");
            attrs
                .push_tlv(u8::try_from(<Integer as BerTag>::TAG).expect("fits"), [min])
                .expect("encodes");
            attrs
                .push_tlv(
                    u8::try_from(<Integer as BerTag>::TAG).expect("fits"),
                    [stored],
                )
                .expect("encodes");
            attrs
                .push_tlv(PWD_REFERENCE_TAG, [UNSIGNED_PREFIX, CUSTOM_REF])
                .expect("encodes");
            if let Some(byte) = pad {
                attrs
                    .push_tlv(
                        u8::try_from(<OctetString as BerTag>::TAG).expect("fits"),
                        [byte],
                    )
                    .expect("encodes");
            }
            let seq_tag = u8::try_from(<Sequence as BerTag>::TAG).expect("fits");
            let typed = tlv(
                TYPE_ATTRIBUTES_TAG,
                tlv(seq_tag, attrs.finish()).expect("encodes"),
            )
            .expect("encodes");
            let raw = tlv(seq_tag, typed).expect("encodes");
            AuthenticationObjects::parse(&raw).expect("AOD parses")
        };

        // needs-padding without padChar must fail closed.
        let missing_pad = build_aod(NEEDS_PADDING_FLAGS, CUSTOM_MIN, CUSTOM_STORED, None);
        assert_eq!(
            CardPinParameters::from_aod(PinReferenceScheme::Estonian, &missing_pad.passwords()[0]),
            Err(AodPinParametersError::MissingPadChar)
        );

        // needs-padding clear with padChar present must fail closed.
        let conflicting = build_aod(BARE_FLAGS, CUSTOM_MIN, CUSTOM_STORED, Some(CUSTOM_PAD));
        assert_eq!(
            CardPinParameters::from_aod(PinReferenceScheme::Estonian, &conflicting.passwords()[0]),
            Err(AodPinParametersError::ConflictingPaddingFlags)
        );

        // storedLength exceeding credential block capacity must fail closed.
        let oversized = build_aod(
            NEEDS_PADDING_FLAGS,
            CUSTOM_MIN,
            OVERSIZED_STORED,
            Some(CUSTOM_PAD),
        );
        assert_eq!(
            CardPinParameters::from_aod(PinReferenceScheme::Estonian, &oversized.passwords()[0]),
            Err(AodPinParametersError::InvalidStoredLength {
                stored_length: OVERSIZED_STORED,
            })
        );

        // Bare (unpadded) EF.AOD object produces Bare encoding.
        let bare = build_aod(BARE_FLAGS, CUSTOM_MIN, CUSTOM_STORED, None);
        let bare_params =
            CardPinParameters::from_aod(PinReferenceScheme::Organizational, &bare.passwords()[0])
                .expect("bare AOD object builds parameters");
        assert_eq!(bare_params.encoding(), PinBlockEncoding::Bare);

        // Custom stored length (8) + custom padChar (FF) + custom reference (84).
        let custom = build_aod(
            NEEDS_PADDING_FLAGS,
            CUSTOM_MIN,
            CUSTOM_STORED,
            Some(CUSTOM_PAD),
        );
        let params =
            CardPinParameters::from_aod(PinReferenceScheme::Estonian, &custom.passwords()[0])
                .expect("valid padded AOD object builds parameters");

        struct Recorder {
            plain: Option<Vec<u8>>,
            credential: Option<Vec<u8>>,
        }
        impl CardTransport for Recorder {
            type Error = &'static str;

            fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
                self.plain = Some(command.as_bytes().to_vec());
                let sw = StatusWord::PinIncorrect {
                    retries: PinRetries::from_nibble(THREE_TRIES).expect("fits"),
                };
                let [sw1, sw2] = sw.as_u16().to_be_bytes();
                Ok(TransportOutcome::Response(ResponseApdu {
                    body: Vec::new(),
                    sw1,
                    sw2,
                }))
            }

            fn transmit_credential(
                &mut self,
                command: CredentialCommand,
            ) -> Result<TransportOutcome, Self::Error> {
                self.credential = Some(command.expose_wire(<[u8]>::to_vec));
                let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
                Ok(TransportOutcome::Response(ResponseApdu {
                    body: Vec::new(),
                    sw1,
                    sw2,
                }))
            }
        }

        // A 4-digit PIN below the card's EF.AOD minLength (5) is refused with zero APDUs.
        let mut short_card = Recorder {
            plain: None,
            credential: None,
        };
        let short_pin =
            Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(FOUR_DIGITS.to_vec()))
                .expect("valid Pin1");
        assert!(matches!(
            short_card.verify_pin1_with_parameters(&params, short_pin),
            Err(super::AuthError::PinLength(_))
        ));
        assert!(short_card.plain.is_none());
        assert!(short_card.credential.is_none());

        // A 5-digit PIN transmits P2=84 with an 8-byte FF-padded body.
        let mut card = Recorder {
            plain: None,
            credential: None,
        };
        let pin = Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(FIVE_DIGITS.to_vec()))
            .expect("valid Pin1");
        assert_eq!(
            card.verify_pin1_with_parameters(&params, pin)
                .expect("verify succeeds"),
            VerifyOutcome::Ok
        );
        assert_eq!(
            card.plain,
            Some(vec![
                ApduClass::Plain.as_byte(),
                VERIFY_INS,
                VERIFY_P1,
                CUSTOM_REF
            ])
        );
        let wire = card.credential.expect("credential transmitted");
        assert_eq!(wire.len(), HEADER_AND_LC_LEN + usize::from(CUSTOM_STORED));
        assert_eq!(
            &wire[..HEADER_AND_LC_LEN],
            &[
                ApduClass::Plain.as_byte(),
                VERIFY_INS,
                VERIFY_P1,
                CUSTOM_REF,
                CUSTOM_STORED
            ]
        );
        assert_eq!(
            &wire[HEADER_AND_LC_LEN..HEADER_AND_LC_LEN + FIVE_DIGITS.len()],
            FIVE_DIGITS
        );
        assert!(
            wire[HEADER_AND_LC_LEN + FIVE_DIGITS.len()..]
                .iter()
                .all(|&byte| byte == CUSTOM_PAD)
        );
    }
}
