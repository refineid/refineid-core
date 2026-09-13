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

//! VERIFY PIN1 and PIN2 against a FINEID card.
//!
//! The typed PIN digits are right-padded with the pad byte to the
//! slot's stored length and shipped as a credential command, consumed
//! exactly once by the transport. Because `Pin1` and `Pin2` are
//! validated at construction, no local re-check is needed and the slot
//! is fixed by the argument type, so a PIN2 can never be sent to the
//! PIN1 slot.
//!
//! The counter-safe status probe (`VERIFY` with an empty data field)
//! reads the retry state without decrementing any counter, per FINEID
//! S1 v4.2 section 4.1.2, and is the safe pre-flight before an
//! operation that would burn a retry on a wrong PIN.

use refineid_apdu::{
    ApduClass, CREDENTIAL_BODY_MAX, CardTransport, CommandApdu, CommandHeader, CredentialBody,
    CredentialBodyError, CredentialCommand, PinRetries, StatusWord, TransportOutcome,
    UnvalidatedCredentialBlock,
};

use crate::credentials::{Pin1, Pin2};

/// Citizen-card PIN1 reference: the global authentication PIN (FINEID S1
/// v4.2 section 3.5.2).
pub const PIN1_REFERENCE: u8 = 0x11;
/// Citizen-card PIN2 reference: the local qualified-signature PIN (FINEID
/// S1 v4.2 section 3.5.2).
pub const PIN2_REFERENCE: u8 = 0x82;

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

/// Largest credential the organizational card stores; it compares at the
/// typed length and caps every credential here (FINEID S4-2 v4.0
/// section 4.3).
pub const ORGANIZATIONAL_PIN_MAX_LENGTH: usize = 8;

/// VERIFY instruction byte (ISO 7816-4 section 7.5.6).
pub(crate) const VERIFY_INS: u8 = 0x20;
/// VERIFY P1 selecting the verify operation.
pub(crate) const VERIFY_P1: u8 = 0x00;

/// FINEID stored length for both PIN slots: the padded block length in
/// bytes (FINEID S1 v4.2 section 3.5).
pub const PIN_STORED_LENGTH: usize = 12;
/// Padding byte applied to the right of the typed digits; FINEID cards
/// reject any other padding value.
const PIN_PAD_BYTE: u8 = 0x00;

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
/// v4.0 section 4.2 security-data-object identifiers instead. The S4-2
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
        }
    }

    /// The PUK reference byte under this numbering.
    #[must_use]
    pub const fn puk_reference(self) -> u8 {
        match self {
            Self::Citizen => PUK_REFERENCE,
            Self::Organizational => PUK_REFERENCE_ORGANIZATIONAL,
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
    /// The typed PIN is longer than the organizational card stores. That
    /// card compares at the typed length and caps every credential at
    /// [`ORGANIZATIONAL_PIN_MAX_LENGTH`], so a longer entry can never
    /// match; it is refused locally before any command, so no retry is
    /// spent learning it.
    LengthUnsupported {
        /// The maximum the card stores.
        max: usize,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for AuthError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "auth transport: {e}"),
            Self::Outcome(outcome) => write!(f, "auth transport state: {outcome}"),
            Self::Command(e) => write!(f, "auth command: {e}"),
            Self::LengthUnsupported { max } => write!(
                f,
                "auth: PIN length exceeds the organizational card's {max}-digit maximum"
            ),
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

/// Largest credential body this crate assembles: two stored-length
/// blocks, as a CHANGE REFERENCE DATA (current, new) or a citizen RESET
/// RETRY COUNTER (unblocking code, new) carries.
pub(crate) const CREDENTIAL_BODY_SCRATCH: usize = 2 * PIN_STORED_LENGTH;

/// Write each digit group as a `scheme`-shaped credential block into
/// `out`, returning the total byte count the card compares.
///
/// The citizen card compares a block right-padded with the pad byte to
/// the stored length; the organizational card compares the bare typed
/// digits at their own length, because it publishes no padding and a
/// padded block would fail the comparison and spend a retry. `out` must
/// be pre-filled with the pad byte so the citizen padding falls out of
/// the untouched tail.
pub(crate) fn write_credential_blocks(
    scheme: PinReferenceScheme,
    groups: &[&[u8]],
    out: &mut [u8; CREDENTIAL_BODY_MAX],
) -> usize {
    // The two stored-length blocks this assembles must fit the wire
    // credential body buffer the transport layer holds.
    const { assert!(CREDENTIAL_BODY_SCRATCH <= CREDENTIAL_BODY_MAX) };
    let mut total = 0;
    for group in groups {
        let copy_len = group.len().min(PIN_STORED_LENGTH);
        out[total..total + copy_len].copy_from_slice(&group[..copy_len]);
        total += match scheme {
            PinReferenceScheme::Citizen => PIN_STORED_LENGTH,
            PinReferenceScheme::Organizational => copy_len,
        };
    }
    total
}

/// Assemble the credential blocks for `groups` into one credential
/// command under `header` and `scheme`, transmit it once, and return the
/// card's status word for the caller to classify.
///
/// The organizational card compares at the typed length and caps every
/// credential at [`ORGANIZATIONAL_PIN_MAX_LENGTH`], so a longer group can
/// never match; it is refused locally before any command, so no retry is
/// spent learning it.
///
/// # Errors
///
/// [`AuthError`] on an unsupported length, a command-assembly failure, a
/// transport failure, or a transport state transition.
pub(crate) fn credential_exchange<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
    header: CommandHeader,
    groups: &[&[u8]],
) -> Result<StatusWord, AuthError<T::Error>> {
    if matches!(scheme, PinReferenceScheme::Organizational) {
        for group in groups {
            if group.len() > ORGANIZATIONAL_PIN_MAX_LENGTH {
                return Err(AuthError::LengthUnsupported {
                    max: ORGANIZATIONAL_PIN_MAX_LENGTH,
                });
            }
        }
    }
    // The block owns the assembled credential octets in a zeroizing
    // buffer. Pre-fill it with the pad byte so the citizen padding falls
    // out of the untouched tail, as `write_credential_blocks` expects.
    let mut block = UnvalidatedCredentialBlock::zeroed();
    block.buffer().fill(PIN_PAD_BYTE);
    let total = write_credential_blocks(scheme, groups, block.buffer());
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

/// Assemble and send the VERIFY credential command for `slot` under
/// `scheme`, classifying the card's status word.
///
/// Crate-private on purpose: the only entries to a VERIFY are the typed
/// [`PinOps::verify_pin1`] and [`PinOps::verify_pin2`] family, which take a
/// validated [`Pin1`] or [`Pin2`]. There is no public raw-digit VERIFY, so
/// no caller outside this crate can present arbitrary bytes as a PIN and
/// spend a retry on them.
///
/// # Errors
///
/// [`AuthError`] on an unsupported length, a command-assembly failure, a
/// transport failure, or a transport state transition.
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
    let status = credential_exchange(transport, scheme, header, &[digits])?;
    Ok(classify_verify_sw(status))
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
    /// a citizen block. The PIN is consumed and its digits are zeroized.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition. A wrong
    /// PIN is not an error; it is [`VerifyOutcome::WrongPin`].
    fn verify_pin1(&mut self, pin: Pin1) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let scheme = self.resolve_pin_reference_scheme()?;
        self.verify_pin1_with_scheme(scheme, pin)
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

    /// VERIFY PIN1 under an explicit numbering.
    ///
    /// # Errors
    ///
    /// As [`PinOps::verify_pin1`], plus [`AuthError::LengthUnsupported`]
    /// when the organizational card cannot store the typed length.
    fn verify_pin1_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
        pin: Pin1,
    ) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        verify_digits(self, scheme, PinSlot::Pin1, pin.digits())
    }

    /// VERIFY PIN2 under an explicit numbering.
    ///
    /// # Errors
    ///
    /// As [`PinOps::verify_pin1_with_scheme`].
    fn verify_pin2_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
        pin: Pin2,
    ) -> Result<VerifyOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        verify_digits(self, scheme, PinSlot::Pin2, pin.digits())
    }

    /// Probe PIN1 retry state and resolve the card's credential numbering in a
    /// single counter-safe probe when the card uses the citizen numbering.
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
        let citizen = self.probe_status_word(PinReferenceScheme::Citizen, PinSlot::Pin1)?;
        if citizen != StatusWord::ReferenceDataNotFound {
            return Ok((PinReferenceScheme::Citizen, classify_pin_status_sw(citizen)));
        }
        let organizational =
            self.probe_status_word(PinReferenceScheme::Organizational, PinSlot::Pin1)?;
        let status = classify_pin_status_sw(organizational);
        match status {
            PinStatus::Other(_) => {
                Ok((PinReferenceScheme::Citizen, classify_pin_status_sw(citizen)))
            }
            PinStatus::Verified
            | PinStatus::Remaining(_)
            | PinStatus::NoInfo
            | PinStatus::Locked => Ok((PinReferenceScheme::Organizational, status)),
        }
    }

    /// Resolve the card's credential numbering with a counter-safe
    /// probe. The citizen numbering is tried first; a
    /// reference-not-found answer re-probes under the organizational
    /// numbering, and a recognized state there settles it as
    /// organizational. Nothing but the card is trusted, and no counter
    /// is touched.
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
        let command = CommandApdu::case_1(CommandHeader {
            class: ApduClass::Plain,
            instruction: VERIFY_INS,
            p1: VERIFY_P1,
            p2: scheme.reference(slot),
        });
        let response = self
            .transmit(&command)
            .map_err(AuthError::Transport)?
            .into_response()
            .map_err(AuthError::Outcome)?;
        Ok(response.status_word())
    }
}

impl<T: CardTransport + ?Sized> PinOps for T {}

#[cfg(test)]
mod tests {
    use super::{
        CREDENTIAL_BODY_MAX, CREDENTIAL_BODY_SCRATCH, PIN_PAD_BYTE, PIN_STORED_LENGTH,
        PIN1_REFERENCE, PIN1_REFERENCE_ORGANIZATIONAL, PinOps, PinReferenceScheme, PinSlot,
        PinStatus, VERIFY_INS, VERIFY_P1, VerifyOutcome, classify_pin_status_sw,
        classify_verify_sw, write_credential_blocks,
    };
    use crate::credentials::{Pin1, UnvalidatedSecret};
    use refineid_apdu::{
        ApduClass, CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu,
        StatusWord, TransportOutcome,
    };

    /// A retry count for the classifier tests.
    const THREE_RETRIES: u8 = 3;
    /// Length of the PIN fixture used in the block tests.
    const PIN_FIXTURE_LEN: usize = 4;
    /// Digits shared by the exact-wire tests.
    const WIRE_DIGITS: &[u8] = b"1234";
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

    /// Records the last plain and credential wire the trait produced,
    /// answering every exchange with a fixed status word.
    struct WireRecorder {
        plain: Option<Vec<u8>>,
        credential: Option<Vec<u8>>,
        sw: StatusWord,
    }

    impl WireRecorder {
        fn new(sw: StatusWord) -> Self {
            Self {
                plain: None,
                credential: None,
                sw,
            }
        }
    }

    impl CardTransport for WireRecorder {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.plain = Some(command.as_bytes().to_vec());
            Ok(TransportOutcome::Response(scripted_response(self.sw)))
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.credential = Some(command.expose_wire(<[u8]>::to_vec));
            Ok(TransportOutcome::Response(scripted_response(self.sw)))
        }
    }

    #[test]
    fn citizen_verify_ships_the_padded_block_under_the_citizen_reference() {
        let mut transport = WireRecorder::new(StatusWord::Success);
        transport
            .verify_pin1_with_scheme(PinReferenceScheme::Citizen, pin1(WIRE_DIGITS))
            .expect("scripted verify succeeds");
        let mut expected = verify_header(PIN1_REFERENCE).to_vec();
        expected.push(PIN_STORED_LENGTH as u8);
        let mut block = WIRE_DIGITS.to_vec();
        block.resize(PIN_STORED_LENGTH, PIN_PAD_BYTE);
        expected.extend_from_slice(&block);
        assert_eq!(transport.credential.as_deref(), Some(expected.as_slice()));
        assert!(
            transport.plain.is_none(),
            "the PIN must travel only through the credential path"
        );
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
    fn citizen_block_pads_and_organizational_block_stays_typed_length() {
        let mut citizen = [PIN_PAD_BYTE; CREDENTIAL_BODY_MAX];
        let citizen_total =
            write_credential_blocks(PinReferenceScheme::Citizen, &[b"1234"], &mut citizen);
        assert_eq!(citizen_total, PIN_STORED_LENGTH);
        assert_eq!(&citizen[..PIN_FIXTURE_LEN], b"1234");
        assert!(
            citizen[PIN_FIXTURE_LEN..PIN_STORED_LENGTH]
                .iter()
                .all(|&byte| byte == PIN_PAD_BYTE)
        );

        let mut organizational = [PIN_PAD_BYTE; CREDENTIAL_BODY_MAX];
        let org_total = write_credential_blocks(
            PinReferenceScheme::Organizational,
            &[b"1234"],
            &mut organizational,
        );
        assert_eq!(org_total, PIN_FIXTURE_LEN);
        assert_eq!(&organizational[..PIN_FIXTURE_LEN], b"1234");
    }

    #[test]
    fn a_two_block_citizen_body_pads_each_block_to_the_stored_length() {
        let mut body = [PIN_PAD_BYTE; CREDENTIAL_BODY_MAX];
        let total = write_credential_blocks(
            PinReferenceScheme::Citizen,
            &[b"1234", b"567890"],
            &mut body,
        );
        assert_eq!(total, CREDENTIAL_BODY_SCRATCH);
        assert_eq!(&body[..PIN_FIXTURE_LEN], b"1234");
        assert_eq!(
            &body[PIN_STORED_LENGTH..PIN_STORED_LENGTH + b"567890".len()],
            b"567890"
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
}
