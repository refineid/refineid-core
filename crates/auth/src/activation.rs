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

//! Card activation and PIN change records (FINEID S4-1 section 4.6).
//!
//! Decides a card's activation scheme, evaluates whether each PIN awaits
//! activation, and performs the initial PIN configuration. Under section
//! 4.6.1 the PUK is the activation PIN that unblocks both PINs; it
//! applies to organization cards and to citizen cards whose
//! authentication certificate is valid from before 13 January 2026.
//! Under section 4.6.2 both PINs ship set to one 7-digit preset
//! activation PIN that each PIN is changed from; it applies to citizen
//! cards whose authentication certificate is valid from that date.

use core::fmt;

use refineid_apdu::{ApduClass, CardTransport, CommandApdu, CommandHeader, PinRetries, StatusWord};
use refineid_ber::{BerTlvAny, BerTlvIter};
use refineid_pkcs15::PasswordLengthRange;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::credentials::{CredentialInputError, CredentialRole, SecretDigits, UnvalidatedSecret};
use crate::manage::ManageOutcome;
use crate::verify::{
    AuthError, PIN1_REFERENCE, PIN2_REFERENCE, PUK_REFERENCE, PinReferenceScheme, PinSlot,
    PinStatus,
};

/// GET DATA instruction byte, odd variant carrying a command data field
/// (ISO 7816-4:2020 section 11.4.2; FINEID S1 v4.2 section 3.15.2 Table 16).
pub(crate) const GET_DATA_INS: u8 = 0xCB;
/// GET DATA P1 for PIN container query (FINEID S1 v4.2 section 3.15.2).
const GET_DATA_P1: u8 = 0x00;
/// GET DATA P2 for PIN container query (FINEID S1 v4.2 section 3.15.2).
const GET_DATA_P2: u8 = 0xFF;
/// Expected response length (Le) for GET DATA.
const GET_DATA_LE: u8 = 0x00;

/// Constructed template tag in PIN container request (FINEID S1 v4.2 section 3.15.2).
pub(crate) const PIN_CONTAINER_TEMPLATE_TAG: u8 = 0xA0;
/// Template length in PIN container request.
const PIN_CONTAINER_TEMPLATE_LEN: u8 = 3;
/// PIN reference tag inside request template.
pub(crate) const PIN_CONTAINER_REF_TAG: u8 = 0x83;
/// PIN reference value length.
pub(crate) const PIN_CONTAINER_REF_LEN: u8 = 1;

/// High byte of PIN changed tag (DF 2F, FINEID S1 v4.2 section 3.15.3).
const PIN_CHANGED_TAG_HIGH: u8 = 0xDF;
/// Low byte of PIN changed tag (DF 2F, FINEID S1 v4.2 section 3.15.3).
const PIN_CHANGED_TAG_LOW: u8 = 0x2F;
/// Value length for PIN changed tag.
const PIN_CHANGED_LEN: u8 = 1;
/// PIN changed window length in bytes: 2 tag bytes, 1 len byte, 1 flag byte.
const PIN_CHANGED_WINDOW_LEN: usize = 4;
/// Offset of flag byte in PIN changed window.
const PIN_CHANGED_FLAG_OFFSET: usize = 3;
/// Flag indicating PIN has not been changed since manufacture.
const PIN_CHANGED_FLAG_UNCHANGED: u8 = 0x00;
/// Flag indicating PIN has been changed since manufacture.
const PIN_CHANGED_FLAG_CHANGED: u8 = 0x01;

/// High byte of PIN attributes tag (DF 21, FINEID S1 v4.2 section 3.15.3).
const PIN_ATTRIBUTES_TAG_HIGH: u8 = 0xDF;
/// Low byte of PIN attributes tag (DF 21, FINEID S1 v4.2 section 3.15.3).
const PIN_ATTRIBUTES_TAG_LOW: u8 = 0x21;
/// Value length for PIN attributes tag.
const PIN_ATTRIBUTES_LEN: u8 = 4;
/// Window length for PIN attributes tag in bytes: 2 tag bytes, 1 len byte, 4 data bytes.
const PIN_ATTRIBUTES_WINDOW_LEN: usize = 7;
/// Offset of tries remaining byte in PIN attributes window.
const PIN_ATTRIBUTES_TRIES_OFFSET: usize = 3;

/// PIN policy tag (DF 3F, FINEID S1 v4.2 section 3.15.3 Table 19).
pub(crate) const PIN_POLICY_TAG: u16 = 0xDF3F;
/// Value length of the PIN policy.
pub(crate) const PIN_POLICY_LEN: usize = 20;
/// Offset of the PIN minimum length in the PIN policy value, after the
/// maximum try limit.
pub(crate) const PIN_POLICY_MIN_LENGTH_OFFSET: usize = 1;
/// Offset of the PIN maximum length in the PIN policy value.
pub(crate) const PIN_POLICY_MAX_LENGTH_OFFSET: usize = 2;
/// Lowest PIN length the PIN policy can state (FINEID S1 v4.2 section
/// 3.15.3).
const PIN_POLICY_LENGTH_FLOOR: u8 = 4;
/// Highest PIN length the PIN policy can state.
const PIN_POLICY_LENGTH_CEILING: u8 = 64;

/// Length byte offset in a two-byte tag TLV window.
const TLV_LENGTH_OFFSET: usize = 2;

/// DVV cutover epoch seconds: 13 January 2026 00:00:00 UTC (FINEID S4-1 section 4.6).
const DVV_PRESET_PIN_CUTOVER_EPOCH_SECONDS: i64 = 1_768_262_400;

/// Number of digits for the preset activation PIN under FINEID S4-1 section 4.6.2.
const PRESET_ACTIVATION_PIN_DIGIT_COUNT: usize = 7;
/// Number of digits for the activation PIN (PUK) under FINEID S4-1 section 4.6.1.
const ACTIVATION_CODE_PUK_DIGIT_COUNT: usize = 8;

/// How a card is activated (FINEID S4-1 v4.2 section 4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationScheme {
    /// Section 4.6.1: PINs ship blocked, the activation PIN is the
    /// 8-digit PUK, and RESET RETRY COUNTER sets each PIN. Citizen cards
    /// issued before 13 January 2026 and organization cards.
    ActivationCodeIsPuk,
    /// Section 4.6.2: PINs ship set to one 7-digit preset activation
    /// PIN, and CHANGE REFERENCE DATA sets each PIN. Citizen cards issued
    /// from 13 January 2026.
    PresetActivationPin,
}

impl ActivationScheme {
    /// Decide the activation scheme from the card's resolved credential
    /// numbering and its authentication certificate's validity start
    /// (notBefore, epoch seconds).
    ///
    /// The organization numbering (FINEID S4-2 v4.0 section 4.2) means
    /// section 4.6.1 whatever the date. Under the citizen numbering the
    /// validity start decides: from 13 January 2026 section 4.6.2,
    /// before it section 4.6.1. A citizen card whose validity start was
    /// not read gives `None`, and no activation decision follows.
    #[must_use]
    pub const fn from_numbering_and_validity_start(
        numbering: PinReferenceScheme,
        auth_certificate_validity_start: Option<i64>,
    ) -> Option<Self> {
        match numbering {
            PinReferenceScheme::Organizational => Some(Self::ActivationCodeIsPuk),
            PinReferenceScheme::Citizen => match auth_certificate_validity_start {
                Some(not_before) if not_before >= DVV_PRESET_PIN_CUTOVER_EPOCH_SECONDS => {
                    Some(Self::PresetActivationPin)
                }
                Some(_) => Some(Self::ActivationCodeIsPuk),
                None => None,
            },
        }
    }

    /// The exact digit count the card accepts for the activation entry.
    #[must_use]
    pub const fn activation_entry_digit_count(self) -> usize {
        match self {
            Self::ActivationCodeIsPuk => ACTIVATION_CODE_PUK_DIGIT_COUNT,
            Self::PresetActivationPin => PRESET_ACTIVATION_PIN_DIGIT_COUNT,
        }
    }
}

/// What the PIN container reports about whether a PIN was changed since manufacture
/// (FINEID S1 v4.2 section 3.15.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinChangeRecord {
    /// Changed at least once since manufacture.
    Changed,
    /// Never changed: the factory state under either scheme.
    Unchanged,
    /// Absent or carrying an unrecognised flag value.
    Unreadable,
}

/// Whether one PIN still awaits factory activation (FINEID S4-1 section 4.6).
///
/// The PIN changed flag is the authority under both schemes: activation
/// sets it for each PIN, so `Unchanged` is the factory state and
/// `Changed` means the holder has set the PIN at least once. Under
/// section 4.6.1 the factory PINs are blocked, and the card reports that
/// either as a blocked method or as an exhausted counter; a blocked PIN
/// whose flag says `Changed` was activated and then used up, and belongs
/// to PUK recovery instead.
///
/// When the flag cannot be read, section 4.6.1 falls back to the
/// counter: a blocked or exhausted PIN is served the activation, which
/// is the same RESET RETRY COUNTER under the PUK that recovery sends.
/// Section 4.6.2 then answers `false`, because presenting the
/// activation PIN to a PIN the holder already set spends a retry.
#[must_use]
pub const fn pin_awaits_activation(
    scheme: ActivationScheme,
    record: PinChangeRecord,
    status: PinStatus,
) -> bool {
    match record {
        PinChangeRecord::Unchanged => true,
        PinChangeRecord::Changed => false,
        PinChangeRecord::Unreadable => match scheme {
            ActivationScheme::PresetActivationPin => false,
            ActivationScheme::ActivationCodeIsPuk => match status {
                PinStatus::Locked => true,
                PinStatus::Remaining(retries) => retries.is_exhausted(),
                PinStatus::Verified | PinStatus::NoInfo | PinStatus::Other(_) => false,
            },
        },
    }
}

/// Which PINs still await factory activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardActivationNeeds {
    /// Whether PIN1 still awaits its initial holder value.
    pub pin1: bool,
    /// Whether PIN2 still awaits its initial holder value.
    pub pin2: bool,
}

impl CardActivationNeeds {
    /// Whether the card has any activation work remaining.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.pin1 || self.pin2
    }
}

/// A validated activation PIN of either scheme.
///
/// Ensures the entered digits strictly match the scheme-specific digit count
/// (7 digits for preset PIN, 8 digits for PUK), carries the scheme it was
/// validated for, and zeroizes on drop.
pub struct ActivationCode {
    digits: SecretDigits,
    scheme: ActivationScheme,
}

impl Drop for ActivationCode {
    fn drop(&mut self) {
        self.digits.zeroize();
    }
}

/// The digits are wiped by the `Drop` above; the scheme is not secret.
impl ZeroizeOnDrop for ActivationCode {}

impl ActivationCode {
    /// Reconstruct an activation PIN from unvalidated secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInputError`] if the length does not match the
    /// expected digit count for `scheme` or contains non-digits.
    pub fn reconstruct(
        input: UnvalidatedSecret,
        scheme: ActivationScheme,
    ) -> Result<Self, CredentialInputError> {
        let count = scheme.activation_entry_digit_count();
        SecretDigits::reconstruct(input, CredentialRole::ActivationCode, count, count)
            .map(|digits| Self { digits, scheme })
    }

    /// The scheme whose digit count this code was validated against.
    #[must_use]
    pub const fn scheme(&self) -> ActivationScheme {
        self.scheme
    }

    /// Borrow validated secret digits for credential commands.
    pub(crate) fn digits(&self) -> &[u8] {
        self.digits.secret_bytes()
    }
}

impl fmt::Debug for ActivationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActivationCode([redacted])")
    }
}

/// Outcome of one card activation execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationReport {
    /// The scheme under which activation was executed.
    pub scheme: ActivationScheme,
    /// Outcome of activating PIN1, or `None` if skipped.
    pub pin1: Option<ManageOutcome>,
    /// Outcome of activating PIN2, or `None` if skipped.
    pub pin2: Option<ManageOutcome>,
}

/// Overall credential status and health summary for UI display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialHealthReport {
    /// Counter-safe status for PIN1.
    pub pin1_status: PinStatus,
    /// Counter-safe status for PIN2.
    pub pin2_status: PinStatus,
    /// PUK status (attempts remaining, locked, or no information).
    pub puk_status: PinStatus,
    /// Resolved credential numbering scheme.
    pub pin_reference_scheme: PinReferenceScheme,
    /// Activation scheme decided from the numbering and the
    /// authentication certificate's validity start; `None` for a citizen
    /// card whose validity start was not read.
    pub activation_scheme: Option<ActivationScheme>,
    /// Activation needs under the decided scheme; `None` without one.
    pub activation_needs: Option<CardActivationNeeds>,
}

/// The GET DATA command that reads the PIN container of `reference`
/// (FINEID S1 v4.2 section 3.15.2), or `None` if it does not assemble.
fn pin_container_query(reference: u8) -> Option<CommandApdu> {
    let header = CommandHeader {
        class: ApduClass::Plain,
        instruction: GET_DATA_INS,
        p1: GET_DATA_P1,
        p2: GET_DATA_P2,
    };
    let data = [
        PIN_CONTAINER_TEMPLATE_TAG,
        PIN_CONTAINER_TEMPLATE_LEN,
        PIN_CONTAINER_REF_TAG,
        PIN_CONTAINER_REF_LEN,
        reference,
    ];
    CommandApdu::case_4(header, &data, GET_DATA_LE).ok()
}

/// Read the length range of the PIN policy in the PIN container of
/// `reference` (FINEID S1 v4.2 section 3.15.3, Table 19): the policy's
/// second octet is the minimum length and its third the maximum, each in
/// the range the specification gives. `None` when the card refuses the
/// read, the container carries no policy, or the policy's lengths fall
/// outside that range or admit nothing.
///
/// # Errors
///
/// Returns [`AuthError`] on transport failure or state transition.
pub(crate) fn read_pin_policy_lengths<T: CardTransport + ?Sized>(
    transport: &mut T,
    reference: u8,
) -> Result<Option<PasswordLengthRange>, AuthError<T::Error>> {
    let Some(apdu) = pin_container_query(reference) else {
        return Ok(None);
    };
    let outcome = transport.transmit(&apdu).map_err(AuthError::Transport)?;
    let response = outcome.into_response().map_err(AuthError::Outcome)?;
    if response.status_word() != StatusWord::Success {
        return Ok(None);
    }
    let Ok(template) = BerTlvAny::parse(&response.body) else {
        return Ok(None);
    };
    if template.tag() != u16::from(PIN_CONTAINER_TEMPLATE_TAG) {
        return Ok(None);
    }
    let policy = BerTlvIter::new(template.value())
        .map_while(Result::ok)
        .find(|element| element.tag() == PIN_POLICY_TAG);
    let Some(policy) = policy else {
        return Ok(None);
    };
    let value = policy.value();
    if value.len() != PIN_POLICY_LEN {
        return Ok(None);
    }
    let (Some(&min), Some(&max)) = (
        value.get(PIN_POLICY_MIN_LENGTH_OFFSET),
        value.get(PIN_POLICY_MAX_LENGTH_OFFSET),
    ) else {
        return Ok(None);
    };
    let in_specified_range =
        |length: u8| (PIN_POLICY_LENGTH_FLOOR..=PIN_POLICY_LENGTH_CEILING).contains(&length);
    if !in_specified_range(min) || !in_specified_range(max) {
        return Ok(None);
    }
    Ok(PasswordLengthRange::new(min, max))
}

/// Read a PIN's changed-since-manufacture record from the card's PIN container.
///
/// # Errors
///
/// Returns [`AuthError`] on transport failure or state transition.
pub fn read_pin_change_record<T: CardTransport + ?Sized>(
    transport: &mut T,
    slot: PinSlot,
) -> Result<PinChangeRecord, AuthError<T::Error>> {
    let reference = match slot {
        PinSlot::Pin1 => PIN1_REFERENCE,
        PinSlot::Pin2 => PIN2_REFERENCE,
    };
    let Some(apdu) = pin_container_query(reference) else {
        return Ok(PinChangeRecord::Unreadable);
    };
    let outcome = transport.transmit(&apdu).map_err(AuthError::Transport)?;
    let response = outcome.into_response().map_err(AuthError::Outcome)?;
    if response.status_word() != StatusWord::Success {
        return Ok(PinChangeRecord::Unreadable);
    }
    let body = &response.body;
    if body.len() < PIN_CHANGED_WINDOW_LEN {
        return Ok(PinChangeRecord::Unreadable);
    }
    for start in 0..=body.len() - PIN_CHANGED_WINDOW_LEN {
        if body[start] == PIN_CHANGED_TAG_HIGH
            && body[start + 1] == PIN_CHANGED_TAG_LOW
            && body[start + TLV_LENGTH_OFFSET] == PIN_CHANGED_LEN
        {
            return Ok(match body[start + PIN_CHANGED_FLAG_OFFSET] {
                PIN_CHANGED_FLAG_UNCHANGED => PinChangeRecord::Unchanged,
                PIN_CHANGED_FLAG_CHANGED => PinChangeRecord::Changed,
                _ => PinChangeRecord::Unreadable,
            });
        }
    }
    Ok(PinChangeRecord::Unreadable)
}

/// Read the PUK retry counter from the citizen card's PIN container.
///
/// # Errors
///
/// Returns [`AuthError`] on transport failure or state transition.
pub fn read_puk_status_from_container<T: CardTransport + ?Sized>(
    transport: &mut T,
) -> Result<PinStatus, AuthError<T::Error>> {
    let Some(apdu) = pin_container_query(PUK_REFERENCE) else {
        return Ok(PinStatus::NoInfo);
    };
    let outcome = transport.transmit(&apdu).map_err(AuthError::Transport)?;
    let response = outcome.into_response().map_err(AuthError::Outcome)?;
    match response.status_word() {
        StatusWord::Success => {
            let body = &response.body;
            if body.len() >= PIN_ATTRIBUTES_WINDOW_LEN {
                for start in 0..=body.len() - PIN_ATTRIBUTES_WINDOW_LEN {
                    if body[start] == PIN_ATTRIBUTES_TAG_HIGH
                        && body[start + 1] == PIN_ATTRIBUTES_TAG_LOW
                        && body[start + TLV_LENGTH_OFFSET] == PIN_ATTRIBUTES_LEN
                    {
                        let tries = body[start + PIN_ATTRIBUTES_TRIES_OFFSET];
                        if let Some(retries) = PinRetries::from_nibble(tries) {
                            return Ok(PinStatus::Remaining(retries));
                        }
                    }
                }
            }
            Ok(PinStatus::NoInfo)
        }
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            Ok(PinStatus::Locked)
        }
        other => Ok(PinStatus::Other(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActivationCode, ActivationScheme, CardActivationNeeds,
        DVV_PRESET_PIN_CUTOVER_EPOCH_SECONDS, PIN_ATTRIBUTES_LEN, PIN_ATTRIBUTES_TAG_HIGH,
        PIN_ATTRIBUTES_TAG_LOW, PIN_CHANGED_FLAG_CHANGED, PIN_CHANGED_FLAG_UNCHANGED,
        PIN_CHANGED_LEN, PIN_CHANGED_TAG_HIGH, PIN_CHANGED_TAG_LOW, PinChangeRecord,
        pin_awaits_activation, read_pin_change_record, read_puk_status_from_container,
    };
    use crate::credentials::UnvalidatedSecret;
    use crate::verify::{AuthError, PinReferenceScheme, PinSlot, PinStatus};
    use refineid_apdu::{
        CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu, StatusWord,
        TransportOutcome,
    };

    const CUTOVER_BEFORE: i64 = 1_700_000_000;
    const CUTOVER_AFTER: i64 = 1_800_000_000;
    const EXACT_7_DIGITS: &[u8] = b"1234567";
    const EXACT_8_DIGITS: &[u8] = b"12345678";
    const SIX_DIGITS: &[u8] = b"123456";

    fn input(bytes: &[u8]) -> UnvalidatedSecret {
        UnvalidatedSecret::from_owned_bytes(bytes.to_vec())
    }

    fn decide(
        numbering: PinReferenceScheme,
        validity_start: Option<i64>,
    ) -> Option<ActivationScheme> {
        ActivationScheme::from_numbering_and_validity_start(numbering, validity_start)
    }

    #[test]
    fn citizen_numbering_follows_the_validity_start() {
        let citizen = PinReferenceScheme::Citizen;
        assert_eq!(
            decide(citizen, Some(CUTOVER_BEFORE)),
            Some(ActivationScheme::ActivationCodeIsPuk)
        );
        assert_eq!(
            decide(citizen, Some(DVV_PRESET_PIN_CUTOVER_EPOCH_SECONDS)),
            Some(ActivationScheme::PresetActivationPin)
        );
        assert_eq!(
            decide(citizen, Some(CUTOVER_AFTER)),
            Some(ActivationScheme::PresetActivationPin)
        );
    }

    #[test]
    fn organization_numbering_is_the_puk_scheme_whatever_the_date() {
        for validity_start in [
            Some(CUTOVER_BEFORE),
            Some(DVV_PRESET_PIN_CUTOVER_EPOCH_SECONDS),
            Some(CUTOVER_AFTER),
            None,
        ] {
            assert_eq!(
                decide(PinReferenceScheme::Organizational, validity_start),
                Some(ActivationScheme::ActivationCodeIsPuk)
            );
        }
    }

    #[test]
    fn citizen_numbering_without_a_validity_start_gives_no_scheme() {
        assert_eq!(decide(PinReferenceScheme::Citizen, None), None);
    }

    #[test]
    fn activation_code_carries_the_scheme_it_was_validated_for() {
        for (digits, scheme) in [
            (EXACT_7_DIGITS, ActivationScheme::PresetActivationPin),
            (EXACT_8_DIGITS, ActivationScheme::ActivationCodeIsPuk),
        ] {
            let code = ActivationCode::reconstruct(input(digits), scheme).expect("exact length");
            assert_eq!(code.scheme(), scheme);
        }
    }

    #[test]
    fn activation_code_validation_enforces_scheme_lengths() {
        assert!(
            ActivationCode::reconstruct(
                input(EXACT_7_DIGITS),
                ActivationScheme::PresetActivationPin
            )
            .is_ok()
        );
        assert!(
            ActivationCode::reconstruct(
                input(EXACT_8_DIGITS),
                ActivationScheme::PresetActivationPin
            )
            .is_err()
        );
        assert!(
            ActivationCode::reconstruct(input(SIX_DIGITS), ActivationScheme::PresetActivationPin)
                .is_err()
        );

        assert!(
            ActivationCode::reconstruct(
                input(EXACT_8_DIGITS),
                ActivationScheme::ActivationCodeIsPuk
            )
            .is_ok()
        );
        assert!(
            ActivationCode::reconstruct(
                input(EXACT_7_DIGITS),
                ActivationScheme::ActivationCodeIsPuk
            )
            .is_err()
        );
    }

    /// Retry count of a credential nobody has tried yet.
    const RETRIES_PRISTINE: u8 = 5;
    /// Retry count of a credential with no tries left.
    const RETRIES_EXHAUSTED: u8 = 0;

    fn remaining(count: u8) -> PinStatus {
        PinStatus::Remaining(PinRetries::from_nibble(count).expect("fits a nibble"))
    }

    fn pristine() -> PinStatus {
        remaining(RETRIES_PRISTINE)
    }

    fn exhausted() -> PinStatus {
        remaining(RETRIES_EXHAUSTED)
    }

    /// A factory-fresh section 4.6.1 card can answer its blocked PINs
    /// with an exhausted counter rather than a blocked method; the
    /// unchanged flag is what marks it as awaiting activation.
    #[test]
    fn unchanged_flag_awaits_activation_whatever_the_counter() {
        for scheme in [
            ActivationScheme::ActivationCodeIsPuk,
            ActivationScheme::PresetActivationPin,
        ] {
            for status in [
                exhausted(),
                pristine(),
                PinStatus::Locked,
                PinStatus::NoInfo,
            ] {
                assert!(pin_awaits_activation(
                    scheme,
                    PinChangeRecord::Unchanged,
                    status
                ));
            }
        }
    }

    #[test]
    fn changed_flag_never_awaits_activation() {
        for scheme in [
            ActivationScheme::ActivationCodeIsPuk,
            ActivationScheme::PresetActivationPin,
        ] {
            for status in [
                exhausted(),
                pristine(),
                PinStatus::Locked,
                PinStatus::Verified,
            ] {
                assert!(!pin_awaits_activation(
                    scheme,
                    PinChangeRecord::Changed,
                    status
                ));
            }
        }
    }

    #[test]
    fn unreadable_flag_falls_back_to_a_blocked_counter_under_the_puk_scheme() {
        let scheme = ActivationScheme::ActivationCodeIsPuk;
        let unreadable = PinChangeRecord::Unreadable;
        assert!(pin_awaits_activation(scheme, unreadable, PinStatus::Locked));
        assert!(pin_awaits_activation(scheme, unreadable, exhausted()));
        assert!(!pin_awaits_activation(scheme, unreadable, pristine()));
        assert!(!pin_awaits_activation(
            scheme,
            unreadable,
            PinStatus::Verified
        ));
        assert!(!pin_awaits_activation(
            scheme,
            unreadable,
            PinStatus::NoInfo
        ));
    }

    #[test]
    fn unreadable_flag_never_awaits_activation_under_the_preset_scheme() {
        let scheme = ActivationScheme::PresetActivationPin;
        for status in [
            exhausted(),
            pristine(),
            PinStatus::Locked,
            PinStatus::NoInfo,
        ] {
            assert!(!pin_awaits_activation(
                scheme,
                PinChangeRecord::Unreadable,
                status
            ));
        }
    }

    #[test]
    fn activation_needs_reports_correctly() {
        let needs = CardActivationNeeds {
            pin1: true,
            pin2: false,
        };
        assert!(needs.any());
        let none = CardActivationNeeds {
            pin1: false,
            pin2: false,
        };
        assert!(!none.any());
    }

    struct MockTransport {
        response: Result<ResponseApdu, String>,
    }

    impl MockTransport {
        fn success(body: Vec<u8>) -> Self {
            let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
            Self {
                response: Ok(ResponseApdu { body, sw1, sw2 }),
            }
        }

        fn sw(sw: StatusWord) -> Self {
            let [sw1, sw2] = sw.as_u16().to_be_bytes();
            Self {
                response: Ok(ResponseApdu {
                    body: vec![],
                    sw1,
                    sw2,
                }),
            }
        }

        fn error(err: &str) -> Self {
            Self {
                response: Err(err.to_owned()),
            }
        }
    }

    impl CardTransport for MockTransport {
        type Error = String;

        fn transmit(&mut self, _command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            match &self.response {
                Ok(resp) => Ok(TransportOutcome::Response(resp.clone())),
                Err(e) => Err(e.clone()),
            }
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("credential transmit unused in activation tests".to_owned())
        }
    }

    #[test]
    fn read_pin_change_record_reports_unchanged_and_changed() {
        let unchanged_body = vec![
            PIN_CHANGED_TAG_HIGH,
            PIN_CHANGED_TAG_LOW,
            PIN_CHANGED_LEN,
            PIN_CHANGED_FLAG_UNCHANGED,
        ];
        let mut t1 = MockTransport::success(unchanged_body);
        let record = read_pin_change_record(&mut t1, PinSlot::Pin1).expect("clean read");
        assert_eq!(record, PinChangeRecord::Unchanged);

        let changed_body = vec![
            PIN_CHANGED_TAG_HIGH,
            PIN_CHANGED_TAG_LOW,
            PIN_CHANGED_LEN,
            PIN_CHANGED_FLAG_CHANGED,
        ];
        let mut t2 = MockTransport::success(changed_body);
        let record = read_pin_change_record(&mut t2, PinSlot::Pin1).expect("clean read");
        assert_eq!(record, PinChangeRecord::Changed);
    }

    #[test]
    fn read_pin_change_record_handles_non_9000_as_unreadable() {
        let mut t = MockTransport::sw(StatusWord::ReferenceDataNotFound);
        let record = read_pin_change_record(&mut t, PinSlot::Pin1).expect("clean read");
        assert_eq!(record, PinChangeRecord::Unreadable);
    }

    #[test]
    fn read_pin_change_record_propagates_transport_error() {
        let mut t = MockTransport::error("card removed");
        let error = read_pin_change_record(&mut t, PinSlot::Pin1);
        assert!(matches!(error, Err(AuthError::Transport(_))));
    }

    #[test]
    fn read_puk_status_propagates_transport_error() {
        let mut t = MockTransport::error("card removed");
        let error = read_puk_status_from_container(&mut t);
        assert!(matches!(error, Err(AuthError::Transport(_))));
    }

    #[test]
    fn read_puk_status_handles_authentication_blocked_as_locked() {
        let mut t1 = MockTransport::sw(StatusWord::AuthenticationBlocked);
        let status = read_puk_status_from_container(&mut t1).expect("clean response");
        assert_eq!(status, PinStatus::Locked);

        let mut t2 = MockTransport::sw(StatusWord::ReferenceDataInvalidated);
        let status = read_puk_status_from_container(&mut t2).expect("clean response");
        assert_eq!(status, PinStatus::Locked);
    }

    #[test]
    fn read_puk_status_handles_other_status_word() {
        let mut t = MockTransport::sw(StatusWord::ReferenceDataNotFound);
        let status = read_puk_status_from_container(&mut t).expect("clean response");
        assert_eq!(status, PinStatus::Other(StatusWord::ReferenceDataNotFound));
    }

    #[test]
    fn read_puk_status_handles_missing_or_corrupt_tlv_as_no_info() {
        let mut t_empty = MockTransport::success(vec![]);
        let status = read_puk_status_from_container(&mut t_empty).expect("clean response");
        assert_eq!(status, PinStatus::NoInfo);

        // Valid tag and length, but invalid retry count nibble exceeding 4 bits.
        const OVERFLOW_NIBBLE: u8 = refineid_apdu::PinRetries::MAX + 1;
        const TLV_FILL_BYTE: u8 = 0;
        let corrupt_nibble = vec![
            PIN_ATTRIBUTES_TAG_HIGH,
            PIN_ATTRIBUTES_TAG_LOW,
            PIN_ATTRIBUTES_LEN,
            OVERFLOW_NIBBLE,
            TLV_FILL_BYTE,
            TLV_FILL_BYTE,
            TLV_FILL_BYTE,
        ];
        let mut t_corrupt = MockTransport::success(corrupt_nibble);
        let status = read_puk_status_from_container(&mut t_corrupt).expect("clean response");
        assert_eq!(status, PinStatus::NoInfo);
    }
}
