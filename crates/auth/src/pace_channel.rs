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

//! PIN management on a secure channel PACE opened with the PUK or PIN 1,
//! and the PIN 2 presentation on a channel PACE opened with PIN 2.
//!
//! The organizational card answers every command on its contactless
//! interface only after PACE, and enables PACE with PIN 1, PIN 2 or the
//! PUK (FINEID S4-2 v4.0 sections 4.2 and 6). A channel PACE opened with
//! the PUK is where a blocked PIN is set -- the activation of a card
//! that ships with blocked PINs (FINEID S4-1 v4.2 section 4.6.1) and the
//! unblock -- and a channel PACE opened with PIN 1 is where PIN 1 is
//! changed. BSI TR-03110-3 section B.7.1 has the terminal unblock or
//! change the PIN on such a channel with RESET RETRY COUNTER carrying only
//! the new PIN: PACE with the PUK or the PIN is the authorisation, and the
//! credential is not sent again. FINEID S4-2 v4.0 section 4.3 states the
//! reset's contactless access condition as the PUK's security
//! environment together with PACE, and the change's as PACE alone, with
//! the current PIN in the command (IAS ECC v1.0.1 section 9.4.2). Whether
//! the organizational card counts a completed PACE with the PUK, or with
//! PIN 1, as the authorisation its reset needs is not stated there, so
//! each operation takes the choice as a [`ChannelProof`]: rely on the
//! handshake, or present the credential once more inside the channel.
//! Real hardware decides which one the card accepts.
//!
//! The channel types live in `refineid-pace`, which implements
//! [`PukPaceChannel`], [`Pin1PaceChannel`] and [`Pin2PaceChannel`] only
//! for the channels the matching password opened; the operations here
//! exist only on those channels. A channel PACE opened with PIN 2 signs
//! once on the handshake's presentation, and every further signature on
//! it presents PIN 2 again with
//! [`Pin2PaceChannelOps::verify_pin2_after_pin2_pace`]. Presenting the
//! credential again is floored by the one rule
//! every presentation follows (`check_retry_floor`), on the channel's
//! own record of the counter: the `MSE:Set AT` answer that opened the
//! channel, lowered by every later answer that reported fewer tries. The
//! record stands in for the counter-safe probe the plain primitives
//! send, because the organizational card does not answer the empty
//! VERIFY over secure messaging with a counter; the operations here send
//! the crate-private commands directly, so the record is read once and
//! no second probe is made.

use refineid_apdu::CardTransport;

use crate::credentials::{Pin1, Pin2, Puk};
use crate::manage::{ManageOutcome, change, reset_new_only, verify_puk};
use crate::pin_lengths::CardPinLengths;
use crate::retry_risk::{FlooredCredential, check_retry_floor};
use crate::verify::{
    AuthError, PinReferenceScheme, PinSlot, PinStatus, VerifyOutcome, verify_digits,
};

/// The numbering every operation here addresses the card under. PACE
/// with a PIN or the PUK exists only on the organizational card (FINEID
/// S4-2 v4.0 section 6), so the channel's type fixes it; the
/// [`CardPinLengths`] an operation takes supply only the lengths.
const CHANNEL_NUMBERING: PinReferenceScheme = PinReferenceScheme::Organizational;

/// How an operation on a PACE channel proves the credential the card
/// needs verified.
///
/// The caller names the choice at every call; there is no implicit one.
/// [`ChannelProof::PaceHandshake`]: the handshake that opened the channel
/// is the proof and nothing carries the credential again.
/// [`ChannelProof::PresentAgain`] carries it once more inside secure
/// messaging, under the retry floor. Which one the organizational card
/// accepts is a hardware finding: the resets after PACE with the PUK take
/// the handshake, the PIN 1 change takes `PresentAgain`
/// (doc/reference/pace.md).
#[derive(Debug)]
pub enum ChannelProof<C> {
    /// The completed PACE handshake is the proof; the credential is not
    /// sent (BSI TR-03110-3 section B.7.1).
    PaceHandshake,
    /// The credential is presented once more inside the channel.
    PresentAgain(C),
}

/// A secure channel PACE opened with the PUK.
///
/// Implemented by `refineid-pace` for the channel only a handshake with a
/// [`Puk`] produces. The channel keeps the PUK's counter as the card last
/// reported it on the channel; [`PukPaceChannel::lower_puk_counter`]
/// only ever lowers it, so the one source of a counter the floor serves
/// is the handshake's `MSE:Set AT` answer.
pub trait PukPaceChannel: CardTransport {
    /// The PUK's counter as the card last reported it on this channel.
    fn puk_counter(&self) -> PinStatus;

    /// Lower the record by the card's answer to a PUK presentation on
    /// this channel; see [`lowered_counter`].
    fn lower_puk_counter(&mut self, answer: ManageOutcome);
}

/// A secure channel PACE opened with PIN 1.
///
/// Implemented by `refineid-pace` for the channel only a handshake with a
/// [`Pin1`] produces, with the same one-way counter record as
/// [`PukPaceChannel`].
pub trait Pin1PaceChannel: CardTransport {
    /// PIN 1's counter as the card last reported it on this channel.
    fn pin1_counter(&self) -> PinStatus;

    /// Lower the record by the card's answer to a PIN 1 presentation on
    /// this channel; see [`lowered_counter`].
    fn lower_pin1_counter(&mut self, answer: ManageOutcome);
}

/// A secure channel PACE opened with PIN 2.
///
/// Implemented by `refineid-pace` for the channel only a handshake with a
/// [`Pin2`] produces. The channel keeps PIN 2's counter as the card last
/// reported it: the `MSE:Set AT` answer the retry floor served, then
/// every VERIFY's answer on the channel ([`counter_after_verify`]). An
/// accepted VERIFY leaves PIN 2 verified with its counter at the limit,
/// so it is the one answer that raises the record.
pub trait Pin2PaceChannel: CardTransport {
    /// PIN 2's counter as the card last reported it on this channel.
    fn pin2_counter(&self) -> PinStatus;

    /// Settle the record by the card's answer to a PIN 2 VERIFY on this
    /// channel; see [`counter_after_verify`].
    fn settle_pin2_counter(&mut self, answer: VerifyOutcome);
}

/// The PIN 2 presentation on a channel PACE opened with PIN 2.
///
/// Exists only on a [`Pin2PaceChannel`]. The organizational card does
/// not answer the counter-safe empty VERIFY over secure messaging with a
/// counter, so the floor is applied to the channel's own record instead
/// of a probe, and no probe is sent.
pub trait Pin2PaceChannelOps: Pin2PaceChannel + Sized {
    /// VERIFY PIN 2 inside the channel under the retry floor on the
    /// channel's record: refused at two or one tries left or an unknown
    /// record, sent otherwise. The card's answer settles the record.
    ///
    /// # Errors
    ///
    /// [`AuthError::RetryFloor`] when the record reads two or one tries
    /// left or is unknown; nothing is sent. [`AuthError`] on a transport
    /// failure or state transition. A wrong PIN is
    /// [`VerifyOutcome::WrongPin`], a blocked PIN
    /// [`VerifyOutcome::Locked`], the card's own answers.
    fn verify_pin2_after_pin2_pace(
        &mut self,
        pin: Pin2,
    ) -> Result<VerifyOutcome, AuthError<Self::Error>> {
        check_retry_floor(FlooredCredential::Pin2, self.pin2_counter())
            .map_err(AuthError::RetryFloor)?;
        let outcome = verify_digits(self, CHANNEL_NUMBERING, PinSlot::Pin2, pin.digits())?;
        self.settle_pin2_counter(outcome);
        Ok(outcome)
    }
}

impl<T: Pin2PaceChannel> Pin2PaceChannelOps for T {}

/// The counter `record` after the card answered a VERIFY with `answer`.
///
/// An accepted VERIFY sets the counter to its limit and the verified
/// flag (FINEID S1 v4.2 section 3.5), so the record reads verified
/// whatever it held. Every other answer lowers the record as
/// [`lowered_counter`] does: a wrong PIN to the tries the card reports,
/// or blocked at none; a blocked answer to blocked; an unknown answer to
/// unknown, which the floor refuses.
#[must_use]
pub const fn counter_after_verify(record: PinStatus, answer: VerifyOutcome) -> PinStatus {
    match answer {
        VerifyOutcome::Ok => PinStatus::Verified,
        VerifyOutcome::WrongPin { retries_left } => {
            lowered_counter(record, ManageOutcome::WrongCredential { retries_left })
        }
        VerifyOutcome::Locked => lowered_counter(record, ManageOutcome::Locked),
        VerifyOutcome::Other(sw) => lowered_counter(record, ManageOutcome::Other(sw)),
    }
}

/// The counter `record` after the card answered a presentation with
/// `answer`, never higher than `record`.
///
/// An accepted presentation leaves the record as it stands: success
/// cannot lower the counter, and the record keeps the count the floor
/// last decided on. A wrong credential sets it to the tries the card
/// reports, or to blocked at none, unless the record is already lower.
/// A blocked answer sets it to blocked; any other answer leaves the
/// count unknown, which the floor refuses. Once blocked or unknown, the
/// record stays so for the channel's life.
#[must_use]
pub const fn lowered_counter(record: PinStatus, answer: ManageOutcome) -> PinStatus {
    match (record, answer) {
        (_, ManageOutcome::Ok)
        | (PinStatus::Locked | PinStatus::NoInfo | PinStatus::Other(_), _) => record,
        (_, ManageOutcome::Locked) => PinStatus::Locked,
        (_, ManageOutcome::Other(_)) => PinStatus::NoInfo,
        (PinStatus::Remaining(held), ManageOutcome::WrongCredential { retries_left })
            if held.get() < retries_left.get() =>
        {
            record
        }
        (_, ManageOutcome::WrongCredential { retries_left }) if retries_left.is_exhausted() => {
            PinStatus::Locked
        }
        (_, ManageOutcome::WrongCredential { retries_left }) => PinStatus::Remaining(retries_left),
    }
}

/// Activation and unblock on a channel PACE opened with the PUK.
///
/// Exists only on a [`PukPaceChannel`]: a channel the Card Access Number,
/// PIN 1 or PIN 2 opened does not have these methods. Each takes the
/// [`CardPinLengths`] the session read and refuses an entry the card
/// does not accept before any command. Activation under FINEID S4-1 v4.2
/// section 4.6.1 is these resets, one per PIN that awaits it.
pub trait PukPaceChannelOps: PukPaceChannel + Sized {
    /// Reset PIN 1's retry counter and set `new`.
    ///
    /// Under [`ChannelProof::PaceHandshake`] one RESET RETRY COUNTER
    /// carries only the new PIN; nothing presents the PUK and no try can
    /// be spent. Under [`ChannelProof::PresentAgain`] the retry floor is
    /// applied to the channel's PUK record, the PUK is verified as its
    /// own object, the record is lowered by the answer, and only an
    /// accepted PUK lets the reset go out.
    ///
    /// # Errors
    ///
    /// [`AuthError::PinLength`] when the card does not accept the length
    /// of an entry, and [`AuthError::RetryFloor`] when the PUK record
    /// reads two or one tries left or is unknown; nothing is sent either
    /// way. At no tries left or blocked the card answers for itself.
    /// [`AuthError`] on a transport failure or state transition. A
    /// refused PUK is [`ManageOutcome::WrongCredential`]; a reset the card
    /// does not authorise on this channel is [`ManageOutcome::Other`].
    fn reset_pin1_after_puk_pace(
        &mut self,
        lengths: &CardPinLengths,
        new: Pin1,
        proof: ChannelProof<Puk>,
    ) -> Result<ManageOutcome, AuthError<Self::Error>> {
        lengths.check_pin1(&new).map_err(AuthError::PinLength)?;
        reset_after_puk_pace(self, lengths, PinSlot::Pin1, new.digits(), proof)
    }

    /// Reset PIN 2's retry counter and set `new`.
    ///
    /// # Errors
    ///
    /// As [`PukPaceChannelOps::reset_pin1_after_puk_pace`].
    fn reset_pin2_after_puk_pace(
        &mut self,
        lengths: &CardPinLengths,
        new: Pin2,
        proof: ChannelProof<Puk>,
    ) -> Result<ManageOutcome, AuthError<Self::Error>> {
        lengths.check_pin2(&new).map_err(AuthError::PinLength)?;
        reset_after_puk_pace(self, lengths, PinSlot::Pin2, new.digits(), proof)
    }
}

impl<T: PukPaceChannel> PukPaceChannelOps for T {}

/// PIN 1 change on a channel PACE opened with PIN 1.
///
/// Exists only on a [`Pin1PaceChannel`].
pub trait Pin1PaceChannelOps: Pin1PaceChannel + Sized {
    /// Set `new` as PIN 1.
    ///
    /// Under [`ChannelProof::PaceHandshake`] one RESET RETRY COUNTER
    /// carries only the new PIN, the change BSI TR-03110-3 section B.7.1
    /// defines after PACE with the PIN; nothing presents PIN 1. Under
    /// [`ChannelProof::PresentAgain`] the retry floor is applied to the
    /// channel's PIN 1 record, one CHANGE REFERENCE DATA carries the
    /// current PIN and the new one, and the record is lowered by the
    /// answer.
    ///
    /// # Errors
    ///
    /// [`AuthError::PinLength`] when the card does not accept the length
    /// of an entry, and [`AuthError::RetryFloor`] when the PIN 1 record
    /// reads two or one tries left or is unknown; nothing is sent either
    /// way. At no tries left or blocked the card answers for itself.
    /// [`AuthError`] on a transport failure or state transition. A wrong
    /// current PIN is [`ManageOutcome::WrongCredential`]; a reset the card
    /// does not authorise on this channel is [`ManageOutcome::Other`].
    fn change_pin1_after_pin1_pace(
        &mut self,
        lengths: &CardPinLengths,
        new: Pin1,
        proof: ChannelProof<Pin1>,
    ) -> Result<ManageOutcome, AuthError<Self::Error>> {
        lengths.check_pin1(&new).map_err(AuthError::PinLength)?;
        let scheme = CHANNEL_NUMBERING;
        match proof {
            ChannelProof::PaceHandshake => {
                reset_new_only(self, scheme, PinSlot::Pin1, new.digits())
            }
            ChannelProof::PresentAgain(current) => {
                lengths.check_pin1(&current).map_err(AuthError::PinLength)?;
                check_retry_floor(FlooredCredential::Pin1, self.pin1_counter())
                    .map_err(AuthError::RetryFloor)?;
                let outcome = change(self, scheme, PinSlot::Pin1, current.digits(), new.digits())?;
                self.lower_pin1_counter(outcome);
                Ok(outcome)
            }
        }
    }
}

impl<T: Pin1PaceChannel> Pin1PaceChannelOps for T {}

/// The reset of `slot` on a PUK channel, after the new PIN's length was
/// checked.
fn reset_after_puk_pace<T: PukPaceChannel>(
    channel: &mut T,
    lengths: &CardPinLengths,
    slot: PinSlot,
    new: &[u8],
    proof: ChannelProof<Puk>,
) -> Result<ManageOutcome, AuthError<T::Error>> {
    let scheme = CHANNEL_NUMBERING;
    if let ChannelProof::PresentAgain(puk) = proof {
        lengths.check_puk(&puk).map_err(AuthError::PinLength)?;
        check_retry_floor(FlooredCredential::Puk, channel.puk_counter())
            .map_err(AuthError::RetryFloor)?;
        let verified = verify_puk(channel, scheme, puk.digits())?;
        channel.lower_puk_counter(verified);
        if !matches!(verified, ManageOutcome::Ok) {
            return Ok(verified);
        }
    }
    reset_new_only(channel, scheme, slot, new)
}

#[cfg(test)]
mod tests {
    use refineid_apdu::{PinRetries, StatusWord};

    use refineid_apdu::{CardTransport, CommandApdu, CredentialCommand, TransportOutcome};
    use refineid_pkcs15::PasswordLengthRange;

    use super::{
        CHANNEL_NUMBERING, ChannelProof, PukPaceChannel, PukPaceChannelOps as _,
        counter_after_verify, lowered_counter,
    };
    use crate::credentials::{Pin1, Puk, UnvalidatedSecret};
    use crate::manage::ManageOutcome;
    use crate::pin_lengths::CardPinLengths;
    use crate::verify::AuthError;
    use crate::verify::PinStatus;
    use crate::verify::VerifyOutcome;

    /// Tries of a pristine credential.
    const PRISTINE: u8 = 5;
    /// The lowest count the floor serves.
    const AT_FLOOR: u8 = 3;
    /// Just below the floor.
    const BELOW_FLOOR: u8 = 2;
    /// A status word outside the modeled set.
    const UNMODELED_SW: u16 = 0x6F00;
    /// The PUK length a synthetic card lists, eight digits.
    const LISTED_PUK_LENGTH: u8 = 8;
    /// A PUK longer than the listed length, within the role type.
    const LONG_PUK: &[u8] = b"3141592653";
    /// A new PIN 1.
    const NEW_PIN1: &[u8] = b"161803";

    /// A PUK channel that records whether anything was sent.
    struct SilentChannel {
        sent: usize,
    }

    impl CardTransport for SilentChannel {
        type Error = String;

        fn transmit(&mut self, _command: &CommandApdu) -> Result<TransportOutcome, String> {
            self.sent += 1;
            Err("nothing may be sent".to_owned())
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, String> {
            self.sent += 1;
            Err("nothing may be sent".to_owned())
        }
    }

    impl PukPaceChannel for SilentChannel {
        fn puk_counter(&self) -> PinStatus {
            remaining(PRISTINE)
        }

        fn lower_puk_counter(&mut self, _answer: ManageOutcome) {}
    }

    #[test]
    fn a_puk_the_card_does_not_accept_is_refused_before_any_command() {
        let puk_listing =
            PasswordLengthRange::new(LISTED_PUK_LENGTH, LISTED_PUK_LENGTH).expect("a range");
        let lengths = CardPinLengths::from_card(CHANNEL_NUMBERING, None, |reference| {
            (reference == CHANNEL_NUMBERING.puk_reference()).then_some(puk_listing)
        });
        let puk = Puk::reconstruct(UnvalidatedSecret::from_owned_bytes(LONG_PUK.to_vec()))
            .expect("valid PUK");
        let new = Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(NEW_PIN1.to_vec()))
            .expect("valid PIN 1");
        let mut channel = SilentChannel { sent: 0 };
        let refused =
            channel.reset_pin1_after_puk_pace(&lengths, new, ChannelProof::PresentAgain(puk));
        assert!(matches!(refused, Err(AuthError::PinLength(_))));
        assert_eq!(channel.sent, 0);
    }

    fn tries(count: u8) -> PinRetries {
        PinRetries::from_nibble(count).expect("a nibble")
    }

    fn remaining(count: u8) -> PinStatus {
        PinStatus::Remaining(tries(count))
    }

    fn wrong(count: u8) -> ManageOutcome {
        ManageOutcome::WrongCredential {
            retries_left: tries(count),
        }
    }

    #[test]
    fn an_accepted_presentation_leaves_the_record() {
        for record in [remaining(AT_FLOOR), PinStatus::Locked, PinStatus::NoInfo] {
            assert_eq!(lowered_counter(record, ManageOutcome::Ok), record);
        }
    }

    #[test]
    fn a_refusal_lowers_the_record_to_the_reported_tries() {
        assert_eq!(
            lowered_counter(remaining(PRISTINE), wrong(BELOW_FLOOR)),
            remaining(BELOW_FLOOR)
        );
        assert_eq!(
            lowered_counter(remaining(AT_FLOOR), wrong(0)),
            PinStatus::Locked
        );
    }

    #[test]
    fn a_report_of_more_tries_never_raises_the_record() {
        assert_eq!(
            lowered_counter(remaining(BELOW_FLOOR), wrong(PRISTINE)),
            remaining(BELOW_FLOOR)
        );
    }

    #[test]
    fn an_accepted_verify_leaves_the_record_verified_whatever_it_held() {
        for record in [
            remaining(PRISTINE),
            remaining(BELOW_FLOOR),
            PinStatus::Locked,
            PinStatus::NoInfo,
        ] {
            assert_eq!(
                counter_after_verify(record, VerifyOutcome::Ok),
                PinStatus::Verified
            );
        }
    }

    #[test]
    fn a_refused_verify_lowers_the_record_like_any_presentation() {
        let wrong_verify = |count| VerifyOutcome::WrongPin {
            retries_left: tries(count),
        };
        assert_eq!(
            counter_after_verify(remaining(PRISTINE), wrong_verify(BELOW_FLOOR)),
            remaining(BELOW_FLOOR)
        );
        assert_eq!(
            counter_after_verify(PinStatus::Verified, wrong_verify(AT_FLOOR)),
            remaining(AT_FLOOR)
        );
        assert_eq!(
            counter_after_verify(remaining(AT_FLOOR), wrong_verify(0)),
            PinStatus::Locked
        );
        assert_eq!(
            counter_after_verify(remaining(PRISTINE), VerifyOutcome::Locked),
            PinStatus::Locked
        );
        assert_eq!(
            counter_after_verify(
                remaining(PRISTINE),
                VerifyOutcome::Other(StatusWord::from_u16(UNMODELED_SW))
            ),
            PinStatus::NoInfo
        );
        assert_eq!(
            counter_after_verify(PinStatus::Locked, wrong_verify(PRISTINE)),
            PinStatus::Locked
        );
    }

    #[test]
    fn blocked_and_unknown_answers_end_the_record() {
        assert_eq!(
            lowered_counter(remaining(PRISTINE), ManageOutcome::Locked),
            PinStatus::Locked
        );
        let other = ManageOutcome::Other(StatusWord::from_u16(UNMODELED_SW));
        assert_eq!(
            lowered_counter(remaining(PRISTINE), other),
            PinStatus::NoInfo
        );
        for record in [PinStatus::Locked, PinStatus::NoInfo] {
            assert_eq!(lowered_counter(record, wrong(PRISTINE)), record);
        }
    }
}
