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

//! CHANGE REFERENCE DATA and RESET RETRY COUNTER.
//!
//! These operations mutate the card. CHANGE REFERENCE DATA replaces a
//! PIN's value once the current value is presented; RESET RETRY COUNTER
//! (the unblock) clears a blocked PIN's retry counter and sets a new
//! value, presenting the PUK. Each consumes its validated credentials
//! through the crate-private path and ships them only as credential
//! commands, consumed exactly once.
//!
//! A card-management session first reads the card's PIN lengths with
//! [`PinManageOps::read_card_pin_lengths`], which resolves the card's
//! reference numbering with the counter-safe probe on [`PinOps`] and reads
//! the lengths the card lists. Every flow takes that
//! [`CardPinLengths`], addresses the card under its numbering, and refuses
//! an entry whose length the card does not accept before any command, so
//! neither a resolution probe nor a length the card would refuse can cost
//! a typed entry. The citizen card
//! unblocks in one RESET RETRY COUNTER carrying the PUK and the new PIN;
//! the organizational card takes two commands, verifying the PUK as its
//! own object before a reset that carries only the new PIN (FINEID S4-2
//! v4.0 section 4.3.2). A wrong PUK spends the PUK's own counter, and
//! exhausting it is terminal for the card, so every flow that presents
//! the PUK reads the PUK's counter without spending a try and applies
//! the retry floor to it before the first command that carries the PUK.
//! The target PIN's counter does not gate the unblock.

use refineid_apdu::{ApduClass, CardTransport, CommandHeader, PinRetries, StatusWord};

use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops};

use crate::credentials::{Pin1, Pin2, Puk};
use crate::pin_lengths::CardPinLengths;
use crate::retry_risk::{FlooredCredential, PinRetryRisk, RetryFloorRefusal, check_retry_floor};
use crate::verify::{
    AuthError, PinOps, PinReferenceScheme, PinSlot, PinStatus, VERIFY_INS, VERIFY_P1,
    credential_exchange,
};

/// CHANGE REFERENCE DATA instruction (ISO 7816-8; FINEID S1 v4.2
/// section 3.11).
pub const CHANGE_REFERENCE_DATA_INS: u8 = 0x24;
/// CHANGE REFERENCE DATA P1: the data field carries the current
/// reference data followed by the new. The organizational card accepts
/// no other P1 and splits the field at its stored length (IAS ECC v1.0.1
/// section 9.4.2).
pub const CHANGE_P1_CURRENT_THEN_NEW: u8 = 0x00;

/// RESET RETRY COUNTER instruction (ISO 7816-8; FINEID S1 v4.2
/// section 3.12).
pub const RESET_RETRY_COUNTER_INS: u8 = 0x2C;
/// RESET RETRY COUNTER P1: the data field carries the unblocking code
/// followed by the new reference data. This is the citizen card's
/// single-command form.
pub const RESET_P1_CODE_THEN_NEW: u8 = 0x00;
/// RESET RETRY COUNTER P1: the data field carries only the new reference
/// data. The organizational card's reset after the PUK is verified as its
/// own object (FINEID S4-2 v4.0 section 4.3.2), and the reset BSI
/// TR-03110-3 section B.7.1 sends on a channel PACE opened with the PUK
/// or the PIN (section B.14.11).
pub const RESET_P1_NEW_ONLY: u8 = 0x02;

/// Outcome of a credential-update round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManageOutcome {
    /// The credential was updated: the new value is set and the retry
    /// counter is at its maximum, but the credential is not presented.
    Ok,
    /// The presented credential was wrong -- the current PIN for a change,
    /// or the PUK for an unblock. `retries_left` attempts remain on that
    /// credential's own counter before it locks. Zero means the next
    /// failure locks it, which for a PUK is terminal for the card.
    WrongCredential {
        /// Attempts remaining on the presented credential's counter.
        retries_left: PinRetries,
    },
    /// The method is blocked or its reference data is invalidated; the
    /// update cannot proceed.
    Locked,
    /// Any other status word, surfaced as-is for the caller to map.
    Other(StatusWord),
}

/// Decode a credential-update response status word into an outcome.
#[must_use]
pub const fn classify_manage_sw(sw: StatusWord) -> ManageOutcome {
    match sw {
        StatusWord::Success => ManageOutcome::Ok,
        StatusWord::PinIncorrect { retries } => ManageOutcome::WrongCredential {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            ManageOutcome::Locked
        }
        other => ManageOutcome::Other(other),
    }
}

/// Send one CHANGE REFERENCE DATA for `slot`: the current credential
/// block, then the new.
///
/// Both numberings take the single-command form under P1
/// [`CHANGE_P1_CURRENT_THEN_NEW`]; no separate VERIFY precedes it. How
/// each card delimits the two blocks is recorded on
/// [`crate::verify::write_credential_blocks`].
pub(crate) fn change<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
    slot: PinSlot,
    current: &[u8],
    new: &[u8],
) -> Result<ManageOutcome, AuthError<T::Error>> {
    let header = CommandHeader {
        class: ApduClass::Plain,
        instruction: CHANGE_REFERENCE_DATA_INS,
        p1: CHANGE_P1_CURRENT_THEN_NEW,
        p2: scheme.reference(slot),
    };
    let status = credential_exchange(transport, scheme, header, &[current, new])?;
    Ok(classify_manage_sw(status))
}

/// Read the PUK's retry status under `scheme` without spending a try.
///
/// Both numberings answer a Case 1 VERIFY (header only, no Lc, no data)
/// under the PUK reference with the comparison status (ISO 7816-4
/// section 7.5.6). When the citizen card answers that probe with neither
/// a counter nor a blocked state, the PIN container is read with GET DATA
/// instead (FINEID S1 v4.2 section 3.15.2).
fn puk_status<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
) -> Result<PinStatus, AuthError<T::Error>> {
    let command = refineid_apdu::CommandApdu::case_1(CommandHeader {
        class: ApduClass::Plain,
        instruction: VERIFY_INS,
        p1: VERIFY_P1,
        p2: scheme.puk_reference(),
    });
    let outcome = transport.transmit(&command).map_err(AuthError::Transport)?;
    let response = outcome.into_response().map_err(AuthError::Outcome)?;
    let status = crate::verify::classify_pin_status_sw(response.status_word());
    match scheme {
        PinReferenceScheme::Citizen
            if !matches!(status, PinStatus::Remaining(_) | PinStatus::Locked) =>
        {
            crate::activation::read_puk_status_from_container(transport)
        }
        PinReferenceScheme::Citizen | PinReferenceScheme::Organizational => Ok(status),
    }
}

/// Unblock `slot`, resetting its retry counter and setting `new`.
///
/// The PUK's counter is read first and the retry floor applied to it;
/// at two, one or no tries left, a blocked PUK, or no readable counter,
/// nothing that carries the PUK is sent. The citizen card then unblocks
/// in one RESET RETRY COUNTER carrying the PUK and the new PIN. The
/// organizational card verifies the PUK as its own object first, and
/// only an accepted PUK lets the reset -- carrying only the new PIN --
/// go out; a refused PUK ends the flow with its own outcome and the
/// reset is never sent.
pub(crate) fn unblock<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
    slot: PinSlot,
    puk: &[u8],
    new: &[u8],
) -> Result<ManageOutcome, AuthError<T::Error>> {
    let puk_counter = puk_status(transport, scheme)?;
    check_retry_floor(FlooredCredential::Puk, puk_counter).map_err(AuthError::RetryFloor)?;
    match scheme {
        PinReferenceScheme::Citizen => {
            let header = CommandHeader {
                class: ApduClass::Plain,
                instruction: RESET_RETRY_COUNTER_INS,
                p1: RESET_P1_CODE_THEN_NEW,
                p2: scheme.reference(slot),
            };
            let status = credential_exchange(transport, scheme, header, &[puk, new])?;
            Ok(classify_manage_sw(status))
        }
        PinReferenceScheme::Organizational => {
            let verified = verify_puk(transport, scheme, puk)?;
            if !matches!(verified, ManageOutcome::Ok) {
                return Ok(verified);
            }
            reset_new_only(transport, scheme, slot, new)
        }
    }
}

/// VERIFY the PUK as its own object under `scheme`'s PUK reference, the
/// organizational card's first unblock command (FINEID S4-2 v4.0 section
/// 4.3.2). The caller has applied the retry floor to the PUK's counter.
pub(crate) fn verify_puk<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
    puk: &[u8],
) -> Result<ManageOutcome, AuthError<T::Error>> {
    let header = CommandHeader {
        class: ApduClass::Plain,
        instruction: VERIFY_INS,
        p1: VERIFY_P1,
        p2: scheme.puk_reference(),
    };
    let status = credential_exchange(transport, scheme, header, &[puk])?;
    Ok(classify_manage_sw(status))
}

/// RESET RETRY COUNTER for `slot` carrying only the new PIN, under P1
/// [`RESET_P1_NEW_ONLY`]. It presents no credential, so it spends no
/// try; the card accepts it only when its security state already
/// authorises the reset.
pub(crate) fn reset_new_only<T: CardTransport + ?Sized>(
    transport: &mut T,
    scheme: PinReferenceScheme,
    slot: PinSlot,
    new: &[u8],
) -> Result<ManageOutcome, AuthError<T::Error>> {
    let header = CommandHeader {
        class: ApduClass::Plain,
        instruction: RESET_RETRY_COUNTER_INS,
        p1: RESET_P1_NEW_ONLY,
        p2: scheme.reference(slot),
    };
    let status = credential_exchange(transport, scheme, header, &[new])?;
    Ok(classify_manage_sw(status))
}

/// Refuse an activation PIN change where it would spend one of the
/// PIN's last two tries, or where the counter cannot be read and so a
/// last try might be spent unknowingly. At no tries left or blocked the
/// change goes to the card: it answers for itself and spends nothing,
/// and which code the holder has in hand (this scheme's activation PIN,
/// or a PUK) is inferred, never known, so the software does not close
/// a recovery the card would allow.
///
/// # Errors
///
/// [`RetryFloorRefusal::TriesBelowFloor`] at two or one tries left;
/// [`RetryFloorRefusal::CounterUnreadable`] at a count above five or a
/// status that carries no counter.
const fn check_activation_last_tries(
    credential: FlooredCredential,
    status: PinStatus,
) -> Result<(), RetryFloorRefusal> {
    match status {
        PinStatus::Remaining(remaining) => match PinRetryRisk::from_retries(remaining) {
            Some(risk) if risk.spends_a_last_try() => Err(RetryFloorRefusal::TriesBelowFloor {
                credential,
                remaining,
            }),
            Some(_) => Ok(()),
            None => Err(RetryFloorRefusal::CounterUnreadable { credential }),
        },
        PinStatus::Verified | PinStatus::Locked => Ok(()),
        PinStatus::NoInfo | PinStatus::Other(_) => {
            Err(RetryFloorRefusal::CounterUnreadable { credential })
        }
    }
}

/// What one activation reading found for each PIN: whether it awaits
/// activation, and the counter-safe status that reading took.
struct ActivationReading {
    /// Which PINs await activation.
    needs: crate::activation::CardActivationNeeds,
    /// PIN 1's status, read under the reading's numbering.
    pin1: PinStatus,
    /// PIN 2's status, read under the reading's numbering.
    pin2: PinStatus,
}

impl ActivationReading {
    /// The status this reading took for `slot`.
    const fn status(&self, slot: PinSlot) -> PinStatus {
        match slot {
            PinSlot::Pin1 => self.pin1,
            PinSlot::Pin2 => self.pin2,
        }
    }
}

/// Read each PIN's changed flag and its counter-safe status under
/// `numbering`, PIN 1 then PIN 2, and judge under `scheme` whether it
/// awaits activation (see [`crate::activation::pin_awaits_activation`]).
/// Every command here is a read and touches no retry counter.
fn read_activation<T: CardTransport>(
    transport: &mut T,
    scheme: crate::activation::ActivationScheme,
    numbering: PinReferenceScheme,
) -> Result<ActivationReading, AuthError<T::Error>> {
    let mut read = |slot: PinSlot| -> Result<(bool, PinStatus), AuthError<T::Error>> {
        let record = crate::activation::read_pin_change_record(transport, slot)?;
        let status = transport.pin_status_with_scheme(numbering, slot)?;
        Ok((
            crate::activation::pin_awaits_activation(scheme, record, status),
            status,
        ))
    };
    let (pin1_awaits, pin1) = read(PinSlot::Pin1)?;
    let (pin2_awaits, pin2) = read(PinSlot::Pin2)?;
    Ok(ActivationReading {
        needs: crate::activation::CardActivationNeeds {
            pin1: pin1_awaits,
            pin2: pin2_awaits,
        },
        pin1,
        pin2,
    })
}

/// PIN change and unblock operations, layered as default methods on every
/// [`CardTransport`].
///
/// Bring the trait into scope to use the methods; the blanket
/// implementation applies to every transport. The change, unblock and
/// activation operations take the [`CardPinLengths`] the session read
/// with [`PinManageOps::read_card_pin_lengths`], and act under the
/// numbering it was read by.
///
/// These operations mutate the card and are not idempotent. A wrong
/// current PIN or PUK spends a retry, and for the PUK exhaustion is
/// terminal. The unblock and activation-by-PUK operations apply the
/// retry floor to the PUK's counter themselves, and activation by the
/// preset activation PIN applies it to the counter of each PIN it
/// changes; a caller of a change must hold the retry floor for the
/// current PIN before calling.
pub trait PinManageOps: PinOps {
    /// Read the PIN 1, PIN 2 and PUK lengths the card accepts, resolving
    /// the card's numbering first.
    ///
    /// Read once per card session where PINs are set -- activation,
    /// change, reset -- and pass the result to those operations; the
    /// signing and login paths never read it.
    ///
    /// # Errors
    ///
    /// As [`PinManageOps::read_card_pin_lengths_with_scheme`].
    fn read_card_pin_lengths(&mut self) -> Result<CardPinLengths, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let scheme = self.resolve_pin_reference_scheme()?;
        self.read_card_pin_lengths_with_scheme(scheme)
    }

    /// Read the PIN 1, PIN 2 and PUK lengths the card accepts under an
    /// explicit numbering.
    ///
    /// EF.AOD is read under the PKCS#15 application, which leaves that
    /// application selected. A citizen card whose EF.AOD does not list a
    /// credential is asked for that credential's PIN container, whose PIN
    /// policy is the second source; the organization card supports no PIN
    /// container and is not asked. An EF.AOD that cannot be selected, read
    /// or decoded lists nothing, and a credential no source lists takes
    /// its role type's FINEID bounds. Every command here is a read and
    /// touches no retry counter.
    ///
    /// # Errors
    ///
    /// [`AuthError::Transport`] or [`AuthError::Outcome`] when the card
    /// session fails during a read.
    fn read_card_pin_lengths_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
    ) -> Result<CardPinLengths, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let objects = match self.read_authentication_objects() {
            Ok(objects) => Some(objects),
            Err(Pkcs15Error::Transport(error)) => return Err(AuthError::Transport(error)),
            Err(Pkcs15Error::Outcome(outcome)) => return Err(AuthError::Outcome(outcome)),
            Err(
                Pkcs15Error::Status(_)
                | Pkcs15Error::Aid(_)
                | Pkcs15Error::Command(_)
                | Pkcs15Error::Empty
                | Pkcs15Error::TooLarge
                | Pkcs15Error::InvalidData(_),
            ) => None,
        };
        let mut failure = None;
        let lengths = CardPinLengths::from_card(scheme, objects.as_ref(), |reference| {
            if failure.is_some() || scheme != PinReferenceScheme::Citizen {
                return None;
            }
            match crate::activation::read_pin_policy_lengths(self, reference) {
                Ok(range) => range,
                Err(error) => {
                    failure = Some(error);
                    None
                }
            }
        });
        match failure {
            Some(error) => Err(error),
            None => Ok(lengths),
        }
    }

    /// Change PIN1, presenting the current value and setting the new one,
    /// under the numbering `lengths` was read by.
    ///
    /// # Errors
    ///
    /// [`AuthError::PinLength`] when the card does not accept the length
    /// of either PIN; nothing is sent. [`AuthError`] on a transport
    /// failure or state transition. A wrong current PIN is not an error;
    /// it is [`ManageOutcome::WrongCredential`].
    fn change_pin1(
        &mut self,
        lengths: &CardPinLengths,
        current: Pin1,
        new: Pin1,
    ) -> Result<ManageOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        lengths.check_pin1(&current).map_err(AuthError::PinLength)?;
        lengths.check_pin1(&new).map_err(AuthError::PinLength)?;
        change(
            self,
            lengths.numbering(),
            PinSlot::Pin1,
            current.digits(),
            new.digits(),
        )
    }

    /// Change PIN2 under the numbering `lengths` was read by.
    ///
    /// # Errors
    ///
    /// As [`PinManageOps::change_pin1`].
    fn change_pin2(
        &mut self,
        lengths: &CardPinLengths,
        current: Pin2,
        new: Pin2,
    ) -> Result<ManageOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        lengths.check_pin2(&current).map_err(AuthError::PinLength)?;
        lengths.check_pin2(&new).map_err(AuthError::PinLength)?;
        change(
            self,
            lengths.numbering(),
            PinSlot::Pin2,
            current.digits(),
            new.digits(),
        )
    }

    /// Unblock PIN1 with the PUK, setting a new value, under the
    /// numbering `lengths` was read by.
    ///
    /// # Errors
    ///
    /// [`AuthError::PinLength`] when the card does not accept the length
    /// of the PUK or the new PIN; nothing is sent.
    /// [`AuthError::RetryFloor`] when the PUK's counter is below the
    /// retry floor, blocked or unreadable; nothing carrying the PUK is
    /// sent. [`AuthError`] on a transport failure or state transition. A
    /// wrong PUK is not an error; it is [`ManageOutcome::WrongCredential`]
    /// carrying the PUK's own remaining attempts.
    fn unblock_pin1(
        &mut self,
        lengths: &CardPinLengths,
        puk: Puk,
        new: Pin1,
    ) -> Result<ManageOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        lengths.check_puk(&puk).map_err(AuthError::PinLength)?;
        lengths.check_pin1(&new).map_err(AuthError::PinLength)?;
        unblock(
            self,
            lengths.numbering(),
            PinSlot::Pin1,
            puk.digits(),
            new.digits(),
        )
    }

    /// Unblock PIN2 with the PUK under the numbering `lengths` was read
    /// by.
    ///
    /// # Errors
    ///
    /// As [`PinManageOps::unblock_pin1`].
    fn unblock_pin2(
        &mut self,
        lengths: &CardPinLengths,
        puk: Puk,
        new: Pin2,
    ) -> Result<ManageOutcome, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        lengths.check_puk(&puk).map_err(AuthError::PinLength)?;
        lengths.check_pin2(&new).map_err(AuthError::PinLength)?;
        unblock(
            self,
            lengths.numbering(),
            PinSlot::Pin2,
            puk.digits(),
            new.digits(),
        )
    }

    /// Read a PIN's changed-since-manufacture record.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn read_pin_change_record(
        &mut self,
        slot: PinSlot,
    ) -> Result<crate::activation::PinChangeRecord, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        crate::activation::read_pin_change_record(self, slot)
    }

    /// Report factory activation needs under `scheme`, one PIN at a time
    /// (FINEID S4-1 v4.2 section 4.6; see
    /// [`crate::activation::pin_awaits_activation`]).
    ///
    /// Resolves the card's numbering, then reads each PIN's changed flag
    /// and retry status under it; every read leaves every counter
    /// untouched.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn activation_needs(
        &mut self,
        scheme: crate::activation::ActivationScheme,
    ) -> Result<crate::activation::CardActivationNeeds, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let numbering = self.resolve_pin_reference_scheme()?;
        read_activation(self, scheme, numbering).map(|reading| reading.needs)
    }

    /// Probe the PUK retry status without side effects under an explicit `scheme`.
    ///
    /// For citizen cards, sends a Case 1 empty VERIFY APDU (header-only, no Lc,
    /// no data field) under [`crate::verify::PUK_REFERENCE`], querying comparison status
    /// without consuming retries (ISO 7816-4 section 7.5.6). If the card does not
    /// report retry status via the VERIFY status word, it falls back to querying
    /// the PIN container via GET DATA (FINEID S1 v4.2 section 3.15.2).
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn probe_puk_status_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
    ) -> Result<PinStatus, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        puk_status(self, scheme)
    }

    /// Probe the PUK retry status without side effects, resolving the numbering first.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn probe_puk_status(&mut self) -> Result<PinStatus, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let scheme = self.resolve_pin_reference_scheme()?;
        self.probe_puk_status_with_scheme(scheme)
    }

    /// Activate a card awaiting activation under the scheme `code` was
    /// validated for (see
    /// [`crate::activation::ActivationScheme::from_numbering_and_validity_start`]),
    /// addressing the card under the numbering `lengths` was read by.
    ///
    /// Each supplied new PIN, and the activation entry presented with it
    /// -- in place of the PUK, or of that PIN under the preset activation
    /// PIN scheme -- is checked against `lengths` before any command.
    ///
    /// Under [`crate::activation::ActivationScheme::ActivationCodeIsPuk`]
    /// the activation PIN is presented as the PUK, so each unblock
    /// applies the retry floor to the PUK's counter first.
    ///
    /// Under [`crate::activation::ActivationScheme::PresetActivationPin`]
    /// the activation PIN is presented as the current value of each PIN
    /// it activates, and a wrong one spends that PIN's own try. Each
    /// PIN's changed flag and counter-safe status are read first, under
    /// the numbering of `lengths`, PIN 1 then PIN 2; the retry floor is
    /// applied to the status of every PIN about to be changed before the
    /// first CHANGE REFERENCE DATA. A refusal for either PIN sends no
    /// CHANGE REFERENCE DATA at all, so the card is left as it was; a
    /// caller that wants PIN 1 activated alone passes no new PIN 2.
    ///
    /// # Errors
    ///
    /// [`AuthError::PinLength`] when the card does not accept the length
    /// of an entry; nothing is sent.
    /// [`AuthError::RetryFloor`] under either scheme when the counter of
    /// the credential the activation PIN is presented as -- the PUK, or
    /// the PIN 1 or PIN 2 it activates -- is below the retry floor,
    /// blocked or unreadable; nothing carrying the activation PIN is sent
    /// to that credential. [`AuthError`] on a transport failure or state
    /// transition.
    fn activate_card(
        &mut self,
        lengths: &CardPinLengths,
        code: crate::activation::ActivationCode,
        new_pin1: Option<Pin1>,
        new_pin2: Option<Pin2>,
    ) -> Result<crate::activation::ActivationReport, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let scheme = code.scheme();
        let code_length = code.digits().len();
        let presented_as = |slot: PinSlot| match scheme {
            crate::activation::ActivationScheme::PresetActivationPin => Some(slot),
            crate::activation::ActivationScheme::ActivationCodeIsPuk => None,
        };
        if let Some(pin) = &new_pin1 {
            lengths
                .check_activation_entry(presented_as(PinSlot::Pin1), code_length)
                .map_err(AuthError::PinLength)?;
            lengths.check_pin1(pin).map_err(AuthError::PinLength)?;
        }
        if let Some(pin) = &new_pin2 {
            lengths
                .check_activation_entry(presented_as(PinSlot::Pin2), code_length)
                .map_err(AuthError::PinLength)?;
            lengths.check_pin2(pin).map_err(AuthError::PinLength)?;
        }
        let ref_scheme = lengths.numbering();
        let reading = read_activation(self, scheme, ref_scheme)?;
        let needs = reading.needs;
        match scheme {
            crate::activation::ActivationScheme::PresetActivationPin => {
                let changes = [
                    (PinSlot::Pin1, needs.pin1 && new_pin1.is_some()),
                    (PinSlot::Pin2, needs.pin2 && new_pin2.is_some()),
                ];
                for (slot, changed) in changes {
                    if changed {
                        check_activation_last_tries(slot.into(), reading.status(slot))
                            .map_err(AuthError::RetryFloor)?;
                    }
                }
            }
            crate::activation::ActivationScheme::ActivationCodeIsPuk => {}
        }
        let mut report = crate::activation::ActivationReport {
            scheme,
            pin1: None,
            pin2: None,
        };

        if needs.pin1
            && let Some(fresh_pin1) = new_pin1
        {
            let outcome = match scheme {
                crate::activation::ActivationScheme::PresetActivationPin => change(
                    self,
                    ref_scheme,
                    PinSlot::Pin1,
                    code.digits(),
                    fresh_pin1.digits(),
                )?,
                crate::activation::ActivationScheme::ActivationCodeIsPuk => unblock(
                    self,
                    ref_scheme,
                    PinSlot::Pin1,
                    code.digits(),
                    fresh_pin1.digits(),
                )?,
            };
            report.pin1 = Some(outcome);
            if outcome != ManageOutcome::Ok {
                return Ok(report);
            }
        }

        if needs.pin2
            && let Some(fresh_pin2) = new_pin2
        {
            let outcome = match scheme {
                crate::activation::ActivationScheme::PresetActivationPin => change(
                    self,
                    ref_scheme,
                    PinSlot::Pin2,
                    code.digits(),
                    fresh_pin2.digits(),
                )?,
                crate::activation::ActivationScheme::ActivationCodeIsPuk => unblock(
                    self,
                    ref_scheme,
                    PinSlot::Pin2,
                    code.digits(),
                    fresh_pin2.digits(),
                )?,
            };
            report.pin2 = Some(outcome);
        }

        Ok(report)
    }

    /// Probe overall credential status and health summary for UI display.
    ///
    /// The activation scheme is decided from the resolved numbering and
    /// `auth_certificate_validity_start`, the authentication
    /// certificate's notBefore in epoch seconds, `None` when it was not
    /// read (see
    /// [`crate::activation::ActivationScheme::from_numbering_and_validity_start`]).
    /// Activation needs are read only when a scheme is decided.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a transport failure or state transition.
    fn probe_credential_health(
        &mut self,
        auth_certificate_validity_start: Option<i64>,
    ) -> Result<crate::activation::CredentialHealthReport, AuthError<Self::Error>>
    where
        Self: Sized,
    {
        let ref_scheme = self.resolve_pin_reference_scheme()?;
        let pin1_status = self.pin_status_with_scheme(ref_scheme, PinSlot::Pin1)?;
        let pin2_status = self.pin_status_with_scheme(ref_scheme, PinSlot::Pin2)?;
        let puk_status = self.probe_puk_status_with_scheme(ref_scheme)?;
        let activation_scheme =
            crate::activation::ActivationScheme::from_numbering_and_validity_start(
                ref_scheme,
                auth_certificate_validity_start,
            );
        let activation_needs = match activation_scheme {
            Some(scheme) => Some(self.activation_needs(scheme)?),
            None => None,
        };
        Ok(crate::activation::CredentialHealthReport {
            pin1_status,
            pin2_status,
            puk_status,
            pin_reference_scheme: ref_scheme,
            activation_scheme,
            activation_needs,
        })
    }
}

impl<T: CardTransport + ?Sized> PinManageOps for T {}

#[cfg(test)]
mod tests {
    use super::{
        CHANGE_P1_CURRENT_THEN_NEW, CHANGE_REFERENCE_DATA_INS, CardPinLengths, ManageOutcome,
        PinManageOps, RESET_P1_CODE_THEN_NEW, RESET_P1_NEW_ONLY, RESET_RETRY_COUNTER_INS,
        classify_manage_sw,
    };
    use crate::activation::{
        ActivationCode, ActivationReport, ActivationScheme, GET_DATA_INS,
        PIN_CHANGED_FLAG_UNCHANGED, PIN_CHANGED_LEN, PIN_CHANGED_TAG_HIGH, PIN_CHANGED_TAG_LOW,
    };
    use crate::credentials::{PIN_MAX_LENGTH, PIN_MIN_LENGTH, Pin1, Pin2, Puk, UnvalidatedSecret};
    use crate::verify::{CREDENTIAL_BODY_SCRATCH, VERIFY_INS, VERIFY_P1};
    use crate::{
        AuthError, FlooredCredential, PIN_STORED_LENGTH, PUK_REFERENCE_ORGANIZATIONAL,
        PinReferenceScheme, PinSlot, PinStatus, RetryFloorRefusal, check_retry_floor,
    };
    use refineid_apdu::{
        ApduClass, CardTransport, CommandApdu, CredentialCommand, PinRetries, ResponseApdu,
        StatusWord, TransportOutcome,
    };

    /// A retry count for the tests.
    const TWO_RETRIES: u8 = 2;
    /// Retry count of a pristine credential.
    const RETRIES_PRISTINE: u8 = 5;
    /// Retry count after one wrong try.
    const RETRIES_ONE_SPENT: u8 = 4;
    /// Lowest retry count the floor serves.
    const RETRIES_FLOOR: u8 = 3;
    /// Commands a refused counter probe leaves on the wire: the probe.
    const PROBE_ONLY_COMMAND_COUNT: usize = 1;
    /// Commands a refusal after the citizen container read leaves on the
    /// wire: the probe, then GET DATA.
    const CONTAINER_READ_COMMAND_COUNT: usize = 2;
    /// Commands the citizen unblock sends: the PUK probe, then the reset.
    const CITIZEN_UNBLOCK_COMMAND_COUNT: usize = 2;
    /// Highest retry count below the retry floor.
    const RETRIES_BELOW_FLOOR: u8 = 2;
    /// Retry count one wrong try from lockout.
    const RETRIES_LOCKDOWN_IMMINENT: u8 = 1;
    /// Retry count of an exhausted PIN.
    const RETRIES_EXHAUSTED: u8 = 0;
    /// A valid new-PIN2 fixture, six digits.
    const NEW_PIN2_DIGITS: &[u8] = b"567890";
    /// Commands the organizational unblock sends: the PUK probe, a VERIFY
    /// then a RESET.
    const ORG_UNBLOCK_COMMAND_COUNT: usize = 3;
    /// Wire index of the class byte.
    const CLA_INDEX: usize = 0;
    /// Wire index of the instruction byte.
    const INS_INDEX: usize = 1;
    /// Wire index of the P1 byte.
    const P1_INDEX: usize = 2;
    /// Wire index of the P2 reference byte.
    const P2_INDEX: usize = 3;
    /// Wire index of the Lc byte.
    const LC_INDEX: usize = 4;
    /// Wire offset of the data field: past the header and the Lc byte.
    const DATA_OFFSET: usize = 5;
    /// A valid PUK fixture, eight digits.
    const PUK_DIGITS: &[u8] = b"12345678";
    /// A valid current-PIN fixture.
    const CURRENT_DIGITS: &[u8] = b"1234";
    /// A valid new-PIN fixture.
    const NEW_DIGITS: &[u8] = b"5678";
    /// A current PIN at the longest length either role accepts.
    const LONGEST_CURRENT_DIGITS: &[u8] = b"135792468024";
    /// A new PIN at the longest length either role accepts.
    const LONGEST_NEW_DIGITS: &[u8] = b"975318642086";

    fn response(sw: StatusWord) -> ResponseApdu {
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

    /// The counter-safe PUK probe's answer at `count` tries left.
    fn puk_counter(count: u8) -> StatusWord {
        StatusWord::PinIncorrect {
            retries: PinRetries::from_nibble(count).expect("fits a nibble"),
        }
    }

    /// A PIN's counter-safe probe answer at `count` tries left, the same
    /// status word the PUK probe answers.
    fn pin_counter(count: u8) -> StatusWord {
        puk_counter(count)
    }

    /// A PUK probe answer the floor serves.
    fn puk_counter_served() -> StatusWord {
        puk_counter(RETRIES_PRISTINE)
    }

    fn puk(digits: &[u8]) -> Puk {
        Puk::reconstruct(UnvalidatedSecret::from_owned_bytes(digits.to_vec()))
            .expect("valid PUK fixture")
    }

    /// Records each credential command's wire and answers with the next
    /// scripted status word.
    struct Recorder {
        commands: Vec<Vec<u8>>,
        responses: Vec<StatusWord>,
        cursor: usize,
    }

    impl Recorder {
        fn new(responses: Vec<StatusWord>) -> Self {
            Self {
                commands: vec![],
                responses,
                cursor: 0,
            }
        }
    }

    impl CardTransport for Recorder {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.commands.push(command.as_bytes().to_vec());
            let sw = *self
                .responses
                .get(self.cursor)
                .ok_or_else(|| format!("script exhausted at command {}", self.cursor))?;
            self.cursor += 1;
            Ok(TransportOutcome::Response(response(sw)))
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.commands.push(command.expose_wire(<[u8]>::to_vec));
            let sw = *self
                .responses
                .get(self.cursor)
                .ok_or_else(|| format!("script exhausted at command {}", self.cursor))?;
            self.cursor += 1;
            Ok(TransportOutcome::Response(response(sw)))
        }
    }

    #[test]
    fn manage_classifier_covers_the_outcomes() {
        assert_eq!(classify_manage_sw(StatusWord::Success), ManageOutcome::Ok);
        let two = PinRetries::from_nibble(TWO_RETRIES).expect("fits a nibble");
        assert_eq!(
            classify_manage_sw(StatusWord::PinIncorrect { retries: two }),
            ManageOutcome::WrongCredential { retries_left: two }
        );
        assert_eq!(
            classify_manage_sw(StatusWord::AuthenticationBlocked),
            ManageOutcome::Locked
        );
        assert_eq!(
            classify_manage_sw(StatusWord::ReferenceDataInvalidated),
            ManageOutcome::Locked
        );
        assert_eq!(
            classify_manage_sw(StatusWord::FileNotFound),
            ManageOutcome::Other(StatusWord::FileNotFound)
        );
    }

    #[test]
    fn citizen_change_pin1_presents_current_then_new_padded_blocks() {
        let mut transport = Recorder::new(vec![StatusWord::Success]);
        let outcome = transport
            .change_pin1(
                &CardPinLengths::not_listed(PinReferenceScheme::Citizen),
                pin1(CURRENT_DIGITS),
                pin1(NEW_DIGITS),
            )
            .expect("scripted change succeeds");
        assert_eq!(outcome, ManageOutcome::Ok);
        assert_eq!(transport.commands.len(), 1);
        let wire = &transport.commands[0];
        assert_eq!(wire[CLA_INDEX], ApduClass::Plain.as_byte());
        assert_eq!(wire[INS_INDEX], CHANGE_REFERENCE_DATA_INS);
        assert_eq!(wire[P1_INDEX], CHANGE_P1_CURRENT_THEN_NEW);
        assert_eq!(
            wire[P2_INDEX],
            PinReferenceScheme::Citizen.reference(PinSlot::Pin1)
        );
        // Two blocks, each padded to the stored length.
        assert_eq!(usize::from(wire[LC_INDEX]), CREDENTIAL_BODY_SCRATCH);
        assert_eq!(
            &wire[DATA_OFFSET..DATA_OFFSET + CURRENT_DIGITS.len()],
            CURRENT_DIGITS
        );
        let new_start = DATA_OFFSET + PIN_STORED_LENGTH;
        assert_eq!(&wire[new_start..new_start + NEW_DIGITS.len()], NEW_DIGITS);
    }

    #[test]
    fn organizational_change_pin1_presents_typed_length_blocks() {
        let mut transport = Recorder::new(vec![StatusWord::Success]);
        transport
            .change_pin1(
                &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                pin1(CURRENT_DIGITS),
                pin1(NEW_DIGITS),
            )
            .expect("scripted change succeeds");
        let wire = &transport.commands[0];
        assert_eq!(wire[INS_INDEX], CHANGE_REFERENCE_DATA_INS);
        assert_eq!(
            wire[P2_INDEX],
            PinReferenceScheme::Organizational.reference(PinSlot::Pin1)
        );
        // Bare typed blocks, back to back, no padding.
        assert_eq!(
            usize::from(wire[LC_INDEX]),
            CURRENT_DIGITS.len() + NEW_DIGITS.len()
        );
        let mut both = CURRENT_DIGITS.to_vec();
        both.extend_from_slice(NEW_DIGITS);
        assert_eq!(&wire[DATA_OFFSET..], both.as_slice());
    }

    #[test]
    fn citizen_unblock_pin1_presents_puk_then_new() {
        let mut transport = Recorder::new(vec![puk_counter_served(), StatusWord::Success]);
        let outcome = transport
            .unblock_pin1(
                &CardPinLengths::not_listed(PinReferenceScheme::Citizen),
                puk(PUK_DIGITS),
                pin1(NEW_DIGITS),
            )
            .expect("scripted unblock succeeds");
        assert_eq!(outcome, ManageOutcome::Ok);
        assert_eq!(transport.commands.len(), CITIZEN_UNBLOCK_COMMAND_COUNT);
        let probe = &transport.commands[0];
        assert_eq!(probe[INS_INDEX], VERIFY_INS);
        assert_eq!(probe[P2_INDEX], crate::verify::PUK_REFERENCE);
        let wire = &transport.commands[1];
        assert_eq!(wire[INS_INDEX], RESET_RETRY_COUNTER_INS);
        assert_eq!(wire[P1_INDEX], RESET_P1_CODE_THEN_NEW);
        assert_eq!(
            wire[P2_INDEX],
            PinReferenceScheme::Citizen.reference(PinSlot::Pin1)
        );
        assert_eq!(usize::from(wire[LC_INDEX]), CREDENTIAL_BODY_SCRATCH);
        assert_eq!(
            &wire[DATA_OFFSET..DATA_OFFSET + PUK_DIGITS.len()],
            PUK_DIGITS
        );
    }

    #[test]
    fn the_puk_sets_a_new_pin_where_the_retry_floor_refuses_an_attempt() {
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            for count in [
                RETRIES_BELOW_FLOOR,
                RETRIES_LOCKDOWN_IMMINENT,
                RETRIES_EXHAUSTED,
            ] {
                let status =
                    PinStatus::Remaining(PinRetries::from_nibble(count).expect("fits a nibble"));
                assert!(check_retry_floor(slot.into(), status).is_err());
                let mut transport = Recorder::new(vec![puk_counter_served(), StatusWord::Success]);
                let outcome = match slot {
                    PinSlot::Pin1 => transport.unblock_pin1(
                        &CardPinLengths::not_listed(PinReferenceScheme::Citizen),
                        puk(PUK_DIGITS),
                        pin1(NEW_DIGITS),
                    ),
                    PinSlot::Pin2 => transport.unblock_pin2(
                        &CardPinLengths::not_listed(PinReferenceScheme::Citizen),
                        puk(PUK_DIGITS),
                        pin2(NEW_PIN2_DIGITS),
                    ),
                }
                .expect("scripted unblock succeeds");
                assert_eq!(outcome, ManageOutcome::Ok);
                assert_eq!(transport.commands.len(), CITIZEN_UNBLOCK_COMMAND_COUNT);
                assert_eq!(transport.commands[1][INS_INDEX], RESET_RETRY_COUNTER_INS);
            }
        }
    }

    /// Unblock `slot` under `scheme` against a card whose PUK probe
    /// answers `probe` and every later command succeeds.
    fn unblock_against(
        scheme: PinReferenceScheme,
        slot: PinSlot,
        probe: StatusWord,
    ) -> (Result<ManageOutcome, AuthError<String>>, Recorder) {
        let mut transport = Recorder::new(vec![probe, StatusWord::Success, StatusWord::Success]);
        let result = match slot {
            PinSlot::Pin1 => transport.unblock_pin1(
                &CardPinLengths::not_listed(scheme),
                puk(PUK_DIGITS),
                pin1(NEW_DIGITS),
            ),
            PinSlot::Pin2 => transport.unblock_pin2(
                &CardPinLengths::not_listed(scheme),
                puk(PUK_DIGITS),
                pin2(NEW_PIN2_DIGITS),
            ),
        };
        (result, transport)
    }

    /// Both credential numberings.
    const SCHEMES: &[PinReferenceScheme] = &[
        PinReferenceScheme::Citizen,
        PinReferenceScheme::Organizational,
    ];

    #[test]
    fn the_puk_is_presented_at_five_four_and_three_tries_left() {
        for &scheme in SCHEMES {
            for slot in [PinSlot::Pin1, PinSlot::Pin2] {
                for count in [RETRIES_PRISTINE, RETRIES_ONE_SPENT, RETRIES_FLOOR] {
                    let (result, transport) = unblock_against(scheme, slot, puk_counter(count));
                    assert_eq!(result.expect("served"), ManageOutcome::Ok);
                    assert!(transport.commands.len() > PROBE_ONLY_COMMAND_COUNT);
                }
            }
        }
    }

    #[test]
    fn the_puk_is_never_presented_at_two_one_or_zero_tries_left() {
        for &scheme in SCHEMES {
            for slot in [PinSlot::Pin1, PinSlot::Pin2] {
                for count in [
                    RETRIES_BELOW_FLOOR,
                    RETRIES_LOCKDOWN_IMMINENT,
                    RETRIES_EXHAUSTED,
                ] {
                    let (result, transport) = unblock_against(scheme, slot, puk_counter(count));
                    let refused = matches!(
                        result,
                        Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
                            credential: FlooredCredential::Puk,
                            remaining,
                        })) if remaining.get() == count
                    );
                    assert!(refused, "{count} tries left must refuse the PUK");
                    assert_eq!(transport.commands.len(), PROBE_ONLY_COMMAND_COUNT);
                }
            }
        }
    }

    #[test]
    fn a_blocked_or_unreadable_puk_is_never_presented() {
        for &scheme in SCHEMES {
            let (blocked, transport) =
                unblock_against(scheme, PinSlot::Pin1, StatusWord::AuthenticationBlocked);
            assert!(matches!(
                blocked,
                Err(AuthError::RetryFloor(RetryFloorRefusal::Blocked {
                    credential: FlooredCredential::Puk
                }))
            ));
            assert_eq!(transport.commands.len(), PROBE_ONLY_COMMAND_COUNT);
        }
        // The organizational card answers the probe without a counter:
        // nothing further is read, and the PUK is refused.
        let (unreadable, transport) = unblock_against(
            PinReferenceScheme::Organizational,
            PinSlot::Pin2,
            StatusWord::AuthenticationFailed,
        );
        assert!(matches!(
            unreadable,
            Err(AuthError::RetryFloor(
                RetryFloorRefusal::CounterUnreadable {
                    credential: FlooredCredential::Puk
                }
            ))
        ));
        assert_eq!(transport.commands.len(), PROBE_ONLY_COMMAND_COUNT);
    }

    #[test]
    fn the_citizen_puk_container_counter_gates_the_unblock() {
        // The citizen probe answers without a counter, so the PIN
        // container is read; a container that reports the PUK blocked
        // refuses before the reset.
        let mut transport = Recorder::new(vec![
            StatusWord::AuthenticationFailed,
            StatusWord::AuthenticationBlocked,
            StatusWord::Success,
        ]);
        let result = transport.unblock_pin1(
            &CardPinLengths::not_listed(PinReferenceScheme::Citizen),
            puk(PUK_DIGITS),
            pin1(NEW_DIGITS),
        );
        assert!(matches!(
            result,
            Err(AuthError::RetryFloor(RetryFloorRefusal::Blocked {
                credential: FlooredCredential::Puk
            }))
        ));
        assert!(
            transport
                .commands
                .iter()
                .all(|wire| wire[INS_INDEX] != RESET_RETRY_COUNTER_INS)
        );
    }

    #[test]
    fn a_citizen_probe_answering_success_reads_the_container() {
        let mut transport = Recorder::new(vec![
            StatusWord::Success,
            StatusWord::AuthenticationBlocked,
            StatusWord::Success,
        ]);
        let result = transport.unblock_pin1(
            &CardPinLengths::not_listed(PinReferenceScheme::Citizen),
            puk(PUK_DIGITS),
            pin1(NEW_DIGITS),
        );
        assert!(matches!(
            result,
            Err(AuthError::RetryFloor(RetryFloorRefusal::Blocked {
                credential: FlooredCredential::Puk
            }))
        ));
        assert_eq!(transport.commands.len(), CONTAINER_READ_COMMAND_COUNT);
        assert_eq!(transport.commands[1][INS_INDEX], GET_DATA_INS);
    }

    #[test]
    fn an_organizational_puk_reported_verified_is_never_presented() {
        let (result, transport) = unblock_against(
            PinReferenceScheme::Organizational,
            PinSlot::Pin1,
            StatusWord::Success,
        );
        assert!(matches!(
            result,
            Err(AuthError::RetryFloor(
                RetryFloorRefusal::CounterUnreadable {
                    credential: FlooredCredential::Puk
                }
            ))
        ));
        assert_eq!(transport.commands.len(), PROBE_ONLY_COMMAND_COUNT);
    }

    #[test]
    fn organizational_unblock_verifies_the_puk_then_resets_new_only() {
        let mut transport = Recorder::new(vec![
            puk_counter_served(),
            StatusWord::Success,
            StatusWord::Success,
        ]);
        let outcome = transport
            .unblock_pin1(
                &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                puk(PUK_DIGITS),
                pin1(NEW_DIGITS),
            )
            .expect("scripted unblock succeeds");
        assert_eq!(outcome, ManageOutcome::Ok);
        assert_eq!(transport.commands.len(), ORG_UNBLOCK_COMMAND_COUNT);

        // First: the counter-safe PUK probe under the org PUK reference.
        let probe = &transport.commands[0];
        assert_eq!(probe[INS_INDEX], VERIFY_INS);
        assert_eq!(probe[P2_INDEX], PUK_REFERENCE_ORGANIZATIONAL);
        assert_eq!(probe.len(), DATA_OFFSET - 1);

        // Then: VERIFY the PUK as its own object under the org PUK reference.
        let verify = &transport.commands[1];
        assert_eq!(verify[INS_INDEX], VERIFY_INS);
        assert_eq!(verify[P1_INDEX], VERIFY_P1);
        assert_eq!(verify[P2_INDEX], PUK_REFERENCE_ORGANIZATIONAL);
        assert_eq!(&verify[DATA_OFFSET..], PUK_DIGITS);

        // Last: RESET carrying only the new PIN under the target reference.
        let reset = &transport.commands[ORG_UNBLOCK_COMMAND_COUNT - 1];
        assert_eq!(reset[INS_INDEX], RESET_RETRY_COUNTER_INS);
        assert_eq!(reset[P1_INDEX], RESET_P1_NEW_ONLY);
        assert_eq!(
            reset[P2_INDEX],
            PinReferenceScheme::Organizational.reference(PinSlot::Pin1)
        );
        assert_eq!(&reset[DATA_OFFSET..], NEW_DIGITS);
    }

    #[test]
    fn organizational_unblock_stops_when_the_puk_is_refused() {
        let two = PinRetries::from_nibble(TWO_RETRIES).expect("fits a nibble");
        let mut transport = Recorder::new(vec![
            puk_counter_served(),
            StatusWord::PinIncorrect { retries: two },
        ]);
        let outcome = transport
            .unblock_pin1(
                &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                puk(PUK_DIGITS),
                pin1(NEW_DIGITS),
            )
            .expect("scripted unblock completes");
        assert_eq!(
            outcome,
            ManageOutcome::WrongCredential { retries_left: two }
        );
        // The refused PUK ends the flow: the reset never went out.
        assert_eq!(transport.commands.len(), ORG_UNBLOCK_COMMAND_COUNT - 1);
    }

    /// The current and new PIN, back to back at their typed lengths, as
    /// the organizational CHANGE REFERENCE DATA carries them.
    fn back_to_back(current: &[u8], new: &[u8]) -> Vec<u8> {
        let mut both = current.to_vec();
        both.extend_from_slice(new);
        both
    }

    #[test]
    fn organizational_change_sends_twelve_digit_pins_unpadded() {
        assert_eq!(LONGEST_CURRENT_DIGITS.len(), PIN_MAX_LENGTH);
        assert_eq!(LONGEST_NEW_DIGITS.len(), PIN_MAX_LENGTH);
        let expected = back_to_back(LONGEST_CURRENT_DIGITS, LONGEST_NEW_DIGITS);

        let mut transport = Recorder::new(vec![StatusWord::Success]);
        transport
            .change_pin1(
                &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                pin1(LONGEST_CURRENT_DIGITS),
                pin1(LONGEST_NEW_DIGITS),
            )
            .expect("scripted change succeeds");
        let wire = &transport.commands[0];
        assert_eq!(
            wire[P2_INDEX],
            PinReferenceScheme::Organizational.reference(PinSlot::Pin1)
        );
        assert_eq!(usize::from(wire[LC_INDEX]), expected.len());
        assert_eq!(&wire[DATA_OFFSET..], expected.as_slice());

        let mut transport = Recorder::new(vec![StatusWord::Success]);
        transport
            .change_pin2(
                &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                pin2(LONGEST_CURRENT_DIGITS),
                pin2(LONGEST_NEW_DIGITS),
            )
            .expect("scripted change succeeds");
        let wire = &transport.commands[0];
        assert_eq!(
            wire[P2_INDEX],
            PinReferenceScheme::Organizational.reference(PinSlot::Pin2)
        );
        assert_eq!(usize::from(wire[LC_INDEX]), expected.len());
        assert_eq!(&wire[DATA_OFFSET..], expected.as_slice());
    }

    #[test]
    fn organizational_unblock_sets_a_twelve_digit_pin_unpadded() {
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            let mut transport = Recorder::new(vec![
                puk_counter_served(),
                StatusWord::Success,
                StatusWord::Success,
            ]);
            let outcome = match slot {
                PinSlot::Pin1 => transport.unblock_pin1(
                    &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                    puk(PUK_DIGITS),
                    pin1(LONGEST_NEW_DIGITS),
                ),
                PinSlot::Pin2 => transport.unblock_pin2(
                    &CardPinLengths::not_listed(PinReferenceScheme::Organizational),
                    puk(PUK_DIGITS),
                    pin2(LONGEST_NEW_DIGITS),
                ),
            }
            .expect("scripted unblock succeeds");
            assert_eq!(outcome, ManageOutcome::Ok);
            let reset = &transport.commands[ORG_UNBLOCK_COMMAND_COUNT - 1];
            assert_eq!(reset[INS_INDEX], RESET_RETRY_COUNTER_INS);
            assert_eq!(
                reset[P2_INDEX],
                PinReferenceScheme::Organizational.reference(slot)
            );
            assert_eq!(usize::from(reset[LC_INDEX]), LONGEST_NEW_DIGITS.len());
            assert_eq!(&reset[DATA_OFFSET..], LONGEST_NEW_DIGITS);
        }
    }

    #[test]
    fn a_pin_outside_the_role_bounds_never_becomes_a_credential() {
        // Change, unblock and activation take only a validated Pin1 or
        // Pin2, so a PIN that fails here has no path to any command.
        let longest_plus_one = back_to_back(LONGEST_NEW_DIGITS, &NEW_DIGITS[..1]);
        assert_eq!(longest_plus_one.len(), PIN_MAX_LENGTH + 1);
        let pin1_short = &NEW_DIGITS[..PIN_MIN_LENGTH - 1];
        let pin2_short = &NEW_PIN2_DIGITS[..PIN_MIN_LENGTH - 1];
        let secret = |digits: &[u8]| UnvalidatedSecret::from_owned_bytes(digits.to_vec());
        assert!(Pin1::reconstruct(secret(&longest_plus_one)).is_err());
        assert!(Pin2::reconstruct(secret(&longest_plus_one)).is_err());
        assert!(Pin1::reconstruct(secret(pin1_short)).is_err());
        assert!(Pin2::reconstruct(secret(pin2_short)).is_err());
    }

    #[test]
    fn citizen_puk_probe_wire_shape_is_case_1_without_data() {
        let two = PinRetries::from_nibble(TWO_RETRIES).expect("fits a nibble");
        let mut transport = Recorder::new(vec![StatusWord::PinIncorrect { retries: two }]);
        let status = transport
            .probe_puk_status_with_scheme(PinReferenceScheme::Citizen)
            .expect("probe completes");
        assert_eq!(status, crate::verify::PinStatus::Remaining(two));
        assert_eq!(transport.commands.len(), 1);
        let wire = &transport.commands[0];
        // Case 1 APDUs consist strictly of the 4-byte header: CLA, INS, P1, P2.
        // There is no Lc byte and no data field, guaranteeing zero retry consumption.
        const CASE_1_APDU_HEADER_LEN: usize = 4;
        assert_eq!(wire.len(), CASE_1_APDU_HEADER_LEN);
        assert_eq!(wire[CLA_INDEX], ApduClass::Plain.as_byte());
        assert_eq!(wire[INS_INDEX], VERIFY_INS);
        assert_eq!(wire[P1_INDEX], VERIFY_P1);
        assert_eq!(wire[P2_INDEX], crate::verify::PUK_REFERENCE);
    }

    #[test]
    fn citizen_puk_probe_falls_back_to_container_on_unsupported_verify() {
        let mut transport = Recorder::new(vec![
            StatusWord::ReferenceDataNotFound,
            StatusWord::AuthenticationBlocked,
        ]);
        let status = transport
            .probe_puk_status_with_scheme(PinReferenceScheme::Citizen)
            .expect("probe completes via container fallback");
        assert_eq!(status, crate::verify::PinStatus::Locked);
        const EXPECTED_COMMAND_COUNT: usize = 2;
        assert_eq!(transport.commands.len(), EXPECTED_COMMAND_COUNT);
    }

    #[test]
    fn citizen_puk_probe_falls_back_to_container_on_no_info_verify() {
        let mut transport = Recorder::new(vec![
            StatusWord::AuthenticationFailed,
            StatusWord::AuthenticationBlocked,
        ]);
        let status = transport
            .probe_puk_status_with_scheme(PinReferenceScheme::Citizen)
            .expect("probe completes via container fallback");
        assert_eq!(status, crate::verify::PinStatus::Locked);
        const EXPECTED_COMMAND_COUNT: usize = 2;
        assert_eq!(transport.commands.len(), EXPECTED_COMMAND_COUNT);
    }

    #[test]
    fn citizen_puk_probe_propagates_transport_error() {
        let mut transport = Recorder::new(vec![]);
        let err = transport
            .probe_puk_status_with_scheme(PinReferenceScheme::Citizen)
            .expect_err("must propagate transport error");
        assert!(matches!(err, AuthError::Transport(_)));
    }

    /// A preset activation PIN fixture, seven digits.
    const ACTIVATION_PIN_DIGITS: &[u8] = b"7654321";
    /// Commands a preset activation of both PINs sends: the PIN 1
    /// container read and counter probe, the same for PIN 2, then one
    /// CHANGE REFERENCE DATA per PIN.
    const PRESET_ACTIVATION_INSTRUCTIONS: &[u8] = &[
        GET_DATA_INS,
        VERIFY_INS,
        GET_DATA_INS,
        VERIFY_INS,
        CHANGE_REFERENCE_DATA_INS,
        CHANGE_REFERENCE_DATA_INS,
    ];
    /// Wire index of the first CHANGE REFERENCE DATA in a preset
    /// activation of both PINs.
    const PRESET_PIN1_CHANGE_INDEX: usize = 4;
    /// Wire index of the second CHANGE REFERENCE DATA in a preset
    /// activation of both PINs.
    const PRESET_PIN2_CHANGE_INDEX: usize = 5;

    /// A citizen card under the preset activation PIN scheme: its PIN
    /// container reports each PIN unchanged since manufacture, its
    /// counter-safe probes answer the scripted status of each PIN, and
    /// every credential command succeeds. Records every command's wire in
    /// order.
    struct PresetCard {
        pin1_probe: StatusWord,
        pin2_probe: StatusWord,
        commands: Vec<Vec<u8>>,
    }

    impl PresetCard {
        fn new(pin1_probe: StatusWord, pin2_probe: StatusWord) -> Self {
            Self {
                pin1_probe,
                pin2_probe,
                commands: vec![],
            }
        }

        /// Activate under the preset scheme with the citizen numbering.
        fn activate(
            &mut self,
            new_pin1: Option<Pin1>,
            new_pin2: Option<Pin2>,
        ) -> Result<ActivationReport, AuthError<String>> {
            let code = ActivationCode::reconstruct(
                UnvalidatedSecret::from_owned_bytes(ACTIVATION_PIN_DIGITS.to_vec()),
                ActivationScheme::PresetActivationPin,
            )
            .expect("valid preset activation PIN fixture");
            self.activate_card(
                &CardPinLengths::not_listed(PinReferenceScheme::Citizen),
                code,
                new_pin1,
                new_pin2,
            )
        }

        fn sent_a_change(&self) -> bool {
            self.commands
                .iter()
                .any(|wire| wire[INS_INDEX] == CHANGE_REFERENCE_DATA_INS)
        }
    }

    impl CardTransport for PresetCard {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let wire = command.as_bytes().to_vec();
            let pin1_reference = PinReferenceScheme::Citizen.reference(PinSlot::Pin1);
            let pin2_reference = PinReferenceScheme::Citizen.reference(PinSlot::Pin2);
            let answer = match (wire[INS_INDEX], wire[P2_INDEX]) {
                (GET_DATA_INS, _) => ResponseApdu {
                    body: vec![
                        PIN_CHANGED_TAG_HIGH,
                        PIN_CHANGED_TAG_LOW,
                        PIN_CHANGED_LEN,
                        PIN_CHANGED_FLAG_UNCHANGED,
                    ],
                    ..response(StatusWord::Success)
                },
                (VERIFY_INS, reference) if reference == pin1_reference => response(self.pin1_probe),
                (VERIFY_INS, reference) if reference == pin2_reference => response(self.pin2_probe),
                _ => response(StatusWord::ReferenceDataNotFound),
            };
            self.commands.push(wire);
            Ok(TransportOutcome::Response(answer))
        }

        fn transmit_credential(
            &mut self,
            command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            self.commands.push(command.expose_wire(<[u8]>::to_vec));
            Ok(TransportOutcome::Response(response(StatusWord::Success)))
        }
    }

    #[test]
    fn preset_activation_changes_each_pin_at_or_above_the_floor() {
        for probe in [
            pin_counter(RETRIES_PRISTINE),
            pin_counter(RETRIES_ONE_SPENT),
            pin_counter(RETRIES_FLOOR),
            StatusWord::Success,
        ] {
            let mut card = PresetCard::new(probe, probe);
            let report = card
                .activate(Some(pin1(NEW_DIGITS)), Some(pin2(NEW_PIN2_DIGITS)))
                .expect("both counters are served");
            assert_eq!(report.pin1, Some(ManageOutcome::Ok));
            assert_eq!(report.pin2, Some(ManageOutcome::Ok));
            let instructions: Vec<u8> = card.commands.iter().map(|wire| wire[INS_INDEX]).collect();
            assert_eq!(instructions, PRESET_ACTIVATION_INSTRUCTIONS);
            for (index, slot) in [
                (PRESET_PIN1_CHANGE_INDEX, PinSlot::Pin1),
                (PRESET_PIN2_CHANGE_INDEX, PinSlot::Pin2),
            ] {
                let change = &card.commands[index];
                assert_eq!(change[P1_INDEX], CHANGE_P1_CURRENT_THEN_NEW);
                assert_eq!(
                    change[P2_INDEX],
                    PinReferenceScheme::Citizen.reference(slot)
                );
                assert_eq!(
                    &change[DATA_OFFSET..DATA_OFFSET + ACTIVATION_PIN_DIGITS.len()],
                    ACTIVATION_PIN_DIGITS
                );
            }
        }
    }

    /// The card's probes with `slot` answering `probe` and the other PIN
    /// pristine.
    fn preset_card_with(slot: PinSlot, probe: StatusWord) -> PresetCard {
        let pristine = pin_counter(RETRIES_PRISTINE);
        match slot {
            PinSlot::Pin1 => PresetCard::new(probe, pristine),
            PinSlot::Pin2 => PresetCard::new(pristine, probe),
        }
    }

    #[test]
    fn preset_activation_never_presents_the_activation_pin_at_the_last_two_tries() {
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            for count in [RETRIES_BELOW_FLOOR, RETRIES_LOCKDOWN_IMMINENT] {
                let mut card = preset_card_with(slot, pin_counter(count));
                let result = card.activate(Some(pin1(NEW_DIGITS)), Some(pin2(NEW_PIN2_DIGITS)));
                let refused = matches!(
                    result,
                    Err(AuthError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
                        credential,
                        remaining,
                    })) if credential == FlooredCredential::from(slot) && remaining.get() == count
                );
                assert!(refused, "{count} tries left must refuse the activation");
                // A refusal for PIN 2 also holds back PIN 1's change.
                assert!(!card.sent_a_change());
            }
        }
    }

    #[test]
    fn preset_activation_lets_the_card_answer_an_exhausted_or_blocked_pin() {
        // Which code the holder has is inferred, not known: at no tries
        // left or blocked the card decides and spends nothing, so the
        // change goes out rather than closing a recovery here.
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            for probe in [
                pin_counter(RETRIES_EXHAUSTED),
                StatusWord::AuthenticationBlocked,
            ] {
                let mut card = preset_card_with(slot, probe);
                let result = card.activate(Some(pin1(NEW_DIGITS)), Some(pin2(NEW_PIN2_DIGITS)));
                assert!(
                    !matches!(result, Err(AuthError::RetryFloor(_))),
                    "{probe:?} must not be refused by the software"
                );
                assert!(card.sent_a_change());
            }
        }
    }

    #[test]
    fn preset_activation_never_presents_the_activation_pin_to_an_unreadable_counter() {
        // An unreadable counter might hide a last try; nothing is sent.
        for slot in [PinSlot::Pin1, PinSlot::Pin2] {
            let credential = FlooredCredential::from(slot);
            let mut card = preset_card_with(slot, StatusWord::AuthenticationFailed);
            let unreadable = card.activate(Some(pin1(NEW_DIGITS)), Some(pin2(NEW_PIN2_DIGITS)));
            assert!(matches!(
                unreadable,
                Err(AuthError::RetryFloor(
                    RetryFloorRefusal::CounterUnreadable { credential: refused }
                )) if refused == credential
            ));
            assert!(!card.sent_a_change());
        }
    }

    #[test]
    fn preset_activation_of_pin1_alone_is_not_gated_by_pin2() {
        let mut card = preset_card_with(PinSlot::Pin2, pin_counter(RETRIES_LOCKDOWN_IMMINENT));
        let report = card
            .activate(Some(pin1(NEW_DIGITS)), None)
            .expect("PIN 1's counter is served");
        assert_eq!(report.pin1, Some(ManageOutcome::Ok));
        assert_eq!(report.pin2, None);
        let changes: Vec<u8> = card
            .commands
            .iter()
            .filter(|wire| wire[INS_INDEX] == CHANGE_REFERENCE_DATA_INS)
            .map(|wire| wire[P2_INDEX])
            .collect();
        assert_eq!(
            changes,
            [PinReferenceScheme::Citizen.reference(PinSlot::Pin1)]
        );
    }

    #[test]
    fn probe_credential_health_propagates_puk_transport_error() {
        let mut transport = Recorder::new(vec![StatusWord::Success, StatusWord::Success]);
        let err = transport
            .probe_credential_health(None)
            .expect_err("must propagate PUK probe transport error");
        assert!(matches!(err, AuthError::Transport(_)));
    }
}
