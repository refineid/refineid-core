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

//! Held PIN1 and negative PIN retry protection for PKCS#11.
//!
//! [`PinSafetyCache`] keeps, per slot, the PIN1 the card accepted through
//! `C_Login`, so that each later signature re-presents it to the card
//! without asking again. This is the PIN1 exception of the credential
//! custody contract (`doc/security/credential-custody.md`): the value
//! lives only in this process's memory, from the first card-confirmed
//! success until an invalidation event, with no idle window or countdown.
//! It is held only under a pristine retry counter, or PIN1 standing
//! verified, which proves one; a login under any other counter bridges to
//! the one operation that follows and no further ([`PIN1_LOGIN_BRIDGE`]).
//!
//! The value is bound to one stay of one card in its reader: the token
//! serial the card reported and the reader's card insertion and removal
//! count ([`refineid_pcsc::ReaderInfo::card_events`]), both read in the
//! card session that accepted it. A checkout that reads another serial
//! or another count destroys it, as removal does.
//!
//! Use is destructive checkout. [`PinSafetyCache::checkout_pin1`] takes
//! the value out under the retry counter the card reports;
//! [`CheckedOutPin1::settle_verify`] settles it by the card's answer to
//! the VERIFY that carried it, and an accepted value is settled again by
//! what became of the card in the operation it authorized
//! ([`AcceptedPin1::settle_operation`]). Only a held value the card
//! accepted, or a VERIFY the card left unanswered, puts it back. Every
//! other ending destroys it, dropping the checkout included. PIN2 never
//! enters this cache.

use core::time::Duration;
use std::sync::{Arc, Weak};
use std::time::Instant;

use refineid_apdu::{TransportErrorExt, TransportErrorKind, TransportOutcome};
use refineid_auth::{
    AuthError, Pin1, PinStatus, UnvalidatedSecret, VerifyOutcome,
    pin1_status_permits_reusable_cache,
};
use refineid_pkcs15::TokenSerial;
use refineid_sign::SignError;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::pin::PinBytes;

/// How long a PIN1 that `C_Login` staged under a retry counter below
/// pristine stays available to the one operation that follows.
///
/// PKCS#11 takes the PIN in `C_Login` and the operation in a later
/// `C_Sign`. A counter below pristine forbids holding the PIN, so such a
/// login only bridges that gap: the staged value serves one checkout and
/// is spent by it, or is destroyed when this bridge runs out, whichever
/// comes first.
pub const PIN1_LOGIN_BRIDGE: Duration = Duration::from_secs(30);

/// How a positive PIN1 entry is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pin1Retention {
    /// Held until an invalidation event, and returned after each use the
    /// card accepted or left unanswered.
    Held,
    /// The one-use bridge of [`PIN1_LOGIN_BRIDGE`], staged at `staged_at`.
    Bridge {
        /// When `C_Login` staged the value.
        staged_at: Instant,
    },
}

struct CachedPin1 {
    serial: TokenSerial,
    /// The reader's card insertion and removal count when the card
    /// accepted the value.
    card_events: u32,
    pin: PinBytes,
    generation: u64,
    retention: Pin1Retention,
}

/// A positive PIN1 taken out of the cache for one VERIFY on the card
/// identified by its serial.
///
/// Dropping it destroys the value; only [`Self::settle_verify`] can lead
/// it back, and only a held value.
pub struct CheckedOutPin1 {
    entry: CachedPin1,
    /// Marks the checkout outstanding to [`PinSafetyCache::holds_pin1`].
    _lease: Arc<()>,
}

/// A checked-out PIN1 the card has just accepted, out for the one
/// operation it authorizes.
///
/// Dropping it destroys the value; only [`Self::settle_operation`] can
/// return it, and only a held value.
pub struct AcceptedPin1 {
    entry: CachedPin1,
    /// Marks the checkout outstanding to [`PinSafetyCache::holds_pin1`].
    _lease: Arc<()>,
}

/// What a failed card exchange says about the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExchangeFailure {
    /// The card left the reader, or the reader went away.
    CardLeft,
    /// No answer arrived with the card still in the reader: a transport
    /// fault, a timeout with the card state unknown, a card reset, or
    /// lost protocol state. The card may or may not have acted.
    Unanswered,
}

impl ExchangeFailure {
    const fn of(kind: TransportErrorKind) -> Self {
        match kind {
            TransportErrorKind::NoCard | TransportErrorKind::ReaderRemoved => Self::CardLeft,
            TransportErrorKind::TimeoutUnknownState
            | TransportErrorKind::CardReset
            | TransportErrorKind::ProtocolDesync
            | TransportErrorKind::Backend => Self::Unanswered,
        }
    }

    /// The failure a transport state transition stands for; `None` for a
    /// response, which is an answer.
    fn of_outcome(outcome: &TransportOutcome) -> Option<Self> {
        outcome.kind().map(Self::of)
    }
}

impl CheckedOutPin1 {
    /// Borrow the PIN for the single VERIFY associated with this checkout.
    #[must_use]
    pub const fn pin(&self) -> &PinBytes {
        &self.entry.pin
    }

    /// Settle this checkout by the card's answer to the VERIFY that
    /// carried it.
    ///
    /// - The card accepted it: the value goes on to the operation it
    ///   authorizes, as the returned [`AcceptedPin1`].
    /// - The VERIFY went unanswered with the card still in the reader: a
    ///   held value is returned to the cache, and the retry counter read
    ///   before its next use decides. A value is checked out only under a
    ///   pristine or verified counter ([`PinSafetyCache::checkout_pin1`]),
    ///   so a refusal the card counted destroys it then instead of
    ///   sending it again.
    /// - The card refused it as wrong: it is remembered as rejected and
    ///   destroyed.
    /// - The card reported the PIN blocked or answered with any other
    ///   status word, the card left the reader, or no command could be
    ///   built: it is destroyed.
    ///
    /// A bridge value is never returned to the cache.
    #[must_use]
    pub fn settle_verify<E: TransportErrorExt>(
        self,
        cache: &mut PinSafetyCache,
        answer: &Result<VerifyOutcome, AuthError<E>>,
    ) -> Option<AcceptedPin1> {
        let failure = match answer {
            Ok(VerifyOutcome::Ok) => {
                return Some(AcceptedPin1 {
                    entry: self.entry,
                    _lease: self._lease,
                });
            }
            Ok(VerifyOutcome::WrongPin { .. }) => {
                cache.record_rejected(&self.entry.serial, &self.entry.pin);
                return None;
            }
            Ok(VerifyOutcome::Locked | VerifyOutcome::Other(_))
            | Err(
                AuthError::Command(_)
                | AuthError::LengthUnsupported { .. }
                | AuthError::RetryFloor(_),
            ) => return None,
            Err(AuthError::Transport(error)) => Some(ExchangeFailure::of(error.kind())),
            Err(AuthError::Outcome(outcome)) => ExchangeFailure::of_outcome(outcome),
        };
        if failure == Some(ExchangeFailure::Unanswered) {
            cache.restore(self.entry);
        }
        None
    }
}

impl AcceptedPin1 {
    /// Settle a value the card accepted by what became of the card in the
    /// operation it authorized: `failure` is that operation's error, or
    /// `None` when it completed.
    ///
    /// A held value is returned to the cache unless the card left the
    /// reader during the operation. A card that refused the operation,
    /// or left it unanswered, did not refuse the PIN it had just
    /// accepted. A bridge value is spent either way.
    pub fn settle_operation<E: TransportErrorExt>(
        self,
        cache: &mut PinSafetyCache,
        failure: Option<&SignError<E>>,
    ) {
        let left = match failure {
            None
            | Some(
                SignError::Status(..)
                | SignError::Command(_)
                | SignError::UnexpectedSignatureLength { .. },
            ) => false,
            Some(SignError::Transport(error)) => {
                ExchangeFailure::of(error.kind()) == ExchangeFailure::CardLeft
            }
            Some(SignError::Outcome(outcome)) => {
                ExchangeFailure::of_outcome(outcome) == Some(ExchangeFailure::CardLeft)
            }
        };
        if !left {
            cache.restore(self.entry);
        }
    }
}

impl core::fmt::Debug for CheckedOutPin1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckedOutPin1")
            .field("serial", &self.entry.serial)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for AcceptedPin1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AcceptedPin1")
            .field("serial", &self.entry.serial)
            .finish_non_exhaustive()
    }
}

/// Whether a bridge staged at `staged_at` is still open at `now`.
fn bridge_open(staged_at: Instant, now: Instant) -> bool {
    now.checked_duration_since(staged_at)
        .is_some_and(|age| age < PIN1_LOGIN_BRIDGE)
}

/// Rejection error when caching a PIN that was previously rejected by the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviouslyRejectedPin;

impl core::fmt::Display for PreviouslyRejectedPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PIN value was previously rejected by this token")
    }
}

impl core::error::Error for PreviouslyRejectedPin {}

/// Held PIN1 for one slot plus the process-lifetime negative PIN cache.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinSafetyCache {
    #[zeroize(skip)]
    positive_pin1: Option<CachedPin1>,
    /// The checkout of the current generation, while one is out.
    #[zeroize(skip)]
    outstanding: Weak<()>,
    generation: u64,
    #[zeroize(skip)]
    negative: refineid_pin_cache::PinSafetyCache,
}

impl PinSafetyCache {
    /// Construct a fresh cache.
    ///
    /// # Errors
    /// Returns OS random-source error if fingerprint key generation fails.
    pub fn new() -> Result<Self, getrandom::Error> {
        Ok(Self {
            positive_pin1: None,
            outstanding: Weak::new(),
            generation: 0,
            negative: refineid_pin_cache::PinSafetyCache::new()?,
        })
    }

    /// Hold a PIN1 the card identified by `serial` has just accepted under
    /// a pristine retry counter, while its reader's card insertion and
    /// removal count read in the same card session stood at
    /// `card_events`. It stays until an invalidation event, and a
    /// checkout still out from before can no longer come back.
    ///
    /// # Errors
    /// Returns [`PreviouslyRejectedPin`] if this PIN was previously recorded as rejected.
    pub fn store_pin1(
        &mut self,
        serial: TokenSerial,
        card_events: u32,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.put_positive(serial, card_events, pin, Pin1Retention::Held)
    }

    /// Stage a PIN1 the card identified by `serial` has just accepted under
    /// a retry counter below pristine, with its reader's count at
    /// `card_events` as for [`Self::store_pin1`], for the one checkout
    /// that follows within [`PIN1_LOGIN_BRIDGE`].
    ///
    /// # Errors
    /// Returns [`PreviouslyRejectedPin`] if this PIN was previously recorded as rejected.
    pub fn stage_pin1_once(
        &mut self,
        serial: TokenSerial,
        card_events: u32,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.stage_pin1_once_at(serial, card_events, pin, Instant::now())
    }

    fn stage_pin1_once_at(
        &mut self,
        serial: TokenSerial,
        card_events: u32,
        pin: PinBytes,
        staged_at: Instant,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.put_positive(
            serial,
            card_events,
            pin,
            Pin1Retention::Bridge { staged_at },
        )
    }

    fn put_positive(
        &mut self,
        serial: TokenSerial,
        card_events: u32,
        pin: PinBytes,
        retention: Pin1Retention,
    ) -> Result<(), PreviouslyRejectedPin> {
        if self.is_rejected(&serial, &pin) {
            return Err(PreviouslyRejectedPin);
        }
        self.next_generation();
        self.positive_pin1 = Some(CachedPin1 {
            serial,
            card_events,
            pin,
            generation: self.generation,
            retention,
        });
        Ok(())
    }

    /// Start a new generation: a checkout still out can no longer come
    /// back.
    fn next_generation(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.outstanding = Weak::new();
    }

    /// Check out the positive PIN1 for the card identified by `serial`,
    /// whose reader's card insertion and removal count now stands at
    /// `card_events`, under `live`, the PIN1 retry state that card
    /// reported; all three read in the same card session.
    ///
    /// The value leaves the cache whatever the outcome. It is destroyed
    /// instead of handed out when it belongs to another card; when the
    /// count moved since the card accepted it, since a card then left
    /// the reader; when `live` is neither pristine nor verified, since
    /// the counter then went down after the card accepted it; or when it
    /// is a bridge past [`PIN1_LOGIN_BRIDGE`]. A bridge is spent by this
    /// checkout.
    #[must_use]
    pub fn checkout_pin1(
        &mut self,
        serial: &TokenSerial,
        card_events: u32,
        live: PinStatus,
    ) -> Option<CheckedOutPin1> {
        self.checkout_pin1_at(serial, card_events, live, Instant::now())
    }

    fn checkout_pin1_at(
        &mut self,
        serial: &TokenSerial,
        card_events: u32,
        live: PinStatus,
        now: Instant,
    ) -> Option<CheckedOutPin1> {
        let entry = self.positive_pin1.take()?;
        let usable = &entry.serial == serial
            && entry.card_events == card_events
            && pin1_status_permits_reusable_cache(live)
            && match entry.retention {
                Pin1Retention::Held => true,
                Pin1Retention::Bridge { staged_at } => bridge_open(staged_at, now),
            };
        if !usable {
            return None;
        }
        let lease = Arc::new(());
        self.outstanding = Arc::downgrade(&lease);
        Some(CheckedOutPin1 {
            entry,
            _lease: lease,
        })
    }

    /// Put a held value back, unless the cache was cleared or given a
    /// newer value while it was out.
    fn restore(&mut self, entry: CachedPin1) {
        if entry.retention != Pin1Retention::Held
            || self.generation != entry.generation
            || self.positive_pin1.is_some()
        {
            return;
        }
        self.positive_pin1 = Some(entry);
    }

    /// Destroy any positive PIN1, including one out on a checkout, which
    /// then cannot come back.
    pub fn clear_positive(&mut self) {
        self.next_generation();
        self.positive_pin1 = None;
    }

    /// Whether this cache holds a PIN1 for the slot's login: a held value,
    /// a bridge still open, or a value out on a checkout that can still
    /// come back. A bridge past its time is destroyed here.
    pub fn holds_pin1(&mut self) -> bool {
        self.holds_pin1_at(Instant::now())
    }

    fn holds_pin1_at(&mut self, now: Instant) -> bool {
        if self.outstanding.strong_count() > 0 {
            return true;
        }
        let Some(entry) = &self.positive_pin1 else {
            return false;
        };
        let present = match entry.retention {
            Pin1Retention::Held => true,
            Pin1Retention::Bridge { staged_at } => bridge_open(staged_at, now),
        };
        if !present {
            self.clear_positive();
        }
        present
    }

    /// Whether `pin` was previously rejected by the card identified by `serial`.
    #[must_use]
    pub fn is_rejected(&self, serial: &TokenSerial, pin: &PinBytes) -> bool {
        let secret = UnvalidatedSecret::from_owned_bytes(pin.as_bytes().to_vec());
        if let Ok(pin1) = Pin1::reconstruct(secret) {
            self.negative.is_rejected(serial, &pin1)
        } else {
            false
        }
    }

    /// Record a PIN1 value the card identified by `serial` rejected, and
    /// destroy the slot's positive PIN1, held, staged or out on a
    /// checkout: the rejection either lowered that card's retry counter
    /// or shows another card in the reader.
    pub fn record_rejected(&mut self, serial: &TokenSerial, pin: &PinBytes) {
        self.clear_positive();
        let secret = UnvalidatedSecret::from_owned_bytes(pin.as_bytes().to_vec());
        if let Ok(pin1) = Pin1::reconstruct(secret) {
            self.negative.record_rejected(serial, &pin1);
        }
    }
}

impl core::fmt::Debug for PinSafetyCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinSafetyCache")
            .field("has_positive_pin1", &self.positive_pin1.is_some())
            .field("negative", &self.negative)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::time::Instant;

    use refineid_apdu::{
        CredentialBodyError, PinRetries, StatusWord, TransportErrorExt, TransportErrorKind,
        TransportOutcome,
    };
    use refineid_auth::{AuthError, ORGANIZATIONAL_PIN_MAX_LENGTH, PinStatus, VerifyOutcome};
    use refineid_pkcs15::TokenSerial;
    use refineid_sign::SignError;

    use super::{AcceptedPin1, PIN1_LOGIN_BRIDGE, PinSafetyCache, PreviouslyRejectedPin};
    use crate::pin::PinBytes;

    /// Retry count of a pristine FINEID PIN.
    const RETRIES_PRISTINE: u8 = 5;
    /// Retry count after one refused presentation.
    const RETRIES_ONE_SPENT: u8 = 4;
    const DECIMAL_DIGIT_RADIX: u8 = 10;
    /// A week without use; a held value has no idle window and outlives it.
    const LONG_IDLE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
    /// Uses of one held value in a row.
    const REPEATED_USES: usize = 3;
    /// The signing stage a scripted card refuses.
    const REFUSED_STAGE: &str = "PSO:CDS";

    /// Distinct synthetic card serials.
    const CARD_A_SERIAL: &str = "CARD-A-FULL-SERIAL";
    const CARD_B_SERIAL: &str = "CARD-B-FULL-SERIAL";
    /// The reader's card insertion and removal count while the card
    /// stays in it.
    const READER_EVENTS: u32 = 4;
    /// The count after the card left the reader and came back.
    const READER_EVENTS_AFTER_RETURN: u32 = READER_EVENTS + 2;

    /// The adapter-level failure a scripted link reports, of the kind it
    /// names.
    #[derive(Debug)]
    struct ScriptedFault(TransportErrorKind);

    impl TransportErrorExt for ScriptedFault {
        fn kind(&self) -> TransportErrorKind {
            self.0
        }
    }

    type VerifyAnswer = Result<VerifyOutcome, AuthError<ScriptedFault>>;

    fn cache() -> PinSafetyCache {
        PinSafetyCache::new().expect("operating system random source is available")
    }

    fn serial(text: &str) -> TokenSerial {
        TokenSerial::new(text.to_owned())
    }

    fn random_pin() -> PinBytes {
        let mut digits = vec![0_u8; PinBytes::MAX_LENGTH];
        getrandom::fill(&mut digits).expect("operating system random source is available");
        for digit in &mut digits {
            *digit = b'0' + (*digit % DECIMAL_DIGIT_RADIX);
        }
        PinBytes::new(digits).expect("random digits satisfy the PIN policy")
    }

    fn remaining(count: u8) -> PinStatus {
        PinStatus::Remaining(
            PinRetries::from_nibble(count).expect("test retry count fits the status-word nibble"),
        )
    }

    fn pristine() -> PinStatus {
        remaining(RETRIES_PRISTINE)
    }

    fn holding(pin: PinBytes) -> PinSafetyCache {
        let mut cache = cache();
        cache
            .store_pin1(serial(CARD_A_SERIAL), READER_EVENTS, pin)
            .expect("a fresh PIN1 is not a rejected one");
        cache
    }

    fn staging(staged_at: Instant) -> PinSafetyCache {
        let mut cache = cache();
        cache
            .stage_pin1_once_at(
                serial(CARD_A_SERIAL),
                READER_EVENTS,
                random_pin(),
                staged_at,
            )
            .expect("a fresh PIN1 is not a rejected one");
        cache
    }

    fn accepted() -> VerifyAnswer {
        Ok(VerifyOutcome::Ok)
    }

    fn fault(kind: TransportErrorKind) -> ScriptedFault {
        ScriptedFault(kind)
    }

    fn unanswered_verifies() -> [VerifyAnswer; 5] {
        [
            Err(AuthError::Transport(fault(TransportErrorKind::Backend))),
            Err(AuthError::Transport(fault(
                TransportErrorKind::TimeoutUnknownState,
            ))),
            Err(AuthError::Outcome(TransportOutcome::TimeoutUnknownState)),
            Err(AuthError::Outcome(TransportOutcome::CardReset)),
            Err(AuthError::Outcome(TransportOutcome::ProtocolDesync)),
        ]
    }

    fn card_left_verifies() -> [VerifyAnswer; 4] {
        [
            Err(AuthError::Outcome(TransportOutcome::NoCard)),
            Err(AuthError::Outcome(TransportOutcome::ReaderRemoved)),
            Err(AuthError::Transport(fault(TransportErrorKind::NoCard))),
            Err(AuthError::Transport(fault(
                TransportErrorKind::ReaderRemoved,
            ))),
        ]
    }

    /// Check the held value out and have the card accept it.
    fn accepted_held(cache: &mut PinSafetyCache) -> AcceptedPin1 {
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the held value is checked out");
        checkout
            .settle_verify(cache, &accepted())
            .expect("an accepted VERIFY leads to the operation")
    }

    fn completed(accepted: AcceptedPin1, cache: &mut PinSafetyCache) {
        accepted.settle_operation::<ScriptedFault>(cache, None);
    }

    #[test]
    fn a_held_pin1_has_no_idle_window() {
        let mut cache = holding(random_pin());
        let much_later = Instant::now() + LONG_IDLE;
        assert!(cache.holds_pin1_at(much_later));
        let checkout = cache
            .checkout_pin1_at(
                &serial(CARD_A_SERIAL),
                READER_EVENTS,
                pristine(),
                much_later,
            )
            .expect("a held value has no idle window");
        let accepted = checkout
            .settle_verify(&mut cache, &accepted())
            .expect("an accepted VERIFY leads to the operation");
        completed(accepted, &mut cache);
        assert!(cache.holds_pin1_at(much_later + LONG_IDLE));
    }

    #[test]
    fn a_held_pin1_serves_every_operation_the_card_confirms() {
        let mut cache = holding(random_pin());
        for _ in 0..REPEATED_USES {
            let accepted = accepted_held(&mut cache);
            completed(accepted, &mut cache);
        }
        assert!(cache.holds_pin1());
    }

    #[test]
    fn a_verified_card_keeps_the_held_pin1() {
        let mut cache = holding(random_pin());
        let checkout =
            cache.checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, PinStatus::Verified);
        assert!(
            checkout.is_some(),
            "a verified PIN1 is a counter at its limit"
        );
    }

    #[test]
    fn another_card_destroys_the_held_pin1() {
        let mut cache = holding(random_pin());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_B_SERIAL), READER_EVENTS, pristine())
                .is_none()
        );
        assert!(!cache.holds_pin1());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
                .is_none()
        );
    }

    /// The card left the reader and came back between two operations,
    /// with no slot refresh in between: the second operation reads a
    /// moved count and the held value is destroyed, as on removal.
    #[test]
    fn a_card_that_left_between_two_operations_takes_the_held_pin1() {
        let mut cache = holding(random_pin());
        let accepted = accepted_held(&mut cache);
        completed(accepted, &mut cache);
        assert!(cache.holds_pin1());
        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_A_SERIAL),
                    READER_EVENTS_AFTER_RETURN,
                    pristine()
                )
                .is_none()
        );
        assert!(!cache.holds_pin1());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
                .is_none(),
            "the moved count destroyed the value for its old stay too"
        );
    }

    #[test]
    fn a_card_that_stayed_keeps_the_held_pin1_across_operations() {
        let mut cache = holding(random_pin());
        for _ in 0..REPEATED_USES {
            let checkout = cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
                .expect("an unmoved count keeps the value checked out");
            let accepted = checkout
                .settle_verify(&mut cache, &accepted())
                .expect("an accepted VERIFY leads to the operation");
            completed(accepted, &mut cache);
        }
        assert!(cache.holds_pin1());
    }

    #[test]
    fn a_card_that_left_after_an_unanswered_verify_takes_the_held_pin1() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the held value is checked out");
        let unanswered: VerifyAnswer =
            Err(AuthError::Transport(fault(TransportErrorKind::Backend)));
        assert!(checkout.settle_verify(&mut cache, &unanswered).is_none());
        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_A_SERIAL),
                    READER_EVENTS_AFTER_RETURN,
                    pristine()
                )
                .is_none()
        );
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn a_counter_below_pristine_destroys_the_held_pin1() {
        let mut cache = holding(random_pin());
        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_A_SERIAL),
                    READER_EVENTS,
                    remaining(RETRIES_ONE_SPENT)
                )
                .is_none()
        );
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn an_unavailable_or_blocked_counter_destroys_the_held_pin1() {
        for live in [
            PinStatus::NoInfo,
            PinStatus::Other(StatusWord::SecurityNotSatisfied),
            PinStatus::Locked,
        ] {
            let mut cache = holding(random_pin());
            assert!(
                cache
                    .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, live)
                    .is_none()
            );
            assert!(!cache.holds_pin1());
        }
    }

    #[test]
    fn an_unanswered_verify_returns_the_held_pin1() {
        for answer in unanswered_verifies() {
            let mut cache = holding(random_pin());
            let checkout = cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
                .expect("the held value is checked out");
            assert!(checkout.settle_verify(&mut cache, &answer).is_none());
            assert!(cache.holds_pin1());
        }
    }

    #[test]
    fn a_verify_the_card_left_destroys_the_held_pin1() {
        for answer in card_left_verifies() {
            let mut cache = holding(random_pin());
            let checkout = cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
                .expect("the held value is checked out");
            assert!(checkout.settle_verify(&mut cache, &answer).is_none());
            assert!(!cache.holds_pin1());
        }
    }

    #[test]
    fn a_refusal_counted_after_an_unanswered_verify_destroys_the_held_pin1() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the held value is checked out");
        let unanswered: VerifyAnswer =
            Err(AuthError::Transport(fault(TransportErrorKind::Backend)));
        assert!(checkout.settle_verify(&mut cache, &unanswered).is_none());
        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_A_SERIAL),
                    READER_EVENTS,
                    remaining(RETRIES_ONE_SPENT)
                )
                .is_none()
        );
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn an_uncounted_unanswered_verify_keeps_serving() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the held value is checked out");
        let unanswered: VerifyAnswer =
            Err(AuthError::Transport(fault(TransportErrorKind::Backend)));
        assert!(checkout.settle_verify(&mut cache, &unanswered).is_none());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
                .is_some()
        );
    }

    #[test]
    fn a_wrong_pin_destroys_the_value_and_remembers_it() {
        let pin = random_pin();
        let mut cache = holding(pin.clone());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the held value is checked out");
        let wrong: VerifyAnswer = Ok(VerifyOutcome::WrongPin {
            retries_left: PinRetries::from_nibble(RETRIES_ONE_SPENT)
                .expect("test retry count fits the status-word nibble"),
        });
        assert!(checkout.settle_verify(&mut cache, &wrong).is_none());
        assert!(!cache.holds_pin1());
        assert!(cache.is_rejected(&serial(CARD_A_SERIAL), &pin));
        assert_eq!(
            cache.store_pin1(serial(CARD_A_SERIAL), READER_EVENTS, pin),
            Err(PreviouslyRejectedPin)
        );
    }

    #[test]
    fn a_blocked_or_malformed_answer_destroys_the_held_pin1() {
        let answers: [VerifyAnswer; 4] = [
            Ok(VerifyOutcome::Locked),
            Ok(VerifyOutcome::Other(StatusWord::SecurityNotSatisfied)),
            Err(AuthError::Command(CredentialBodyError::Empty)),
            Err(AuthError::LengthUnsupported {
                max: ORGANIZATIONAL_PIN_MAX_LENGTH,
            }),
        ];
        for answer in answers {
            let mut cache = holding(random_pin());
            let checkout = cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
                .expect("the held value is checked out");
            assert!(checkout.settle_verify(&mut cache, &answer).is_none());
            assert!(!cache.holds_pin1());
        }
    }

    #[test]
    fn an_operation_the_card_left_destroys_the_accepted_pin1() {
        let failures: [SignError<ScriptedFault>; 4] = [
            SignError::Outcome(TransportOutcome::NoCard),
            SignError::Outcome(TransportOutcome::ReaderRemoved),
            SignError::Transport(fault(TransportErrorKind::NoCard)),
            SignError::Transport(fault(TransportErrorKind::ReaderRemoved)),
        ];
        for failure in failures {
            let mut cache = holding(random_pin());
            let accepted = accepted_held(&mut cache);
            accepted.settle_operation(&mut cache, Some(&failure));
            assert!(!cache.holds_pin1());
        }
    }

    #[test]
    fn an_operation_that_failed_with_the_card_present_keeps_the_accepted_pin1() {
        let failures: [SignError<ScriptedFault>; 4] = [
            SignError::Status(REFUSED_STAGE, StatusWord::SecurityNotSatisfied),
            SignError::Outcome(TransportOutcome::CardReset),
            SignError::Outcome(TransportOutcome::TimeoutUnknownState),
            SignError::Transport(fault(TransportErrorKind::Backend)),
        ];
        for failure in failures {
            let mut cache = holding(random_pin());
            let accepted = accepted_held(&mut cache);
            accepted.settle_operation(&mut cache, Some(&failure));
            assert!(cache.holds_pin1());
        }
    }

    #[test]
    fn dropping_a_checkout_destroys_the_value() {
        let mut cache = holding(random_pin());
        let checkout = cache.checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine());
        assert!(checkout.is_some());
        drop(checkout);
        assert!(!cache.holds_pin1());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
                .is_none()
        );
    }

    #[test]
    fn dropping_an_accepted_value_destroys_it() {
        let mut cache = holding(random_pin());
        let accepted = accepted_held(&mut cache);
        drop(accepted);
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn clearing_during_a_checkout_keeps_the_value_from_coming_back() {
        let mut cache = holding(random_pin());
        let accepted = accepted_held(&mut cache);
        cache.clear_positive();
        assert!(!cache.holds_pin1());
        completed(accepted, &mut cache);
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn a_rejection_on_another_card_destroys_the_held_pin1() {
        let mut cache = holding(random_pin());
        cache.record_rejected(&serial(CARD_B_SERIAL), &random_pin());
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn a_rejection_during_a_checkout_keeps_the_value_from_coming_back() {
        let mut cache = holding(random_pin());
        let accepted = accepted_held(&mut cache);
        cache.record_rejected(&serial(CARD_B_SERIAL), &random_pin());
        completed(accepted, &mut cache);
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn a_stale_checkout_does_not_replace_a_newer_login() {
        let newer = random_pin();
        let mut cache = holding(random_pin());
        let stale = accepted_held(&mut cache);
        cache
            .store_pin1(serial(CARD_A_SERIAL), READER_EVENTS, newer.clone())
            .expect("a fresh PIN1 is not a rejected one");
        completed(stale, &mut cache);
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the newer value is held");
        assert_eq!(checkout.pin().as_bytes(), newer.as_bytes());
    }

    #[test]
    fn a_checkout_counts_as_the_login_until_it_settles() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the held value is checked out");
        assert!(cache.holds_pin1());
        let accepted = checkout
            .settle_verify(&mut cache, &accepted())
            .expect("an accepted VERIFY leads to the operation");
        assert!(cache.holds_pin1());
        completed(accepted, &mut cache);
        assert!(cache.holds_pin1());
    }

    #[test]
    fn the_login_bridge_serves_one_operation() {
        let mut cache = staging(Instant::now());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the bridge serves the operation after the login");
        let accepted = checkout
            .settle_verify(&mut cache, &accepted())
            .expect("an accepted VERIFY leads to the operation");
        completed(accepted, &mut cache);
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn the_login_bridge_is_spent_by_an_unanswered_verify() {
        let mut cache = staging(Instant::now());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, pristine())
            .expect("the bridge serves the operation after the login");
        let unanswered: VerifyAnswer =
            Err(AuthError::Transport(fault(TransportErrorKind::Backend)));
        assert!(checkout.settle_verify(&mut cache, &unanswered).is_none());
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn the_login_bridge_needs_an_intact_counter() {
        for live in [remaining(RETRIES_ONE_SPENT), PinStatus::Locked] {
            let mut cache = staging(Instant::now());
            assert!(
                cache
                    .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, live)
                    .is_none()
            );
            assert!(!cache.holds_pin1());
        }
        let mut cache = staging(Instant::now());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), READER_EVENTS, PinStatus::Verified)
                .is_some()
        );
    }

    #[test]
    fn the_login_bridge_is_bound_to_the_card_stay() {
        let mut cache = staging(Instant::now());
        assert!(
            cache
                .checkout_pin1(
                    &serial(CARD_A_SERIAL),
                    READER_EVENTS_AFTER_RETURN,
                    pristine()
                )
                .is_none()
        );
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn a_checkout_past_the_login_bridge_destroys_it() {
        let staged_at = Instant::now();
        let mut cache = staging(staged_at);
        assert!(
            cache
                .checkout_pin1_at(
                    &serial(CARD_A_SERIAL),
                    READER_EVENTS,
                    pristine(),
                    staged_at + PIN1_LOGIN_BRIDGE
                )
                .is_none()
        );
        assert!(
            cache
                .checkout_pin1_at(&serial(CARD_A_SERIAL), READER_EVENTS, pristine(), staged_at)
                .is_none(),
            "the expired checkout removed the bridge"
        );
    }

    #[test]
    fn the_login_bridge_leaves_the_login_when_its_time_runs_out() {
        let staged_at = Instant::now();
        let mut cache = staging(staged_at);
        assert!(cache.holds_pin1_at(staged_at));
        assert!(!cache.holds_pin1_at(staged_at + PIN1_LOGIN_BRIDGE));
        assert!(!cache.holds_pin1_at(staged_at));
    }

    #[test]
    fn a_rejected_pin_destroys_a_staged_bridge() {
        let mut cache = staging(Instant::now());
        cache.record_rejected(&serial(CARD_A_SERIAL), &random_pin());
        assert!(!cache.holds_pin1());
    }
}
