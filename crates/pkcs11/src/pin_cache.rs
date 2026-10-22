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
//! custody contract (`docs/security/credential-custody.md`): the value
//! lives only in this process's memory, from the first card-confirmed
//! success until an invalidation event, with no idle window or countdown.
//! It is held only under a pristine retry counter; a login under a counter
//! below pristine bridges to the one operation that follows and no further
//! ([`PIN1_LOGIN_BRIDGE`]).
//!
//! Use is destructive checkout: [`PinSafetyCache::checkout_pin1`] takes
//! the value out under the retry counter the card reports, and
//! [`CheckedOutPin1`] puts it back only when the card accepted it or left
//! its VERIFY unanswered. Every other ending destroys it, dropping the
//! checkout included. PIN2 never enters this cache.

use core::time::Duration;
use std::time::Instant;

use refineid_apdu::TransportOutcome;
use refineid_auth::{
    AuthError, Pin1, PinStatus, UnvalidatedSecret, VerifyOutcome,
    pin1_status_permits_reusable_cache,
};
use refineid_pkcs15::TokenSerial;
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
    pin: PinBytes,
    generation: u64,
    retention: Pin1Retention,
}

/// A positive PIN1 taken out of the cache for one credential operation on
/// the card identified by its serial.
///
/// Dropping it destroys the value; only [`Self::restore_after_success`]
/// and [`Self::settle_verify`] can return it, and only a held value.
pub struct CheckedOutPin1 {
    entry: CachedPin1,
}

impl CheckedOutPin1 {
    /// Borrow the PIN for the single VERIFY associated with this checkout.
    #[must_use]
    pub const fn pin(&self) -> &PinBytes {
        &self.entry.pin
    }

    /// Return a held value after the card confirmed it: it signed under
    /// the PIN1 verification it already held. A bridge value is spent by
    /// its one use and is destroyed instead.
    pub fn restore_after_success(self, cache: &mut PinSafetyCache) {
        self.restore(cache);
    }

    /// Settle this checkout by the card's answer to the VERIFY that
    /// carried it.
    ///
    /// - The card accepted it: a held value is returned, as
    ///   [`Self::restore_after_success`] does.
    /// - The VERIFY went unanswered with the card still in the reader --
    ///   a transport failure, a timeout with the state unknown, a card
    ///   reset, or lost protocol state: a held value is returned, and the
    ///   retry counter read before its next use decides. A held value is
    ///   checked out only under a pristine or verified counter
    ///   ([`PinSafetyCache::checkout_pin1`]), so a refusal the card
    ///   counted destroys it then instead of sending it again.
    /// - The card refused it as wrong: it is remembered as rejected and
    ///   destroyed.
    /// - The card reported the PIN blocked or answered with any other
    ///   status word, the card left the reader, or no command could be
    ///   built: it is destroyed.
    ///
    /// A bridge value is destroyed whatever the answer.
    pub fn settle_verify<E>(
        self,
        cache: &mut PinSafetyCache,
        answer: &Result<VerifyOutcome, AuthError<E>>,
    ) {
        let keep = match answer {
            Ok(VerifyOutcome::Ok) => true,
            Ok(VerifyOutcome::WrongPin { .. }) => {
                cache.record_rejected(&self.entry.serial, &self.entry.pin);
                false
            }
            Ok(VerifyOutcome::Locked | VerifyOutcome::Other(_)) => false,
            Err(error) => verify_unanswered(error),
        };
        if keep {
            self.restore(cache);
        }
    }

    /// Put a held value back, unless the cache was cleared or given a
    /// newer value while it was out.
    fn restore(self, cache: &mut PinSafetyCache) {
        if self.entry.retention != Pin1Retention::Held {
            return;
        }
        if cache.generation != self.entry.generation || cache.positive_pin1.is_some() {
            return;
        }
        cache.positive_pin1 = Some(self.entry);
    }
}

impl core::fmt::Debug for CheckedOutPin1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckedOutPin1")
            .field("serial", &self.entry.serial)
            .finish_non_exhaustive()
    }
}

/// Whether a VERIFY that failed left its command unanswered with the card
/// still in the reader, so the card may or may not have counted it.
const fn verify_unanswered<E>(error: &AuthError<E>) -> bool {
    match error {
        AuthError::Transport(_) => true,
        AuthError::Outcome(outcome) => match outcome {
            TransportOutcome::TimeoutUnknownState
            | TransportOutcome::CardReset
            | TransportOutcome::ProtocolDesync => true,
            TransportOutcome::NoCard
            | TransportOutcome::ReaderRemoved
            | TransportOutcome::Response(_) => false,
        },
        AuthError::Command(_) | AuthError::LengthUnsupported { .. } => false,
    }
}

/// Whether the retry counter the card reports leaves a held PIN1 usable:
/// pristine, or PIN1 standing verified. Any lower count means the card
/// counted a refused PIN since it last confirmed this one.
const fn held_counter_intact(live: PinStatus) -> bool {
    matches!(live, PinStatus::Verified) || pin1_status_permits_reusable_cache(live)
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
            generation: 0,
            negative: refineid_pin_cache::PinSafetyCache::new()?,
        })
    }

    /// Hold a PIN1 the card identified by `serial` has just accepted under
    /// a pristine retry counter. It stays until an invalidation event.
    ///
    /// # Errors
    /// Returns [`PreviouslyRejectedPin`] if this PIN was previously recorded as rejected.
    pub fn store_pin1(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.put_positive(serial, pin, Pin1Retention::Held)
    }

    /// Stage a PIN1 the card identified by `serial` has just accepted under
    /// a retry counter below pristine, for the one checkout that follows
    /// within [`PIN1_LOGIN_BRIDGE`].
    ///
    /// # Errors
    /// Returns [`PreviouslyRejectedPin`] if this PIN was previously recorded as rejected.
    pub fn stage_pin1_once(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.stage_pin1_once_at(serial, pin, Instant::now())
    }

    fn stage_pin1_once_at(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
        staged_at: Instant,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.put_positive(serial, pin, Pin1Retention::Bridge { staged_at })
    }

    fn put_positive(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
        retention: Pin1Retention,
    ) -> Result<(), PreviouslyRejectedPin> {
        if self.is_rejected(&serial, &pin) {
            return Err(PreviouslyRejectedPin);
        }
        self.generation = self.generation.saturating_add(1);
        self.positive_pin1 = Some(CachedPin1 {
            serial,
            pin,
            generation: self.generation,
            retention,
        });
        Ok(())
    }

    /// Check out the positive PIN1 for the card identified by `serial`,
    /// under `live`, the PIN1 retry state that card reported in the same
    /// card transaction.
    ///
    /// The value leaves the cache whatever the outcome. It is destroyed
    /// instead of handed out when it belongs to another card; when it is
    /// held and `live` is neither pristine nor verified, since the counter
    /// then went down after the card last confirmed it; or when it is a
    /// bridge past [`PIN1_LOGIN_BRIDGE`]. A bridge is spent by this
    /// checkout.
    #[must_use]
    pub fn checkout_pin1(
        &mut self,
        serial: &TokenSerial,
        live: PinStatus,
    ) -> Option<CheckedOutPin1> {
        self.checkout_pin1_at(serial, live, Instant::now())
    }

    fn checkout_pin1_at(
        &mut self,
        serial: &TokenSerial,
        live: PinStatus,
        now: Instant,
    ) -> Option<CheckedOutPin1> {
        let entry = self.positive_pin1.take()?;
        if &entry.serial != serial {
            return None;
        }
        let usable = match entry.retention {
            Pin1Retention::Held => held_counter_intact(live),
            Pin1Retention::Bridge { staged_at } => bridge_open(staged_at, now),
        };
        usable.then_some(CheckedOutPin1 { entry })
    }

    /// Destroy any positive PIN1, including one out on a checkout, which
    /// then cannot come back.
    pub fn clear_positive(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.positive_pin1 = None;
    }

    /// Destroy the positive PIN1 if it belongs to `serial`.
    pub fn clear_positive_for_serial(&mut self, serial: &TokenSerial) {
        if let Some(entry) = &self.positive_pin1
            && &entry.serial == serial
        {
            self.clear_positive();
        }
    }

    /// Whether a positive PIN1 is in the cache: a held value, or a bridge
    /// still open. A bridge past its time is destroyed here; a value out on
    /// a checkout is not in the cache and is left alone.
    pub fn has_positive_pin1(&mut self) -> bool {
        self.has_positive_pin1_at(Instant::now())
    }

    fn has_positive_pin1_at(&mut self, now: Instant) -> bool {
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

    /// Record a card-rejected PIN1 value, destroying a positive PIN1 held
    /// for the same card.
    pub fn record_rejected(&mut self, serial: &TokenSerial, pin: &PinBytes) {
        self.clear_positive_for_serial(serial);
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
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::time::Instant;

    use refineid_apdu::{CredentialBodyError, PinRetries, StatusWord, TransportOutcome};
    use refineid_auth::{AuthError, ORGANIZATIONAL_PIN_MAX_LENGTH, PinStatus, VerifyOutcome};
    use refineid_pkcs15::TokenSerial;

    use super::{PIN1_LOGIN_BRIDGE, PinSafetyCache, PreviouslyRejectedPin};
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

    /// Distinct synthetic card serials.
    const CARD_A_SERIAL: &str = "CARD-A-FULL-SERIAL";
    const CARD_B_SERIAL: &str = "CARD-B-FULL-SERIAL";

    /// The adapter-level failure a scripted link reports.
    #[derive(Debug)]
    struct LinkDown;

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
            .store_pin1(serial(CARD_A_SERIAL), pin)
            .expect("a fresh PIN1 is not a rejected one");
        cache
    }

    fn answered(outcome: VerifyOutcome) -> Result<VerifyOutcome, AuthError<LinkDown>> {
        Ok(outcome)
    }

    fn failed(error: AuthError<LinkDown>) -> Result<VerifyOutcome, AuthError<LinkDown>> {
        Err(error)
    }

    fn unanswered_failures() -> [AuthError<LinkDown>; 4] {
        [
            AuthError::Transport(LinkDown),
            AuthError::Outcome(TransportOutcome::TimeoutUnknownState),
            AuthError::Outcome(TransportOutcome::CardReset),
            AuthError::Outcome(TransportOutcome::ProtocolDesync),
        ]
    }

    #[test]
    fn a_held_pin1_has_no_idle_window() {
        let mut cache = holding(random_pin());
        let much_later = Instant::now() + LONG_IDLE;
        assert!(cache.has_positive_pin1_at(much_later));
        let checkout = cache
            .checkout_pin1_at(&serial(CARD_A_SERIAL), pristine(), much_later)
            .expect("a held value has no idle window");
        checkout.restore_after_success(&mut cache);
        assert!(cache.has_positive_pin1_at(much_later + LONG_IDLE));
    }

    #[test]
    fn a_held_pin1_serves_every_operation_the_card_confirms() {
        let mut cache = holding(random_pin());
        for _ in 0..REPEATED_USES {
            let checkout = cache
                .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
                .expect("the held value is checked out");
            checkout.settle_verify(&mut cache, &answered(VerifyOutcome::Ok));
        }
        assert!(cache.has_positive_pin1());
    }

    #[test]
    fn a_verified_card_keeps_the_held_pin1() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), PinStatus::Verified)
            .expect("a verified PIN1 is not a counter that went down");
        checkout.restore_after_success(&mut cache);
        assert!(cache.has_positive_pin1());
    }

    #[test]
    fn another_card_destroys_the_held_pin1() {
        let mut cache = holding(random_pin());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_B_SERIAL), pristine())
                .is_none()
        );
        assert!(!cache.has_positive_pin1());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
                .is_none()
        );
    }

    #[test]
    fn a_counter_below_pristine_destroys_the_held_pin1() {
        let mut cache = holding(random_pin());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), remaining(RETRIES_ONE_SPENT))
                .is_none()
        );
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn an_unavailable_or_blocked_counter_destroys_the_held_pin1() {
        for live in [
            PinStatus::NoInfo,
            PinStatus::Other(StatusWord::SecurityNotSatisfied),
            PinStatus::Locked,
        ] {
            let mut cache = holding(random_pin());
            assert!(cache.checkout_pin1(&serial(CARD_A_SERIAL), live).is_none());
            assert!(!cache.has_positive_pin1());
        }
    }

    #[test]
    fn an_unanswered_verify_returns_the_held_pin1() {
        for failure in unanswered_failures() {
            let mut cache = holding(random_pin());
            let checkout = cache
                .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
                .expect("the held value is checked out");
            checkout.settle_verify(&mut cache, &failed(failure));
            assert!(cache.has_positive_pin1());
        }
    }

    #[test]
    fn a_refusal_counted_after_an_unanswered_verify_destroys_the_held_pin1() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
            .expect("the held value is checked out");
        checkout.settle_verify(&mut cache, &failed(AuthError::Transport(LinkDown)));
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), remaining(RETRIES_ONE_SPENT))
                .is_none()
        );
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn an_uncounted_unanswered_verify_keeps_serving() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
            .expect("the held value is checked out");
        checkout.settle_verify(&mut cache, &failed(AuthError::Transport(LinkDown)));
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
                .is_some()
        );
    }

    #[test]
    fn a_wrong_pin_destroys_the_value_and_remembers_it() {
        let pin = random_pin();
        let mut cache = holding(pin.clone());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
            .expect("the held value is checked out");
        let wrong = VerifyOutcome::WrongPin {
            retries_left: PinRetries::from_nibble(RETRIES_ONE_SPENT)
                .expect("test retry count fits the status-word nibble"),
        };
        checkout.settle_verify(&mut cache, &answered(wrong));
        assert!(!cache.has_positive_pin1());
        assert!(cache.is_rejected(&serial(CARD_A_SERIAL), &pin));
        assert_eq!(
            cache.store_pin1(serial(CARD_A_SERIAL), pin),
            Err(PreviouslyRejectedPin)
        );
    }

    #[test]
    fn a_blocked_or_malformed_answer_destroys_the_held_pin1() {
        let answers = [
            answered(VerifyOutcome::Locked),
            answered(VerifyOutcome::Other(StatusWord::SecurityNotSatisfied)),
            failed(AuthError::Command(CredentialBodyError::Empty)),
            failed(AuthError::LengthUnsupported {
                max: ORGANIZATIONAL_PIN_MAX_LENGTH,
            }),
        ];
        for answer in answers {
            let mut cache = holding(random_pin());
            let checkout = cache
                .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
                .expect("the held value is checked out");
            checkout.settle_verify(&mut cache, &answer);
            assert!(!cache.has_positive_pin1());
        }
    }

    #[test]
    fn a_card_that_left_the_reader_destroys_the_held_pin1() {
        for gone in [TransportOutcome::NoCard, TransportOutcome::ReaderRemoved] {
            let mut cache = holding(random_pin());
            let checkout = cache
                .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
                .expect("the held value is checked out");
            checkout.settle_verify(&mut cache, &failed(AuthError::Outcome(gone)));
            assert!(!cache.has_positive_pin1());
        }
    }

    #[test]
    fn dropping_a_checkout_destroys_the_value() {
        let mut cache = holding(random_pin());
        let checkout = cache.checkout_pin1(&serial(CARD_A_SERIAL), pristine());
        assert!(checkout.is_some());
        drop(checkout);
        assert!(!cache.has_positive_pin1());
        assert!(
            cache
                .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
                .is_none()
        );
    }

    #[test]
    fn clearing_during_a_checkout_keeps_the_value_from_coming_back() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
            .expect("the held value is checked out");
        cache.clear_positive();
        checkout.settle_verify(&mut cache, &answered(VerifyOutcome::Ok));
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn asking_for_login_state_during_a_checkout_does_not_destroy_the_value() {
        let mut cache = holding(random_pin());
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
            .expect("the held value is checked out");
        assert!(!cache.has_positive_pin1());
        checkout.restore_after_success(&mut cache);
        assert!(cache.has_positive_pin1());
    }

    #[test]
    fn the_login_bridge_serves_one_operation() {
        let mut cache = cache();
        cache
            .stage_pin1_once(serial(CARD_A_SERIAL), random_pin())
            .expect("a fresh PIN1 is not a rejected one");
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), remaining(RETRIES_ONE_SPENT))
            .expect("the bridge serves the operation after the login");
        checkout.settle_verify(&mut cache, &answered(VerifyOutcome::Ok));
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn the_login_bridge_is_spent_by_an_unanswered_verify() {
        let mut cache = cache();
        cache
            .stage_pin1_once(serial(CARD_A_SERIAL), random_pin())
            .expect("a fresh PIN1 is not a rejected one");
        let checkout = cache
            .checkout_pin1(&serial(CARD_A_SERIAL), pristine())
            .expect("the bridge serves the operation after the login");
        checkout.settle_verify(&mut cache, &failed(AuthError::Transport(LinkDown)));
        assert!(!cache.has_positive_pin1());
    }

    #[test]
    fn the_login_bridge_closes_when_its_time_runs_out() {
        let staged_at = Instant::now();
        let mut cache = cache();
        cache
            .stage_pin1_once_at(serial(CARD_A_SERIAL), random_pin(), staged_at)
            .expect("a fresh PIN1 is not a rejected one");
        assert!(cache.has_positive_pin1_at(staged_at));
        assert!(!cache.has_positive_pin1_at(staged_at + PIN1_LOGIN_BRIDGE));
        assert!(
            cache
                .checkout_pin1_at(&serial(CARD_A_SERIAL), pristine(), staged_at)
                .is_none()
        );
    }

    #[test]
    fn a_checkout_past_the_login_bridge_finds_nothing() {
        let staged_at = Instant::now();
        let mut cache = cache();
        cache
            .stage_pin1_once_at(serial(CARD_A_SERIAL), random_pin(), staged_at)
            .expect("a fresh PIN1 is not a rejected one");
        assert!(
            cache
                .checkout_pin1_at(
                    &serial(CARD_A_SERIAL),
                    pristine(),
                    staged_at + PIN1_LOGIN_BRIDGE
                )
                .is_none()
        );
        assert!(!cache.has_positive_pin1_at(staged_at));
    }
}
