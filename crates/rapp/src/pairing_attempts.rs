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

//! The pairing ceremony's attempt accounting, post-PAKE deadlines,
//! pre-authentication rate limit and post-lockout backoff (RAPP v26.10.10
//! §3.3).

/// Attempts one offer admits.
pub const MAXIMUM_CPACE_ATTEMPTS: u8 = 3;

/// Non-extendable window from admission to a verified `T_A`.
pub const CPACE_ATTEMPT_WINDOW_MS: u64 = 5_000;

/// From local CPace handoff to a completed `Noise_XXpsk3` handshake
/// (§3.3.7).
pub const POST_PAKE_HANDSHAKE_MS: u64 = 10_000;

/// From local Noise completion to stored trust: hello, confirmation and
/// storage (§3.3.7).
pub const POST_PAKE_CONFIRMATION_MS: u64 = 10_000;

/// Minimum spacing of pre-authentication attempts at the custodian
/// (§3.3.8).
pub const PRE_AUTHENTICATION_SPACING_MS: u64 = 500;

/// The monotonic deadline `window` milliseconds after `start_ms`.
#[must_use]
pub const fn phase_deadline_ms(start_ms: u64, window_ms: u64) -> u64 {
    start_ms.saturating_add(window_ms)
}

/// The §3.3.8 limit of one pre-authentication attempt per 500 ms.
///
/// The custodian pairing bridge applies it to every CPace start, which
/// covers repeated invalid `Y_A` submissions; the platform applies its own
/// instance to accepted pre-authentication connections before reading the
/// routing preamble. Times are the platform's monotonic milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PreAuthenticationRateLimit {
    last_admitted_ms: Option<u64>,
}

impl PreAuthenticationRateLimit {
    /// Admit one attempt at `now_ms`, or refuse it when the previous
    /// admitted attempt is less than 500 ms old. A refused attempt does not
    /// move the window.
    pub fn admit(&mut self, now_ms: u64) -> bool {
        if self
            .last_admitted_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < PRE_AUTHENTICATION_SPACING_MS)
        {
            return false;
        }
        self.last_admitted_ms = Some(now_ms);
        true
    }
}

/// The custodian's attempt accounting for one offer.
///
/// An attempt is admitted before `Y_B` and `T_B` leave the custodian, so a
/// peer that tests `T_B` and disconnects still spends it. A verified `T_A`
/// consumes the offer; three failed attempts exhaust it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpaceAttemptLedger {
    admitted: u8,
    failed: u8,
    consumed: bool,
    active_deadline_ms: Option<u64>,
}

impl CpaceAttemptLedger {
    /// Whether three attempts failed and the offer is locked out.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.failed >= MAXIMUM_CPACE_ATTEMPTS
    }

    /// Whether a verified `T_A` consumed the offer.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Whether an attempt is running under its timer.
    #[must_use]
    pub const fn has_active_attempt(&self) -> bool {
        self.active_deadline_ms.is_some()
    }

    /// Whether another attempt may still be admitted under this offer.
    #[must_use]
    pub const fn accepts_another_attempt(&self) -> bool {
        !self.consumed && !self.is_exhausted() && self.admitted < MAXIMUM_CPACE_ATTEMPTS
    }

    /// Reserve one attempt whose deadline is clamped to the offer deadline.
    /// Returns whether the attempt was admitted.
    pub fn admit(&mut self, now_ms: u64, offer_expires_at_ms: u64) -> bool {
        if self.consumed
            || self.active_deadline_ms.is_some()
            || self.admitted >= MAXIMUM_CPACE_ATTEMPTS
            || now_ms >= offer_expires_at_ms
        {
            return false;
        }
        self.admitted += 1;
        self.active_deadline_ms = Some(
            now_ms
                .saturating_add(CPACE_ATTEMPT_WINDOW_MS)
                .min(offer_expires_at_ms),
        );
        true
    }

    /// Whether the active attempt may still complete.
    #[must_use]
    pub fn attempt_is_live(&self, now_ms: u64) -> bool {
        self.active_deadline_ms
            .is_some_and(|deadline| now_ms < deadline)
    }

    /// End the active attempt as failed; disconnects and timeouts are not
    /// refunded.
    pub const fn fail_active_attempt(&mut self) {
        if self.active_deadline_ms.is_some() {
            self.active_deadline_ms = None;
            self.failed += 1;
        }
    }

    /// End the active attempt as the one that consumed the offer.
    pub const fn consume(&mut self) {
        self.active_deadline_ms = None;
        self.consumed = true;
    }
}

/// Ceiling of the post-lockout delay.
const BACKOFF_CEILING_MS: u64 = 300_000;
/// Exponent at which the delay saturates at the ceiling.
const BACKOFF_SATURATING_EXPONENT: u32 = 9;
/// One second, the unit of the backoff schedule.
const BACKOFF_UNIT_MS: u64 = 1_000;
/// Inactivity after which the lockout count resets.
const BACKOFF_INACTIVITY_RESET_MS: u64 = 900_000;

/// The custodian's exponential backoff after locked-out offers
/// (RAPP v26.10.10 §3.3.7).
///
/// After `n` consecutive lockouts a new offer waits `min(2^n, 300)` seconds.
/// The count is volatile: it resets on a successful pairing, after fifteen
/// minutes without a lockout, and when the process ends. Times are the
/// platform's monotonic milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PairingBackoff {
    consecutive_lockouts: u32,
    last_lockout_ms: Option<u64>,
}

impl PairingBackoff {
    /// Record one offer locked out by three failed attempts.
    pub fn record_lockout(&mut self, now_ms: u64) {
        self.expire_if_inactive(now_ms);
        self.consecutive_lockouts =
            (self.consecutive_lockouts + 1).min(BACKOFF_SATURATING_EXPONENT);
        self.last_lockout_ms = Some(now_ms);
    }

    /// Clear the count after a completed pairing.
    pub const fn record_success(&mut self) {
        self.consecutive_lockouts = 0;
        self.last_lockout_ms = None;
    }

    /// Milliseconds before a new offer may be created; zero when one may be
    /// created now.
    #[must_use]
    pub fn ms_until_next_offer(&self, now_ms: u64) -> u64 {
        let mut current = *self;
        current.expire_if_inactive(now_ms);
        let Some(last) = current.last_lockout_ms else {
            return 0;
        };
        if current.consecutive_lockouts == 0 {
            return 0;
        }
        let delay = (BACKOFF_UNIT_MS << current.consecutive_lockouts).min(BACKOFF_CEILING_MS);
        delay.saturating_sub(now_ms.saturating_sub(last))
    }

    fn expire_if_inactive(&mut self, now_ms: u64) {
        if self
            .last_lockout_ms
            .is_some_and(|last| now_ms.saturating_sub(last) >= BACKOFF_INACTIVITY_RESET_MS)
        {
            self.record_success();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CPACE_ATTEMPT_WINDOW_MS, CpaceAttemptLedger, PRE_AUTHENTICATION_SPACING_MS, PairingBackoff,
        PreAuthenticationRateLimit, phase_deadline_ms,
    };

    #[test]
    fn pre_authentication_attempts_are_spaced_by_500_ms() {
        let mut limit = PreAuthenticationRateLimit::default();
        assert!(limit.admit(1_000));
        assert!(!limit.admit(1_000 + PRE_AUTHENTICATION_SPACING_MS - 1));
        assert!(limit.admit(1_000 + PRE_AUTHENTICATION_SPACING_MS));
        assert!(!limit.admit(1_000 + PRE_AUTHENTICATION_SPACING_MS + 1));
    }

    #[test]
    fn phase_deadlines_saturate() {
        assert_eq!(phase_deadline_ms(1_000, 10_000), 11_000);
        assert_eq!(phase_deadline_ms(u64::MAX - 1, 10_000), u64::MAX);
    }

    const OFFER_END: u64 = 60_000;

    #[test]
    fn three_failed_attempts_exhaust_the_offer() {
        let mut ledger = CpaceAttemptLedger::default();
        for attempt in 0..3_u64 {
            assert!(ledger.admit(attempt * 10, OFFER_END));
            assert!(!ledger.admit(attempt * 10 + 1, OFFER_END), "single flight");
            ledger.fail_active_attempt();
        }
        assert!(ledger.is_exhausted());
        assert!(!ledger.accepts_another_attempt());
        assert!(!ledger.admit(100, OFFER_END));
    }

    #[test]
    fn the_attempt_window_is_clamped_to_the_offer_deadline() {
        let mut ledger = CpaceAttemptLedger::default();
        assert!(ledger.admit(59_000, OFFER_END));
        assert!(ledger.attempt_is_live(59_999));
        assert!(!ledger.attempt_is_live(OFFER_END));
        let mut early = CpaceAttemptLedger::default();
        assert!(early.admit(1_000, OFFER_END));
        assert!(!early.attempt_is_live(1_000 + CPACE_ATTEMPT_WINDOW_MS));
        assert!(!CpaceAttemptLedger::default().admit(OFFER_END, OFFER_END));
    }

    #[test]
    fn consumption_admits_nothing_more() {
        let mut ledger = CpaceAttemptLedger::default();
        assert!(ledger.admit(0, OFFER_END));
        ledger.consume();
        assert!(ledger.is_consumed());
        assert!(!ledger.admit(1, OFFER_END));
    }

    #[test]
    fn backoff_doubles_saturates_and_resets() {
        let mut backoff = PairingBackoff::default();
        assert_eq!(backoff.ms_until_next_offer(0), 0);
        backoff.record_lockout(0);
        assert_eq!(backoff.ms_until_next_offer(0), 2_000);
        backoff.record_lockout(10_000);
        assert_eq!(backoff.ms_until_next_offer(10_000), 4_000);
        assert_eq!(backoff.ms_until_next_offer(13_000), 1_000);
        for step in 0..10_u64 {
            backoff.record_lockout(20_000 + step);
        }
        assert_eq!(backoff.ms_until_next_offer(20_009), 300_000);
        assert_eq!(backoff.ms_until_next_offer(20_009 + 900_000), 0);
        backoff.record_success();
        assert_eq!(backoff.ms_until_next_offer(30_000), 0);
    }
}
