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

//! The pairing ceremony's attempt admission, post-PAKE deadlines and
//! pre-authentication rate limit (RAPP v26.11.1 §3.3).

/// Non-extendable window from admission to a verified `T_A`.
pub const CPACE_ATTEMPT_WINDOW_MS: u64 = 5_000;

/// From local CPace handoff to a completed `Noise_XXpsk3` handshake
/// (§3.3 item 7).
pub const POST_PAKE_HANDSHAKE_MS: u64 = 10_000;

/// From local Noise completion to an active pairing: hello, confirmation,
/// storage and the peer's storage confirmation (§3.3 item 7, §4.3 item 4).
pub const POST_PAKE_CONFIRMATION_MS: u64 = 10_000;

/// Minimum spacing of pre-authentication attempts at the custodian
/// (§3.3 item 6).
pub const PRE_AUTHENTICATION_SPACING_MS: u64 = 500;

/// The monotonic deadline `window` milliseconds after `start_ms`.
#[must_use]
pub const fn phase_deadline_ms(start_ms: u64, window_ms: u64) -> u64 {
    start_ms.saturating_add(window_ms)
}

/// The §3.3 item 6 limit of one pre-authentication attempt per 500 ms.
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

    /// Milliseconds from `now_ms` until [`Self::admit`] admits an attempt,
    /// zero when it would admit one now. Asking moves nothing.
    #[must_use]
    pub fn wait_ms(&self, now_ms: u64) -> u64 {
        self.last_admitted_ms.map_or(0, |last| {
            PRE_AUTHENTICATION_SPACING_MS.saturating_sub(now_ms.saturating_sub(last))
        })
    }
}

/// The custodian's one attempt slot for an offer (§3.3 items 1 to 5).
///
/// An attempt is admitted before `Y_B` and `T_B` leave the custodian, so a
/// peer that tests `T_B` and disconnects holds the slot no longer than a
/// completed wrong guess does. A failed attempt frees the slot and changes
/// nothing else; a verified `T_A` consumes the offer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpaceAttemptSlot {
    consumed: bool,
    active_deadline_ms: Option<u64>,
}

impl CpaceAttemptSlot {
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

    /// Whether another attempt may be admitted under this offer now.
    #[must_use]
    pub const fn accepts_another_attempt(&self) -> bool {
        !self.consumed && self.active_deadline_ms.is_none()
    }

    /// Admit one attempt whose deadline is clamped to the offer deadline.
    /// Returns whether the attempt was admitted.
    pub fn admit(&mut self, now_ms: u64, offer_expires_at_ms: u64) -> bool {
        if !self.accepts_another_attempt() || now_ms >= offer_expires_at_ms {
            return false;
        }
        self.active_deadline_ms = Some(
            now_ms
                .saturating_add(CPACE_ATTEMPT_WINDOW_MS)
                .min(offer_expires_at_ms),
        );
        true
    }

    /// Milliseconds from `now_ms` until the active attempt's deadline, zero
    /// when no attempt is active or its deadline has passed.
    #[must_use]
    pub fn active_attempt_wait_ms(&self, now_ms: u64) -> u64 {
        self.active_deadline_ms
            .map_or(0, |deadline| deadline.saturating_sub(now_ms))
    }

    /// Whether the active attempt may still complete.
    #[must_use]
    pub fn attempt_is_live(&self, now_ms: u64) -> bool {
        self.active_deadline_ms
            .is_some_and(|deadline| now_ms < deadline)
    }

    /// End the active attempt as failed: a disconnect, a timeout or a wrong
    /// `T_A` frees the slot and leaves the offer as it was.
    pub const fn end_active_attempt(&mut self) {
        self.active_deadline_ms = None;
    }

    /// End the active attempt as the one that consumed the offer.
    pub const fn consume(&mut self) {
        self.active_deadline_ms = None;
        self.consumed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CPACE_ATTEMPT_WINDOW_MS, CpaceAttemptSlot, PRE_AUTHENTICATION_SPACING_MS,
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
    fn the_spacing_wait_is_read_without_moving_the_window() {
        let mut limit = PreAuthenticationRateLimit::default();
        assert_eq!(limit.wait_ms(1_000), 0);
        assert!(limit.admit(1_000));
        assert_eq!(limit.wait_ms(1_000), PRE_AUTHENTICATION_SPACING_MS);
        assert_eq!(limit.wait_ms(1_100), PRE_AUTHENTICATION_SPACING_MS - 100);
        assert_eq!(limit.wait_ms(1_000 + PRE_AUTHENTICATION_SPACING_MS), 0);
        assert!(!limit.admit(1_100));
        assert_eq!(limit.wait_ms(1_100), PRE_AUTHENTICATION_SPACING_MS - 100);
    }

    #[test]
    fn the_attempt_wait_is_the_time_left_on_its_deadline() {
        let mut slot = CpaceAttemptSlot::default();
        assert_eq!(slot.active_attempt_wait_ms(1_000), 0);
        assert!(slot.admit(1_000, OFFER_END));
        assert_eq!(slot.active_attempt_wait_ms(1_000), CPACE_ATTEMPT_WINDOW_MS);
        assert_eq!(
            slot.active_attempt_wait_ms(3_000),
            CPACE_ATTEMPT_WINDOW_MS - 2_000
        );
        assert_eq!(
            slot.active_attempt_wait_ms(1_000 + CPACE_ATTEMPT_WINDOW_MS),
            0
        );
        slot.end_active_attempt();
        assert_eq!(slot.active_attempt_wait_ms(2_000), 0);
    }

    #[test]
    fn phase_deadlines_saturate() {
        assert_eq!(phase_deadline_ms(1_000, 10_000), 11_000);
        assert_eq!(phase_deadline_ms(u64::MAX - 1, 10_000), u64::MAX);
    }

    const OFFER_END: u64 = 60_000;

    #[test]
    fn failed_attempts_never_exhaust_the_offer() {
        let mut slot = CpaceAttemptSlot::default();
        for attempt in 0..100_u64 {
            assert!(slot.admit(attempt * 10, OFFER_END), "attempt {attempt}");
            assert!(!slot.admit(attempt * 10 + 1, OFFER_END), "single flight");
            slot.end_active_attempt();
            assert!(slot.accepts_another_attempt());
        }
        assert!(slot.admit(1_000, OFFER_END));
    }

    #[test]
    fn the_attempt_window_is_clamped_to_the_offer_deadline() {
        let mut slot = CpaceAttemptSlot::default();
        assert!(slot.admit(59_000, OFFER_END));
        assert!(slot.attempt_is_live(59_999));
        assert!(!slot.attempt_is_live(OFFER_END));
        let mut early = CpaceAttemptSlot::default();
        assert!(early.admit(1_000, OFFER_END));
        assert!(!early.attempt_is_live(1_000 + CPACE_ATTEMPT_WINDOW_MS));
        assert!(!CpaceAttemptSlot::default().admit(OFFER_END, OFFER_END));
    }

    #[test]
    fn consumption_admits_nothing_more() {
        let mut slot = CpaceAttemptSlot::default();
        assert!(slot.admit(0, OFFER_END));
        slot.consume();
        assert!(slot.is_consumed());
        assert!(!slot.accepts_another_attempt());
        assert!(!slot.admit(1, OFFER_END));
    }
}
