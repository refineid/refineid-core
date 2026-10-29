//! Session liveness (RAPP v26.10.29 section 8.3): a ping after 5 seconds of
//! silence, the session's end after 30 seconds without any message.

use core::fmt;

use super::LIVENESS_CHALLENGE_SIZE;

/// Silence after which an endpoint sends `liveness.ping`.
pub const LIVENESS_PING_AFTER_SILENCE_MS: u64 = 5_000;
/// Silence after which the session ends.
pub const SESSION_SILENCE_LIMIT_MS: u64 = 30_000;

/// Unpredictable caller-supplied ping value echoed by the peer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PingChallenge([u8; LIVENESS_CHALLENGE_SIZE]);

impl PingChallenge {
    /// Constructs a challenge from cryptographically random bytes supplied by
    /// the platform RNG.
    #[must_use]
    pub const fn reconstruct(bytes: [u8; LIVENESS_CHALLENGE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Challenge bytes sent in the authenticated ping body.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; LIVENESS_CHALLENGE_SIZE] {
        &self.0
    }
}

impl fmt::Debug for PingChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PingChallenge([redacted])")
    }
}

/// Session-local liveness on an injected monotonic clock.
#[allow(
    missing_copy_implementations,
    reason = "one tracker per session; a copied tracker would fork liveness state"
)]
#[derive(Debug)]
pub struct LivenessTracker {
    last_heard_ms: u64,
    last_ping_ms: Option<u64>,
    outstanding: Option<PingChallenge>,
    closed: bool,
}

impl LivenessTracker {
    /// Starts tracking with the peer last heard at `now_ms`.
    #[must_use]
    pub const fn new(now_ms: u64) -> Self {
        Self {
            last_heard_ms: now_ms,
            last_ping_ms: None,
            outstanding: None,
            closed: false,
        }
    }

    /// Any authenticated message from the peer resets the silence.
    pub const fn heard(&mut self, now_ms: u64) {
        self.last_heard_ms = now_ms;
        self.last_ping_ms = None;
    }

    /// Advances the clock. The challenge is consumed only when a ping is due:
    /// after each 5 seconds of silence, until 30 seconds of silence end the
    /// session.
    pub fn poll(&mut self, now_ms: u64, next_challenge: PingChallenge) -> LivenessDecision {
        if self.closed {
            return LivenessDecision::AlreadyClosed;
        }
        let silence = now_ms.saturating_sub(self.last_heard_ms);
        if silence >= SESSION_SILENCE_LIMIT_MS {
            self.closed = true;
            return LivenessDecision::CloseSession;
        }
        let since_ping = self
            .last_ping_ms
            .map_or(silence, |ping| now_ms.saturating_sub(ping));
        if silence >= LIVENESS_PING_AFTER_SILENCE_MS && since_ping >= LIVENESS_PING_AFTER_SILENCE_MS
        {
            self.last_ping_ms = Some(now_ms);
            self.outstanding = Some(next_challenge);
            return LivenessDecision::SendPing(next_challenge);
        }
        LivenessDecision::NoAction
    }

    /// Accepts only the exact challenge outstanding. Any authenticated
    /// message counts as heard through [`Self::heard`]; a pong also clears
    /// its challenge.
    pub fn receive_pong(&mut self, now_ms: u64, challenge: PingChallenge) -> PongDisposition {
        if self.outstanding != Some(challenge) {
            return PongDisposition::IgnoredUnmatched;
        }
        self.outstanding = None;
        self.heard(now_ms);
        PongDisposition::Accepted
    }

    /// Permanently closes this tracker.
    pub const fn close(&mut self) {
        self.closed = true;
    }
}

/// Action emitted by a liveness clock tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessDecision {
    /// Nothing to send.
    NoAction,
    /// Send an authenticated ping carrying this challenge.
    SendPing(PingChallenge),
    /// The silence limit passed; the session ends.
    CloseSession,
    /// The tracker was already closed.
    AlreadyClosed,
}

/// Result of receiving an authenticated pong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PongDisposition {
    /// The outstanding challenge matched.
    Accepted,
    /// No outstanding challenge matched; a delayed race.
    IgnoredUnmatched,
}

#[cfg(test)]
mod tests {
    use super::{
        LIVENESS_CHALLENGE_SIZE, LIVENESS_PING_AFTER_SILENCE_MS, LivenessDecision, LivenessTracker,
        PingChallenge, PongDisposition, SESSION_SILENCE_LIMIT_MS,
    };

    const CHALLENGE: PingChallenge = PingChallenge::reconstruct([7; LIVENESS_CHALLENGE_SIZE]);

    #[test]
    fn silence_brings_a_ping_and_then_the_end() {
        let mut tracker = LivenessTracker::new(0);
        assert_eq!(
            tracker.poll(LIVENESS_PING_AFTER_SILENCE_MS - 1, CHALLENGE),
            LivenessDecision::NoAction
        );
        assert_eq!(
            tracker.poll(LIVENESS_PING_AFTER_SILENCE_MS, CHALLENGE),
            LivenessDecision::SendPing(CHALLENGE)
        );
        assert_eq!(
            tracker.poll(LIVENESS_PING_AFTER_SILENCE_MS + 1, CHALLENGE),
            LivenessDecision::NoAction
        );
        assert_eq!(
            tracker.poll(2 * LIVENESS_PING_AFTER_SILENCE_MS, CHALLENGE),
            LivenessDecision::SendPing(CHALLENGE)
        );
        assert_eq!(
            tracker.poll(SESSION_SILENCE_LIMIT_MS, CHALLENGE),
            LivenessDecision::CloseSession
        );
        assert_eq!(
            tracker.poll(SESSION_SILENCE_LIMIT_MS, CHALLENGE),
            LivenessDecision::AlreadyClosed
        );
    }

    #[test]
    fn a_matching_pong_resets_the_silence() {
        let mut tracker = LivenessTracker::new(0);
        tracker.poll(LIVENESS_PING_AFTER_SILENCE_MS, CHALLENGE);
        let other = PingChallenge::reconstruct([8; LIVENESS_CHALLENGE_SIZE]);
        assert_eq!(
            tracker.receive_pong(LIVENESS_PING_AFTER_SILENCE_MS, other),
            PongDisposition::IgnoredUnmatched
        );
        let answered = SESSION_SILENCE_LIMIT_MS - 1;
        assert_eq!(
            tracker.receive_pong(answered, CHALLENGE),
            PongDisposition::Accepted
        );
        assert_eq!(
            tracker.poll(SESSION_SILENCE_LIMIT_MS, CHALLENGE),
            LivenessDecision::NoAction
        );
    }
}
