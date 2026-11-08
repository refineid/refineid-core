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

//! How a requester treats the end of a session to its custodian (RAPP
//! v26.11.8 section 4.5 item 6, "How a session ends").

use super::CloseReason;

/// What a requester does when a session it did not end itself ends: the
/// four cases of section 4.5 item 6. A close the requester sends for its
/// own reasons (its withdrawal, its user's forget) is not classified here,
/// except that its own `pairing_revoked` close is [`Self::Revoked`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequesterSessionEnd {
    /// A `pairing_revoked` close, received or sent: forget the pairing,
    /// withdraw its identity at once (item 6.1, section 4.6 item 4).
    Revoked,
    /// A `service_withdrawn` or `card_unavailable` close received: withdraw
    /// the custodian's identity at once, without the grace of section 8.4
    /// item 3, dial nothing and offer nothing until the custodian announces
    /// itself again (item 6.2, section 8.4 item 5). The pairing stays.
    Withdrawn,
    /// An authenticated protocol violation, the custodian's
    /// `protocol_violation` close or one the requester detected and closed
    /// with: keep the pairing and do not redial; dial again only when the
    /// custodian next appears or a local consumer asks (item 6.3). The
    /// identity stays offered under the grace of section 8.4 item 3.
    Violation,
    /// A loss: transport close, the silence limit, an AEAD or framing
    /// failure, or a close with reason `normal`, `complete`,
    /// `user_disconnect`, `policy` or `shutdown`. Open the redial window
    /// ([`REDIAL_WINDOW_MS`](crate::REDIAL_WINDOW_MS)) at once, counted from
    /// the loss, whether or not the custodian is in sight (item 6.4,
    /// section 8.3). The identity stays offered under the grace of section
    /// 8.4 item 3.
    Loss,
}

impl RequesterSessionEnd {
    /// The treatment of a session that ended with the authenticated close
    /// `reason` from the custodian, or with none (`None`: a transport close,
    /// silence, an AEAD or framing failure).
    #[must_use]
    pub const fn of_received_close(reason: Option<CloseReason>) -> Self {
        match reason {
            Some(CloseReason::PairingRevoked) => Self::Revoked,
            Some(CloseReason::ServiceWithdrawn | CloseReason::CardUnavailable) => Self::Withdrawn,
            Some(CloseReason::ProtocolViolation) => Self::Violation,
            Some(
                CloseReason::Normal
                | CloseReason::Complete
                | CloseReason::UserDisconnect
                | CloseReason::Policy
                | CloseReason::Shutdown,
            )
            | None => Self::Loss,
        }
    }

    /// The treatment of a session the requester closed because the
    /// custodian's authenticated traffic violated the protocol.
    #[must_use]
    pub const fn of_detected_violation() -> Self {
        Self::Violation
    }

    /// Whether the treatment opens the redial window.
    #[must_use]
    pub const fn redials(self) -> bool {
        matches!(self, Self::Loss)
    }

    /// Whether the treatment withdraws the custodian's identity at once,
    /// without the grace of section 8.4 item 3.
    #[must_use]
    pub const fn withdraws_identity_at_once(self) -> bool {
        matches!(self, Self::Revoked | Self::Withdrawn)
    }
}

#[cfg(test)]
mod tests {
    use super::RequesterSessionEnd;
    use crate::CloseReason;

    #[test]
    fn every_close_reason_has_its_treatment() {
        let cases = [
            (
                Some(CloseReason::PairingRevoked),
                RequesterSessionEnd::Revoked,
            ),
            (
                Some(CloseReason::ServiceWithdrawn),
                RequesterSessionEnd::Withdrawn,
            ),
            (
                Some(CloseReason::CardUnavailable),
                RequesterSessionEnd::Withdrawn,
            ),
            (
                Some(CloseReason::ProtocolViolation),
                RequesterSessionEnd::Violation,
            ),
            (Some(CloseReason::Normal), RequesterSessionEnd::Loss),
            (Some(CloseReason::Complete), RequesterSessionEnd::Loss),
            (Some(CloseReason::UserDisconnect), RequesterSessionEnd::Loss),
            (Some(CloseReason::Policy), RequesterSessionEnd::Loss),
            (Some(CloseReason::Shutdown), RequesterSessionEnd::Loss),
            (None, RequesterSessionEnd::Loss),
        ];
        for (reason, expected) in cases {
            assert_eq!(
                RequesterSessionEnd::of_received_close(reason),
                expected,
                "{reason:?}"
            );
        }
        assert_eq!(
            RequesterSessionEnd::of_detected_violation(),
            RequesterSessionEnd::Violation
        );
    }

    #[test]
    fn only_a_loss_redials_and_only_revocation_and_withdrawal_drop_at_once() {
        assert!(RequesterSessionEnd::Loss.redials());
        assert!(!RequesterSessionEnd::Violation.redials());
        assert!(!RequesterSessionEnd::Withdrawn.redials());
        assert!(!RequesterSessionEnd::Revoked.redials());
        assert!(RequesterSessionEnd::Revoked.withdraws_identity_at_once());
        assert!(RequesterSessionEnd::Withdrawn.withdraws_identity_at_once());
        assert!(!RequesterSessionEnd::Violation.withdraws_identity_at_once());
        assert!(!RequesterSessionEnd::Loss.withdraws_identity_at_once());
    }
}
