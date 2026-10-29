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

//! The requester's tries of one typed pairing code across the custodians it
//! finds in pairing mode (RAPP v26.10.29 §4.2, "Trying Each Custodian in
//! Pairing Mode").
//!
//! Nothing a custodian advertises tells which one shows the typed code, so
//! the requester tries them in turn. A candidate is an endpoint discovery
//! found in pairing mode: a `mode=pairing` service instance, or a BLE
//! peripheral of the RAPP service, which shows its mode only by serving an
//! offer. The ledger holds no code.

use core::fmt;

use crate::{Guards, OfferId, PairingEvent, PairingOffer};

/// Pairing connections one typed code may open (§4.2, "Trying Each
/// Custodian in Pairing Mode" item 5).
pub const PAIRING_CANDIDATES_MAX: usize = 8;

/// Where the tries of one typed code stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidatePhase {
    /// No pairing connection is open.
    Closed,
    /// A pairing connection is open and no CPace runs on it yet.
    Opened,
    /// CPace runs on the open connection's offer.
    Trying,
    /// A custodian's `T_B` verified: it holds the code.
    Accepted,
    /// Every custodian tried refused the code and no endpoint is left.
    NotAccepted,
}

/// The custodians in pairing mode a requester tries with one typed code.
///
/// One ledger serves one typed code; a new code starts a new ledger. It
/// opens each endpoint at most once and at most [`PAIRING_CANDIDATES_MAX`]
/// in all, one at a time; it lets CPace run at most once per `offer_id`, so
/// a custodian found on two transports receives one guess; and it reports
/// the code as not accepted only once every custodian tried refused it.
/// `E` is the platform's name for an endpoint: a service instance or a
/// peripheral address. No outcome names one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCandidates<E> {
    /// Endpoints found, in the order found; the first `opened` were opened.
    endpoints: Vec<E>,
    opened: usize,
    /// Offers CPace ran on.
    tried: Vec<OfferId>,
    phase: CandidatePhase,
}

/// What the requester does after a pairing connection closed without its
/// custodian taking the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextCandidate {
    /// Open the next endpoint ([`PairingCandidates::next_endpoint`]).
    Try,
    /// Every custodian tried refused the code: report it as not accepted,
    /// naming none of them.
    NotAccepted,
    /// No custodian has been tried and no endpoint is left to open: wait
    /// for discovery to find another, or report that none in pairing mode
    /// was found.
    NoneTried,
}

impl NextCandidate {
    /// The pairing-machine event of this outcome on the requester, with the
    /// guards it carries. `remote_use_available` says whether the
    /// requester's remote use is on and no card is in a reader attached to
    /// it. Without it no further custodian is tried and the search ends as
    /// [`PairingEvent::SearchInterrupted`], unless every custodian tried
    /// already refused the code (hierarchy specification section 5.2).
    /// [`Self::NoneTried`] is [`PairingEvent::NoCustodianTried`] once the
    /// requester's search ends.
    #[must_use]
    pub fn pairing_event(self, remote_use_available: bool) -> (PairingEvent, Guards) {
        match self {
            Self::NotAccepted => (PairingEvent::LastCandidateFailed, Guards::default()),
            Self::Try | Self::NoneTried if !remote_use_available => {
                (PairingEvent::SearchInterrupted, Guards::default())
            }
            Self::Try => (
                PairingEvent::AttemptFailed,
                Guards {
                    untried_pairing_candidate: true,
                    ..Guards::default()
                },
            ),
            Self::NoneTried => (PairingEvent::NoCustodianTried, Guards::default()),
        }
    }
}

/// A ledger call that the tries of the code do not admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateError {
    /// A pairing connection is open; it closes before the next one opens.
    ConnectionOpen,
    /// No pairing connection is open, or CPace already runs on it.
    NoConnection,
    /// No CPace runs on the open connection.
    NoTry,
    /// CPace already ran on this offer with the code: the same custodian,
    /// found on another transport. Close the connection without CPace.
    OfferAlreadyTried,
    /// A custodian accepted the code, or every one tried refused it.
    Settled,
}

impl fmt::Display for CandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ConnectionOpen => "a pairing connection is already open",
            Self::NoConnection => "no pairing connection awaits an offer",
            Self::NoTry => "no CPace runs on the pairing connection",
            Self::OfferAlreadyTried => "this offer was already tried with the code",
            Self::Settled => "the code was already accepted or refused",
        })
    }
}

impl core::error::Error for CandidateError {}

impl<E> Default for PairingCandidates<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> PairingCandidates<E> {
    /// The ledger of a code the user has just submitted.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            endpoints: Vec::new(),
            opened: 0,
            tried: Vec::new(),
            phase: CandidatePhase::Closed,
        }
    }
}

impl<E: PartialEq> PairingCandidates<E> {
    /// Record an endpoint discovery found in pairing mode. An endpoint
    /// already recorded, one beyond [`PAIRING_CANDIDATES_MAX`], and one found
    /// once the code is accepted or refused are not tried with this code.
    pub fn found(&mut self, endpoint: E) {
        if self.is_settled()
            || self.endpoints.len() >= PAIRING_CANDIDATES_MAX
            || self.endpoints.contains(&endpoint)
        {
            return;
        }
        self.endpoints.push(endpoint);
    }

    /// The next endpoint to open a pairing connection to, in the order
    /// found, or `None` when every endpoint recorded is opened.
    ///
    /// # Errors
    /// [`CandidateError::ConnectionOpen`] while a pairing connection is
    /// open, and [`CandidateError::Settled`] once the code is accepted or
    /// refused.
    pub fn next_endpoint(&mut self) -> Result<Option<&E>, CandidateError> {
        match self.phase {
            CandidatePhase::Closed => {}
            CandidatePhase::Opened | CandidatePhase::Trying => {
                return Err(CandidateError::ConnectionOpen);
            }
            CandidatePhase::Accepted | CandidatePhase::NotAccepted => {
                return Err(CandidateError::Settled);
            }
        }
        let Some(endpoint) = self.endpoints.get(self.opened) else {
            return Ok(None);
        };
        self.opened += 1;
        self.phase = CandidatePhase::Opened;
        Ok(Some(endpoint))
    }

    /// Admit the offer the open connection served, before CPace step 1.
    ///
    /// # Errors
    /// [`CandidateError::OfferAlreadyTried`] when CPace already ran on this
    /// `offer_id` with the code, [`CandidateError::NoConnection`] when no
    /// connection awaits an offer, and [`CandidateError::Settled`] once the
    /// code is accepted or refused. The caller closes the connection and
    /// calls [`Self::closed`].
    pub fn begin_try(&mut self, offer: &PairingOffer) -> Result<(), CandidateError> {
        match self.phase {
            CandidatePhase::Opened => {}
            CandidatePhase::Closed | CandidatePhase::Trying => {
                return Err(CandidateError::NoConnection);
            }
            CandidatePhase::Accepted | CandidatePhase::NotAccepted => {
                return Err(CandidateError::Settled);
            }
        }
        if self.tried.contains(&offer.offer_id) {
            return Err(CandidateError::OfferAlreadyTried);
        }
        self.tried.push(offer.offer_id);
        self.phase = CandidatePhase::Trying;
        Ok(())
    }

    /// The open connection closed without its custodian taking the code:
    /// the connection was refused or closed, it served no offer or one the
    /// requester rejects or already tried, CPace step 2 did not arrive
    /// within the attempt deadline, or `T_B` did not verify.
    ///
    /// # Errors
    /// [`CandidateError::NoConnection`] when no connection is open, and
    /// [`CandidateError::Settled`] once the code is accepted or refused.
    pub fn closed(&mut self) -> Result<NextCandidate, CandidateError> {
        match self.phase {
            CandidatePhase::Opened | CandidatePhase::Trying => {}
            CandidatePhase::Closed => return Err(CandidateError::NoConnection),
            CandidatePhase::Accepted | CandidatePhase::NotAccepted => {
                return Err(CandidateError::Settled);
            }
        }
        if self.opened < self.endpoints.len() {
            self.phase = CandidatePhase::Closed;
            return Ok(NextCandidate::Try);
        }
        if self.tried.is_empty() {
            self.phase = CandidatePhase::Closed;
            return Ok(NextCandidate::NoneTried);
        }
        self.phase = CandidatePhase::NotAccepted;
        Ok(NextCandidate::NotAccepted)
    }

    /// The custodian tried proved it holds the code: its `T_B` verified.
    /// No other custodian is tried with the code.
    ///
    /// # Errors
    /// [`CandidateError::NoTry`] when no CPace runs, and
    /// [`CandidateError::Settled`] once the code is accepted or refused.
    pub const fn accepted(&mut self) -> Result<(), CandidateError> {
        match self.phase {
            CandidatePhase::Trying => {
                self.phase = CandidatePhase::Accepted;
                Ok(())
            }
            CandidatePhase::Closed | CandidatePhase::Opened => Err(CandidateError::NoTry),
            CandidatePhase::Accepted | CandidatePhase::NotAccepted => Err(CandidateError::Settled),
        }
    }

    /// Whether the code is accepted or refused.
    const fn is_settled(&self) -> bool {
        matches!(
            self.phase,
            CandidatePhase::Accepted | CandidatePhase::NotAccepted
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{CandidateError, NextCandidate, PAIRING_CANDIDATES_MAX, PairingCandidates};
    use crate::{
        Action, EndpointRole, Guards, OFFER_ID_SIZE, OfferId, PairingEvent, PairingOffer,
        PairingState, ProfileName, TransitionError, TransportProfile,
    };

    fn offer(id: u8) -> PairingOffer {
        PairingOffer::create(
            OfferId::from_array([id; OFFER_ID_SIZE]),
            ProfileName::ALL
                .iter()
                .map(|profile| profile.as_str().to_owned())
                .collect(),
            &[TransportProfile::Stream, TransportProfile::Ble],
        )
        .expect("fixture offer is valid")
    }

    fn open(ledger: &mut PairingCandidates<&'static str>) -> &'static str {
        ledger
            .next_endpoint()
            .expect("no connection is open")
            .copied()
            .expect("an endpoint is left")
    }

    #[test]
    fn a_refusal_moves_on_to_the_custodian_that_shows_the_code() {
        let mut ledger = PairingCandidates::new();
        ledger.found("android");
        ledger.found("iphone");
        assert_eq!(open(&mut ledger), "android");
        ledger.begin_try(&offer(1)).expect("first offer");
        assert_eq!(ledger.closed(), Ok(NextCandidate::Try));
        assert_eq!(open(&mut ledger), "iphone");
        ledger.begin_try(&offer(2)).expect("second offer");
        assert_eq!(ledger.accepted(), Ok(()));
        assert_eq!(ledger.next_endpoint(), Err(CandidateError::Settled));
    }

    #[test]
    fn the_code_is_refused_only_after_every_custodian_refused_it() {
        let mut ledger = PairingCandidates::new();
        ledger.found("first");
        ledger.found("second");
        open(&mut ledger);
        ledger.begin_try(&offer(1)).expect("first offer");
        assert_eq!(ledger.closed(), Ok(NextCandidate::Try));
        open(&mut ledger);
        ledger.begin_try(&offer(2)).expect("second offer");
        assert_eq!(ledger.closed(), Ok(NextCandidate::NotAccepted));
        ledger.found("late");
        assert_eq!(ledger.next_endpoint(), Err(CandidateError::Settled));
    }

    #[test]
    fn an_endpoint_found_during_a_try_is_tried_too() {
        let mut ledger = PairingCandidates::new();
        ledger.found("first");
        open(&mut ledger);
        ledger.begin_try(&offer(1)).expect("first offer");
        ledger.found("second");
        assert_eq!(ledger.closed(), Ok(NextCandidate::Try));
        assert_eq!(open(&mut ledger), "second");
    }

    #[test]
    fn a_custodian_on_two_transports_receives_one_guess() {
        let mut ledger = PairingCandidates::new();
        ledger.found("stream");
        ledger.found("ble");
        ledger.found("stream");
        open(&mut ledger);
        ledger.begin_try(&offer(1)).expect("first offer");
        assert_eq!(ledger.closed(), Ok(NextCandidate::Try));
        assert_eq!(open(&mut ledger), "ble");
        assert_eq!(
            ledger.begin_try(&offer(1)),
            Err(CandidateError::OfferAlreadyTried)
        );
        assert_eq!(ledger.closed(), Ok(NextCandidate::NotAccepted));
    }

    #[test]
    fn one_pairing_connection_at_a_time() {
        let mut ledger = PairingCandidates::new();
        ledger.found("first");
        ledger.found("second");
        open(&mut ledger);
        assert_eq!(ledger.next_endpoint(), Err(CandidateError::ConnectionOpen));
        ledger.begin_try(&offer(1)).expect("first offer");
        assert_eq!(ledger.next_endpoint(), Err(CandidateError::ConnectionOpen));
        assert_eq!(
            ledger.begin_try(&offer(2)),
            Err(CandidateError::NoConnection)
        );
    }

    #[test]
    fn at_most_the_limit_of_endpoints_is_opened() {
        let mut ledger = PairingCandidates::new();
        for endpoint in ["a", "b", "c", "d", "e", "f", "g", "h", "i"] {
            ledger.found(endpoint);
        }
        let mut opened = 0_usize;
        let mut next = NextCandidate::Try;
        let mut offer_id = 0_u8;
        while next == NextCandidate::Try {
            open(&mut ledger);
            opened += 1;
            offer_id += 1;
            ledger.begin_try(&offer(offer_id)).expect("fresh offer");
            next = ledger.closed().expect("a connection is open");
        }
        assert_eq!(opened, PAIRING_CANDIDATES_MAX);
        assert_eq!(next, NextCandidate::NotAccepted);
    }

    #[test]
    fn endpoints_that_serve_no_offer_are_not_a_refused_code() {
        let mut ledger = PairingCandidates::new();
        ledger.found("session-mode phone");
        open(&mut ledger);
        assert_eq!(ledger.closed(), Ok(NextCandidate::NoneTried));
        assert_eq!(ledger.next_endpoint(), Ok(None));
        ledger.found("pairing phone");
        assert_eq!(open(&mut ledger), "pairing phone");
        ledger.begin_try(&offer(1)).expect("offer");
        assert_eq!(ledger.closed(), Ok(NextCandidate::NotAccepted));
    }

    #[test]
    fn acceptance_needs_a_running_try() {
        let mut ledger = PairingCandidates::new();
        assert_eq!(ledger.accepted(), Err(CandidateError::NoTry));
        assert_eq!(ledger.closed(), Err(CandidateError::NoConnection));
        ledger.found("only");
        open(&mut ledger);
        assert_eq!(ledger.accepted(), Err(CandidateError::NoTry));
    }

    #[test]
    fn the_outcomes_drive_the_requester_pairing_machine() {
        let requester = EndpointRole::Requester;
        let (event, guards) = NextCandidate::Try.pairing_event(true);
        let next = PairingState::Exchanging
            .transition(requester, event, guards)
            .expect("an untried candidate is tried");
        assert_eq!(next.state, PairingState::Exchanging);
        assert!(next.actions.contains(&Action::TryNextCandidate));
        assert!(!next.actions.contains(&Action::ShowWrongCode));

        let (event, guards) = NextCandidate::NotAccepted.pairing_event(true);
        assert_eq!(event, PairingEvent::LastCandidateFailed);
        let last = PairingState::Exchanging
            .transition(requester, event, guards)
            .expect("the last refusal ends the ceremony");
        assert_eq!(last.state, PairingState::Unpaired);
        assert!(last.actions.contains(&Action::ShowWrongCode));

        let (event, guards) = NextCandidate::NoneTried.pairing_event(true);
        let none = PairingState::Exchanging
            .transition(requester, event, guards)
            .expect("a search that tried nobody ends");
        assert!(none.actions.contains(&Action::ShowNoneInPairingMode));
        assert!(!none.actions.contains(&Action::ShowWrongCode));

        let (_, guards) = NextCandidate::NotAccepted.pairing_event(true);
        assert_eq!(
            PairingState::Exchanging.transition(requester, PairingEvent::AttemptFailed, guards),
            Err(TransitionError::GuardFailed),
            "a refusal with nobody left to try never stays exchanging"
        );
    }

    #[test]
    fn a_local_card_or_remote_use_off_ends_the_search() {
        for outcome in [NextCandidate::Try, NextCandidate::NoneTried] {
            let (event, guards) = outcome.pairing_event(false);
            assert_eq!(event, PairingEvent::SearchInterrupted);
            let ended = PairingState::Exchanging
                .transition(EndpointRole::Requester, event, guards)
                .expect("the search ends");
            assert_eq!(ended.state, PairingState::Unpaired);
            assert_eq!(ended.actions, &[Action::CloseCandidate]);
        }
        let (event, _) = NextCandidate::NotAccepted.pairing_event(false);
        assert_eq!(
            event,
            PairingEvent::LastCandidateFailed,
            "a code every custodian tried refused is still reported"
        );
        let refused = Guards {
            untried_pairing_candidate: false,
            ..Guards::default()
        };
        assert_eq!(
            PairingState::Exchanging.transition(
                EndpointRole::Requester,
                PairingEvent::AttemptFailed,
                refused
            ),
            Err(TransitionError::GuardFailed),
            "no further custodian is tried without the guard"
        );
    }
}
