//! Executable conformance against the normative RAPP state-machine grammar.

use refineid_rapp::{
    Action, EndpointRole, Guards, IDENTITY_OFFER_GRACE_MS, LIVENESS_PING_AFTER_SILENCE_MS,
    MAXIMUM_CPACE_ATTEMPTS, MINIMUM_REMAINING_ATTEMPTS, OFFER_TTL_MS, OperationEvent,
    OperationState, PAIRING_CANDIDATES_MAX, PAIRING_IDLE_EXPIRY_DAYS, PairingEvent, PairingState,
    QUIT_WITHDRAWAL_BOUND_MS, REVOCATION_NOTICE_DAYS, SESSION_SILENCE_LIMIT_MS, SessionEvent,
    SessionState,
};
use serde::Deserialize;
use std::collections::BTreeMap;

const MODEL: &str = include_str!("../../../doc/protocols/rapp-state-machine-v26.10.22.yaml");

#[derive(Deserialize)]
struct Model {
    document_version: String,
    constants: Constants,
    guards: BTreeMap<String, String>,
    pairing: Machine,
    session: Machine,
    operation: Machine,
}

/// The model's named numbers that the engine mirrors.
#[derive(Deserialize)]
struct Constants {
    pairing_attempts_per_offer: u64,
    pairing_candidates_max: u64,
    minimum_remaining_attempts: u64,
    offer_ttl_ms: u64,
    liveness_ping_after_silence_ms: u64,
    session_silence_limit_ms: u64,
    revocation_notice_days: u64,
    pairing_idle_expiry_days: u64,
    identity_offer_grace_ms: u64,
    quit_withdrawal_bound_ms: u64,
}

#[derive(Deserialize)]
struct Machine {
    initial: String,
    states: Vec<String>,
    transitions: Vec<Rule>,
}

#[derive(Deserialize)]
struct Rule {
    from: OneOrMany,
    event: String,
    role: String,
    guard: Option<String>,
    to: String,
    actions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn values(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Self::One(value) => Box::new(core::iter::once(value.as_str())),
            Self::Many(values) => Box::new(values.iter().map(String::as_str)),
        }
    }
}

fn model() -> Model {
    serde_saphyr::from_str(MODEL).expect("normative RAPP state model must parse")
}

const fn all_guards() -> Guards {
    Guards {
        user_initiated: true,
        local_user_action: true,
        transcript_matches: true,
        granted_sets_equal: true,
        initiation_permitted: true,
        pairing_routed: true,
        ready_parameters_match: true,
        untried_pairing_candidate: true,
    }
}

fn roles(rule: &Rule) -> &'static [EndpointRole] {
    match rule.role.as_str() {
        "requester" => &[EndpointRole::Requester],
        "custodian" => &[EndpointRole::Proxy],
        "both" => &[EndpointRole::Requester, EndpointRole::Proxy],
        value => panic!("unknown formal role {value}"),
    }
}

fn guard_is_registered(guard: &str) -> bool {
    matches!(
        guard,
        "user_initiated"
            | "local_user_action"
            | "transcript_matches"
            | "granted_sets_equal"
            | "initiation_permitted"
            | "pairing_routed"
            | "ready_parameters_match"
            | "untried_pairing_candidate"
    )
}

#[test]
fn formal_document_version_is_the_reviewed_revision() {
    assert_eq!(model().document_version, "26.10.22");
}

#[test]
fn formal_constants_are_the_engine_constants() {
    let constants = model().constants;
    let pairing_candidates_max =
        u64::try_from(PAIRING_CANDIDATES_MAX).expect("the candidate limit fits in u64");
    assert_eq!(constants.pairing_candidates_max, pairing_candidates_max);
    assert_eq!(
        constants.pairing_attempts_per_offer,
        u64::from(MAXIMUM_CPACE_ATTEMPTS)
    );
    assert_eq!(
        constants.minimum_remaining_attempts,
        u64::from(MINIMUM_REMAINING_ATTEMPTS)
    );
    assert_eq!(constants.offer_ttl_ms, OFFER_TTL_MS);
    assert_eq!(
        constants.liveness_ping_after_silence_ms,
        LIVENESS_PING_AFTER_SILENCE_MS
    );
    assert_eq!(constants.session_silence_limit_ms, SESSION_SILENCE_LIMIT_MS);
    assert_eq!(constants.revocation_notice_days, REVOCATION_NOTICE_DAYS);
    assert_eq!(constants.pairing_idle_expiry_days, PAIRING_IDLE_EXPIRY_DAYS);
    assert_eq!(constants.identity_offer_grace_ms, IDENTITY_OFFER_GRACE_MS);
    assert_eq!(constants.quit_withdrawal_bound_ms, QUIT_WITHDRAWAL_BOUND_MS);
}

#[test]
fn every_formal_transition_is_implemented() {
    let model = model();
    assert_pairing_rules(&model.pairing);
    assert_session_rules(&model.session);
    assert_operation_rules(&model.operation);
}

#[test]
fn rust_defines_no_transition_absent_from_the_formal_model() {
    let model = model();
    assert_no_extra_pairing_transitions(&model.pairing);
    assert_no_extra_session_transitions(&model.session);
    assert_no_extra_operation_transitions(&model.operation);
}

/// Actions that change or end a stored pairing.
const PAIRING_CHANGING_ACTIONS: &[&str] = &[
    "store_pair_record_atomically",
    "mark_record_confirmed",
    "revoke_unconfirmed_pair_record",
    "mark_record_revoked",
    "send_close_pairing_revoked",
    "destroy_pair_keys",
    "clear_residual_pair_record",
];

/// Events that are an endpoint's withdrawal or the notice of its peer's
/// (RAPP section 4.5).
const WITHDRAWAL_EVENTS: &[&str] = &["service_withdrawn", "peer_withdrawal_notice"];

#[test]
fn no_withdrawal_revokes_a_pairing() {
    let model = model();
    let rules = model
        .pairing
        .transitions
        .iter()
        .chain(&model.session.transitions)
        .filter(|rule| WITHDRAWAL_EVENTS.contains(&rule.event.as_str()))
        .collect::<Vec<_>>();
    assert!(!rules.is_empty(), "the model names withdrawal");
    for rule in rules {
        assert!(
            rule.actions
                .iter()
                .all(|action| !PAIRING_CHANGING_ACTIONS.contains(&action.as_str())),
            "withdrawal changes a pairing: {}",
            rule.event
        );
        assert_ne!(rule.to, "revoked", "{}", rule.event);
        assert_ne!(rule.to, "unpaired", "{}", rule.event);
    }
}

#[test]
fn both_endpoints_withdraw_and_only_the_custodian_shows_its_peer_off() {
    for role in [EndpointRole::Requester, EndpointRole::Proxy] {
        let closing = SessionState::Healthy
            .transition(role, SessionEvent::ServiceWithdrawn, all_guards())
            .expect("an open session closes on withdrawal");
        assert_eq!(closing.state, SessionState::Closing);
        assert_eq!(
            closing.actions.first(),
            Some(&Action::SendCloseServiceWithdrawn)
        );
    }
    let off = PairingState::PairedConnected
        .transition(
            EndpointRole::Proxy,
            PairingEvent::PeerWithdrawalNotice,
            all_guards(),
        )
        .expect("the custodian records the computer's withdrawal");
    assert_eq!(off.state, PairingState::PairedDisconnected);
    assert_eq!(
        off.actions,
        &[Action::RecordLastSession, Action::ShowPeerWithdrawn]
    );
    let back = off
        .state
        .transition(
            EndpointRole::Proxy,
            PairingEvent::SessionHealthy,
            all_guards(),
        )
        .expect("the pairing's next session ends the off display");
    assert_eq!(back.state, PairingState::PairedConnected);
    assert!(
        PairingState::PairedConnected
            .transition(
                EndpointRole::Requester,
                PairingEvent::PeerWithdrawalNotice,
                all_guards(),
            )
            .is_err()
    );
}

/// Actions that tell anyone anything: a user or the peer.
fn is_notice(action: &str) -> bool {
    action.starts_with("show_") || action.starts_with("send_")
}

#[test]
fn no_pairing_expires_while_a_session_to_it_is_established() {
    let model = model();
    let expiries = model
        .pairing
        .transitions
        .iter()
        .filter(|rule| rule.event == "idle_expired")
        .collect::<Vec<_>>();
    assert!(!expiries.is_empty(), "the model names idle expiry");
    for rule in expiries {
        assert!(
            rule.from.values().all(|from| from == "paired_disconnected"),
            "a pairing expires only with no session established"
        );
        assert_eq!(rule.role, "both", "both endpoints expire a pairing");
        assert!(
            rule.actions.iter().all(|action| !is_notice(action)),
            "idle expiry is silent"
        );
    }
    for role in [EndpointRole::Requester, EndpointRole::Proxy] {
        assert!(
            PairingState::PairedConnected
                .transition(role, PairingEvent::IdleExpired, all_guards())
                .is_err()
        );
        let check = PairingState::PairedConnected
            .transition(role, PairingEvent::ExpiryCheck, all_guards())
            .expect("the sweep checks a pairing in session");
        assert_eq!(check.state, PairingState::PairedConnected);
        assert_eq!(check.actions, &[Action::RecordLastSession]);
    }
}

/// Conditions every requester guard that reaches a phone carries
/// (hierarchy specification section 5.2).
const REMOTE_USE_CONDITIONS: &[&str] =
    &["remote use is on", "no card is in a reader attached to it"];

#[test]
fn nothing_reaches_a_phone_while_remote_use_is_off_or_suspended() {
    let model = model();
    for guard in ["initiation_permitted", "untried_pairing_candidate"] {
        let statement = model
            .guards
            .get(guard)
            .unwrap_or_else(|| panic!("the model names {guard}"));
        for condition in REMOTE_USE_CONDITIONS {
            assert!(
                statement.contains(condition),
                "{guard} lacks \"{condition}\""
            );
        }
    }
    let refused = Guards {
        untried_pairing_candidate: false,
        ..all_guards()
    };
    assert!(
        PairingState::Exchanging
            .transition(
                EndpointRole::Requester,
                PairingEvent::AttemptFailed,
                refused
            )
            .is_err()
    );
    let refused = Guards {
        initiation_permitted: false,
        ..all_guards()
    };
    assert!(
        SessionState::Absent
            .transition(EndpointRole::Requester, SessionEvent::Connect, refused)
            .is_err()
    );
}

#[test]
fn a_requester_that_forgets_with_no_session_open_owes_nothing() {
    let forgotten = PairingState::PairedDisconnected
        .transition(
            EndpointRole::Requester,
            PairingEvent::ForgetPairing,
            all_guards(),
        )
        .expect("the holder turns remote use off");
    assert_eq!(forgotten.state, PairingState::Revoked);
    assert!(forgotten.actions.contains(&Action::DestroyPairKeys));
    assert!(!forgotten.actions.contains(&Action::SendClosePairingRevoked));
    let custodian = PairingState::PairedDisconnected
        .transition(
            EndpointRole::Proxy,
            PairingEvent::ForgetPairing,
            all_guards(),
        )
        .expect("the custodian's user forgets the computer");
    assert_eq!(custodian.state, PairingState::Revoking);
}

#[test]
fn every_session_start_and_end_records_the_last_session() {
    let model = model();
    for event in [
        "session_healthy",
        "session_closed",
        "peer_withdrawal_notice",
    ] {
        let rules = model
            .pairing
            .transitions
            .iter()
            .filter(|rule| rule.event == event)
            .collect::<Vec<_>>();
        assert!(!rules.is_empty(), "the model names {event}");
        for rule in rules {
            assert_eq!(
                rule.actions.first().map(String::as_str),
                Some("record_last_session"),
                "{event}"
            );
        }
    }
}

fn assert_pairing_rules(machine: &Machine) {
    assert_eq!(machine.initial, "unpaired");
    assert_eq!(machine.states.len(), PAIRING_STATES.len());
    for rule in &machine.transitions {
        if let Some(guard) = &rule.guard {
            assert!(guard_is_registered(guard), "unknown pairing guard {guard}");
        }
        for from in rule.from.values() {
            for &role in roles(rule) {
                let transition = pairing_state(from)
                    .transition(role, pairing_event(&rule.event), all_guards())
                    .unwrap_or_else(|error| {
                        panic!(
                            "formal pairing rule rejected: {from} / {} / {role:?}: {error:?}",
                            rule.event
                        )
                    });
                assert_eq!(transition.state, pairing_state(&rule.to));
                assert_actions(transition.actions, rule, from, role);
            }
        }
    }
}

fn assert_session_rules(machine: &Machine) {
    assert_eq!(machine.initial, "absent");
    assert_eq!(machine.states.len(), SESSION_STATES.len());
    for rule in &machine.transitions {
        if let Some(guard) = &rule.guard {
            assert!(guard_is_registered(guard), "unknown session guard {guard}");
        }
        for from in rule.from.values() {
            for &role in roles(rule) {
                let transition = session_state(from)
                    .transition(role, session_event(&rule.event), all_guards())
                    .unwrap_or_else(|error| {
                        panic!(
                            "formal session rule rejected: {from} / {} / {role:?}: {error:?}",
                            rule.event
                        )
                    });
                assert_eq!(transition.state, session_state(&rule.to));
                assert_actions(transition.actions, rule, from, role);
            }
        }
    }
}

fn assert_operation_rules(machine: &Machine) {
    assert_eq!(machine.initial, "none");
    assert_eq!(machine.states.len(), OPERATION_STATES.len());
    for rule in &machine.transitions {
        if let Some(guard) = &rule.guard {
            assert!(
                guard_is_registered(guard),
                "unknown operation guard {guard}"
            );
        }
        for from in rule.from.values() {
            for &role in roles(rule) {
                let transition = operation_state(from)
                    .transition(role, operation_event(&rule.event), all_guards())
                    .unwrap_or_else(|error| {
                        panic!(
                            "formal operation rule rejected: {from} / {} / {role:?}: {error:?}",
                            rule.event
                        )
                    });
                assert_eq!(transition.state, operation_state(&rule.to));
                assert_actions(transition.actions, rule, from, role);
            }
        }
    }
}

fn assert_actions(actual: &[Action], rule: &Rule, from: &str, endpoint_role: EndpointRole) {
    let actual = actual
        .iter()
        .copied()
        .map(formal_action_name)
        .collect::<Vec<_>>();
    let expected = rule.actions.iter().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(
        actual, expected,
        "formal action drift: {from} / {} / {endpoint_role:?}",
        rule.event
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "the match is the complete formal action name table"
)]
const fn formal_action_name(action: Action) -> &'static str {
    match action {
        Action::GenerateOffer => "generate_offer",
        Action::GeneratePairingCode => "generate_pairing_code",
        Action::AdvertisePairingMode => "advertise_pairing_mode",
        Action::DisplayPairingCode => "display_pairing_code",
        Action::HidePairingCode => "hide_pairing_code",
        Action::DestroyOffer => "destroy_offer",
        Action::StartPairingBackoff => "start_pairing_backoff",
        Action::ShowAttemptsExhausted => "show_attempts_exhausted",
        Action::ReadOffer => "read_offer",
        Action::BeginCpaceInitiator => "begin_cpace_initiator",
        Action::TryNextCandidate => "try_next_candidate",
        Action::ReserveAttempt => "reserve_attempt",
        Action::CountFailedAttempt => "count_failed_attempt",
        Action::ShowWrongCode => "show_wrong_code",
        Action::ShowNoneInPairingMode => "show_none_in_pairing_mode",
        Action::ConsumeOffer => "consume_offer",
        Action::DerivePairingSecret => "derive_pairing_secret",
        Action::BeginPairingHandshake => "begin_pairing_handshake",
        Action::DeriveChannelIdentifiers => "derive_channel_identifiers",
        Action::DestroyPairingSecret => "destroy_pairing_secret",
        Action::SendPairingHello => "send_pairing_hello",
        Action::SendPairingConfirm => "send_pairing_confirm",
        Action::SendPairingAbortBestEffort => "send_pairing_abort_best_effort",
        Action::DestroyCandidateKeys => "destroy_candidate_keys",
        Action::CloseCandidate => "close_candidate",
        Action::StorePairRecordAtomically => "store_pair_record_atomically",
        Action::SendPairingStored => "send_pairing_stored",
        Action::MarkRecordConfirmed => "mark_record_confirmed",
        Action::ClosePairingChannel => "close_pairing_channel",
        Action::RevokeUnconfirmedPairRecord => "revoke_unconfirmed_pair_record",
        Action::MarkRecordRevoked => "mark_record_revoked",
        Action::SendClosePairingRevoked => "send_close_pairing_revoked",
        Action::CloseSession => "close_session",
        Action::DestroyPairKeys => "destroy_pair_keys",
        Action::RecordLastSession => "record_last_session",
        Action::WithdrawIdentity => "withdraw_identity",
        Action::ShowConnected => "show_connected",
        Action::ShowPairedDisconnected => "show_paired_disconnected",
        Action::ShowForgotten => "show_forgotten",
        Action::ShowPeerForgot => "show_peer_forgot",
        Action::ShowPeerWithdrawn => "show_peer_withdrawn",
        Action::ClearResidualPairRecord => "clear_residual_pair_record",
        Action::OpenTransport => "open_transport",
        Action::SendSessionPreamble => "send_session_preamble",
        Action::BeginKkInitiator => "begin_kk_initiator",
        Action::BeginKkResponder => "begin_kk_responder",
        Action::DeriveSessionIdentifiers => "derive_session_identifiers",
        Action::SendSessionReady => "send_session_ready",
        Action::SendCardStatus => "send_card_status",
        Action::StartLiveness => "start_liveness",
        Action::SendLivenessPing => "send_liveness_ping",
        Action::RecordPeerCloseReason => "record_peer_close_reason",
        Action::SendCloseUserDisconnect => "send_close_user_disconnect",
        Action::SendCloseNormal => "send_close_normal",
        Action::SendCloseProtocolViolation => "send_close_protocol_violation",
        Action::SendCloseServiceWithdrawn => "send_close_service_withdrawn",
        Action::SendCloseCardUnavailable => "send_close_card_unavailable",
        Action::NoteCloseNoticeImpossible => "note_close_notice_impossible",
        Action::ProceedWithoutCloseNotice => "proceed_without_close_notice",
        Action::DestroySessionMaterial => "destroy_session_material",
        Action::DestroyCredentialBuffers => "destroy_credential_buffers",
        Action::ShowDisconnecting => "show_disconnecting",
        Action::ShowConnectionStopped => "show_connection_stopped",
        Action::StartExpiryClock => "start_expiry_clock",
        Action::SendErrorBusy => "send_error_busy",
        Action::SendErrorDuplicateOperation => "send_error_duplicate_operation",
        Action::SendResultUnauthorized => "send_result_unauthorized",
        Action::SendResultUnsupportedParameter => "send_result_unsupported_parameter",
        Action::SendProgressQueued => "send_progress_queued",
        Action::PresentConsent => "present_consent",
        Action::SendProgressConsentShown => "send_progress_consent_shown",
        Action::DismissConsent => "dismiss_consent",
        Action::ExecuteRead => "execute_read",
        Action::CheckRetryFloor => "check_retry_floor",
        Action::ConsumeCardCommand => "consume_card_command",
        Action::SendProgressWaitingForCard => "send_progress_waiting_for_card",
        Action::SendProgressCardWaitEnded => "send_progress_card_wait_ended",
        Action::PromptPinAgain => "prompt_pin_again",
        Action::SendResultCompleted => "send_result_completed",
        Action::SendResultUserCancelled => "send_result_user_cancelled",
        Action::SendResultRetryFloor => "send_result_retry_floor",
        Action::SendResultCardError => "send_result_card_error",
        Action::SendResultOperationExpired => "send_result_operation_expired",
        Action::ClearOperationCredentials => "clear_operation_credentials",
        Action::ContinueCardExchangeLocally => "continue_card_exchange_locally",
        Action::DiscardAnswer => "discard_answer",
        Action::ReleaseCard => "release_card",
        Action::ShowProgress => "show_progress",
        Action::ReleaseResult => "release_result",
        Action::ReleaseFailure => "release_failure",
        Action::ReportOperationLost => "report_operation_lost",
    }
}

fn assert_no_extra_pairing_transitions(machine: &Machine) {
    for &(state_name, state) in PAIRING_STATES {
        for &(event_name, event) in PAIRING_EVENTS {
            for role in [EndpointRole::Requester, EndpointRole::Proxy] {
                if state.transition(role, event, all_guards()).is_ok() {
                    assert!(
                        has_rule(machine, state_name, event_name, role),
                        "Rust-only pairing transition: {state_name} / {event_name} / {role:?}"
                    );
                }
            }
        }
    }
}

fn assert_no_extra_session_transitions(machine: &Machine) {
    for &(state_name, state) in SESSION_STATES {
        for &(event_name, event) in SESSION_EVENTS {
            for role in [EndpointRole::Requester, EndpointRole::Proxy] {
                if state.transition(role, event, all_guards()).is_ok() {
                    assert!(
                        has_rule(machine, state_name, event_name, role),
                        "Rust-only session transition: {state_name} / {event_name} / {role:?}"
                    );
                }
            }
        }
    }
}

fn assert_no_extra_operation_transitions(machine: &Machine) {
    for &(state_name, state) in OPERATION_STATES {
        for &(event_name, event) in OPERATION_EVENTS {
            for role in [EndpointRole::Requester, EndpointRole::Proxy] {
                if state.transition(role, event, all_guards()).is_ok() {
                    assert!(
                        has_rule(machine, state_name, event_name, role),
                        "Rust-only operation transition: {state_name} / {event_name} / {role:?}"
                    );
                }
            }
        }
    }
}

fn has_rule(machine: &Machine, from: &str, event: &str, role: EndpointRole) -> bool {
    machine.transitions.iter().any(|rule| {
        rule.event == event
            && rule.from.values().any(|value| value == from)
            && roles(rule).contains(&role)
    })
}

fn pairing_state(value: &str) -> PairingState {
    PAIRING_STATES
        .iter()
        .find(|(name, _)| *name == value)
        .map_or_else(
            || panic!("unknown pairing state {value}"),
            |(_, state)| *state,
        )
}

fn pairing_event(value: &str) -> PairingEvent {
    PAIRING_EVENTS
        .iter()
        .find(|(name, _)| *name == value)
        .map_or_else(
            || panic!("unknown pairing event {value}"),
            |(_, event)| *event,
        )
}

fn session_state(value: &str) -> SessionState {
    SESSION_STATES
        .iter()
        .find(|(name, _)| *name == value)
        .map_or_else(
            || panic!("unknown session state {value}"),
            |(_, state)| *state,
        )
}

fn session_event(value: &str) -> SessionEvent {
    SESSION_EVENTS
        .iter()
        .find(|(name, _)| *name == value)
        .map_or_else(
            || panic!("unknown session event {value}"),
            |(_, event)| *event,
        )
}

fn operation_state(value: &str) -> OperationState {
    OPERATION_STATES
        .iter()
        .find(|(name, _)| *name == value)
        .map_or_else(
            || panic!("unknown operation state {value}"),
            |(_, state)| *state,
        )
}

fn operation_event(value: &str) -> OperationEvent {
    OPERATION_EVENTS
        .iter()
        .find(|(name, _)| *name == value)
        .map_or_else(
            || panic!("unknown operation event {value}"),
            |(_, event)| *event,
        )
}

const PAIRING_STATES: &[(&str, PairingState)] = &[
    ("unpaired", PairingState::Unpaired),
    ("offering", PairingState::Offering),
    ("exchanging", PairingState::Exchanging),
    ("handshaking", PairingState::Handshaking),
    ("confirming", PairingState::Confirming),
    ("storage_confirming", PairingState::StorageConfirming),
    ("paired_disconnected", PairingState::PairedDisconnected),
    ("paired_connected", PairingState::PairedConnected),
    ("revoking", PairingState::Revoking),
    ("revoked", PairingState::Revoked),
];

const SESSION_STATES: &[(&str, SessionState)] = &[
    ("absent", SessionState::Absent),
    ("connecting", SessionState::Connecting),
    ("authenticating", SessionState::Authenticating),
    ("healthy", SessionState::Healthy),
    ("closing", SessionState::Closing),
    ("closed", SessionState::Closed),
];

const OPERATION_STATES: &[(&str, OperationState)] = &[
    ("none", OperationState::None),
    ("requested", OperationState::Requested),
    ("queued", OperationState::Queued),
    ("awaiting_consent", OperationState::AwaitingConsent),
    ("executing", OperationState::Executing),
    ("completed", OperationState::Completed),
    ("rejected", OperationState::Rejected),
    ("cancelled", OperationState::Cancelled),
];

const PAIRING_EVENTS: &[(&str, PairingEvent)] = &[
    ("start_pairing", PairingEvent::StartPairing),
    (
        "offer_expired_or_cancelled",
        PairingEvent::OfferExpiredOrCancelled,
    ),
    ("attempt_started", PairingEvent::AttemptStarted),
    ("code_entered", PairingEvent::CodeEntered),
    ("attempt_failed", PairingEvent::AttemptFailed),
    ("last_attempt_failed", PairingEvent::LastAttemptFailed),
    ("last_candidate_failed", PairingEvent::LastCandidateFailed),
    ("no_custodian_tried", PairingEvent::NoCustodianTried),
    ("key_confirmed", PairingEvent::KeyConfirmed),
    (
        "handshake_authenticated",
        PairingEvent::HandshakeAuthenticated,
    ),
    ("handshake_failed", PairingEvent::HandshakeFailed),
    ("hello_verified", PairingEvent::HelloVerified),
    ("both_confirmed", PairingEvent::BothConfirmed),
    (
        "denied_aborted_or_timed_out",
        PairingEvent::DeniedAbortedOrTimedOut,
    ),
    ("peer_storage_confirmed", PairingEvent::PeerStorageConfirmed),
    ("session_healthy", PairingEvent::SessionHealthy),
    ("session_closed", PairingEvent::SessionClosed),
    ("forget_pairing", PairingEvent::ForgetPairing),
    ("expiry_check", PairingEvent::ExpiryCheck),
    ("idle_expired", PairingEvent::IdleExpired),
    ("revocation_notice_sent", PairingEvent::RevocationNoticeSent),
    ("notice_window_expired", PairingEvent::NoticeWindowExpired),
    ("peer_revocation_notice", PairingEvent::PeerRevocationNotice),
    ("peer_withdrawal_notice", PairingEvent::PeerWithdrawalNotice),
];

const SESSION_EVENTS: &[(&str, SessionEvent)] = &[
    ("connect", SessionEvent::Connect),
    ("preamble_received", SessionEvent::PreambleReceived),
    ("transport_connected", SessionEvent::TransportConnected),
    ("transport_failed", SessionEvent::TransportFailed),
    ("handshake_complete", SessionEvent::HandshakeComplete),
    (
        "handshake_complete_while_revoking",
        SessionEvent::HandshakeCompleteWhileRevoking,
    ),
    ("ready_verified", SessionEvent::ReadyVerified),
    ("candidate_failure", SessionEvent::CandidateFailure),
    (
        "authenticated_protocol_violation",
        SessionEvent::AuthenticatedProtocolViolation,
    ),
    ("peer_silent", SessionEvent::PeerSilent),
    ("silence_limit_reached", SessionEvent::SilenceLimitReached),
    ("user_disconnect", SessionEvent::UserDisconnect),
    ("local_close_requested", SessionEvent::LocalCloseRequested),
    ("service_withdrawn", SessionEvent::ServiceWithdrawn),
    ("card_unavailable", SessionEvent::CardUnavailable),
    ("peer_close_received", SessionEvent::PeerCloseReceived),
    (
        "session_integrity_failed",
        SessionEvent::SessionIntegrityFailed,
    ),
    (
        "close_requested_by_pairing",
        SessionEvent::CloseRequestedByPairing,
    ),
    (
        "close_complete_or_deadline",
        SessionEvent::CloseCompleteOrDeadline,
    ),
];

const OPERATION_EVENTS: &[(&str, OperationEvent)] = &[
    ("request_received", OperationEvent::RequestReceived),
    ("request_duplicate", OperationEvent::RequestDuplicate),
    ("request_while_busy", OperationEvent::RequestWhileBusy),
    ("request_unauthorized", OperationEvent::RequestUnauthorized),
    ("request_unsupported", OperationEvent::RequestUnsupported),
    ("card_held_elsewhere", OperationEvent::CardHeldElsewhere),
    (
        "card_acquired_for_consent",
        OperationEvent::CardAcquiredForConsent,
    ),
    (
        "card_acquired_for_read",
        OperationEvent::CardAcquiredForRead,
    ),
    ("user_denied", OperationEvent::UserDenied),
    ("user_approved", OperationEvent::UserApproved),
    ("waiting_for_card", OperationEvent::WaitingForCard),
    ("card_found", OperationEvent::CardFound),
    ("wrong_pin", OperationEvent::WrongPin),
    ("retry_floor_refused", OperationEvent::RetryFloorRefused),
    ("card_success", OperationEvent::CardSuccess),
    ("card_error", OperationEvent::CardError),
    ("request_expired", OperationEvent::RequestExpired),
    ("session_closed", OperationEvent::SessionClosed),
    ("request_sent", OperationEvent::RequestSent),
    ("progress_received", OperationEvent::ProgressReceived),
    (
        "result_completed_received",
        OperationEvent::ResultCompletedReceived,
    ),
    (
        "result_rejected_received",
        OperationEvent::ResultRejectedReceived,
    ),
    (
        "result_cancelled_received",
        OperationEvent::ResultCancelledReceived,
    ),
];
