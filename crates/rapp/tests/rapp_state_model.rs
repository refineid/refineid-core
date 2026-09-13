//! Executable conformance against the normative RAPP state-machine grammar.

use refineid_rapp::{
    Action, EndpointRole, Guards, OperationEvent, OperationState, PairingEvent, PairingState,
    SessionEvent, SessionState,
};
use serde::Deserialize;

const MODEL: &str = include_str!("../../../docs/protocols/rapp-state-machine-v26.9.13.yaml");

#[derive(Deserialize)]
struct Model {
    document_version: String,
    pairing: Machine,
    session: Machine,
    operation: Machine,
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
    serde_yaml::from_str(MODEL).expect("normative RAPP state model must parse")
}

const fn all_guards() -> Guards {
    Guards {
        user_initiated: true,
        offer_valid_and_supported: true,
        offer_live: true,
        transcript_matches: true,
        granted_sets_equal: true,
        pairing_paired: true,
        initiation_permitted: true,
        ready_parameters_match: true,
        deadline_not_expired: true,
        another_session_live: true,
        admission_permitted: true,
        hash_echo_matches: true,
        hash_matches: true,
        zero_transmissions: true,
        proven_no_transmission: true,
        profile_has_no_consequential_command: true,
    }
}

fn roles(rule: &Rule) -> &'static [EndpointRole] {
    match rule.role.as_str() {
        "requester" => &[EndpointRole::Requester],
        "proxy" => &[EndpointRole::Proxy],
        "both" => &[EndpointRole::Requester, EndpointRole::Proxy],
        value => panic!("unknown formal role {value}"),
    }
}

fn guard_is_registered(guard: &str) -> bool {
    matches!(
        guard,
        "user_initiated"
            | "local_user_action"
            | "offer_valid_and_supported"
            | "offer_live"
            | "transcript_matches"
            | "granted_sets_equal"
            | "pairing_paired"
            | "initiation_permitted"
            | "ready_parameters_match"
            | "deadline_not_expired"
            | "another_session_live"
            | "admission_permitted"
            | "hash_echo_matches"
            | "hash_matches"
            | "zero_transmissions"
            | "proven_no_transmission"
            | "profile_has_no_consequential_command"
    )
}

#[test]
fn formal_document_version_is_the_reviewed_revision() {
    assert_eq!(model().document_version, "26.9.13");
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
        Action::GenerateOfferId => "generate_offer_id",
        Action::GeneratePairingSecret => "generate_pairing_secret",
        Action::StartOfferExpiry => "start_offer_expiry",
        Action::DisplayPairingCode => "display_pairing_code",
        Action::HidePairingCode => "hide_pairing_code",
        Action::SelectOneCandidate => "select_one_candidate",
        Action::ConnectCandidate => "connect_candidate",
        Action::PreparePairingResponder => "prepare_pairing_responder",
        Action::BeginPairingHandshakeInitiator => "begin_pairing_handshake_initiator",
        Action::DeriveChannelIdentifiers => "derive_channel_identifiers",
        Action::DestroyPairingSecret => "destroy_pairing_secret",
        Action::StopAcceptingCandidates => "stop_accepting_candidates",
        Action::SendPairingHello => "send_pairing_hello",
        Action::ShowPeerAndRequestedGrants => "show_peer_and_requested_grants",
        Action::DiscardCandidate => "discard_candidate",
        Action::RetainOffer => "retain_offer",
        Action::InvalidateOffer => "invalidate_offer",
        Action::CloseCandidate => "close_candidate",
        Action::StorePairRecordAtomically => "store_pair_record_atomically",
        Action::ClosePairingChannel => "close_pairing_channel",
        Action::SendPairingAbortBestEffort => "send_pairing_abort_best_effort",
        Action::DestroyCandidateKeys => "destroy_candidate_keys",
        Action::ShowConnected => "show_connected",
        Action::ShowPairedDisconnected => "show_paired_disconnected",
        Action::ShowChecking => "show_checking",
        Action::ShowDisconnecting => "show_disconnecting",
        Action::ShowConnectionStopped => "show_connection_stopped",
        Action::ShowRevoked => "show_revoked",
        Action::SendCloseBestEffort(_) => "send_close_best_effort",
        Action::CloseSession => "close_session",
        Action::DestroyPairKeys => "destroy_pair_keys",
        Action::DestroyRelayTokens => "destroy_relay_tokens",
        Action::ClearPairMetadata => "clear_pair_metadata",
        Action::ClearResidualPairRecord => "clear_residual_pair_record",
        Action::RecordPeerInitiated => "record_peer_initiated",
        Action::SelectOneTransport => "select_one_transport",
        Action::OpenTransport => "open_transport",
        Action::AssociatePairingFromRendezvous => "associate_pairing_from_rendezvous",
        Action::BeginKkInitiator => "begin_kk_initiator",
        Action::BeginKkResponder => "begin_kk_responder",
        Action::DeriveSessionIdentifiers => "derive_session_identifiers",
        Action::SendSessionReady => "send_session_ready",
        Action::SendErrorBusy => "send_error_busy",
        Action::StartAuthenticatedLiveness => "start_authenticated_liveness",
        Action::BlockNewOperations => "block_new_operations",
        Action::StartBackoffAndDeadline => "start_backoff_and_deadline",
        Action::ResetBackoff => "reset_backoff",
        Action::RecordPeerCloseReason => "record_peer_close_reason",
        Action::CountCandidateFailureHint => "count_candidate_failure_hint",
        Action::NoteCloseNoticeImpossible => "note_close_notice_impossible",
        Action::ProceedWithoutCloseNotice => "proceed_without_close_notice",
        Action::AbortCandidate => "abort_candidate",
        Action::DestroySessionMaterial => "destroy_session_material",
        Action::DestroyCredentialBuffers => "destroy_credential_buffers",
        Action::PersistTerminalSessionRecord => "persist_terminal_session_record",
        Action::ValidateSchemaHashExpiryAndContext => "validate_schema_hash_expiry_and_context",
        Action::StartExpiryClock => "start_expiry_clock",
        Action::BeginSafePrerequisiteReads => "begin_safe_prerequisite_reads",
        Action::PresentConsentPerProfile => "present_consent_per_profile",
        Action::DismissConsent => "dismiss_consent",
        Action::ClearOperationCredentials => "clear_operation_credentials",
        Action::ClearAllActiveCredentials => "clear_all_active_credentials",
        Action::RemoveRejectedCredentialAndDerivedState => {
            "remove_rejected_credential_and_derived_state"
        }
        Action::SendPrepared => "send_prepared",
        Action::SendResultCompleted => "send_result_completed",
        Action::SendResultDenied => "send_result_denied",
        Action::SendResultCancelled => "send_result_cancelled",
        Action::SendResultRejected => "send_result_rejected",
        Action::SendResultRetryPolicyRefused => "send_result_retry_policy_refused",
        Action::SendResultCredentialRejectedBestEffort => {
            "send_result_credential_rejected_best_effort"
        }
        Action::SendResultAmbiguousBestEffort => "send_result_ambiguous_best_effort",
        Action::RequestSessionClose => "request_session_close",
        Action::RequestSessionCloseCredentialRejected => {
            "request_session_close_credential_rejected"
        }
        Action::RevokePairAfterCredentialRejection => "revoke_pair_after_credential_rejection",
        Action::RequestSessionCloseAmbiguous => "request_session_close_ambiguous",
        Action::SendOperationCancel => "send_operation_cancel",
        Action::DurablyWriteCommitBeforeTransmission => "durably_write_commit_before_transmission",
        Action::ConsumeNonClonableCommand => "consume_non_clonable_command",
        Action::IncrementTransmissionCountOnce => "increment_transmission_count_once",
        Action::RecordAdvisoryCancel => "record_advisory_cancel",
        Action::ContinueCardExchangeLocally => "continue_card_exchange_locally",
        Action::NoteResultDeliveryImpossible => "note_result_delivery_impossible",
        Action::PersistResult => "persist_result",
        Action::PersistRejection => "persist_rejection",
        Action::PersistCancelled => "persist_cancelled",
        Action::PersistAmbiguous => "persist_ambiguous",
        Action::PersistCompleted => "persist_completed",
        Action::PersistDeliveryUncertain => "persist_delivery_uncertain",
        Action::RetainResultUnderLocalStorage => "retain_result_under_local_storage",
        Action::ReleaseResult => "release_result",
        Action::ProhibitRetry => "prohibit_retry",
        Action::ProhibitCardRetry => "prohibit_card_retry",
        Action::ComputeRequestHash => "compute_request_hash",
        Action::JournalRequest => "journal_request",
        Action::JournalPrepared => "journal_prepared",
        Action::JournalCommitIntentDurably => "journal_commit_intent_durably",
        Action::JournalCompleted => "journal_completed",
        Action::JournalDenied => "journal_denied",
        Action::JournalCancelled => "journal_cancelled",
        Action::JournalRejected => "journal_rejected",
        Action::JournalCredentialRejected => "journal_credential_rejected",
        Action::JournalAmbiguous => "journal_ambiguous",
        Action::SendResultAck => "send_result_ack",
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
    ("offer_active", PairingState::OfferActive),
    ("handshaking", PairingState::Handshaking),
    ("confirming", PairingState::Confirming),
    ("paired_disconnected", PairingState::PairedDisconnected),
    ("paired_connected", PairingState::PairedConnected),
    ("revoked", PairingState::Revoked),
];

const SESSION_STATES: &[(&str, SessionState)] = &[
    ("absent", SessionState::Absent),
    ("connecting", SessionState::Connecting),
    ("authenticating", SessionState::Authenticating),
    ("healthy", SessionState::Healthy),
    ("checking", SessionState::Checking),
    ("closing", SessionState::Closing),
    ("closed", SessionState::Closed),
];

const OPERATION_STATES: &[(&str, OperationState)] = &[
    ("none", OperationState::None),
    ("requested", OperationState::Requested),
    ("awaiting_consent", OperationState::AwaitingConsent),
    ("prepared", OperationState::Prepared),
    ("committed", OperationState::Committed),
    ("executing", OperationState::Executing),
    ("result_pending", OperationState::ResultPending),
    ("completed", OperationState::Completed),
    ("denied", OperationState::Denied),
    ("cancelled", OperationState::Cancelled),
    ("rejected", OperationState::Rejected),
    ("credential_rejected", OperationState::CredentialRejected),
    ("ambiguous", OperationState::Ambiguous),
    ("delivery_uncertain", OperationState::DeliveryUncertain),
];

const PAIRING_EVENTS: &[(&str, PairingEvent)] = &[
    ("create_offer", PairingEvent::CreateOffer),
    ("offer_scanned", PairingEvent::OfferScanned),
    ("candidate_connected", PairingEvent::CandidateConnected),
    (
        "offer_expired_or_cancelled",
        PairingEvent::OfferExpiredOrCancelled,
    ),
    (
        "handshake_authenticated",
        PairingEvent::HandshakeAuthenticated,
    ),
    ("handshake_failed", PairingEvent::HandshakeFailed),
    ("both_users_confirmed", PairingEvent::BothUsersConfirmed),
    (
        "denied_aborted_or_timed_out",
        PairingEvent::DeniedAbortedOrTimedOut,
    ),
    ("session_healthy", PairingEvent::SessionHealthy),
    ("session_closed", PairingEvent::SessionClosed),
    ("forget_pairing", PairingEvent::ForgetPairing),
    (
        "authenticated_protocol_violation",
        PairingEvent::AuthenticatedProtocolViolation,
    ),
    ("local_revoke", PairingEvent::LocalRevoke),
    ("peer_revocation_notice", PairingEvent::PeerRevocationNotice),
];

const SESSION_EVENTS: &[(&str, SessionEvent)] = &[
    ("connect", SessionEvent::Connect),
    ("transport_accepted", SessionEvent::TransportAccepted),
    ("transport_connected", SessionEvent::TransportConnected),
    ("transport_failed", SessionEvent::TransportFailed),
    ("user_disconnect", SessionEvent::UserDisconnect),
    ("handshake_complete", SessionEvent::HandshakeComplete),
    (
        "second_session_detected",
        SessionEvent::SecondSessionDetected,
    ),
    ("ready_verified", SessionEvent::ReadyVerified),
    ("candidate_failure", SessionEvent::CandidateFailure),
    ("busy_received", SessionEvent::BusyReceived),
    ("peer_close_received", SessionEvent::PeerCloseReceived),
    (
        "authenticated_protocol_violation",
        SessionEvent::AuthenticatedProtocolViolation,
    ),
    ("liveness_missed", SessionEvent::LivenessMissed),
    ("liveness_restored", SessionEvent::LivenessRestored),
    (
        "liveness_deadline_expired",
        SessionEvent::LivenessDeadlineExpired,
    ),
    ("local_close_requested", SessionEvent::LocalCloseRequested),
    ("credential_rejected", SessionEvent::CredentialRejected),
    (
        "card_completion_ambiguous",
        SessionEvent::CardCompletionAmbiguous,
    ),
    (
        "session_integrity_failed",
        SessionEvent::SessionIntegrityFailed,
    ),
    (
        "close_requested_by_pairing",
        SessionEvent::CloseRequestedByPairing,
    ),
    (
        "local_security_shutdown",
        SessionEvent::LocalSecurityShutdown,
    ),
    (
        "close_complete_or_deadline",
        SessionEvent::CloseCompleteOrDeadline,
    ),
];

const OPERATION_EVENTS: &[(&str, OperationEvent)] = &[
    ("operation_request_sent", OperationEvent::RequestSent),
    (
        "operation_request_received",
        OperationEvent::RequestReceived,
    ),
    ("request_valid", OperationEvent::RequestValid),
    (
        "request_invalid_or_unsupported",
        OperationEvent::RequestInvalidOrUnsupported,
    ),
    ("cancel_received", OperationEvent::CancelReceived),
    ("request_expired", OperationEvent::RequestExpired),
    ("user_denied", OperationEvent::UserDenied),
    ("retry_policy_refused", OperationEvent::RetryPolicyRefused),
    (
        "invalid_can_or_pin1_or_pin2",
        OperationEvent::InvalidCanOrPin1OrPin2,
    ),
    ("safe_reads_complete", OperationEvent::SafeReadsComplete),
    (
        "user_approved_and_proxy_ready",
        OperationEvent::UserApprovedAndProxyReady,
    ),
    ("valid_commit", OperationEvent::ValidCommit),
    ("begin_card_command", OperationEvent::BeginCardCommand),
    (
        "crash_recovered_without_terminal_result",
        OperationEvent::CrashRecoveredWithoutTerminalResult,
    ),
    ("card_success", OperationEvent::CardSuccess),
    ("card_policy_rejection", OperationEvent::CardPolicyRejection),
    (
        "card_removed_before_transmit",
        OperationEvent::CardRemovedBeforeTransmit,
    ),
    (
        "card_removed_or_transport_uncertain",
        OperationEvent::CardRemovedOrTransportUncertain,
    ),
    (
        "session_closed_post_commit",
        OperationEvent::SessionClosedPostCommit,
    ),
    ("valid_result_ack", OperationEvent::ValidResultAck),
    (
        "session_closed_before_ack",
        OperationEvent::SessionClosedBeforeAck,
    ),
    ("prepared_received", OperationEvent::PreparedReceived),
    (
        "cancel_sent_or_request_expired",
        OperationEvent::CancelSentOrRequestExpired,
    ),
    ("commit_sent", OperationEvent::CommitSent),
    (
        "result_completed_received",
        OperationEvent::ResultCompletedReceived,
    ),
    (
        "result_denied_received",
        OperationEvent::ResultDeniedReceived,
    ),
    (
        "result_cancelled_received",
        OperationEvent::ResultCancelledReceived,
    ),
    (
        "result_rejected_received",
        OperationEvent::ResultRejectedReceived,
    ),
    (
        "result_credential_rejected_received",
        OperationEvent::ResultCredentialRejectedReceived,
    ),
    (
        "result_ambiguous_received",
        OperationEvent::ResultAmbiguousReceived,
    ),
    (
        "session_closed_pre_commit",
        OperationEvent::SessionClosedPreCommit,
    ),
];
