//! Mandatory semantic decoding for every authenticated RAPP message.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    CardOperationError, CloseReason, Envelope, GrantsHash, LIVENESS_CHALLENGE_SIZE,
    MANDATORY_PAIRING_SUITE, MANDATORY_SESSION_SUITE, MessageType, OperationId,
    OperationProgressMessage, OperationReference, OperationRequest, OperationResultMessage,
    OperationState, PairId, PingChallenge, ProfileName, RequestHash, SESSION_READY_NONCE_SIZE,
    VISIBLE_WIRE_VERSION, WireValue,
};

/// Pairing-channel parameter echo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedParameters {
    /// Hash of the offer content with the pairing secret removed.
    pub offer_hash: [u8; 32],
    /// Transport profile carrying the pairing channel.
    pub transport_profile: String,
    /// Selected transport candidate within the offer.
    pub candidate_id: String,
}

/// Authenticated pairing peer introduction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingHelloMessage {
    /// Negotiated-parameter echo bound to the local view.
    pub parameters: NegotiatedParameters,
    /// Peer-chosen label, not an identity.
    pub display_name: String,
    /// Peer platform description, not an identity.
    pub platform: String,
    /// Profiles the requester asks to be granted.
    pub requested_profiles: Option<Vec<ProfileName>>,
}

/// Explicit grant confirmation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingConfirmMessage {
    /// Granted profile set; both confirmations must carry equal sets.
    pub granted_profiles: Vec<ProfileName>,
}

/// Authenticated pairing cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingAbortMessage {
    /// Bounded abort reason label.
    pub reason: String,
}

/// Fresh-session parameter echo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionParameters {
    /// Transport profile carrying this session.
    pub transport_profile: String,
    /// Transport candidate the connection used.
    pub candidate_id: String,
    /// Hash of the granted profile set bound at pairing confirmation.
    pub grants_hash: GrantsHash,
}

/// Session-ready proof carrying a fresh nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionReadyMessage {
    /// Session-parameter echo bound to the local view.
    pub parameters: SessionParameters,
    /// Fresh random nonce for this ready proof.
    pub nonce: [u8; SESSION_READY_NONCE_SIZE],
}

/// Authenticated close notice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCloseMessage {
    /// Registered close reason.
    pub reason: CloseReason,
    /// Highest peer sequence accepted before closing.
    pub last_received_sequence: u64,
}

/// Authenticated ping or pong body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LivenessMessage {
    /// Fresh challenge, echoed exactly by the answering pong.
    pub challenge: PingChallenge,
    /// Highest peer sequence accepted so far.
    pub last_received_sequence: u64,
}

/// Advisory operation cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelMessage {
    /// Operation identifier and request-hash echo.
    pub reference: OperationReference,
    /// Bounded cancellation reason label.
    pub reason: Option<String>,
}

/// Durable status reconciliation answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusReport {
    /// Queried operation identifier.
    pub operation_id: OperationId,
    /// Whether the proxy journal holds this operation.
    pub known: bool,
    /// Journaled terminal state of a known operation.
    pub state: Option<OperationState>,
    /// Journaled request hash of a known operation.
    pub request_hash: Option<RequestHash>,
}

/// Stable generic protocol error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolErrorMessage {
    /// A live session already serves this pairing.
    Busy,
    /// Referenced operation is unknown or terminal; a normal race.
    UnknownOperation(Option<OperationId>),
}

/// Fully typed authenticated message. No raw map crosses this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedMessage {
    /// Authenticated pairing peer introduction.
    PairingHello(PairingHelloMessage),
    /// Explicit grant confirmation.
    PairingConfirm(PairingConfirmMessage),
    /// Authenticated pairing cancellation.
    PairingAbort(PairingAbortMessage),
    /// Session-ready parameter echo and nonce.
    SessionReady(SessionReadyMessage),
    /// Authenticated close notice.
    SessionClose(SessionCloseMessage),
    /// Liveness challenge.
    LivenessPing(LivenessMessage),
    /// Liveness challenge echo.
    LivenessPong(LivenessMessage),
    /// Typed credential-operation request.
    OperationRequest(OperationRequest),
    /// Proxy is ready to execute exactly the committed request.
    OperationPrepared(OperationReference),
    /// Requester's point of no return.
    OperationCommit(OperationReference),
    /// Operation cancellation; advisory after commit.
    OperationCancel(CancelMessage),
    /// Profile-defined operation result.
    OperationResult(OperationResultMessage),
    /// Acknowledgment of a completed result.
    OperationResultAck(OperationReference),
    /// Durable status reconciliation query.
    OperationStatusRequest(OperationId),
    /// Durable status reconciliation answer.
    OperationStatus(StatusReport),
    /// Advisory operation progress update.
    OperationProgress(OperationProgressMessage),
    /// Stable generic protocol error.
    Error(ProtocolErrorMessage),
}

impl TypedMessage {
    /// Semantically decode a decrypted, envelope-validated message.
    ///
    /// # Errors
    /// [`MessageError`] on a field, schema, or typed-operation violation.
    pub fn from_envelope(
        envelope: Envelope,
        pair_id: PairId,
        local_start_ms: u64,
    ) -> Result<Self, MessageError> {
        let session_id = envelope.session_id;
        let message = match envelope.message_type {
            MessageType::PairingHello => {
                Self::PairingHello(pairing_hello_from_body(envelope.body)?)
            }
            MessageType::PairingConfirm => {
                Self::PairingConfirm(pairing_confirm_from_body(envelope.body)?)
            }
            MessageType::PairingAbort => {
                Self::PairingAbort(pairing_abort_from_body(envelope.body)?)
            }
            MessageType::SessionReady => {
                Self::SessionReady(session_ready_from_body(envelope.body)?)
            }
            MessageType::SessionClose => {
                Self::SessionClose(session_close_from_body(envelope.body)?)
            }
            MessageType::LivenessPing => Self::LivenessPing(liveness_from_body(envelope.body)?),
            MessageType::LivenessPong => Self::LivenessPong(liveness_from_body(envelope.body)?),
            MessageType::OperationRequest => Self::OperationRequest(
                OperationRequest::from_wire_body(
                    envelope.body,
                    pair_id,
                    session_id,
                    local_start_ms,
                )
                .map_err(MessageError::Operation)?,
            ),
            MessageType::OperationPrepared => Self::OperationPrepared(
                OperationReference::from_wire_body(envelope.body)
                    .map_err(MessageError::Operation)?,
            ),
            MessageType::OperationCommit => Self::OperationCommit(
                OperationReference::from_wire_body(envelope.body)
                    .map_err(MessageError::Operation)?,
            ),
            MessageType::OperationCancel => Self::OperationCancel(cancel_from_body(envelope.body)?),
            MessageType::OperationResult => Self::OperationResult(
                OperationResultMessage::from_wire_body(envelope.body)
                    .map_err(MessageError::Operation)?,
            ),
            MessageType::OperationResultAck => Self::OperationResultAck(
                OperationReference::from_wire_body(envelope.body)
                    .map_err(MessageError::Operation)?,
            ),
            MessageType::OperationStatusRequest => {
                Self::OperationStatusRequest(status_request_from_body(envelope.body)?)
            }
            MessageType::OperationStatus => Self::OperationStatus(status_from_body(envelope.body)?),
            MessageType::OperationProgress => Self::OperationProgress(
                OperationProgressMessage::from_wire_body(envelope.body)
                    .map_err(MessageError::Operation)?,
            ),
            MessageType::Error => Self::Error(error_from_body(envelope.body)?),
        };
        Ok(message)
    }

    /// Registered envelope discriminant.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::PairingHello(_) => MessageType::PairingHello,
            Self::PairingConfirm(_) => MessageType::PairingConfirm,
            Self::PairingAbort(_) => MessageType::PairingAbort,
            Self::SessionReady(_) => MessageType::SessionReady,
            Self::SessionClose(_) => MessageType::SessionClose,
            Self::LivenessPing(_) => MessageType::LivenessPing,
            Self::LivenessPong(_) => MessageType::LivenessPong,
            Self::OperationRequest(_) => MessageType::OperationRequest,
            Self::OperationPrepared(_) => MessageType::OperationPrepared,
            Self::OperationCommit(_) => MessageType::OperationCommit,
            Self::OperationCancel(_) => MessageType::OperationCancel,
            Self::OperationResult(_) => MessageType::OperationResult,
            Self::OperationResultAck(_) => MessageType::OperationResultAck,
            Self::OperationStatusRequest(_) => MessageType::OperationStatusRequest,
            Self::OperationStatus(_) => MessageType::OperationStatus,
            Self::OperationProgress(_) => MessageType::OperationProgress,
            Self::Error(_) => MessageType::Error,
        }
    }

    /// Encode the exact registered body for secure-channel sequence allocation.
    ///
    /// # Errors
    /// [`MessageError`] when a field fails its registered validation.
    pub fn to_wire_body(&self) -> Result<BTreeMap<String, WireValue>, MessageError> {
        match self {
            Self::PairingHello(value) => pairing_hello_to_body(value),
            Self::PairingConfirm(value) => pairing_confirm_to_body(value),
            Self::PairingAbort(value) => pairing_abort_to_body(value),
            Self::SessionReady(value) => session_ready_to_body(value),
            Self::SessionClose(value) => Ok(session_close_to_body(*value)),
            Self::LivenessPing(value) | Self::LivenessPong(value) => Ok(liveness_to_body(*value)),
            Self::OperationRequest(value) => value.to_wire_body().map_err(MessageError::Operation),
            Self::OperationPrepared(value)
            | Self::OperationCommit(value)
            | Self::OperationResultAck(value) => Ok(value.to_wire_body()),
            Self::OperationCancel(value) => cancel_to_body(value),
            Self::OperationResult(value) => value.to_wire_body().map_err(MessageError::Operation),
            Self::OperationStatusRequest(operation_id) => {
                let mut body = BTreeMap::new();
                body.insert(
                    "operation_id".into(),
                    WireValue::Bytes(operation_id.as_bytes().to_vec()),
                );
                Ok(body)
            }
            Self::OperationStatus(value) => status_to_body(value),
            Self::OperationProgress(value) => Ok(value.to_wire_body()),
            Self::Error(value) => Ok(error_to_body(*value)),
        }
    }
}

fn pairing_hello_to_body(
    value: &PairingHelloMessage,
) -> Result<BTreeMap<String, WireValue>, MessageError> {
    validate_label(&value.display_name, "display_name")?;
    validate_label(&value.platform, "platform")?;
    validate_transport_name(&value.parameters.transport_profile, "transport_profile")?;
    validate_label(&value.parameters.candidate_id, "candidate_id")?;
    if let Some(profiles) = value.requested_profiles.as_ref() {
        validate_profile_set(profiles)?;
    }
    let mut body = BTreeMap::new();
    body.insert(
        "parameters".into(),
        WireValue::Map(negotiated_parameters_to_map(&value.parameters)),
    );
    body.insert(
        "display_name".into(),
        WireValue::Text(value.display_name.clone()),
    );
    body.insert("platform".into(), WireValue::Text(value.platform.clone()));
    if let Some(profiles) = value.requested_profiles.as_ref() {
        body.insert("requested_profiles".into(), profile_array(profiles));
    }
    Ok(body)
}

fn pairing_hello_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<PairingHelloMessage, MessageError> {
    let parameters = negotiated_parameters_from_map(take_map(&mut body, "parameters")?)?;
    let display_name = take_text(&mut body, "display_name")?;
    let platform = take_text(&mut body, "platform")?;
    let requested_profiles = match body.remove("requested_profiles") {
        None => None,
        Some(WireValue::Array(values)) => Some(profiles_from_array(values)?),
        Some(_) => return Err(MessageError::InvalidField("requested_profiles")),
    };
    require_empty(&body)?;
    validate_label(&display_name, "display_name")?;
    validate_label(&platform, "platform")?;
    Ok(PairingHelloMessage {
        parameters,
        display_name,
        platform,
        requested_profiles,
    })
}

fn pairing_confirm_to_body(
    value: &PairingConfirmMessage,
) -> Result<BTreeMap<String, WireValue>, MessageError> {
    validate_profile_set(&value.granted_profiles)?;
    let mut body = BTreeMap::new();
    body.insert(
        "granted_profiles".into(),
        profile_array(&value.granted_profiles),
    );
    Ok(body)
}

fn pairing_confirm_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<PairingConfirmMessage, MessageError> {
    let profiles = match body.remove("granted_profiles") {
        Some(WireValue::Array(values)) => profiles_from_array(values)?,
        _ => return Err(MessageError::InvalidField("granted_profiles")),
    };
    require_empty(&body)?;
    Ok(PairingConfirmMessage {
        granted_profiles: profiles,
    })
}

fn pairing_abort_to_body(
    value: &PairingAbortMessage,
) -> Result<BTreeMap<String, WireValue>, MessageError> {
    validate_label(&value.reason, "reason")?;
    let mut body = BTreeMap::new();
    body.insert("reason".into(), WireValue::Text(value.reason.clone()));
    Ok(body)
}

fn pairing_abort_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<PairingAbortMessage, MessageError> {
    let reason = take_text(&mut body, "reason")?;
    require_empty(&body)?;
    validate_label(&reason, "reason")?;
    Ok(PairingAbortMessage { reason })
}

fn negotiated_parameters_to_map(value: &NegotiatedParameters) -> BTreeMap<String, WireValue> {
    let mut map = BTreeMap::new();
    map.insert("version".into(), version_value());
    map.insert(
        "suite".into(),
        WireValue::Text(MANDATORY_PAIRING_SUITE.into()),
    );
    map.insert(
        "offer_hash".into(),
        WireValue::Bytes(value.offer_hash.to_vec()),
    );
    map.insert(
        "transport_profile".into(),
        WireValue::Text(value.transport_profile.clone()),
    );
    map.insert(
        "candidate_id".into(),
        WireValue::Text(value.candidate_id.clone()),
    );
    map
}

fn negotiated_parameters_from_map(
    mut map: BTreeMap<String, WireValue>,
) -> Result<NegotiatedParameters, MessageError> {
    require_version(&mut map)?;
    require_suite(&mut map, MANDATORY_PAIRING_SUITE)?;
    let offer_hash = take_fixed::<32>(&mut map, "offer_hash")?;
    let transport_profile = take_text(&mut map, "transport_profile")?;
    let candidate_id = take_text(&mut map, "candidate_id")?;
    require_empty(&map)?;
    validate_transport_name(&transport_profile, "transport_profile")?;
    validate_label(&candidate_id, "candidate_id")?;
    Ok(NegotiatedParameters {
        offer_hash,
        transport_profile,
        candidate_id,
    })
}

fn session_ready_to_body(
    value: &SessionReadyMessage,
) -> Result<BTreeMap<String, WireValue>, MessageError> {
    validate_transport_name(&value.parameters.transport_profile, "transport_profile")?;
    validate_label(&value.parameters.candidate_id, "candidate_id")?;
    let mut parameters = BTreeMap::new();
    parameters.insert("version".into(), version_value());
    parameters.insert(
        "suite".into(),
        WireValue::Text(MANDATORY_SESSION_SUITE.into()),
    );
    parameters.insert(
        "transport_profile".into(),
        WireValue::Text(value.parameters.transport_profile.clone()),
    );
    parameters.insert(
        "candidate_id".into(),
        WireValue::Text(value.parameters.candidate_id.clone()),
    );
    parameters.insert(
        "grants_hash".into(),
        WireValue::Bytes(value.parameters.grants_hash.as_bytes().to_vec()),
    );
    let mut body = BTreeMap::new();
    body.insert("parameters".into(), WireValue::Map(parameters));
    body.insert("nonce".into(), WireValue::Bytes(value.nonce.to_vec()));
    Ok(body)
}

fn session_ready_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<SessionReadyMessage, MessageError> {
    let mut parameters = take_map(&mut body, "parameters")?;
    let nonce = take_fixed::<SESSION_READY_NONCE_SIZE>(&mut body, "nonce")?;
    require_empty(&body)?;
    require_version(&mut parameters)?;
    require_suite(&mut parameters, MANDATORY_SESSION_SUITE)?;
    let transport_profile = take_text(&mut parameters, "transport_profile")?;
    let candidate_id = take_text(&mut parameters, "candidate_id")?;
    let grants_bytes = take_bytes(&mut parameters, "grants_hash")?;
    let grants_hash = GrantsHash::reconstruct(&grants_bytes)
        .map_err(|_| MessageError::InvalidField("grants_hash"))?;
    require_empty(&parameters)?;
    validate_transport_name(&transport_profile, "transport_profile")?;
    validate_label(&candidate_id, "candidate_id")?;
    Ok(SessionReadyMessage {
        parameters: SessionParameters {
            transport_profile,
            candidate_id,
            grants_hash,
        },
        nonce,
    })
}

fn session_close_to_body(value: SessionCloseMessage) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    body.insert(
        "reason".into(),
        WireValue::Text(close_reason_name(value.reason).into()),
    );
    body.insert(
        "last_received_sequence".into(),
        WireValue::Unsigned(value.last_received_sequence),
    );
    body
}

fn session_close_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<SessionCloseMessage, MessageError> {
    let reason = parse_close_reason(&take_text(&mut body, "reason")?)?;
    let last_received_sequence = take_unsigned(&mut body, "last_received_sequence")?;
    require_empty(&body)?;
    Ok(SessionCloseMessage {
        reason,
        last_received_sequence,
    })
}

fn liveness_to_body(value: LivenessMessage) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    body.insert(
        "challenge".into(),
        WireValue::Bytes(value.challenge.as_bytes().to_vec()),
    );
    body.insert(
        "last_received_sequence".into(),
        WireValue::Unsigned(value.last_received_sequence),
    );
    body
}

fn liveness_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<LivenessMessage, MessageError> {
    let challenge = PingChallenge::reconstruct(take_fixed::<LIVENESS_CHALLENGE_SIZE>(
        &mut body,
        "challenge",
    )?);
    let last_received_sequence = take_unsigned(&mut body, "last_received_sequence")?;
    require_empty(&body)?;
    Ok(LivenessMessage {
        challenge,
        last_received_sequence,
    })
}

fn cancel_to_body(value: &CancelMessage) -> Result<BTreeMap<String, WireValue>, MessageError> {
    let mut body = value.reference.to_wire_body();
    if let Some(reason) = value.reason.as_ref() {
        validate_label(reason, "reason")?;
        body.insert("reason".into(), WireValue::Text(reason.clone()));
    }
    Ok(body)
}

fn cancel_from_body(mut body: BTreeMap<String, WireValue>) -> Result<CancelMessage, MessageError> {
    let reason = match body.remove("reason") {
        None => None,
        Some(WireValue::Text(value)) => {
            validate_label(&value, "reason")?;
            Some(value)
        }
        Some(_) => return Err(MessageError::InvalidField("reason")),
    };
    let reference = OperationReference::from_wire_body(body).map_err(MessageError::Operation)?;
    Ok(CancelMessage { reference, reason })
}

fn status_request_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<OperationId, MessageError> {
    let bytes = take_bytes(&mut body, "operation_id")?;
    let operation_id =
        OperationId::reconstruct(&bytes).map_err(|_| MessageError::InvalidField("operation_id"))?;
    require_empty(&body)?;
    Ok(operation_id)
}

fn status_to_body(value: &StatusReport) -> Result<BTreeMap<String, WireValue>, MessageError> {
    validate_status_report(value)?;
    let mut body = BTreeMap::new();
    body.insert(
        "operation_id".into(),
        WireValue::Bytes(value.operation_id.as_bytes().to_vec()),
    );
    body.insert("known".into(), WireValue::Bool(value.known));
    if let Some(state) = value.state {
        body.insert(
            "state".into(),
            WireValue::Text(operation_state_name(state).into()),
        );
    }
    if let Some(hash) = value.request_hash {
        body.insert(
            "request_hash".into(),
            WireValue::Bytes(hash.as_bytes().to_vec()),
        );
    }
    Ok(body)
}

fn status_from_body(mut body: BTreeMap<String, WireValue>) -> Result<StatusReport, MessageError> {
    let operation_id = OperationId::reconstruct(&take_bytes(&mut body, "operation_id")?)
        .map_err(|_| MessageError::InvalidField("operation_id"))?;
    let known = take_bool(&mut body, "known")?;
    let state = match body.remove("state") {
        None => None,
        Some(WireValue::Text(value)) => Some(parse_terminal_state(&value)?),
        Some(_) => return Err(MessageError::InvalidField("state")),
    };
    let request_hash = match body.remove("request_hash") {
        None => None,
        Some(WireValue::Bytes(value)) => Some(
            RequestHash::reconstruct(&value)
                .map_err(|_| MessageError::InvalidField("request_hash"))?,
        ),
        Some(_) => return Err(MessageError::InvalidField("request_hash")),
    };
    require_empty(&body)?;
    let report = StatusReport {
        operation_id,
        known,
        state,
        request_hash,
    };
    validate_status_report(&report)?;
    Ok(report)
}

const fn validate_status_report(value: &StatusReport) -> Result<(), MessageError> {
    if value.known != (value.state.is_some() && value.request_hash.is_some()) {
        return Err(MessageError::InvalidField("known"));
    }
    if let Some(state) = value.state
        && !state.is_terminal()
    {
        return Err(MessageError::InvalidField("state"));
    }
    Ok(())
}

fn error_to_body(value: ProtocolErrorMessage) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    match value {
        ProtocolErrorMessage::Busy => {
            body.insert("error".into(), WireValue::Text("busy".into()));
        }
        ProtocolErrorMessage::UnknownOperation(operation_id) => {
            body.insert("error".into(), WireValue::Text("unknown_operation".into()));
            if let Some(operation_id) = operation_id {
                body.insert(
                    "operation_id".into(),
                    WireValue::Bytes(operation_id.as_bytes().to_vec()),
                );
            }
        }
    }
    body
}

fn error_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<ProtocolErrorMessage, MessageError> {
    let name = take_text(&mut body, "error")?;
    let operation_id = match body.remove("operation_id") {
        None => None,
        Some(WireValue::Bytes(value)) => Some(
            OperationId::reconstruct(&value)
                .map_err(|_| MessageError::InvalidField("operation_id"))?,
        ),
        Some(_) => return Err(MessageError::InvalidField("operation_id")),
    };
    require_empty(&body)?;
    match name.as_str() {
        "busy" if operation_id.is_none() => Ok(ProtocolErrorMessage::Busy),
        "unknown_operation" => Ok(ProtocolErrorMessage::UnknownOperation(operation_id)),
        _ => Err(MessageError::InvalidField("error")),
    }
}

fn profile_array(profiles: &[ProfileName]) -> WireValue {
    let mut profiles = profiles.to_vec();
    profiles.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    WireValue::Array(
        profiles
            .into_iter()
            .map(|profile| WireValue::Text(profile.as_str().into()))
            .collect(),
    )
}

fn profiles_from_array(values: Vec<WireValue>) -> Result<Vec<ProfileName>, MessageError> {
    let mut profiles = values
        .into_iter()
        .map(|value| match value {
            WireValue::Text(name) => {
                ProfileName::parse(&name).ok_or(MessageError::InvalidField("profiles"))
            }
            _ => Err(MessageError::InvalidField("profiles")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_profile_set(&profiles)?;
    profiles.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    Ok(profiles)
}

fn validate_profile_set(profiles: &[ProfileName]) -> Result<(), MessageError> {
    let mut names = profiles
        .iter()
        .map(|profile| profile.as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    if profiles.is_empty() || names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(MessageError::InvalidField("profiles"));
    }
    Ok(())
}

fn version_value() -> WireValue {
    WireValue::Array(vec![
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.0)),
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.1)),
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.2)),
    ])
}

fn require_version(map: &mut BTreeMap<String, WireValue>) -> Result<(), MessageError> {
    if map.remove("version") != Some(version_value()) {
        return Err(MessageError::InvalidField("version"));
    }
    Ok(())
}

fn require_suite(
    map: &mut BTreeMap<String, WireValue>,
    expected: &'static str,
) -> Result<(), MessageError> {
    if map.remove("suite") != Some(WireValue::Text(expected.into())) {
        return Err(MessageError::InvalidField("suite"));
    }
    Ok(())
}

const fn close_reason_name(value: CloseReason) -> &'static str {
    match value {
        CloseReason::UserDisconnect => "user_disconnect",
        CloseReason::Policy => "policy",
        CloseReason::CredentialRejected => "credential_rejected",
        CloseReason::ProtocolViolation => "protocol_violation",
        CloseReason::PairingRevoked => "pairing_revoked",
        CloseReason::Shutdown => "shutdown",
    }
}

fn parse_close_reason(value: &str) -> Result<CloseReason, MessageError> {
    match value {
        "user_disconnect" => Ok(CloseReason::UserDisconnect),
        "policy" => Ok(CloseReason::Policy),
        "credential_rejected" => Ok(CloseReason::CredentialRejected),
        "protocol_violation" => Ok(CloseReason::ProtocolViolation),
        "pairing_revoked" => Ok(CloseReason::PairingRevoked),
        "shutdown" => Ok(CloseReason::Shutdown),
        _ => Err(MessageError::InvalidField("reason")),
    }
}

const fn operation_state_name(value: OperationState) -> &'static str {
    match value {
        OperationState::Completed => "completed",
        OperationState::Denied => "denied",
        OperationState::Cancelled => "cancelled",
        OperationState::Rejected => "rejected",
        OperationState::CredentialRejected => "credential_rejected",
        OperationState::Ambiguous => "ambiguous",
        OperationState::DeliveryUncertain => "delivery_uncertain",
        _ => "non_terminal",
    }
}

fn parse_terminal_state(value: &str) -> Result<OperationState, MessageError> {
    match value {
        "completed" => Ok(OperationState::Completed),
        "denied" => Ok(OperationState::Denied),
        "cancelled" => Ok(OperationState::Cancelled),
        "rejected" => Ok(OperationState::Rejected),
        "credential_rejected" => Ok(OperationState::CredentialRejected),
        "ambiguous" => Ok(OperationState::Ambiguous),
        "delivery_uncertain" => Ok(OperationState::DeliveryUncertain),
        _ => Err(MessageError::InvalidField("state")),
    }
}

fn validate_label(value: &str, field: &'static str) -> Result<(), MessageError> {
    if value.trim().is_empty() || value.len() > 4_096 {
        Err(MessageError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_transport_name(value: &str, field: &'static str) -> Result<(), MessageError> {
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        Err(MessageError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn take_text(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<String, MessageError> {
    match map.remove(field) {
        Some(WireValue::Text(value)) => Ok(value),
        _ => Err(MessageError::InvalidField(field)),
    }
}

fn take_bytes(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<u8>, MessageError> {
    match map.remove(field) {
        Some(WireValue::Bytes(value)) => Ok(value),
        _ => Err(MessageError::InvalidField(field)),
    }
}

fn take_fixed<const N: usize>(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<[u8; N], MessageError> {
    take_bytes(map, field)?
        .try_into()
        .map_err(|_| MessageError::InvalidField(field))
}

fn take_unsigned(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<u64, MessageError> {
    match map.remove(field) {
        Some(WireValue::Unsigned(value)) => Ok(value),
        _ => Err(MessageError::InvalidField(field)),
    }
}

fn take_bool(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<bool, MessageError> {
    match map.remove(field) {
        Some(WireValue::Bool(value)) => Ok(value),
        _ => Err(MessageError::InvalidField(field)),
    }
}

fn take_map(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<BTreeMap<String, WireValue>, MessageError> {
    match map.remove(field) {
        Some(WireValue::Map(value)) => Ok(value),
        _ => Err(MessageError::InvalidField(field)),
    }
}

fn require_empty(map: &BTreeMap<String, WireValue>) -> Result<(), MessageError> {
    if map.is_empty() {
        Ok(())
    } else {
        Err(MessageError::UnexpectedField)
    }
}

/// Authenticated semantic-message failure. Every variant is a protocol
/// violation unless a higher-level state machine classifies it as a documented
/// stale-reference race.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageError {
    /// Named field is missing, has the wrong type, or an invalid value.
    InvalidField(&'static str),
    /// Body carries a field outside the registered schema.
    UnexpectedField,
    /// Operation body failed its typed validation.
    Operation(CardOperationError),
}

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for MessageError {}
