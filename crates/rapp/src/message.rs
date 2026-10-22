//! Mandatory semantic decoding for every authenticated RAPP message.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    CERTIFICATE_FINGERPRINT_SIZE, CPACE_KC2_SUITE, CardOperationError, CertificateFingerprint,
    CloseReason, Envelope, GrantsHash, LIVENESS_CHALLENGE_SIZE, MANDATORY_PAIRING_SUITE,
    MANDATORY_SESSION_SUITE, MessageType, OperationId, OperationProgressMessage, OperationRequest,
    OperationRequestRefusal, OperationResultMessage, PairId, PingChallenge, ProfileName,
    RequestError, ResultError, SESSION_READY_NONCE_SIZE, WIRE_VERSION_V26_10_21, WireValue,
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

/// Confirmation that the sender's pairing trust record is durably stored
/// (section 4.3 item 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingStoredMessage {
    /// The pairing identifier derived from the completed handshake.
    pub pair_id: PairId,
}

/// Whether the custodian can serve a card now, and which (section 8.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardStatusMessage {
    /// A card can answer; the fingerprint of its authentication certificate.
    Present(CertificateFingerprint),
    /// No card can answer.
    Absent,
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
}

/// Authenticated ping or pong body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LivenessMessage {
    /// Fresh challenge, echoed exactly by the answering pong.
    pub challenge: PingChallenge,
}

/// An `error` message (RAPP v26.10.21 sections 7.1 and 10.3): a registered
/// name and, when it concerns one, the operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolErrorMessage {
    /// Registered error name.
    pub error: ResultError,
    /// The operation the error concerns.
    pub operation_id: Option<OperationId>,
}

impl ProtocolErrorMessage {
    /// A request that arrived while another operation of the session is live.
    #[must_use]
    pub const fn busy(operation_id: OperationId) -> Self {
        Self {
            error: ResultError::Busy,
            operation_id: Some(operation_id),
        }
    }

    /// A request reusing an identifier the session has seen.
    #[must_use]
    pub const fn duplicate(operation_id: OperationId) -> Self {
        Self {
            error: ResultError::DuplicateOperation,
            operation_id: Some(operation_id),
        }
    }

    /// Human-readable `message` for the error.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self.error {
            ResultError::Busy => "Another operation of this session is live.",
            ResultError::DuplicateOperation => {
                "The operation identifier was already used on this session."
            }
            ResultError::InvalidLifetime => "The operation lifetime is zero.",
            ResultError::OperationExpired => "The operation deadline passed.",
            ResultError::Unauthorized => "The profile is not granted to this pairing.",
            ResultError::UnsupportedParameter => "A parameter is not supported.",
            ResultError::UserCancelled => "The holder declined.",
            ResultError::RetryFloor => {
                "The card's remaining attempts are reserved for its issuer's software."
            }
            ResultError::CardError => "The card did not answer.",
            ResultError::OperationFailed => "The operation could not be carried out.",
        }
    }
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
    /// The sender's pairing trust record is durably stored.
    PairingStored(PairingStoredMessage),
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
    /// A well-formed request naming something this endpoint cannot serve;
    /// inbound only, answered with a rejected result.
    OperationRequestRefused(OperationRequestRefusal),
    /// Profile-defined operation result.
    OperationResult(OperationResultMessage),
    /// Operation progress update.
    OperationProgress(OperationProgressMessage),
    /// Whether the custodian can serve a card now, and which.
    CardStatus(CardStatusMessage),
    /// Protocol error.
    Error(ProtocolErrorMessage),
}

impl TypedMessage {
    /// Semantically decode a decrypted, envelope-validated message.
    ///
    /// # Errors
    /// [`MessageError`] on a field, schema, or typed-operation violation.
    pub fn from_envelope(envelope: Envelope, local_start_ms: u64) -> Result<Self, MessageError> {
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
            MessageType::PairingStored => {
                Self::PairingStored(pairing_stored_from_body(envelope.body)?)
            }
            MessageType::SessionReady => {
                Self::SessionReady(session_ready_from_body(envelope.body)?)
            }
            MessageType::SessionClose => {
                Self::SessionClose(session_close_from_body(envelope.body)?)
            }
            MessageType::LivenessPing => Self::LivenessPing(liveness_from_body(envelope.body)?),
            MessageType::LivenessPong => Self::LivenessPong(liveness_from_body(envelope.body)?),
            MessageType::OperationRequest => {
                match OperationRequest::from_wire_body(envelope.body, local_start_ms) {
                    Ok(request) => Self::OperationRequest(request),
                    Err(RequestError::Refused(refusal)) => Self::OperationRequestRefused(refusal),
                    Err(RequestError::Malformed(error)) => {
                        return Err(MessageError::Operation(error));
                    }
                }
            }
            MessageType::OperationResult => Self::OperationResult(
                OperationResultMessage::from_wire_body(envelope.body)
                    .map_err(MessageError::Operation)?,
            ),
            MessageType::OperationProgress => Self::OperationProgress(
                OperationProgressMessage::from_wire_body(envelope.body)
                    .map_err(MessageError::Operation)?,
            ),
            MessageType::CardStatus => Self::CardStatus(card_status_from_body(envelope.body)?),
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
            Self::PairingStored(_) => MessageType::PairingStored,
            Self::SessionReady(_) => MessageType::SessionReady,
            Self::SessionClose(_) => MessageType::SessionClose,
            Self::LivenessPing(_) => MessageType::LivenessPing,
            Self::LivenessPong(_) => MessageType::LivenessPong,
            Self::OperationRequest(_) | Self::OperationRequestRefused(_) => {
                MessageType::OperationRequest
            }
            Self::OperationResult(_) => MessageType::OperationResult,
            Self::OperationProgress(_) => MessageType::OperationProgress,
            Self::CardStatus(_) => MessageType::CardStatus,
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
            Self::PairingStored(value) => Ok(pairing_stored_to_body(*value)),
            Self::SessionReady(value) => session_ready_to_body(value),
            Self::SessionClose(value) => Ok(session_close_to_body(*value)),
            Self::LivenessPing(value) | Self::LivenessPong(value) => Ok(liveness_to_body(*value)),
            Self::OperationRequest(value) => value.to_wire_body().map_err(MessageError::Operation),
            Self::OperationRequestRefused(_) => Err(MessageError::InvalidField("operation")),
            Self::OperationResult(value) => value.to_wire_body().map_err(MessageError::Operation),
            Self::OperationProgress(value) => Ok(value.to_wire_body()),
            Self::CardStatus(value) => Ok(card_status_to_body(*value)),
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

fn pairing_stored_to_body(value: PairingStoredMessage) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    body.insert(
        "pair_id".into(),
        WireValue::Bytes(value.pair_id.as_bytes().to_vec()),
    );
    body
}

fn pairing_stored_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<PairingStoredMessage, MessageError> {
    let pair_id = PairId::reconstruct(&take_bytes(&mut body, "pair_id")?)
        .map_err(|_| MessageError::InvalidField("pair_id"))?;
    require_empty(&body)?;
    Ok(PairingStoredMessage { pair_id })
}

/// A present card names its certificate; an absent one carries 32 zero
/// bytes, so the message has one size whatever it says (section 8.4).
fn card_status_to_body(value: CardStatusMessage) -> BTreeMap<String, WireValue> {
    let (present, fingerprint) = match value {
        CardStatusMessage::Present(fingerprint) => (true, *fingerprint.as_bytes()),
        CardStatusMessage::Absent => (false, [0; CERTIFICATE_FINGERPRINT_SIZE]),
    };
    BTreeMap::from([
        ("card_present".into(), WireValue::Bool(present)),
        (
            "certificate_fingerprint".into(),
            WireValue::Bytes(fingerprint.to_vec()),
        ),
    ])
}

fn card_status_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<CardStatusMessage, MessageError> {
    let card_present = take_bool(&mut body, "card_present")?;
    let fingerprint =
        take_fixed::<CERTIFICATE_FINGERPRINT_SIZE>(&mut body, "certificate_fingerprint")?;
    require_empty(&body)?;
    let zero = fingerprint == [0; CERTIFICATE_FINGERPRINT_SIZE];
    match (card_present, zero) {
        (true, false) => Ok(CardStatusMessage::Present(
            CertificateFingerprint::from_array(fingerprint),
        )),
        (false, true) => Ok(CardStatusMessage::Absent),
        _ => Err(MessageError::InvalidField("certificate_fingerprint")),
    }
}

fn negotiated_parameters_to_map(value: &NegotiatedParameters) -> BTreeMap<String, WireValue> {
    let mut map = BTreeMap::new();
    map.insert("version".into(), version_value());
    map.insert("suite".into(), WireValue::Text(CPACE_KC2_SUITE.into()));
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
    require_pairing_suite(&mut map)?;
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
    let suite = take_text(&mut parameters, "suite")?;
    if suite != MANDATORY_SESSION_SUITE {
        return Err(MessageError::InvalidField("suite"));
    }
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
    body
}

fn session_close_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<SessionCloseMessage, MessageError> {
    let reason = parse_close_reason(&take_text(&mut body, "reason")?)?;
    require_empty(&body)?;
    Ok(SessionCloseMessage { reason })
}

fn liveness_to_body(value: LivenessMessage) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    body.insert(
        "challenge".into(),
        WireValue::Bytes(value.challenge.as_bytes().to_vec()),
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
    require_empty(&body)?;
    Ok(LivenessMessage { challenge })
}

fn error_to_body(value: ProtocolErrorMessage) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    body.insert(
        "error_name".into(),
        WireValue::Text(value.error.as_str().into()),
    );
    body.insert("message".into(), WireValue::Text(value.message().into()));
    if let Some(operation_id) = value.operation_id {
        body.insert(
            "operation_id".into(),
            WireValue::Bytes(operation_id.as_bytes().to_vec()),
        );
    }
    body
}

fn error_from_body(
    mut body: BTreeMap<String, WireValue>,
) -> Result<ProtocolErrorMessage, MessageError> {
    let error = ResultError::parse(&take_text(&mut body, "error_name")?)
        .map_err(|_| MessageError::InvalidField("error_name"))?;
    take_text(&mut body, "message")?;
    let operation_id = match body.remove("operation_id") {
        None => None,
        Some(WireValue::Bytes(value)) => Some(
            OperationId::reconstruct(&value)
                .map_err(|_| MessageError::InvalidField("operation_id"))?,
        ),
        Some(_) => return Err(MessageError::InvalidField("operation_id")),
    };
    require_empty(&body)?;
    Ok(ProtocolErrorMessage {
        error,
        operation_id,
    })
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
        WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_21.0)),
        WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_21.1)),
        WireValue::Unsigned(u64::from(WIRE_VERSION_V26_10_21.2)),
    ])
}

fn require_version(map: &mut BTreeMap<String, WireValue>) -> Result<(), MessageError> {
    let Some(version) = map.remove("version") else {
        return Err(MessageError::InvalidField("version"));
    };
    if version == version_value() {
        Ok(())
    } else {
        Err(MessageError::InvalidField("version"))
    }
}

fn require_pairing_suite(map: &mut BTreeMap<String, WireValue>) -> Result<(), MessageError> {
    match map.remove("suite") {
        Some(WireValue::Text(suite))
            if suite == CPACE_KC2_SUITE || suite == MANDATORY_PAIRING_SUITE =>
        {
            Ok(())
        }
        _ => Err(MessageError::InvalidField("suite")),
    }
}

const fn close_reason_name(value: CloseReason) -> &'static str {
    match value {
        CloseReason::Normal => "normal",
        CloseReason::Complete => "complete",
        CloseReason::UserDisconnect => "user_disconnect",
        CloseReason::Policy => "policy",
        CloseReason::ProtocolViolation => "protocol_violation",
        CloseReason::PairingRevoked => "pairing_revoked",
        CloseReason::Shutdown => "shutdown",
        CloseReason::CardUnavailable => "card_unavailable",
        CloseReason::ServiceWithdrawn => "service_withdrawn",
    }
}

fn parse_close_reason(value: &str) -> Result<CloseReason, MessageError> {
    match value {
        "normal" => Ok(CloseReason::Normal),
        "complete" => Ok(CloseReason::Complete),
        "user_disconnect" => Ok(CloseReason::UserDisconnect),
        "policy" => Ok(CloseReason::Policy),
        "protocol_violation" => Ok(CloseReason::ProtocolViolation),
        "pairing_revoked" => Ok(CloseReason::PairingRevoked),
        "shutdown" => Ok(CloseReason::Shutdown),
        "card_unavailable" => Ok(CloseReason::CardUnavailable),
        "service_withdrawn" => Ok(CloseReason::ServiceWithdrawn),
        _ => Err(MessageError::InvalidField("reason")),
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

#[cfg(test)]
mod tests {
    use super::{
        MessageError, close_reason_name, parse_close_reason, require_version, version_value,
    };
    use crate::CloseReason;
    use crate::{WIRE_VERSION_V26_10_21, WireValue};
    use std::collections::BTreeMap;

    /// Named so the test states which version is being refused. This constant is
    /// test-only: nothing on a runtime path may admit it.
    const REFUSED_LEGACY_VERSION: (u16, u16, u16) = (26, 10, 10);

    fn version_triple(version: (u16, u16, u16)) -> WireValue {
        WireValue::Array(vec![
            WireValue::Unsigned(u64::from(version.0)),
            WireValue::Unsigned(u64::from(version.1)),
            WireValue::Unsigned(u64::from(version.2)),
        ])
    }

    fn map_with(version: WireValue) -> BTreeMap<String, WireValue> {
        BTreeMap::from([("version".to_owned(), version)])
    }

    #[test]
    fn card_unavailable_close_reason_round_trips() {
        assert_eq!(
            close_reason_name(CloseReason::CardUnavailable),
            "card_unavailable"
        );
        assert_eq!(
            parse_close_reason("card_unavailable"),
            Ok(CloseReason::CardUnavailable)
        );
    }

    #[test]
    fn service_withdrawn_close_reason_round_trips() {
        assert_eq!(
            close_reason_name(CloseReason::ServiceWithdrawn),
            "service_withdrawn"
        );
        assert_eq!(
            parse_close_reason("service_withdrawn"),
            Ok(CloseReason::ServiceWithdrawn)
        );
    }

    #[test]
    fn current_version_is_accepted() {
        assert_eq!(require_version(&mut map_with(version_value())), Ok(()));
    }

    #[test]
    fn legacy_wire_version_is_refused() {
        assert_eq!(
            require_version(&mut map_with(version_triple(REFUSED_LEGACY_VERSION))),
            Err(MessageError::InvalidField("version"))
        );
    }

    #[test]
    fn unknown_version_is_refused() {
        assert_eq!(
            require_version(&mut map_with(version_triple((27, 0, 0)))),
            Err(MessageError::InvalidField("version"))
        );
    }

    #[test]
    fn absent_version_is_refused() {
        assert_eq!(
            require_version(&mut BTreeMap::new()),
            Err(MessageError::InvalidField("version"))
        );
    }

    #[test]
    fn scalar_version_is_refused() {
        assert_eq!(
            require_version(&mut map_with(WireValue::Unsigned(u64::from(
                WIRE_VERSION_V26_10_21.0
            )))),
            Err(MessageError::InvalidField("version"))
        );
    }
}
