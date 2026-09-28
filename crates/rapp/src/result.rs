//! Typed operation results and stable symbolic failure registry.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    CardInspection, CardOperation, CardOperationError, CardOperationResult, CertificateKind,
    OperationId, OperationReference, RequestHash, WireValue,
};

/// Stable result status registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultStatus {
    /// Operation completed; acknowledgment is required.
    Completed,
    /// Human authorizer denied the operation before commit.
    Denied,
    /// Cancellation or expiry proven before physical transmission.
    Cancelled,
    /// Non-credential policy or card rejection.
    Rejected,
    /// Invalid CAN, PIN 1, or PIN 2; the session must close.
    CredentialRejected,
    /// Card completion cannot be proven; retry forbidden.
    Ambiguous,
}

impl ResultStatus {
    /// Wire-format status label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::CredentialRejected => "credential_rejected",
            Self::Ambiguous => "ambiguous",
        }
    }

    fn parse(value: &str) -> Result<Self, CardOperationError> {
        match value {
            "completed" => Ok(Self::Completed),
            "denied" => Ok(Self::Denied),
            "cancelled" => Ok(Self::Cancelled),
            "rejected" => Ok(Self::Rejected),
            "credential_rejected" => Ok(Self::CredentialRejected),
            "ambiguous" => Ok(Self::Ambiguous),
            _ => Err(CardOperationError::InvalidField("status")),
        }
    }
}

/// Stable operation failure names. Arbitrary exception text is forbidden.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultError {
    /// Human authorizer denied the operation.
    UserDenied,
    /// Local monotonic request expiry elapsed.
    RequestExpired,
    /// Operation was cancelled before physical transmission.
    Cancelled,
    /// Request failed validation or is unsupported.
    RequestInvalidOrUnsupported,
    /// Fewer than three attempts remained on the decrementable counter.
    RetryPolicyRefused,
    /// Card rejected the CAN, PIN 1, or PIN 2.
    CredentialRejected,
    /// Card left before transmission provably began.
    CardRemovedBeforeTransmit,
    /// Card completion cannot be proven; retry forbidden.
    CardCompletionAmbiguous,
}

impl ResultError {
    /// Wire-format error label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDenied => "user_denied",
            Self::RequestExpired => "request_expired",
            Self::Cancelled => "cancelled",
            Self::RequestInvalidOrUnsupported => "request_invalid_or_unsupported",
            Self::RetryPolicyRefused => "retry_policy_refused",
            Self::CredentialRejected => "credential_rejected",
            Self::CardRemovedBeforeTransmit => "card_removed_before_transmit",
            Self::CardCompletionAmbiguous => "card_completion_ambiguous",
        }
    }

    fn parse(value: &str) -> Result<Self, CardOperationError> {
        match value {
            "user_denied" => Ok(Self::UserDenied),
            "request_expired" => Ok(Self::RequestExpired),
            "cancelled" => Ok(Self::Cancelled),
            "request_invalid_or_unsupported" => Ok(Self::RequestInvalidOrUnsupported),
            "retry_policy_refused" => Ok(Self::RetryPolicyRefused),
            "credential_rejected" => Ok(Self::CredentialRejected),
            "card_removed_before_transmit" => Ok(Self::CardRemovedBeforeTransmit),
            "card_completion_ambiguous" => Ok(Self::CardCompletionAmbiguous),
            _ => Err(CardOperationError::InvalidField("error")),
        }
    }
}

/// One exact operation result bound to the request hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationResultMessage {
    /// Semantic operation identifier.
    pub operation_id: OperationId,
    /// Original request commitment.
    pub request_hash: RequestHash,
    /// Stable result state.
    pub status: ResultStatus,
    /// Stable failure name for non-success states.
    pub error: Option<ResultError>,
    /// Typed successful output.
    pub result: Option<CardOperationResult>,
}

impl OperationResultMessage {
    /// Constructs a completed typed result.
    #[must_use]
    pub const fn completed(reference: OperationReference, result: CardOperationResult) -> Self {
        Self {
            operation_id: reference.operation_id,
            request_hash: reference.request_hash,
            status: ResultStatus::Completed,
            error: None,
            result: Some(result),
        }
    }

    /// Constructs a non-success result from stable registry values.
    ///
    /// # Errors
    /// [`CardOperationError`] when the error name does not belong to the
    /// status.
    pub fn failure(
        reference: OperationReference,
        status: ResultStatus,
        error: ResultError,
    ) -> Result<Self, CardOperationError> {
        if status == ResultStatus::Completed || !error_matches_status(error, status) {
            return Err(CardOperationError::InvalidField("error"));
        }
        Ok(Self {
            operation_id: reference.operation_id,
            request_hash: reference.request_hash,
            status,
            error: Some(error),
            result: None,
        })
    }

    /// Verifies hash binding and that a completed body's type matches the
    /// operation which was actually requested.
    ///
    /// # Errors
    /// [`CardOperationError`] on a reference mismatch or a result shape that
    /// does not fit the requested operation.
    pub fn validate_for(
        &self,
        reference: OperationReference,
        operation: &CardOperation,
    ) -> Result<(), CardOperationError> {
        if self.operation_id != reference.operation_id
            || self.request_hash != reference.request_hash
        {
            return Err(CardOperationError::RequestHashMismatch);
        }
        match (self.status, self.error, self.result.as_ref()) {
            (ResultStatus::Completed, None, Some(result)) => {
                if result_matches_operation(result, operation) {
                    Ok(())
                } else {
                    Err(CardOperationError::ProfileActionMismatch)
                }
            }
            (status, Some(error), None)
                if status != ResultStatus::Completed && error_matches_status(error, status) =>
            {
                Ok(())
            }
            _ => Err(CardOperationError::InvalidField("result")),
        }
    }

    /// Encode the exact `operation.result` body.
    ///
    /// # Errors
    /// [`CardOperationError`] when the reference cannot be encoded.
    pub fn to_wire_body(&self) -> Result<BTreeMap<String, WireValue>, CardOperationError> {
        let mut body = OperationReference {
            operation_id: self.operation_id,
            request_hash: self.request_hash,
        }
        .to_wire_body();
        body.insert(
            "status".into(),
            WireValue::Text(self.status.as_str().into()),
        );
        if let Some(error) = self.error {
            body.insert("error".into(), WireValue::Text(error.as_str().into()));
        }
        body.insert(
            "body".into(),
            WireValue::Map(
                self.result
                    .as_ref()
                    .map_or_else(BTreeMap::new, result_to_wire),
            ),
        );
        Ok(body)
    }

    /// Parse a result after envelope-level schema validation.
    ///
    /// # Errors
    /// [`CardOperationError`] on unregistered values or a status, error, and
    /// body combination outside the registry.
    pub fn from_wire_body(
        mut body: BTreeMap<String, WireValue>,
    ) -> Result<Self, CardOperationError> {
        let operation_id = take_id(&mut body, "operation_id")?;
        let request_hash = take_hash(&mut body, "request_hash")?;
        let status = ResultStatus::parse(&take_text(&mut body, "status")?)?;
        let error = match body.remove("error") {
            None => None,
            Some(WireValue::Text(value)) => Some(ResultError::parse(&value)?),
            Some(_) => return Err(CardOperationError::InvalidField("error")),
        };
        let result_body = take_map(&mut body, "body")?;
        if !body.is_empty() {
            return Err(CardOperationError::UnexpectedField);
        }
        let result = if status == ResultStatus::Completed {
            Some(result_from_wire(result_body)?)
        } else {
            if !result_body.is_empty() {
                return Err(CardOperationError::UnexpectedField);
            }
            None
        };
        let message = Self {
            operation_id,
            request_hash,
            status,
            error,
            result,
        };
        match (message.status, message.error, message.result.as_ref()) {
            (ResultStatus::Completed, None, Some(_)) => Ok(message),
            (status, Some(error), None) if error_matches_status(error, status) => Ok(message),
            _ => Err(CardOperationError::InvalidField("result")),
        }
    }
}

const fn error_matches_status(error: ResultError, status: ResultStatus) -> bool {
    matches!(
        (error, status),
        (ResultError::UserDenied, ResultStatus::Denied)
            | (
                ResultError::RequestExpired
                    | ResultError::Cancelled
                    | ResultError::CardRemovedBeforeTransmit,
                ResultStatus::Cancelled
            )
            | (
                ResultError::RequestInvalidOrUnsupported | ResultError::RetryPolicyRefused,
                ResultStatus::Rejected
            )
            | (
                ResultError::CredentialRejected,
                ResultStatus::CredentialRejected
            )
            | (
                ResultError::CardCompletionAmbiguous,
                ResultStatus::Ambiguous
            )
    )
}

const fn result_matches_operation(result: &CardOperationResult, operation: &CardOperation) -> bool {
    matches!(
        (result, operation),
        (
            CardOperationResult::Inspection(_),
            CardOperation::InspectCard
        ) | (
            CardOperationResult::Identity { .. },
            CardOperation::ReadIdentity
        ) | (
            CardOperationResult::Certificate(_),
            CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication | CertificateKind::Signature
            }
        ) | (
            CardOperationResult::Signature(_),
            CardOperation::BrowserAuthenticate { .. } | CardOperation::SignDocument { .. }
        )
    )
}

fn result_to_wire(result: &CardOperationResult) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    match result {
        CardOperationResult::Inspection(inspection) => {
            body.insert("type".into(), WireValue::Text("inspection".into()));
            body.insert(
                "pin1_factory".into(),
                WireValue::Bool(inspection.pin1_factory),
            );
            body.insert(
                "pin2_factory".into(),
                WireValue::Bool(inspection.pin2_factory),
            );
            insert_optional_attempt(&mut body, "pin1_attempts", inspection.pin1_attempts);
            insert_optional_attempt(&mut body, "pin2_attempts", inspection.pin2_attempts);
            insert_optional_attempt(&mut body, "puk_attempts", inspection.puk_attempts);
        }
        CardOperationResult::Identity {
            display_name,
            person_id,
        } => {
            body.insert("type".into(), WireValue::Text("identity".into()));
            body.insert("display_name".into(), WireValue::Text(display_name.clone()));
            body.insert("person_id".into(), WireValue::Text(person_id.clone()));
        }
        CardOperationResult::Certificate(bytes) => {
            body.insert("type".into(), WireValue::Text("certificate".into()));
            body.insert("der".into(), WireValue::Bytes(bytes.clone()));
        }
        CardOperationResult::Signature(bytes) => {
            body.insert("type".into(), WireValue::Text("signature".into()));
            body.insert("bytes".into(), WireValue::Bytes(bytes.clone()));
        }
    }
    body
}

fn result_from_wire(
    mut body: BTreeMap<String, WireValue>,
) -> Result<CardOperationResult, CardOperationError> {
    let result = match take_text(&mut body, "type")?.as_str() {
        "inspection" => CardOperationResult::Inspection(CardInspection {
            pin1_factory: take_bool(&mut body, "pin1_factory")?,
            pin2_factory: take_bool(&mut body, "pin2_factory")?,
            pin1_attempts: take_optional_attempt(&mut body, "pin1_attempts")?,
            pin2_attempts: take_optional_attempt(&mut body, "pin2_attempts")?,
            puk_attempts: take_optional_attempt(&mut body, "puk_attempts")?,
        }),
        "identity" => CardOperationResult::Identity {
            display_name: take_text(&mut body, "display_name")?,
            person_id: take_text(&mut body, "person_id")?,
        },
        "certificate" => CardOperationResult::Certificate(take_bytes(&mut body, "der")?),
        "signature" => CardOperationResult::Signature(take_bytes(&mut body, "bytes")?),
        _ => return Err(CardOperationError::InvalidField("type")),
    };
    if !body.is_empty() {
        return Err(CardOperationError::UnexpectedField);
    }
    Ok(result)
}

fn insert_optional_attempt(body: &mut BTreeMap<String, WireValue>, name: &str, value: Option<u8>) {
    body.insert(
        name.into(),
        value.map_or(WireValue::Null, |count| {
            WireValue::Unsigned(u64::from(count))
        }),
    );
}

fn take_optional_attempt(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<Option<u8>, CardOperationError> {
    match body.remove(name) {
        Some(WireValue::Null) => Ok(None),
        Some(WireValue::Unsigned(value)) => u8::try_from(value)
            .map(Some)
            .map_err(|_| CardOperationError::InvalidField(name)),
        _ => Err(CardOperationError::InvalidField(name)),
    }
}

fn take_id(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<OperationId, CardOperationError> {
    let bytes = take_bytes(body, name)?;
    OperationId::reconstruct(&bytes).map_err(|_| CardOperationError::InvalidIdentifier)
}

fn take_hash(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<RequestHash, CardOperationError> {
    let bytes = take_bytes(body, name)?;
    RequestHash::reconstruct(&bytes).map_err(|_| CardOperationError::InvalidIdentifier)
}

fn take_text(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<String, CardOperationError> {
    match body.remove(name) {
        Some(WireValue::Text(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(name)),
    }
}

fn take_bytes(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<Vec<u8>, CardOperationError> {
    match body.remove(name) {
        Some(WireValue::Bytes(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(name)),
    }
}

fn take_bool(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<bool, CardOperationError> {
    match body.remove(name) {
        Some(WireValue::Bool(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(name)),
    }
}

fn take_map(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<BTreeMap<String, WireValue>, CardOperationError> {
    match body.remove(name) {
        Some(WireValue::Map(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(name)),
    }
}

impl fmt::Display for ResultStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
