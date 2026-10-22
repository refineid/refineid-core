//! Typed operation results and the registry of error names.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    CardIdentity, CardInspection, CardOperation, CardOperationError, CardOperationResult,
    OperationId, ProfileName, WireValue,
};

/// `operation-status-val` (RAPP v26.10.21 section 7.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultStatus {
    /// The operation completed and carries its response.
    Completed,
    /// The operation was refused or failed; the error says why.
    Rejected,
    /// The deadline passed before the card was commanded.
    Cancelled,
}

impl ResultStatus {
    /// Wire-format status label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parse a wire-format status label.
    ///
    /// # Errors
    /// [`CardOperationError::InvalidField`] when the string does not match a registered status.
    pub fn parse(value: &str) -> Result<Self, CardOperationError> {
        match value {
            "completed" => Ok(Self::Completed),
            "rejected" => Ok(Self::Rejected),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(CardOperationError::InvalidField("status")),
        }
    }
}

/// An `error_name` of RAPP v26.10.21 section 10.3, carried by an `error`
/// message or by the `error` field of an `operation.result`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultError {
    /// A request arrived while another operation of the session is live.
    Busy,
    /// The operation identifier was already used on this session.
    DuplicateOperation,
    /// `expires_after_ms` of 0.
    InvalidLifetime,
    /// The deadline passed before the card was commanded.
    OperationExpired,
    /// The pairing does not grant the requested profile.
    Unauthorized,
    /// Unsupported key profile, algorithm or parameter value.
    UnsupportedParameter,
    /// The holder declined on the screen.
    UserCancelled,
    /// The card reports fewer than three remaining attempts for the PIN; no
    /// verification was sent.
    RetryFloor,
    /// The card did not answer.
    CardError,
    /// The custodian could not carry the operation out for a reason of its own.
    OperationFailed,
}

impl ResultError {
    /// Wire-format error label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::DuplicateOperation => "duplicate_operation",
            Self::InvalidLifetime => "invalid_lifetime",
            Self::OperationExpired => "operation_expired",
            Self::Unauthorized => "unauthorized",
            Self::UnsupportedParameter => "unsupported_parameter",
            Self::UserCancelled => "user_cancelled",
            Self::RetryFloor => "retry_floor",
            Self::CardError => "card_error",
            Self::OperationFailed => "operation_failed",
        }
    }

    /// Parse a registered error label.
    ///
    /// # Errors
    /// [`CardOperationError::InvalidField`] for a name outside section 10.3.
    pub fn parse(value: &str) -> Result<Self, CardOperationError> {
        Ok(match value {
            "busy" => Self::Busy,
            "duplicate_operation" => Self::DuplicateOperation,
            "invalid_lifetime" => Self::InvalidLifetime,
            "operation_expired" => Self::OperationExpired,
            "unauthorized" => Self::Unauthorized,
            "unsupported_parameter" => Self::UnsupportedParameter,
            "user_cancelled" => Self::UserCancelled,
            "retry_floor" => Self::RetryFloor,
            "card_error" => Self::CardError,
            "operation_failed" => Self::OperationFailed,
            _ => return Err(CardOperationError::InvalidField("error")),
        })
    }

    /// Whether an `operation.result` may pair this error with `status`.
    /// `busy` and `duplicate_operation` answer a request the session never
    /// admitted, so they travel only in an `error` message.
    #[must_use]
    pub const fn permits(self, status: ResultStatus) -> bool {
        match self {
            Self::OperationExpired => matches!(status, ResultStatus::Cancelled),
            Self::Busy | Self::DuplicateOperation => false,
            Self::InvalidLifetime
            | Self::Unauthorized
            | Self::UnsupportedParameter
            | Self::UserCancelled
            | Self::RetryFloor
            | Self::CardError
            | Self::OperationFailed => matches!(status, ResultStatus::Rejected),
        }
    }
}

/// Why the custodian ends an admitted operation without a response.
///
/// Each reason fixes the status and the registered error the result carries,
/// so a result cannot pair a failure with a status that contradicts it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyFailure {
    /// The deadline passed before the card was commanded.
    RequestExpired,
    /// The request names a parameter this endpoint cannot serve.
    RequestInvalidOrUnsupported,
    /// The pairing did not grant the requested profile.
    Unauthorized,
    /// The holder declined on screen.
    UserDenied,
    /// The retry floor refused before any verification (section 10.2).
    RetryFloor,
    /// The card did not answer: no card within the wait, the field lost, a
    /// transmission fault.
    CardError,
    /// The custodian failed for a reason of its own.
    OperationFailed,
}

impl ProxyFailure {
    /// Result status this failure reports.
    #[must_use]
    pub const fn status(self) -> ResultStatus {
        match self {
            Self::RequestExpired => ResultStatus::Cancelled,
            Self::RequestInvalidOrUnsupported
            | Self::Unauthorized
            | Self::UserDenied
            | Self::RetryFloor
            | Self::CardError
            | Self::OperationFailed => ResultStatus::Rejected,
        }
    }

    /// Registered error this failure reports.
    #[must_use]
    pub const fn error(self) -> ResultError {
        match self {
            Self::RequestExpired => ResultError::OperationExpired,
            Self::RequestInvalidOrUnsupported => ResultError::UnsupportedParameter,
            Self::Unauthorized => ResultError::Unauthorized,
            Self::UserDenied => ResultError::UserCancelled,
            Self::RetryFloor => ResultError::RetryFloor,
            Self::CardError => ResultError::CardError,
            Self::OperationFailed => ResultError::OperationFailed,
        }
    }
}

/// The `response` map of a completed result, as the wire carries it.
///
/// The section 9 response schemas carry no type discriminator, so only the
/// requester, which knows the operation it asked for, reads the map as a
/// typed answer ([`ResultResponse::typed_for`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultResponse {
    fields: BTreeMap<String, WireValue>,
}

impl ResultResponse {
    /// The response a completed typed answer puts on the wire.
    #[must_use]
    pub fn from_result(result: &CardOperationResult) -> Self {
        Self {
            fields: result_to_wire(result),
        }
    }

    /// The fields as the wire carries them.
    #[must_use]
    pub const fn fields(&self) -> &BTreeMap<String, WireValue> {
        &self.fields
    }

    /// Reads the response as the answer to `operation`.
    ///
    /// # Errors
    /// [`CardOperationError`] when the map does not carry exactly the
    /// section 9 response of that operation.
    pub fn typed_for(
        &self,
        operation: &CardOperation,
    ) -> Result<CardOperationResult, CardOperationError> {
        result_from_wire(self.fields.clone(), operation)
    }
}

/// One `operation.result` (RAPP v26.10.21 section 7.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationResultMessage {
    /// The operation this result ends.
    pub operation_id: OperationId,
    /// Stable result state.
    pub status: ResultStatus,
    /// Registered error of a result that did not complete.
    pub error: Option<ResultError>,
    /// Profile-defined response of a completed result.
    pub response: Option<ResultResponse>,
}

impl OperationResultMessage {
    /// Constructs a completed typed result.
    #[must_use]
    pub fn completed(operation_id: OperationId, result: &CardOperationResult) -> Self {
        Self {
            operation_id,
            status: ResultStatus::Completed,
            error: None,
            response: Some(ResultResponse::from_result(result)),
        }
    }

    /// A result whose status and error the failure fixes.
    #[must_use]
    pub const fn failure(operation_id: OperationId, failure: ProxyFailure) -> Self {
        Self::rejection(operation_id, failure.status(), failure.error())
    }

    /// A result that did not complete, naming a registered status and error.
    #[must_use]
    pub const fn rejection(
        operation_id: OperationId,
        status: ResultStatus,
        error: ResultError,
    ) -> Self {
        Self {
            operation_id,
            status,
            error: Some(error),
            response: None,
        }
    }

    /// A completed result carries a response and no error; every other
    /// status carries an error its registry pairs with that status and no
    /// response.
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        match (self.status, self.error, &self.response) {
            (ResultStatus::Completed, None, Some(_)) => true,
            (status, Some(error), None) => {
                !matches!(status, ResultStatus::Completed) && error.permits(status)
            }
            _ => false,
        }
    }

    /// Verifies the identifier, the status and error pairing, and that a
    /// completed response answers the operation which was requested.
    ///
    /// # Errors
    /// [`CardOperationError`] on another operation's result or a result shape
    /// that does not fit the requested operation.
    pub fn validate_for(
        &self,
        operation_id: OperationId,
        operation: &CardOperation,
    ) -> Result<(), CardOperationError> {
        if self.operation_id != operation_id {
            return Err(CardOperationError::OperationMismatch);
        }
        if !self.is_consistent() {
            return Err(CardOperationError::InvalidField("result"));
        }
        if let Some(response) = &self.response {
            let result = response.typed_for(operation)?;
            if !result_matches_operation(&result, operation) {
                return Err(CardOperationError::ProfileActionMismatch);
            }
        }
        Ok(())
    }

    /// Encode the exact `operation.result` body.
    ///
    /// # Errors
    /// [`CardOperationError`] when the result is inconsistent.
    pub fn to_wire_body(&self) -> Result<BTreeMap<String, WireValue>, CardOperationError> {
        if !self.is_consistent() {
            return Err(CardOperationError::InvalidField("result"));
        }
        let mut body = BTreeMap::new();
        body.insert(
            "operation_id".into(),
            WireValue::Bytes(self.operation_id.as_bytes().to_vec()),
        );
        body.insert(
            "status".into(),
            WireValue::Text(self.status.as_str().into()),
        );
        if let Some(error) = self.error {
            body.insert("error".into(), WireValue::Text(error.as_str().into()));
        }
        if let Some(response) = &self.response {
            body.insert("response".into(), WireValue::Map(response.fields.clone()));
        }
        Ok(body)
    }

    /// Parse a result after envelope-level schema validation.
    ///
    /// # Errors
    /// [`CardOperationError`] on unregistered values or a status, error, and
    /// response combination outside the registry.
    pub fn from_wire_body(
        mut body: BTreeMap<String, WireValue>,
    ) -> Result<Self, CardOperationError> {
        let operation_id = take_id(&mut body, "operation_id")?;
        let status = ResultStatus::parse(&take_text(&mut body, "status")?)?;
        let error = match body.remove("error") {
            None => None,
            Some(WireValue::Text(value)) => Some(ResultError::parse(&value)?),
            Some(_) => return Err(CardOperationError::InvalidField("error")),
        };
        let response = match body.remove("response") {
            None => None,
            Some(WireValue::Map(fields)) => Some(ResultResponse { fields }),
            Some(_) => return Err(CardOperationError::InvalidField("response")),
        };
        if !body.is_empty() {
            return Err(CardOperationError::UnexpectedField);
        }
        let message = Self {
            operation_id,
            status,
            error,
            response,
        };
        if message.is_consistent() {
            Ok(message)
        } else {
            Err(CardOperationError::InvalidField("result"))
        }
    }
}

fn result_matches_operation(result: &CardOperationResult, operation: &CardOperation) -> bool {
    if let (
        CardOperationResult::Signatures(signatures),
        CardOperation::BatchSignDocuments { digests, .. },
    ) = (result, operation)
    {
        return signatures.len() == digests.len();
    }
    matches!(
        (result, operation),
        (
            CardOperationResult::Inspection(_),
            CardOperation::InspectCard
        ) | (
            CardOperationResult::Identity(_),
            CardOperation::ReadIdentity
        ) | (
            CardOperationResult::Certificate(_),
            CardOperation::ReadCertificate { .. }
        ) | (
            CardOperationResult::Signature(_),
            CardOperation::BrowserAuthenticate { .. } | CardOperation::SignDocument { .. }
        )
    )
}

/// The section 9 response map of a typed answer.
fn result_to_wire(result: &CardOperationResult) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    match result {
        CardOperationResult::Inspection(inspection) => {
            body.insert(
                "atr".into(),
                WireValue::Bytes(inspection.answer_to_reset.clone()),
            );
            body.insert(
                "supported_profiles".into(),
                WireValue::Array(
                    ProfileName::ALL
                        .iter()
                        .map(|profile| WireValue::Text(profile.as_str().into()))
                        .collect(),
                ),
            );
        }
        CardOperationResult::Identity(identity) => {
            body.insert(
                "card_holder_name".into(),
                WireValue::Text(identity.holder_name.clone()),
            );
            body.insert("card_id".into(), WireValue::Text(identity.card_id.clone()));
            body.insert(
                "issuance_date".into(),
                WireValue::Text(identity.issuance_date.clone()),
            );
            body.insert(
                "expiration_date".into(),
                WireValue::Text(identity.expiration_date.clone()),
            );
            body.insert(
                "certificates".into(),
                WireValue::Array(
                    identity
                        .certificates
                        .iter()
                        .cloned()
                        .map(WireValue::Bytes)
                        .collect(),
                ),
            );
            if let Some(name) = &identity.token_display_name {
                body.insert("token_display_name".into(), WireValue::Text(name.clone()));
            }
        }
        CardOperationResult::Certificate(bytes) => {
            body.insert("certificate".into(), WireValue::Bytes(bytes.clone()));
        }
        CardOperationResult::Signature(bytes) => {
            body.insert("signature".into(), WireValue::Bytes(bytes.clone()));
        }
        CardOperationResult::Signatures(signatures) => {
            body.insert(
                "signatures".into(),
                WireValue::Array(signatures.iter().cloned().map(WireValue::Bytes).collect()),
            );
        }
    }
    body
}

fn result_from_wire(
    mut body: BTreeMap<String, WireValue>,
    operation: &CardOperation,
) -> Result<CardOperationResult, CardOperationError> {
    let result = match operation {
        CardOperation::InspectCard => {
            let answer_to_reset = take_bytes(&mut body, "atr")?;
            match body.remove("supported_profiles") {
                Some(WireValue::Array(_)) => {}
                _ => return Err(CardOperationError::InvalidField("supported_profiles")),
            }
            CardOperationResult::Inspection(CardInspection { answer_to_reset })
        }
        CardOperation::ReadIdentity => {
            let certificates = match body.remove("certificates") {
                Some(WireValue::Array(values)) => values
                    .into_iter()
                    .map(|value| match value {
                        WireValue::Bytes(bytes) => Ok(bytes),
                        _ => Err(CardOperationError::InvalidField("certificates")),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(CardOperationError::InvalidField("certificates")),
            };
            let token_display_name = match body.remove("token_display_name") {
                None => None,
                Some(WireValue::Text(value)) => Some(value),
                Some(_) => return Err(CardOperationError::InvalidField("token_display_name")),
            };
            CardOperationResult::Identity(CardIdentity::reconstruct(
                take_text(&mut body, "card_holder_name")?,
                take_text(&mut body, "card_id")?,
                take_text(&mut body, "issuance_date")?,
                take_text(&mut body, "expiration_date")?,
                certificates,
                token_display_name,
            )?)
        }
        CardOperation::ReadCertificate { .. } => {
            CardOperationResult::Certificate(take_bytes(&mut body, "certificate")?)
        }
        CardOperation::BrowserAuthenticate { .. } | CardOperation::SignDocument { .. } => {
            CardOperationResult::Signature(take_bytes(&mut body, "signature")?)
        }
        CardOperation::BatchSignDocuments { .. } => {
            CardOperationResult::Signatures(take_byte_array(&mut body, "signatures")?)
        }
    };
    if !body.is_empty() {
        return Err(CardOperationError::UnexpectedField);
    }
    Ok(result)
}

fn take_byte_array(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<Vec<Vec<u8>>, CardOperationError> {
    let Some(WireValue::Array(values)) = body.remove(name) else {
        return Err(CardOperationError::InvalidField(name));
    };
    values
        .into_iter()
        .map(|value| match value {
            WireValue::Bytes(bytes) if !bytes.is_empty() => Ok(bytes),
            _ => Err(CardOperationError::InvalidField(name)),
        })
        .collect()
}

fn take_id(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<OperationId, CardOperationError> {
    let bytes = take_bytes(body, name)?;
    OperationId::reconstruct(&bytes).map_err(|_| CardOperationError::InvalidIdentifier)
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

impl fmt::Display for ResultStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl core::str::FromStr for ResultStatus {
    type Err = CardOperationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for ResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::{ProxyFailure, ResultError, ResultStatus};

    #[test]
    fn result_status_wire_labels_bidirectional_round_trip() {
        let cases = [
            (ResultStatus::Completed, "completed"),
            (ResultStatus::Rejected, "rejected"),
            (ResultStatus::Cancelled, "cancelled"),
        ];

        for (status, expected_label) in cases {
            assert_eq!(status.as_str(), expected_label);
            assert_eq!(status.to_string(), expected_label);
            assert_eq!(
                ResultStatus::parse(expected_label).expect("registered status label"),
                status
            );
            assert_eq!(
                ResultStatus::from_str(expected_label).expect("registered status label"),
                status
            );
        }

        assert!(ResultStatus::parse("ambiguous").is_err());
        assert!(ResultStatus::from_str("unknown").is_err());
    }

    #[test]
    fn result_error_wire_labels_bidirectional_round_trip() {
        let cases = [
            (ResultError::Busy, "busy"),
            (ResultError::DuplicateOperation, "duplicate_operation"),
            (ResultError::InvalidLifetime, "invalid_lifetime"),
            (ResultError::OperationExpired, "operation_expired"),
            (ResultError::Unauthorized, "unauthorized"),
            (ResultError::UnsupportedParameter, "unsupported_parameter"),
            (ResultError::UserCancelled, "user_cancelled"),
            (ResultError::RetryFloor, "retry_floor"),
            (ResultError::CardError, "card_error"),
            (ResultError::OperationFailed, "operation_failed"),
        ];

        for (error, expected_label) in cases {
            assert_eq!(error.as_str(), expected_label);
            assert_eq!(error.to_string(), expected_label);
            assert_eq!(ResultError::parse(expected_label), Ok(error));
        }
    }

    #[test]
    fn an_unregistered_error_name_is_malformed() {
        assert!(ResultError::parse("invalid_credential").is_err());
    }

    #[test]
    fn every_proxy_failure_pairs_a_permitted_status_and_error() {
        for failure in [
            ProxyFailure::RequestExpired,
            ProxyFailure::RequestInvalidOrUnsupported,
            ProxyFailure::Unauthorized,
            ProxyFailure::UserDenied,
            ProxyFailure::RetryFloor,
            ProxyFailure::CardError,
            ProxyFailure::OperationFailed,
        ] {
            assert!(failure.error().permits(failure.status()), "{failure:?}");
        }
    }
}
