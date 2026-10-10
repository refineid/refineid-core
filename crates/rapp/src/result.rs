//! Typed operation results and stable symbolic failure registry.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    CardIdentity, CardInspection, CardOperation, CardOperationError, CardOperationResult,
    OperationId, OperationReference, ProfileName, RequestHash, WireValue,
};

/// `operation-status-val` (RAPP v26.10.9 section 7.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultStatus {
    /// Operation completed; acknowledgment is required unless retired.
    Completed,
    /// Semantic, consent, or policy rejection; no card retry was consumed.
    Rejected,
    /// The card blocked the credential.
    CredentialRejected,
    /// Expiry or cancellation proven before physical transmission.
    Cancelled,
    /// Card completion cannot be proven; retry forbidden.
    Ambiguous,
}

impl ResultStatus {
    /// Wire-format status label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::CredentialRejected => "credential_rejected",
            Self::Cancelled => "cancelled",
            Self::Ambiguous => "ambiguous",
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
            "credential_rejected" => Ok(Self::CredentialRejected),
            "cancelled" => Ok(Self::Cancelled),
            "ambiguous" => Ok(Self::Ambiguous),
            _ => Err(CardOperationError::InvalidField("status")),
        }
    }
}

/// The `error` an `operation.result` names (RAPP v26.10.9 sections 8 and 10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultError {
    /// The holder declined on screen.
    UserCancelled,
    /// The local deadline passed before authorization.
    OperationExpired,
    /// The pairing does not grant the requested profile.
    Unauthorized,
    /// Unsupported key profile, algorithm, or parameter value.
    UnsupportedParameter,
    /// Incorrect credential; attempts remain.
    InvalidCredential,
    /// The card blocked the credential.
    CardBlocked,
    /// Card transmission failure or card removal.
    CardError,
    /// Consequential execution or durable journal write failed.
    OperationFailed,
    /// The operation identifier is in use with different content.
    DuplicateOperation,
    /// The holder declined under the low-retry warning.
    UserDeclined,
    /// Tombstone storage is exhausted.
    StorageExhausted,
    /// The operation was executed, acknowledged, and retired.
    OperationAlreadyRetired,
    /// A zero `expires_after_ms` (section 8.2.1).
    InvalidLifetime,
}

impl ResultError {
    /// Wire-format error label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserCancelled => "user_cancelled",
            Self::OperationExpired => "operation_expired",
            Self::Unauthorized => "unauthorized",
            Self::UnsupportedParameter => "unsupported_parameter",
            Self::InvalidCredential => "invalid_credential",
            Self::CardBlocked => "card_blocked",
            Self::CardError => "card_error",
            Self::OperationFailed => "operation_failed",
            Self::DuplicateOperation => "duplicate_operation",
            Self::UserDeclined => "user_declined",
            Self::StorageExhausted => "storage_exhausted",
            Self::OperationAlreadyRetired => "operation_already_retired",
            Self::InvalidLifetime => "invalid_lifetime",
        }
    }

    /// Parse a received error label; an unrecognized one is handled as a
    /// general `operation_failed` (section 10.4).
    #[must_use]
    pub fn from_wire_name(value: &str) -> Self {
        match value {
            "user_cancelled" => Self::UserCancelled,
            "operation_expired" => Self::OperationExpired,
            "unauthorized" => Self::Unauthorized,
            "unsupported_parameter" => Self::UnsupportedParameter,
            "invalid_credential" => Self::InvalidCredential,
            "card_blocked" => Self::CardBlocked,
            "card_error" => Self::CardError,
            "duplicate_operation" => Self::DuplicateOperation,
            "user_declined" => Self::UserDeclined,
            "storage_exhausted" => Self::StorageExhausted,
            "operation_already_retired" => Self::OperationAlreadyRetired,
            "invalid_lifetime" => Self::InvalidLifetime,
            _ => Self::OperationFailed,
        }
    }

    /// Whether a result may pair this error with `status`.
    #[must_use]
    pub const fn permits(self, status: ResultStatus) -> bool {
        match self {
            Self::OperationExpired => matches!(status, ResultStatus::Cancelled),
            Self::CardBlocked => matches!(status, ResultStatus::CredentialRejected),
            Self::CardError => matches!(status, ResultStatus::Cancelled | ResultStatus::Ambiguous),
            Self::OperationAlreadyRetired => matches!(status, ResultStatus::Completed),
            Self::UserCancelled
            | Self::Unauthorized
            | Self::UnsupportedParameter
            | Self::InvalidCredential
            | Self::OperationFailed
            | Self::DuplicateOperation
            | Self::UserDeclined
            | Self::StorageExhausted
            | Self::InvalidLifetime => matches!(status, ResultStatus::Rejected),
        }
    }
}

/// Why the custodian ends an operation without an answer.
///
/// Each reason fixes the status and the registered error the result carries,
/// so a result cannot pair a failure with a status that contradicts it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyFailure {
    /// The session ended before the card was touched.
    Cancelled,
    /// The card may have acted; the outcome cannot be known.
    CardCompletionAmbiguous,
    /// The card left before any command was sent.
    CardRemovedBeforeTransmit,
    /// The card reports the credential blocked.
    CredentialRejected,
    /// The card refused the credential and attempts remain (section 10.2).
    InvalidCredential {
        /// Attempts the card reports remaining.
        remaining_retries: u8,
    },
    /// The local deadline passed before approval.
    RequestExpired,
    /// The request names a parameter this endpoint cannot serve.
    RequestInvalidOrUnsupported,
    /// The retry floor refused the command (section 10.3).
    RetryPolicyRefused,
    /// The pairing did not grant the requested profile.
    Unauthorized,
    /// The holder declined on screen.
    UserDenied,
}

impl ProxyFailure {
    /// Result status this failure reports.
    #[must_use]
    pub const fn status(self) -> ResultStatus {
        match self {
            Self::UserDenied
            | Self::RequestInvalidOrUnsupported
            | Self::Unauthorized
            | Self::RetryPolicyRefused
            | Self::InvalidCredential { .. } => ResultStatus::Rejected,
            Self::RequestExpired | Self::Cancelled | Self::CardRemovedBeforeTransmit => {
                ResultStatus::Cancelled
            }
            Self::CredentialRejected => ResultStatus::CredentialRejected,
            Self::CardCompletionAmbiguous => ResultStatus::Ambiguous,
        }
    }

    /// Registered error this failure reports.
    #[must_use]
    pub const fn error(self) -> ResultError {
        match self {
            Self::UserDenied => ResultError::UserCancelled,
            Self::RequestExpired | Self::Cancelled => ResultError::OperationExpired,
            Self::RequestInvalidOrUnsupported => ResultError::UnsupportedParameter,
            Self::Unauthorized => ResultError::Unauthorized,
            Self::RetryPolicyRefused => ResultError::OperationFailed,
            Self::CredentialRejected => ResultError::CardBlocked,
            Self::InvalidCredential { .. } => ResultError::InvalidCredential,
            Self::CardRemovedBeforeTransmit | Self::CardCompletionAmbiguous => {
                ResultError::CardError
            }
        }
    }

    /// Whether the endpoint can make no further safe progress on the session.
    #[must_use]
    pub const fn closes_session(self) -> bool {
        matches!(
            self,
            Self::RetryPolicyRefused | Self::CredentialRejected | Self::CardCompletionAmbiguous
        )
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

/// One `operation.result` (RAPP v26.10.9 section 7.1) bound to the request
/// hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationResultMessage {
    /// Semantic operation identifier.
    pub operation_id: OperationId,
    /// Original request commitment.
    pub request_hash: RequestHash,
    /// Stable result state.
    pub status: ResultStatus,
    /// Registered failure name.
    pub error: Option<ResultError>,
    /// Profile-defined response of a live completed result.
    pub response: Option<ResultResponse>,
    /// Remaining credential attempts after an invalid credential.
    pub remaining_retries: Option<u8>,
    /// The operation is acknowledged and only its tombstone remains.
    pub retired: bool,
}

impl OperationResultMessage {
    /// Constructs a completed typed result.
    #[must_use]
    pub fn completed(reference: OperationReference, result: &CardOperationResult) -> Self {
        Self {
            operation_id: reference.operation_id,
            request_hash: reference.request_hash,
            status: ResultStatus::Completed,
            error: None,
            response: Some(ResultResponse::from_result(result)),
            remaining_retries: None,
            retired: false,
        }
    }

    /// A non-successful result whose status and error the failure fixes.
    #[must_use]
    pub const fn failure(reference: OperationReference, failure: ProxyFailure) -> Self {
        let mut result = Self::rejection(reference, failure.status(), failure.error());
        if let ProxyFailure::InvalidCredential { remaining_retries } = failure {
            result.remaining_retries = Some(remaining_retries);
        }
        result
    }

    /// A non-successful result that also carries a batch's progress.
    ///
    /// An ambiguous batch that already made signatures carries them as the
    /// section 9.3 partial response, so they are delivered and never made
    /// again; every other failure carries no response.
    #[must_use]
    pub fn failure_with_batch(
        reference: OperationReference,
        failure: ProxyFailure,
        completed_signatures: &[Vec<u8>],
    ) -> Self {
        let mut result = Self::failure(reference, failure);
        if failure.status() == ResultStatus::Ambiguous && !completed_signatures.is_empty() {
            result.response = Some(ResultResponse {
                fields: partial_batch_response(completed_signatures),
            });
        }
        result
    }

    /// A non-successful result naming a registered status and error.
    #[must_use]
    pub const fn rejection(
        reference: OperationReference,
        status: ResultStatus,
        error: ResultError,
    ) -> Self {
        Self {
            operation_id: reference.operation_id,
            request_hash: reference.request_hash,
            status,
            error: Some(error),
            response: None,
            remaining_retries: None,
            retired: false,
        }
    }

    /// The result a retired operation answers with (section 8.2.5).
    ///
    /// The preserved disposition is honoured: a retired failure is never
    /// reported as completed, and no pruned response travels.
    #[must_use]
    pub const fn retired(
        reference: OperationReference,
        disposition: ResultStatus,
        preserved_error: Option<ResultError>,
    ) -> Self {
        let error = match (disposition, preserved_error) {
            (ResultStatus::Completed, _) => ResultError::OperationAlreadyRetired,
            (_, Some(error)) => error,
            (_, None) => ResultError::OperationFailed,
        };
        Self {
            operation_id: reference.operation_id,
            request_hash: reference.request_hash,
            status: disposition,
            error: Some(error),
            response: None,
            remaining_retries: None,
            retired: true,
        }
    }

    /// The reference this result echoes.
    #[must_use]
    pub const fn reference(&self) -> OperationReference {
        OperationReference {
            operation_id: self.operation_id,
            request_hash: self.request_hash,
        }
    }

    /// A live completed result carries a response and no error; a retired
    /// one carries `operation_already_retired` and no response; every other
    /// status carries an error its registry pairs with that status.
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        match (self.status, self.error, &self.response) {
            (ResultStatus::Completed, None, Some(_)) => !self.retired,
            (ResultStatus::Completed, Some(error), None) => {
                self.retired && matches!(error, ResultError::OperationAlreadyRetired)
            }
            (ResultStatus::Ambiguous, Some(error), Some(_)) => {
                !self.retired && error.permits(ResultStatus::Ambiguous)
            }
            (status, Some(error), None) => {
                !matches!(status, ResultStatus::Completed) && error.permits(status)
            }
            _ => false,
        }
    }

    /// Verifies the hash binding, the status and error pairing, and that a
    /// completed response answers the operation which was requested.
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
        if !self.is_consistent() {
            return Err(CardOperationError::InvalidField("result"));
        }
        if self.status == ResultStatus::Ambiguous {
            self.partial_batch_signatures(operation)?;
        } else if let Some(response) = &self.response {
            let result = response.typed_for(operation)?;
            if !result_matches_operation(&result, operation) {
                return Err(CardOperationError::ProfileActionMismatch);
            }
        }
        Ok(())
    }

    /// The signatures an ambiguous batch made before it was interrupted;
    /// empty when the result carries no partial progress.
    ///
    /// # Errors
    /// [`CardOperationError::InvalidField`] when a partial response answers
    /// an operation that is not a batch, or does not carry fewer signatures
    /// than the batch has documents with a matching count.
    pub fn partial_batch_signatures(
        &self,
        operation: &CardOperation,
    ) -> Result<Vec<Vec<u8>>, CardOperationError> {
        let (ResultStatus::Ambiguous, Some(response)) = (self.status, &self.response) else {
            return Ok(Vec::new());
        };
        let total = operation
            .batch_total()
            .ok_or(CardOperationError::InvalidField("response"))?;
        let mut fields = response.fields.clone();
        let completed = take_byte_array(&mut fields, "completed_signatures")
            .map_err(|_| CardOperationError::InvalidField("response"))?;
        let count = match fields.remove("completed_count") {
            Some(WireValue::Unsigned(count)) => usize::try_from(count).ok(),
            _ => None,
        };
        if count != Some(completed.len()) || completed.len() >= total || !fields.is_empty() {
            return Err(CardOperationError::InvalidField("response"));
        }
        Ok(completed)
    }

    /// Encode the exact `operation.result` body.
    ///
    /// # Errors
    /// [`CardOperationError`] when the result is inconsistent.
    pub fn to_wire_body(&self) -> Result<BTreeMap<String, WireValue>, CardOperationError> {
        if !self.is_consistent() {
            return Err(CardOperationError::InvalidField("result"));
        }
        let mut body = self.reference().to_wire_body();
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
        if let Some(remaining) = self.remaining_retries {
            body.insert(
                "remaining_retries".into(),
                WireValue::Unsigned(u64::from(remaining)),
            );
        }
        if self.retired {
            body.insert("retired".into(), WireValue::Bool(true));
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
        let request_hash = take_hash(&mut body, "request_hash")?;
        let status = ResultStatus::parse(&take_text(&mut body, "status")?)?;
        let error = match body.remove("error") {
            None => None,
            Some(WireValue::Text(value)) => Some(ResultError::from_wire_name(&value)),
            Some(_) => return Err(CardOperationError::InvalidField("error")),
        };
        let response = match body.remove("response") {
            None => None,
            Some(WireValue::Map(fields)) => Some(ResultResponse { fields }),
            Some(_) => return Err(CardOperationError::InvalidField("response")),
        };
        let remaining_retries = match body.remove("remaining_retries") {
            None => None,
            Some(WireValue::Unsigned(value)) => Some(
                u8::try_from(value)
                    .map_err(|_| CardOperationError::InvalidField("remaining_retries"))?,
            ),
            Some(_) => return Err(CardOperationError::InvalidField("remaining_retries")),
        };
        let retired = match body.remove("retired") {
            None => false,
            Some(WireValue::Bool(value)) => value,
            Some(_) => return Err(CardOperationError::InvalidField("retired")),
        };
        if !body.is_empty() {
            return Err(CardOperationError::UnexpectedField);
        }
        let message = Self {
            operation_id,
            request_hash,
            status,
            error,
            response,
            remaining_retries,
            retired,
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
///
/// `inspect_card` carries the card's answer to reset beside the factory flags
/// and counters this implementation reports as its own response fields.
fn result_to_wire(result: &CardOperationResult) -> BTreeMap<String, WireValue> {
    let mut body = BTreeMap::new();
    match result {
        CardOperationResult::Inspection(inspection) => {
            body.insert("card_present".into(), WireValue::Bool(true));
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
            if !take_bool(&mut body, "card_present")? {
                return Err(CardOperationError::InvalidField("card_present"));
            }
            let answer_to_reset = take_bytes(&mut body, "atr")?;
            match body.remove("supported_profiles") {
                Some(WireValue::Array(_)) => {}
                _ => return Err(CardOperationError::InvalidField("supported_profiles")),
            }
            CardOperationResult::Inspection(CardInspection {
                answer_to_reset,
                pin1_factory: take_optional_bool(&mut body, "pin1_factory")?,
                pin2_factory: take_optional_bool(&mut body, "pin2_factory")?,
                pin1_attempts: take_optional_attempt(&mut body, "pin1_attempts")?,
                pin2_attempts: take_optional_attempt(&mut body, "pin2_attempts")?,
                puk_attempts: take_optional_attempt(&mut body, "puk_attempts")?,
            })
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

/// The `response` an ambiguous batch carries: the signatures made before
/// the interruption, which are never made again (section 9.3).
fn partial_batch_response(completed: &[Vec<u8>]) -> BTreeMap<String, WireValue> {
    BTreeMap::from([
        (
            "completed_signatures".to_owned(),
            WireValue::Array(completed.iter().cloned().map(WireValue::Bytes).collect()),
        ),
        (
            "completed_count".to_owned(),
            WireValue::Unsigned(completed.len() as u64),
        ),
    ])
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
        None | Some(WireValue::Null) => Ok(None),
        Some(WireValue::Unsigned(value)) => u8::try_from(value)
            .map(Some)
            .map_err(|_| CardOperationError::InvalidField(name)),
        _ => Err(CardOperationError::InvalidField(name)),
    }
}

fn take_optional_bool(
    body: &mut BTreeMap<String, WireValue>,
    name: &'static str,
) -> Result<bool, CardOperationError> {
    match body.remove(name) {
        None => Ok(false),
        Some(WireValue::Bool(value)) => Ok(value),
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
            (ResultStatus::CredentialRejected, "credential_rejected"),
            (ResultStatus::Cancelled, "cancelled"),
            (ResultStatus::Ambiguous, "ambiguous"),
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

        assert!(ResultStatus::parse("denied").is_err());
        assert!(ResultStatus::from_str("unknown").is_err());
    }

    #[test]
    fn result_error_wire_labels_bidirectional_round_trip() {
        let cases = [
            (ResultError::UserCancelled, "user_cancelled"),
            (ResultError::OperationExpired, "operation_expired"),
            (ResultError::Unauthorized, "unauthorized"),
            (ResultError::UnsupportedParameter, "unsupported_parameter"),
            (ResultError::InvalidCredential, "invalid_credential"),
            (ResultError::CardBlocked, "card_blocked"),
            (ResultError::CardError, "card_error"),
            (ResultError::OperationFailed, "operation_failed"),
            (ResultError::DuplicateOperation, "duplicate_operation"),
            (ResultError::UserDeclined, "user_declined"),
            (ResultError::StorageExhausted, "storage_exhausted"),
            (
                ResultError::OperationAlreadyRetired,
                "operation_already_retired",
            ),
            (ResultError::InvalidLifetime, "invalid_lifetime"),
        ];

        for (error, expected_label) in cases {
            assert_eq!(error.as_str(), expected_label);
            assert_eq!(error.to_string(), expected_label);
            assert_eq!(ResultError::from_wire_name(expected_label), error);
        }
    }

    #[test]
    fn unrecognized_error_name_reads_as_operation_failed() {
        assert_eq!(
            ResultError::from_wire_name("future_error"),
            ResultError::OperationFailed
        );
    }

    #[test]
    fn every_proxy_failure_pairs_a_permitted_status_and_error() {
        for failure in [
            ProxyFailure::Cancelled,
            ProxyFailure::CardCompletionAmbiguous,
            ProxyFailure::CardRemovedBeforeTransmit,
            ProxyFailure::CredentialRejected,
            ProxyFailure::InvalidCredential {
                remaining_retries: 2,
            },
            ProxyFailure::RequestExpired,
            ProxyFailure::RequestInvalidOrUnsupported,
            ProxyFailure::RetryPolicyRefused,
            ProxyFailure::Unauthorized,
            ProxyFailure::UserDenied,
        ] {
            assert!(failure.error().permits(failure.status()), "{failure:?}");
        }
    }
}
