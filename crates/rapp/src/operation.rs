//! Closed RAPP operation registry.
//!
//! Requests describe user-visible authorization goals. They never contain a
//! raw APDU or CAN/PIN/PUK value; card credentials are collected and retained
//! by the authorizer endpoint.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    OperationId, PairId, ProfileName, RequestHash, SessionId, WireError, WireValue,
    compute_request_hash,
};

/// Card credential selected by an operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialKind {
    /// Basic authentication credential shown as PIN 1.
    Pin1,
    /// Qualified-signature credential shown as PIN 2.
    Pin2,
}

/// Certificate selected for a public-data read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateKind {
    /// Authentication certificate associated with PIN 1.
    Authentication,
    /// Signing certificate associated with PIN 2.
    Signature,
}

impl CertificateKind {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Signature => "signature",
        }
    }

    fn parse(value: &str) -> Result<Self, CardOperationError> {
        match value {
            "authentication" => Ok(Self::Authentication),
            "signature" => Ok(Self::Signature),
            _ => Err(CardOperationError::InvalidField("kind")),
        }
    }
}

/// Public-key profile expected from the certificate already published by the
/// requester and independently checked by the card-authorizer endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardKeyProfile {
    /// ECDSA P-256 key.
    EcdsaP256,
    /// ECDSA P-384 key.
    EcdsaP384,
    /// RSA 2048-bit key.
    Rsa2048,
    /// RSA 3072-bit key.
    Rsa3072,
}

impl CardKeyProfile {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa_p256",
            Self::EcdsaP384 => "ecdsa_p384",
            Self::Rsa2048 => "rsa_2048",
            Self::Rsa3072 => "rsa_3072",
        }
    }

    fn parse(value: &str) -> Result<Self, CardOperationError> {
        match value {
            "ecdsa_p256" => Ok(Self::EcdsaP256),
            "ecdsa_p384" => Ok(Self::EcdsaP384),
            "rsa_2048" => Ok(Self::Rsa2048),
            "rsa_3072" => Ok(Self::Rsa3072),
            _ => Err(CardOperationError::InvalidField("key_profile")),
        }
    }
}

/// Exact closed signature operation. A digest family alone is insufficient:
/// PKCS#1, PSS, and ECDSA are not interchangeable card commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    /// ECDSA over a 28-byte SHA-224 digest.
    EcdsaSha224,
    /// ECDSA over a 32-byte SHA-256 digest.
    EcdsaSha256,
    /// ECDSA over a 48-byte SHA-384 digest.
    EcdsaSha384,
    /// ECDSA over a 64-byte SHA-512 digest.
    EcdsaSha512,
    /// RSA PKCS#1 v1.5 over a 32-byte SHA-256 digest.
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 over a 48-byte SHA-384 digest.
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 over a 64-byte SHA-512 digest.
    RsaPkcs1Sha512,
    /// RSA PSS over a 32-byte SHA-256 digest.
    RsaPssSha256,
}

impl SignatureAlgorithm {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::EcdsaSha224 => "ecdsa_sha224",
            Self::EcdsaSha256 => "ecdsa_sha256",
            Self::EcdsaSha384 => "ecdsa_sha384",
            Self::EcdsaSha512 => "ecdsa_sha512",
            Self::RsaPkcs1Sha256 => "rsa_pkcs1_sha256",
            Self::RsaPkcs1Sha384 => "rsa_pkcs1_sha384",
            Self::RsaPkcs1Sha512 => "rsa_pkcs1_sha512",
            Self::RsaPssSha256 => "rsa_pss_sha256",
        }
    }

    const fn digest_size(self) -> usize {
        match self {
            Self::EcdsaSha224 => 28,
            Self::EcdsaSha256 | Self::RsaPkcs1Sha256 | Self::RsaPssSha256 => 32,
            Self::EcdsaSha384 | Self::RsaPkcs1Sha384 => 48,
            Self::EcdsaSha512 | Self::RsaPkcs1Sha512 => 64,
        }
    }

    const fn supports(self, profile: CardKeyProfile) -> bool {
        matches!(
            (self, profile),
            (
                Self::EcdsaSha224 | Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512,
                CardKeyProfile::EcdsaP256 | CardKeyProfile::EcdsaP384
            ) | (
                Self::RsaPkcs1Sha256
                    | Self::RsaPkcs1Sha384
                    | Self::RsaPkcs1Sha512
                    | Self::RsaPssSha256,
                CardKeyProfile::Rsa2048 | CardKeyProfile::Rsa3072
            )
        )
    }

    fn parse(value: &str) -> Result<Self, CardOperationError> {
        match value {
            "ecdsa_sha224" => Ok(Self::EcdsaSha224),
            "ecdsa_sha256" => Ok(Self::EcdsaSha256),
            "ecdsa_sha384" => Ok(Self::EcdsaSha384),
            "ecdsa_sha512" => Ok(Self::EcdsaSha512),
            "rsa_pkcs1_sha256" => Ok(Self::RsaPkcs1Sha256),
            "rsa_pkcs1_sha384" => Ok(Self::RsaPkcs1Sha384),
            "rsa_pkcs1_sha512" => Ok(Self::RsaPkcs1Sha512),
            "rsa_pss_sha256" => Ok(Self::RsaPssSha256),
            _ => Err(CardOperationError::InvalidField("algorithm")),
        }
    }
}

/// Explicitly supported remote card operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CardOperation {
    /// Read activation and retry state without attempting a credential.
    InspectCard,
    /// Read the public identity fields displayed by `RefineID`.
    ReadIdentity,
    /// Read a public certificate.
    ReadCertificate {
        /// Which certificate to read.
        kind: CertificateKind,
    },
    /// Authenticate a browser challenge after local authorizer consent.
    BrowserAuthenticate {
        /// Human-readable relying-party origin shown by the authorizer.
        origin: String,
        /// Expected public-key profile, verified again by the authorizer.
        key_profile: CardKeyProfile,
        /// Exact signature algorithm.
        algorithm: SignatureAlgorithm,
        /// Already-hashed challenge; never an arbitrary APDU.
        digest: Vec<u8>,
    },
    /// Sign a document digest after local authorizer consent.
    SignDocument {
        /// Human-readable document name shown by the authorizer.
        document_name: String,
        /// Expected public-key profile, verified again by the authorizer.
        key_profile: CardKeyProfile,
        /// Exact signature algorithm.
        algorithm: SignatureAlgorithm,
        /// Already-hashed document bytes.
        digest: Vec<u8>,
    },
}

impl CardOperation {
    /// Whether this action crosses the prepare/commit boundary and may consume
    /// a credential attempt or invoke a private key.
    #[must_use]
    pub const fn is_consequential(&self) -> bool {
        matches!(
            self,
            Self::BrowserAuthenticate { .. } | Self::SignDocument { .. }
        )
    }

    /// Credential profile that owns this closed action schema.
    #[must_use]
    pub const fn required_profile(&self) -> ProfileName {
        match self {
            Self::InspectCard | Self::ReadIdentity => ProfileName::CardStatus,
            Self::ReadCertificate {
                kind: CertificateKind::Authentication,
            }
            | Self::BrowserAuthenticate { .. } => ProfileName::Authentication,
            Self::ReadCertificate {
                kind: CertificateKind::Signature,
            }
            | Self::SignDocument { .. } => ProfileName::DocumentSigning,
        }
    }

    fn validate(&self) -> Result<(), CardOperationError> {
        match self {
            Self::BrowserAuthenticate {
                origin,
                key_profile,
                algorithm,
                digest,
            } => validate_named_digest(origin, *key_profile, *algorithm, digest),
            Self::SignDocument {
                document_name,
                key_profile,
                algorithm,
                digest,
            } => validate_named_digest(document_name, *key_profile, *algorithm, digest),
            _ => Ok(()),
        }
    }

    fn wire_parts(
        &self,
    ) -> (
        &'static str,
        BTreeMap<String, WireValue>,
        BTreeMap<String, WireValue>,
    ) {
        let mut context = BTreeMap::new();
        let mut payload = BTreeMap::new();
        match self {
            Self::InspectCard => ("inspect_card", context, payload),
            Self::ReadIdentity => ("read_identity", context, payload),
            Self::ReadCertificate { kind } => {
                payload.insert("kind".into(), WireValue::Text(kind.wire_name().into()));
                ("read_certificate", context, payload)
            }
            Self::BrowserAuthenticate {
                origin,
                key_profile,
                algorithm,
                digest,
            } => {
                context.insert("origin".into(), WireValue::Text(origin.clone()));
                payload.insert(
                    "key_profile".into(),
                    WireValue::Text(key_profile.wire_name().into()),
                );
                payload.insert(
                    "algorithm".into(),
                    WireValue::Text(algorithm.wire_name().into()),
                );
                payload.insert("digest".into(), WireValue::Bytes(digest.clone()));
                ("browser_authenticate", context, payload)
            }
            Self::SignDocument {
                document_name,
                key_profile,
                algorithm,
                digest,
            } => {
                context.insert(
                    "document_name".into(),
                    WireValue::Text(document_name.clone()),
                );
                payload.insert(
                    "key_profile".into(),
                    WireValue::Text(key_profile.wire_name().into()),
                );
                payload.insert(
                    "algorithm".into(),
                    WireValue::Text(algorithm.wire_name().into()),
                );
                payload.insert("digest".into(), WireValue::Bytes(digest.clone()));
                ("sign_document", context, payload)
            }
        }
    }

    fn from_wire_parts(
        action: &str,
        mut context: BTreeMap<String, WireValue>,
        mut payload: BTreeMap<String, WireValue>,
    ) -> Result<Self, CardOperationError> {
        let operation = match action {
            "inspect_card" => Self::InspectCard,
            "read_identity" => Self::ReadIdentity,
            "read_certificate" => Self::ReadCertificate {
                kind: CertificateKind::parse(&take_text(&mut payload, "kind")?)?,
            },
            "browser_authenticate" => Self::BrowserAuthenticate {
                origin: take_text(&mut context, "origin")?,
                key_profile: CardKeyProfile::parse(&take_text(&mut payload, "key_profile")?)?,
                algorithm: SignatureAlgorithm::parse(&take_text(&mut payload, "algorithm")?)?,
                digest: take_bytes(&mut payload, "digest")?,
            },
            "sign_document" => Self::SignDocument {
                document_name: take_text(&mut context, "document_name")?,
                key_profile: CardKeyProfile::parse(&take_text(&mut payload, "key_profile")?)?,
                algorithm: SignatureAlgorithm::parse(&take_text(&mut payload, "algorithm")?)?,
                digest: take_bytes(&mut payload, "digest")?,
            },
            _ => return Err(CardOperationError::UnknownAction),
        };
        if !context.is_empty() || !payload.is_empty() {
            return Err(CardOperationError::UnexpectedField);
        }
        operation.validate()?;
        Ok(operation)
    }
}

/// Typed request bound to one authenticated pair and session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRequest {
    /// Unique at-most-once operation identifier.
    pub operation_id: OperationId,
    /// Long-term pair binding.
    pub pair_id: PairId,
    /// Current secure-session binding.
    pub session_id: SessionId,
    /// Negotiated operation profile.
    pub profile: ProfileName,
    /// Local monotonic receipt/creation time. This is never sent or hashed.
    pub local_start_ms: u64,
    /// Relative validity interval sent on the wire and independently capped
    /// by each endpoint's local policy. Wall clocks are not used.
    pub expires_after_ms: u64,
    /// Closed operation body.
    pub operation: CardOperation,
}

impl OperationRequest {
    /// Constructs and validates a local or received operation request.
    ///
    /// # Errors
    /// [`CardOperationError`] when validation rejects the request.
    #[allow(
        clippy::too_many_arguments,
        reason = "one atomic constructor takes every field of the request"
    )]
    pub fn reconstruct(
        operation_id: OperationId,
        pair_id: PairId,
        session_id: SessionId,
        profile: ProfileName,
        local_start_ms: u64,
        expires_after_ms: u64,
        operation: CardOperation,
    ) -> Result<Self, CardOperationError> {
        let request = Self {
            operation_id,
            pair_id,
            session_id,
            profile,
            local_start_ms,
            expires_after_ms,
            operation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates time bounds and operation parameters.
    ///
    /// # Errors
    /// [`CardOperationError`] on a zero lifetime, a profile that does not own
    /// the action, or invalid operation parameters.
    pub fn validate(&self) -> Result<(), CardOperationError> {
        if self.expires_after_ms == 0 {
            return Err(CardOperationError::InvalidLifetime);
        }
        if self.profile != self.operation.required_profile() {
            return Err(CardOperationError::ProfileActionMismatch);
        }
        self.operation.validate()
    }

    /// Local monotonic deadline with an endpoint-specific maximum lifetime.
    ///
    /// # Errors
    /// [`CardOperationError`] on an invalid request or a zero maximum
    /// lifetime.
    pub fn local_deadline_ms(&self, maximum_lifetime_ms: u64) -> Result<u64, CardOperationError> {
        self.validate()?;
        if maximum_lifetime_ms == 0 {
            return Err(CardOperationError::InvalidLifetime);
        }
        Ok(self
            .local_start_ms
            .saturating_add(self.expires_after_ms.min(maximum_lifetime_ms)))
    }

    /// Computes the deterministic request hash committed by approval and the
    /// durable at-most-once journal.
    ///
    /// # Errors
    /// [`CardOperationError`] on an invalid request or an encoding failure.
    pub fn request_hash(&self) -> Result<RequestHash, CardOperationError> {
        self.validate()?;
        let (action, context, payload) = self.operation.wire_parts();
        compute_request_hash(
            self.session_id,
            self.operation_id,
            self.profile,
            action,
            context,
            payload,
        )
        .map_err(|_| CardOperationError::HashFailure)
    }

    /// Registered wire action and its separately bounded consent context and
    /// credential-profile payload.
    #[must_use]
    pub fn wire_parts(
        &self,
    ) -> (
        &'static str,
        BTreeMap<String, WireValue>,
        BTreeMap<String, WireValue>,
    ) {
        self.operation.wire_parts()
    }

    /// Builds the exact `operation.request` body from the typed request.
    ///
    /// # Errors
    /// [`CardOperationError`] on an invalid request or an encoding failure.
    pub fn to_wire_body(&self) -> Result<BTreeMap<String, WireValue>, CardOperationError> {
        let (action, context, payload) = self.wire_parts();
        let mut body = BTreeMap::new();
        body.insert(
            "operation_id".into(),
            WireValue::Bytes(self.operation_id.as_bytes().to_vec()),
        );
        body.insert(
            "profile".into(),
            WireValue::Text(self.profile.as_str().to_owned()),
        );
        body.insert("action".into(), WireValue::Text(action.to_owned()));
        body.insert(
            "request_hash".into(),
            WireValue::Bytes(self.request_hash()?.as_bytes().to_vec()),
        );
        body.insert(
            "expires_after_ms".into(),
            WireValue::Unsigned(self.expires_after_ms),
        );
        body.insert("context".into(), WireValue::Map(context));
        body.insert("payload".into(), WireValue::Map(payload));
        Ok(body)
    }

    /// Parses an authenticated `operation.request` body and independently
    /// verifies its deterministic hash.
    ///
    /// # Errors
    /// [`CardOperationError`] on a schema violation, unregistered values, or
    /// a request-hash mismatch.
    pub fn from_wire_body(
        mut body: BTreeMap<String, WireValue>,
        pair_id: PairId,
        session_id: SessionId,
        local_start_ms: u64,
    ) -> Result<Self, CardOperationError> {
        let operation_id_bytes = take_bytes(&mut body, "operation_id")?;
        let operation_id = OperationId::reconstruct(&operation_id_bytes)
            .map_err(|_| CardOperationError::InvalidIdentifier)?;
        let profile_text = take_text(&mut body, "profile")?;
        let profile =
            ProfileName::parse(&profile_text).ok_or(CardOperationError::UnknownProfile)?;
        let action = take_text(&mut body, "action")?;
        let claimed_hash_bytes = take_bytes(&mut body, "request_hash")?;
        let claimed_hash = RequestHash::reconstruct(&claimed_hash_bytes)
            .map_err(|_| CardOperationError::InvalidIdentifier)?;
        let expires_after_ms = take_unsigned(&mut body, "expires_after_ms")?;
        let context = take_map(&mut body, "context")?;
        let payload = take_map(&mut body, "payload")?;
        if !body.is_empty() {
            return Err(CardOperationError::UnexpectedField);
        }
        let operation = CardOperation::from_wire_parts(&action, context, payload)?;
        let request = Self::reconstruct(
            operation_id,
            pair_id,
            session_id,
            profile,
            local_start_ms,
            expires_after_ms,
            operation,
        )?;
        if request.request_hash()? != claimed_hash {
            return Err(CardOperationError::RequestHashMismatch);
        }
        Ok(request)
    }
}

/// Public card state returned by `InspectCard`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CardInspection {
    /// Whether PIN 1 still has factory reference data.
    pub pin1_factory: bool,
    /// Whether PIN 2 still has factory reference data.
    pub pin2_factory: bool,
    /// Remaining PIN 1 attempts, when the card exposes it.
    pub pin1_attempts: Option<u8>,
    /// Remaining PIN 2 attempts, when the card exposes it.
    pub pin2_attempts: Option<u8>,
    /// Remaining PUK attempts, when the card exposes it.
    pub puk_attempts: Option<u8>,
}

/// Successful typed operation output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CardOperationResult {
    /// Card status read.
    Inspection(CardInspection),
    /// Display identity returned as separately labelled values.
    Identity {
        /// Cardholder display name.
        display_name: String,
        /// Cardholder person identifier.
        person_id: String,
    },
    /// DER certificate bytes.
    Certificate(Vec<u8>),
    /// Card-produced signature bytes.
    Signature(Vec<u8>),
}

fn validate_named_digest(
    display_name: &str,
    key_profile: CardKeyProfile,
    algorithm: SignatureAlgorithm,
    digest: &[u8],
) -> Result<(), CardOperationError> {
    if display_name.trim().is_empty() || display_name.len() > 512 {
        return Err(CardOperationError::InvalidDisplayContext);
    }
    if digest.len() != algorithm.digest_size() {
        return Err(CardOperationError::WrongDigestLength);
    }
    if !algorithm.supports(key_profile) {
        return Err(CardOperationError::KeyAlgorithmMismatch);
    }
    Ok(())
}

/// Rejected operation construction or hashing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardOperationError {
    /// Expiry did not follow creation.
    InvalidLifetime,
    /// Human-readable context was absent or unbounded.
    InvalidDisplayContext,
    /// Digest bytes did not match the named algorithm.
    WrongDigestLength,
    /// The requested signature scheme cannot use the expected card key.
    KeyAlgorithmMismatch,
    /// A fixed-size identifier could not be reconstructed.
    InvalidIdentifier,
    /// Action is not registered under the named credential profile.
    ProfileActionMismatch,
    /// The request names no registered action.
    UnknownAction,
    /// The request names no registered profile.
    UnknownProfile,
    /// A required typed field was absent or had the wrong value type.
    InvalidField(&'static str),
    /// A typed request contained an additional unregistered field.
    UnexpectedField,
    /// Echoed request hash did not cover the received request.
    RequestHashMismatch,
    /// Deterministic request commitment could not be constructed.
    HashFailure,
    /// Deterministic wire encoding failed.
    Wire(WireError),
}

impl From<WireError> for CardOperationError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl fmt::Display for CardOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for CardOperationError {}

fn take_text(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<String, CardOperationError> {
    match map.remove(field) {
        Some(WireValue::Text(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(field)),
    }
}

fn take_bytes(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<u8>, CardOperationError> {
    match map.remove(field) {
        Some(WireValue::Bytes(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(field)),
    }
}

fn take_unsigned(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<u64, CardOperationError> {
    match map.remove(field) {
        Some(WireValue::Unsigned(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(field)),
    }
}

fn take_map(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<BTreeMap<String, WireValue>, CardOperationError> {
    match map.remove(field) {
        Some(WireValue::Map(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(field)),
    }
}
