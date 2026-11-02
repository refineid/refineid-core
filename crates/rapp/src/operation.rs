//! Closed RAPP operation registry.
//!
//! Requests describe user-visible authorization goals. They never contain a
//! raw APDU or CAN/PIN/PUK value; card credentials are collected and retained
//! by the authorizer endpoint.

use core::fmt;
use std::collections::BTreeMap;

use super::{
    Envelope, MessageType, OPERATION_ID_SIZE, OperationId, OperationResultMessage, ProfileName,
    ResultError, SESSION_ID_SIZE, SessionId, WireError, WireValue,
};

/// The lifetime a request that names none receives (section 8.1 item 2).
pub const DEFAULT_OPERATION_LIFETIME_MS: u64 = 300_000;

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

/// ECDSA P-256 signature on the wire: 32-byte r || 32-byte s (section 9.2).
const ECDSA_P256_SIGNATURE_SIZE: usize = 64;
/// ECDSA P-384 signature on the wire: 48-byte r || 48-byte s (section 9.2).
const ECDSA_P384_SIGNATURE_SIZE: usize = 96;
/// RSA-2048 signature on the wire: the modulus length (section 9.2).
const RSA_2048_SIGNATURE_SIZE: usize = 256;
/// RSA-3072 signature on the wire: the modulus length (section 9.2).
const RSA_3072_SIGNATURE_SIZE: usize = 384;

impl CardKeyProfile {
    /// Byte length of one signature of this key on the wire (section 9.2).
    #[must_use]
    pub const fn signature_size(self) -> usize {
        match self {
            Self::EcdsaP256 => ECDSA_P256_SIGNATURE_SIZE,
            Self::EcdsaP384 => ECDSA_P384_SIGNATURE_SIZE,
            Self::Rsa2048 => RSA_2048_SIGNATURE_SIZE,
            Self::Rsa3072 => RSA_3072_SIGNATURE_SIZE,
        }
    }

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
    /// Read the card's answer to reset and supported profiles.
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
        /// Human-readable document name shown by the authorizer; for a
        /// package, the package's own name (section 9.3).
        document_name: String,
        /// The files the document holds when it is a package, shown by the
        /// authorizer under its name; `None` for a single document
        /// (section 9.3).
        contained_files: Option<ContainedFiles>,
        /// Expected public-key profile, verified again by the authorizer.
        key_profile: CardKeyProfile,
        /// Exact signature algorithm.
        algorithm: SignatureAlgorithm,
        /// Already-hashed document bytes.
        digest: Vec<u8>,
    },
    /// Sign several document digests under one consent and one PIN 2 entry
    /// (section 9.3).
    BatchSignDocuments {
        /// Human-readable document names shown by the authorizer, in
        /// signing order.
        document_names: Vec<String>,
        /// Expected public-key profile, verified again by the authorizer.
        key_profile: CardKeyProfile,
        /// Exact signature algorithm.
        algorithm: SignatureAlgorithm,
        /// Already-hashed document bytes, paired with `document_names`.
        digests: Vec<Vec<u8>>,
    },
}

/// Byte length of one name the authorizer shows: `origin` (section 9.2),
/// `document_name`, an entry of `document_names` or of `contained_files`
/// (section 9.3), `tstr .size (1..256)`.
const DISPLAY_NAME_BYTES: core::ops::RangeInclusive<usize> = 1..=256;

/// The directory an ASiC-E container reserves for its manifest and
/// signatures; no entry of `contained_files` lies under it (section 9.3).
const CONTAINER_RESERVED_DIRECTORY: &str = "META-INF/";

/// The files a package holds, as `sign_document`'s `contained_files`
/// carries them (section 9.3): the names of the data objects as the
/// container holds them, in container order, at least one, each within
/// the 1 to 256 byte name bound and not blank, unique, none under
/// `META-INF/` in any letter case.
///
/// Whether the request they travel in encodes in one frame is the
/// request's predicate, checked by [`OperationRequest::validate`], which
/// sees the whole request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainedFiles(Vec<String>);

impl ContainedFiles {
    /// The entries of a package, in container order.
    ///
    /// # Errors
    /// [`CardOperationError::InvalidDisplayContext`] for an entry outside
    /// the name bound or blank; [`CardOperationError::InvalidField`]
    /// naming `contained_files` for no entry, a repeated entry, or an
    /// entry under the container's reserved directory.
    pub fn reconstruct(names: Vec<String>) -> Result<Self, CardOperationError> {
        if names.is_empty() {
            return Err(CardOperationError::InvalidField("contained_files"));
        }
        for (index, name) in names.iter().enumerate() {
            if !DISPLAY_NAME_BYTES.contains(&name.len()) || name.trim().is_empty() {
                return Err(CardOperationError::InvalidDisplayContext);
            }
            let reserved = name
                .get(..CONTAINER_RESERVED_DIRECTORY.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(CONTAINER_RESERVED_DIRECTORY));
            if reserved || names[..index].contains(name) {
                return Err(CardOperationError::InvalidField("contained_files"));
            }
        }
        Ok(Self(names))
    }

    /// The entries, in container order; never empty.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.0
    }
}

impl CardOperation {
    /// Whether this action commands a private key behind a PIN, and so needs
    /// the holder's consent (section 8.2 item 3).
    #[must_use]
    pub const fn is_consequential(&self) -> bool {
        matches!(
            self,
            Self::BrowserAuthenticate { .. }
                | Self::SignDocument { .. }
                | Self::BatchSignDocuments { .. }
        )
    }

    /// How many documents a batch signs; `None` for any other operation.
    #[must_use]
    pub fn batch_total(&self) -> Option<usize> {
        match self {
            Self::BatchSignDocuments { digests, .. } => Some(digests.len()),
            _ => None,
        }
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
            | Self::SignDocument { .. }
            | Self::BatchSignDocuments { .. } => ProfileName::DocumentSigning,
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
                contained_files: _,
                key_profile,
                algorithm,
                digest,
            } => validate_named_digest(document_name, *key_profile, *algorithm, digest),
            Self::BatchSignDocuments {
                document_names,
                key_profile,
                algorithm,
                digests,
            } => {
                if digests.is_empty() || document_names.len() != digests.len() {
                    return Err(CardOperationError::InvalidField("digests"));
                }
                for (name, digest) in document_names.iter().zip(digests) {
                    validate_named_digest(name, *key_profile, *algorithm, digest)?;
                }
                ensure_batch_result_fits_one_frame(digests.len(), *key_profile)
            }
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
                contained_files,
                key_profile,
                algorithm,
                digest,
            } => {
                context.insert(
                    "document_name".into(),
                    WireValue::Text(document_name.clone()),
                );
                if let Some(files) = contained_files {
                    context.insert(
                        "contained_files".into(),
                        WireValue::Array(
                            files.names().iter().cloned().map(WireValue::Text).collect(),
                        ),
                    );
                }
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
            Self::BatchSignDocuments {
                document_names,
                key_profile,
                algorithm,
                digests,
            } => {
                context.insert(
                    "document_names".into(),
                    WireValue::Array(
                        document_names
                            .iter()
                            .cloned()
                            .map(WireValue::Text)
                            .collect(),
                    ),
                );
                payload.insert(
                    "key_profile".into(),
                    WireValue::Text(key_profile.wire_name().into()),
                );
                payload.insert(
                    "algorithm".into(),
                    WireValue::Text(algorithm.wire_name().into()),
                );
                payload.insert(
                    "digests".into(),
                    WireValue::Array(digests.iter().cloned().map(WireValue::Bytes).collect()),
                );
                ("batch_sign_documents", context, payload)
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
                contained_files: take_optional_text_array(&mut context, "contained_files")?
                    .map(ContainedFiles::reconstruct)
                    .transpose()?,
                key_profile: CardKeyProfile::parse(&take_text(&mut payload, "key_profile")?)?,
                algorithm: SignatureAlgorithm::parse(&take_text(&mut payload, "algorithm")?)?,
                digest: take_bytes(&mut payload, "digest")?,
            },
            "batch_sign_documents" => Self::BatchSignDocuments {
                document_names: take_text_array(&mut context, "document_names")?,
                key_profile: CardKeyProfile::parse(&take_text(&mut payload, "key_profile")?)?,
                algorithm: SignatureAlgorithm::parse(&take_text(&mut payload, "algorithm")?)?,
                digests: take_array(&mut payload, "digests")?
                    .into_iter()
                    .map(|value| match value {
                        WireValue::Bytes(digest) => Ok(digest),
                        _ => Err(CardOperationError::InvalidField("digests")),
                    })
                    .collect::<Result<_, _>>()?,
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

/// Typed request of one operation, which lives inside the session that
/// carried it (section 8.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRequest {
    /// Identifier, used once per session.
    pub operation_id: OperationId,
    /// Negotiated operation profile.
    pub profile: ProfileName,
    /// Local receipt or creation time on the continuous clock, which
    /// advances through suspension (section 8.1 item 2). This is never sent.
    pub local_start_ms: u64,
    /// Relative validity interval sent on the wire and capped by each
    /// endpoint's local policy. Wall clocks are not used.
    pub expires_after_ms: u64,
    /// Closed operation body.
    pub operation: CardOperation,
}

impl OperationRequest {
    /// Constructs and validates a local or received operation request.
    ///
    /// # Errors
    /// [`CardOperationError`] when validation rejects the request.
    pub fn reconstruct(
        operation_id: OperationId,
        profile: ProfileName,
        local_start_ms: u64,
        expires_after_ms: u64,
        operation: CardOperation,
    ) -> Result<Self, CardOperationError> {
        let request = Self {
            operation_id,
            profile,
            local_start_ms,
            expires_after_ms,
            operation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates time bounds and operation parameters, and that a package's
    /// request travels in one frame (section 9.3).
    ///
    /// # Errors
    /// [`CardOperationError`] on a zero lifetime, a profile that does not own
    /// the action, invalid operation parameters, or a package whose request
    /// exceeds one frame.
    pub fn validate(&self) -> Result<(), CardOperationError> {
        if self.expires_after_ms == 0 {
            return Err(CardOperationError::InvalidLifetime);
        }
        if self.profile != self.operation.required_profile() {
            return Err(CardOperationError::ProfileActionMismatch);
        }
        self.operation.validate()?;
        if let CardOperation::SignDocument {
            contained_files: Some(_),
            ..
        } = &self.operation
        {
            self.ensure_request_fits_one_frame()?;
        }
        Ok(())
    }

    /// Check that this request travels in one frame (section 7.2 item 4):
    /// its `operation.request` envelope at the widest sequence encoding is
    /// built and encoded against the single-frame limit.
    ///
    /// # Errors
    /// [`CardOperationError::PackageTooLarge`] when that envelope exceeds one
    /// frame; any other encoding failure as itself.
    fn ensure_request_fits_one_frame(&self) -> Result<(), CardOperationError> {
        let envelope = Envelope::reconstruct(
            MessageType::OperationRequest,
            SessionId::from_array([u8::MIN; SESSION_ID_SIZE]),
            u64::MAX,
            self.wire_body(),
        )
        .map_err(CardOperationError::Wire)?;
        match envelope.encode() {
            Ok(_) => Ok(()),
            Err(WireError::OversizedPlaintext { .. }) => Err(CardOperationError::PackageTooLarge),
            Err(error) => Err(CardOperationError::Wire(error)),
        }
    }

    /// Local deadline on the continuous clock with an endpoint-specific
    /// maximum lifetime (section 8.1 item 2).
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
        self.validate()?;
        Ok(self.wire_body())
    }

    /// The `operation.request` body of this request as the wire carries it,
    /// valid or not.
    fn wire_body(&self) -> BTreeMap<String, WireValue> {
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
            "expires_after_ms".into(),
            WireValue::Unsigned(self.expires_after_ms),
        );
        body.insert("context".into(), WireValue::Map(context));
        body.insert("payload".into(), WireValue::Map(payload));
        body
    }

    /// Parses an authenticated `operation.request` body.
    ///
    /// # Errors
    /// [`RequestError::Malformed`] on a schema violation, and
    /// [`RequestError::Refused`] when the request is well formed but names a
    /// lifetime, profile, action, or parameter this endpoint cannot serve.
    pub fn from_wire_body(
        mut body: BTreeMap<String, WireValue>,
        local_start_ms: u64,
    ) -> Result<Self, RequestError> {
        let operation_id_bytes = take_bytes(&mut body, "operation_id")?;
        let operation_id = OperationId::reconstruct(&operation_id_bytes)
            .map_err(|_| CardOperationError::InvalidIdentifier)?;
        let profile_text = take_text(&mut body, "profile")?;
        let action = take_text(&mut body, "action")?;
        let context = take_map(&mut body, "context")?;
        let payload = take_map(&mut body, "payload")?;
        let expires_after_ms = if body.contains_key("expires_after_ms") {
            take_unsigned(&mut body, "expires_after_ms")?
        } else {
            DEFAULT_OPERATION_LIFETIME_MS
        };
        if !body.is_empty() {
            return Err(CardOperationError::UnexpectedField.into());
        }
        let refuse = |error| {
            RequestError::Refused(OperationRequestRefusal {
                operation_id,
                error,
            })
        };
        if expires_after_ms == 0 {
            return Err(refuse(ResultError::InvalidLifetime));
        }
        let Some(profile) = ProfileName::parse(&profile_text) else {
            return Err(refuse(ResultError::UnsupportedParameter));
        };
        CardOperation::from_wire_parts(&action, context, payload)
            .and_then(|operation| {
                Self::reconstruct(
                    operation_id,
                    profile,
                    local_start_ms,
                    expires_after_ms,
                    operation,
                )
            })
            .map_err(|_| refuse(ResultError::UnsupportedParameter))
    }
}

/// A request that parsed as an envelope but names something this endpoint
/// cannot serve.
///
/// It is answered with a rejected result, so it carries the identifier the
/// result names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationRequestRefusal {
    /// The identifier the refusal result names.
    pub operation_id: OperationId,
    /// The registered rejection error.
    pub error: ResultError,
}

/// Why a received `operation.request` body cannot become a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    /// The body violates the registered schema.
    Malformed(CardOperationError),
    /// The body is well formed but cannot be served; answer with a result.
    Refused(OperationRequestRefusal),
}

impl From<CardOperationError> for RequestError {
    fn from(error: CardOperationError) -> Self {
        Self::Malformed(error)
    }
}

/// The `inspect_card` answer (section 9.1). PIN state stays on the
/// custodian.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardInspection {
    /// The answer to reset, or its historical bytes where the platform hides
    /// the rest; empty when the platform exposes neither.
    pub answer_to_reset: Vec<u8>,
}

/// Successful typed operation output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CardOperationResult {
    /// Card status read.
    Inspection(CardInspection),
    /// The `read_identity` answer (section 9.1).
    Identity(CardIdentity),
    /// DER certificate bytes.
    Certificate(Vec<u8>),
    /// Card-produced signature bytes.
    Signature(Vec<u8>),
    /// The ordered signatures of a batch, one per document.
    Signatures(Vec<Vec<u8>>),
}

/// The `read_identity` answer (section 9.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardIdentity {
    /// Cardholder name, 1 to 128 bytes.
    pub holder_name: String,
    /// Card identifier, 1 to 64 bytes.
    pub card_id: String,
    /// `YYYY-MM-DD`.
    pub issuance_date: String,
    /// `YYYY-MM-DD`.
    pub expiration_date: String,
    /// DER-encoded X.509 certificates, at least one.
    pub certificates: Vec<Vec<u8>>,
    /// Optional token label, 1 to 64 bytes.
    pub token_display_name: Option<String>,
}

/// Byte bounds of the `read_identity` response schema (section 9.1).
const HOLDER_NAME_BYTES: core::ops::RangeInclusive<usize> = 1..=128;
const CARD_ID_BYTES: core::ops::RangeInclusive<usize> = 1..=64;
const DATE_BYTES: usize = 10;
const TOKEN_DISPLAY_NAME_BYTES: core::ops::RangeInclusive<usize> = 1..=64;

impl CardIdentity {
    /// Constructs an identity answer within the section 9.1 bounds.
    ///
    /// # Errors
    /// [`CardOperationError::InvalidField`] naming the first field outside
    /// its bounds.
    pub fn reconstruct(
        holder_name: String,
        card_id: String,
        issuance_date: String,
        expiration_date: String,
        certificates: Vec<Vec<u8>>,
        token_display_name: Option<String>,
    ) -> Result<Self, CardOperationError> {
        if !HOLDER_NAME_BYTES.contains(&holder_name.len()) {
            return Err(CardOperationError::InvalidField("card_holder_name"));
        }
        if !CARD_ID_BYTES.contains(&card_id.len()) {
            return Err(CardOperationError::InvalidField("card_id"));
        }
        if issuance_date.len() != DATE_BYTES {
            return Err(CardOperationError::InvalidField("issuance_date"));
        }
        if expiration_date.len() != DATE_BYTES {
            return Err(CardOperationError::InvalidField("expiration_date"));
        }
        if certificates.is_empty() || certificates.iter().any(Vec::is_empty) {
            return Err(CardOperationError::InvalidField("certificates"));
        }
        if token_display_name
            .as_ref()
            .is_some_and(|name| !TOKEN_DISPLAY_NAME_BYTES.contains(&name.len()))
        {
            return Err(CardOperationError::InvalidField("token_display_name"));
        }
        Ok(Self {
            holder_name,
            card_id,
            issuance_date,
            expiration_date,
            certificates,
            token_display_name,
        })
    }
}

fn validate_named_digest(
    display_name: &str,
    key_profile: CardKeyProfile,
    algorithm: SignatureAlgorithm,
    digest: &[u8],
) -> Result<(), CardOperationError> {
    if display_name.trim().is_empty() || !DISPLAY_NAME_BYTES.contains(&display_name.len()) {
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

/// Check that the completed result of a batch of `count` signatures of
/// `key_profile` travels in one frame (section 7.2 item 4): the largest
/// `operation.result` envelope such a batch can produce is built and
/// encoded against the single-frame limit.
///
/// # Errors
/// [`CardOperationError::BatchTooLarge`] when that envelope exceeds one
/// frame; any other encoding failure as itself.
fn ensure_batch_result_fits_one_frame(
    count: usize,
    key_profile: CardKeyProfile,
) -> Result<(), CardOperationError> {
    let signature = vec![u8::MIN; key_profile.signature_size()];
    let result = CardOperationResult::Signatures(vec![signature; count]);
    let body = OperationResultMessage::completed(
        OperationId::from_array([u8::MIN; OPERATION_ID_SIZE]),
        &result,
    )
    .to_wire_body()?;
    let envelope = Envelope::reconstruct(
        MessageType::OperationResult,
        SessionId::from_array([u8::MIN; SESSION_ID_SIZE]),
        u64::MAX,
        body,
    )
    .map_err(CardOperationError::Wire)?;
    match envelope.encode() {
        Ok(_) => Ok(()),
        Err(WireError::OversizedPlaintext { .. }) => Err(CardOperationError::BatchTooLarge),
        Err(error) => Err(CardOperationError::Wire(error)),
    }
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
    /// The signatures of the batch do not fit one result frame.
    BatchTooLarge,
    /// The request of a package, with every file it holds, does not fit one
    /// frame.
    PackageTooLarge,
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
    /// A result names another operation than the one it answers.
    OperationMismatch,
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

fn take_array(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<WireValue>, CardOperationError> {
    match map.remove(field) {
        Some(WireValue::Array(value)) => Ok(value),
        _ => Err(CardOperationError::InvalidField(field)),
    }
}

/// A present array of text values; a missing field or any other value type
/// is a schema violation.
fn take_text_array(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<String>, CardOperationError> {
    take_array(map, field)?
        .into_iter()
        .map(|value| match value {
            WireValue::Text(name) => Ok(name),
            _ => Err(CardOperationError::InvalidField(field)),
        })
        .collect()
}

/// An array of text values when the field is present, `None` when it is
/// absent; a present field of any other shape is a schema violation.
fn take_optional_text_array(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Option<Vec<String>>, CardOperationError> {
    if map.contains_key(field) {
        take_text_array(map, field).map(Some)
    } else {
        Ok(None)
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
