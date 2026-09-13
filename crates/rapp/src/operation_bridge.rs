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

//! Closed generated binding for durable RAPP operations.
//!
//! The platform transports only opaque encrypted frames and receives bounded
//! semantic actions. It never receives a generic decrypted protocol message,
//! raw APDU, CAN, PIN, PUK, pair key, or journal body.

use std::sync::{Arc, Mutex, MutexGuard};

use super::{
    AuthorizedCardCommand, BinaryFrame, CardInspection, CardKeyProfile, CardOperation,
    CardOperationResult, CertificateKind, EndpointError, EstablishedSessionRuntime, LivenessConfig,
    OperationId, OperationReference, OperationRequest, OperationResultMessage, OperationState,
    PairId, PingChallenge, ProfileName, ProxyDispatch, ProxyEngineError, ProxyOperationEngine,
    RequesterDispatch, RequesterEngineError, RequesterOperationEngine, ResultError, ResultStatus,
    RuntimeError, RuntimePoll, RuntimeReceive, SessionId, SignatureAlgorithm, TypedMessage,
    UserApproval,
    bindings::{BindingPairStore, RappBindingError, RappSessionBridge, fixed_array},
    operation_bindings::{BindingOperationStore, RappOperationVault},
};

/// Closed operation names exposed to platform card adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappOperationKind {
    /// Inspect supported card and retry state; no consequential command.
    InspectCard,
    /// Read the cardholder identity; no consequential command.
    ReadIdentity,
    /// Read the authentication certificate; a safe read.
    ReadAuthenticationCertificate,
    /// Read the signature certificate; a safe read.
    ReadSignatureCertificate,
    /// PIN 1 verify and private-key operation over a hashed challenge.
    BrowserAuthenticate,
    /// PIN 2 verify and private-key operation over a document digest.
    SignDocument,
}

/// Registered public-key profiles; arbitrary key descriptions cannot cross the binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappCardKeyProfile {
    /// ECDSA P-256 key.
    EcdsaP256,
    /// ECDSA P-384 key.
    EcdsaP384,
    /// RSA 2048-bit key.
    Rsa2048,
    /// RSA 3072-bit key.
    Rsa3072,
}

impl From<RappCardKeyProfile> for CardKeyProfile {
    fn from(value: RappCardKeyProfile) -> Self {
        match value {
            RappCardKeyProfile::EcdsaP256 => Self::EcdsaP256,
            RappCardKeyProfile::EcdsaP384 => Self::EcdsaP384,
            RappCardKeyProfile::Rsa2048 => Self::Rsa2048,
            RappCardKeyProfile::Rsa3072 => Self::Rsa3072,
        }
    }
}

const fn exported_key_profile(value: CardKeyProfile) -> RappCardKeyProfile {
    match value {
        CardKeyProfile::EcdsaP256 => RappCardKeyProfile::EcdsaP256,
        CardKeyProfile::EcdsaP384 => RappCardKeyProfile::EcdsaP384,
        CardKeyProfile::Rsa2048 => RappCardKeyProfile::Rsa2048,
        CardKeyProfile::Rsa3072 => RappCardKeyProfile::Rsa3072,
    }
}

/// Exact closed signature algorithms supported by card adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappSignatureAlgorithm {
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

impl From<RappSignatureAlgorithm> for SignatureAlgorithm {
    fn from(value: RappSignatureAlgorithm) -> Self {
        match value {
            RappSignatureAlgorithm::EcdsaSha224 => Self::EcdsaSha224,
            RappSignatureAlgorithm::EcdsaSha256 => Self::EcdsaSha256,
            RappSignatureAlgorithm::EcdsaSha384 => Self::EcdsaSha384,
            RappSignatureAlgorithm::EcdsaSha512 => Self::EcdsaSha512,
            RappSignatureAlgorithm::RsaPkcs1Sha256 => Self::RsaPkcs1Sha256,
            RappSignatureAlgorithm::RsaPkcs1Sha384 => Self::RsaPkcs1Sha384,
            RappSignatureAlgorithm::RsaPkcs1Sha512 => Self::RsaPkcs1Sha512,
            RappSignatureAlgorithm::RsaPssSha256 => Self::RsaPssSha256,
        }
    }
}

const fn exported_algorithm(value: SignatureAlgorithm) -> RappSignatureAlgorithm {
    match value {
        SignatureAlgorithm::EcdsaSha224 => RappSignatureAlgorithm::EcdsaSha224,
        SignatureAlgorithm::EcdsaSha256 => RappSignatureAlgorithm::EcdsaSha256,
        SignatureAlgorithm::EcdsaSha384 => RappSignatureAlgorithm::EcdsaSha384,
        SignatureAlgorithm::EcdsaSha512 => RappSignatureAlgorithm::EcdsaSha512,
        SignatureAlgorithm::RsaPkcs1Sha256 => RappSignatureAlgorithm::RsaPkcs1Sha256,
        SignatureAlgorithm::RsaPkcs1Sha384 => RappSignatureAlgorithm::RsaPkcs1Sha384,
        SignatureAlgorithm::RsaPkcs1Sha512 => RappSignatureAlgorithm::RsaPkcs1Sha512,
        SignatureAlgorithm::RsaPssSha256 => RappSignatureAlgorithm::RsaPssSha256,
    }
}

/// Exact user-visible or card-adapter operation, without local credentials.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappOperationDescriptor {
    /// Registered operation name.
    pub kind: RappOperationKind,
    /// Requester-asserted origin or document name shown to the authorizer.
    pub display_context: Option<String>,
    /// Expected key profile of the selected certificate.
    pub key_profile: Option<RappCardKeyProfile>,
    /// Exact signature algorithm.
    pub algorithm: Option<RappSignatureAlgorithm>,
    /// Already-hashed input of the registered length.
    pub digest: Vec<u8>,
}

impl From<&CardOperation> for RappOperationDescriptor {
    fn from(operation: &CardOperation) -> Self {
        match operation {
            CardOperation::InspectCard => Self {
                kind: RappOperationKind::InspectCard,
                display_context: None,
                key_profile: None,
                algorithm: None,
                digest: Vec::new(),
            },
            CardOperation::ReadIdentity => Self {
                kind: RappOperationKind::ReadIdentity,
                display_context: None,
                key_profile: None,
                algorithm: None,
                digest: Vec::new(),
            },
            CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            } => Self {
                kind: RappOperationKind::ReadAuthenticationCertificate,
                display_context: None,
                key_profile: None,
                algorithm: None,
                digest: Vec::new(),
            },
            CardOperation::ReadCertificate {
                kind: CertificateKind::Signature,
            } => Self {
                kind: RappOperationKind::ReadSignatureCertificate,
                display_context: None,
                key_profile: None,
                algorithm: None,
                digest: Vec::new(),
            },
            CardOperation::BrowserAuthenticate {
                origin,
                key_profile,
                algorithm,
                digest,
            } => Self {
                kind: RappOperationKind::BrowserAuthenticate,
                display_context: Some(origin.clone()),
                key_profile: Some(exported_key_profile(*key_profile)),
                algorithm: Some(exported_algorithm(*algorithm)),
                digest: digest.clone(),
            },
            CardOperation::SignDocument {
                document_name,
                key_profile,
                algorithm,
                digest,
            } => Self {
                kind: RappOperationKind::SignDocument,
                display_context: Some(document_name.clone()),
                key_profile: Some(exported_key_profile(*key_profile)),
                algorithm: Some(exported_algorithm(*algorithm)),
                digest: digest.clone(),
            },
        }
    }
}

/// Advisory progress events exposed to platform callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappProgressEvent {
    /// Proxy is waiting for card presentation.
    WaitingForCard,
    /// Card presentation wait has ended.
    CardWaitEnded,
}

impl From<RappProgressEvent> for super::ProgressEvent {
    fn from(value: RappProgressEvent) -> Self {
        match value {
            RappProgressEvent::WaitingForCard => Self::WaitingForCard,
            RappProgressEvent::CardWaitEnded => Self::CardWaitEnded,
        }
    }
}

impl From<super::ProgressEvent> for RappProgressEvent {
    fn from(value: super::ProgressEvent) -> Self {
        match value {
            super::ProgressEvent::WaitingForCard => Self::WaitingForCard,
            super::ProgressEvent::CardWaitEnded => Self::CardWaitEnded,
        }
    }
}

/// Bounded action produced by the authoritative Rust state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappBridgeActionKind {
    /// Deliver one opaque encrypted frame to the transport.
    SendFrame,
    /// Perform the profile's safe prerequisite inspection.
    InspectPrerequisites,
    /// Present the descriptor and wait for the human authorizer.
    AwaitUserApproval,
    /// Execute the described safe read; no consequential command.
    ExecuteSafeRead,
    /// Execute the single authorized card command.
    ExecuteCardCommand,
    /// Frame carrying the acknowledgment of a completed result.
    ResultAcknowledgment,
    /// Operation reached its completed terminal state.
    Completed,
    /// Operation reached the named terminal state.
    Terminal,
    /// Operation was safely cancelled.
    Cancelled,
    /// Post-commit cancel recorded; the operation continues.
    AdvisoryCancellation,
    /// Peer acknowledged the completed result.
    ResultAcknowledged,
    /// Advisory progress update reported by peer.
    Progress,
    /// Peer already serves a live session for this pairing.
    PeerBusy,
    /// Peer answered a stale reference; a normal race.
    PeerUnknownOperation,
    /// Duplicate commit matching the committed hash was discarded.
    IgnoredDuplicate,
    /// Nothing to execute.
    NoAction,
    /// Session closed; the pairing remains stored.
    SessionClosed,
    /// Pairing was revoked and its keys destroyed.
    PairRevoked,
}

/// Stable terminal reason exposed without transport or backend error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappTerminalReason {
    /// Human authorizer denied the operation.
    UserDenied,
    /// Local monotonic request expiry elapsed.
    RequestExpired,
    /// Cancellation proven before physical transmission.
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

impl From<ResultError> for RappTerminalReason {
    fn from(error: ResultError) -> Self {
        match error {
            ResultError::UserDenied => Self::UserDenied,
            ResultError::RequestExpired => Self::RequestExpired,
            ResultError::Cancelled => Self::Cancelled,
            ResultError::RequestInvalidOrUnsupported => Self::RequestInvalidOrUnsupported,
            ResultError::RetryPolicyRefused => Self::RetryPolicyRefused,
            ResultError::CredentialRejected => Self::CredentialRejected,
            ResultError::CardRemovedBeforeTransmit => Self::CardRemovedBeforeTransmit,
            ResultError::CardCompletionAmbiguous => Self::CardCompletionAmbiguous,
        }
    }
}

/// One bridge action. Only `SendFrame` and `ResultAcknowledgment` contain
/// opaque ciphertext. Operation data is a closed semantic descriptor.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappBridgeAction {
    /// Bounded action to execute.
    pub kind: RappBridgeActionKind,
    /// Referenced operation identifier bytes.
    pub operation_id: Option<Vec<u8>>,
    /// Closed semantic descriptor of the operation.
    pub operation: Option<RappOperationDescriptor>,
    /// Opaque encrypted frame for the transport.
    pub frame: Option<Vec<u8>>,
    /// Journaled terminal state name.
    pub terminal_state: Option<String>,
    /// Stable terminal reason.
    pub terminal_reason: Option<RappTerminalReason>,
    /// Advisory progress event.
    pub progress_event: Option<RappProgressEvent>,
    /// The session must close after this frame is delivered.
    pub close_session_after_send: bool,
    /// Monotonic time of the next required liveness poll.
    pub next_poll_at_ms: Option<u64>,
}

impl RappBridgeAction {
    const fn simple(kind: RappBridgeActionKind) -> Self {
        Self {
            kind,
            operation_id: None,
            operation: None,
            frame: None,
            terminal_state: None,
            terminal_reason: None,
            progress_event: None,
            close_session_after_send: false,
            next_poll_at_ms: None,
        }
    }

    fn for_operation(kind: RappBridgeActionKind, operation_id: OperationId) -> Self {
        Self {
            operation_id: Some(operation_id.as_bytes().to_vec()),
            ..Self::simple(kind)
        }
    }

    fn send(
        kind: RappBridgeActionKind,
        operation_id: Option<OperationId>,
        frame: BinaryFrame,
        close_session_after_send: bool,
    ) -> Self {
        Self {
            kind,
            operation_id: operation_id.map(|id| id.as_bytes().to_vec()),
            operation: None,
            frame: Some(frame.into_bytes()),
            terminal_state: None,
            terminal_reason: None,
            progress_event: None,
            close_session_after_send,
            next_poll_at_ms: None,
        }
    }
}

/// Injected monotonic liveness policy without hidden timing constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappLivenessConfiguration {
    /// Interval between probes while healthy.
    pub base_interval_ms: u64,
    /// Deadline for the exact challenge echo.
    pub response_timeout_ms: u64,
    /// Upper bound of the backoff interval.
    pub maximum_interval_ms: u64,
    /// Upper bound of caller-generated jitter.
    pub maximum_jitter_ms: u64,
    /// Consecutive misses closing the session.
    pub maximum_misses: u8,
}

impl RappLivenessConfiguration {
    fn core(self) -> Result<LivenessConfig, RappBindingError> {
        LivenessConfig {
            base_interval_ms: self.base_interval_ms,
            response_timeout_ms: self.response_timeout_ms,
            maximum_interval_ms: self.maximum_interval_ms,
            maximum_jitter_ms: self.maximum_jitter_ms,
            maximum_misses: self.maximum_misses,
        }
        .validate()
        .map_err(|_| RappBindingError::InvalidInput)
    }
}

/// Successful requester result in a stable generated-binding shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappResultKind {
    /// Card and retry-state inspection.
    Inspection,
    /// Cardholder identity read.
    Identity,
    /// Certificate read.
    Certificate,
    /// Private-key signature.
    Signature,
}

/// Profile-defined result body in a stable generated-binding shape.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappOperationResult {
    /// Registered result shape.
    pub kind: RappResultKind,
    /// Whether PIN 1 is still in factory state.
    pub pin1_factory: Option<bool>,
    /// Whether PIN 2 is still in factory state.
    pub pin2_factory: Option<bool>,
    /// Remaining PIN 1 try counter.
    pub pin1_attempts: Option<u8>,
    /// Remaining PIN 2 try counter.
    pub pin2_attempts: Option<u8>,
    /// Remaining PUK try counter.
    pub puk_attempts: Option<u8>,
    /// Cardholder display name.
    pub display_name: Option<String>,
    /// Cardholder person identifier.
    pub person_id: Option<String>,
    /// Certificate or signature bytes.
    pub bytes: Vec<u8>,
}

impl From<CardOperationResult> for RappOperationResult {
    fn from(result: CardOperationResult) -> Self {
        match result {
            CardOperationResult::Inspection(value) => Self {
                kind: RappResultKind::Inspection,
                pin1_factory: Some(value.pin1_factory),
                pin2_factory: Some(value.pin2_factory),
                pin1_attempts: value.pin1_attempts,
                pin2_attempts: value.pin2_attempts,
                puk_attempts: value.puk_attempts,
                display_name: None,
                person_id: None,
                bytes: Vec::new(),
            },
            CardOperationResult::Identity {
                display_name,
                person_id,
            } => Self {
                kind: RappResultKind::Identity,
                pin1_factory: None,
                pin2_factory: None,
                pin1_attempts: None,
                pin2_attempts: None,
                puk_attempts: None,
                display_name: Some(display_name),
                person_id: Some(person_id),
                bytes: Vec::new(),
            },
            CardOperationResult::Certificate(bytes) => Self {
                kind: RappResultKind::Certificate,
                pin1_factory: None,
                pin2_factory: None,
                pin1_attempts: None,
                pin2_attempts: None,
                puk_attempts: None,
                display_name: None,
                person_id: None,
                bytes,
            },
            CardOperationResult::Signature(bytes) => Self {
                kind: RappResultKind::Signature,
                pin1_factory: None,
                pin2_factory: None,
                pin1_attempts: None,
                pin2_attempts: None,
                puk_attempts: None,
                display_name: None,
                person_id: None,
                bytes,
            },
        }
    }
}

enum OperationBridgeState {
    Requester {
        runtime: EstablishedSessionRuntime,
        pair_store: BindingPairStore,
        journal: BindingOperationStore,
        engine: RequesterOperationEngine,
        pair_id: PairId,
        session_id: SessionId,
        granted_profiles: Vec<ProfileName>,
    },
    Proxy {
        runtime: EstablishedSessionRuntime,
        pair_store: BindingPairStore,
        journal: BindingOperationStore,
        engine: ProxyOperationEngine,
        requests: Vec<OperationRequest>,
    },
    Closed,
    Revoked,
}

/// One established RAPP session with closed, durable operation dispatch.
#[allow(
    missing_debug_implementations,
    reason = "state holds session keys and credential-bearing engines; no formatted view exists"
)]
#[derive(uniffi::Object)]
pub struct RappOperationBridge {
    state: Mutex<OperationBridgeState>,
    maximum_lifetime_ms: u64,
}

#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "uniffi lowers exported arguments as owned values"
)]
impl RappOperationBridge {
    /// Take the established session as the requester and recover the
    /// durable operation engine from the vault.
    ///
    /// # Errors
    /// [`RappBindingError`] on an invalid lifetime or liveness policy, a
    /// session that is not established, or a failed journal recovery.
    #[uniffi::constructor]
    pub fn begin_requester(
        session: Arc<RappSessionBridge>,
        vault: Arc<dyn RappOperationVault>,
        maximum_lifetime_ms: u64,
        liveness: RappLivenessConfiguration,
        now_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        require_lifetime(maximum_lifetime_ms)?;
        let (endpoint, pair_store, pair_id, session_id, granted_profiles) =
            session.take_established()?;
        let runtime = EstablishedSessionRuntime::new(endpoint, liveness.core()?, now_ms)
            .map_err(|_| RappBindingError::InvalidInput)?;
        let mut journal = BindingOperationStore::new(pair_id, vault);
        let engine = RequesterOperationEngine::recover(&mut journal)
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        Ok(Arc::new(Self {
            state: Mutex::new(OperationBridgeState::Requester {
                runtime,
                pair_store,
                journal,
                engine,
                pair_id,
                session_id,
                granted_profiles,
            }),
            maximum_lifetime_ms,
        }))
    }

    /// Take the established session as the proxy and recover the durable
    /// operation engine from the vault.
    ///
    /// # Errors
    /// [`RappBindingError`] on an invalid lifetime or liveness policy, a
    /// session that is not established, or a failed journal recovery.
    #[uniffi::constructor]
    pub fn begin_proxy(
        session: Arc<RappSessionBridge>,
        vault: Arc<dyn RappOperationVault>,
        maximum_lifetime_ms: u64,
        liveness: RappLivenessConfiguration,
        now_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        require_lifetime(maximum_lifetime_ms)?;
        let (endpoint, pair_store, pair_id, _, granted_profiles) = session.take_established()?;
        let runtime = EstablishedSessionRuntime::new(endpoint, liveness.core()?, now_ms)
            .map_err(|_| RappBindingError::InvalidInput)?;
        let mut journal = BindingOperationStore::new(pair_id, vault);
        let engine = ProxyOperationEngine::recover(&mut journal, granted_profiles)
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        Ok(Arc::new(Self {
            state: Mutex::new(OperationBridgeState::Proxy {
                runtime,
                pair_store,
                journal,
                engine,
                requests: Vec::new(),
            }),
            maximum_lifetime_ms,
        }))
    }

    /// Begin a card and retry-state inspection.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, an ungranted profile, or the
    /// wrong protocol phase.
    pub fn begin_inspect_card(
        &self,
        operation_id: Vec<u8>,
        local_start_ms: u64,
        expires_after_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.begin_operation(
            &operation_id,
            local_start_ms,
            expires_after_ms,
            CardOperation::InspectCard,
        )
    }

    /// Begin a cardholder identity read.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, an ungranted profile, or the
    /// wrong protocol phase.
    pub fn begin_read_identity(
        &self,
        operation_id: Vec<u8>,
        local_start_ms: u64,
        expires_after_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.begin_operation(
            &operation_id,
            local_start_ms,
            expires_after_ms,
            CardOperation::ReadIdentity,
        )
    }

    /// Begin a certificate read; owned by the profile whose key the
    /// certificate serves.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, an ungranted profile, or the
    /// wrong protocol phase.
    pub fn begin_read_certificate(
        &self,
        operation_id: Vec<u8>,
        signature_certificate: bool,
        local_start_ms: u64,
        expires_after_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.begin_operation(
            &operation_id,
            local_start_ms,
            expires_after_ms,
            CardOperation::ReadCertificate {
                kind: if signature_certificate {
                    CertificateKind::Signature
                } else {
                    CertificateKind::Authentication
                },
            },
        )
    }

    /// Begin a browser authentication over an already-hashed challenge.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, an ungranted profile, or the
    /// wrong protocol phase.
    #[allow(
        clippy::too_many_arguments,
        reason = "the closed action schema fixes every request field"
    )]
    pub fn begin_browser_authentication(
        &self,
        operation_id: Vec<u8>,
        origin: String,
        key_profile: RappCardKeyProfile,
        algorithm: RappSignatureAlgorithm,
        digest: Vec<u8>,
        local_start_ms: u64,
        expires_after_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.begin_operation(
            &operation_id,
            local_start_ms,
            expires_after_ms,
            CardOperation::BrowserAuthenticate {
                origin,
                key_profile: key_profile.into(),
                algorithm: algorithm.into(),
                digest,
            },
        )
    }

    /// Begin a document signature over a document digest.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, an ungranted profile, or the
    /// wrong protocol phase.
    #[allow(
        clippy::too_many_arguments,
        reason = "the closed action schema fixes every request field"
    )]
    pub fn begin_sign_document(
        &self,
        operation_id: Vec<u8>,
        document_name: String,
        key_profile: RappCardKeyProfile,
        algorithm: RappSignatureAlgorithm,
        digest: Vec<u8>,
        local_start_ms: u64,
        expires_after_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.begin_operation(
            &operation_id,
            local_start_ms,
            expires_after_ms,
            CardOperation::SignDocument {
                document_name,
                key_profile: key_profile.into(),
                algorithm: algorithm.into(),
                digest,
            },
        )
    }

    /// Decrypt, authenticate, schema-check, and dispatch one opaque frame.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, a protocol failure, or a
    /// poisoned local state.
    #[allow(
        clippy::too_many_lines,
        reason = "frame ingress is one dispatch over both role state machines and reads best unsplit"
    )]
    pub fn receive_frame(
        &self,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        let mut state = self.lock_state()?;
        match &mut *state {
            OperationBridgeState::Requester {
                runtime,
                pair_store,
                journal,
                engine,
                ..
            } => {
                let message = match receive_runtime(runtime, pair_store, &frame, now_ms)? {
                    RuntimeFrame::Message(message) => message,
                    RuntimeFrame::Action(action) => return Ok(action),
                    RuntimeFrame::Terminal { action, revoked } => {
                        engine
                            .session_closed(journal)
                            .map_err(|_| RappBindingError::LocalStateFailure)?;
                        *state = if revoked {
                            OperationBridgeState::Revoked
                        } else {
                            OperationBridgeState::Closed
                        };
                        return Ok(action);
                    }
                };
                let terminal_reason = match &message {
                    TypedMessage::OperationResult(result) => result.error.map(Into::into),
                    _ => None,
                };
                let dispatch = match engine.receive(journal, message) {
                    Ok(dispatch) => dispatch,
                    Err(RequesterEngineError::AuthenticatedProtocolViolation(violation)) => {
                        let _ = runtime
                            .endpoint_mut()
                            .revoke_requester_violation(pair_store, now_ms, violation);
                        *state = OperationBridgeState::Revoked;
                        return Ok(RappBridgeAction::simple(RappBridgeActionKind::PairRevoked));
                    }
                    Err(_) => return Err(RappBindingError::LocalStateFailure),
                };
                let credential_rejected =
                    terminal_reason == Some(RappTerminalReason::CredentialRejected);
                let mut action =
                    requester_dispatch(runtime, journal, engine, dispatch, terminal_reason)?;
                if credential_rejected {
                    runtime
                        .endpoint_mut()
                        .revoke_credential_rejection(pair_store, now_ms)
                        .map_err(|_| RappBindingError::LocalStateFailure)?;
                    action.close_session_after_send = true;
                    *state = OperationBridgeState::Revoked;
                    return Ok(action);
                }
                if action_closes_session(&action) {
                    *state = OperationBridgeState::Closed;
                }
                Ok(action)
            }
            OperationBridgeState::Proxy {
                runtime,
                pair_store,
                journal,
                engine,
                requests,
            } => {
                let message = match receive_runtime(runtime, pair_store, &frame, now_ms)? {
                    RuntimeFrame::Message(message) => message,
                    RuntimeFrame::Action(action) => return Ok(action),
                    RuntimeFrame::Terminal { action, revoked } => {
                        engine
                            .session_closed(journal)
                            .map_err(|_| RappBindingError::LocalStateFailure)?;
                        *state = if revoked {
                            OperationBridgeState::Revoked
                        } else {
                            OperationBridgeState::Closed
                        };
                        return Ok(action);
                    }
                };
                let incoming_request = match &message {
                    TypedMessage::OperationRequest(request) => Some(request.clone()),
                    _ => None,
                };
                let dispatch =
                    match engine.receive(journal, message, now_ms, self.maximum_lifetime_ms) {
                        Ok(dispatch) => dispatch,
                        Err(ProxyEngineError::AuthenticatedProtocolViolation(violation)) => {
                            let _ = runtime
                                .endpoint_mut()
                                .revoke_proxy_violation(pair_store, now_ms, violation);
                            *state = OperationBridgeState::Revoked;
                            return Ok(RappBridgeAction::simple(RappBridgeActionKind::PairRevoked));
                        }
                        Err(_) => return Err(RappBindingError::LocalStateFailure),
                    };
                if let Some(request) = incoming_request
                    && matches!(dispatch, ProxyDispatch::InspectPrerequisites(_))
                {
                    requests.push(request);
                }
                let action = proxy_dispatch(runtime, journal, engine, requests, dispatch)?;
                if action_closes_session(&action) {
                    *state = OperationBridgeState::Closed;
                    drop(state);
                }
                Ok(action)
            }
            OperationBridgeState::Closed => Err(RappBindingError::WrongPhase),
            OperationBridgeState::Revoked => Err(RappBindingError::PairNotFound),
        }
    }

    /// Mark bounded card-status/certificate prerequisites complete.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn prerequisites_complete(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(&operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            engine, requests, ..
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        engine
            .prerequisites_complete(operation_id)
            .map_err(|_| RappBindingError::WrongPhase)?;
        let mut action =
            RappBridgeAction::for_operation(RappBridgeActionKind::AwaitUserApproval, operation_id);
        action.operation = Some((&request(requests, operation_id)?.operation).into());
        drop(state);
        Ok(action)
    }

    /// Approve exactly the request displayed by the authorizer UI.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn approve(
        &self,
        operation_id: Vec<u8>,
        approved_at_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(&operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime,
            journal,
            engine,
            requests,
            ..
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let approval = UserApproval::for_request(request(requests, operation_id)?, approved_at_ms)
            .map_err(|_| RappBindingError::InvalidInput)?;
        let dispatch = engine
            .approve(
                operation_id,
                approval,
                approved_at_ms,
                self.maximum_lifetime_ms,
            )
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, journal, engine, requests, dispatch)?;
        if action_closes_session(&action) {
            *state = OperationBridgeState::Closed;
            drop(state);
        }
        Ok(action)
    }

    /// Deny the exact request and durably emit a stable denial.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn deny(&self, operation_id: Vec<u8>) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(&operation_id, ResultStatus::Denied, ResultError::UserDenied)
    }

    /// Reject a request whose authenticated descriptor is unsupported or
    /// contradicts the live card's certificate/profile.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn request_invalid_or_unsupported(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(
            &operation_id,
            ResultStatus::Rejected,
            ResultError::RequestInvalidOrUnsupported,
        )
    }

    /// Reject the operation because fewer than three attempts remain on the
    /// decrementable counter.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn retry_refused(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(
            &operation_id,
            ResultStatus::Rejected,
            ResultError::RetryPolicyRefused,
        )
    }

    /// Record a CAN, PIN 1, or PIN 2 rejection: emit the bounded result,
    /// revoke the pairing, and close the session.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, the wrong protocol phase, or a
    /// failed durable revocation.
    pub fn credential_rejected(
        &self,
        operation_id: Vec<u8>,
        rejected_at_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(&operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime,
            pair_store,
            journal,
            engine,
            requests,
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let dispatch = engine
            .finish_failure(
                journal,
                operation_id,
                ResultStatus::CredentialRejected,
                ResultError::CredentialRejected,
            )
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, journal, engine, requests, dispatch)?;
        runtime
            .endpoint_mut()
            .revoke_credential_rejection(pair_store, rejected_at_ms)
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        *state = OperationBridgeState::Revoked;
        drop(state);
        Ok(action)
    }

    /// Cancel the operation after the card left before transmission provably
    /// began.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn card_removed_before_transmit(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(
            &operation_id,
            ResultStatus::Cancelled,
            ResultError::CardRemovedBeforeTransmit,
        )
    }

    /// Mark the operation ambiguous; the card command is never repeated.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn card_completion_ambiguous(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(
            &operation_id,
            ResultStatus::Ambiguous,
            ResultError::CardCompletionAmbiguous,
        )
    }

    /// Report authenticated advisory progress on an active operation.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn report_progress(
        &self,
        operation_id: Vec<u8>,
        event: RappProgressEvent,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(&operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime, engine, ..
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let message = engine
            .report_progress(operation_id, event.into())
            .map_err(|_| RappBindingError::WrongPhase)?;
        let frame = runtime
            .endpoint_mut()
            .send(&message)
            .map_err(|_| RappBindingError::WrongPhase)?;
        Ok(RappBridgeAction::send(
            RappBridgeActionKind::SendFrame,
            Some(operation_id),
            frame,
            false,
        ))
    }

    /// Complete a card inspection with factory and retry state.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn complete_inspection(
        &self,
        operation_id: Vec<u8>,
        pin1_factory: bool,
        pin2_factory: bool,
        pin1_attempts: Option<u8>,
        pin2_attempts: Option<u8>,
        puk_attempts: Option<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.complete(
            &operation_id,
            CardOperationResult::Inspection(CardInspection {
                pin1_factory,
                pin2_factory,
                pin1_attempts,
                pin2_attempts,
                puk_attempts,
            }),
        )
    }

    /// Complete an identity read with the cardholder name and identifier.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn complete_identity(
        &self,
        operation_id: Vec<u8>,
        display_name: String,
        person_id: String,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.complete(
            &operation_id,
            CardOperationResult::Identity {
                display_name,
                person_id,
            },
        )
    }

    /// Complete a certificate read with the certificate bytes.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn complete_certificate(
        &self,
        operation_id: Vec<u8>,
        der: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.complete(&operation_id, CardOperationResult::Certificate(der))
    }

    /// Complete a signing operation with the signature bytes.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn complete_signature(
        &self,
        operation_id: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.complete(&operation_id, CardOperationResult::Signature(signature))
    }

    /// Deliver a completed requester result only after its acknowledgment was
    /// successfully released to transport and durably recorded.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn acknowledgment_released(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappOperationResult, RappBindingError> {
        let operation_id = decode_operation_id(&operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Requester {
            journal, engine, ..
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let result = engine
            .acknowledgment_released(journal, operation_id)
            .map(Into::into)
            .map_err(|_| RappBindingError::WrongPhase);
        drop(state);
        result
    }

    /// Advance authenticated liveness using platform monotonic time, CSPRNG
    /// challenge bytes, and bounded caller-generated jitter.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid challenge bytes or a protocol
    /// failure.
    pub fn poll_liveness(
        &self,
        now_ms: u64,
        challenge: Vec<u8>,
        jitter_ms: i64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let challenge = PingChallenge::reconstruct(fixed_array(challenge)?);
        let mut state = self.lock_state()?;
        let decision = match &mut *state {
            OperationBridgeState::Requester { runtime, .. }
            | OperationBridgeState::Proxy { runtime, .. } => runtime
                .poll(now_ms, challenge, jitter_ms)
                .map_err(|_| RappBindingError::ProtocolFailure)?,
            OperationBridgeState::Closed => {
                return Ok(RappBridgeAction::simple(
                    RappBridgeActionKind::SessionClosed,
                ));
            }
            OperationBridgeState::Revoked => {
                return Ok(RappBridgeAction::simple(RappBridgeActionKind::PairRevoked));
            }
        };
        match decision {
            RuntimePoll::NoAction => Ok(RappBridgeAction::simple(RappBridgeActionKind::NoAction)),
            RuntimePoll::Send(frame) => Ok(RappBridgeAction::send(
                RappBridgeActionKind::SendFrame,
                None,
                frame,
                false,
            )),
            RuntimePoll::Checking {
                next_probe_at_ms, ..
            } => {
                let mut action = RappBridgeAction::simple(RappBridgeActionKind::NoAction);
                action.next_poll_at_ms = Some(next_probe_at_ms);
                Ok(action)
            }
            RuntimePoll::SessionClosed(_) | RuntimePoll::AlreadyClosed => {
                match &mut *state {
                    OperationBridgeState::Requester {
                        journal, engine, ..
                    } => {
                        engine
                            .session_closed(journal)
                            .map_err(|_| RappBindingError::LocalStateFailure)?;
                    }
                    OperationBridgeState::Proxy {
                        journal, engine, ..
                    } => {
                        engine
                            .session_closed(journal)
                            .map_err(|_| RappBindingError::LocalStateFailure)?;
                    }
                    OperationBridgeState::Closed | OperationBridgeState::Revoked => {}
                }
                *state = OperationBridgeState::Closed;
                drop(state);
                Ok(RappBridgeAction::simple(
                    RappBridgeActionKind::SessionClosed,
                ))
            }
        }
    }

    /// Close the ephemeral session, classify every in-flight operation, and
    /// retain pairing unless an authenticated violation already revoked it.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] when the durable close
    /// classification fails.
    pub fn close_session(&self) -> Result<RappBridgeAction, RappBindingError> {
        let mut state = self.lock_state()?;
        match &mut *state {
            OperationBridgeState::Requester {
                runtime,
                journal,
                engine,
                ..
            } => {
                engine
                    .session_closed(journal)
                    .map_err(|_| RappBindingError::LocalStateFailure)?;
                runtime.close_session();
            }
            OperationBridgeState::Proxy {
                runtime,
                journal,
                engine,
                ..
            } => {
                engine
                    .session_closed(journal)
                    .map_err(|_| RappBindingError::LocalStateFailure)?;
                runtime.close_session();
            }
            OperationBridgeState::Closed => {}
            OperationBridgeState::Revoked => {
                return Ok(RappBridgeAction::simple(RappBridgeActionKind::PairRevoked));
            }
        }
        *state = OperationBridgeState::Closed;
        drop(state);
        Ok(RappBridgeAction::simple(
            RappBridgeActionKind::SessionClosed,
        ))
    }
}

impl RappOperationBridge {
    fn lock_state(&self) -> Result<MutexGuard<'_, OperationBridgeState>, RappBindingError> {
        self.state
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)
    }

    fn begin_operation(
        &self,
        operation_id: &[u8],
        local_start_ms: u64,
        expires_after_ms: u64,
        operation: CardOperation,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Requester {
            runtime,
            journal,
            engine,
            pair_id,
            session_id,
            granted_profiles,
            ..
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let profile: ProfileName = operation.required_profile();
        if !granted_profiles.contains(&profile) {
            return Err(RappBindingError::InvalidInput);
        }
        let request = OperationRequest::reconstruct(
            operation_id,
            *pair_id,
            *session_id,
            profile,
            local_start_ms,
            expires_after_ms,
            operation,
        )
        .map_err(|_| RappBindingError::InvalidInput)?;
        let message = engine
            .begin(journal, request)
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        if let Ok(frame) = runtime.endpoint_mut().send(&message) {
            Ok(RappBridgeAction::send(
                RappBridgeActionKind::SendFrame,
                Some(operation_id),
                frame,
                false,
            ))
        } else {
            engine
                .session_closed(journal)
                .map_err(|_| RappBindingError::LocalStateFailure)?;
            runtime.close_session();
            *state = OperationBridgeState::Closed;
            drop(state);
            Ok(RappBridgeAction::simple(
                RappBridgeActionKind::SessionClosed,
            ))
        }
    }

    fn finish_failure(
        &self,
        operation_id: &[u8],
        status: ResultStatus,
        error: ResultError,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime,
            journal,
            engine,
            requests,
            ..
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let dispatch = engine
            .finish_failure(journal, operation_id, status, error)
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, journal, engine, requests, dispatch)?;
        if action_closes_session(&action) {
            *state = OperationBridgeState::Closed;
            drop(state);
        }
        Ok(action)
    }

    fn complete(
        &self,
        operation_id: &[u8],
        result: CardOperationResult,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime,
            journal,
            engine,
            requests,
            ..
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let reference = reference(requests, operation_id)?;
        let dispatch = engine
            .finish_completed(
                journal,
                operation_id,
                OperationResultMessage::completed(reference, result),
            )
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, journal, engine, requests, dispatch)?;
        if action_closes_session(&action) {
            *state = OperationBridgeState::Closed;
            drop(state);
        }
        Ok(action)
    }
}

fn requester_dispatch(
    runtime: &mut EstablishedSessionRuntime,
    journal: &mut BindingOperationStore,
    engine: &mut RequesterOperationEngine,
    dispatch: RequesterDispatch,
    terminal_reason: Option<RappTerminalReason>,
) -> Result<RappBridgeAction, RappBindingError> {
    match dispatch {
        RequesterDispatch::Prepared(operation_id) => {
            let message = engine
                .commit(journal, operation_id)
                .map_err(|_| RappBindingError::LocalStateFailure)?;
            send_requester(
                runtime,
                engine,
                journal,
                RappBridgeActionKind::SendFrame,
                Some(operation_id),
                &message,
            )
        }
        RequesterDispatch::SendResultAcknowledgment {
            operation_id,
            message,
        } => send_requester(
            runtime,
            engine,
            journal,
            RappBridgeActionKind::ResultAcknowledgment,
            Some(operation_id),
            &message,
        ),
        RequesterDispatch::Terminal {
            operation_id,
            state,
        } => {
            let mut action =
                RappBridgeAction::for_operation(RappBridgeActionKind::Terminal, operation_id);
            action.terminal_state = Some(operation_state_name(state).to_owned());
            action.terminal_reason = terminal_reason;
            Ok(action)
        }
        RequesterDispatch::CancellationReceived {
            operation_id,
            state,
        } => {
            let mut action =
                RappBridgeAction::for_operation(RappBridgeActionKind::Terminal, operation_id);
            action.terminal_state = Some(operation_state_name(state).to_owned());
            action.terminal_reason = Some(RappTerminalReason::Cancelled);
            Ok(action)
        }
        RequesterDispatch::StatusAnnotated(operation_id) => Ok(RappBridgeAction::for_operation(
            RappBridgeActionKind::NoAction,
            operation_id,
        )),
        RequesterDispatch::Progress {
            operation_id,
            event,
        } => Ok(RappBridgeAction {
            kind: RappBridgeActionKind::Progress,
            operation_id: Some(operation_id.as_bytes().to_vec()),
            progress_event: Some(event.into()),
            ..RappBridgeAction::simple(RappBridgeActionKind::Progress)
        }),
        RequesterDispatch::PeerBusy => Ok(RappBridgeAction::simple(RappBridgeActionKind::PeerBusy)),
        RequesterDispatch::PeerUnknownOperation(operation_id) => Ok(operation_id.map_or_else(
            || RappBridgeAction::simple(RappBridgeActionKind::PeerUnknownOperation),
            |operation_id| {
                RappBridgeAction::for_operation(
                    RappBridgeActionKind::PeerUnknownOperation,
                    operation_id,
                )
            },
        )),
        RequesterDispatch::IgnoredStale {
            operation_id,
            response,
        } => send_requester(
            runtime,
            engine,
            journal,
            RappBridgeActionKind::SendFrame,
            Some(operation_id),
            &response,
        ),
        RequesterDispatch::NotOperation(_) => {
            Ok(RappBridgeAction::simple(RappBridgeActionKind::NoAction))
        }
    }
}

fn proxy_dispatch(
    runtime: &mut EstablishedSessionRuntime,
    journal: &mut BindingOperationStore,
    engine: &mut ProxyOperationEngine,
    requests: &mut Vec<OperationRequest>,
    dispatch: ProxyDispatch,
) -> Result<RappBridgeAction, RappBindingError> {
    match dispatch {
        ProxyDispatch::InspectPrerequisites(operation_id) => {
            let mut action = RappBridgeAction::for_operation(
                RappBridgeActionKind::InspectPrerequisites,
                operation_id,
            );
            action.operation = Some((&request(requests, operation_id)?.operation).into());
            Ok(action)
        }
        ProxyDispatch::ExecuteSafeRead { operation_id, read } => {
            let mut action = RappBridgeAction::for_operation(
                RappBridgeActionKind::ExecuteSafeRead,
                operation_id,
            );
            action.operation = Some((&read.operation).into());
            Ok(action)
        }
        ProxyDispatch::BeginCardCommand(operation_id) => {
            let pending = engine
                .begin_card_command(journal, operation_id)
                .map_err(|_| RappBindingError::LocalStateFailure)?;
            let operation = pending.execute(|command: AuthorizedCardCommand| command.operation);
            let mut action = RappBridgeAction::for_operation(
                RappBridgeActionKind::ExecuteCardCommand,
                operation_id,
            );
            action.operation = Some((&operation).into());
            Ok(action)
        }
        ProxyDispatch::Cancelled(operation_id) => Ok(RappBridgeAction::for_operation(
            RappBridgeActionKind::Cancelled,
            operation_id,
        )),
        ProxyDispatch::AdvisoryCancellation(operation_id) => Ok(RappBridgeAction::for_operation(
            RappBridgeActionKind::AdvisoryCancellation,
            operation_id,
        )),
        ProxyDispatch::ResultAcknowledged(operation_id) => {
            requests.retain(|request| request.operation_id != operation_id);
            Ok(RappBridgeAction::for_operation(
                RappBridgeActionKind::ResultAcknowledged,
                operation_id,
            ))
        }
        ProxyDispatch::IgnoredDuplicateCommit(operation_id) => Ok(RappBridgeAction::for_operation(
            RappBridgeActionKind::IgnoredDuplicate,
            operation_id,
        )),
        ProxyDispatch::IgnoredStale {
            operation_id,
            response,
        } => send_proxy(
            runtime,
            engine,
            journal,
            Some(operation_id),
            &response,
            false,
        ),
        ProxyDispatch::Send(message) => {
            let operation_id = referenced_operation_id(&message);
            send_proxy(runtime, engine, journal, operation_id, &message, false)
        }
        ProxyDispatch::SendFailure {
            message,
            close_session,
        } => {
            let operation_id = referenced_operation_id(&message);
            send_proxy(
                runtime,
                engine,
                journal,
                operation_id,
                &message,
                close_session,
            )
        }
        ProxyDispatch::NotOperation(_) => {
            Ok(RappBridgeAction::simple(RappBridgeActionKind::NoAction))
        }
    }
}

fn send_proxy(
    runtime: &mut EstablishedSessionRuntime,
    engine: &mut ProxyOperationEngine,
    journal: &mut BindingOperationStore,
    operation_id: Option<OperationId>,
    message: &TypedMessage,
    close_session: bool,
) -> Result<RappBridgeAction, RappBindingError> {
    if let Ok(frame) = runtime.endpoint_mut().send(message) {
        if close_session {
            runtime.close_session();
        }
        Ok(RappBridgeAction::send(
            RappBridgeActionKind::SendFrame,
            operation_id,
            frame,
            close_session,
        ))
    } else {
        engine
            .session_closed(journal)
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        runtime.close_session();
        Ok(RappBridgeAction::simple(
            RappBridgeActionKind::SessionClosed,
        ))
    }
}

fn send_requester(
    runtime: &mut EstablishedSessionRuntime,
    engine: &mut RequesterOperationEngine,
    journal: &mut BindingOperationStore,
    kind: RappBridgeActionKind,
    operation_id: Option<OperationId>,
    message: &TypedMessage,
) -> Result<RappBridgeAction, RappBindingError> {
    if let Ok(frame) = runtime.endpoint_mut().send(message) {
        Ok(RappBridgeAction::send(kind, operation_id, frame, false))
    } else {
        engine
            .session_closed(journal)
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        runtime.close_session();
        Ok(RappBridgeAction::simple(
            RappBridgeActionKind::SessionClosed,
        ))
    }
}

enum RuntimeFrame {
    Message(TypedMessage),
    Action(RappBridgeAction),
    Terminal {
        action: RappBridgeAction,
        revoked: bool,
    },
}

fn receive_runtime(
    runtime: &mut EstablishedSessionRuntime,
    pair_store: &mut BindingPairStore,
    frame: &BinaryFrame,
    now_ms: u64,
) -> Result<RuntimeFrame, RappBindingError> {
    let received = match runtime.receive(pair_store, frame, now_ms) {
        Ok(received) => received,
        Err(RuntimeError::Receive(EndpointError::SessionClosed)) => {
            return Ok(RuntimeFrame::Terminal {
                action: RappBridgeAction::simple(RappBridgeActionKind::SessionClosed),
                revoked: false,
            });
        }
        Err(_) => return Err(RappBindingError::ProtocolFailure),
    };
    match received {
        RuntimeReceive::Message(message) => Ok(RuntimeFrame::Message(message)),
        RuntimeReceive::Send(frame) => Ok(RuntimeFrame::Action(RappBridgeAction::send(
            RappBridgeActionKind::SendFrame,
            None,
            frame,
            false,
        ))),
        RuntimeReceive::LivenessRestored(_) | RuntimeReceive::IgnoredStalePong => Ok(
            RuntimeFrame::Action(RappBridgeAction::simple(RappBridgeActionKind::NoAction)),
        ),
        RuntimeReceive::SessionClosed(_) => Ok(RuntimeFrame::Terminal {
            action: RappBridgeAction::simple(RappBridgeActionKind::SessionClosed),
            revoked: false,
        }),
        RuntimeReceive::PairRevoked { .. } => Ok(RuntimeFrame::Terminal {
            action: RappBridgeAction::simple(RappBridgeActionKind::PairRevoked),
            revoked: true,
        }),
    }
}

fn action_closes_session(action: &RappBridgeAction) -> bool {
    action.kind == RappBridgeActionKind::SessionClosed || action.close_session_after_send
}

fn request(
    requests: &[OperationRequest],
    operation_id: OperationId,
) -> Result<&OperationRequest, RappBindingError> {
    requests
        .iter()
        .find(|request| request.operation_id == operation_id)
        .ok_or(RappBindingError::WrongPhase)
}

fn reference(
    requests: &[OperationRequest],
    operation_id: OperationId,
) -> Result<OperationReference, RappBindingError> {
    let request = request(requests, operation_id)?;
    Ok(OperationReference {
        operation_id,
        request_hash: request
            .request_hash()
            .map_err(|_| RappBindingError::ProtocolFailure)?,
    })
}

fn decode_operation_id(bytes: &[u8]) -> Result<OperationId, RappBindingError> {
    OperationId::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)
}

const fn require_lifetime(maximum_lifetime_ms: u64) -> Result<(), RappBindingError> {
    if maximum_lifetime_ms == 0 {
        Err(RappBindingError::InvalidInput)
    } else {
        Ok(())
    }
}

const fn referenced_operation_id(message: &TypedMessage) -> Option<OperationId> {
    match message {
        TypedMessage::OperationRequest(request) => Some(request.operation_id),
        TypedMessage::OperationPrepared(reference)
        | TypedMessage::OperationCommit(reference)
        | TypedMessage::OperationResultAck(reference) => Some(reference.operation_id),
        TypedMessage::OperationCancel(cancel) => Some(cancel.reference.operation_id),
        TypedMessage::OperationResult(result) => Some(result.operation_id),
        TypedMessage::OperationStatusRequest(operation_id) => Some(*operation_id),
        TypedMessage::OperationStatus(report) => Some(report.operation_id),
        _ => None,
    }
}

const fn operation_state_name(state: OperationState) -> &'static str {
    match state {
        OperationState::None => "none",
        OperationState::Requested => "requested",
        OperationState::AwaitingConsent => "awaiting_consent",
        OperationState::Prepared => "prepared",
        OperationState::Committed => "committed",
        OperationState::Executing => "executing",
        OperationState::ResultPending => "result_pending",
        OperationState::DeliveryUncertain => "delivery_uncertain",
        OperationState::Completed => "completed",
        OperationState::Denied => "denied",
        OperationState::Cancelled => "cancelled",
        OperationState::Rejected => "rejected",
        OperationState::CredentialRejected => "credential_rejected",
        OperationState::Ambiguous => "ambiguous",
    }
}
