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

//! Closed generated binding for the operations of one RAPP session
//! (RAPP v26.10.22 section 8).
//!
//! The platform transports only opaque encrypted frames and receives bounded
//! semantic actions. It never receives a generic decrypted protocol message,
//! raw APDU, CAN, PIN, PUK, or pair key. Nothing of an operation outlives its
//! session.

use std::sync::{Arc, Mutex, MutexGuard};

use super::{
    AuthorizedCardCommand, BinaryFrame, CardIdentity, CardInspection, CardKeyProfile,
    CardOperation, CardOperationResult, CardPresence, CardReader, CardStatusMessage,
    CertificateFingerprint, CertificateKind, CloseReason, EndpointError, EstablishedSessionRuntime,
    OperationId, OperationRequest, OperationResultMessage, OperationViolation, PingChallenge,
    ProfileName, ProxyDispatch, ProxyEngineError, ProxyFailure, ProxyOperationEngine,
    ProxySessionCloseAction, RequesterDispatch, RequesterEngineError, RequesterOperationEngine,
    ResultError, RuntimeError, RuntimePoll, RuntimeReceive, SignatureAlgorithm, TypedMessage,
    UserApproval,
    bindings::{RappBindingError, RappSessionBridge, fixed_array},
};

/// Closed operation names exposed to platform card adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappOperationKind {
    /// Read the card's answer to reset and supported profiles.
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
    /// One PIN 2 verify and one private-key operation per document digest,
    /// in order (section 9.3).
    BatchSignDocuments,
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
    /// A batch's document names, in signing order; empty otherwise.
    pub document_names: Vec<String>,
    /// A batch's digests, paired with `document_names`; empty otherwise.
    pub digests: Vec<Vec<u8>>,
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
                document_names: Vec::new(),
                digests: Vec::new(),
            },
            CardOperation::ReadIdentity => Self {
                kind: RappOperationKind::ReadIdentity,
                display_context: None,
                key_profile: None,
                algorithm: None,
                digest: Vec::new(),
                document_names: Vec::new(),
                digests: Vec::new(),
            },
            CardOperation::ReadCertificate {
                kind: CertificateKind::Authentication,
            } => Self {
                kind: RappOperationKind::ReadAuthenticationCertificate,
                display_context: None,
                key_profile: None,
                algorithm: None,
                digest: Vec::new(),
                document_names: Vec::new(),
                digests: Vec::new(),
            },
            CardOperation::ReadCertificate {
                kind: CertificateKind::Signature,
            } => Self {
                kind: RappOperationKind::ReadSignatureCertificate,
                display_context: None,
                key_profile: None,
                algorithm: None,
                digest: Vec::new(),
                document_names: Vec::new(),
                digests: Vec::new(),
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
                document_names: Vec::new(),
                digests: Vec::new(),
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
                document_names: Vec::new(),
                digests: Vec::new(),
            },
            CardOperation::BatchSignDocuments {
                document_names,
                key_profile,
                algorithm,
                digests,
            } => Self {
                kind: RappOperationKind::BatchSignDocuments,
                display_context: None,
                key_profile: Some(exported_key_profile(*key_profile)),
                algorithm: Some(exported_algorithm(*algorithm)),
                digest: Vec::new(),
                document_names: document_names.clone(),
                digests: digests.clone(),
            },
        }
    }
}

/// Progress events exposed to platform callers (RAPP v26.10.22 section 8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappProgressEvent {
    /// Another session's operation holds the card.
    Queued,
    /// A PIN prompt is on the custodian's screen.
    ConsentShown,
    /// The custodian waits for the holder to present the card.
    WaitingForCard,
    /// The card was found or the wait is over.
    CardWaitEnded,
}

impl From<RappProgressEvent> for super::ProgressEvent {
    fn from(value: RappProgressEvent) -> Self {
        match value {
            RappProgressEvent::Queued => Self::Queued,
            RappProgressEvent::ConsentShown => Self::ConsentShown,
            RappProgressEvent::WaitingForCard => Self::WaitingForCard,
            RappProgressEvent::CardWaitEnded => Self::CardWaitEnded,
        }
    }
}

impl From<super::ProgressEvent> for RappProgressEvent {
    fn from(value: super::ProgressEvent) -> Self {
        match value {
            super::ProgressEvent::Queued => Self::Queued,
            super::ProgressEvent::ConsentShown => Self::ConsentShown,
            super::ProgressEvent::WaitingForCard => Self::WaitingForCard,
            super::ProgressEvent::CardWaitEnded => Self::CardWaitEnded,
        }
    }
}

/// Whether a contact card reader is connected to the custodian (RAPP
/// v26.10.22 section 8.4 item 1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappCardReader {
    /// A contact card reader is connected: built in, or attached to a port.
    Attached,
    /// No contact card reader is connected, as on a custodian that reads
    /// cards only over NFC.
    Absent,
}

impl From<RappCardReader> for CardReader {
    fn from(value: RappCardReader) -> Self {
        match value {
            RappCardReader::Attached => Self::Attached,
            RappCardReader::Absent => Self::Absent,
        }
    }
}

impl From<CardReader> for RappCardReader {
    fn from(value: CardReader) -> Self {
        match value {
            CardReader::Attached => Self::Attached,
            CardReader::Absent => Self::Absent,
        }
    }
}

/// Bounded action produced by the Rust state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappBridgeActionKind {
    /// Deliver one opaque encrypted frame to the transport.
    SendFrame,
    /// Take the card in the order operations arrived, perform the reads
    /// that precede the PIN, then call `prerequisites_complete`.
    InspectPrerequisites,
    /// Present the descriptor and wait for the holder.
    AwaitUserApproval,
    /// Execute the described read; no private key, no PIN.
    ExecuteSafeRead,
    /// Execute the one approved card command.
    ExecuteCardCommand,
    /// The requester's operation completed; `result` carries the answer.
    Completed,
    /// The requester's operation ended without completing; `terminal_reason`
    /// says why.
    Terminal,
    /// The custodian reported the operation's progress.
    Progress,
    /// The custodian reported its card, present with a fingerprint or
    /// absent, and whether a card reader is connected to it (RAPP section
    /// 8.4).
    CardStatus,
    /// Nothing to execute.
    NoAction,
    /// The session closed; the pairing stays. `operation_id`, when present,
    /// names the session's operation that ended with it, and
    /// `card_exchange_continues` says whether the custodian's card command
    /// runs on to the card's answer, which is discarded (RAPP section 8.1
    /// item 3). On a received `PairingRevoked` close, revoke the record with
    /// `RappPairRecord::revoke` and withdraw its identity (section 4.6 item
    /// 4). A received `ServiceWithdrawn` close is the peer's withdrawal
    /// (section 4.5) and the pairing stays: a custodian shows that computer
    /// as off, not merely disconnected, until the pairing's next session
    /// (item 9); a requester withdraws the custodian's identity at once and
    /// does not dial it until it is discovered serving again (item 6). A
    /// close with no reason, or with another one, is neither a revocation
    /// nor a withdrawal.
    SessionClosed,
}

/// Registered reason of an authenticated session close (RAPP section 7.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappCloseReason {
    /// Orderly close.
    Normal,
    /// The work the session existed for is done.
    Complete,
    /// The user disconnected.
    UserDisconnect,
    /// Local policy ended the session.
    Policy,
    /// An authenticated protocol violation.
    ProtocolViolation,
    /// The pairing was revoked.
    PairingRevoked,
    /// The application is shutting down.
    Shutdown,
    /// The custodian can no longer serve the card.
    CardUnavailable,
    /// The sender withdrew: a custodian stopped serving, or a requester
    /// stopped using, every pairing (RAPP section 4.5).
    ServiceWithdrawn,
}

impl From<RappCloseReason> for CloseReason {
    fn from(reason: RappCloseReason) -> Self {
        match reason {
            RappCloseReason::Normal => Self::Normal,
            RappCloseReason::Complete => Self::Complete,
            RappCloseReason::UserDisconnect => Self::UserDisconnect,
            RappCloseReason::Policy => Self::Policy,
            RappCloseReason::ProtocolViolation => Self::ProtocolViolation,
            RappCloseReason::PairingRevoked => Self::PairingRevoked,
            RappCloseReason::Shutdown => Self::Shutdown,
            RappCloseReason::CardUnavailable => Self::CardUnavailable,
            RappCloseReason::ServiceWithdrawn => Self::ServiceWithdrawn,
        }
    }
}

impl From<CloseReason> for RappCloseReason {
    fn from(reason: CloseReason) -> Self {
        match reason {
            CloseReason::Normal => Self::Normal,
            CloseReason::Complete => Self::Complete,
            CloseReason::UserDisconnect => Self::UserDisconnect,
            CloseReason::Policy => Self::Policy,
            CloseReason::ProtocolViolation => Self::ProtocolViolation,
            CloseReason::PairingRevoked => Self::PairingRevoked,
            CloseReason::Shutdown => Self::Shutdown,
            CloseReason::CardUnavailable => Self::CardUnavailable,
            CloseReason::ServiceWithdrawn => Self::ServiceWithdrawn,
        }
    }
}

/// Why an operation ended without completing: the registered error name
/// (RAPP section 10.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappTerminalReason {
    /// Another operation of the session was live.
    Busy,
    /// The identifier was already used on the session.
    DuplicateOperation,
    /// The lifetime was zero.
    InvalidLifetime,
    /// The deadline passed before the card was commanded.
    OperationExpired,
    /// The pairing does not grant the profile.
    Unauthorized,
    /// A parameter is not supported.
    UnsupportedParameter,
    /// The holder declined.
    UserCancelled,
    /// The card's remaining attempts are reserved for its issuer's software.
    RetryFloor,
    /// The card did not answer.
    CardError,
    /// The custodian could not carry the operation out.
    OperationFailed,
}

impl From<ResultError> for RappTerminalReason {
    fn from(error: ResultError) -> Self {
        match error {
            ResultError::Busy => Self::Busy,
            ResultError::DuplicateOperation => Self::DuplicateOperation,
            ResultError::InvalidLifetime => Self::InvalidLifetime,
            ResultError::OperationExpired => Self::OperationExpired,
            ResultError::Unauthorized => Self::Unauthorized,
            ResultError::UnsupportedParameter => Self::UnsupportedParameter,
            ResultError::UserCancelled => Self::UserCancelled,
            ResultError::RetryFloor => Self::RetryFloor,
            ResultError::CardError => Self::CardError,
            ResultError::OperationFailed => Self::OperationFailed,
        }
    }
}

/// One bridge action. Only `frame` carries ciphertext; operation data is a
/// closed semantic descriptor.
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
    /// The answer of a completed requester operation.
    pub result: Option<RappOperationResult>,
    /// Why an operation ended without completing.
    pub terminal_reason: Option<RappTerminalReason>,
    /// Progress event.
    pub progress_event: Option<RappProgressEvent>,
    /// Whether the custodian can serve a card now, on a card-status action.
    pub card_present: Option<bool>,
    /// SHA-256 of the present card's authentication certificate.
    pub certificate_fingerprint: Option<Vec<u8>>,
    /// Whether a contact card reader is connected to the custodian, on a
    /// card-status action. While the card is absent, the requester names
    /// the custodian's reader to its user only when this is `Attached`
    /// (RAPP section 8.4 item 6).
    pub card_reader: Option<RappCardReader>,
    /// The session must close after this frame is delivered.
    pub close_session_after_send: bool,
    /// Registered reason of a session closed by an authenticated notice,
    /// sent or received.
    pub close_reason: Option<RappCloseReason>,
    /// On a closed session, the custodian's card command for `operation_id`
    /// runs to the card's answer, which is discarded; otherwise the
    /// operation was dropped before the card was commanded.
    pub card_exchange_continues: bool,
}

impl RappBridgeAction {
    pub(super) const fn simple(kind: RappBridgeActionKind) -> Self {
        Self {
            kind,
            operation_id: None,
            operation: None,
            frame: None,
            result: None,
            terminal_reason: None,
            progress_event: None,
            card_present: None,
            certificate_fingerprint: None,
            card_reader: None,
            close_session_after_send: false,
            close_reason: None,
            card_exchange_continues: false,
        }
    }

    fn for_operation(kind: RappBridgeActionKind, operation_id: OperationId) -> Self {
        Self {
            operation_id: Some(operation_id.as_bytes().to_vec()),
            ..Self::simple(kind)
        }
    }

    fn send(operation_id: Option<OperationId>, frame: BinaryFrame) -> Self {
        Self {
            operation_id: operation_id.map(|id| id.as_bytes().to_vec()),
            frame: Some(frame.into_bytes()),
            ..Self::simple(RappBridgeActionKind::SendFrame)
        }
    }

    pub(super) fn session_closed(ended: EndedOperation) -> Self {
        Self::simple(RappBridgeActionKind::SessionClosed).ending(ended)
    }

    /// The session closed on a protocol violation: deliver the sealed
    /// `protocol_violation` notice, when there is one, then drop the link.
    pub(super) fn violation_closed(notice: Option<BinaryFrame>) -> Self {
        let closed = Self {
            close_reason: Some(RappCloseReason::ProtocolViolation),
            ..Self::simple(RappBridgeActionKind::SessionClosed)
        };
        match notice {
            Some(frame) => Self {
                kind: RappBridgeActionKind::SendFrame,
                frame: Some(frame.into_bytes()),
                close_session_after_send: true,
                ..closed
            },
            None => closed,
        }
    }

    /// Name the session's operation that ended with the session.
    fn ending(self, ended: EndedOperation) -> Self {
        Self {
            operation_id: ended.operation_id.map(|id| id.as_bytes().to_vec()),
            card_exchange_continues: ended.card_exchange_continues,
            ..self
        }
    }
}

/// The session's operation that ended when the session closed (RAPP
/// section 8.1 item 3).
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct EndedOperation {
    operation_id: Option<OperationId>,
    card_exchange_continues: bool,
}

impl EndedOperation {
    fn requester(engine: &mut RequesterOperationEngine) -> Self {
        Self {
            operation_id: engine.session_closed(),
            card_exchange_continues: false,
        }
    }

    fn proxy(engine: &mut ProxyOperationEngine) -> Self {
        match engine.session_closed() {
            None => Self::default(),
            Some(ProxySessionCloseAction::Dropped(operation_id)) => Self {
                operation_id: Some(operation_id),
                card_exchange_continues: false,
            },
            Some(ProxySessionCloseAction::ContinueCardExchange(operation_id)) => Self {
                operation_id: Some(operation_id),
                card_exchange_continues: true,
            },
        }
    }
}

/// Successful requester result in a stable generated-binding shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappResultKind {
    /// Card inspection.
    Inspection,
    /// Cardholder identity read.
    Identity,
    /// Certificate read.
    Certificate,
    /// Private-key signature.
    Signature,
    /// The ordered signatures of a batch.
    Signatures,
}

/// Profile-defined result body in a stable generated-binding shape.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappOperationResult {
    /// Registered result shape.
    pub kind: RappResultKind,
    /// The card's answer to reset, or its historical bytes; empty when the
    /// custodian's platform exposes neither.
    pub answer_to_reset: Vec<u8>,
    /// Cardholder name (section 9.1 `card_holder_name`).
    pub holder_name: Option<String>,
    /// Card identifier (section 9.1 `card_id`).
    pub card_id: Option<String>,
    /// Issuance date, `YYYY-MM-DD`.
    pub issuance_date: Option<String>,
    /// Expiration date, `YYYY-MM-DD`.
    pub expiration_date: Option<String>,
    /// DER-encoded certificates of an identity read.
    pub certificates: Vec<Vec<u8>>,
    /// Certificate or signature bytes.
    pub bytes: Vec<u8>,
    /// The ordered signatures of a batch, one per document.
    pub signatures: Vec<Vec<u8>>,
}

impl RappOperationResult {
    const fn empty(kind: RappResultKind) -> Self {
        Self {
            kind,
            answer_to_reset: Vec::new(),
            holder_name: None,
            card_id: None,
            issuance_date: None,
            expiration_date: None,
            certificates: Vec::new(),
            bytes: Vec::new(),
            signatures: Vec::new(),
        }
    }
}

impl From<CardOperationResult> for RappOperationResult {
    fn from(result: CardOperationResult) -> Self {
        match result {
            CardOperationResult::Inspection(value) => Self {
                answer_to_reset: value.answer_to_reset,
                ..Self::empty(RappResultKind::Inspection)
            },
            CardOperationResult::Identity(identity) => Self {
                holder_name: Some(identity.holder_name),
                card_id: Some(identity.card_id),
                issuance_date: Some(identity.issuance_date),
                expiration_date: Some(identity.expiration_date),
                certificates: identity.certificates,
                ..Self::empty(RappResultKind::Identity)
            },
            CardOperationResult::Certificate(bytes) => Self {
                bytes,
                ..Self::empty(RappResultKind::Certificate)
            },
            CardOperationResult::Signature(bytes) => Self {
                bytes,
                ..Self::empty(RappResultKind::Signature)
            },
            CardOperationResult::Signatures(signatures) => Self {
                signatures,
                ..Self::empty(RappResultKind::Signatures)
            },
        }
    }
}

enum OperationBridgeState {
    Requester {
        runtime: EstablishedSessionRuntime,
        engine: RequesterOperationEngine,
        granted_profiles: Vec<ProfileName>,
    },
    Proxy {
        runtime: EstablishedSessionRuntime,
        engine: ProxyOperationEngine,
        live_request: Option<OperationRequest>,
    },
    Closed,
}

/// One established RAPP session with closed operation dispatch.
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
    /// Take the established session as the requester.
    ///
    /// # Errors
    /// [`RappBindingError`] on a zero lifetime or a session that is not
    /// established.
    #[uniffi::constructor]
    pub fn begin_requester(
        session: Arc<RappSessionBridge>,
        maximum_lifetime_ms: u64,
        now_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        require_lifetime(maximum_lifetime_ms)?;
        let (endpoint, granted_profiles) = session.take_established()?;
        Ok(Arc::new(Self {
            state: Mutex::new(OperationBridgeState::Requester {
                runtime: EstablishedSessionRuntime::new(endpoint, now_ms),
                engine: RequesterOperationEngine::new(),
                granted_profiles,
            }),
            maximum_lifetime_ms,
        }))
    }

    /// Take the established session as the custodian. Report the card with
    /// [`Self::report_card_status`] right after, so `card.status` follows
    /// `session.ready` (RAPP section 8.4).
    ///
    /// # Errors
    /// [`RappBindingError`] on a zero lifetime or a session that is not
    /// established.
    #[uniffi::constructor]
    pub fn begin_proxy(
        session: Arc<RappSessionBridge>,
        maximum_lifetime_ms: u64,
        now_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        require_lifetime(maximum_lifetime_ms)?;
        let (endpoint, granted_profiles) = session.take_established()?;
        Ok(Arc::new(Self {
            state: Mutex::new(OperationBridgeState::Proxy {
                runtime: EstablishedSessionRuntime::new(endpoint, now_ms),
                engine: ProxyOperationEngine::new(granted_profiles),
                live_request: None,
            }),
            maximum_lifetime_ms,
        }))
    }

    /// Begin a card inspection.
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

    /// Begin a batch signature over the documents' digests, in order
    /// (section 9.3).
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, an ungranted profile, or the
    /// wrong protocol phase.
    #[allow(
        clippy::too_many_arguments,
        reason = "the closed action schema fixes every request field"
    )]
    pub fn begin_batch_sign_documents(
        &self,
        operation_id: Vec<u8>,
        document_names: Vec<String>,
        key_profile: RappCardKeyProfile,
        algorithm: RappSignatureAlgorithm,
        digests: Vec<Vec<u8>>,
        local_start_ms: u64,
        expires_after_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.begin_operation(
            &operation_id,
            local_start_ms,
            expires_after_ms,
            CardOperation::BatchSignDocuments {
                document_names,
                key_profile: key_profile.into(),
                algorithm: algorithm.into(),
                digests,
            },
        )
    }

    /// Decrypt, authenticate, schema-check, and dispatch one opaque frame.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, a protocol failure, or a
    /// poisoned local state.
    pub fn receive_frame(
        &self,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        let mut state = self.lock_state()?;
        let action = match &mut *state {
            OperationBridgeState::Requester {
                runtime, engine, ..
            } => {
                let message = match receive_runtime(runtime, &frame, now_ms)? {
                    RuntimeFrame::Message(message) => message,
                    RuntimeFrame::Action(action) => return Ok(action),
                    RuntimeFrame::Closed(action) => {
                        let ended = EndedOperation::requester(engine);
                        *state = OperationBridgeState::Closed;
                        return Ok(action.ending(ended));
                    }
                };
                match engine.receive(message) {
                    Ok(dispatch) => requester_dispatch(dispatch),
                    Err(RequesterEngineError::AuthenticatedProtocolViolation(violation)) => {
                        let notice = violation_notice(runtime.close_for_operation_violation(
                            OperationViolation::Requester(violation),
                        ));
                        let ended = EndedOperation::requester(engine);
                        *state = OperationBridgeState::Closed;
                        return Ok(RappBridgeAction::violation_closed(notice).ending(ended));
                    }
                    Err(_) => return Err(RappBindingError::LocalStateFailure),
                }
            }
            OperationBridgeState::Proxy {
                runtime,
                engine,
                live_request,
            } => {
                let message = match receive_runtime(runtime, &frame, now_ms)? {
                    RuntimeFrame::Message(message) => message,
                    RuntimeFrame::Action(action) => return Ok(action),
                    RuntimeFrame::Closed(action) => {
                        let ended = EndedOperation::proxy(engine);
                        *state = OperationBridgeState::Closed;
                        return Ok(action.ending(ended));
                    }
                };
                let incoming = match &message {
                    TypedMessage::OperationRequest(request) => Some(request.clone()),
                    _ => None,
                };
                let dispatch = match engine.receive(message) {
                    Ok(dispatch) => dispatch,
                    Err(ProxyEngineError::AuthenticatedProtocolViolation(violation)) => {
                        let notice =
                            violation_notice(runtime.close_for_operation_violation(
                                OperationViolation::Proxy(violation),
                            ));
                        let ended = EndedOperation::proxy(engine);
                        *state = OperationBridgeState::Closed;
                        return Ok(RappBridgeAction::violation_closed(notice).ending(ended));
                    }
                    Err(_) => return Err(RappBindingError::LocalStateFailure),
                };
                if matches!(dispatch, ProxyDispatch::InspectPrerequisites(_)) {
                    *live_request = incoming;
                }
                proxy_dispatch(runtime, engine, live_request.as_ref(), dispatch)
            }
            OperationBridgeState::Closed => return Err(RappBindingError::WrongPhase),
        };
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
        Ok(action)
    }

    /// The operation has the card and its prerequisite reads are done. An
    /// action that needs the holder's authorization gives
    /// `AwaitUserApproval`; a read skips consent and gives `ExecuteSafeRead`
    /// (RAPP section 8.2 items 3 and 6). An operation past its deadline is
    /// cancelled instead, with the result to send. `now_ms` is the
    /// continuous clock.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn prerequisites_complete(
        &self,
        operation_id: Vec<u8>,
        now_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(&operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime,
            engine,
            live_request,
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let dispatch = engine
            .prerequisites_complete(operation_id, now_ms, self.maximum_lifetime_ms)
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, engine, live_request.as_ref(), dispatch);
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
        Ok(action)
    }

    /// Approve exactly the admitted request: the holder entered the PIN
    /// on the prompt it rendered, or the custodian holds PIN 1.
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
            engine,
            live_request,
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let approval =
            UserApproval::for_request(live(live_request.as_ref(), operation_id)?, approved_at_ms);
        let dispatch = engine
            .approve(
                operation_id,
                approval,
                approved_at_ms,
                self.maximum_lifetime_ms,
            )
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, engine, live_request.as_ref(), dispatch);
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
        Ok(action)
    }

    /// The holder declined.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn deny(&self, operation_id: Vec<u8>) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(&operation_id, ProxyFailure::UserDenied)
    }

    /// Reject a request the custodian cannot serve, such as one naming a key
    /// the card does not hold.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn request_invalid_or_unsupported(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(&operation_id, ProxyFailure::RequestInvalidOrUnsupported)
    }

    /// The retry floor refused before any verification: the card reports
    /// fewer than three remaining attempts for the PIN (section 10.2).
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn retry_floor(&self, operation_id: Vec<u8>) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(&operation_id, ProxyFailure::RetryFloor)
    }

    /// The card did not answer: no card within the wait, the field lost, a
    /// transmission fault.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn card_error(&self, operation_id: Vec<u8>) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(&operation_id, ProxyFailure::CardError)
    }

    /// The custodian could not carry the operation out for a reason of its
    /// own.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn operation_failed(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.finish_failure(&operation_id, ProxyFailure::OperationFailed)
    }

    /// Cancel the live operation if its deadline passed before the card was
    /// commanded (section 8.1 item 2); `NoAction` when nothing is due.
    /// `now_ms` is the continuous clock.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong protocol phase.
    pub fn expire_due(&self, now_ms: u64) -> Result<RappBridgeAction, RappBindingError> {
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime,
            engine,
            live_request,
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let action = match engine
            .expire_due(now_ms, self.maximum_lifetime_ms)
            .map_err(|_| RappBindingError::WrongPhase)?
        {
            Some(dispatch) => proxy_dispatch(runtime, engine, live_request.as_ref(), dispatch),
            None => RappBridgeAction::simple(RappBridgeActionKind::NoAction),
        };
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
        Ok(action)
    }

    /// Tell the requester which card the custodian holds and whether a
    /// contact card reader is connected to it (RAPP section 8.4): the DER
    /// authentication certificate of a present card, or `None` when the
    /// custodian holds no card, and the reader's attachment. Call it once
    /// right after `begin_proxy` and again whenever the card, its presence
    /// or the reader's attachment changes; a card busy with another
    /// session's operation is present, and detaching a reader removes the
    /// card in it.
    ///
    /// # Errors
    /// [`RappBindingError`] on an empty certificate, the wrong protocol
    /// phase, or a poisoned local state.
    pub fn report_card_status(
        &self,
        authentication_certificate: Option<Vec<u8>>,
        card_reader: RappCardReader,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let card = match authentication_certificate {
            Some(der) if der.is_empty() => return Err(RappBindingError::InvalidInput),
            Some(der) => CardPresence::Present(CertificateFingerprint::of_certificate(&der)),
            None => CardPresence::Absent,
        };
        let status = CardStatusMessage {
            card,
            reader: card_reader.into(),
        };
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime, engine, ..
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let action = send_proxy(
            runtime,
            engine,
            None,
            &ProxyOperationEngine::report_card_status(status),
        );
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
        Ok(action)
    }

    /// Report a change of the live operation's state.
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
            .map_err(|error| match error {
                ProxyEngineError::UnknownLocalOperation => RappBindingError::UnknownOperation,
                _ => RappBindingError::WrongPhase,
            })?;
        let action = send_proxy(runtime, engine, Some(operation_id), &message);
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
        Ok(action)
    }

    /// Complete a card inspection with the card's answer to reset, or its
    /// historical bytes; empty when the platform exposes neither.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or the wrong protocol phase.
    pub fn complete_inspection(
        &self,
        operation_id: Vec<u8>,
        answer_to_reset: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        self.complete(
            &operation_id,
            CardOperationResult::Inspection(CardInspection { answer_to_reset }),
        )
    }

    /// Complete an identity read (RAPP section 9.1).
    ///
    /// Both dates are `YYYY-MM-DD`; at least one DER certificate travels.
    ///
    /// # Errors
    /// [`RappBindingError`] on a field outside its section 9.1 bounds or the
    /// wrong protocol phase.
    pub fn complete_identity(
        &self,
        operation_id: Vec<u8>,
        holder_name: String,
        card_id: String,
        issuance_date: String,
        expiration_date: String,
        certificates: Vec<Vec<u8>>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let identity = CardIdentity::reconstruct(
            holder_name,
            card_id,
            issuance_date,
            expiration_date,
            certificates,
            None,
        )
        .map_err(|_| RappBindingError::InvalidInput)?;
        self.complete(&operation_id, CardOperationResult::Identity(identity))
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

    /// Record one batch signature as the card makes it.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input or an operation that is not an
    /// executing batch.
    pub fn record_batch_signature(
        &self,
        operation_id: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), RappBindingError> {
        let operation_id = decode_operation_id(&operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy { engine, .. } = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let result = engine
            .record_batch_signature(operation_id, signature)
            .map_err(|_| RappBindingError::WrongPhase);
        drop(state);
        result
    }

    /// Answer a batch once every document is signed, with exactly those
    /// signatures.
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid input, a batch with documents left, or
    /// the wrong protocol phase.
    pub fn complete_batch(
        &self,
        operation_id: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(&operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime,
            engine,
            live_request,
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let dispatch = engine
            .complete_batch(operation_id)
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, engine, live_request.as_ref(), dispatch);
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
        Ok(action)
    }

    /// Advance liveness with the platform's monotonic time and CSPRNG
    /// challenge bytes: a ping after 5 seconds of silence, the session's end
    /// after 30 (RAPP section 8.3).
    ///
    /// # Errors
    /// [`RappBindingError`] on invalid challenge bytes or a protocol failure.
    pub fn poll_liveness(
        &self,
        now_ms: u64,
        challenge: Vec<u8>,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let challenge = PingChallenge::reconstruct(fixed_array(challenge)?);
        let mut state = self.lock_state()?;
        let decision = match &mut *state {
            OperationBridgeState::Requester { runtime, .. }
            | OperationBridgeState::Proxy { runtime, .. } => runtime
                .poll(now_ms, challenge)
                .map_err(|_| RappBindingError::ProtocolFailure)?,
            OperationBridgeState::Closed => {
                return Ok(RappBridgeAction::session_closed(EndedOperation::default()));
            }
        };
        let action = match decision {
            RuntimePoll::NoAction => RappBridgeAction::simple(RappBridgeActionKind::NoAction),
            RuntimePoll::Send(frame) => RappBridgeAction::send(None, frame),
            RuntimePoll::SessionClosed(_) | RuntimePoll::AlreadyClosed => {
                RappBridgeAction::session_closed(end_operations(&mut state))
            }
        };
        drop(state);
        Ok(action)
    }

    /// Close the session; every operation of it is over and the pairing
    /// stays.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] on a poisoned local state.
    pub fn close_session(&self) -> Result<RappBridgeAction, RappBindingError> {
        let mut state = self.lock_state()?;
        match &mut *state {
            OperationBridgeState::Requester { runtime, .. }
            | OperationBridgeState::Proxy { runtime, .. } => runtime.close_session(),
            OperationBridgeState::Closed => {}
        }
        let ended = end_operations(&mut state);
        drop(state);
        Ok(RappBridgeAction::session_closed(ended))
    }

    /// Close the session with an authenticated `session.close` carrying
    /// `reason` and return the notice frame to deliver before dropping the
    /// link. A session that is already closed yields `SessionClosed` without
    /// a frame. An endpoint that withdraws, custodian or requester, closes
    /// every open session with `ServiceWithdrawn` (RAPP section 4.5 items 3
    /// and 8); a requester that quits waits at most
    /// `rapp_quit_withdrawal_bound_ms()` for the frames to leave.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] on a poisoned local state.
    pub fn close_with_reason(
        &self,
        reason: RappCloseReason,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let mut state = self.lock_state()?;
        let sealed = match &mut *state {
            OperationBridgeState::Requester { runtime, .. }
            | OperationBridgeState::Proxy { runtime, .. } => {
                runtime.close_with_reason(reason.into()).ok()
            }
            OperationBridgeState::Closed => None,
        };
        let ended = end_operations(&mut state);
        drop(state);
        let closed = RappBridgeAction::session_closed(ended);
        Ok(match sealed {
            Some(frame) => RappBridgeAction {
                kind: RappBridgeActionKind::SendFrame,
                frame: Some(frame.into_bytes()),
                close_reason: Some(reason),
                close_session_after_send: true,
                ..closed
            },
            None => closed,
        })
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
            engine,
            granted_profiles,
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
            profile,
            local_start_ms,
            expires_after_ms,
            operation,
        )
        .map_err(|_| RappBindingError::InvalidInput)?;
        let message = engine.begin(request).map_err(|error| match error {
            RequesterEngineError::LiveOperation => RappBindingError::WrongPhase,
            _ => RappBindingError::InvalidInput,
        })?;
        let action = if let Ok(frame) = runtime.endpoint_mut().send(&message) {
            RappBridgeAction::send(Some(operation_id), frame)
        } else {
            runtime.close_session();
            let ended = EndedOperation::requester(engine);
            *state = OperationBridgeState::Closed;
            RappBridgeAction::session_closed(ended)
        };
        drop(state);
        Ok(action)
    }

    fn finish_failure(
        &self,
        operation_id: &[u8],
        failure: ProxyFailure,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let operation_id = decode_operation_id(operation_id)?;
        let mut state = self.lock_state()?;
        let OperationBridgeState::Proxy {
            runtime,
            engine,
            live_request,
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let dispatch = engine
            .finish_failure(operation_id, failure)
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, engine, live_request.as_ref(), dispatch);
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
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
            engine,
            live_request,
        } = &mut *state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let dispatch = engine
            .finish_completed(
                operation_id,
                OperationResultMessage::completed(operation_id, &result),
            )
            .map_err(|_| RappBindingError::WrongPhase)?;
        let action = proxy_dispatch(runtime, engine, live_request.as_ref(), dispatch);
        if action.kind == RappBridgeActionKind::SessionClosed {
            *state = OperationBridgeState::Closed;
        }
        drop(state);
        Ok(action)
    }
}

/// End every operation of a closing session; returns the operation that
/// ended with it.
fn end_operations(state: &mut OperationBridgeState) -> EndedOperation {
    let ended = match state {
        OperationBridgeState::Requester { engine, .. } => EndedOperation::requester(engine),
        OperationBridgeState::Proxy { engine, .. } => EndedOperation::proxy(engine),
        OperationBridgeState::Closed => EndedOperation::default(),
    };
    *state = OperationBridgeState::Closed;
    ended
}

/// The sealed `protocol_violation` close of a session an operation engine
/// closed.
fn violation_notice(received: RuntimeReceive) -> Option<BinaryFrame> {
    match received {
        RuntimeReceive::ViolationClosed { notice, .. } => notice,
        _ => None,
    }
}

fn requester_dispatch(dispatch: RequesterDispatch) -> RappBridgeAction {
    match dispatch {
        RequesterDispatch::CardStatus(CardStatusMessage { card, reader }) => {
            let (card_present, certificate_fingerprint) = match card {
                CardPresence::Present(fingerprint) => (true, Some(fingerprint.as_bytes().to_vec())),
                CardPresence::Absent => (false, None),
            };
            RappBridgeAction {
                card_present: Some(card_present),
                certificate_fingerprint,
                card_reader: Some(reader.into()),
                ..RappBridgeAction::simple(RappBridgeActionKind::CardStatus)
            }
        }
        RequesterDispatch::Progress {
            operation_id,
            event,
        } => RappBridgeAction {
            progress_event: Some(event.into()),
            ..RappBridgeAction::for_operation(RappBridgeActionKind::Progress, operation_id)
        },
        RequesterDispatch::Completed {
            operation_id,
            result,
        } => RappBridgeAction {
            result: Some(result.into()),
            ..RappBridgeAction::for_operation(RappBridgeActionKind::Completed, operation_id)
        },
        RequesterDispatch::Ended {
            operation_id,
            error,
            ..
        }
        | RequesterDispatch::Refused {
            operation_id,
            error,
        } => RappBridgeAction {
            terminal_reason: Some(error.into()),
            ..RappBridgeAction::for_operation(RappBridgeActionKind::Terminal, operation_id)
        },
        RequesterDispatch::PeerError(_)
        | RequesterDispatch::Ignored(_)
        | RequesterDispatch::NotOperation(_) => {
            RappBridgeAction::simple(RappBridgeActionKind::NoAction)
        }
    }
}

fn proxy_dispatch(
    runtime: &mut EstablishedSessionRuntime,
    engine: &mut ProxyOperationEngine,
    live_request: Option<&OperationRequest>,
    dispatch: ProxyDispatch,
) -> RappBridgeAction {
    match dispatch {
        ProxyDispatch::InspectPrerequisites(operation_id) => RappBridgeAction {
            operation: live_request
                .filter(|request| request.operation_id == operation_id)
                .map(|request| (&request.operation).into()),
            ..RappBridgeAction::for_operation(
                RappBridgeActionKind::InspectPrerequisites,
                operation_id,
            )
        },
        ProxyDispatch::AwaitConsent(operation_id) => RappBridgeAction {
            operation: live_request
                .filter(|request| request.operation_id == operation_id)
                .map(|request| (&request.operation).into()),
            ..RappBridgeAction::for_operation(RappBridgeActionKind::AwaitUserApproval, operation_id)
        },
        ProxyDispatch::ExecuteSafeRead { operation_id, read } => RappBridgeAction {
            operation: Some((&read.operation).into()),
            ..RappBridgeAction::for_operation(RappBridgeActionKind::ExecuteSafeRead, operation_id)
        },
        ProxyDispatch::ExecuteCardCommand {
            operation_id,
            command,
        } => {
            let operation = command.execute(|command: AuthorizedCardCommand| command.operation);
            RappBridgeAction {
                operation: Some((&operation).into()),
                ..RappBridgeAction::for_operation(
                    RappBridgeActionKind::ExecuteCardCommand,
                    operation_id,
                )
            }
        }
        ProxyDispatch::Send(message) => {
            let operation_id = referenced_operation_id(&message);
            send_proxy(runtime, engine, operation_id, &message)
        }
        ProxyDispatch::NotOperation(_) => RappBridgeAction::simple(RappBridgeActionKind::NoAction),
    }
}

fn send_proxy(
    runtime: &mut EstablishedSessionRuntime,
    engine: &mut ProxyOperationEngine,
    operation_id: Option<OperationId>,
    message: &TypedMessage,
) -> RappBridgeAction {
    if let Ok(frame) = runtime.endpoint_mut().send(message) {
        RappBridgeAction::send(operation_id, frame)
    } else {
        runtime.close_session();
        RappBridgeAction::session_closed(EndedOperation::proxy(engine))
    }
}

enum RuntimeFrame {
    Message(TypedMessage),
    Action(RappBridgeAction),
    Closed(RappBridgeAction),
}

fn receive_runtime(
    runtime: &mut EstablishedSessionRuntime,
    frame: &BinaryFrame,
    now_ms: u64,
) -> Result<RuntimeFrame, RappBindingError> {
    let received = match runtime.receive(frame, now_ms) {
        Ok(received) => received,
        Err(RuntimeError::Receive(EndpointError::SessionClosed)) => {
            return Ok(RuntimeFrame::Closed(RappBridgeAction::session_closed(
                EndedOperation::default(),
            )));
        }
        Err(_) => return Err(RappBindingError::ProtocolFailure),
    };
    Ok(match received {
        RuntimeReceive::Message(message) => RuntimeFrame::Message(message),
        RuntimeReceive::Send(frame) => RuntimeFrame::Action(RappBridgeAction::send(None, frame)),
        RuntimeReceive::LivenessConfirmed | RuntimeReceive::IgnoredStalePong => {
            RuntimeFrame::Action(RappBridgeAction::simple(RappBridgeActionKind::NoAction))
        }
        RuntimeReceive::SessionClosed(_) => {
            RuntimeFrame::Closed(RappBridgeAction::session_closed(EndedOperation::default()))
        }
        RuntimeReceive::ViolationClosed { notice, .. } => {
            RuntimeFrame::Closed(RappBridgeAction::violation_closed(notice))
        }
        RuntimeReceive::PeerClosed(reason) => RuntimeFrame::Closed(RappBridgeAction {
            close_reason: Some(reason.into()),
            ..RappBridgeAction::session_closed(EndedOperation::default())
        }),
    })
}

fn live(
    live_request: Option<&OperationRequest>,
    operation_id: OperationId,
) -> Result<&OperationRequest, RappBindingError> {
    live_request
        .filter(|request| request.operation_id == operation_id)
        .ok_or(RappBindingError::WrongPhase)
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
        TypedMessage::OperationRequestRefused(refusal) => Some(refusal.operation_id),
        TypedMessage::OperationResult(result) => Some(result.operation_id),
        TypedMessage::OperationProgress(progress) => Some(progress.operation_id),
        TypedMessage::Error(error) => error.operation_id,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProgressEvent;

    #[test]
    fn close_reasons_convert_both_ways() {
        for reason in [
            RappCloseReason::Normal,
            RappCloseReason::Complete,
            RappCloseReason::UserDisconnect,
            RappCloseReason::Policy,
            RappCloseReason::ProtocolViolation,
            RappCloseReason::PairingRevoked,
            RappCloseReason::Shutdown,
            RappCloseReason::CardUnavailable,
            RappCloseReason::ServiceWithdrawn,
        ] {
            assert_eq!(RappCloseReason::from(CloseReason::from(reason)), reason);
        }
    }

    #[test]
    fn progress_events_convert_both_ways() {
        for event in [
            RappProgressEvent::Queued,
            RappProgressEvent::ConsentShown,
            RappProgressEvent::WaitingForCard,
            RappProgressEvent::CardWaitEnded,
        ] {
            assert_eq!(RappProgressEvent::from(ProgressEvent::from(event)), event);
        }
    }

    #[test]
    fn card_readers_convert_both_ways() {
        for reader in [RappCardReader::Attached, RappCardReader::Absent] {
            assert_eq!(RappCardReader::from(CardReader::from(reader)), reader);
        }
    }

    #[test]
    fn a_present_card_reports_its_fingerprint() {
        let fingerprint = CertificateFingerprint::of_certificate(b"certificate");
        let action = requester_dispatch(RequesterDispatch::CardStatus(CardStatusMessage {
            card: CardPresence::Present(fingerprint),
            reader: CardReader::Absent,
        }));
        assert_eq!(action.kind, RappBridgeActionKind::CardStatus);
        assert_eq!(action.card_present, Some(true));
        assert_eq!(
            action.certificate_fingerprint,
            Some(fingerprint.as_bytes().to_vec())
        );
        assert_eq!(action.card_reader, Some(RappCardReader::Absent));
    }

    #[test]
    fn an_absent_card_reports_the_custodians_reader() {
        for (reader, exported) in [
            (CardReader::Attached, RappCardReader::Attached),
            (CardReader::Absent, RappCardReader::Absent),
        ] {
            let action = requester_dispatch(RequesterDispatch::CardStatus(CardStatusMessage {
                card: CardPresence::Absent,
                reader,
            }));
            assert_eq!(action.kind, RappBridgeActionKind::CardStatus);
            assert_eq!(action.card_present, Some(false));
            assert_eq!(action.certificate_fingerprint, None);
            assert_eq!(action.card_reader, Some(exported));
        }
    }
}
