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

//! Transport-independent Remote Authorization Proxy Protocol core.
//!
//! This crate implements the ownership and state boundaries of the RAPP
//! 0.1 draft. Network transports, platform key stores, presentation, and card
//! drivers are injected by adapters. They do not get to reinterpret protocol
//! state or repeat credential commands.

#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();

mod authorization;
#[cfg(feature = "bindings")]
pub mod bindings;
mod crypto;
mod endpoint;
mod journal;
mod liveness;
mod message;
mod offer;
mod operation;
#[cfg(feature = "bindings")]
pub mod operation_bindings;
#[cfg(feature = "bindings")]
pub mod operation_bridge;
mod pairing;
mod pairing_flow;
mod policy;
mod proxy_engine;
mod requester;
mod requester_engine;
mod result;
mod runtime;
mod session_flow;
mod state;
mod stream;
mod transport;
mod types;
mod wire;

pub use authorization::{
    ApprovalOutcome, AuthorizationError, AuthorizationStage, AuthorizationTransaction,
    AuthorizedCardCommand, AuthorizedSafeRead, OperationProgressMessage, OperationReference,
    ProgressEvent, ProxyCancelOutcome, UserApproval,
};
pub use crypto::{
    CryptoError, HandshakeChannel, HandshakeCompletion, HandshakeRole, OpenError, PairKeyMaterial,
    PairingHandshakeParameters, SecureChannel, SessionHandshakeParameters, compute_grants_hash,
    compute_request_hash, derive_pair_id, derive_rendezvous_token, derive_session_id,
    generate_pair_key_material,
};
pub use endpoint::{AuthenticatedViolation, EndpointError, EstablishedEndpoint, ReceiveOutcome};
pub use journal::{
    JournalError, JournalRecord, JournalRecoveryStore, JournalStore, OperationJournal,
    PendingCardCommand, RecoveredProxyRecord, ResultJournalStore,
};
pub use liveness::{
    LivenessConfig, LivenessDecision, LivenessError, LivenessTracker, PingChallenge,
    PongDisposition,
};
pub use message::{
    CancelMessage, LivenessMessage, MessageError, NegotiatedParameters, PairingAbortMessage,
    PairingConfirmMessage, PairingHelloMessage, ProtocolErrorMessage, SessionCloseMessage,
    SessionParameters, SessionReadyMessage, StatusReport, TypedMessage,
};
pub use offer::{PairingOffer, PairingOfferDeadline, PairingOfferError, PairingOfferUri};
pub use operation::{
    CardInspection, CardKeyProfile, CardOperation, CardOperationError, CardOperationResult,
    CertificateKind, CredentialKind, OperationRequest, SignatureAlgorithm,
};
pub use pairing::{
    PairRecord, PairRecordError, PairStore, PairStoreError, PairTombstone, PairTransportBinding,
};
pub use pairing_flow::{
    PairingAttemptFailure, PairingConfirmation, PairingError, PairingHandshake,
};
pub use policy::{
    IncidentDisposition, OperationDisposition, PairDisposition, SecurityIncident,
    SessionDisposition,
};
pub use proxy_engine::{
    ProxyDispatch, ProxyEngineError, ProxyOperationEngine, ProxySessionCloseAction, ProxyViolation,
};
pub use requester::{
    RequesterCancelAction, RequesterError, RequesterJournalRecord, RequesterJournalStore,
    RequesterOperation, RequesterRecoveryStore, RequesterResultAction,
};
pub use requester_engine::{
    RequesterDispatch, RequesterEngineError, RequesterOperationEngine, RequesterViolation,
};
pub use result::{OperationResultMessage, ResultError, ResultStatus};
pub use runtime::{EstablishedSessionRuntime, RuntimeError, RuntimePoll, RuntimeReceive};
pub use session_flow::{ExplicitUserIntent, SessionAuthentication, SessionError, SessionHandshake};
pub use state::{
    Action, EndpointRole, Guards, OperationEvent, OperationState, PairingEvent, PairingState,
    RappState, SecurityOutcome, SessionEvent, SessionState, Transition, TransitionError,
};
pub use stream::{
    MAX_STREAM_ENDPOINT_BYTES, MAX_STREAM_ENDPOINTS, MAX_STREAM_RENDEZVOUS_FRAME, STREAM_PROFILE,
    StreamCandidateParameters, StreamError, StreamRendezvous,
};
pub use transport::{BinaryFrame, FrameError, FrameTransport, TransportCandidate};
pub use types::{
    CANDIDATE_FAILURE_HINT_THRESHOLD, CloseReason, FailureClass, GRANTS_HASH_SIZE, GrantsHash,
    IdentifierError, LIVENESS_CHALLENGE_SIZE, MANDATORY_PAIRING_SUITE, MANDATORY_SESSION_SUITE,
    MAX_ACTIVE_OPERATIONS, MAX_FRAME_PLAINTEXT, MAX_FRAME_SIZE, MAX_TRANSPORT_CANDIDATES,
    MINIMUM_REMAINING_ATTEMPTS, OFFER_ID_SIZE, OFFER_TTL_MAX_MS, OPERATION_ID_SIZE, OfferId,
    OperationId, PAIR_ID_SIZE, PAIRING_SECRET_SIZE, PairId, PairingSecret, ProfileName,
    RENDEZVOUS_TOKEN_SIZE, REQUEST_HASH_SIZE, RendezvousToken, RequestHash, RetryDecision,
    SESSION_ID_SIZE, SESSION_READY_NONCE_SIZE, SessionId, VISIBLE_WIRE_VERSION,
    VisibleConnectionState,
};
pub use wire::{
    Envelope, MessageType, SequenceGuard, WireError, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor,
};
