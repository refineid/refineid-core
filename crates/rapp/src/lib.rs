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
pub mod cpace;
mod crypto;
mod endpoint;
mod journal;
mod liveness;
mod message;
pub mod noise;
mod offer;
mod operation;
#[cfg(feature = "bindings")]
pub mod operation_bindings;
#[cfg(feature = "bindings")]
pub mod operation_bridge;
mod pairing;
mod pairing_attempts;
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
    ProgressEvent, UserApproval,
};
pub use cpace::{
    CPACE_CONFIRMATION_KEY_SIZE, CPACE_KC2_SUITE, CPACE_POINT_SIZE, CPACE_PRK_SIZE, CPACE_PSK_SIZE,
    CPACE_STEP1_MSG_SIZE, CPACE_STEP2_MSG_SIZE, CPACE_STEP3_MSG_SIZE, CPACE_TAG_SIZE,
    CPACE_TRANSCRIPT_HASH_SIZE, CpaceError, CpaceKc2Initiator, CpaceKc2Keys, CpaceKc2Responder,
    CpaceKc2ResponderWaiting, CpaceState, calculate_confirmation_tag, calculate_generator_kc2,
    calculate_transcript_hash_v2, decode_kc2_step1_frame, decode_kc2_step2_frame,
    decode_kc2_step3_frame, derive_kc2_keys, encode_kc2_step1_frame, encode_kc2_step2_frame,
    encode_kc2_step3_frame, encode_pairing_context_v2, hkdf_expand_sha512_32, hkdf_extract_sha512,
    sample_scalar_canonical, sample_scalar_wide, standard_pairing_context_v2,
    verify_tag_constant_time,
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
    LivenessMessage, MessageError, NegotiatedParameters, PairingAbortMessage,
    PairingConfirmMessage, PairingHelloMessage, ProtocolErrorMessage, SessionCloseMessage,
    SessionParameters, SessionReadyMessage, StatusReport, TypedMessage,
};
pub use offer::{MAX_OFFER_SIZE, PairingOffer, PairingOfferDeadline, PairingOfferError};
pub use operation::{
    CardIdentity, CardInspection, CardKeyProfile, CardOperation, CardOperationError,
    CardOperationResult, CertificateKind, CredentialKind, DEFAULT_OPERATION_LIFETIME_MS,
    OperationRequest, OperationRequestRefusal, RequestError, SignatureAlgorithm,
};
pub use pairing::{
    PAIR_RECORD_FORMAT_VERSION, PairRecord, PairRecordCodecError, PairRecordError, PairStore,
    PairStoreError, PairTombstone, PairTransportBinding, decode_pair_record, decode_pair_records,
    encode_pair_record, encode_pair_records,
};
pub use pairing_attempts::{
    CPACE_ATTEMPT_WINDOW_MS, CpaceAttemptLedger, MAXIMUM_CPACE_ATTEMPTS, PairingBackoff,
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
    RequesterError, RequesterJournalRecord, RequesterJournalStore, RequesterOperation,
    RequesterRecoveryStore, RequesterResultAction,
};
pub use requester_engine::{
    RequesterDispatch, RequesterEngineError, RequesterOperationEngine, RequesterViolation,
};
pub use result::{OperationResultMessage, ProxyFailure, ResultError, ResultResponse, ResultStatus};
pub use runtime::{EstablishedSessionRuntime, RuntimeError, RuntimePoll, RuntimeReceive};
pub use session_flow::{ExplicitUserIntent, SessionAuthentication, SessionError, SessionHandshake};
pub use state::{
    Action, EndpointRole, Guards, OperationEvent, OperationState, PairingEvent, PairingState,
    RappState, SecurityOutcome, SessionEvent, SessionState, Transition, TransitionError,
};
pub use stream::{
    DISCOVERY_HINT_EPOCH_SECONDS, DISCOVERY_HINT_SIZE, MAX_STREAM_RENDEZVOUS_FRAME, STREAM_PROFILE,
    StreamError, StreamRendezvous, discovery_hint,
};
pub use transport::{
    BLE_CANDIDATE_ID, BLE_PROFILE, BLE_SERVICE_UUID, BinaryFrame, FrameError, FrameTransport,
    STREAM_CANDIDATE_ID, TransportCandidate, TransportProfile,
};
pub use types::{
    CANDIDATE_FAILURE_HINT_THRESHOLD, CloseReason, FailureClass, GRANTS_HASH_SIZE, GrantsHash,
    IdentifierError, LIVENESS_CHALLENGE_SIZE, MANDATORY_PAIRING_SUITE, MANDATORY_SESSION_SUITE,
    MAX_ACTIVE_OPERATIONS, MAX_FRAME_PLAINTEXT, MAX_FRAME_SIZE, MINIMUM_REMAINING_ATTEMPTS,
    NOISE_TAG_SIZE, OFFER_ID_SIZE, OFFER_TTL_MS, OPERATION_ID_SIZE, OfferId, OperationId,
    PAIR_ID_SIZE, PAIRING_SECRET_SIZE, PairId, PairingSecret, ProfileName, RENDEZVOUS_TOKEN_SIZE,
    REQUEST_HASH_SIZE, RendezvousToken, RequestHash, RetryDecision, SESSION_ID_SIZE,
    SESSION_READY_NONCE_SIZE, SessionId, VisibleConnectionState, WIRE_VERSION_V26_10_9,
    X25519_KEY_SIZE,
};
pub use wire::{
    Envelope, MessageType, SequenceGuard, WireError, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor,
};
