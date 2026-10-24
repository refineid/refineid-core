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
pub mod ble_sar;
pub mod cpace;
mod crypto;
mod endpoint;
mod liveness;
mod message;
pub mod noise;
mod offer;
mod operation;
#[cfg(feature = "bindings")]
pub mod operation_bridge;
mod pair_keys;
mod pairing;
mod pairing_attempts;
mod pairing_candidates;
mod pairing_flow;
mod policy;
mod proxy_engine;
mod requester_engine;
mod result;
mod routing;
mod runtime;
mod session_flow;
mod state;
mod stream;
mod transport;
mod txt;
mod types;
mod wire;
mod withdrawal;

pub use authorization::{
    AuthorizationError, AuthorizationStage, AuthorizationTransaction, AuthorizedCardCommand,
    AuthorizedSafeRead, OperationProgressMessage, PendingCardCommand, PrerequisitesOutcome,
    ProgressEvent, UserApproval,
};
pub use cpace::{
    CPACE_CONFIRMATION_KEY_SIZE, CPACE_KC2_SUITE, CPACE_POINT_SIZE, CPACE_PRK_SIZE, CPACE_PSK_SIZE,
    CPACE_STEP1_MSG_SIZE, CPACE_STEP2_MSG_SIZE, CPACE_STEP3_MSG_SIZE, CPACE_TAG_SIZE,
    CPACE_TRANSCRIPT_HASH_SIZE, CpaceError, CpaceKc2Initiator, CpaceKc2Keys, CpaceKc2Responder,
    CpaceKc2ResponderWaiting, calculate_confirmation_tag, calculate_generator_kc2,
    calculate_transcript_hash_v2, decode_kc2_step1_frame, decode_kc2_step2_frame,
    decode_kc2_step3_frame, derive_kc2_keys, encode_kc2_step1_frame, encode_kc2_step2_frame,
    encode_kc2_step3_frame, encode_pairing_context_v2, hkdf_expand_sha512_32, hkdf_extract_sha512,
    sample_scalar_canonical, sample_scalar_wide, standard_pairing_context_v2,
    verify_tag_constant_time,
};
pub use crypto::{
    CryptoError, HandshakeChannel, HandshakeCompletion, HandshakeRole, OpenError, PairKeyMaterial,
    PairingHandshakeParameters, SecureChannel, SessionHandshakeParameters, compute_grants_hash,
    derive_pair_id, derive_session_id, generate_pair_key_material,
};
pub use endpoint::{
    AuthenticatedViolation, EndpointError, EstablishedEndpoint, OperationViolation, ReceiveOutcome,
};
pub use liveness::{
    LIVENESS_PING_AFTER_SILENCE_MS, LivenessDecision, LivenessTracker, PingChallenge,
    PongDisposition, SESSION_SILENCE_LIMIT_MS,
};
pub use message::{
    CardPresence, CardReader, CardStatusMessage, LivenessMessage, MessageError,
    NegotiatedParameters, PairingAbortMessage, PairingConfirmMessage, PairingHelloMessage,
    PairingStoredMessage, ProtocolErrorMessage, SessionCloseMessage, SessionParameters,
    SessionReadyMessage, TypedMessage,
};
pub use offer::{MAX_OFFER_SIZE, PairingOffer, PairingOfferDeadline, PairingOfferError};
pub use operation::{
    CardIdentity, CardInspection, CardKeyProfile, CardOperation, CardOperationError,
    CardOperationResult, CertificateKind, CredentialKind, DEFAULT_OPERATION_LIFETIME_MS,
    OperationRequest, OperationRequestRefusal, RequestError, SignatureAlgorithm,
};
pub use pair_keys::{DegenerateAgreement, PAIR_KEY_SIZE};
pub(crate) use pair_keys::{derive_pair_key, mac as pair_key_mac};
pub use pairing::{
    EncodedPairRecord, PAIR_RECORD_FORMAT_VERSION, PAIRING_IDLE_EXPIRY_DAYS,
    PAIRING_IDLE_EXPIRY_MS, PairRecord, PairRecordCodecError, PairRecordError,
    REVOCATION_NOTICE_DAYS, REVOCATION_NOTICE_MS, SweepError, SweepOutcome, decode_pair_record,
    decode_pair_records, encode_pair_record, encode_pair_records,
};
pub use pairing_attempts::{
    CPACE_ATTEMPT_WINDOW_MS, CpaceAttemptLedger, MAXIMUM_CPACE_ATTEMPTS, POST_PAKE_CONFIRMATION_MS,
    POST_PAKE_HANDSHAKE_MS, PRE_AUTHENTICATION_SPACING_MS, PairingBackoff,
    PreAuthenticationRateLimit, phase_deadline_ms,
};
pub use pairing_candidates::{
    CandidateError, NextCandidate, PAIRING_CANDIDATES_MAX, PairingCandidates,
};
pub use pairing_flow::{
    ActivePairing, PairingAttemptFailure, PairingConfirmation, PairingError, PairingHandshake,
    PairingStorage,
};
pub use policy::{
    IncidentDisposition, OperationDisposition, PairDisposition, SecurityIncident,
    SessionDisposition,
};
pub use proxy_engine::{
    ProxyDispatch, ProxyEngineError, ProxyOperationEngine, ProxySessionCloseAction, ProxyViolation,
};
pub use requester_engine::{
    RequesterDispatch, RequesterEngineError, RequesterOperationEngine, RequesterViolation,
};
pub use result::{OperationResultMessage, ProxyFailure, ResultError, ResultResponse, ResultStatus};
pub use routing::{
    DISCOVERY_HINT_EPOCH_SECONDS, DISCOVERY_HINT_SIZE, DiscoveryKey, DiscoveryRecord,
    DiscoveryRecordError, MAX_DISCOVERY_HINTS, ROUTING_NONCE_SIZE, ROUTING_REPLAY_WINDOW,
    ROUTING_TAG_SIZE, RandomUnavailable, RecordKeyError, RoutingKey, RoutingReplayCache,
    SESSION_ROUTING_SIZE, SessionRouting, discovery_epoch, route_session,
};
pub use runtime::{EstablishedSessionRuntime, RuntimeError, RuntimePoll, RuntimeReceive};
pub use session_flow::{
    ExplicitUserIntent, ReadyOutcome, SessionAuthentication, SessionError, SessionHandshake,
};
pub use state::{
    Action, EndpointRole, Guards, OperationEvent, OperationState, PairingEvent, PairingState,
    RappState, SecurityOutcome, SessionEvent, SessionState, Transition, TransitionError,
};
pub use stream::{MAX_ROUTING_PREAMBLE_FRAME, PreambleError, RoutingPreamble, STREAM_PROFILE};
pub use transport::{
    BLE_CANDIDATE_ID, BLE_PROFILE, BLE_SERVICE_UUID, BinaryFrame, FrameError, FrameTransport,
    STREAM_CANDIDATE_ID, TransportCandidate, TransportProfile,
};
pub use txt::AnnouncementCandidate;
pub use types::{
    CERTIFICATE_FINGERPRINT_SIZE, CertificateFingerprint, CloseReason, GRANTS_HASH_SIZE,
    GrantsHash, IDENTITY_OFFER_GRACE_MS, IdentifierError, LIVENESS_CHALLENGE_SIZE,
    MANDATORY_PAIRING_SUITE, MANDATORY_SESSION_SUITE, MAX_ACTIVE_OPERATIONS, MAX_FRAME_PLAINTEXT,
    MAX_FRAME_SIZE, MINIMUM_REMAINING_ATTEMPTS, NOISE_TAG_SIZE, OFFER_ID_SIZE, OFFER_TTL_MS,
    OPERATION_ID_SIZE, OfferId, OperationId, PAIR_ID_SIZE, PAIRING_SECRET_SIZE, PairId,
    PairingSecret, ProfileName, QUIT_WITHDRAWAL_BOUND_MS, RetryDecision, SESSION_ID_SIZE,
    SESSION_READY_NONCE_SIZE, SessionId, WIRE_VERSION_V26_10_22, X25519_KEY_SIZE,
};
pub use wire::{
    Envelope, MessageType, SequenceGuard, WireError, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor,
};
pub use withdrawal::{
    InstanceName, MAX_INSTANCE_NAME_SIZE, WITHDRAWAL_COUNTER_SECONDS, WITHDRAWAL_HINT_SIZE,
    WITHDRAWN_RECORD_ENTRIES, WithdrawalError, WithdrawalKey, WithdrawnRecord,
    WithdrawnRecordError, withdrawal_counter,
};
