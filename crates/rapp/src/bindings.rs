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

//! Generated-binding boundary for the authenticated RAPP pairing ceremony.
//!
//! The foreign application transports opaque bounded frames. Noise state,
//! one-use QR ownership, authenticated parameter checks, and grant equality
//! remain inside Rust. Completed private pair material stays inside the opaque
//! [`RappPairRecord`] until a device-only vault adapter is supplied.

use std::sync::{Arc, Mutex, MutexGuard};

use super::{
    BinaryFrame, CandidateError, CpaceAttemptLedger, CpaceKc2Initiator, CpaceKc2Responder,
    CpaceKc2ResponderWaiting, EndpointRole, EstablishedEndpoint, ExplicitUserIntent, NextCandidate,
    OfferId, POST_PAKE_CONFIRMATION_MS, POST_PAKE_HANDSHAKE_MS, PairId, PairKeyMaterial,
    PairRecord, PairingBackoff, PairingCandidates, PairingConfirmation, PairingError,
    PairingHandshake, PairingOffer, PairingOfferDeadline, PairingSecret, PairingStorage,
    PreAuthenticationRateLimit, ProfileName, ReadyOutcome, RoutingPreamble, STREAM_PROFILE,
    SessionAuthentication, SessionHandshake, SessionId, TransportProfile, encode_kc2_step1_frame,
    generate_pair_key_material,
    operation_bridge::{EndedOperation, RappBridgeAction, RappBridgeActionKind},
    phase_deadline_ms, standard_pairing_context_v2,
};

/// Endpoint role fixed by the protocol rather than transport direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappEndpointRole {
    /// Device requesting use of a remote card.
    Requester,
    /// Phone holding and authorizing access to the card.
    Proxy,
}

/// Exact platform-CSPRNG byte counts required by generated bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappRandomByteCounts {
    /// Offer identifier length in bytes.
    pub offer_id: u64,
    /// CPace random scalar entropy length in bytes.
    pub cpace_random: u64,
    /// Session-ready nonce length in bytes.
    pub session_ready_nonce: u64,
    /// Operation identifier length in bytes.
    pub operation_id: u64,
    /// Liveness challenge length in bytes.
    pub liveness_challenge: u64,
}

/// Exact byte counts the platform CSPRNG must supply.
#[uniffi::export]
#[must_use]
pub const fn rapp_random_byte_counts() -> RappRandomByteCounts {
    RappRandomByteCounts {
        offer_id: super::OFFER_ID_SIZE as u64,
        cpace_random: 64,
        session_ready_nonce: super::SESSION_READY_NONCE_SIZE as u64,
        operation_id: super::OPERATION_ID_SIZE as u64,
        liveness_challenge: super::LIVENESS_CHALLENGE_SIZE as u64,
    }
}

impl From<RappEndpointRole> for EndpointRole {
    fn from(value: RappEndpointRole) -> Self {
        match value {
            RappEndpointRole::Requester => Self::Requester,
            RappEndpointRole::Proxy => Self::Proxy,
        }
    }
}

impl From<EndpointRole> for RappEndpointRole {
    fn from(value: EndpointRole) -> Self {
        match value {
            EndpointRole::Requester => Self::Requester,
            EndpointRole::Proxy => Self::Proxy,
        }
    }
}

/// One transport entry of a live offer.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappOfferCandidate {
    /// Registered transport profile.
    pub profile: String,
    /// Its registered candidate identifier, echoed after authentication.
    pub candidate_id: String,
}

/// Authenticated label and requested profiles received from the peer.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappPeerHello {
    /// User-visible peer label shown during explicit pairing confirmation.
    pub display_name: String,
    /// Peer platform label.
    pub platform: String,
    /// Exact requester profile list; absent when the peer is the proxy.
    pub requested_profiles: Option<Vec<String>>,
}

/// Stable, non-secret metadata for a completed pairing.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappPairMetadata {
    /// Transcript-derived pair identifier.
    pub pair_id: Vec<u8>,
    /// Local role permanently bound into the pair record.
    pub role: RappEndpointRole,
    /// Exact mutually confirmed profile registry names.
    pub profiles: Vec<String>,
    /// Pair-record creation time supplied by the platform wall clock.
    pub created_at_ms: u64,
    /// Whether the peer confirmed storing its record (RAPP v26.10.22 §4.3
    /// item 4). A record loaded unconfirmed survived a crash inside the
    /// confirmation window: it opens no session, routes nothing, and the
    /// caller revokes it.
    pub storage_confirmed: bool,
    /// When the local user forgot the pairing, or it expired, while no
    /// session was open: the record serves nothing and keeps its key only
    /// to deliver the `pairing_revoked` close on the next session (RAPP
    /// §4.6 item 2).
    pub forgotten_at_ms: Option<u64>,
    /// The latest wall-clock time [`RappPairRecord::sweep`] recorded at
    /// which the pairing had an established session, or `None` while it has
    /// had none (RAPP §4.6 item 5).
    pub last_session_at_ms: Option<u64>,
}

/// What an idle-expiry sweep did with one pairing (RAPP §4.6 item 5).
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappSweepOutcome {
    /// A session to the pairing is established: its time is recorded and
    /// stored, and the pairing stays.
    Recorded,
    /// Nothing changed: no session is established and the pairing is short
    /// of the idle limit, or the record is forgotten already.
    Kept,
    /// The pairing went 30 days without an established session: it is
    /// stored as forgotten and keeps its key only for the close (RAPP §4.6
    /// items 2 to 4). Withdraw its identity; send nothing and tell no user.
    Expired,
}

impl From<super::SweepOutcome> for RappSweepOutcome {
    fn from(value: super::SweepOutcome) -> Self {
        match value {
            super::SweepOutcome::Recorded => Self::Recorded,
            super::SweepOutcome::Kept => Self::Kept,
            super::SweepOutcome::Expired => Self::Expired,
        }
    }
}

/// What forgetting a pairing did (RAPP §4.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappForgetOutcome {
    /// The record is marked forgotten and keeps its key until the next
    /// session delivers the close, or for 30 days: dial or route as usual,
    /// then call [`RappSessionBridge::deliver_revocation_notice`].
    NoticePending,
    /// The pairing was never confirmed; its key is destroyed and nobody is
    /// told.
    Destroyed,
}

/// Deliberately coarse binding failure. Protocol internals and secrets never
/// become UI strings or foreign-language log material.
#[allow(
    missing_copy_implementations,
    reason = "generated FFI error registry; Copy is not part of the binding contract"
)]
#[derive(Debug, uniffi::Error)]
pub enum RappBindingError {
    /// Caller-provided bytes or registry values were invalid.
    InvalidInput,
    /// Method was not legal in the current protocol phase.
    WrongPhase,
    /// The one-use pairing offer reached its monotonic deadline.
    OfferExpired,
    /// The peer never confirmed that it stored the pairing (RAPP v26.10.22
    /// §4.3 item 4): the post-PAKE deadline passed in the storage phase, or
    /// a record loaded from the vault is unconfirmed. Such a record opens
    /// no session, routes nothing and is announced nowhere; the caller
    /// revokes it with [`RappPairRecord::revoke`].
    StorageUnconfirmed,
    /// Authenticated protocol or cryptographic processing failed.
    ProtocolFailure,
    /// Local synchronization state was poisoned and cannot be reused.
    LocalStateFailure,
    /// Requested active pair record was not present in device-only storage.
    PairNotFound,
    /// Referenced operation was not found in the active session.
    UnknownOperation,
    /// Three pairing attempts failed against one offer; the offer is
    /// destroyed (RAPP v26.10.22 §3.3).
    AttemptsExhausted,
    /// A pre-authentication attempt came within 500 ms of the previous one
    /// (RAPP v26.10.22 §3.3.8); the caller refuses it and changes nothing.
    RateLimited,
}

impl core::fmt::Display for RappBindingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for RappBindingError {}

enum CpaceBridgeState {
    RequesterStep1 {
        initiator: Box<CpaceKc2Initiator>,
        step1_frame: BinaryFrame,
        offer: PairingOffer,
        candidate_id: String,
        local_keys: PairKeyMaterial,
        deadline: PairingOfferDeadline,
    },
    RequesterStep3 {
        step3_frame: BinaryFrame,
        pairing_secret: PairingSecret,
        offer: PairingOffer,
        candidate_id: String,
        local_keys: PairKeyMaterial,
        deadline: PairingOfferDeadline,
    },
    CustodianWaitingStep1 {
        pairing_code: String,
        random_bytes_64: [u8; 64],
        offer: PairingOffer,
        candidate_id: String,
        local_keys: PairKeyMaterial,
        deadline: PairingOfferDeadline,
    },
    CustodianWaitingStep3 {
        waiting: Box<CpaceKc2ResponderWaiting>,
        step2_frame: BinaryFrame,
        offer: PairingOffer,
        candidate_id: String,
        local_keys: PairKeyMaterial,
        deadline: PairingOfferDeadline,
    },
}

impl CpaceBridgeState {
    fn deadline(&self) -> PairingOfferDeadline {
        match self {
            Self::RequesterStep1 { deadline, .. }
            | Self::RequesterStep3 { deadline, .. }
            | Self::CustodianWaitingStep1 { deadline, .. }
            | Self::CustodianWaitingStep3 { deadline, .. } => *deadline,
        }
    }

    fn role(&self) -> EndpointRole {
        match self {
            Self::RequesterStep1 { .. } | Self::RequesterStep3 { .. } => EndpointRole::Requester,
            Self::CustodianWaitingStep1 { .. } | Self::CustodianWaitingStep3 { .. } => {
                EndpointRole::Proxy
            }
        }
    }

    fn into_offer(self) -> PairingOffer {
        match self {
            Self::RequesterStep1 { offer, .. }
            | Self::RequesterStep3 { offer, .. }
            | Self::CustodianWaitingStep1 { offer, .. }
            | Self::CustodianWaitingStep3 { offer, .. } => offer,
        }
    }
}

enum PairingBridgeState {
    Offer {
        role: EndpointRole,
        offer: PairingOffer,
        deadline: PairingOfferDeadline,
    },
    Cpace(Box<CpaceBridgeState>),
    /// `Noise_XXpsk3` after CPace handoff, bounded by the post-PAKE
    /// handshake deadline instead of the offer lifetime (§3.3.7).
    Handshake {
        handshake: Box<PairingHandshake>,
        deadline_ms: u64,
    },
    /// Hello, grant confirmation and storage, bounded by the deadline that
    /// starts at local Noise completion (§3.3.7).
    Confirmation {
        confirmation: Box<PairingConfirmation>,
        deadline_ms: u64,
    },
    /// The stored record awaiting the peer's storage confirmation, under
    /// the confirmation deadline (§3.3.7, §4.3 item 4).
    Storage {
        storage: Box<PairingStorage>,
        record: Arc<RappPairRecord>,
        deadline_ms: u64,
    },
    Completed,
    Expired,
    /// Three failed attempts destroyed the custodian's offer (§3.3.5).
    Exhausted,
    Failed,
}

impl PairingBridgeState {
    /// Enforce the deadline of the current phase: the offer lifetime before
    /// CPace handoff, the post-PAKE deadlines after it. Any expiry destroys
    /// the candidate.
    fn require_live_offer(&mut self, now_monotonic_ms: u64) -> Result<(), RappBindingError> {
        let deadline = match self {
            Self::Offer { deadline, .. } => *deadline,
            Self::Handshake { deadline_ms, .. } | Self::Confirmation { deadline_ms, .. } => {
                if now_monotonic_ms < *deadline_ms {
                    return Ok(());
                }
                *self = Self::Expired;
                return Err(RappBindingError::OfferExpired);
            }
            Self::Storage { deadline_ms, .. } => {
                if now_monotonic_ms < *deadline_ms {
                    return Ok(());
                }
                *self = Self::Failed;
                return Err(RappBindingError::StorageUnconfirmed);
            }
            Self::Cpace(cpace) => cpace.deadline(),
            Self::Exhausted => return Err(RappBindingError::AttemptsExhausted),
            _ => return Ok(()),
        };
        if deadline.is_live(now_monotonic_ms) {
            return Ok(());
        }
        *self = Self::Expired;
        Err(RappBindingError::OfferExpired)
    }

    /// The state after a CPace failure that spent no admitted attempt: the
    /// offer stays for another connection on either role.
    const fn after_cpace_failure(
        role: EndpointRole,
        offer: PairingOffer,
        deadline: PairingOfferDeadline,
    ) -> Self {
        Self::Offer {
            role,
            offer,
            deadline,
        }
    }
}

/// Opaque pairing lifecycle used by generated Swift and Kotlin bindings.
#[allow(
    missing_debug_implementations,
    reason = "state holds the bearer secret and candidate keys; no formatted view exists"
)]
#[derive(uniffi::Object)]
pub struct RappPairingBridge {
    state: Mutex<PairingBridgeState>,
    attempts: Mutex<CpaceAttemptLedger>,
    pre_authentication: Mutex<PreAuthenticationRateLimit>,
}

#[uniffi::export]
impl RappPairingBridge {
    /// Create the custodian's offer (RAPP v26.10.22 §4.2) from a fresh
    /// platform-CSPRNG `offer_id`, the offered credential profiles, and the
    /// transport profiles the offer is served on.
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on a wrong-size identifier, an
    /// unregistered profile, or an offer that fails validation.
    #[uniffi::constructor]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn create_custodian_offer(
        offer_id: Vec<u8>,
        profiles: Vec<String>,
        transport_profiles: Vec<String>,
        started_at_monotonic_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        let offer_id =
            OfferId::reconstruct(&offer_id).map_err(|_| RappBindingError::InvalidInput)?;
        let transports = transport_profiles
            .iter()
            .map(|name| TransportProfile::parse(name).ok_or(RappBindingError::InvalidInput))
            .collect::<Result<Vec<_>, _>>()?;
        let offer = PairingOffer::create(offer_id, profiles, &transports)
            .map_err(|_| RappBindingError::InvalidInput)?;
        Self::with_offer(EndpointRole::Proxy, offer, started_at_monotonic_ms)
    }

    /// Accept the offer bootstrap the requester received over the
    /// transport `transport_profile` (RAPP v26.10.22 §4.2): the Bootstrap
    /// Characteristic value on BLE, or the custodian's first frame after the
    /// pairing preamble on the stream transport.
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on an unregistered transport
    /// profile, or an offer that does not decode, validate, or list the
    /// transport it arrived over.
    #[uniffi::constructor]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn from_bootstrap(
        offer_bytes: Vec<u8>,
        transport_profile: String,
        started_at_monotonic_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        let profile =
            TransportProfile::parse(&transport_profile).ok_or(RappBindingError::InvalidInput)?;
        let offer = PairingOffer::from_bootstrap(&offer_bytes, profile)
            .map_err(|_| RappBindingError::InvalidInput)?;
        Self::with_offer(EndpointRole::Requester, offer, started_at_monotonic_ms)
    }

    /// The custodian's offer bootstrap bytes,
    /// `encode_deterministic_cbor(pairing-offer)`, while the offer is live.
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer, the requester role, or a
    /// phase other than the offer.
    pub fn bootstrap_bytes(&self, now_monotonic_ms: u64) -> Result<Vec<u8>, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let PairingBridgeState::Offer {
            role: EndpointRole::Proxy,
            offer,
            ..
        } = &*state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let bytes = offer
            .to_cbor()
            .map_err(|_| RappBindingError::ProtocolFailure);
        drop(state);
        bytes
    }

    /// Advertised lifetime used by the platform to schedule visible expiry.
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] outside the offer phase.
    pub fn offer_ttl_ms(&self) -> Result<u64, RappBindingError> {
        let state = self.lock()?;
        match &*state {
            PairingBridgeState::Offer { offer, .. } => Ok(offer.offer_ttl_ms),
            _ => Err(RappBindingError::WrongPhase),
        }
    }

    /// Transport entries of the live offer.
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] outside the offer phase.
    pub fn offer_candidates(&self) -> Result<Vec<RappOfferCandidate>, RappBindingError> {
        let state = self.lock()?;
        let PairingBridgeState::Offer { offer, .. } = &*state else {
            return Err(RappBindingError::WrongPhase);
        };
        let candidates = offer
            .transports
            .iter()
            .map(|candidate| RappOfferCandidate {
                profile: candidate.profile.clone(),
                candidate_id: candidate.candidate_id.clone(),
            })
            .collect();
        drop(state);
        Ok(candidates)
    }

    /// Begin CPace PAKE key exchange for a selected transport candidate using the 6-digit code.
    ///
    /// # Errors
    /// [`RappBindingError`] on expired offer, wrong phase, or invalid random scalar entropy.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn begin_cpace(
        &self,
        candidate_id: String,
        pairing_code: String,
        random_bytes_64: Vec<u8>,
        now_monotonic_ms: u64,
    ) -> Result<(), RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Offer {
            role,
            offer,
            deadline,
        } = previous
        else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        let random_array: [u8; 64] = random_bytes_64
            .as_slice()
            .try_into()
            .map_err(|_| RappBindingError::InvalidInput)?;
        let Ok(local_keys) = generate_pair_key_material() else {
            *state = PairingBridgeState::Offer {
                role,
                offer,
                deadline,
            };
            return Err(RappBindingError::ProtocolFailure);
        };
        let offer_hash = match offer.offer_hash() {
            Ok(h) => h,
            Err(_) => {
                *state = PairingBridgeState::Offer {
                    role,
                    offer,
                    deadline,
                };
                return Err(RappBindingError::ProtocolFailure);
            }
        };
        let context = match pairing_context(&offer, &offer_hash, &candidate_id) {
            Ok(c) => c,
            Err(_) => {
                *state = PairingBridgeState::Offer {
                    role,
                    offer,
                    deadline,
                };
                return Err(RappBindingError::ProtocolFailure);
            }
        };

        match role {
            EndpointRole::Requester => {
                let (initiator, ya) = match CpaceKc2Initiator::new(
                    &pairing_code,
                    &context,
                    &offer.offer_id,
                    &random_array,
                ) {
                    Ok(res) => res,
                    Err(_) => {
                        *state = PairingBridgeState::Offer {
                            role,
                            offer,
                            deadline,
                        };
                        return Err(RappBindingError::InvalidInput);
                    }
                };
                let step1_frame = match encode_kc2_step1_frame(&ya) {
                    Ok(f) => f,
                    Err(_) => {
                        *state = PairingBridgeState::Offer {
                            role,
                            offer,
                            deadline,
                        };
                        return Err(RappBindingError::ProtocolFailure);
                    }
                };
                *state = PairingBridgeState::Cpace(Box::new(CpaceBridgeState::RequesterStep1 {
                    initiator: Box::new(initiator),
                    step1_frame,
                    offer,
                    candidate_id,
                    local_keys,
                    deadline,
                }));
                Ok(())
            }
            EndpointRole::Proxy => {
                // §3.3.8: one pre-authentication attempt per 500 ms, which
                // also spaces repeated invalid Y_A submissions.
                let admitted = self
                    .pre_authentication
                    .lock()
                    .map_err(|_| RappBindingError::LocalStateFailure)?
                    .admit(now_monotonic_ms);
                if !admitted {
                    *state = PairingBridgeState::Offer {
                        role,
                        offer,
                        deadline,
                    };
                    return Err(RappBindingError::RateLimited);
                }
                let ledger = self.lock_attempts()?;
                if !ledger.accepts_another_attempt() || ledger.has_active_attempt() {
                    let exhausted = ledger.is_exhausted();
                    drop(ledger);
                    *state = PairingBridgeState::Offer {
                        role,
                        offer,
                        deadline,
                    };
                    return Err(if exhausted {
                        RappBindingError::AttemptsExhausted
                    } else {
                        RappBindingError::WrongPhase
                    });
                }
                drop(ledger);
                *state =
                    PairingBridgeState::Cpace(Box::new(CpaceBridgeState::CustodianWaitingStep1 {
                        pairing_code,
                        random_bytes_64: random_array,
                        offer,
                        candidate_id,
                        local_keys,
                        deadline,
                    }));
                Ok(())
            }
        }
    }

    /// Produce the local CPace public point frame to send to the peer.
    ///
    /// # Errors
    /// [`RappBindingError`] on wrong phase or framing error.
    pub fn write_cpace_frame(&self, now_monotonic_ms: u64) -> Result<Vec<u8>, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Cpace(cpace_state) = previous else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        match *cpace_state {
            CpaceBridgeState::RequesterStep1 {
                initiator,
                step1_frame,
                offer,
                candidate_id,
                local_keys,
                deadline,
            } => {
                let bytes = step1_frame.as_bytes().to_vec();
                *state = PairingBridgeState::Cpace(Box::new(CpaceBridgeState::RequesterStep1 {
                    initiator,
                    step1_frame,
                    offer,
                    candidate_id,
                    local_keys,
                    deadline,
                }));
                Ok(bytes)
            }
            CpaceBridgeState::RequesterStep3 {
                step3_frame,
                pairing_secret,
                offer,
                candidate_id,
                local_keys,
                deadline,
            } => {
                let bytes = step3_frame.as_bytes().to_vec();
                match PairingHandshake::begin(
                    EndpointRole::Requester,
                    offer,
                    &candidate_id,
                    local_keys,
                    &pairing_secret,
                ) {
                    Ok(handshake) => {
                        *state = PairingBridgeState::Handshake {
                            handshake: Box::new(handshake),
                            deadline_ms: phase_deadline_ms(
                                now_monotonic_ms,
                                POST_PAKE_HANDSHAKE_MS,
                            ),
                        };
                        Ok(bytes)
                    }
                    Err(failure) => {
                        let (_, offer) = failure.into_parts();
                        *state = PairingBridgeState::after_cpace_failure(
                            EndpointRole::Requester,
                            offer,
                            deadline,
                        );
                        Err(RappBindingError::ProtocolFailure)
                    }
                }
            }
            CpaceBridgeState::CustodianWaitingStep3 {
                waiting,
                step2_frame,
                offer,
                candidate_id,
                local_keys,
                deadline,
            } => {
                if !self.lock_attempts()?.attempt_is_live(now_monotonic_ms) {
                    let (next, error) =
                        self.custodian_attempt_failed(offer, deadline, now_monotonic_ms)?;
                    *state = next;
                    return Err(error);
                }
                let bytes = step2_frame.as_bytes().to_vec();
                *state =
                    PairingBridgeState::Cpace(Box::new(CpaceBridgeState::CustodianWaitingStep3 {
                        waiting,
                        step2_frame,
                        offer,
                        candidate_id,
                        local_keys,
                        deadline,
                    }));
                Ok(bytes)
            }
            CpaceBridgeState::CustodianWaitingStep1 {
                pairing_code,
                random_bytes_64,
                offer,
                candidate_id,
                local_keys,
                deadline,
            } => {
                *state =
                    PairingBridgeState::Cpace(Box::new(CpaceBridgeState::CustodianWaitingStep1 {
                        pairing_code,
                        random_bytes_64,
                        offer,
                        candidate_id,
                        local_keys,
                        deadline,
                    }));
                Err(RappBindingError::WrongPhase)
            }
        }
    }

    /// Consume the peer's CPace frame, derive the shared pairing secret, and immediately
    /// begin the Noise XXpsk3 handshake.
    ///
    /// # Errors
    /// [`RappBindingError`] on wrong phase, invalid point, or handshake creation failure.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn read_cpace_frame(
        &self,
        frame: Vec<u8>,
        now_monotonic_ms: u64,
    ) -> Result<(), RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Cpace(cpace_state) = previous else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        match *cpace_state {
            CpaceBridgeState::CustodianWaitingStep1 {
                pairing_code,
                random_bytes_64,
                offer,
                candidate_id,
                local_keys,
                deadline,
            } => {
                let binary_frame = match BinaryFrame::reconstruct(frame) {
                    Ok(f) => f,
                    Err(_) => {
                        *state = PairingBridgeState::after_cpace_failure(
                            EndpointRole::Proxy,
                            offer,
                            deadline,
                        );
                        return Err(RappBindingError::ProtocolFailure);
                    }
                };
                let offer_hash = match offer.offer_hash() {
                    Ok(h) => h,
                    Err(_) => {
                        *state = PairingBridgeState::after_cpace_failure(
                            EndpointRole::Proxy,
                            offer,
                            deadline,
                        );
                        return Err(RappBindingError::ProtocolFailure);
                    }
                };
                let context = match pairing_context(&offer, &offer_hash, &candidate_id) {
                    Ok(c) => c,
                    Err(_) => {
                        *state = PairingBridgeState::after_cpace_failure(
                            EndpointRole::Proxy,
                            offer,
                            deadline,
                        );
                        return Err(RappBindingError::ProtocolFailure);
                    }
                };
                let (step2_frame, waiting) = match CpaceKc2Responder::process_step1_frame(
                    &pairing_code,
                    &context,
                    &offer.offer_id,
                    &binary_frame,
                    &random_bytes_64,
                ) {
                    Ok(res) => res,
                    Err(_) => {
                        *state = PairingBridgeState::after_cpace_failure(
                            EndpointRole::Proxy,
                            offer,
                            deadline,
                        );
                        return Err(RappBindingError::ProtocolFailure);
                    }
                };
                // §3.3.2: the attempt is reserved before Y_B and T_B leave.
                let mut ledger = self.lock_attempts()?;
                if !ledger.admit(now_monotonic_ms, deadline.expires_at_ms()) {
                    let exhausted = ledger.is_exhausted();
                    drop(ledger);
                    *state = PairingBridgeState::after_cpace_failure(
                        EndpointRole::Proxy,
                        offer,
                        deadline,
                    );
                    return Err(if exhausted {
                        RappBindingError::AttemptsExhausted
                    } else {
                        RappBindingError::WrongPhase
                    });
                }
                drop(ledger);
                *state =
                    PairingBridgeState::Cpace(Box::new(CpaceBridgeState::CustodianWaitingStep3 {
                        waiting: Box::new(waiting),
                        step2_frame,
                        offer,
                        candidate_id,
                        local_keys,
                        deadline,
                    }));
                Ok(())
            }
            CpaceBridgeState::CustodianWaitingStep3 {
                waiting,
                offer,
                candidate_id,
                local_keys,
                deadline,
                ..
            } => {
                let verified = self
                    .lock_attempts()?
                    .attempt_is_live(now_monotonic_ms)
                    .then(|| BinaryFrame::reconstruct(frame).ok())
                    .flatten()
                    .and_then(|binary_frame| waiting.process_step3_frame(&binary_frame).ok());
                let Some(pairing_secret) = verified else {
                    let (next, error) =
                        self.custodian_attempt_failed(offer, deadline, now_monotonic_ms)?;
                    *state = next;
                    return Err(error);
                };
                self.lock_attempts()?.consume();
                match PairingHandshake::begin(
                    EndpointRole::Proxy,
                    offer,
                    &candidate_id,
                    local_keys,
                    &pairing_secret,
                ) {
                    Ok(handshake) => {
                        *state = PairingBridgeState::Handshake {
                            handshake: Box::new(handshake),
                            deadline_ms: phase_deadline_ms(
                                now_monotonic_ms,
                                POST_PAKE_HANDSHAKE_MS,
                            ),
                        };
                        Ok(())
                    }
                    Err(_) => {
                        // The verified T_A consumed the offer.
                        *state = PairingBridgeState::Failed;
                        Err(RappBindingError::ProtocolFailure)
                    }
                }
            }
            CpaceBridgeState::RequesterStep1 {
                initiator,
                offer,
                candidate_id,
                local_keys,
                deadline,
                ..
            } => {
                let binary_frame = match BinaryFrame::reconstruct(frame) {
                    Ok(f) => f,
                    Err(_) => {
                        *state = PairingBridgeState::after_cpace_failure(
                            EndpointRole::Requester,
                            offer,
                            deadline,
                        );
                        return Err(RappBindingError::ProtocolFailure);
                    }
                };
                let (step3_frame, pairing_secret) =
                    match initiator.process_step2_frame(&binary_frame) {
                        Ok(res) => res,
                        Err(_) => {
                            *state = PairingBridgeState::after_cpace_failure(
                                EndpointRole::Requester,
                                offer,
                                deadline,
                            );
                            return Err(RappBindingError::ProtocolFailure);
                        }
                    };
                *state = PairingBridgeState::Cpace(Box::new(CpaceBridgeState::RequesterStep3 {
                    step3_frame,
                    pairing_secret,
                    offer,
                    candidate_id,
                    local_keys,
                    deadline,
                }));
                Ok(())
            }
            CpaceBridgeState::RequesterStep3 {
                offer, deadline, ..
            } => {
                *state = PairingBridgeState::after_cpace_failure(
                    EndpointRole::Requester,
                    offer,
                    deadline,
                );
                Err(RappBindingError::WrongPhase)
            }
        }
    }

    /// Discard one unauthenticated transport candidate. A requester retains
    /// the same still-live offer and absolute deadline; a proxy discards its
    /// scanned copy. Returns whether the requester offer remains reusable.
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer or the wrong phase.
    pub fn candidate_failed(&self, now_monotonic_ms: u64) -> Result<bool, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let (role, offer, deadline) = match previous {
            PairingBridgeState::Handshake { .. } => {
                // CPace consumed the offer; a lost candidate after handoff
                // destroys candidate trust (§3.3.6).
                drop(state);
                return Ok(false);
            }
            PairingBridgeState::Cpace(cpace) if cpace.role() == EndpointRole::Proxy => {
                let deadline = cpace.deadline();
                let (next, _) =
                    self.custodian_attempt_failed(cpace.into_offer(), deadline, now_monotonic_ms)?;
                let retained = matches!(next, PairingBridgeState::Offer { .. });
                *state = next;
                drop(state);
                return Ok(retained);
            }
            PairingBridgeState::Cpace(cpace) => {
                let role = cpace.role();
                let deadline = cpace.deadline();
                (role, cpace.into_offer(), deadline)
            }
            _ => {
                *state = previous;
                return Err(RappBindingError::WrongPhase);
            }
        };
        let retained = role == EndpointRole::Requester;
        *state = if role == EndpointRole::Requester {
            PairingBridgeState::Offer {
                role,
                offer,
                deadline,
            }
        } else {
            PairingBridgeState::Failed
        };
        drop(state);
        Ok(retained)
    }

    /// Cancel pairing and destroy every in-progress offer or handshake secret.
    /// Cancelled in the storage phase, the record the caller stored is not
    /// active; the caller revokes it.
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] after the pairing completed.
    #[allow(
        clippy::match_same_arms,
        reason = "phases whose secrets are destroyed and already-inert phases are distinct classifications that both cancel cleanly"
    )]
    pub fn cancel_pairing(&self) -> Result<(), RappBindingError> {
        let mut state = self.lock()?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        match previous {
            PairingBridgeState::Offer { .. }
            | PairingBridgeState::Cpace(_)
            | PairingBridgeState::Handshake { .. }
            | PairingBridgeState::Confirmation { .. }
            | PairingBridgeState::Storage { .. } => Ok(()),
            PairingBridgeState::Expired
            | PairingBridgeState::Exhausted
            | PairingBridgeState::Failed => Ok(()),
            PairingBridgeState::Completed => {
                *state = PairingBridgeState::Completed;
                drop(state);
                Err(RappBindingError::WrongPhase)
            }
        }
    }

    /// Produce the next role-specific Noise handshake frame.
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer, the wrong phase, or a
    /// failed handshake.
    pub fn write_handshake_frame(
        &self,
        now_monotonic_ms: u64,
    ) -> Result<Vec<u8>, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Handshake {
            mut handshake,
            deadline_ms,
        } = previous
        else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        if let Ok(frame) = handshake.write_message() {
            *state = PairingBridgeState::Handshake {
                handshake,
                deadline_ms,
            };
            Ok(frame.into_bytes())
        } else {
            drop(state);
            Err(RappBindingError::ProtocolFailure)
        }
    }

    /// Consume the next role-specific Noise handshake frame.
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer, the wrong phase, an
    /// oversized frame, or a failed handshake.
    pub fn read_handshake_frame(
        &self,
        bytes: Vec<u8>,
        now_monotonic_ms: u64,
    ) -> Result<(), RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Handshake {
            mut handshake,
            deadline_ms,
        } = previous
        else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        let Ok(frame) = BinaryFrame::reconstruct(bytes) else {
            return Err(RappBindingError::InvalidInput);
        };
        if matches!(handshake.read_message(&frame), Ok(())) {
            *state = PairingBridgeState::Handshake {
                handshake,
                deadline_ms,
            };
            Ok(())
        } else {
            drop(state);
            Err(RappBindingError::ProtocolFailure)
        }
    }

    /// Whether the role-specific three-message Noise exchange has completed.
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer or the wrong phase.
    pub fn handshake_complete(&self, now_monotonic_ms: u64) -> Result<bool, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let PairingBridgeState::Handshake { handshake, .. } = &*state else {
            return Err(RappBindingError::WrongPhase);
        };
        let complete = handshake.is_complete();
        drop(state);
        Ok(complete)
    }

    /// Enter authenticated confirmation after Noise completes; hello,
    /// confirmation, storage and the peer's storage confirmation must
    /// follow within 10 seconds of `now_monotonic_ms` (§3.3.7).
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer, the wrong phase, or an
    /// incomplete handshake.
    pub fn enter_confirmation(&self, now_monotonic_ms: u64) -> Result<(), RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Handshake { handshake, .. } = previous else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        match (*handshake).into_confirmation() {
            Ok(confirmation) => {
                *state = PairingBridgeState::Confirmation {
                    confirmation: Box::new(confirmation),
                    deadline_ms: phase_deadline_ms(now_monotonic_ms, POST_PAKE_CONFIRMATION_MS),
                };
                Ok(())
            }
            Err(_) => Err(RappBindingError::ProtocolFailure),
        }
    }

    /// Send the authenticated peer label and exact negotiated-parameter echo.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase or a duplicate or failed
    /// hello.
    pub fn send_hello(
        &self,
        display_name: String,
        platform: String,
        now_monotonic_ms: u64,
    ) -> Result<Vec<u8>, RappBindingError> {
        self.with_confirmation(now_monotonic_ms, |confirmation| {
            confirmation
                .send_hello(display_name, platform)
                .map(BinaryFrame::into_bytes)
        })
    }

    /// Verify the peer's authenticated label and exact parameter echo.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, an oversized frame, or a
    /// hello that fails verification.
    pub fn receive_hello(
        &self,
        bytes: Vec<u8>,
        now_monotonic_ms: u64,
    ) -> Result<RappPeerHello, RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        self.with_confirmation(now_monotonic_ms, |confirmation| {
            confirmation
                .receive_hello(&frame, now_monotonic_ms)
                .map(|hello| RappPeerHello {
                    display_name: hello.display_name.clone(),
                    platform: hello.platform.clone(),
                    requested_profiles: hello.requested_profiles.as_ref().map(|profiles| {
                        profiles
                            .iter()
                            .map(|profile| profile.as_str().to_owned())
                            .collect()
                    }),
                })
        })
    }

    /// Send the exact locally approved grant set.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, an invalid grant set, or a
    /// grant mismatch.
    pub fn send_confirmation(
        &self,
        granted_profiles: Vec<String>,
        now_monotonic_ms: u64,
    ) -> Result<Vec<u8>, RappBindingError> {
        let granted_profiles = parse_profiles(granted_profiles)?;
        self.with_confirmation(now_monotonic_ms, |confirmation| {
            confirmation
                .send_confirmation(granted_profiles)
                .map(BinaryFrame::into_bytes)
        })
    }

    /// Verify and return the peer's exact grant set.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, an oversized frame, or a
    /// confirmation that fails verification.
    pub fn receive_confirmation(
        &self,
        bytes: Vec<u8>,
        now_monotonic_ms: u64,
    ) -> Result<Vec<String>, RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        self.with_confirmation(now_monotonic_ms, |confirmation| {
            confirmation
                .receive_confirmation(&frame, now_monotonic_ms)
                .map(|profiles| {
                    profiles
                        .iter()
                        .map(|profile| profile.as_str().to_owned())
                        .collect()
                })
        })
    }

    /// Build the pair record after equal confirmation and keep the pairing
    /// channel open for the storage confirmation (§4.3 item 4). The record
    /// is unconfirmed: the caller persists it with
    /// [`RappPairRecord::persist_device_only`], then calls
    /// [`Self::send_stored`] and feeds the peer's frame to
    /// [`Self::receive_stored`]; once [`Self::activate_pairing`] returns
    /// the record, the caller stores it again with
    /// [`RappPairRecord::replace_device_only`], and only that stored form
    /// opens sessions. No private key bytes are returned to the platform.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, the passed deadline, or
    /// incomplete or unequal confirmations.
    pub fn build_pair_record(
        &self,
        created_at_ms: u64,
        now_monotonic_ms: u64,
    ) -> Result<Arc<RappPairRecord>, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Confirmation {
            confirmation,
            deadline_ms,
        } = previous
        else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        let (record, storage) = (*confirmation)
            .into_storage(created_at_ms)
            .map_err(|_| RappBindingError::ProtocolFailure)?;
        let record = Arc::new(RappPairRecord {
            record: Mutex::new(Some(record)),
        });
        *state = PairingBridgeState::Storage {
            storage: Box::new(storage),
            record: Arc::clone(&record),
            deadline_ms,
        };
        drop(state);
        Ok(record)
    }

    /// Confirm to the peer that the record is durably stored: the frame to
    /// send once the vault reported the record written (§4.3 item 4).
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, the passed deadline, or a
    /// second confirmation.
    pub fn send_stored(&self, now_monotonic_ms: u64) -> Result<Vec<u8>, RappBindingError> {
        self.with_storage(now_monotonic_ms, |storage| {
            storage.send_stored().map(BinaryFrame::into_bytes)
        })
    }

    /// Verify the peer's storage confirmation. A confirmation naming another
    /// pairing is an authenticated protocol violation: the ceremony fails,
    /// and the caller revokes the record it stored.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, the passed deadline, an
    /// oversized frame, or a confirmation that fails verification.
    pub fn receive_stored(
        &self,
        bytes: Vec<u8>,
        now_monotonic_ms: u64,
    ) -> Result<(), RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        self.with_storage(now_monotonic_ms, |storage| {
            storage.receive_stored(&frame, now_monotonic_ms)
        })
    }

    /// The record in its confirmed form once both storage confirmations
    /// have been exchanged, or `None` while the peer's is still awaited.
    /// Returning the record closes the pairing channel and completes the
    /// ceremony; the caller stores the returned record with
    /// [`RappPairRecord::replace_device_only`], and the pairing is active
    /// from that write on. A `None` past the deadline is
    /// [`RappBindingError::StorageUnconfirmed`].
    ///
    /// # Errors
    /// [`RappBindingError`] outside the storage phase or past the deadline.
    pub fn activate_pairing(
        &self,
        now_monotonic_ms: u64,
    ) -> Result<Option<Arc<RappPairRecord>>, RappBindingError> {
        let mut state = self.lock()?;
        let confirmed = match &*state {
            PairingBridgeState::Storage { storage, .. } => storage.is_confirmed(),
            _ => return Err(RappBindingError::WrongPhase),
        };
        if !confirmed {
            state.require_live_offer(now_monotonic_ms)?;
            return Ok(None);
        }
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Completed);
        drop(state);
        let PairingBridgeState::Storage {
            storage, record, ..
        } = previous
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let active = storage
            .into_active()
            .map_err(|_| RappBindingError::ProtocolFailure)?;
        let mut guard = record
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let unconfirmed = guard.take().ok_or(RappBindingError::WrongPhase)?;
        let confirmed = active
            .confirm(unconfirmed)
            .map_err(|_| RappBindingError::ProtocolFailure)?;
        *guard = Some(confirmed);
        drop(guard);
        Ok(Some(record))
    }
}

impl RappPairingBridge {
    fn lock(&self) -> Result<MutexGuard<'_, PairingBridgeState>, RappBindingError> {
        self.state
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)
    }

    /// Run one confirmation step before the post-PAKE deadline; a failed
    /// step destroys candidate trust (§3.3.7).
    fn with_confirmation<T>(
        &self,
        now_monotonic_ms: u64,
        step: impl FnOnce(&mut PairingConfirmation) -> Result<T, PairingError>,
    ) -> Result<T, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let PairingBridgeState::Confirmation { confirmation, .. } = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let outcome = step(confirmation);
        if outcome.is_err() {
            *state = PairingBridgeState::Failed;
        }
        drop(state);
        outcome.map_err(|_| RappBindingError::ProtocolFailure)
    }

    /// Run one storage-confirmation step before the deadline; a failed step
    /// ends the ceremony, and the caller revokes the record it stored.
    fn with_storage<T>(
        &self,
        now_monotonic_ms: u64,
        step: impl FnOnce(&mut PairingStorage) -> Result<T, PairingError>,
    ) -> Result<T, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let PairingBridgeState::Storage { storage, .. } = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let outcome = step(storage);
        if outcome.is_err() {
            *state = PairingBridgeState::Failed;
        }
        drop(state);
        outcome.map_err(|_| RappBindingError::ProtocolFailure)
    }

    fn lock_attempts(&self) -> Result<MutexGuard<'_, CpaceAttemptLedger>, RappBindingError> {
        self.attempts
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)
    }

    /// Spend the custodian's active attempt (§3.3.5) and decide what the
    /// offer becomes: kept while attempts and lifetime remain, otherwise
    /// destroyed, with [`RappBindingError::AttemptsExhausted`] after the
    /// third failure.
    fn custodian_attempt_failed(
        &self,
        offer: PairingOffer,
        deadline: PairingOfferDeadline,
        now_monotonic_ms: u64,
    ) -> Result<(PairingBridgeState, RappBindingError), RappBindingError> {
        let mut ledger = self.lock_attempts()?;
        ledger.fail_active_attempt();
        if ledger.is_exhausted() {
            return Ok((
                PairingBridgeState::Exhausted,
                RappBindingError::AttemptsExhausted,
            ));
        }
        if ledger.accepts_another_attempt() && deadline.is_live(now_monotonic_ms) {
            return Ok((
                PairingBridgeState::Offer {
                    role: EndpointRole::Proxy,
                    offer,
                    deadline,
                },
                RappBindingError::ProtocolFailure,
            ));
        }
        Ok((
            PairingBridgeState::Failed,
            RappBindingError::ProtocolFailure,
        ))
    }

    fn with_offer(
        role: EndpointRole,
        offer: PairingOffer,
        started_at_monotonic_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        let deadline = PairingOfferDeadline::from_offer(&offer, started_at_monotonic_ms)
            .map_err(|_| RappBindingError::InvalidInput)?;
        Ok(Arc::new(Self {
            state: Mutex::new(PairingBridgeState::Offer {
                role,
                offer,
                deadline,
            }),
            attempts: Mutex::new(CpaceAttemptLedger::default()),
            pre_authentication: Mutex::new(PreAuthenticationRateLimit::default()),
        }))
    }
}

/// The CPace context of `offer` for the connection whose offer entry has
/// `candidate_id` (RAPP v26.10.22 §6.1.1).
fn pairing_context(
    offer: &PairingOffer,
    offer_hash: &[u8; 32],
    candidate_id: &str,
) -> Result<Vec<u8>, RappBindingError> {
    let mut entries = offer
        .transports
        .iter()
        .filter(|candidate| candidate.candidate_id == candidate_id);
    let (Some(entry), None) = (entries.next(), entries.next()) else {
        return Err(RappBindingError::InvalidInput);
    };
    standard_pairing_context_v2(offer_hash, &entry.profile, &entry.candidate_id)
        .map_err(|_| RappBindingError::ProtocolFailure)
}

#[cfg(test)]
mod pairing_bridge_tests {
    use super::*;
    use crate::{
        BLE_CANDIDATE_ID, CPACE_ATTEMPT_WINDOW_MS, PRE_AUTHENTICATION_SPACING_MS,
        STREAM_CANDIDATE_ID,
    };

    const STARTED_AT_MS: u64 = 1_000;
    const PAIRING_CODE: &str = "7KX4M9";
    const WRONG_CODE: &str = "7KX4M8";
    /// Spacing between attempts, beyond the §3.3.8 rate limit.
    const NEXT_ATTEMPT_MS: u64 = 1_000;

    fn custodian(transports: &[TransportProfile]) -> Arc<RappPairingBridge> {
        let counts = rapp_random_byte_counts();
        RappPairingBridge::create_custodian_offer(
            vec![0x11; usize::try_from(counts.offer_id).expect("offer id size fits usize")],
            vec![ProfileName::Authentication.as_str().to_owned()],
            transports
                .iter()
                .map(|profile| profile.name().to_owned())
                .collect(),
            STARTED_AT_MS,
        )
        .expect("custodian offer is valid")
    }

    fn requester(
        custodian: &RappPairingBridge,
        transport: TransportProfile,
        at: u64,
    ) -> Arc<RappPairingBridge> {
        RappPairingBridge::from_bootstrap(
            custodian
                .bootstrap_bytes(at)
                .expect("custodian serves its offer"),
            transport.name().to_owned(),
            at,
        )
        .expect("requester accepts the bootstrap")
    }

    struct Attempt<'a> {
        requester_candidate: &'a str,
        requester_code: &'a str,
        custodian_candidate: &'a str,
        at: u64,
    }

    impl Attempt<'_> {
        const fn honest(at: u64) -> Self {
            Attempt {
                requester_candidate: STREAM_CANDIDATE_ID,
                requester_code: PAIRING_CODE,
                custodian_candidate: STREAM_CANDIDATE_ID,
                at,
            }
        }

        const fn wrong_code(at: u64) -> Self {
            Attempt {
                requester_code: WRONG_CODE,
                ..Self::honest(at)
            }
        }
    }

    fn begin_both(requester: &RappPairingBridge, custodian: &RappPairingBridge, attempt: &Attempt) {
        requester
            .begin_cpace(
                attempt.requester_candidate.into(),
                attempt.requester_code.into(),
                vec![0x33; 64],
                attempt.at + 1,
            )
            .expect("requester begins cpace");
        custodian
            .begin_cpace(
                attempt.custodian_candidate.into(),
                PAIRING_CODE.into(),
                vec![0x44; 64],
                attempt.at + 1,
            )
            .expect("custodian begins cpace");
    }

    /// Runs CPace steps 1 and 2 and returns the requester's verdict on T_B.
    fn exchange_through_step2(
        requester: &RappPairingBridge,
        custodian: &RappPairingBridge,
        at: u64,
    ) -> Result<(), RappBindingError> {
        let step1 = requester
            .write_cpace_frame(at + 2)
            .expect("requester writes step 1");
        custodian
            .read_cpace_frame(step1, at + 2)
            .expect("custodian reads step 1");
        let step2 = custodian
            .write_cpace_frame(at + 3)
            .expect("custodian writes step 2");
        requester.read_cpace_frame(step2, at + 3)
    }

    /// Runs one attempt over the stream transport through T_B.
    fn attempt_through_step2(
        custodian: &RappPairingBridge,
        attempt: &Attempt,
    ) -> (Arc<RappPairingBridge>, Result<(), RappBindingError>) {
        let requester = requester(custodian, TransportProfile::Stream, attempt.at);
        begin_both(&requester, custodian, attempt);
        let verdict = exchange_through_step2(&requester, custodian, attempt.at);
        (requester, verdict)
    }

    /// Completes CPace and Noise from `at`; returns when both entered
    /// confirmation at `at + 9`.
    fn pair_into_confirmation(at: u64) -> (Arc<RappPairingBridge>, Arc<RappPairingBridge>) {
        let custodian = custodian(&[TransportProfile::Ble, TransportProfile::Stream]);
        let (requester, verdict) = attempt_through_step2(&custodian, &Attempt::honest(at));
        verdict.expect("T_B verifies");
        let step3 = requester
            .write_cpace_frame(at + 4)
            .expect("requester writes step 3 and enters Noise");
        assert_eq!(step3.len(), 32);
        custodian
            .read_cpace_frame(step3, at + 4)
            .expect("custodian verifies T_A and enters Noise");
        let msg1 = requester
            .write_handshake_frame(at + 5)
            .expect("requester emits Noise message 1");
        custodian
            .read_handshake_frame(msg1, at + 5)
            .expect("custodian accepts Noise message 1");
        let msg2 = custodian
            .write_handshake_frame(at + 6)
            .expect("custodian emits Noise message 2");
        requester
            .read_handshake_frame(msg2, at + 6)
            .expect("requester accepts Noise message 2");
        let msg3 = requester
            .write_handshake_frame(at + 7)
            .expect("requester emits Noise message 3");
        custodian
            .read_handshake_frame(msg3, at + 7)
            .expect("custodian accepts Noise message 3");
        requester
            .enter_confirmation(at + 9)
            .expect("requester enters confirmation");
        custodian
            .enter_confirmation(at + 9)
            .expect("custodian enters confirmation");
        (requester, custodian)
    }

    #[test]
    fn requester_refuses_a_bootstrap_over_an_unlisted_transport() {
        let custodian = custodian(&[TransportProfile::Ble]);
        let bytes = custodian
            .bootstrap_bytes(STARTED_AT_MS)
            .expect("custodian serves its offer");
        assert!(matches!(
            RappPairingBridge::from_bootstrap(
                bytes,
                TransportProfile::Stream.name().to_owned(),
                STARTED_AT_MS
            ),
            Err(RappBindingError::InvalidInput)
        ));
    }

    #[test]
    fn only_the_custodian_serves_bootstrap_bytes() {
        let custodian = custodian(&[TransportProfile::Stream]);
        let requester = requester(&custodian, TransportProfile::Stream, STARTED_AT_MS);
        assert!(matches!(
            requester.bootstrap_bytes(STARTED_AT_MS),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn the_offer_expires_after_its_lifetime() {
        let custodian = custodian(&[TransportProfile::Stream]);
        assert!(matches!(
            custodian.bootstrap_bytes(STARTED_AT_MS + crate::OFFER_TTL_MS),
            Err(RappBindingError::OfferExpired)
        ));
    }

    #[test]
    fn cancellation_consumes_offer() {
        let custodian = custodian(&[TransportProfile::Stream]);
        custodian
            .cancel_pairing()
            .expect("active offer can be cancelled");
        assert!(matches!(
            custodian.bootstrap_bytes(STARTED_AT_MS + 1),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn cpace_kc2_bridge_3step_exchange_to_pair_records() {
        let at = STARTED_AT_MS;
        let (requester, custodian) = pair_into_confirmation(at);
        let requester_hello = requester
            .send_hello("desktop".into(), "macos".into(), at + 10)
            .expect("requester sends hello");
        let custodian_hello = custodian
            .send_hello("phone".into(), "ios".into(), at + 10)
            .expect("custodian sends hello");
        custodian
            .receive_hello(requester_hello, at + 10)
            .expect("custodian receives hello");
        requester
            .receive_hello(custodian_hello, at + 10)
            .expect("requester receives hello");
        let grants = vec![ProfileName::Authentication.as_str().to_owned()];
        let requester_confirmation = requester
            .send_confirmation(grants.clone(), at + 11)
            .expect("requester sends confirmation");
        let custodian_confirmation = custodian
            .send_confirmation(grants, at + 11)
            .expect("custodian sends confirmation");
        custodian
            .receive_confirmation(requester_confirmation, at + 11)
            .expect("custodian receives confirmation");
        requester
            .receive_confirmation(custodian_confirmation, at + 11)
            .expect("requester receives confirmation");

        let requester_record = requester
            .build_pair_record(at + 12, at + 12)
            .expect("requester builds its record");
        let custodian_record = custodian
            .build_pair_record(at + 12, at + 12)
            .expect("custodian builds its record");
        let requester_metadata = requester_record.metadata().expect("requester metadata");
        let custodian_metadata = custodian_record.metadata().expect("custodian metadata");
        assert_eq!(requester_metadata.pair_id, custodian_metadata.pair_id);
        assert!(!requester_metadata.storage_confirmed);
        assert!(!custodian_metadata.storage_confirmed);
        assert!(
            requester
                .activate_pairing(at + 12)
                .expect("storage phase")
                .is_none()
        );

        let requester_stored = requester
            .send_stored(at + 13)
            .expect("requester confirms storage");
        let custodian_stored = custodian
            .send_stored(at + 13)
            .expect("custodian confirms storage");
        custodian
            .receive_stored(requester_stored, at + 13)
            .expect("custodian verifies the requester's confirmation");
        requester
            .receive_stored(custodian_stored, at + 13)
            .expect("requester verifies the custodian's confirmation");
        let requester_active = requester
            .activate_pairing(at + 14)
            .expect("exchange done")
            .expect("the confirmed record is returned");
        assert!(Arc::ptr_eq(&requester_active, &requester_record));
        assert!(
            requester_active
                .metadata()
                .expect("metadata")
                .storage_confirmed
        );
        assert!(
            custodian
                .activate_pairing(at + 14)
                .expect("exchange done")
                .expect("the custodian's record is returned")
                .metadata()
                .expect("metadata")
                .storage_confirmed
        );
        assert!(matches!(
            requester.activate_pairing(at + 14),
            Err(RappBindingError::WrongPhase)
        ));
        assert!(matches!(
            requester.send_stored(at + 14),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn a_pairing_the_peer_never_confirms_is_not_active() {
        let at = STARTED_AT_MS;
        let (requester, custodian) = pair_into_confirmation(at);
        let requester_hello = requester
            .send_hello("desktop".into(), "macos".into(), at + 10)
            .expect("requester sends hello");
        let custodian_hello = custodian
            .send_hello("phone".into(), "ios".into(), at + 10)
            .expect("custodian sends hello");
        custodian
            .receive_hello(requester_hello, at + 10)
            .expect("custodian receives hello");
        requester
            .receive_hello(custodian_hello, at + 10)
            .expect("requester receives hello");
        let grants = vec![ProfileName::Authentication.as_str().to_owned()];
        let requester_confirmation = requester
            .send_confirmation(grants.clone(), at + 11)
            .expect("requester sends confirmation");
        let custodian_confirmation = custodian
            .send_confirmation(grants, at + 11)
            .expect("custodian sends confirmation");
        custodian
            .receive_confirmation(requester_confirmation, at + 11)
            .expect("custodian receives confirmation");
        requester
            .receive_confirmation(custodian_confirmation, at + 11)
            .expect("requester receives confirmation");
        requester
            .build_pair_record(at + 12, at + 12)
            .expect("requester builds its record");
        requester
            .send_stored(at + 13)
            .expect("requester confirms storage");
        assert!(
            requester
                .activate_pairing(at + 14)
                .expect("still waiting")
                .is_none()
        );
        assert!(matches!(
            requester.activate_pairing(at + 9 + POST_PAKE_CONFIRMATION_MS),
            Err(RappBindingError::StorageUnconfirmed)
        ));
        assert!(matches!(
            requester.activate_pairing(at + 9 + POST_PAKE_CONFIRMATION_MS + 1),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn the_handshake_deadline_replaces_the_offer_lifetime() {
        let custodian = custodian(&[TransportProfile::Stream]);
        let at = STARTED_AT_MS + crate::OFFER_TTL_MS - 10;
        let (requester, verdict) = attempt_through_step2(&custodian, &Attempt::honest(at));
        verdict.expect("T_B verifies inside the offer lifetime");
        let step3 = requester
            .write_cpace_frame(at + 4)
            .expect("requester hands off to Noise");
        custodian
            .read_cpace_frame(step3, at + 4)
            .expect("custodian hands off to Noise");
        // Past the offer lifetime, inside the 10 s handshake deadline.
        let msg1 = requester
            .write_handshake_frame(at + 1_000)
            .expect("the ceremony survives the offer lifetime");
        custodian
            .read_handshake_frame(msg1, at + 1_000)
            .expect("custodian reads message 1");
        assert!(matches!(
            custodian.write_handshake_frame(at + 4 + POST_PAKE_HANDSHAKE_MS),
            Err(RappBindingError::OfferExpired)
        ));
        assert!(matches!(
            custodian.write_handshake_frame(at + 4),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn the_confirmation_deadline_destroys_candidate_trust() {
        let at = STARTED_AT_MS;
        let (requester, _custodian) = pair_into_confirmation(at);
        requester
            .send_hello("desktop".into(), "macos".into(), at + 9 + 1)
            .expect("hello inside the deadline");
        assert!(matches!(
            requester.send_confirmation(
                vec![ProfileName::Authentication.as_str().to_owned()],
                at + 9 + POST_PAKE_CONFIRMATION_MS
            ),
            Err(RappBindingError::OfferExpired)
        ));
        assert!(matches!(
            requester.build_pair_record(at, at + 10),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn a_failed_confirmation_step_destroys_candidate_trust() {
        let at = STARTED_AT_MS;
        let (requester, _custodian) = pair_into_confirmation(at);
        assert!(matches!(
            requester.receive_hello(vec![0x00; 16], at + 10),
            Err(RappBindingError::ProtocolFailure)
        ));
        assert!(matches!(
            requester.send_hello("desktop".into(), "macos".into(), at + 11),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn cpace_kc2_bridge_wrong_code_fails_tag_b() {
        let custodian = custodian(&[TransportProfile::Stream]);
        let (_, verdict) = attempt_through_step2(&custodian, &Attempt::wrong_code(STARTED_AT_MS));
        assert!(matches!(verdict, Err(RappBindingError::ProtocolFailure)));
    }

    #[test]
    fn cpace_binds_the_transport_of_the_connection() {
        let custodian = custodian(&[TransportProfile::Ble, TransportProfile::Stream]);
        let (_, verdict) = attempt_through_step2(
            &custodian,
            &Attempt {
                custodian_candidate: BLE_CANDIDATE_ID,
                ..Attempt::honest(STARTED_AT_MS)
            },
        );
        assert!(matches!(verdict, Err(RappBindingError::ProtocolFailure)));
    }

    #[test]
    fn three_wrong_codes_exhaust_the_custodian_offer() {
        let custodian = custodian(&[TransportProfile::Stream]);
        for attempt in 0..3 {
            let at = STARTED_AT_MS + attempt * NEXT_ATTEMPT_MS;
            let (_, verdict) = attempt_through_step2(&custodian, &Attempt::wrong_code(at));
            assert!(matches!(verdict, Err(RappBindingError::ProtocolFailure)));
            // The requester hangs up after T_B fails; the attempt is spent.
            let retained = custodian
                .candidate_failed(at + 4)
                .expect("custodian classifies the lost candidate");
            assert_eq!(retained, attempt < 2, "attempt {attempt}");
        }
        let later = STARTED_AT_MS + 3 * NEXT_ATTEMPT_MS;
        assert!(matches!(
            custodian.bootstrap_bytes(later),
            Err(RappBindingError::AttemptsExhausted)
        ));
        assert!(matches!(
            custodian.begin_cpace(
                STREAM_CANDIDATE_ID.into(),
                PAIRING_CODE.into(),
                vec![0x44; 64],
                later
            ),
            Err(RappBindingError::AttemptsExhausted)
        ));
    }

    #[test]
    fn a_correct_code_on_the_second_attempt_succeeds() {
        let custodian = custodian(&[TransportProfile::Stream]);
        let (_, verdict) = attempt_through_step2(&custodian, &Attempt::wrong_code(STARTED_AT_MS));
        assert!(verdict.is_err());
        assert!(
            custodian
                .candidate_failed(STARTED_AT_MS + 4)
                .expect("custodian keeps the offer")
        );
        let at = STARTED_AT_MS + NEXT_ATTEMPT_MS;
        let (right, verdict) = attempt_through_step2(&custodian, &Attempt::honest(at));
        verdict.expect("T_B verifies");
        let step3 = right
            .write_cpace_frame(at + 4)
            .expect("requester writes step 3");
        custodian
            .read_cpace_frame(step3, at + 4)
            .expect("the second attempt consumes the offer");
        assert!(matches!(
            custodian.bootstrap_bytes(at + 5),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn a_wrong_t_a_on_the_third_attempt_reports_exhaustion() {
        let custodian = custodian(&[TransportProfile::Stream]);
        for attempt in 0..2 {
            let at = STARTED_AT_MS + attempt * NEXT_ATTEMPT_MS;
            let (_, verdict) = attempt_through_step2(&custodian, &Attempt::wrong_code(at));
            assert!(verdict.is_err());
            assert!(custodian.candidate_failed(at + 4).expect("offer kept"));
        }
        let at = STARTED_AT_MS + 2 * NEXT_ATTEMPT_MS;
        let (requester, verdict) = attempt_through_step2(&custodian, &Attempt::honest(at));
        verdict.expect("T_B verifies");
        let mut step3 = requester
            .write_cpace_frame(at + 4)
            .expect("requester writes step 3");
        if let Some(byte) = step3.last_mut() {
            *byte ^= 0x01;
        }
        assert!(matches!(
            custodian.read_cpace_frame(step3, at + 4),
            Err(RappBindingError::AttemptsExhausted)
        ));
    }

    #[test]
    fn an_attempt_past_its_window_is_spent() {
        let custodian = custodian(&[TransportProfile::Stream]);
        let at = STARTED_AT_MS;
        let (requester, verdict) = attempt_through_step2(&custodian, &Attempt::honest(at));
        verdict.expect("T_B verifies");
        let step3 = requester
            .write_cpace_frame(at + 4)
            .expect("requester writes step 3");
        assert!(matches!(
            custodian.read_cpace_frame(step3, at + 2 + CPACE_ATTEMPT_WINDOW_MS),
            Err(RappBindingError::ProtocolFailure)
        ));
        assert!(custodian.bootstrap_bytes(at + 10_000).is_ok());
    }

    #[test]
    fn cpace_starts_inside_500_ms_are_rate_limited() {
        let custodian = custodian(&[TransportProfile::Stream]);
        let (_, verdict) = attempt_through_step2(&custodian, &Attempt::wrong_code(STARTED_AT_MS));
        assert!(verdict.is_err());
        assert!(
            custodian
                .candidate_failed(STARTED_AT_MS + 4)
                .expect("offer kept")
        );
        assert!(matches!(
            custodian.begin_cpace(
                STREAM_CANDIDATE_ID.into(),
                PAIRING_CODE.into(),
                vec![0x44; 64],
                STARTED_AT_MS + 1 + PRE_AUTHENTICATION_SPACING_MS - 1
            ),
            Err(RappBindingError::RateLimited)
        ));
        custodian
            .begin_cpace(
                STREAM_CANDIDATE_ID.into(),
                PAIRING_CODE.into(),
                vec![0x44; 64],
                STARTED_AT_MS + 1 + PRE_AUTHENTICATION_SPACING_MS,
            )
            .expect("the limit lets the next attempt through");
    }

    #[test]
    fn the_platform_limiter_spaces_accepted_connections() {
        let limiter = RappPreAuthenticationLimiter::new();
        assert!(limiter.admit(0).expect("lock"));
        assert!(
            !limiter
                .admit(PRE_AUTHENTICATION_SPACING_MS - 1)
                .expect("lock")
        );
        assert!(limiter.admit(PRE_AUTHENTICATION_SPACING_MS).expect("lock"));
    }

    #[test]
    fn cpace_kc2_bridge_corrupted_step3_fails_custodian() {
        let custodian = custodian(&[TransportProfile::Stream]);
        let (requester, verdict) =
            attempt_through_step2(&custodian, &Attempt::honest(STARTED_AT_MS));
        verdict.expect("T_B verifies");
        let mut step3 = requester
            .write_cpace_frame(STARTED_AT_MS + 4)
            .expect("requester writes step 3");
        if let Some(byte) = step3.last_mut() {
            *byte ^= 0x01;
        }
        assert!(matches!(
            custodian.read_cpace_frame(step3, STARTED_AT_MS + 4),
            Err(RappBindingError::ProtocolFailure)
        ));
    }

    /// A second phone in pairing mode, showing a code of its own.
    fn other_custodian() -> Arc<RappPairingBridge> {
        let counts = rapp_random_byte_counts();
        RappPairingBridge::create_custodian_offer(
            vec![0x12; usize::try_from(counts.offer_id).expect("offer id size fits usize")],
            vec![ProfileName::Authentication.as_str().to_owned()],
            vec![TransportProfile::Stream.name().to_owned()],
            STARTED_AT_MS,
        )
        .expect("custodian offer is valid")
    }

    /// Runs CPace through T_B with the code the user typed against the code
    /// the custodian shows.
    fn try_code(
        requester: &RappPairingBridge,
        custodian: &RappPairingBridge,
        shown: &str,
        at: u64,
    ) -> Result<(), RappBindingError> {
        requester
            .begin_cpace(
                STREAM_CANDIDATE_ID.into(),
                PAIRING_CODE.into(),
                vec![0x33; 64],
                at + 1,
            )
            .expect("requester begins cpace");
        custodian
            .begin_cpace(
                STREAM_CANDIDATE_ID.into(),
                shown.into(),
                vec![0x44; 64],
                at + 1,
            )
            .expect("custodian begins cpace");
        exchange_through_step2(requester, custodian, at)
    }

    #[test]
    fn a_requester_tries_the_next_phone_before_refusing_the_code() {
        let other = other_custodian();
        let this = custodian(&[TransportProfile::Stream]);
        let candidates = RappPairingCandidates::new();
        candidates.found("other".into()).expect("lock");
        candidates.found("this".into()).expect("lock");

        assert_eq!(
            candidates.next_endpoint().expect("none open").as_deref(),
            Some("other")
        );
        let first = requester(&other, TransportProfile::Stream, STARTED_AT_MS);
        assert!(candidates.begin_try(Arc::clone(&first)).expect("offer"));
        assert!(try_code(&first, &other, WRONG_CODE, STARTED_AT_MS).is_err());
        assert_eq!(candidates.closed().expect("open"), RappNextCandidate::Try);

        let at = STARTED_AT_MS + NEXT_ATTEMPT_MS;
        assert_eq!(
            candidates.next_endpoint().expect("none open").as_deref(),
            Some("this")
        );
        let second = requester(&this, TransportProfile::Stream, at);
        assert!(candidates.begin_try(Arc::clone(&second)).expect("offer"));
        try_code(&second, &this, PAIRING_CODE, at).expect("T_B verifies");
        candidates.accepted().expect("a try runs");
        assert!(matches!(
            candidates.next_endpoint(),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn a_phone_found_twice_receives_one_guess() {
        let phone = custodian(&[TransportProfile::Ble, TransportProfile::Stream]);
        let candidates = RappPairingCandidates::new();
        candidates.found("stream".into()).expect("lock");
        candidates.found("ble".into()).expect("lock");

        candidates.next_endpoint().expect("none open");
        let first = requester(&phone, TransportProfile::Stream, STARTED_AT_MS);
        assert!(candidates.begin_try(Arc::clone(&first)).expect("offer"));
        assert!(try_code(&first, &phone, WRONG_CODE, STARTED_AT_MS).is_err());
        assert!(
            phone
                .candidate_failed(STARTED_AT_MS + 4)
                .expect("the phone keeps its offer")
        );
        assert_eq!(candidates.closed().expect("open"), RappNextCandidate::Try);

        candidates.next_endpoint().expect("none open");
        let again = requester(
            &phone,
            TransportProfile::Ble,
            STARTED_AT_MS + NEXT_ATTEMPT_MS,
        );
        assert!(!candidates.begin_try(again).expect("offer"));
        assert_eq!(
            candidates.closed().expect("open"),
            RappNextCandidate::NotAccepted
        );
    }
}

/// The custodian's process-wide backoff after locked-out offers
/// (RAPP v26.10.22 §3.3.7), driven by platform monotonic milliseconds.
#[derive(Debug, Default, uniffi::Object)]
pub struct RappPairingBackoff {
    backoff: Mutex<PairingBackoff>,
}

#[uniffi::export]
impl RappPairingBackoff {
    /// A counter with no lockouts recorded.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record one offer locked out by three failed attempts.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] on a poisoned lock.
    pub fn record_lockout(&self, now_monotonic_ms: u64) -> Result<(), RappBindingError> {
        self.lock()?.record_lockout(now_monotonic_ms);
        Ok(())
    }

    /// Clear the count after a completed pairing.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] on a poisoned lock.
    pub fn record_success(&self) -> Result<(), RappBindingError> {
        self.lock()?.record_success();
        Ok(())
    }

    /// Milliseconds before a new offer may be created; zero when one may be
    /// created now.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] on a poisoned lock.
    pub fn ms_until_next_offer(&self, now_monotonic_ms: u64) -> Result<u64, RappBindingError> {
        Ok(self.lock()?.ms_until_next_offer(now_monotonic_ms))
    }
}

impl RappPairingBackoff {
    fn lock(&self) -> Result<MutexGuard<'_, PairingBackoff>, RappBindingError> {
        self.backoff
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)
    }
}

/// The §3.3.8 limit of one pre-authentication attempt per 500 ms for a
/// custodian's connection accepts. The platform calls [`Self::admit`] for
/// every accepted pairing or session connection before reading its routing
/// preamble, and closes the connection unanswered when it returns `false`.
/// The pairing bridge applies its own instance to CPace starts.
#[derive(Debug, Default, uniffi::Object)]
pub struct RappPreAuthenticationLimiter {
    limit: Mutex<PreAuthenticationRateLimit>,
}

#[uniffi::export]
impl RappPreAuthenticationLimiter {
    /// A limiter that has admitted nothing yet.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Admit one pre-authentication attempt at the platform's monotonic
    /// `now_monotonic_ms`, or refuse it inside the 500 ms spacing.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] on a poisoned lock.
    pub fn admit(&self, now_monotonic_ms: u64) -> Result<bool, RappBindingError> {
        Ok(self
            .limit
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .admit(now_monotonic_ms))
    }
}

/// What a requester does after a pairing connection closed without its
/// custodian taking the code (RAPP v26.10.22 §4.2, "Trying Each Custodian in
/// Pairing Mode").
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappNextCandidate {
    /// Open the next endpoint with [`RappPairingCandidates::next_endpoint`].
    Try,
    /// Every custodian tried refused the code: report it as not accepted,
    /// naming none of them.
    NotAccepted,
    /// No custodian has been tried and no endpoint is left to open: wait
    /// for discovery to find another, or report that none in pairing mode
    /// was found.
    NoneTried,
}

impl From<NextCandidate> for RappNextCandidate {
    fn from(next: NextCandidate) -> Self {
        match next {
            NextCandidate::Try => Self::Try,
            NextCandidate::NotAccepted => Self::NotAccepted,
            NextCandidate::NoneTried => Self::NoneTried,
        }
    }
}

/// The custodians in pairing mode a requester tries with one typed code
/// (RAPP v26.10.22 §4.2, "Trying Each Custodian in Pairing Mode"). The
/// platform creates one per submitted code, reports every endpoint
/// discovery finds in pairing mode by its own name for it (a service
/// instance, a peripheral identifier), opens the endpoints the ledger hands
/// out one at a time, and reports how each connection ended.
#[derive(Debug, Default, uniffi::Object)]
pub struct RappPairingCandidates {
    candidates: Mutex<PairingCandidates<String>>,
}

#[uniffi::export]
impl RappPairingCandidates {
    /// The ledger of a code the user has just submitted.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record an endpoint discovery found in pairing mode: a `mode=pairing`
    /// service instance, or a BLE peripheral of the RAPP service.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] on a poisoned lock.
    pub fn found(&self, endpoint: String) -> Result<(), RappBindingError> {
        self.lock()?.found(endpoint);
        Ok(())
    }

    /// The next endpoint to open a pairing connection to, or `None` when
    /// every endpoint found is opened.
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] while a pairing connection is open
    /// or once the code is accepted or refused.
    pub fn next_endpoint(&self) -> Result<Option<String>, RappBindingError> {
        let mut candidates = self.lock()?;
        let endpoint = candidates
            .next_endpoint()
            .map_err(|_| RappBindingError::WrongPhase)?
            .cloned();
        drop(candidates);
        Ok(endpoint)
    }

    /// Admit the offer `bridge` holds, read over the open connection, before
    /// CPace step 1. Returns `false` when CPace already ran on this offer
    /// with the code, the same custodian found on another transport: the
    /// caller closes the connection without CPace and calls [`Self::closed`].
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] when `bridge` is not a requester's
    /// offer awaiting CPace, or no connection awaits an offer.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn begin_try(&self, bridge: Arc<RappPairingBridge>) -> Result<bool, RappBindingError> {
        let state = bridge.lock()?;
        let PairingBridgeState::Offer {
            role: EndpointRole::Requester,
            offer,
            ..
        } = &*state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let admitted = self.lock()?.begin_try(offer);
        drop(state);
        match admitted {
            Ok(()) => Ok(true),
            Err(CandidateError::OfferAlreadyTried) => Ok(false),
            Err(_) => Err(RappBindingError::WrongPhase),
        }
    }

    /// The open connection closed without its custodian taking the code:
    /// refused or closed, no offer or one the requester rejects or already
    /// tried, no CPace step 2 within the attempt deadline, or a `T_B` that
    /// did not verify.
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] when no connection is open or the
    /// code is already accepted or refused.
    pub fn closed(&self) -> Result<RappNextCandidate, RappBindingError> {
        self.lock()?
            .closed()
            .map(RappNextCandidate::from)
            .map_err(|_| RappBindingError::WrongPhase)
    }

    /// The custodian tried proved it holds the code: its `T_B` verified.
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] when no CPace runs.
    pub fn accepted(&self) -> Result<(), RappBindingError> {
        self.lock()?
            .accepted()
            .map_err(|_| RappBindingError::WrongPhase)
    }
}

impl RappPairingCandidates {
    fn lock(&self) -> Result<MutexGuard<'_, PairingCandidates<String>>, RappBindingError> {
        self.candidates
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)
    }
}

/// Opaque completed pair record. Private key material cannot be requested by
/// foreign application or UI code.
#[allow(
    missing_debug_implementations,
    reason = "record holds the pair private key; no formatted view exists"
)]
#[derive(uniffi::Object)]
pub struct RappPairRecord {
    record: Mutex<Option<PairRecord>>,
}

#[uniffi::export]
impl RappPairRecord {
    /// Load an active pair record from platform device-only storage.
    ///
    /// A record whose [`RappPairMetadata::storage_confirmed`] is false was
    /// stored inside a confirmation window this endpoint did not complete:
    /// it opens no session, routes nothing and is announced nowhere, and
    /// the caller revokes it with [`Self::revoke`] at the first start that
    /// finds it.
    ///
    /// # Errors
    /// [`RappBindingError`] on an invalid identifier, a revoked or absent
    /// pair, or a storage failure.
    #[uniffi::constructor]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn load_from_vault(
        pair_id: Vec<u8>,
        vault: Arc<dyn RappPairVault>,
    ) -> Result<Arc<Self>, RappBindingError> {
        let pair_id = PairId::reconstruct(&pair_id).map_err(|_| RappBindingError::InvalidInput)?;
        if vault
            .is_revoked(pair_id.as_bytes().to_vec())
            .map_err(|_| RappBindingError::LocalStateFailure)?
        {
            return Err(RappBindingError::PairNotFound);
        }
        let bytes = vault
            .load_device_only(pair_id.as_bytes().to_vec())
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .ok_or(RappBindingError::PairNotFound)?;
        let record = decode_pair_record(&bytes)?;
        if record.pair_id() != pair_id {
            return Err(RappBindingError::InvalidInput);
        }
        Ok(Arc::new(Self {
            record: Mutex::new(Some(record)),
        }))
    }

    /// A fresh `"session"` routing preamble for one dial on the transport
    /// profile `profile_name`: a new random nonce and the routing tag this
    /// pairing keys from it (RAPP section 2.2.1).
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on an unregistered profile name or
    /// a degenerate static agreement, [`RappBindingError::WrongPhase`] when
    /// the record was revoked, and [`RappBindingError::LocalStateFailure`]
    /// when the random source fails.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn session_preamble(&self, profile_name: String) -> Result<Vec<u8>, RappBindingError> {
        let profile = transport_profile(&profile_name)?;
        let routing = self
            .routing_key()?
            .route(profile, |bytes| {
                getrandom::fill(bytes).map_err(|_| super::RandomUnavailable)
            })
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        RoutingPreamble::Session(routing)
            .encode(profile)
            .map_err(|_| RappBindingError::ProtocolFailure)
    }

    /// This pairing's discovery hint for the 15-minute window containing
    /// `unix_time_seconds` (hierarchy specification section 4.3).
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on a degenerate static agreement,
    /// and [`RappBindingError::WrongPhase`] when the record was revoked.
    pub fn discovery_hint(&self, unix_time_seconds: u64) -> Result<Vec<u8>, RappBindingError> {
        Ok(self
            .discovery_key()?
            .hint(super::discovery_epoch(unix_time_seconds))
            .to_vec())
    }

    /// Whether the TXT attributes `txt` form a `mode=session` record that
    /// carries this pairing's discovery hint for the window containing
    /// `unix_time_seconds` or an adjacent one. A malformed record is `false`.
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on a degenerate static agreement,
    /// and [`RappBindingError::WrongPhase`] when the record was revoked.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn matches_discovery_record(
        &self,
        txt: Vec<RappTxtEntry>,
        unix_time_seconds: u64,
    ) -> Result<bool, RappBindingError> {
        let pairs: Vec<(&str, &str)> = txt
            .iter()
            .map(|entry| (entry.key.as_str(), entry.value.as_str()))
            .collect();
        let Ok(record) = super::DiscoveryRecord::parse(&pairs) else {
            return Ok(false);
        };
        Ok(self
            .discovery_key()?
            .matches_record(&record, super::discovery_epoch(unix_time_seconds)))
    }

    /// This pairing's withdrawal hint for the advertised service instance
    /// `instance_name` in the minute containing `unix_time_seconds`
    /// (RAPP section 4.5).
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on an instance name that is not the
    /// instance portion of the published name, or a degenerate static
    /// agreement, and
    /// [`RappBindingError::WrongPhase`] when the record was revoked.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn withdrawal_hint(
        &self,
        instance_name: String,
        unix_time_seconds: u64,
    ) -> Result<Vec<u8>, RappBindingError> {
        let instance =
            super::InstanceName::new(&instance_name).map_err(|_| RappBindingError::InvalidInput)?;
        let key = self.withdrawal_key()?;
        Ok(key
            .hint(&instance, super::withdrawal_counter(unix_time_seconds))
            .to_vec())
    }

    /// Whether the TXT attributes `txt` discovered on the service instance
    /// `instance_name` form a withdrawn record carrying this pairing's hint
    /// for the minute containing `unix_time_seconds` or an adjacent one
    /// (RAPP section 4.5). A malformed record or instance name is `false`.
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on a degenerate static agreement,
    /// and [`RappBindingError::WrongPhase`] when the record was revoked.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn matches_withdrawn_record(
        &self,
        instance_name: String,
        txt: Vec<RappTxtEntry>,
        unix_time_seconds: u64,
    ) -> Result<bool, RappBindingError> {
        let Ok(instance) = super::InstanceName::new(&instance_name) else {
            return Ok(false);
        };
        let pairs: Vec<(&str, &str)> = txt
            .iter()
            .map(|entry| (entry.key.as_str(), entry.value.as_str()))
            .collect();
        let Ok(record) = super::WithdrawnRecord::parse(&pairs) else {
            return Ok(false);
        };
        let key = self.withdrawal_key()?;
        Ok(key.matches(
            &record,
            &instance,
            super::withdrawal_counter(unix_time_seconds),
        ))
    }

    /// Read non-secret metadata suitable for confirmation and connection UI.
    ///
    /// # Errors
    /// [`RappBindingError`] when the record was already revoked or the lock
    /// is poisoned.
    pub fn metadata(&self) -> Result<RappPairMetadata, RappBindingError> {
        let guard = self
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let record = guard.as_ref().ok_or(RappBindingError::WrongPhase)?;
        let metadata = pair_metadata(record);
        drop(guard);
        Ok(metadata)
    }

    /// Persist the complete pair record through a platform adapter that must
    /// use non-synchronizing, device-only storage excluded from backup.
    ///
    /// # Errors
    /// [`RappBindingError`] on a revoked record or a storage failure.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the record lock covers the vault write so revocation cannot interleave with persistence"
    )]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn persist_device_only(
        &self,
        vault: Arc<dyn RappPairVault>,
    ) -> Result<(), RappBindingError> {
        let record = self
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let record = record.as_ref().ok_or(RappBindingError::WrongPhase)?;
        let pair_id = record.pair_id().as_bytes().to_vec();
        let bytes = encode_pair_record(record)?;
        vault
            .insert_device_only(pair_id, bytes)
            .map_err(|_| RappBindingError::LocalStateFailure)
    }

    /// Store the confirmed record in place of the unconfirmed one written
    /// by [`Self::persist_device_only`], once
    /// [`RappPairingBridge::activate_pairing`] returned it (§4.3 item 4).
    ///
    /// # Errors
    /// [`RappBindingError::StorageUnconfirmed`] for a record the peer has
    /// not confirmed, [`RappBindingError::WrongPhase`] for a revoked one,
    /// and [`RappBindingError::LocalStateFailure`] on a storage failure.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the record lock covers the vault write so revocation cannot interleave with persistence"
    )]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn replace_device_only(
        &self,
        vault: Arc<dyn RappPairVault>,
    ) -> Result<(), RappBindingError> {
        let record = self
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let record = record.as_ref().ok_or(RappBindingError::WrongPhase)?;
        if !record.is_storage_confirmed() {
            return Err(RappBindingError::StorageUnconfirmed);
        }
        let pair_id = record.pair_id().as_bytes().to_vec();
        let bytes = encode_pair_record(record)?;
        vault
            .replace_device_only(pair_id, bytes)
            .map_err(|_| RappBindingError::LocalStateFailure)
    }

    /// The custodian's user forgets the pairing while no session to the
    /// peer is open (RAPP §4.6); idle expiry is [`Self::sweep`]'s. A
    /// confirmed record is stored as forgotten and keeps its key
    /// only to deliver the `pairing_revoked` close on the next session; an
    /// unconfirmed one is destroyed at once. With a session open, close it
    /// with reason `pairing_revoked` and call [`Self::revoke`] instead. A
    /// requester whose holder turns remote use off never forgets this way:
    /// it closes each open session with `pairing_revoked`, waits at most
    /// [`rapp_quit_withdrawal_bound_ms`] for the closes to leave, and calls
    /// [`Self::revoke`] for every pairing, owing nothing (§4.6 item 6).
    /// `forgotten_at_ms` is milliseconds since the Unix epoch.
    ///
    /// # Errors
    /// [`RappBindingError`] on an already-revoked record or a storage
    /// failure.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn forget(
        &self,
        vault: Arc<dyn RappPairVault>,
        forgotten_at_ms: u64,
    ) -> Result<RappForgetOutcome, RappBindingError> {
        let mut guard = self
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let record = guard.take().ok_or(RappBindingError::WrongPhase)?;
        let pair_id = record.pair_id().as_bytes().to_vec();
        if !record.is_storage_confirmed() {
            let outcome = vault
                .revoke_device_only(pair_id, forgotten_at_ms)
                .map(|()| RappForgetOutcome::Destroyed);
            if outcome.is_err() {
                *guard = Some(record);
            }
            return outcome.map_err(|_| RappBindingError::LocalStateFailure);
        }
        let forgotten = record.forgotten(forgotten_at_ms);
        let stored = encode_pair_record(&forgotten).and_then(|bytes| {
            vault
                .replace_device_only(pair_id, bytes)
                .map_err(|_| RappBindingError::LocalStateFailure)
        });
        *guard = Some(forgotten);
        drop(guard);
        stored.map(|()| RappForgetOutcome::NoticePending)
    }

    /// Whether a forgotten record kept its key for 30 days without a session
    /// to deliver the close; destroy it then with [`Self::revoke`].
    ///
    /// # Errors
    /// [`RappBindingError`] when the record was already revoked.
    pub fn revocation_notice_expired(&self, now_ms: u64) -> Result<bool, RappBindingError> {
        self.with_record(|record| Ok(record.revocation_notice_expired(now_ms)))
    }

    /// Check this pairing for idle expiry at `now_ms`, milliseconds since
    /// the Unix epoch, and store what changed (RAPP §4.6 item 5).
    /// `session_established` says whether a session to the pairing is
    /// established now. With one, the time is recorded and the pairing kept,
    /// whatever was recorded before, so no order of calls expires a pairing
    /// in session; the recorded time never moves back. Without one, the
    /// pairing expires 30 days after its latest recorded session, or its
    /// creation while it has had none, and is then stored as forgotten. The
    /// change is stored first and taken into memory only once the vault
    /// confirmed it, so a sweep that failed to store is repeated whole by
    /// the next one.
    ///
    /// Sweep every pairing at launch and at least once a day, and sweep a
    /// pairing with `session_established` true once
    /// [`RappSessionBridge::enter_established`] succeeded and when that
    /// session ends.
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] for a revoked record,
    /// [`RappBindingError::StorageUnconfirmed`] for one the peer has not
    /// confirmed, and [`RappBindingError::LocalStateFailure`] on a storage
    /// failure, which changes nothing.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the record lock covers the vault write so the record in memory changes only with the stored one"
    )]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn sweep(
        &self,
        vault: Arc<dyn RappPairVault>,
        now_ms: u64,
        session_established: bool,
    ) -> Result<RappSweepOutcome, RappBindingError> {
        let mut guard = self
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let record = guard.as_mut().ok_or(RappBindingError::WrongPhase)?;
        if !record.is_storage_confirmed() {
            return Err(RappBindingError::StorageUnconfirmed);
        }
        let pair_id = record.pair_id().as_bytes().to_vec();
        let outcome = record
            .sweep(now_ms, session_established, |encoded| {
                vault.replace_device_only(pair_id, encoded.as_bytes().to_vec())
            })
            .map_err(|error| match error {
                super::SweepError::Encoding(_) => RappBindingError::ProtocolFailure,
                super::SweepError::Store(_) => RappBindingError::LocalStateFailure,
            })?;
        drop(guard);
        Ok(outcome.into())
    }

    /// Irreversibly delete active secret material and retain only a local
    /// tombstone. The in-memory private key is dropped only after the vault
    /// confirms deletion; `revoked_at_ms` is milliseconds since the Unix
    /// epoch. A requester whose holder turns remote use off revokes every
    /// pairing this way, after the closes of its open sessions left or
    /// their bound passed (RAPP §4.6 item 6).
    ///
    /// # Errors
    /// [`RappBindingError`] on an already-revoked record or a storage
    /// failure.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn revoke(
        &self,
        vault: Arc<dyn RappPairVault>,
        revoked_at_ms: u64,
    ) -> Result<(), RappBindingError> {
        let mut record = self
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let active = record.as_ref().ok_or(RappBindingError::WrongPhase)?;
        let pair_id = active.pair_id();
        vault
            .revoke_device_only(pair_id.as_bytes().to_vec(), revoked_at_ms)
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        record.take();
        Ok(())
    }
}

/// Platform-owned long-term pair storage.
///
/// Implementations must use device-only, non-migrating, non-synchronizing
/// secret storage excluded from backups. Insert and revoke must be atomic;
/// revoke must destroy the secret before returning success.
#[uniffi::export(with_foreign)]
pub trait RappPairVault: Send + Sync {
    /// Atomically insert a new secret-bearing opaque record.
    ///
    /// # Errors
    /// [`RappVaultError`] on a reused identifier or unavailable storage.
    fn insert_device_only(&self, pair_id: Vec<u8>, record: Vec<u8>) -> Result<(), RappVaultError>;

    /// Load one opaque record into process memory for a fresh session.
    ///
    /// # Errors
    /// [`RappVaultError`] when storage is unavailable.
    fn load_device_only(&self, pair_id: Vec<u8>) -> Result<Option<Vec<u8>>, RappVaultError>;

    /// Atomically replace the record stored under an existing identifier:
    /// the confirmed form of a record inserted before the peer confirmed
    /// its storage (RAPP v26.10.22 §4.3 item 4).
    ///
    /// # Errors
    /// [`RappVaultError`] on an absent pair or unavailable storage.
    fn replace_device_only(&self, pair_id: Vec<u8>, record: Vec<u8>) -> Result<(), RappVaultError>;

    /// Atomically destroy the record and retain a non-secret tombstone.
    ///
    /// # Errors
    /// [`RappVaultError`] on an absent pair or unavailable storage.
    fn revoke_device_only(
        &self,
        pair_id: Vec<u8>,
        revoked_at_ms: u64,
    ) -> Result<(), RappVaultError>;

    /// Check the permanent local tombstone before accepting a pair identifier.
    ///
    /// # Errors
    /// [`RappVaultError`] when storage is unavailable.
    fn is_revoked(&self, pair_id: Vec<u8>) -> Result<bool, RappVaultError>;
}

/// Platform vault failure, intentionally free of backend strings or secrets.
#[allow(
    missing_copy_implementations,
    reason = "generated FFI error registry; Copy is not part of the binding contract"
)]
#[derive(Debug, uniffi::Error)]
pub enum RappVaultError {
    /// Secret storage was unavailable or rejected the atomic operation.
    Unavailable,
    /// Identifier already has an active record or permanent tombstone.
    IdentifierAlreadyUsed,
    /// Requested active pair did not exist.
    PairNotFound,
}

impl core::fmt::Display for RappVaultError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for RappVaultError {}

pub(super) enum SessionBridgeState {
    Handshake(Box<SessionHandshake>),
    Authentication(SessionAuthentication),
    Established(EstablishedEndpoint),
    Closed,
    Failed,
}

/// Opaque fresh Noise KK session lifecycle for one stored pairing.
#[allow(
    missing_debug_implementations,
    reason = "state holds handshake and session keys; no formatted view exists"
)]
#[derive(uniffi::Object)]
pub struct RappSessionBridge {
    pub(super) state: Mutex<SessionBridgeState>,
    pair: Arc<RappPairRecord>,
    session_id: Mutex<Option<SessionId>>,
}

#[uniffi::export]
impl RappSessionBridge {
    /// Begin a requester session over the transport `transport_profile`
    /// only after a fresh local user action.
    ///
    /// # Errors
    /// [`RappBindingError`] on a revoked or absent pair, a role mismatch, an
    /// unregistered transport profile, or a handshake-construction failure.
    #[uniffi::constructor]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn begin_requester(
        pair: Arc<RappPairRecord>,
        vault: Arc<dyn RappPairVault>,
        transport_profile: String,
    ) -> Result<Arc<Self>, RappBindingError> {
        Self::begin_session(pair, vault, EndpointRole::Requester, &transport_profile)
    }

    /// Begin the proxy response to one incoming connection over the
    /// transport `transport_profile`.
    ///
    /// # Errors
    /// [`RappBindingError`] on a revoked or absent pair, a role mismatch, an
    /// unregistered transport profile, or a handshake-construction failure.
    #[uniffi::constructor]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn begin_proxy(
        pair: Arc<RappPairRecord>,
        vault: Arc<dyn RappPairVault>,
        transport_profile: String,
    ) -> Result<Arc<Self>, RappBindingError> {
        Self::begin_session(pair, vault, EndpointRole::Proxy, &transport_profile)
    }

    /// Produce the next role-specific Noise KK frame.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase or a failed handshake.
    pub fn write_handshake_frame(&self) -> Result<Vec<u8>, RappBindingError> {
        let mut state = self.lock_state()?;
        let SessionBridgeState::Handshake(handshake) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let frame = handshake
            .write_message()
            .map(BinaryFrame::into_bytes)
            .map_err(|_| RappBindingError::ProtocolFailure);
        drop(state);
        frame
    }

    /// Consume the next role-specific Noise KK frame.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, an oversized frame, or a
    /// failed handshake.
    pub fn read_handshake_frame(&self, bytes: Vec<u8>) -> Result<(), RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        let mut state = self.lock_state()?;
        let SessionBridgeState::Handshake(handshake) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let outcome = handshake
            .read_message(&frame)
            .map_err(|_| RappBindingError::ProtocolFailure);
        drop(state);
        outcome
    }

    /// Whether the two-message Noise KK exchange has completed.
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] outside the handshake phase.
    pub fn handshake_complete(&self) -> Result<bool, RappBindingError> {
        let state = self.lock_state()?;
        let SessionBridgeState::Handshake(handshake) = &*state else {
            return Err(RappBindingError::WrongPhase);
        };
        let complete = handshake.is_complete();
        drop(state);
        Ok(complete)
    }

    /// Enter `session.ready` authentication: the Custodian sends it, the
    /// Requester verifies it (RAPP §7.1 item 5). For a forgotten record,
    /// call [`Self::deliver_revocation_notice`] instead.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase or an incomplete handshake.
    pub fn enter_authentication(&self) -> Result<(), RappBindingError> {
        let mut state = self.lock_state()?;
        let previous = core::mem::replace(&mut *state, SessionBridgeState::Failed);
        let SessionBridgeState::Handshake(handshake) = previous else {
            return Err(RappBindingError::WrongPhase);
        };
        let authentication = handshake
            .into_authentication()
            .map_err(|_| RappBindingError::ProtocolFailure)?;
        *self
            .session_id
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)? = Some(authentication.session_id());
        *state = SessionBridgeState::Authentication(authentication);
        drop(state);
        Ok(())
    }

    /// The Custodian's `session.ready`: the exact session parameters with a
    /// platform-CSPRNG nonce. Then call [`Self::enter_established`].
    ///
    /// # Errors
    /// [`RappBindingError`] on a wrong-size nonce, the wrong phase, a
    /// Requester, a forgotten record, or a second ready.
    pub fn send_ready(&self, nonce: Vec<u8>) -> Result<Vec<u8>, RappBindingError> {
        let nonce = fixed_array(nonce)?;
        if self.is_forgotten()? {
            return Err(RappBindingError::WrongPhase);
        }
        let mut state = self.lock_state()?;
        let SessionBridgeState::Authentication(authentication) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let frame = authentication
            .send_ready(nonce)
            .map(BinaryFrame::into_bytes)
            .map_err(|error| match error {
                super::SessionError::RoleViolation | super::SessionError::DuplicateReady => {
                    RappBindingError::WrongPhase
                }
                _ => RappBindingError::ProtocolFailure,
            });
        drop(state);
        frame
    }

    /// The Requester reads the Custodian's first message (RAPP §7.1 item 5):
    ///
    /// - `NoAction`: `session.ready` verified; call
    ///   [`Self::enter_established`].
    /// - `SessionClosed`: the Custodian closed the session, with its reason
    ///   in `close_reason`; on `PairingRevoked`, revoke the record with
    ///   [`RappPairRecord::revoke`] and withdraw its identity (§4.6 item 4).
    ///   A frame that fails authentication closes it without a reason.
    /// - `SendFrame`: the message violated the protocol; deliver the sealed
    ///   `protocol_violation` close, then drop the link.
    ///
    /// The pairing stays in every case but a received `PairingRevoked`.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, a Custodian, or an oversized
    /// frame.
    pub fn receive_ready(
        &self,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<RappBridgeAction, RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        let mut state = self.lock_state()?;
        let SessionBridgeState::Authentication(authentication) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let action = match authentication.receive_ready(&frame, now_ms) {
            Ok(ReadyOutcome::Verified) => {
                return Ok(RappBridgeAction::simple(RappBridgeActionKind::NoAction));
            }
            Ok(ReadyOutcome::PeerClosed(reason)) => RappBridgeAction {
                close_reason: Some(reason.into()),
                ..RappBridgeAction::session_closed(EndedOperation::default())
            },
            Ok(ReadyOutcome::ViolationClosed { notice, .. }) => {
                RappBridgeAction::violation_closed(notice)
            }
            Err(super::SessionError::IntegrityFailure) => {
                RappBridgeAction::session_closed(EndedOperation::default())
            }
            Err(_) => return Err(RappBindingError::WrongPhase),
        };
        *state = SessionBridgeState::Closed;
        drop(state);
        Ok(action)
    }

    /// Promote the authenticated channel to healthy established use once the
    /// Custodian sent, or the Requester verified, `session.ready`. The
    /// session is then established: sweep its pairing with
    /// [`RappPairRecord::sweep`], `session_established` true.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, a forgotten record, or a
    /// ready not yet sent or verified.
    pub fn enter_established(&self) -> Result<(), RappBindingError> {
        if self.is_forgotten()? {
            return Err(RappBindingError::WrongPhase);
        }
        let mut state = self.lock_state()?;
        let previous = core::mem::replace(&mut *state, SessionBridgeState::Failed);
        let SessionBridgeState::Authentication(authentication) = previous else {
            return Err(RappBindingError::WrongPhase);
        };
        let endpoint = authentication
            .into_established()
            .map_err(|_| RappBindingError::ProtocolFailure)?;
        *state = SessionBridgeState::Established(endpoint);
        drop(state);
        Ok(())
    }

    /// Whether `session.ready` produced a healthy session.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] when the lock is poisoned.
    pub fn is_established(&self) -> Result<bool, RappBindingError> {
        let state = self.lock_state()?;
        Ok(matches!(&*state, SessionBridgeState::Established(_)))
    }

    /// The first and only message of a session whose record was forgotten:
    /// the sealed `session.close` with reason `pairing_revoked` (RAPP §4.6
    /// item 2), sent once [`Self::enter_authentication`] ran and before
    /// anything else. The session closes and no card session starts; deliver
    /// the frame, drop the link, then destroy the record with
    /// [`RappPairRecord::revoke`].
    ///
    /// # Errors
    /// [`RappBindingError::WrongPhase`] outside authentication, after the
    /// Custodian's `session.ready`, or for a record that is not forgotten,
    /// and [`RappBindingError::ProtocolFailure`] when the close cannot be
    /// sealed.
    pub fn deliver_revocation_notice(&self) -> Result<Vec<u8>, RappBindingError> {
        if !self.is_forgotten()? {
            return Err(RappBindingError::WrongPhase);
        }
        let mut state = self.lock_state()?;
        let SessionBridgeState::Authentication(authentication) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let sealed = match authentication.send_revocation_notice() {
            Err(super::SessionError::DuplicateReady) => return Err(RappBindingError::WrongPhase),
            sealed => sealed,
        };
        *state = SessionBridgeState::Closed;
        drop(state);
        sealed
            .map(super::BinaryFrame::into_bytes)
            .map_err(|_| RappBindingError::ProtocolFailure)
    }

    /// Close only the ephemeral session while retaining the pairing.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] when the lock is poisoned.
    pub fn close_session(&self) -> Result<(), RappBindingError> {
        let mut state = self.lock_state()?;
        if let SessionBridgeState::Established(endpoint) = &mut *state {
            endpoint.close_session();
        }
        *state = SessionBridgeState::Closed;
        drop(state);
        Ok(())
    }
}

impl RappSessionBridge {
    fn begin_session(
        pair: Arc<RappPairRecord>,
        vault: Arc<dyn RappPairVault>,
        role: EndpointRole,
        transport_profile: &str,
    ) -> Result<Arc<Self>, RappBindingError> {
        let transport =
            TransportProfile::parse(transport_profile).ok_or(RappBindingError::InvalidInput)?;
        let pair_guard = pair
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let pair_record = pair_guard.as_ref().ok_or(RappBindingError::PairNotFound)?;
        if pair_record.role() != role {
            return Err(RappBindingError::InvalidInput);
        }
        if vault
            .is_revoked(pair_record.pair_id().as_bytes().to_vec())
            .map_err(|_| RappBindingError::LocalStateFailure)?
        {
            return Err(RappBindingError::PairNotFound);
        }
        let handshake = match role {
            EndpointRole::Requester => SessionHandshake::begin_requester(
                pair_record,
                transport,
                ExplicitUserIntent::record(),
            ),
            EndpointRole::Proxy => SessionHandshake::begin_proxy(pair_record, transport),
        }
        .map_err(|error| match error {
            super::SessionError::StorageUnconfirmed => RappBindingError::StorageUnconfirmed,
            _ => RappBindingError::ProtocolFailure,
        })?;
        drop(pair_guard);
        Ok(Arc::new(Self {
            state: Mutex::new(SessionBridgeState::Handshake(Box::new(handshake))),
            pair,
            session_id: Mutex::new(None),
        }))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, SessionBridgeState>, RappBindingError> {
        self.state
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)
    }

    fn is_forgotten(&self) -> Result<bool, RappBindingError> {
        self.pair
            .with_record(|record| Ok(record.forgotten_at_ms().is_some()))
    }

    pub(super) fn take_established(
        &self,
    ) -> Result<(EstablishedEndpoint, Vec<ProfileName>), RappBindingError> {
        let mut state = self.lock_state()?;
        let previous = core::mem::replace(&mut *state, SessionBridgeState::Closed);
        let endpoint = match previous {
            SessionBridgeState::Established(endpoint) => endpoint,
            previous => {
                *state = previous;
                return Err(RappBindingError::WrongPhase);
            }
        };
        drop(state);
        let profiles = self
            .pair
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .as_ref()
            .ok_or(RappBindingError::PairNotFound)?
            .serving_profiles()
            .to_vec();
        Ok((endpoint, profiles))
    }
}

pub(super) fn fixed_array<const SIZE: usize>(
    bytes: Vec<u8>,
) -> Result<[u8; SIZE], RappBindingError> {
    bytes.try_into().map_err(|_| RappBindingError::InvalidInput)
}

fn parse_profiles(names: Vec<String>) -> Result<Vec<ProfileName>, RappBindingError> {
    names
        .into_iter()
        .map(|name| ProfileName::parse(&name).ok_or(RappBindingError::InvalidInput))
        .collect()
}

fn pair_metadata(record: &PairRecord) -> RappPairMetadata {
    RappPairMetadata {
        pair_id: record.pair_id().as_bytes().to_vec(),
        role: record.role().into(),
        profiles: record
            .profiles()
            .iter()
            .map(|profile| profile.as_str().to_owned())
            .collect(),
        created_at_ms: record.created_at_ms(),
        storage_confirmed: record.is_storage_confirmed(),
        forgotten_at_ms: record.forgotten_at_ms(),
        last_session_at_ms: record.last_session_at_ms(),
    }
}

fn transport_profile(name: &str) -> Result<TransportProfile, RappBindingError> {
    TransportProfile::parse(name).ok_or(RappBindingError::InvalidInput)
}

/// Preamble frame payload the dialing proxy sends to reach the custodian's
/// active pairing offer on the transport profile `profile_name`.
///
/// # Errors
/// [`RappBindingError::InvalidInput`] on an unregistered profile name.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "uniffi lowers exported arguments as owned values"
)]
pub fn rapp_pairing_preamble(profile_name: String) -> Result<Vec<u8>, RappBindingError> {
    RoutingPreamble::Pairing
        .encode(transport_profile(&profile_name)?)
        .map_err(|_| RappBindingError::ProtocolFailure)
}

/// Registered stream transport profile name.
#[uniffi::export]
#[must_use]
pub fn rapp_stream_profile_name() -> String {
    STREAM_PROFILE.to_owned()
}

/// How long a requester that quits waits for its `service_withdrawn` closes
/// to leave before it exits (RAPP v26.10.22 section 4.5 item 8), and one
/// whose holder turned remote use off waits for its `pairing_revoked` closes
/// (section 4.6 item 6).
#[uniffi::export]
#[must_use]
pub const fn rapp_quit_withdrawal_bound_ms() -> u64 {
    super::QUIT_WITHDRAWAL_BOUND_MS
}

/// How long a pairing lives without an established session before it
/// expires (RAPP v26.10.22 section 4.6 item 5).
#[uniffi::export]
#[must_use]
pub const fn rapp_pairing_idle_expiry_ms() -> u64 {
    super::PAIRING_IDLE_EXPIRY_MS
}

/// Where a custodian sends one received routing preamble.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum RappRoute {
    /// Serve the active pairing offer.
    Pairing,
    /// Open a session for the stored pairing at `index` in the list given.
    Session {
        /// Position of the matching pair record.
        index: u32,
    },
    /// Close the connection without answering and change no stored state.
    Refuse,
}

/// A custodian's router for received routing preambles (RAPP section
/// 2.2.1). It remembers the nonces of recently routed sessions, so one
/// router serves every connection the custodian accepts.
#[derive(Debug, Default, uniffi::Object)]
pub struct RappSessionRouter {
    replay: Mutex<super::RoutingReplayCache>,
}

#[uniffi::export]
impl RappSessionRouter {
    /// A router that has routed nothing yet.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Routes the preamble `preamble` received on the transport profile
    /// `profile_name` against the custodian's non-revoked pair records.
    ///
    /// A malformed preamble, a routing value no record keyed, a replayed
    /// nonce, and an unregistered profile name are all
    /// [`RappRoute::Refuse`].
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] when the replay memory is
    /// unavailable.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn route(
        &self,
        profile_name: String,
        preamble: Vec<u8>,
        records: Vec<Arc<RappPairRecord>>,
    ) -> Result<RappRoute, RappBindingError> {
        let Ok(profile) = transport_profile(&profile_name) else {
            return Ok(RappRoute::Refuse);
        };
        let routing = match RoutingPreamble::decode(profile, &preamble) {
            Ok(RoutingPreamble::Pairing) => return Ok(RappRoute::Pairing),
            Ok(RoutingPreamble::Session(routing)) => routing,
            Err(_) => return Ok(RappRoute::Refuse),
        };
        // A record the peer never confirmed routes nothing (§4.3 item 4);
        // it is left out, and the answer indexes the caller's list.
        let mut indices = Vec::with_capacity(records.len());
        let mut keys = Vec::with_capacity(records.len());
        for (index, record) in records.iter().enumerate() {
            match record.routing_key() {
                Ok(key) => {
                    indices.push(index);
                    keys.push(key);
                }
                Err(RappBindingError::StorageUnconfirmed) => {}
                Err(error) => return Err(error),
            }
        }
        let Some(position) = super::route_session(&keys, profile, &routing) else {
            return Ok(RappRoute::Refuse);
        };
        let index = indices[position];
        let fresh = self
            .replay
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .admit(routing.nonce());
        if !fresh {
            return Ok(RappRoute::Refuse);
        }
        Ok(RappRoute::Session {
            index: u32::try_from(index).map_err(|_| RappBindingError::InvalidInput)?,
        })
    }
}

impl RappPairRecord {
    fn with_record<T>(
        &self,
        use_record: impl FnOnce(&PairRecord) -> Result<T, RappBindingError>,
    ) -> Result<T, RappBindingError> {
        let guard = self
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let record = guard.as_ref().ok_or(RappBindingError::WrongPhase)?;
        let value = use_record(record);
        drop(guard);
        value
    }

    fn routing_key(&self) -> Result<super::RoutingKey, RappBindingError> {
        self.with_record(|record| {
            super::RoutingKey::derive(record).map_err(|error| match error {
                super::RecordKeyError::StorageUnconfirmed => RappBindingError::StorageUnconfirmed,
                super::RecordKeyError::DegenerateAgreement(_) => RappBindingError::InvalidInput,
            })
        })
    }

    fn discovery_key(&self) -> Result<super::DiscoveryKey, RappBindingError> {
        self.with_record(|record| {
            super::DiscoveryKey::derive(record).map_err(|error| match error {
                super::RecordKeyError::StorageUnconfirmed => RappBindingError::StorageUnconfirmed,
                super::RecordKeyError::DegenerateAgreement(_) => RappBindingError::InvalidInput,
            })
        })
    }

    fn withdrawal_key(&self) -> Result<super::WithdrawalKey, RappBindingError> {
        self.with_record(|record| {
            super::WithdrawalKey::derive(record).map_err(|error| match error {
                super::WithdrawalError::StorageUnconfirmed => RappBindingError::StorageUnconfirmed,
                _ => RappBindingError::InvalidInput,
            })
        })
    }
}

/// One DNS-SD TXT attribute, key and value.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappTxtEntry {
    /// Attribute key.
    pub key: String,
    /// Attribute value.
    pub value: String,
}

/// One stored pairing a custodian could announce: its hint for the record
/// being published and the time of its most recent established session, or
/// of its creation when it has had none.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappAnnouncementCandidate {
    /// The pairing's discovery or withdrawal hint.
    pub hint: Vec<u8>,
    /// Milliseconds since the Unix epoch of the pairing's last use.
    pub last_used_ms: u64,
}

fn announcement_candidates(
    candidates: &[RappAnnouncementCandidate],
) -> Result<Vec<super::AnnouncementCandidate>, RappBindingError> {
    candidates
        .iter()
        .map(|candidate| {
            Ok(super::AnnouncementCandidate {
                hint: <[u8; super::DISCOVERY_HINT_SIZE]>::try_from(candidate.hint.as_slice())
                    .map_err(|_| RappBindingError::InvalidInput)?,
                last_used_ms: candidate.last_used_ms,
            })
        })
        .collect()
}

fn txt_entries(entries: impl IntoIterator<Item = (&'static str, String)>) -> Vec<RappTxtEntry> {
    entries
        .into_iter()
        .map(|(key, value)| RappTxtEntry {
            key: key.to_owned(),
            value,
        })
        .collect()
}

/// The TXT attributes of a `mode=session` record announcing the discovery
/// hints of the four most recently used `candidates` (hierarchy
/// specification section 4.3). No candidates give the minimal record.
///
/// # Errors
/// [`RappBindingError::InvalidInput`] for a hint of the wrong size.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "uniffi lowers exported arguments as owned values"
)]
pub fn rapp_session_record(
    candidates: Vec<RappAnnouncementCandidate>,
) -> Result<Vec<RappTxtEntry>, RappBindingError> {
    let candidates = announcement_candidates(&candidates)?;
    Ok(txt_entries(
        super::DiscoveryRecord::assemble(&candidates).txt_entries(),
    ))
}

/// The TXT attributes of a `mode=withdrawn` record announcing the
/// withdrawal hints of the eight most recently used `candidates`, padded to
/// eight entries with random fillers and shuffled (RAPP section 4.5).
///
/// # Errors
/// [`RappBindingError::InvalidInput`] for a hint of the wrong size, and
/// [`RappBindingError::LocalStateFailure`] when the random source fails.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "uniffi lowers exported arguments as owned values"
)]
pub fn rapp_withdrawn_record(
    candidates: Vec<RappAnnouncementCandidate>,
) -> Result<Vec<RappTxtEntry>, RappBindingError> {
    let candidates = announcement_candidates(&candidates)?;
    let record = super::WithdrawnRecord::assemble(&candidates, |bytes| {
        getrandom::fill(bytes).map_err(|_| super::WithdrawalError::RandomUnavailable)
    })
    .map_err(|_| RappBindingError::LocalStateFailure)?;
    Ok(txt_entries(record.txt_entries()))
}

fn encode_pair_record(record: &PairRecord) -> Result<Vec<u8>, RappBindingError> {
    super::encode_pair_record(record).map_err(|_| RappBindingError::ProtocolFailure)
}

fn decode_pair_record(bytes: &[u8]) -> Result<PairRecord, RappBindingError> {
    super::decode_pair_record(bytes).map_err(|_| RappBindingError::InvalidInput)
}

/// The BLE segmentation and reassembly receiver for one connection and one
/// direction (RAPP v26.10.22 §5.3).
///
/// Any refused fragment zeroizes the partial frame; the caller then drops
/// the connection.
#[derive(Debug, Default, uniffi::Object)]
pub struct RappBleSarReassembler {
    inner: Mutex<crate::ble_sar::BleSarReassembler>,
}

#[uniffi::export]
impl RappBleSarReassembler {
    /// A receiver waiting for the first fragment of a frame.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Consume one fragment at the platform's monotonic `now_monotonic_ms`;
    /// returns the complete message once its last fragment arrives.
    ///
    /// # Errors
    /// [`RappBindingError::ProtocolFailure`] for any fragment §5.3 refuses,
    /// and [`RappBindingError::LocalStateFailure`] on a poisoned lock.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn receive(
        &self,
        fragment: Vec<u8>,
        capacity: u32,
        now_monotonic_ms: u64,
    ) -> Result<Option<Vec<u8>>, RappBindingError> {
        let capacity = usize::try_from(capacity).map_err(|_| RappBindingError::InvalidInput)?;
        self.inner
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .receive(&fragment, capacity, now_monotonic_ms)
            .map_err(|_| RappBindingError::ProtocolFailure)
    }

    /// Refuse a frame whose 5.0-second reassembly timer has run out.
    ///
    /// # Errors
    /// [`RappBindingError::ProtocolFailure`] when the timer expired, and
    /// [`RappBindingError::LocalStateFailure`] on a poisoned lock.
    pub fn check_timer(&self, now_monotonic_ms: u64) -> Result<(), RappBindingError> {
        self.inner
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .check_timer(now_monotonic_ms)
            .map_err(|_| RappBindingError::ProtocolFailure)
    }

    /// Zeroize any partial frame and return to idle.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] on a poisoned lock.
    pub fn reset(&self) -> Result<(), RappBindingError> {
        self.inner
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .reset();
        Ok(())
    }
}

/// The uniform SAR fragment payload capacity for a negotiated ATT MTU and
/// any smaller value limit the platform reports (RAPP v26.10.22 §5.3).
///
/// # Errors
/// [`RappBindingError::InvalidInput`] below an MTU of 512 or when the limit
/// leaves no room for a non-final fragment.
#[uniffi::export]
pub fn rapp_ble_sar_payload_capacity(
    negotiated_att_mtu: u32,
    platform_value_limit: Option<u32>,
) -> Result<u32, RappBindingError> {
    let mtu = usize::try_from(negotiated_att_mtu).map_err(|_| RappBindingError::InvalidInput)?;
    let limit = platform_value_limit
        .map(usize::try_from)
        .transpose()
        .map_err(|_| RappBindingError::InvalidInput)?;
    let capacity =
        crate::ble_sar::payload_capacity(mtu, limit).map_err(|_| RappBindingError::InvalidInput)?;
    u32::try_from(capacity).map_err(|_| RappBindingError::InvalidInput)
}

/// Split one message into the SAR fragments that carry it, in order.
///
/// # Errors
/// [`RappBindingError::InvalidInput`] for an empty or oversized message or
/// a capacity outside the profile's range.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "uniffi lowers exported arguments as owned values"
)]
pub fn rapp_ble_sar_segment(
    message: Vec<u8>,
    capacity: u32,
) -> Result<Vec<Vec<u8>>, RappBindingError> {
    let capacity = usize::try_from(capacity).map_err(|_| RappBindingError::InvalidInput)?;
    crate::ble_sar::segment(&message, capacity).map_err(|_| RappBindingError::InvalidInput)
}

#[cfg(test)]
mod routing_binding_tests {
    use super::{
        RappAnnouncementCandidate, RappPairRecord, RappPairVault, RappRoute, RappSessionRouter,
        RappSweepOutcome, RappVaultError, rapp_pairing_preamble, rapp_session_record,
        rapp_withdrawn_record,
    };
    use crate::{
        BLE_PROFILE, EndpointRole, GrantsHash, PAIR_ID_SIZE, PAIRING_IDLE_EXPIRY_DAYS,
        PAIRING_IDLE_EXPIRY_MS, PairId, PairRecord, ProfileName, STREAM_PROFILE, X25519_KEY_SIZE,
        noise::x25519_public_key,
    };
    use std::sync::{Arc, Mutex};

    const CUSTODIAN_BYTE: u8 = 0x11;
    const REQUESTER_BYTE: u8 = 0x22;
    const PAIR_BYTE: u8 = 0x33;
    const OTHER_PAIR_BYTE: u8 = 0x55;
    const GRANTS_BYTE: u8 = 0x66;
    const CREATED_AT_MS: u64 = 1;
    const UNIX_TIME_SECONDS: u64 = 1_791_504_899;
    const MILLISECONDS_PER_SECOND: u64 = 1_000;
    const REVOKED_AT_MS: u64 = UNIX_TIME_SECONDS * MILLISECONDS_PER_SECOND;
    const SESSION_AT_MS: u64 = UNIX_TIME_SECONDS * MILLISECONDS_PER_SECOND;

    fn record(own: u8, peer: u8, pair: u8, role: EndpointRole) -> Arc<RappPairRecord> {
        let own_private = [own; X25519_KEY_SIZE];
        let record = PairRecord::new(
            PairId::from_array([pair; PAIR_ID_SIZE]),
            role,
            own_private,
            x25519_public_key(&own_private),
            x25519_public_key(&[peer; X25519_KEY_SIZE]),
            GrantsHash::from_array([GRANTS_BYTE; crate::GRANTS_HASH_SIZE]),
            vec![ProfileName::Authentication],
            CREATED_AT_MS,
        )
        .expect("record");
        Arc::new(RappPairRecord {
            record: Mutex::new(Some(record)),
        })
    }

    /// A vault holding one encoded record.
    struct StoringVault {
        bytes: Vec<u8>,
        revoked: Mutex<bool>,
    }

    impl RappPairVault for StoringVault {
        fn insert_device_only(&self, _: Vec<u8>, _: Vec<u8>) -> Result<(), RappVaultError> {
            Err(RappVaultError::IdentifierAlreadyUsed)
        }

        fn load_device_only(&self, _: Vec<u8>) -> Result<Option<Vec<u8>>, RappVaultError> {
            Ok(Some(self.bytes.clone()))
        }

        fn replace_device_only(&self, _: Vec<u8>, _: Vec<u8>) -> Result<(), RappVaultError> {
            Ok(())
        }

        fn revoke_device_only(&self, _: Vec<u8>, _: u64) -> Result<(), RappVaultError> {
            *self.revoked.lock().expect("lock") = true;
            Ok(())
        }

        fn is_revoked(&self, _: Vec<u8>) -> Result<bool, RappVaultError> {
            Ok(*self.revoked.lock().expect("lock"))
        }
    }

    /// A vault that keeps the record last written in place, after refusing
    /// as many writes as it was told to.
    struct ReplacingVault {
        replaced: Mutex<Option<Vec<u8>>>,
        writes_to_refuse: Mutex<usize>,
    }

    impl ReplacingVault {
        fn shared() -> Arc<Self> {
            Self::refusing(0)
        }

        fn refusing(writes_to_refuse: usize) -> Arc<Self> {
            Arc::new(Self {
                replaced: Mutex::new(None),
                writes_to_refuse: Mutex::new(writes_to_refuse),
            })
        }
    }

    impl RappPairVault for ReplacingVault {
        fn insert_device_only(&self, _: Vec<u8>, _: Vec<u8>) -> Result<(), RappVaultError> {
            Err(RappVaultError::IdentifierAlreadyUsed)
        }

        fn load_device_only(&self, _: Vec<u8>) -> Result<Option<Vec<u8>>, RappVaultError> {
            Ok(self.replaced.lock().expect("lock").clone())
        }

        fn replace_device_only(&self, _: Vec<u8>, record: Vec<u8>) -> Result<(), RappVaultError> {
            let mut refusals = self.writes_to_refuse.lock().expect("lock");
            if *refusals > 0 {
                *refusals -= 1;
                return Err(RappVaultError::Unavailable);
            }
            drop(refusals);
            *self.replaced.lock().expect("lock") = Some(record);
            Ok(())
        }

        fn revoke_device_only(&self, _: Vec<u8>, _: u64) -> Result<(), RappVaultError> {
            Ok(())
        }

        fn is_revoked(&self, _: Vec<u8>) -> Result<bool, RappVaultError> {
            Ok(false)
        }
    }

    #[test]
    fn a_session_held_open_past_the_idle_limit_is_recorded_never_expired() {
        let pair = requester();
        let vault = ReplacingVault::shared();
        let day_ms = PAIRING_IDLE_EXPIRY_MS / PAIRING_IDLE_EXPIRY_DAYS;
        let mut now_ms = CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS * 2;
        for _ in 0..PAIRING_IDLE_EXPIRY_DAYS * 2 {
            assert_eq!(
                pair.sweep(Arc::clone(&vault) as Arc<dyn RappPairVault>, now_ms, true)
                    .expect("sweep"),
                RappSweepOutcome::Recorded,
                "a pairing in session is recorded however long it was idle before"
            );
            now_ms += day_ms;
        }
        let last_ms = now_ms - day_ms;
        let metadata = pair.metadata().expect("metadata");
        assert_eq!(metadata.forgotten_at_ms, None);
        assert_eq!(metadata.last_session_at_ms, Some(last_ms));
        assert_eq!(
            pair.sweep(
                Arc::clone(&vault) as Arc<dyn RappPairVault>,
                last_ms + PAIRING_IDLE_EXPIRY_MS - 1,
                false,
            )
            .expect("sweep"),
            RappSweepOutcome::Kept
        );
        let expired_at_ms = last_ms + PAIRING_IDLE_EXPIRY_MS;
        assert_eq!(
            pair.sweep(
                Arc::clone(&vault) as Arc<dyn RappPairVault>,
                expired_at_ms,
                false,
            )
            .expect("sweep"),
            RappSweepOutcome::Expired
        );
        let reloaded = RappPairRecord::load_from_vault(
            vec![PAIR_BYTE; PAIR_ID_SIZE],
            vault as Arc<dyn RappPairVault>,
        )
        .expect("the stored record loads");
        let stored = reloaded.metadata().expect("metadata");
        assert_eq!(stored.forgotten_at_ms, Some(expired_at_ms));
        assert_eq!(stored.last_session_at_ms, Some(last_ms));
    }

    #[test]
    fn a_sweep_never_moves_the_recorded_session_back() {
        let pair = requester();
        let vault = ReplacingVault::shared();
        pair.sweep(
            Arc::clone(&vault) as Arc<dyn RappPairVault>,
            SESSION_AT_MS,
            true,
        )
        .expect("sweep");
        pair.sweep(vault as Arc<dyn RappPairVault>, CREATED_AT_MS, true)
            .expect("sweep with a clock set back");
        assert_eq!(
            pair.metadata().expect("metadata").last_session_at_ms,
            Some(SESSION_AT_MS)
        );
    }

    #[test]
    fn a_sweep_whose_store_failed_is_repeated_whole() {
        let expired_at_ms = CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS;
        let pair = requester();
        let vault = ReplacingVault::refusing(1);
        assert!(matches!(
            pair.sweep(
                Arc::clone(&vault) as Arc<dyn RappPairVault>,
                expired_at_ms,
                false,
            ),
            Err(super::RappBindingError::LocalStateFailure)
        ));
        assert_eq!(
            pair.metadata().expect("metadata").forgotten_at_ms,
            None,
            "a failed store leaves the record in memory as it was"
        );
        assert_eq!(
            pair.sweep(
                Arc::clone(&vault) as Arc<dyn RappPairVault>,
                expired_at_ms,
                false,
            )
            .expect("the retry stores"),
            RappSweepOutcome::Expired
        );
        let reloaded = RappPairRecord::load_from_vault(
            vec![PAIR_BYTE; PAIR_ID_SIZE],
            vault as Arc<dyn RappPairVault>,
        )
        .expect("the stored record loads");
        assert_eq!(
            reloaded.metadata().expect("metadata").forgotten_at_ms,
            Some(expired_at_ms)
        );

        let pair = requester();
        let vault = ReplacingVault::refusing(1);
        assert!(
            pair.sweep(
                Arc::clone(&vault) as Arc<dyn RappPairVault>,
                SESSION_AT_MS,
                true,
            )
            .is_err()
        );
        assert_eq!(pair.metadata().expect("metadata").last_session_at_ms, None);
        assert_eq!(
            pair.sweep(vault as Arc<dyn RappPairVault>, SESSION_AT_MS, true)
                .expect("the retry stores"),
            RappSweepOutcome::Recorded
        );
        assert_eq!(
            pair.metadata().expect("metadata").last_session_at_ms,
            Some(SESSION_AT_MS)
        );
    }

    #[test]
    fn a_forgotten_pairing_is_kept_by_the_sweep() {
        let pair = requester();
        let vault = ReplacingVault::shared();
        pair.forget(Arc::clone(&vault) as Arc<dyn RappPairVault>, SESSION_AT_MS)
            .expect("forget");
        assert_eq!(
            pair.sweep(vault as Arc<dyn RappPairVault>, u64::MAX, false)
                .expect("sweep"),
            RappSweepOutcome::Kept
        );
        assert_eq!(
            pair.metadata().expect("metadata").forgotten_at_ms,
            Some(SESSION_AT_MS)
        );
    }

    #[test]
    fn the_idle_expiry_accessor_is_the_engine_constant() {
        assert_eq!(super::rapp_pairing_idle_expiry_ms(), PAIRING_IDLE_EXPIRY_MS);
    }

    #[test]
    fn forgetting_a_confirmed_pairing_keeps_its_key_for_the_close() {
        let pair = record(
            REQUESTER_BYTE,
            CUSTODIAN_BYTE,
            PAIR_BYTE,
            EndpointRole::Requester,
        );
        let vault = Arc::new(StoringVault {
            bytes: Vec::new(),
            revoked: Mutex::new(false),
        });
        assert_eq!(
            pair.forget(Arc::clone(&vault) as Arc<dyn RappPairVault>, CREATED_AT_MS)
                .expect("forget"),
            super::RappForgetOutcome::NoticePending
        );
        assert!(!*vault.revoked.lock().expect("lock"));
        assert_eq!(
            pair.metadata().expect("metadata").forgotten_at_ms,
            Some(CREATED_AT_MS)
        );
        assert!(
            pair.discovery_hint(UNIX_TIME_SECONDS).is_ok(),
            "a forgotten record is still announced so the close can travel"
        );
    }

    #[test]
    fn forgetting_an_unconfirmed_pairing_destroys_it_untold() {
        let own_private = [REQUESTER_BYTE; X25519_KEY_SIZE];
        let unconfirmed = PairRecord::new(
            PairId::from_array([PAIR_BYTE; PAIR_ID_SIZE]),
            EndpointRole::Requester,
            own_private,
            x25519_public_key(&own_private),
            x25519_public_key(&[CUSTODIAN_BYTE; X25519_KEY_SIZE]),
            GrantsHash::from_array([GRANTS_BYTE; crate::GRANTS_HASH_SIZE]),
            vec![ProfileName::Authentication],
            CREATED_AT_MS,
        )
        .expect("record")
        .awaiting_storage_confirmation();
        let pair = Arc::new(RappPairRecord {
            record: Mutex::new(Some(unconfirmed)),
        });
        let vault = Arc::new(StoringVault {
            bytes: Vec::new(),
            revoked: Mutex::new(false),
        });
        assert_eq!(
            pair.forget(Arc::clone(&vault) as Arc<dyn RappPairVault>, CREATED_AT_MS)
                .expect("forget"),
            super::RappForgetOutcome::Destroyed
        );
        assert!(*vault.revoked.lock().expect("lock"));
        assert!(pair.metadata().is_err());
    }

    #[test]
    fn an_unconfirmed_record_from_the_vault_serves_nothing_and_revokes() {
        let own_private = [REQUESTER_BYTE; X25519_KEY_SIZE];
        let unconfirmed = PairRecord::new(
            PairId::from_array([PAIR_BYTE; PAIR_ID_SIZE]),
            EndpointRole::Requester,
            own_private,
            x25519_public_key(&own_private),
            x25519_public_key(&[CUSTODIAN_BYTE; X25519_KEY_SIZE]),
            GrantsHash::from_array([GRANTS_BYTE; crate::GRANTS_HASH_SIZE]),
            vec![ProfileName::Authentication],
            CREATED_AT_MS,
        )
        .expect("record")
        .awaiting_storage_confirmation();
        let vault = Arc::new(StoringVault {
            bytes: crate::encode_pair_record(&unconfirmed).expect("encode"),
            revoked: Mutex::new(false),
        });
        let loaded = RappPairRecord::load_from_vault(
            unconfirmed.pair_id().as_bytes().to_vec(),
            Arc::clone(&vault) as Arc<dyn RappPairVault>,
        )
        .expect("an unconfirmed record loads so that it can be revoked");
        assert!(!loaded.metadata().expect("metadata").storage_confirmed);
        assert!(matches!(
            super::RappSessionBridge::begin_requester(
                Arc::clone(&loaded),
                Arc::clone(&vault) as Arc<dyn RappPairVault>,
                STREAM_PROFILE.to_owned(),
            ),
            Err(super::RappBindingError::StorageUnconfirmed)
        ));
        assert!(matches!(
            loaded.discovery_hint(UNIX_TIME_SECONDS),
            Err(super::RappBindingError::StorageUnconfirmed)
        ));
        assert!(matches!(
            loaded.replace_device_only(Arc::clone(&vault) as Arc<dyn RappPairVault>),
            Err(super::RappBindingError::StorageUnconfirmed)
        ));
        loaded
            .revoke(Arc::clone(&vault) as Arc<dyn RappPairVault>, REVOKED_AT_MS)
            .expect("an unconfirmed record is revoked");
        assert!(*vault.revoked.lock().expect("lock"));
    }

    fn requester() -> Arc<RappPairRecord> {
        record(
            REQUESTER_BYTE,
            CUSTODIAN_BYTE,
            PAIR_BYTE,
            EndpointRole::Requester,
        )
    }

    fn custodian(pair: u8) -> Arc<RappPairRecord> {
        record(CUSTODIAN_BYTE, REQUESTER_BYTE, pair, EndpointRole::Proxy)
    }

    #[test]
    fn a_session_preamble_routes_to_its_pairing_once() {
        let router = RappSessionRouter::new();
        let preamble = requester()
            .session_preamble(STREAM_PROFILE.to_owned())
            .expect("preamble");
        let stored = vec![custodian(OTHER_PAIR_BYTE), custodian(PAIR_BYTE)];
        assert_eq!(
            router
                .route(STREAM_PROFILE.to_owned(), preamble.clone(), stored.clone())
                .expect("route"),
            RappRoute::Session { index: 1 }
        );
        assert_eq!(
            router
                .route(STREAM_PROFILE.to_owned(), preamble, stored)
                .expect("route"),
            RappRoute::Refuse
        );
    }

    #[test]
    fn each_dial_carries_a_different_preamble() {
        let first = requester()
            .session_preamble(BLE_PROFILE.to_owned())
            .expect("preamble");
        let second = requester()
            .session_preamble(BLE_PROFILE.to_owned())
            .expect("preamble");
        assert_ne!(first, second);
    }

    #[test]
    fn a_preamble_for_another_profile_or_pairing_is_refused() {
        let router = RappSessionRouter::new();
        let preamble = requester()
            .session_preamble(BLE_PROFILE.to_owned())
            .expect("preamble");
        assert_eq!(
            router
                .route(
                    STREAM_PROFILE.to_owned(),
                    preamble.clone(),
                    vec![custodian(PAIR_BYTE)]
                )
                .expect("route"),
            RappRoute::Refuse
        );
        assert_eq!(
            router
                .route(
                    BLE_PROFILE.to_owned(),
                    preamble,
                    vec![custodian(OTHER_PAIR_BYTE)]
                )
                .expect("route"),
            RappRoute::Refuse
        );
    }

    #[test]
    fn a_pairing_preamble_routes_to_the_offer() {
        let router = RappSessionRouter::new();
        let preamble = rapp_pairing_preamble(STREAM_PROFILE.to_owned()).expect("preamble");
        assert_eq!(
            router
                .route(STREAM_PROFILE.to_owned(), preamble, Vec::new())
                .expect("route"),
            RappRoute::Pairing
        );
    }

    #[test]
    fn discovery_records_match_across_the_pairing() {
        let hint = custodian(PAIR_BYTE)
            .discovery_hint(UNIX_TIME_SECONDS)
            .expect("hint");
        let txt = rapp_session_record(vec![RappAnnouncementCandidate {
            hint,
            last_used_ms: CREATED_AT_MS,
        }])
        .expect("record");
        assert!(
            requester()
                .matches_discovery_record(txt.clone(), UNIX_TIME_SECONDS)
                .expect("match")
        );
        assert!(
            !custodian(OTHER_PAIR_BYTE)
                .matches_discovery_record(txt, UNIX_TIME_SECONDS)
                .expect("match")
        );
    }

    #[test]
    fn a_withdrawn_record_announces_at_most_eight_of_many_pairings() {
        let candidates = (0..=crate::WITHDRAWN_RECORD_ENTRIES)
            .map(|index| RappAnnouncementCandidate {
                hint: vec![u8::try_from(index).expect("small"); crate::WITHDRAWAL_HINT_SIZE],
                last_used_ms: u64::try_from(index).expect("small"),
            })
            .collect::<Vec<_>>();
        let txt = rapp_withdrawn_record(candidates).expect("record");
        let list = &txt.last().expect("hint list").value;
        assert_eq!(list.split(',').count(), crate::WITHDRAWN_RECORD_ENTRIES);
        assert!(!list.contains(&"00".repeat(crate::WITHDRAWAL_HINT_SIZE)));
    }

    /// The session phase of one stored pairing, both ends in memory.
    mod session_bridge {
        use super::{CREATED_AT_MS, PAIR_BYTE, RappPairRecord, RappPairVault, StoringVault};
        use crate::{
            STREAM_PROFILE,
            bindings::{RappBindingError, RappSessionBridge},
            operation_bridge::{
                RappBridgeAction, RappBridgeActionKind, RappCardKeyProfile, RappCardReader,
                RappCloseReason, RappOperationBridge, RappResultKind, RappSignatureAlgorithm,
            },
        };
        use std::sync::{Arc, Mutex};

        /// Monotonic instant the sessions start at.
        const NOW_MS: u64 = 1_000;
        const MAXIMUM_LIFETIME_MS: u64 = 300_000;
        const LIFETIME_MS: u64 = 60_000;
        const NONCE_BYTE: u8 = 0x5a;
        const OPERATION_BYTE: u8 = 0x71;
        const DIGEST_BYTE: u8 = 0xcc;
        const SHA256_DIGEST_SIZE: usize = 32;
        const OPERATION_ID_SIZE: usize = 16;
        const SESSION_READY_NONCE_SIZE: usize = 32;
        /// Opaque certificate bytes; the custodian relays what the card
        /// holds.
        const CERTIFICATE_BYTE: u8 = 0x30;
        const CERTIFICATE_SIZE: usize = 64;

        fn vault() -> Arc<dyn RappPairVault> {
            Arc::new(StoringVault {
                bytes: Vec::new(),
                revoked: Mutex::new(false),
            })
        }

        fn requester_record() -> Arc<RappPairRecord> {
            super::requester()
        }

        fn custodian_record() -> Arc<RappPairRecord> {
            super::custodian(PAIR_BYTE)
        }

        /// Both ends after the Noise KK handshake, awaiting `session.ready`.
        fn authenticating(
            requester: &Arc<RappPairRecord>,
            custodian: &Arc<RappPairRecord>,
        ) -> (Arc<RappSessionBridge>, Arc<RappSessionBridge>) {
            let requester = RappSessionBridge::begin_requester(
                Arc::clone(requester),
                vault(),
                STREAM_PROFILE.to_owned(),
            )
            .expect("requester session starts");
            let custodian = RappSessionBridge::begin_proxy(
                Arc::clone(custodian),
                vault(),
                STREAM_PROFILE.to_owned(),
            )
            .expect("custodian session starts");
            custodian
                .read_handshake_frame(requester.write_handshake_frame().expect("message one"))
                .expect("custodian reads message one");
            requester
                .read_handshake_frame(custodian.write_handshake_frame().expect("message two"))
                .expect("requester reads message two");
            requester
                .enter_authentication()
                .expect("requester authenticates");
            custodian
                .enter_authentication()
                .expect("custodian authenticates");
            (requester, custodian)
        }

        fn nonce() -> Vec<u8> {
            vec![NONCE_BYTE; SESSION_READY_NONCE_SIZE]
        }

        /// Both ends healthy, with their operation bridges.
        fn established() -> (Arc<RappOperationBridge>, Arc<RappOperationBridge>) {
            established_with(&requester_record(), &custodian_record())
        }

        /// Both ends of the given records healthy, with their operation
        /// bridges.
        fn established_with(
            requester: &Arc<RappPairRecord>,
            custodian: &Arc<RappPairRecord>,
        ) -> (Arc<RappOperationBridge>, Arc<RappOperationBridge>) {
            let (requester, custodian) = authenticating(requester, custodian);
            let ready = custodian
                .send_ready(nonce())
                .expect("custodian sends ready");
            custodian.enter_established().expect("custodian is healthy");
            assert_eq!(
                requester
                    .receive_ready(ready, NOW_MS)
                    .expect("requester reads ready")
                    .kind,
                RappBridgeActionKind::NoAction
            );
            requester.enter_established().expect("requester is healthy");
            (
                RappOperationBridge::begin_requester(requester, MAXIMUM_LIFETIME_MS, NOW_MS)
                    .expect("requester operations"),
                RappOperationBridge::begin_proxy(custodian, MAXIMUM_LIFETIME_MS, NOW_MS)
                    .expect("custodian operations"),
            )
        }

        fn frame(action: RappBridgeAction) -> Vec<u8> {
            assert_eq!(action.kind, RappBridgeActionKind::SendFrame, "{action:?}");
            action.frame.expect("a frame to send")
        }

        fn operation_id() -> Vec<u8> {
            vec![OPERATION_BYTE; OPERATION_ID_SIZE]
        }

        #[test]
        fn only_the_custodian_sends_ready() {
            let (requester, custodian) = authenticating(&requester_record(), &custodian_record());
            assert!(matches!(
                requester.send_ready(nonce()),
                Err(RappBindingError::WrongPhase)
            ));
            let ready = custodian
                .send_ready(nonce())
                .expect("custodian sends ready");
            assert!(matches!(
                custodian.receive_ready(ready, NOW_MS),
                Err(RappBindingError::WrongPhase)
            ));
        }

        #[test]
        fn the_requester_learns_the_card_and_the_custodians_reader() {
            let (requester, custodian) = established();
            for (certificate, reader) in [
                (None, RappCardReader::Attached),
                (
                    Some(vec![CERTIFICATE_BYTE; CERTIFICATE_SIZE]),
                    RappCardReader::Attached,
                ),
                (None, RappCardReader::Absent),
                (
                    Some(vec![CERTIFICATE_BYTE; CERTIFICATE_SIZE]),
                    RappCardReader::Absent,
                ),
            ] {
                let present = certificate.is_some();
                let action = requester
                    .receive_frame(
                        frame(
                            custodian
                                .report_card_status(certificate, reader)
                                .expect("card status"),
                        ),
                        NOW_MS,
                    )
                    .expect("requester reads the card status");
                assert_eq!(action.kind, RappBridgeActionKind::CardStatus);
                assert_eq!(action.card_present, Some(present));
                assert_eq!(action.certificate_fingerprint.is_some(), present);
                assert_eq!(action.card_reader, Some(reader));
            }
        }

        #[test]
        fn a_read_is_served_without_consent() {
            let (requester, custodian) = established();
            requester
                .receive_frame(
                    frame(
                        custodian
                            .report_card_status(None, RappCardReader::Absent)
                            .expect("card status"),
                    ),
                    NOW_MS,
                )
                .expect("requester reads the card status");
            let request = frame(
                requester
                    .begin_read_certificate(operation_id(), false, NOW_MS, LIFETIME_MS)
                    .expect("requester asks"),
            );
            assert_eq!(
                custodian
                    .receive_frame(request, NOW_MS)
                    .expect("custodian admits")
                    .kind,
                RappBridgeActionKind::InspectPrerequisites
            );
            assert_eq!(
                custodian
                    .prerequisites_complete(operation_id(), NOW_MS)
                    .expect("the read has the card")
                    .kind,
                RappBridgeActionKind::ExecuteSafeRead
            );
            let result = frame(
                custodian
                    .complete_certificate(operation_id(), vec![CERTIFICATE_BYTE; CERTIFICATE_SIZE])
                    .expect("completion"),
            );
            let completed = requester
                .receive_frame(result, NOW_MS)
                .expect("requester reads the result");
            assert_eq!(completed.kind, RappBridgeActionKind::Completed);
            assert_eq!(
                completed.result.expect("an answer").kind,
                RappResultKind::Certificate
            );
        }

        #[test]
        fn closing_tells_the_custodian_its_card_command_runs_on() {
            let (requester, custodian) = established();
            let request = frame(
                requester
                    .begin_browser_authentication(
                        operation_id(),
                        "https://example.org".to_owned(),
                        RappCardKeyProfile::EcdsaP256,
                        RappSignatureAlgorithm::EcdsaSha256,
                        vec![DIGEST_BYTE; SHA256_DIGEST_SIZE],
                        NOW_MS,
                        LIFETIME_MS,
                    )
                    .expect("requester asks"),
            );
            custodian
                .receive_frame(request, NOW_MS)
                .expect("custodian admits");
            assert_eq!(
                custodian
                    .prerequisites_complete(operation_id(), NOW_MS)
                    .expect("consent")
                    .kind,
                RappBridgeActionKind::AwaitUserApproval
            );
            assert_eq!(
                custodian
                    .approve(operation_id(), NOW_MS)
                    .expect("approval")
                    .kind,
                RappBridgeActionKind::ExecuteCardCommand
            );
            let closed = custodian.close_session().expect("close");
            assert_eq!(closed.kind, RappBridgeActionKind::SessionClosed);
            assert_eq!(closed.operation_id, Some(operation_id()));
            assert!(closed.card_exchange_continues);
        }

        #[test]
        fn a_requester_withdrawal_reaches_the_custodian_and_ends_its_operation() {
            let (requester, custodian) = established();
            let request = frame(
                requester
                    .begin_read_certificate(operation_id(), false, NOW_MS, LIFETIME_MS)
                    .expect("requester asks"),
            );
            assert_eq!(
                custodian
                    .receive_frame(request, NOW_MS)
                    .expect("custodian admits")
                    .kind,
                RappBridgeActionKind::InspectPrerequisites
            );
            let notice = requester
                .close_with_reason(RappCloseReason::ServiceWithdrawn)
                .expect("the requester withdraws");
            assert!(notice.close_session_after_send);
            assert_eq!(notice.close_reason, Some(RappCloseReason::ServiceWithdrawn));
            assert_eq!(notice.operation_id, Some(operation_id()));
            let closed = custodian
                .receive_frame(frame(notice), NOW_MS)
                .expect("custodian reads the close");
            assert_eq!(closed.kind, RappBridgeActionKind::SessionClosed);
            assert_eq!(closed.close_reason, Some(RappCloseReason::ServiceWithdrawn));
            assert_eq!(closed.operation_id, Some(operation_id()));
            assert!(!closed.card_exchange_continues);
            assert!(matches!(
                custodian.report_card_status(None, RappCardReader::Absent),
                Err(RappBindingError::WrongPhase)
            ));
        }

        #[test]
        fn a_withdrawal_in_either_direction_keeps_the_pairing() {
            let requester_record = requester_record();
            let custodian_record = custodian_record();
            for requester_withdraws in [true, false] {
                let (requester, custodian) = established_with(&requester_record, &custodian_record);
                let (withdrawing, peer) = if requester_withdraws {
                    (&requester, &custodian)
                } else {
                    (&custodian, &requester)
                };
                let notice = withdrawing
                    .close_with_reason(RappCloseReason::ServiceWithdrawn)
                    .expect("the endpoint withdraws");
                let closed = peer
                    .receive_frame(frame(notice), NOW_MS)
                    .expect("the peer reads the close");
                assert_eq!(closed.kind, RappBridgeActionKind::SessionClosed);
                assert_eq!(closed.close_reason, Some(RappCloseReason::ServiceWithdrawn));
            }
            let (requester, custodian) = established_with(&requester_record, &custodian_record);
            let status = requester
                .receive_frame(
                    frame(
                        custodian
                            .report_card_status(None, RappCardReader::Absent)
                            .expect("card status"),
                    ),
                    NOW_MS,
                )
                .expect("the next session carries the card status");
            assert_eq!(status.kind, RappBridgeActionKind::CardStatus);
        }

        #[test]
        fn a_forgotten_custodian_record_sends_the_close_in_place_of_ready() {
            let custodian_record = custodian_record();
            custodian_record
                .forget(vault(), CREATED_AT_MS)
                .expect("forget");
            let (requester, custodian) = authenticating(&requester_record(), &custodian_record);
            assert!(matches!(
                custodian.send_ready(nonce()),
                Err(RappBindingError::WrongPhase)
            ));
            let notice = custodian
                .deliver_revocation_notice()
                .expect("the close is the first message");
            let closed = requester
                .receive_ready(notice, NOW_MS)
                .expect("requester reads the close");
            assert_eq!(closed.kind, RappBridgeActionKind::SessionClosed);
            assert_eq!(closed.close_reason, Some(RappCloseReason::PairingRevoked));
            assert!(matches!(
                requester.enter_established(),
                Err(RappBindingError::WrongPhase)
            ));
        }

        #[test]
        fn a_forgotten_requester_record_sends_the_close_as_its_first_message() {
            let requester_record = requester_record();
            requester_record
                .forget(vault(), CREATED_AT_MS)
                .expect("forget");
            let (requester, custodian) = authenticating(&requester_record, &custodian_record());
            custodian
                .send_ready(nonce())
                .expect("custodian sends ready");
            custodian.enter_established().expect("custodian is healthy");
            let custodian =
                RappOperationBridge::begin_proxy(custodian, MAXIMUM_LIFETIME_MS, NOW_MS)
                    .expect("custodian operations");
            let notice = requester
                .deliver_revocation_notice()
                .expect("the close is the first message");
            let closed = custodian
                .receive_frame(notice, NOW_MS)
                .expect("custodian reads the close");
            assert_eq!(closed.kind, RappBridgeActionKind::SessionClosed);
            assert_eq!(closed.close_reason, Some(RappCloseReason::PairingRevoked));
        }
    }
}
