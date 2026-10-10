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

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use super::{
    BinaryFrame, CpaceAttemptLedger, CpaceKc2Initiator, CpaceKc2Responder,
    CpaceKc2ResponderWaiting, EndpointRole, EstablishedEndpoint, ExplicitUserIntent, OfferId,
    POST_PAKE_CONFIRMATION_MS, POST_PAKE_HANDSHAKE_MS, PairId, PairKeyMaterial, PairRecord,
    PairStore, PairStoreError, PairTombstone, PairingBackoff, PairingConfirmation, PairingError,
    PairingHandshake, PairingOffer, PairingOfferDeadline, PairingSecret,
    PreAuthenticationRateLimit, ProfileName, RendezvousToken, STREAM_PROFILE,
    SessionAuthentication, SessionHandshake, SessionId, StreamRendezvous, TransportProfile,
    WireValue, encode_kc2_step1_frame, generate_pair_key_material, phase_deadline_ms,
    standard_pairing_context_v2,
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
    /// Pair-specific transport rendezvous token bytes.
    pub rendezvous_token: Vec<u8>,
    /// Pair-record creation time supplied by the platform wall clock.
    pub created_at_ms: u64,
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
    /// Authenticated protocol or cryptographic processing failed.
    ProtocolFailure,
    /// Local synchronization state was poisoned and cannot be reused.
    LocalStateFailure,
    /// Requested active pair record was not present in device-only storage.
    PairNotFound,
    /// Referenced operation was not found in the active session.
    UnknownOperation,
    /// Three pairing attempts failed against one offer; the offer is
    /// destroyed (RAPP v26.10.9 §3.3).
    AttemptsExhausted,
    /// A pre-authentication attempt came within 500 ms of the previous one
    /// (RAPP v26.10.9 §3.3.8); the caller refuses it and changes nothing.
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
    /// Create the custodian's offer (RAPP v26.10.9 §4.2) from a fresh
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
    /// transport `transport_profile` (RAPP v26.10.9 §4.2): the Bootstrap
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
            | PairingBridgeState::Confirmation { .. } => Ok(()),
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
    /// confirmation and storage must follow within 10 seconds of
    /// `now_monotonic_ms` (§3.3.7).
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

    /// Complete equal human confirmation and retain the resulting pair record
    /// in an opaque Rust object. No private key bytes are returned to Swift.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase or incomplete or unequal
    /// confirmations.
    pub fn finish_pairing(
        &self,
        created_at_ms: u64,
        now_monotonic_ms: u64,
    ) -> Result<Arc<RappPairRecord>, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Confirmation { confirmation, .. } = previous else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        let record = (*confirmation)
            .into_pair_record(created_at_ms)
            .map_err(|_| RappBindingError::ProtocolFailure)?;
        *state = PairingBridgeState::Completed;
        drop(state);
        Ok(Arc::new(RappPairRecord {
            record: Mutex::new(Some(record)),
        }))
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
/// `candidate_id` (RAPP v26.10.9 §6.1.1).
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
mod discovery_hint_tests {
    use super::{RappBindingError, rapp_discovery_hint};

    /// Seconds into the window the corpus vector names, so the export
    /// must divide by the window length rather than take an epoch.
    const SECONDS_INTO_WINDOW: u64 = 899;

    #[test]
    fn export_matches_the_corpus_window_from_wall_time() {
        let token = hex::decode("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a").expect("token hex");
        let epoch_start = 1_990_560 * crate::DISCOVERY_HINT_EPOCH_SECONDS;
        let hint = rapp_discovery_hint(token, epoch_start + SECONDS_INTO_WINDOW).expect("hint");
        assert_eq!(hex::encode(hint), "96b4d41e75873658");
    }

    #[test]
    fn wrong_size_token_is_refused() {
        assert!(matches!(
            rapp_discovery_hint(vec![0; 15], 0),
            Err(RappBindingError::InvalidInput)
        ));
    }
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
            .finish_pairing(at + 12, at + 12)
            .expect("requester finishes pairing")
            .metadata()
            .expect("requester metadata");
        let custodian_record = custodian
            .finish_pairing(at + 12, at + 12)
            .expect("custodian finishes pairing")
            .metadata()
            .expect("custodian metadata");
        assert_eq!(requester_record.pair_id, custodian_record.pair_id);
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
            requester.finish_pairing(at, at + 10),
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
}

/// The custodian's process-wide backoff after locked-out offers
/// (RAPP v26.10.9 §3.3.7), driven by platform monotonic milliseconds.
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

    /// This pairing's withdrawal hint for the advertised service instance
    /// `instance_name` in the minute containing `unix_time_seconds`
    /// (RAPP section 4.5).
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on an instance name that is not one
    /// DNS label or a degenerate static agreement, and
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

    /// Irreversibly delete active secret material and retain only a local
    /// tombstone. The in-memory private key is dropped only after the vault
    /// confirms deletion.
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
        let pair_id = record
            .as_ref()
            .ok_or(RappBindingError::WrongPhase)?
            .pair_id();
        vault
            .revoke_device_only(pair_id.as_bytes().to_vec(), revoked_at_ms)
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        record.take();
        drop(record);
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

#[derive(Clone)]
pub(super) struct BindingPairStore {
    pair_id: PairId,
    pair: Arc<RappPairRecord>,
    vault: Arc<dyn RappPairVault>,
}

impl PairStore for BindingPairStore {
    type Error = RappVaultError;

    fn load(&mut self, pair_id: PairId) -> Result<Option<PairRecord>, Self::Error> {
        let Some(bytes) = self.vault.load_device_only(pair_id.as_bytes().to_vec())? else {
            return Ok(None);
        };
        decode_pair_record(&bytes)
            .map(Some)
            .map_err(|_| RappVaultError::Unavailable)
    }

    fn insert(&mut self, record: PairRecord) -> Result<(), PairStoreError<Self::Error>> {
        let pair_id = record.pair_id().as_bytes().to_vec();
        let bytes = encode_pair_record(&record)
            .map_err(|_| PairStoreError::Backend(RappVaultError::Unavailable))?;
        self.vault
            .insert_device_only(pair_id, bytes)
            .map_err(PairStoreError::Backend)
    }

    fn revoke(&mut self, tombstone: PairTombstone) -> Result<(), PairStoreError<Self::Error>> {
        if tombstone.pair_id != self.pair_id {
            return Err(PairStoreError::PairNotFound);
        }
        self.vault
            .revoke_device_only(
                tombstone.pair_id.as_bytes().to_vec(),
                tombstone.revoked_at_ms,
            )
            .map_err(PairStoreError::Backend)?;
        self.pair
            .record
            .lock()
            .map_err(|_| PairStoreError::Backend(RappVaultError::Unavailable))?
            .take();
        Ok(())
    }

    fn is_revoked(&mut self, pair_id: PairId) -> Result<bool, Self::Error> {
        self.vault.is_revoked(pair_id.as_bytes().to_vec())
    }
}

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
    pub(super) pair_store: Mutex<BindingPairStore>,
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

    /// Enter exact bilateral `session.ready` authentication.
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

    /// Send the exact session parameters with a platform-CSPRNG nonce.
    ///
    /// # Errors
    /// [`RappBindingError`] on a wrong-size nonce, the wrong phase, or a
    /// duplicate or failed ready.
    pub fn send_ready(&self, nonce: Vec<u8>) -> Result<Vec<u8>, RappBindingError> {
        let nonce = fixed_array(nonce)?;
        let mut state = self.lock_state()?;
        let SessionBridgeState::Authentication(authentication) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let frame = authentication
            .send_ready(nonce)
            .map(BinaryFrame::into_bytes)
            .map_err(|_| RappBindingError::ProtocolFailure);
        drop(state);
        frame
    }

    /// Verify the peer's exact authenticated session parameters. The first
    /// attributable violation synchronously revokes device-only pair keys.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, an oversized frame, or an
    /// echo that fails verification.
    pub fn receive_ready(&self, bytes: Vec<u8>, now_ms: u64) -> Result<(), RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        let mut state = self.lock_state()?;
        let mut pair_store = self
            .pair_store
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let SessionBridgeState::Authentication(authentication) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        if authentication
            .receive_ready(&mut *pair_store, &frame, now_ms)
            .is_err()
        {
            *state = SessionBridgeState::Failed;
            drop(state);
            return Err(RappBindingError::ProtocolFailure);
        }
        drop(pair_store);
        Ok(())
    }

    /// Promote the mutually authenticated channel to healthy established use.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase or incomplete ready
    /// verification.
    pub fn enter_established(&self) -> Result<(), RappBindingError> {
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

    /// Whether exact bilateral ready verification produced a healthy session.
    ///
    /// # Errors
    /// [`RappBindingError::LocalStateFailure`] when the lock is poisoned.
    pub fn is_established(&self) -> Result<bool, RappBindingError> {
        let state = self.lock_state()?;
        Ok(matches!(&*state, SessionBridgeState::Established(_)))
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
        .map_err(|_| RappBindingError::ProtocolFailure)?;
        let pair_id = pair_record.pair_id();
        drop(pair_guard);
        Ok(Arc::new(Self {
            state: Mutex::new(SessionBridgeState::Handshake(Box::new(handshake))),
            pair_store: Mutex::new(BindingPairStore {
                pair_id,
                pair,
                vault,
            }),
            session_id: Mutex::new(None),
        }))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, SessionBridgeState>, RappBindingError> {
        self.state
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)
    }

    pub(super) fn take_established(
        &self,
    ) -> Result<
        (
            EstablishedEndpoint,
            BindingPairStore,
            PairId,
            SessionId,
            Vec<ProfileName>,
        ),
        RappBindingError,
    > {
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

        let pair_store = self
            .pair_store
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .clone();
        let pair_id = pair_store.pair_id;
        let profiles = pair_store
            .pair
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .as_ref()
            .ok_or(RappBindingError::PairNotFound)?
            .profiles()
            .to_vec();
        let session_id = self
            .session_id
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?
            .ok_or(RappBindingError::WrongPhase)?;
        Ok((endpoint, pair_store, pair_id, session_id, profiles))
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
        rendezvous_token: record.rendezvous_token().as_bytes().to_vec(),
        created_at_ms: record.created_at_ms(),
    }
}

/// Preamble frame payload the dialing proxy sends to reach the listener's
/// active pairing offer on the stream profile.
#[uniffi::export]
#[must_use]
pub fn rapp_stream_pairing_preamble() -> Vec<u8> {
    StreamRendezvous::Pairing.encode().unwrap_or_default()
}

/// Preamble frame payload the dialing proxy sends to open a fresh session
/// for the stored pairing this rendezvous token names.
///
/// # Errors
/// [`RappBindingError`] on a wrong-size token or an encoding failure.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "uniffi lowers exported arguments as owned values"
)]
pub fn rapp_stream_session_preamble(
    rendezvous_token: Vec<u8>,
) -> Result<Vec<u8>, RappBindingError> {
    let token = RendezvousToken::reconstruct(&rendezvous_token)
        .map_err(|_| RappBindingError::InvalidInput)?;
    StreamRendezvous::Session(token)
        .encode()
        .map_err(|_| RappBindingError::ProtocolFailure)
}

/// Registered stream transport profile name.
#[uniffi::export]
#[must_use]
pub fn rapp_stream_profile_name() -> String {
    STREAM_PROFILE.to_owned()
}

/// Rotating discovery hint of one stored pairing for the 15-minute window
/// containing `unix_time_seconds` (hierarchy specification section 4.3).
///
/// A custodian publishes the hints of the current window; a requester
/// compares its own pairings against the current and adjacent windows.
///
/// # Errors
/// [`RappBindingError::InvalidInput`] on a wrong-size token.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "uniffi lowers exported arguments as owned values"
)]
pub fn rapp_discovery_hint(
    rendezvous_token: Vec<u8>,
    unix_time_seconds: u64,
) -> Result<Vec<u8>, RappBindingError> {
    let token = RendezvousToken::reconstruct(&rendezvous_token)
        .map_err(|_| RappBindingError::InvalidInput)?;
    Ok(super::discovery_hint(
        &token,
        unix_time_seconds / super::DISCOVERY_HINT_EPOCH_SECONDS,
    )
    .to_vec())
}

impl RappPairRecord {
    fn withdrawal_key(&self) -> Result<super::WithdrawalKey, RappBindingError> {
        let guard = self
            .record
            .lock()
            .map_err(|_| RappBindingError::LocalStateFailure)?;
        let record = guard.as_ref().ok_or(RappBindingError::WrongPhase)?;
        let key = super::WithdrawalKey::derive(record).map_err(|_| RappBindingError::InvalidInput);
        drop(guard);
        key
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

/// The TXT attributes of a `mode=withdrawn` record carrying `hints`, the
/// withdrawal hints of the custodian's stored pairings, padded to eight
/// entries with random fillers and shuffled (RAPP section 4.5).
///
/// # Errors
/// [`RappBindingError::InvalidInput`] for more than eight hints or a hint of
/// the wrong size, and [`RappBindingError::LocalStateFailure`] when the
/// random source fails.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "uniffi lowers exported arguments as owned values"
)]
pub fn rapp_withdrawn_record(hints: Vec<Vec<u8>>) -> Result<Vec<RappTxtEntry>, RappBindingError> {
    let hints = hints
        .iter()
        .map(|hint| {
            <[u8; super::WITHDRAWAL_HINT_SIZE]>::try_from(hint.as_slice())
                .map_err(|_| RappBindingError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let record = super::WithdrawnRecord::assemble(&hints, |bytes| {
        getrandom::fill(bytes).map_err(|_| super::WithdrawalError::RandomUnavailable)
    })
    .map_err(|error| match error {
        super::WithdrawalError::RandomUnavailable => RappBindingError::LocalStateFailure,
        _ => RappBindingError::InvalidInput,
    })?;
    Ok(record
        .txt_entries()
        .into_iter()
        .map(|(key, value)| RappTxtEntry {
            key: key.to_owned(),
            value,
        })
        .collect())
}

fn encode_pair_record(record: &PairRecord) -> Result<Vec<u8>, RappBindingError> {
    super::encode_pair_record(record).map_err(|_| RappBindingError::ProtocolFailure)
}

fn decode_pair_record(bytes: &[u8]) -> Result<PairRecord, RappBindingError> {
    super::decode_pair_record(bytes).map_err(|_| RappBindingError::InvalidInput)
}

pub(super) fn take_value(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<WireValue, RappBindingError> {
    map.remove(key).ok_or(RappBindingError::InvalidInput)
}

pub(super) fn take_bytes(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<Vec<u8>, RappBindingError> {
    match take_value(map, key)? {
        WireValue::Bytes(value) => Ok(value),
        _ => Err(RappBindingError::InvalidInput),
    }
}

pub(super) fn take_text(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<String, RappBindingError> {
    match take_value(map, key)? {
        WireValue::Text(value) => Ok(value),
        _ => Err(RappBindingError::InvalidInput),
    }
}

pub(super) fn take_unsigned(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<u64, RappBindingError> {
    match take_value(map, key)? {
        WireValue::Unsigned(value) => Ok(value),
        _ => Err(RappBindingError::InvalidInput),
    }
}

/// The BLE segmentation and reassembly receiver for one connection and one
/// direction (RAPP v26.10.9 §5.3).
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
/// any smaller value limit the platform reports (RAPP v26.10.9 §5.3).
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
