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
    BinaryFrame, EndpointRole, EstablishedEndpoint, ExplicitUserIntent, GrantsHash,
    MANDATORY_PAIRING_SUITE, OfferId, PairId, PairRecord, PairStore, PairStoreError, PairTombstone,
    PairTransportBinding, PairingConfirmation, PairingHandshake, PairingOffer,
    PairingOfferDeadline, PairingOfferUri, PairingSecret, ProfileName, RendezvousToken,
    STREAM_PROFILE, SessionAuthentication, SessionHandshake, SessionId, StreamCandidateParameters,
    StreamRendezvous, TransportCandidate, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor, generate_pair_key_material,
};

const PAIR_RECORD_FORMAT_VERSION: u64 = 2;

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
    /// Pairing secret length in bytes.
    pub pairing_secret: u64,
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
        pairing_secret: super::PAIRING_SECRET_SIZE as u64,
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

/// Public rendezvous candidate placed in the one-use QR offer.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappTransportCandidate {
    /// Registered transport profile.
    pub profile: String,
    /// Opaque identifier echoed after peer authentication.
    pub candidate_id: String,
    /// Deterministic-CBOR map of profile-specific public parameters.
    pub parameters_cbor: Vec<u8>,
}

/// One transport candidate of a live offer, for proxy-side selection.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappOfferCandidate {
    /// Registered transport profile.
    pub profile: String,
    /// Opaque identifier echoed after peer authentication.
    pub candidate_id: String,
    /// Decoded listener endpoints of a stream candidate; absent on other
    /// profiles.
    pub stream_endpoints: Option<Vec<String>>,
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
    /// Bound transport profile.
    pub transport_profile: String,
    /// Bound candidate identifier.
    pub candidate_id: String,
    /// Pair-specific transport rendezvous token bytes.
    pub rendezvous_token: Vec<u8>,
    /// Stored stream-profile listener endpoints; absent on other transports.
    pub stream_endpoints: Option<Vec<String>>,
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
}

impl core::fmt::Display for RappBindingError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for RappBindingError {}

enum PairingBridgeState {
    Offer {
        role: EndpointRole,
        offer: PairingOffer,
        deadline: PairingOfferDeadline,
    },
    Handshake {
        role: EndpointRole,
        handshake: Box<PairingHandshake>,
        deadline: PairingOfferDeadline,
    },
    Confirmation(Box<PairingConfirmation>),
    Completed,
    Expired,
    Failed,
}

impl PairingBridgeState {
    fn require_live_offer(&mut self, now_monotonic_ms: u64) -> Result<(), RappBindingError> {
        let deadline = match self {
            Self::Offer { deadline, .. } | Self::Handshake { deadline, .. } => *deadline,
            _ => return Ok(()),
        };
        if deadline.is_live(now_monotonic_ms) {
            return Ok(());
        }
        *self = Self::Expired;
        Err(RappBindingError::OfferExpired)
    }

    fn after_handshake_failure(
        role: EndpointRole,
        handshake: PairingHandshake,
        deadline: PairingOfferDeadline,
    ) -> Self {
        if role == EndpointRole::Requester && !handshake.is_complete() {
            return Self::Offer {
                role,
                offer: handshake.abort(),
                deadline,
            };
        }
        Self::Failed
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
}

#[uniffi::export]
impl RappPairingBridge {
    /// Construct the requester-owned one-use QR offer from platform CSPRNG
    /// bytes. The bearer secret is retained only inside this object.
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on wrong-size bytes or an offer
    /// that fails validation.
    #[uniffi::constructor]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn create_requester_offer(
        offer_id: Vec<u8>,
        pairing_secret: Vec<u8>,
        profiles: Vec<String>,
        transports: Vec<RappTransportCandidate>,
        offer_ttl_ms: u64,
        started_at_monotonic_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        let offer_id =
            OfferId::reconstruct(&offer_id).map_err(|_| RappBindingError::InvalidInput)?;
        let pairing_secret = fixed_array(pairing_secret)?;
        let transports = transports
            .into_iter()
            .map(transport_candidate)
            .collect::<Result<Vec<_>, _>>()?;
        let offer = PairingOffer::reconstruct(
            offer_id,
            PairingSecret::from_random_bytes(pairing_secret),
            vec![MANDATORY_PAIRING_SUITE.to_owned()],
            profiles,
            transports,
            offer_ttl_ms,
        )
        .map_err(|_| RappBindingError::InvalidInput)?;
        let deadline = PairingOfferDeadline::from_offer(&offer, started_at_monotonic_ms)
            .map_err(|_| RappBindingError::InvalidInput)?;
        Ok(Arc::new(Self {
            state: Mutex::new(PairingBridgeState::Offer {
                role: EndpointRole::Requester,
                offer,
                deadline,
            }),
        }))
    }

    /// Decode a scanned one-use QR offer for the authorization proxy.
    ///
    /// # Errors
    /// [`RappBindingError::InvalidInput`] on a URI that fails structural or
    /// policy validation.
    #[uniffi::constructor]
    pub fn from_scanned_offer(
        uri: String,
        started_at_monotonic_ms: u64,
    ) -> Result<Arc<Self>, RappBindingError> {
        let offer = PairingOffer::from_uri(PairingOfferUri::from_scanned_text(uri))
            .map_err(|_| RappBindingError::InvalidInput)?;
        let deadline = PairingOfferDeadline::from_offer(&offer, started_at_monotonic_ms)
            .map_err(|_| RappBindingError::InvalidInput)?;
        Ok(Arc::new(Self {
            state: Mutex::new(PairingBridgeState::Offer {
                role: EndpointRole::Proxy,
                offer,
                deadline,
            }),
        }))
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

    /// Transport candidates of the live offer, for the proxy's candidate
    /// selection. Stream candidates carry their decoded listener endpoints;
    /// a stream candidate whose parameters fail validation is omitted, and
    /// other profiles pass through with no endpoints. The platform selects
    /// exactly one candidate and hands its identifier to [`Self::begin`].
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
            .filter_map(|candidate| {
                let stream_endpoints = if candidate.profile == STREAM_PROFILE {
                    let parameters =
                        StreamCandidateParameters::from_parameters(&candidate.parameters).ok()?;
                    Some(parameters.endpoints().to_vec())
                } else {
                    None
                };
                Some(RappOfferCandidate {
                    profile: candidate.profile.clone(),
                    candidate_id: candidate.candidate_id.clone(),
                    stream_endpoints,
                })
            })
            .collect();
        drop(state);
        Ok(candidates)
    }

    /// Secret-bearing QR text. Available only while the requester owns the
    /// unconsumed offer.
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer, the wrong phase, or an
    /// encoding failure.
    pub fn offer_uri(&self, now_monotonic_ms: u64) -> Result<String, RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let PairingBridgeState::Offer {
            role: EndpointRole::Requester,
            offer,
            ..
        } = &*state
        else {
            return Err(RappBindingError::WrongPhase);
        };
        let uri = offer
            .to_uri()
            .map(|uri| uri.expose().to_owned())
            .map_err(|_| RappBindingError::ProtocolFailure);
        drop(state);
        uri
    }

    /// Consume the offer for exactly one selected transport candidate and
    /// start mandatory Noise `XXpsk3` with fresh pair-specific static keys.
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer, the wrong phase, or a
    /// handshake-construction failure that returns the live offer.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "uniffi lowers exported arguments as owned values"
    )]
    pub fn begin(
        &self,
        candidate_id: String,
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
        let Ok(local_keys) = generate_pair_key_material() else {
            *state = PairingBridgeState::Offer {
                role,
                offer,
                deadline,
            };
            return Err(RappBindingError::ProtocolFailure);
        };
        match PairingHandshake::begin(role, offer, &candidate_id, local_keys) {
            Ok(handshake) => {
                *state = PairingBridgeState::Handshake {
                    role,
                    handshake: Box::new(handshake),
                    deadline,
                };
                Ok(())
            }
            Err(failure) => {
                let (_, offer) = failure.into_parts();
                *state = PairingBridgeState::Offer {
                    role,
                    offer,
                    deadline,
                };
                drop(state);
                Err(RappBindingError::ProtocolFailure)
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
        let PairingBridgeState::Handshake {
            role,
            handshake,
            deadline,
        } = previous
        else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        let retained = role == EndpointRole::Requester && !handshake.is_complete();
        *state = PairingBridgeState::after_handshake_failure(role, *handshake, deadline);
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
            | PairingBridgeState::Handshake { .. }
            | PairingBridgeState::Confirmation(_) => Ok(()),
            PairingBridgeState::Expired | PairingBridgeState::Failed => Ok(()),
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
            role,
            mut handshake,
            deadline,
        } = previous
        else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        if let Ok(frame) = handshake.write_message() {
            *state = PairingBridgeState::Handshake {
                role,
                handshake,
                deadline,
            };
            Ok(frame.into_bytes())
        } else {
            *state = PairingBridgeState::after_handshake_failure(role, *handshake, deadline);
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
            role,
            mut handshake,
            deadline,
        } = previous
        else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        let Ok(frame) = BinaryFrame::reconstruct(bytes) else {
            *state = PairingBridgeState::after_handshake_failure(role, *handshake, deadline);
            return Err(RappBindingError::InvalidInput);
        };
        if matches!(handshake.read_message(&frame), Ok(())) {
            *state = PairingBridgeState::Handshake {
                role,
                handshake,
                deadline,
            };
            Ok(())
        } else {
            *state = PairingBridgeState::after_handshake_failure(role, *handshake, deadline);
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

    /// Destroy the QR bearer secret and enter authenticated human
    /// confirmation after Noise completes.
    ///
    /// # Errors
    /// [`RappBindingError`] on an expired offer, the wrong phase, or an
    /// incomplete handshake.
    pub fn enter_confirmation(&self, now_monotonic_ms: u64) -> Result<(), RappBindingError> {
        let mut state = self.lock()?;
        state.require_live_offer(now_monotonic_ms)?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Handshake {
            role,
            handshake,
            deadline,
        } = previous
        else {
            *state = previous;
            return Err(RappBindingError::WrongPhase);
        };
        match (*handshake).into_confirmation() {
            Ok(confirmation) => {
                *state = PairingBridgeState::Confirmation(Box::new(confirmation));
                Ok(())
            }
            Err(failure) => {
                let (_, offer) = failure.into_parts();
                *state = if role == EndpointRole::Requester {
                    PairingBridgeState::Offer {
                        role,
                        offer,
                        deadline,
                    }
                } else {
                    PairingBridgeState::Failed
                };
                Err(RappBindingError::ProtocolFailure)
            }
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
    ) -> Result<Vec<u8>, RappBindingError> {
        let mut state = self.lock()?;
        let PairingBridgeState::Confirmation(confirmation) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let frame = confirmation
            .send_hello(display_name, platform)
            .map(BinaryFrame::into_bytes)
            .map_err(|_| RappBindingError::ProtocolFailure);
        drop(state);
        frame
    }

    /// Verify the peer's authenticated label and exact parameter echo.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, an oversized frame, or a
    /// hello that fails verification.
    pub fn receive_hello(
        &self,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<RappPeerHello, RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        let mut state = self.lock()?;
        let PairingBridgeState::Confirmation(confirmation) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let hello = confirmation
            .receive_hello(&frame, now_ms)
            .map_err(|_| RappBindingError::ProtocolFailure)?;
        let peer = RappPeerHello {
            display_name: hello.display_name.clone(),
            platform: hello.platform.clone(),
            requested_profiles: hello.requested_profiles.as_ref().map(|profiles| {
                profiles
                    .iter()
                    .map(|profile| profile.as_str().to_owned())
                    .collect()
            }),
        };
        drop(state);
        Ok(peer)
    }

    /// Send the exact locally approved grant set.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, an invalid grant set, or a
    /// grant mismatch.
    pub fn send_confirmation(
        &self,
        granted_profiles: Vec<String>,
    ) -> Result<Vec<u8>, RappBindingError> {
        let granted_profiles = parse_profiles(granted_profiles)?;
        let mut state = self.lock()?;
        let PairingBridgeState::Confirmation(confirmation) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let frame = confirmation
            .send_confirmation(granted_profiles)
            .map(BinaryFrame::into_bytes)
            .map_err(|_| RappBindingError::ProtocolFailure);
        drop(state);
        frame
    }

    /// Verify and return the peer's exact grant set.
    ///
    /// # Errors
    /// [`RappBindingError`] on the wrong phase, an oversized frame, or a
    /// confirmation that fails verification.
    pub fn receive_confirmation(
        &self,
        bytes: Vec<u8>,
        now_ms: u64,
    ) -> Result<Vec<String>, RappBindingError> {
        let frame = BinaryFrame::reconstruct(bytes).map_err(|_| RappBindingError::InvalidInput)?;
        let mut state = self.lock()?;
        let PairingBridgeState::Confirmation(confirmation) = &mut *state else {
            return Err(RappBindingError::WrongPhase);
        };
        let profiles = confirmation
            .receive_confirmation(&frame, now_ms)
            .map(|profiles| {
                profiles
                    .iter()
                    .map(|profile| profile.as_str().to_owned())
                    .collect()
            })
            .map_err(|_| RappBindingError::ProtocolFailure);
        drop(state);
        profiles
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
    ) -> Result<Arc<RappPairRecord>, RappBindingError> {
        let mut state = self.lock()?;
        let previous = core::mem::replace(&mut *state, PairingBridgeState::Failed);
        let PairingBridgeState::Confirmation(confirmation) = previous else {
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
}

#[cfg(test)]
mod pairing_bridge_tests {
    use super::*;

    const STARTED_AT_MS: u64 = 1_000;
    const OFFER_TTL_MS: u64 = 60_000;
    const CANDIDATE_ID: &str = "candidate-1";

    fn requester_bridge() -> Arc<RappPairingBridge> {
        let counts = rapp_random_byte_counts();
        RappPairingBridge::create_requester_offer(
            vec![0x11; usize::try_from(counts.offer_id).expect("offer id size fits usize")],
            vec![
                0x22;
                usize::try_from(counts.pairing_secret).expect("pairing secret size fits usize")
            ],
            vec![ProfileName::Authentication.as_str().to_owned()],
            vec![RappTransportCandidate {
                profile: "local-quic-v1".into(),
                candidate_id: CANDIDATE_ID.into(),
                parameters_cbor: Vec::new(),
            }],
            OFFER_TTL_MS,
            STARTED_AT_MS,
        )
        .expect("requester offer is valid")
    }

    #[test]
    fn requester_handshake_garbage_retains_offer_and_original_deadline() {
        let requester = requester_bridge();
        let original_uri = requester
            .offer_uri(STARTED_AT_MS)
            .expect("requester exposes its live offer");

        requester
            .begin(CANDIDATE_ID.into(), STARTED_AT_MS + 1)
            .expect("first candidate starts");
        assert!(matches!(
            requester.read_handshake_frame(Vec::new(), STARTED_AT_MS + 2),
            Err(RappBindingError::ProtocolFailure)
        ));
        assert_eq!(
            requester
                .offer_uri(STARTED_AT_MS + 3)
                .expect("garbage does not consume requester offer"),
            original_uri
        );

        requester
            .begin(CANDIDATE_ID.into(), STARTED_AT_MS + 4)
            .expect("the same offer can start a replacement candidate");
        assert!(matches!(
            requester.write_handshake_frame(STARTED_AT_MS + OFFER_TTL_MS),
            Err(RappBindingError::OfferExpired)
        ));
        assert!(matches!(
            requester.offer_uri(STARTED_AT_MS + OFFER_TTL_MS),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn proxy_handshake_garbage_discards_candidate_without_reusing_offer() {
        let requester = requester_bridge();
        let uri = requester
            .offer_uri(STARTED_AT_MS)
            .expect("requester exposes its live offer");
        let proxy = RappPairingBridge::from_scanned_offer(uri, STARTED_AT_MS)
            .expect("proxy scans the offer");

        proxy
            .begin(CANDIDATE_ID.into(), STARTED_AT_MS + 1)
            .expect("proxy candidate starts");
        assert!(matches!(
            proxy.read_handshake_frame(Vec::new(), STARTED_AT_MS + 2),
            Err(RappBindingError::ProtocolFailure)
        ));
        assert!(matches!(
            proxy.begin(CANDIDATE_ID.into(), STARTED_AT_MS + 3),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn explicit_candidate_failure_retains_only_requester_offer() {
        let requester = requester_bridge();
        let uri = requester
            .offer_uri(STARTED_AT_MS)
            .expect("requester exposes its live offer");
        let proxy = RappPairingBridge::from_scanned_offer(uri, STARTED_AT_MS)
            .expect("proxy scans the offer");
        requester
            .begin(CANDIDATE_ID.into(), STARTED_AT_MS + 1)
            .expect("requester candidate starts");
        proxy
            .begin(CANDIDATE_ID.into(), STARTED_AT_MS + 1)
            .expect("proxy candidate starts");

        assert!(
            requester
                .candidate_failed(STARTED_AT_MS + 2)
                .expect("requester discards candidate")
        );
        assert!(requester.offer_uri(STARTED_AT_MS + 3).is_ok());
        assert!(
            !proxy
                .candidate_failed(STARTED_AT_MS + 2)
                .expect("proxy discards candidate")
        );
        assert!(matches!(
            proxy.begin(CANDIDATE_ID.into(), STARTED_AT_MS + 3),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn cancellation_consumes_offer() {
        let requester = requester_bridge();
        requester
            .cancel_pairing()
            .expect("active offer can be cancelled");
        assert!(matches!(
            requester.offer_uri(STARTED_AT_MS + 1),
            Err(RappBindingError::WrongPhase)
        ));
        assert!(matches!(
            requester.begin(CANDIDATE_ID.into(), STARTED_AT_MS + 1),
            Err(RappBindingError::WrongPhase)
        ));
    }

    #[test]
    fn authenticated_handshake_consumes_requester_offer() {
        let requester = requester_bridge();
        let uri = requester
            .offer_uri(STARTED_AT_MS)
            .expect("requester exposes its live offer");
        let proxy = RappPairingBridge::from_scanned_offer(uri, STARTED_AT_MS)
            .expect("proxy scans the offer");
        requester
            .begin(CANDIDATE_ID.into(), STARTED_AT_MS + 1)
            .expect("requester candidate starts");
        proxy
            .begin(CANDIDATE_ID.into(), STARTED_AT_MS + 1)
            .expect("proxy candidate starts");

        let first = requester
            .write_handshake_frame(STARTED_AT_MS + 2)
            .expect("requester emits Noise message one");
        proxy
            .read_handshake_frame(first, STARTED_AT_MS + 2)
            .expect("proxy accepts Noise message one");
        let second = proxy
            .write_handshake_frame(STARTED_AT_MS + 3)
            .expect("proxy emits Noise message two");
        requester
            .read_handshake_frame(second, STARTED_AT_MS + 3)
            .expect("requester accepts Noise message two");
        let third = requester
            .write_handshake_frame(STARTED_AT_MS + 4)
            .expect("requester emits Noise message three");
        proxy
            .read_handshake_frame(third, STARTED_AT_MS + 4)
            .expect("proxy accepts Noise message three");

        assert!(
            requester
                .handshake_complete(STARTED_AT_MS + 5)
                .expect("requester completion is readable")
        );
        requester
            .enter_confirmation(STARTED_AT_MS + 5)
            .expect("authenticated requester enters confirmation");
        assert!(matches!(
            requester.offer_uri(STARTED_AT_MS + 6),
            Err(RappBindingError::WrongPhase)
        ));
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
    /// Begin a requester session only after a fresh local user action.
    ///
    /// # Errors
    /// [`RappBindingError`] on a revoked or absent pair, a role mismatch, or
    /// a handshake-construction failure.
    #[uniffi::constructor]
    pub fn begin_requester(
        pair: Arc<RappPairRecord>,
        vault: Arc<dyn RappPairVault>,
    ) -> Result<Arc<Self>, RappBindingError> {
        Self::begin_session(pair, vault, EndpointRole::Requester)
    }

    /// Begin the proxy response to one incoming transport candidate.
    ///
    /// # Errors
    /// [`RappBindingError`] on a revoked or absent pair, a role mismatch, or
    /// a handshake-construction failure.
    #[uniffi::constructor]
    pub fn begin_proxy(
        pair: Arc<RappPairRecord>,
        vault: Arc<dyn RappPairVault>,
    ) -> Result<Arc<Self>, RappBindingError> {
        Self::begin_session(pair, vault, EndpointRole::Proxy)
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
    ) -> Result<Arc<Self>, RappBindingError> {
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
            EndpointRole::Requester => {
                SessionHandshake::begin_requester(pair_record, ExplicitUserIntent::record())
            }
            EndpointRole::Proxy => SessionHandshake::begin_proxy(pair_record),
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

fn transport_candidate(
    candidate: RappTransportCandidate,
) -> Result<TransportCandidate, RappBindingError> {
    let parameters = if candidate.parameters_cbor.is_empty() {
        BTreeMap::new()
    } else {
        let WireValue::Map(parameters) = decode_deterministic_cbor(&candidate.parameters_cbor)
            .map_err(|_| RappBindingError::InvalidInput)?
        else {
            return Err(RappBindingError::InvalidInput);
        };
        parameters
    };
    Ok(TransportCandidate {
        profile: candidate.profile,
        candidate_id: candidate.candidate_id,
        parameters,
    })
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
        transport_profile: record.transport().profile.clone(),
        candidate_id: record.transport().candidate_id.clone(),
        rendezvous_token: record.rendezvous_token().as_bytes().to_vec(),
        stream_endpoints: (record.transport().profile == STREAM_PROFILE)
            .then(|| {
                StreamCandidateParameters::from_parameters(&record.transport().parameters)
                    .ok()
                    .map(|parameters| parameters.endpoints().to_vec())
            })
            .flatten(),
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

fn encode_pair_record(record: &PairRecord) -> Result<Vec<u8>, RappBindingError> {
    let role = match record.role() {
        EndpointRole::Requester => "requester",
        EndpointRole::Proxy => "proxy",
    };
    let value = WireValue::Map(BTreeMap::from([
        (
            "format_version".to_owned(),
            WireValue::Unsigned(PAIR_RECORD_FORMAT_VERSION),
        ),
        (
            "pair_id".to_owned(),
            WireValue::Bytes(record.pair_id().as_bytes().to_vec()),
        ),
        (
            "rendezvous_token".to_owned(),
            WireValue::Bytes(record.rendezvous_token().as_bytes().to_vec()),
        ),
        ("role".to_owned(), WireValue::Text(role.to_owned())),
        (
            "local_static_private".to_owned(),
            WireValue::Bytes(record.local_static_private().to_vec()),
        ),
        (
            "local_static_public".to_owned(),
            WireValue::Bytes(record.local_static_public().to_vec()),
        ),
        (
            "remote_static_public".to_owned(),
            WireValue::Bytes(record.remote_static_public().to_vec()),
        ),
        (
            "grants_hash".to_owned(),
            WireValue::Bytes(record.grants_hash().as_bytes().to_vec()),
        ),
        (
            "profiles".to_owned(),
            WireValue::Array(
                record
                    .profiles()
                    .iter()
                    .map(|profile| WireValue::Text(profile.as_str().to_owned()))
                    .collect(),
            ),
        ),
        (
            "transport_profile".to_owned(),
            WireValue::Text(record.transport().profile.clone()),
        ),
        (
            "candidate_id".to_owned(),
            WireValue::Text(record.transport().candidate_id.clone()),
        ),
        (
            "transport_parameters".to_owned(),
            WireValue::Map(record.transport().parameters.clone()),
        ),
        (
            "created_at_ms".to_owned(),
            WireValue::Unsigned(record.created_at_ms()),
        ),
    ]));
    encode_deterministic_cbor(&value).map_err(|_| RappBindingError::ProtocolFailure)
}

fn decode_pair_record(bytes: &[u8]) -> Result<PairRecord, RappBindingError> {
    let WireValue::Map(mut map) =
        decode_deterministic_cbor(bytes).map_err(|_| RappBindingError::InvalidInput)?
    else {
        return Err(RappBindingError::InvalidInput);
    };
    let expected = [
        "format_version",
        "pair_id",
        "rendezvous_token",
        "role",
        "local_static_private",
        "local_static_public",
        "remote_static_public",
        "grants_hash",
        "profiles",
        "transport_profile",
        "candidate_id",
        "transport_parameters",
        "created_at_ms",
    ];
    if map.keys().any(|key| !expected.contains(&key.as_str())) {
        return Err(RappBindingError::InvalidInput);
    }
    if take_unsigned(&mut map, "format_version")? != PAIR_RECORD_FORMAT_VERSION {
        return Err(RappBindingError::InvalidInput);
    }
    let pair_id = PairId::reconstruct(&take_bytes(&mut map, "pair_id")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let rendezvous_token = RendezvousToken::reconstruct(&take_bytes(&mut map, "rendezvous_token")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let role = match take_text(&mut map, "role")?.as_str() {
        "requester" => EndpointRole::Requester,
        "proxy" => EndpointRole::Proxy,
        _ => return Err(RappBindingError::InvalidInput),
    };
    let local_static_private = fixed_array(take_bytes(&mut map, "local_static_private")?)?;
    let local_static_public = fixed_array(take_bytes(&mut map, "local_static_public")?)?;
    let remote_static_public = fixed_array(take_bytes(&mut map, "remote_static_public")?)?;
    let grants_hash = GrantsHash::reconstruct(&take_bytes(&mut map, "grants_hash")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let profiles = take_text_array(&mut map, "profiles")?
        .into_iter()
        .map(|name| ProfileName::parse(&name).ok_or(RappBindingError::InvalidInput))
        .collect::<Result<Vec<_>, _>>()?;
    let transport = PairTransportBinding {
        profile: take_text(&mut map, "transport_profile")?,
        candidate_id: take_text(&mut map, "candidate_id")?,
        parameters: take_map(&mut map, "transport_parameters")?,
    };
    let created_at_ms = take_unsigned(&mut map, "created_at_ms")?;
    if !map.is_empty() {
        return Err(RappBindingError::InvalidInput);
    }
    PairRecord::new(
        pair_id,
        rendezvous_token,
        role,
        local_static_private,
        local_static_public,
        remote_static_public,
        grants_hash,
        profiles,
        transport,
        created_at_ms,
    )
    .map_err(|_| RappBindingError::InvalidInput)
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

pub(super) fn take_map(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<BTreeMap<String, WireValue>, RappBindingError> {
    match take_value(map, key)? {
        WireValue::Map(value) => Ok(value),
        _ => Err(RappBindingError::InvalidInput),
    }
}

pub(super) fn take_text_array(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<Vec<String>, RappBindingError> {
    let WireValue::Array(values) = take_value(map, key)? else {
        return Err(RappBindingError::InvalidInput);
    };
    values
        .into_iter()
        .map(|value| match value {
            WireValue::Text(value) => Ok(value),
            _ => Err(RappBindingError::InvalidInput),
        })
        .collect()
}
