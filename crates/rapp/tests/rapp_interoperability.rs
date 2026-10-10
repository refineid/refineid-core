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

//! End-to-end cryptographic interoperability through the public RAPP API.

use refineid_rapp::{
    AuthenticatedViolation, BinaryFrame, CardOperation, CloseReason, CpaceKc2Initiator,
    CpaceKc2Responder, EndpointError, EndpointRole, EstablishedEndpoint, EstablishedSessionRuntime,
    ExplicitUserIntent, HandshakeChannel, HandshakeRole, LivenessConfig, MessageType, OfferId,
    OperationId, OperationRequest, OperationState, PairRecord, PairStore, PairStoreError,
    PairTombstone, PairingHandshake, PairingOffer, PairingSecret, PairingState, ProfileName,
    RappState, ReceiveOutcome, RuntimeReceive, SecureChannel, SessionHandshake,
    SessionHandshakeParameters, SessionParameters, SessionReadyMessage, SessionState,
    TransportProfile, TypedMessage, compute_grants_hash, encode_kc2_step1_frame,
    generate_pair_key_material, standard_pairing_context_v2,
};

#[derive(Default)]
struct MemoryPairStore {
    revoked: Vec<PairTombstone>,
}

impl PairStore for MemoryPairStore {
    type Error = core::convert::Infallible;

    fn load(&mut self, _pair_id: refineid_rapp::PairId) -> Result<Option<PairRecord>, Self::Error> {
        Ok(None)
    }

    fn insert(&mut self, _record: PairRecord) -> Result<(), PairStoreError<Self::Error>> {
        Ok(())
    }

    fn revoke(&mut self, tombstone: PairTombstone) -> Result<(), PairStoreError<Self::Error>> {
        self.revoked.push(tombstone);
        Ok(())
    }

    fn is_revoked(&mut self, pair_id: refineid_rapp::PairId) -> Result<bool, Self::Error> {
        Ok(self.revoked.iter().any(|entry| entry.pair_id == pair_id))
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture constructs both complete pair records inline"
)]
fn paired_records() -> (PairRecord, PairRecord) {
    let profiles = vec![
        ProfileName::CardStatus.as_str().to_owned(),
        ProfileName::Authentication.as_str().to_owned(),
    ];
    let proxy_offer = PairingOffer::create(
        OfferId::from_array([0x10; 32]),
        profiles,
        &[TransportProfile::Stream],
    )
    .expect("the pairing offer fixture is valid");
    let bootstrap = proxy_offer.to_cbor().expect("the offer encodes");
    let offer = PairingOffer::from_bootstrap(&bootstrap, TransportProfile::Stream)
        .expect("the bootstrap decodes");

    let pairing_secret = PairingSecret::from_random_bytes([0x20; 32]);

    let mut requester = PairingHandshake::begin(
        EndpointRole::Requester,
        offer,
        refineid_rapp::STREAM_CANDIDATE_ID,
        generate_pair_key_material().expect("requester key generation succeeds"),
        &pairing_secret,
    )
    .expect("requester pairing starts");
    let mut proxy = PairingHandshake::begin(
        EndpointRole::Proxy,
        proxy_offer,
        refineid_rapp::STREAM_CANDIDATE_ID,
        generate_pair_key_material().expect("proxy key generation succeeds"),
        &pairing_secret,
    )
    .expect("proxy pairing starts");

    let first = requester.write_message().expect("XX message one");
    proxy
        .read_message(&first)
        .expect("proxy reads XX message one");
    let second = proxy.write_message().expect("XX message two");
    requester
        .read_message(&second)
        .expect("requester reads XX message two");
    let third = requester.write_message().expect("XX message three");
    proxy
        .read_message(&third)
        .expect("proxy reads XX message three");
    assert!(requester.is_complete());
    assert!(proxy.is_complete());

    let mut requester = requester
        .into_confirmation()
        .expect("requester enters authenticated confirmation");
    let mut proxy = proxy
        .into_confirmation()
        .expect("proxy enters authenticated confirmation");
    assert_eq!(requester.pair_id(), proxy.pair_id());

    let requester_hello = requester
        .send_hello("Requester".into(), "macOS".into())
        .expect("requester hello seals");
    proxy
        .receive_hello(&requester_hello, 100)
        .expect("proxy verifies requester hello");
    let proxy_hello = proxy
        .send_hello("Authorization proxy".into(), "iOS".into())
        .expect("proxy hello seals");
    requester
        .receive_hello(&proxy_hello, 100)
        .expect("requester verifies proxy hello");

    let grants = vec![ProfileName::Authentication, ProfileName::CardStatus];
    let requester_confirmation = requester
        .send_confirmation(grants.clone())
        .expect("requester confirms grants");
    proxy
        .receive_confirmation(&requester_confirmation, 101)
        .expect("proxy verifies requester grants");
    let proxy_confirmation = proxy
        .send_confirmation(grants)
        .expect("proxy confirms equal grants");
    requester
        .receive_confirmation(&proxy_confirmation, 101)
        .expect("requester verifies equal grants");

    let requester_record = requester
        .into_pair_record(200)
        .expect("requester record becomes persistable after both confirmations");
    let proxy_record = proxy
        .into_pair_record(200)
        .expect("proxy record becomes persistable after both confirmations");
    assert_eq!(requester_record.pair_id(), proxy_record.pair_id());
    assert_eq!(requester_record.grants_hash(), proxy_record.grants_hash());
    assert_eq!(requester_record.profiles(), proxy_record.profiles());
    assert_eq!(
        requester_record.remote_static_public(),
        proxy_record.local_static_public()
    );
    assert_eq!(
        proxy_record.remote_static_public(),
        requester_record.local_static_public()
    );
    (requester_record, proxy_record)
}

fn raw_established_channels() -> (
    refineid_rapp::PairId,
    SecureChannel,
    SecureChannel,
    refineid_rapp::GrantsHash,
) {
    let pair_id = refineid_rapp::PairId::from_array([0x81; 16]);
    let grants_hash =
        compute_grants_hash(&[ProfileName::CardStatus]).expect("the fixed grant set hashes");
    let requester_keys = generate_pair_key_material().expect("requester key generation succeeds");
    let proxy_keys = generate_pair_key_material().expect("proxy key generation succeeds");
    let mut requester = HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Initiator,
        local_keys: &requester_keys,
        remote_public_key: proxy_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile: "local-quic-v1",
    })
    .expect("raw requester KK starts");
    let mut proxy = HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Responder,
        local_keys: &proxy_keys,
        remote_public_key: requester_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile: "local-quic-v1",
    })
    .expect("raw proxy KK starts");
    let first = requester.write_message().expect("raw KK message one");
    proxy
        .read_message(&first)
        .expect("raw proxy reads message one");
    let second = proxy.write_message().expect("raw KK message two");
    requester
        .read_message(&second)
        .expect("raw requester reads message two");
    let requester = requester.complete().expect("raw requester KK completes");
    let proxy = proxy.complete().expect("raw proxy KK completes");
    assert_eq!(requester.session_id, proxy.session_id);
    (
        pair_id,
        requester.secure_channel,
        proxy.secure_channel,
        grants_hash,
    )
}

const fn healthy_proxy(
    pair_id: refineid_rapp::PairId,
    channel: SecureChannel,
) -> EstablishedEndpoint {
    EstablishedEndpoint::new(
        pair_id,
        channel,
        RappState {
            role: EndpointRole::Proxy,
            pairing: PairingState::PairedConnected,
            session: SessionState::Healthy,
            operation: OperationState::None,
            requires_user_intent: false,
        },
    )
}

#[test]
fn pairing_and_fresh_session_interoperate_end_to_end() {
    let (requester_record, proxy_record) = paired_records();
    let pair_id = requester_record.pair_id();
    let mut requester = SessionHandshake::begin_requester(
        &requester_record,
        TransportProfile::Stream,
        ExplicitUserIntent::record(),
    )
    .expect("explicit requester session starts");
    let mut proxy = SessionHandshake::begin_proxy(&proxy_record, TransportProfile::Stream)
        .expect("proxy session starts");

    let first = requester.write_message().expect("KK message one");
    proxy
        .read_message(&first)
        .expect("proxy reads KK message one");
    let second = proxy.write_message().expect("KK message two");
    requester
        .read_message(&second)
        .expect("requester reads KK message two");
    assert!(requester.is_complete());
    assert!(proxy.is_complete());

    let mut requester = requester
        .into_authentication()
        .expect("requester derives the fresh session");
    let mut proxy = proxy
        .into_authentication()
        .expect("proxy derives the fresh session");
    assert_eq!(requester.session_id(), proxy.session_id());
    let session_id = requester.session_id();

    let mut requester_nonce = [0_u8; 32];
    getrandom::fill(&mut requester_nonce).expect("random requester nonce");
    let mut proxy_nonce = [0_u8; 32];
    getrandom::fill(&mut proxy_nonce).expect("random proxy nonce");
    let requester_ready = requester
        .send_ready(requester_nonce)
        .expect("requester session.ready seals");
    let proxy_ready = proxy
        .send_ready(proxy_nonce)
        .expect("proxy session.ready seals");
    let mut requester_store = MemoryPairStore::default();
    let mut proxy_store = MemoryPairStore::default();
    requester
        .receive_ready(&mut requester_store, &proxy_ready, 300)
        .expect("requester verifies exact proxy parameters");
    proxy
        .receive_ready(&mut proxy_store, &requester_ready, 300)
        .expect("proxy verifies exact requester parameters");
    assert!(requester_store.revoked.is_empty());
    assert!(proxy_store.revoked.is_empty());

    let mut requester = requester
        .into_established()
        .expect("requester becomes healthy only after mutual ready");
    let mut proxy = proxy
        .into_established()
        .expect("proxy becomes healthy only after mutual ready");
    assert!(requester.state().operation_admission_permitted());
    assert!(proxy.state().operation_admission_permitted());

    let request = OperationRequest::reconstruct(
        OperationId::from_array([0x70; 16]),
        pair_id,
        session_id,
        ProfileName::CardStatus,
        400,
        5_000,
        CardOperation::ReadIdentity,
    )
    .expect("the typed read request is valid");
    let frame = requester
        .send(&TypedMessage::OperationRequest(request.clone()))
        .expect("established requester seals typed traffic");
    match proxy
        .receive(&mut proxy_store, &frame, 401)
        .expect("proxy authenticates typed traffic")
    {
        ReceiveOutcome::Message(TypedMessage::OperationRequest(received)) => {
            let expected = OperationRequest::reconstruct(
                request.operation_id,
                request.pair_id,
                request.session_id,
                request.profile,
                401,
                request.expires_after_ms,
                request.operation.clone(),
            )
            .expect("the receiver-local request is valid");
            assert_eq!(received, expected);
            assert_eq!(
                received.request_hash().expect("received request hashes"),
                request.request_hash().expect("sent request hashes"),
            );
        }
        other => panic!("unexpected established-session outcome: {other:?}"),
    }

    let wrong_phase = TypedMessage::SessionReady(SessionReadyMessage {
        parameters: SessionParameters {
            transport_profile: TransportProfile::Stream.name().to_owned(),
            candidate_id: TransportProfile::Stream.candidate_id().to_owned(),
            grants_hash: requester_record.grants_hash(),
        },
        nonce: [0x71; 32],
    });
    assert!(matches!(
        requester.send(&wrong_phase),
        Err(EndpointError::UnexpectedPhase(_))
    ));
}

#[test]
fn first_authenticated_wrong_phase_message_revokes_pairing() {
    let (pair_id, mut sender, receiver, grants_hash) = raw_established_channels();
    let mut receiver = healthy_proxy(pair_id, receiver);
    let mut store = MemoryPairStore::default();
    let wrong_phase = TypedMessage::SessionReady(SessionReadyMessage {
        parameters: SessionParameters {
            transport_profile: refineid_rapp::STREAM_PROFILE.into(),
            candidate_id: refineid_rapp::STREAM_CANDIDATE_ID.into(),
            grants_hash,
        },
        nonce: [0x82; 32],
    });
    let frame = sender
        .seal(
            wrong_phase.message_type(),
            wrong_phase.to_wire_body().expect("session.ready encodes"),
        )
        .expect("the paired peer authenticates the wrong-phase message");

    match receiver
        .receive(&mut store, &frame, 10_000)
        .expect("durable pair revocation succeeds")
    {
        ReceiveOutcome::PairRevoked {
            violation: AuthenticatedViolation::UnexpectedPhase(MessageType::SessionReady),
            ..
        } => {}
        other => panic!("wrong-phase traffic did not revoke immediately: {other:?}"),
    }
    assert_eq!(store.revoked.len(), 1);
    assert_eq!(store.revoked[0].pair_id, pair_id);
    assert_eq!(receiver.state().pairing, PairingState::Revoked);
    assert!(matches!(
        receiver.receive(&mut store, &frame, 10_001),
        Err(EndpointError::SessionClosed)
    ));
}

/// Liveness timing that never fires within these tests.
const QUIET_LIVENESS: LivenessConfig = LivenessConfig {
    base_interval_ms: 60_000,
    response_timeout_ms: 10_000,
    maximum_interval_ms: 60_000,
    maximum_jitter_ms: 0,
    maximum_misses: 1,
};

/// Monotonic instant the sessions start at.
const SESSION_START_MS: u64 = 1_000;

fn established_runtimes() -> (EstablishedSessionRuntime, EstablishedSessionRuntime) {
    let (pair_id, requester, proxy, _) = raw_established_channels();
    let requester = EstablishedEndpoint::new(
        pair_id,
        requester,
        RappState {
            role: EndpointRole::Requester,
            pairing: PairingState::PairedConnected,
            session: SessionState::Healthy,
            operation: OperationState::None,
            requires_user_intent: false,
        },
    );
    (
        EstablishedSessionRuntime::new(requester, QUIET_LIVENESS, SESSION_START_MS)
            .expect("requester runtime starts"),
        EstablishedSessionRuntime::new(
            healthy_proxy(pair_id, proxy),
            QUIET_LIVENESS,
            SESSION_START_MS,
        )
        .expect("proxy runtime starts"),
    )
}

#[test]
fn custodian_withdrawal_close_reaches_the_requester_with_its_reason() {
    let (mut requester, mut proxy) = established_runtimes();
    let mut store = MemoryPairStore::default();
    let frame = proxy
        .close_with_reason(CloseReason::ServiceWithdrawn)
        .expect("close notice seals");
    assert!(matches!(
        requester
            .receive(&mut store, &frame, SESSION_START_MS)
            .expect("close notice opens"),
        RuntimeReceive::PeerClosed(CloseReason::ServiceWithdrawn)
    ));
    assert!(store.revoked.is_empty());
    assert!(proxy.close_with_reason(CloseReason::Normal).is_err());
}

#[test]
fn requester_close_reaches_the_custodian_with_its_reason() {
    let (mut requester, mut proxy) = established_runtimes();
    let mut store = MemoryPairStore::default();
    let frame = requester
        .close_with_reason(CloseReason::UserDisconnect)
        .expect("close notice seals");
    assert!(matches!(
        proxy
            .receive(&mut store, &frame, SESSION_START_MS)
            .expect("close notice opens"),
        RuntimeReceive::PeerClosed(CloseReason::UserDisconnect)
    ));
    assert!(store.revoked.is_empty());
}

#[test]
fn unauthenticated_ciphertext_failure_closes_only_session() {
    let (pair_id, mut sender, receiver, _) = raw_established_channels();
    let mut receiver = healthy_proxy(pair_id, receiver);
    let mut store = MemoryPairStore::default();
    let message = TypedMessage::OperationStatusRequest(OperationId::from_array([0x83; 16]));
    let valid = sender
        .seal(
            message.message_type(),
            message.to_wire_body().expect("status request encodes"),
        )
        .expect("status request encrypts");
    let mut tampered = valid.as_bytes().to_vec();
    let last = tampered.last_mut().expect("Noise frame is nonempty");
    *last ^= 0x01;
    let tampered = BinaryFrame::reconstruct(tampered).expect("frame remains bounded");

    assert!(matches!(
        receiver
            .receive(&mut store, &tampered, 20_000)
            .expect("integrity failure has a fail-closed outcome"),
        ReceiveOutcome::SessionClosed(_)
    ));
    assert!(store.revoked.is_empty());
    assert_eq!(receiver.state().pairing, PairingState::PairedConnected);
}

#[test]
fn credential_rejection_durably_revokes_the_pair() {
    let (pair_id, _, receiver, _) = raw_established_channels();
    let mut receiver = healthy_proxy(pair_id, receiver);
    let mut store = MemoryPairStore::default();

    let outcome = receiver
        .revoke_credential_rejection(&mut store, 12_345)
        .expect("credential rejection tombstones the pair");

    assert_eq!(store.revoked.len(), 1);
    assert_eq!(store.revoked[0].pair_id, pair_id);
    assert_eq!(store.revoked[0].revoked_at_ms, 12_345);
    assert_eq!(receiver.state().pairing, PairingState::Revoked);
    assert_eq!(receiver.state().session, SessionState::Closing);
    assert!(
        outcome
            .actions
            .contains(&refineid_rapp::Action::DestroyPairKeys)
    );
}

#[test]
fn cpace_bootstrap_pairing_and_fresh_session_interoperate_end_to_end() {
    let pairing_code = "7KX4M9";

    let profiles = vec![
        ProfileName::CardStatus.as_str().to_owned(),
        ProfileName::Authentication.as_str().to_owned(),
    ];
    let proxy_offer = PairingOffer::create(
        OfferId::from_array([0x21; 32]),
        profiles,
        &[TransportProfile::Ble, TransportProfile::Stream],
    )
    .expect("custodian offer is valid");
    let bootstrap = proxy_offer.to_cbor().expect("the offer encodes");
    let requester_offer = PairingOffer::from_bootstrap(&bootstrap, TransportProfile::Stream)
        .expect("the stream bootstrap decodes");
    let offer_id = requester_offer.offer_id;

    let offer_hash = requester_offer.offer_hash().expect("offer hash succeeds");
    let context = standard_pairing_context_v2(
        &offer_hash,
        TransportProfile::Stream.name(),
        TransportProfile::Stream.candidate_id(),
    )
    .expect("context succeeds");

    // Phase 1: CPace KC2 3-step mutual confirmation exchange
    let (initiator, ya) = CpaceKc2Initiator::new(pairing_code, &context, &offer_id, &[0x33; 64])
        .expect("alice cpace init succeeds");
    let step1_frame = encode_kc2_step1_frame(&ya).expect("alice writes step 1 frame");

    let (step2_frame, bob_waiting) = CpaceKc2Responder::process_step1_frame(
        pairing_code,
        &context,
        &offer_id,
        &step1_frame,
        &[0x44; 64],
    )
    .expect("bob processes step 1 frame");

    let (step3_frame, alice_secret) = initiator
        .process_step2_frame(&step2_frame)
        .expect("alice processes step 2 frame");

    let bob_secret = bob_waiting
        .process_step3_frame(&step3_frame)
        .expect("bob processes step 3 frame");

    assert_eq!(alice_secret, bob_secret);

    // Phase 2: Noise XXpsk3 Handshake
    let mut requester = PairingHandshake::begin(
        EndpointRole::Requester,
        requester_offer,
        refineid_rapp::STREAM_CANDIDATE_ID,
        generate_pair_key_material().expect("requester key generation succeeds"),
        &alice_secret,
    )
    .expect("requester pairing starts");
    let mut proxy = PairingHandshake::begin(
        EndpointRole::Proxy,
        proxy_offer,
        refineid_rapp::STREAM_CANDIDATE_ID,
        generate_pair_key_material().expect("proxy key generation succeeds"),
        &bob_secret,
    )
    .expect("proxy pairing starts");

    let msg1 = requester.write_message().expect("msg1 writes");
    proxy.read_message(&msg1).expect("msg1 reads");

    let msg2 = proxy.write_message().expect("msg2 writes");
    requester.read_message(&msg2).expect("msg2 reads");

    let msg3 = requester.write_message().expect("msg3 writes");
    proxy.read_message(&msg3).expect("msg3 reads");

    assert!(requester.is_complete());
    assert!(proxy.is_complete());

    // Phase 3: Confirmation
    let mut requester_confirm = requester.into_confirmation().expect("requester confirms");
    let mut proxy_confirm = proxy.into_confirmation().expect("proxy confirms");

    let req_hello = requester_confirm
        .send_hello("desktop".into(), "macos".into())
        .expect("requester hello sends");
    proxy_confirm
        .receive_hello(&req_hello, 100)
        .expect("proxy receives hello");

    let proxy_hello = proxy_confirm
        .send_hello("phone".into(), "ios".into())
        .expect("proxy hello sends");
    requester_confirm
        .receive_hello(&proxy_hello, 100)
        .expect("requester receives hello");

    let grants = vec![ProfileName::Authentication];
    let proxy_confirm_msg = proxy_confirm
        .send_confirmation(grants.clone())
        .expect("proxy confirms");
    requester_confirm
        .receive_confirmation(&proxy_confirm_msg, 101)
        .expect("requester receives confirm");

    let req_confirm_msg = requester_confirm
        .send_confirmation(grants)
        .expect("requester confirms");
    proxy_confirm
        .receive_confirmation(&req_confirm_msg, 101)
        .expect("proxy receives confirm");

    let requester_record = requester_confirm
        .into_pair_record(200)
        .expect("requester finishes");
    let proxy_record = proxy_confirm.into_pair_record(200).expect("proxy finishes");

    assert_eq!(requester_record.pair_id(), proxy_record.pair_id());

    // Phase 4: Fresh Session Handshake
    let mut requester_session = SessionHandshake::begin_requester(
        &requester_record,
        TransportProfile::Stream,
        ExplicitUserIntent::record(),
    )
    .expect("explicit requester session starts");
    let mut proxy_session = SessionHandshake::begin_proxy(&proxy_record, TransportProfile::Stream)
        .expect("proxy session starts");

    let s_msg1 = requester_session.write_message().expect("KK message one");
    proxy_session
        .read_message(&s_msg1)
        .expect("proxy reads KK message one");
    let s_msg2 = proxy_session.write_message().expect("KK message two");
    requester_session
        .read_message(&s_msg2)
        .expect("requester reads KK message two");
    assert!(requester_session.is_complete());
    assert!(proxy_session.is_complete());

    let requester_session = requester_session
        .into_authentication()
        .expect("requester derives session");
    let proxy_session = proxy_session
        .into_authentication()
        .expect("proxy derives session");
    assert_eq!(requester_session.session_id(), proxy_session.session_id());
}
