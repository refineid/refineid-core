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
    AuthenticatedViolation, BinaryFrame, BootstrapAnswer, CardOperation, CloseEcho, CloseReason,
    CpaceKc2Initiator, CpaceKc2Responder, DisplayName, EndpointError, EndpointRole,
    EstablishedEndpoint, EstablishedSessionRuntime, ExplicitUserIntent, HandshakeChannel,
    HandshakeRole, MessageType, OfferId, OperationId, OperationRequest, PairRecord, PairingCode,
    PairingHandshake, PairingOffer, PairingSecret, PairingState, ProfileName, RappState,
    ReadyOutcome, ReceiveOutcome, RuntimeReceive, SecureChannel, SessionAuthentication,
    SessionCloseMessage, SessionError, SessionHandshake, SessionHandshakeParameters,
    SessionHelloMessage, SessionParameters, SessionReadyMessage, SessionState, TransportProfile,
    TypedMessage, compute_grants_hash, encode_kc2_step1_frame, generate_pair_key_material,
    standard_pairing_context_v2,
};

/// The name the requester sends for itself.
const REQUESTER_NAME: &str = "macOS - example-host";
/// The name the custodian sends for itself.
const CUSTODIAN_NAME: &str = "iPhone 16";
/// The custodian's name after its holder renamed the phone.
const RENAMED_CUSTODIAN: &str = "Kitchen iPhone";

fn name(text: &str) -> DisplayName {
    DisplayName::parse(text.to_owned()).expect("a valid name")
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
    let Ok(BootstrapAnswer::Offer(offer)) =
        BootstrapAnswer::from_bootstrap(&bootstrap, TransportProfile::Stream)
    else {
        panic!("the bootstrap decodes as the offer");
    };

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
        .send_hello(name(REQUESTER_NAME), "macOS".into())
        .expect("requester hello seals");
    proxy
        .receive_hello(&requester_hello, 100)
        .expect("proxy verifies requester hello");
    let proxy_hello = proxy
        .send_hello(name(CUSTODIAN_NAME), "iOS".into())
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

    let (requester_record, mut requester_storage) = requester
        .into_storage(200)
        .expect("requester record becomes persistable after both confirmations");
    let (proxy_record, mut proxy_storage) = proxy
        .into_storage(200)
        .expect("proxy record becomes persistable after both confirmations");
    let requester_stored = requester_storage
        .send_stored()
        .expect("requester confirms storage");
    let proxy_stored = proxy_storage.send_stored().expect("proxy confirms storage");
    proxy_storage
        .receive_stored(&requester_stored, 201)
        .expect("proxy verifies the requester's confirmation");
    requester_storage
        .receive_stored(&proxy_stored, 201)
        .expect("requester verifies the proxy's confirmation");
    assert!(!requester_record.is_storage_confirmed());
    assert!(!proxy_record.is_storage_confirmed());
    let requester_active = requester_storage
        .into_active()
        .expect("both confirmations make the requester's pairing active");
    let proxy_active = proxy_storage
        .into_active()
        .expect("both confirmations make the proxy's pairing active");
    assert_eq!(requester_active.pair_id(), requester_record.pair_id());
    assert_eq!(proxy_active.pair_id(), proxy_record.pair_id());
    let requester_record = requester_active
        .confirm(requester_record)
        .expect("the active pairing confirms the requester's record");
    let proxy_record = proxy_active
        .confirm(proxy_record)
        .expect("the active pairing confirms the proxy's record");
    assert!(requester_record.is_storage_confirmed());
    assert!(proxy_record.is_storage_confirmed());
    assert_eq!(requester_record.pair_id(), proxy_record.pair_id());
    assert_eq!(requester_record.peer_display_name(), &name(CUSTODIAN_NAME));
    assert_eq!(proxy_record.peer_display_name(), &name(REQUESTER_NAME));
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
        },
    )
}

/// Runs the session handshake of a stored pairing; both sides then hold
/// the completed handshake awaiting `session.ready`.
fn authenticating_sessions(
    requester_record: &PairRecord,
    proxy_record: &PairRecord,
) -> (SessionAuthentication, SessionAuthentication) {
    let mut requester = SessionHandshake::begin_requester(
        requester_record,
        TransportProfile::Stream,
        ExplicitUserIntent::record(),
    )
    .expect("explicit requester session starts");
    let mut proxy = SessionHandshake::begin_proxy(proxy_record, TransportProfile::Stream)
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

    let requester = requester
        .into_authentication()
        .expect("requester derives the fresh session");
    let proxy = proxy
        .into_authentication()
        .expect("proxy derives the fresh session");
    assert_eq!(requester.session_id(), proxy.session_id());
    (requester, proxy)
}

/// Monotonic instant the custodian's first message arrives.
const READY_AT_MS: u64 = 300;

fn ready_nonce() -> [u8; 32] {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).expect("random ready nonce");
    nonce
}

#[test]
fn pairing_and_fresh_session_interoperate_end_to_end() {
    let (requester_record, proxy_record) = paired_records();
    let (mut requester, mut proxy) = authenticating_sessions(&requester_record, &proxy_record);

    assert!(matches!(
        requester.send_ready(ready_nonce(), &name(REQUESTER_NAME)),
        Err(SessionError::RoleViolation)
    ));
    assert!(matches!(
        proxy.send_hello(&name(CUSTODIAN_NAME)),
        Err(SessionError::RoleViolation)
    ));
    let proxy_ready = proxy
        .send_ready(ready_nonce(), &name(RENAMED_CUSTODIAN))
        .expect("custodian session.ready seals");
    match requester
        .receive_ready(&proxy_ready, READY_AT_MS)
        .expect("requester reads the custodian's first message")
    {
        ReadyOutcome::Verified { custodian_name } => {
            assert_eq!(custodian_name, name(RENAMED_CUSTODIAN));
        }
        other => panic!("session.ready was not verified: {other:?}"),
    }
    let hello = requester
        .send_hello(&name(REQUESTER_NAME))
        .expect("requester session.hello seals");
    assert!(matches!(
        requester.send_hello(&name(REQUESTER_NAME)),
        Err(SessionError::DuplicateHello)
    ));

    let mut requester = requester
        .into_established()
        .expect("requester becomes healthy once it verified ready and sent its hello");
    let mut proxy = proxy
        .into_established()
        .expect("custodian becomes healthy once it sent ready");
    match proxy
        .receive(&hello, READY_AT_MS)
        .expect("custodian reads the hello")
    {
        ReceiveOutcome::Message(TypedMessage::SessionHello(received)) => {
            assert_eq!(received.display_name, name(REQUESTER_NAME));
        }
        other => panic!("the hello was not admitted: {other:?}"),
    }
    assert!(requester.state().operation_admission_permitted());
    assert!(proxy.state().operation_admission_permitted());

    let request = OperationRequest::reconstruct(
        OperationId::from_array([0x70; 16]),
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
        .receive(&frame, 401)
        .expect("proxy authenticates typed traffic")
    {
        ReceiveOutcome::Message(TypedMessage::OperationRequest(received)) => {
            let expected = OperationRequest::reconstruct(
                request.operation_id,
                request.profile,
                401,
                request.expires_after_ms,
                request.operation.clone(),
            )
            .expect("the receiver-local request is valid");
            assert_eq!(received, expected);
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
        display_name: name(CUSTODIAN_NAME),
    });
    assert!(matches!(
        requester.send(&wrong_phase),
        Err(EndpointError::UnexpectedPhase(_))
    ));
}

#[test]
fn an_authenticated_wrong_phase_message_closes_the_session_and_keeps_the_pairing() {
    let (pair_id, mut sender, receiver, grants_hash) = raw_established_channels();
    let mut receiver = healthy_proxy(pair_id, receiver);
    let wrong_phase = TypedMessage::SessionReady(SessionReadyMessage {
        parameters: SessionParameters {
            transport_profile: refineid_rapp::STREAM_PROFILE.into(),
            candidate_id: refineid_rapp::STREAM_CANDIDATE_ID.into(),
            grants_hash,
        },
        nonce: [0x82; 32],
        display_name: name(CUSTODIAN_NAME),
    });
    let frame = sender
        .seal(
            wrong_phase.message_type(),
            wrong_phase.to_wire_body().expect("session.ready encodes"),
        )
        .expect("the paired peer authenticates the wrong-phase message");

    let notice = match receiver.receive(&frame, 10_000).expect("receive") {
        ReceiveOutcome::ViolationClosed {
            violation: AuthenticatedViolation::UnexpectedPhase(MessageType::SessionReady),
            outcome,
            notice,
        } => {
            assert!(
                !outcome
                    .actions
                    .contains(&refineid_rapp::Action::DestroyPairKeys)
            );
            notice.expect("the violation close is sealed")
        }
        other => panic!("wrong-phase traffic did not close the session: {other:?}"),
    };
    let envelope = sender.open(&notice).expect("the sender opens the close");
    assert_eq!(
        TypedMessage::from_envelope(envelope, 10_000).expect("the close decodes"),
        TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::ProtocolViolation
        })
    );
    assert_eq!(receiver.state().pairing, PairingState::PairedConnected);
    assert_eq!(receiver.state().session, SessionState::Closing);
    assert!(
        receiver.awaits_close_echo(),
        "the violation close awaits its echo"
    );
    assert!(matches!(
        receiver.receive(&frame, 10_001),
        Ok(ReceiveOutcome::SessionClosed(_))
    ));
    assert!(matches!(
        receiver.receive(&frame, 10_002),
        Err(EndpointError::SessionClosed)
    ));
}

/// Monotonic instant the sessions start at.
const SESSION_START_MS: u64 = 1_000;

/// The requester's `session.hello`, sealed on its raw channel and read by
/// the custodian, as every session starts (RAPP section 7.1 item 6).
fn greet(requester: &mut SecureChannel, proxy: &mut EstablishedEndpoint) {
    let hello = TypedMessage::SessionHello(SessionHelloMessage {
        display_name: name(REQUESTER_NAME),
    });
    let frame = requester
        .seal(
            hello.message_type(),
            hello.to_wire_body().expect("session.hello encodes"),
        )
        .expect("session.hello seals");
    assert!(matches!(
        proxy
            .receive(&frame, SESSION_START_MS)
            .expect("hello opens"),
        ReceiveOutcome::Message(TypedMessage::SessionHello(_))
    ));
}

fn established_runtimes() -> (EstablishedSessionRuntime, EstablishedSessionRuntime) {
    let (pair_id, mut requester, proxy, _) = raw_established_channels();
    let mut proxy = healthy_proxy(pair_id, proxy);
    greet(&mut requester, &mut proxy);
    let requester = EstablishedEndpoint::new(
        pair_id,
        requester,
        RappState {
            role: EndpointRole::Requester,
            pairing: PairingState::PairedConnected,
            session: SessionState::Healthy,
        },
    );
    (
        EstablishedSessionRuntime::new(requester, SESSION_START_MS),
        EstablishedSessionRuntime::new(proxy, SESSION_START_MS),
    )
}

/// `sender` closes with `reason`; `receiver` answers with the echo, which
/// `sender` reads as the acknowledgement of its close (RAPP section 7.1
/// item 7).
fn close_is_acknowledged(
    sender: &mut EstablishedSessionRuntime,
    receiver: &mut EstablishedSessionRuntime,
    reason: CloseReason,
) {
    let frame = sender
        .close_with_reason(reason)
        .expect("close notice seals");
    assert!(sender.awaits_close_echo());
    let echo = match receiver
        .receive(&frame, SESSION_START_MS)
        .expect("close notice opens")
    {
        RuntimeReceive::PeerClosed {
            reason: received,
            echo: Some(echo),
        } if received == reason => echo,
        other => panic!("{reason:?} was not answered with its echo: {other:?}"),
    };
    assert!(matches!(
        sender.receive(&echo, SESSION_START_MS).expect("the echo opens"),
        RuntimeReceive::CloseAcknowledged {
            reason: acknowledged,
            crossing: false,
        } if acknowledged == reason
    ));
    assert!(!sender.awaits_close_echo());
}

#[test]
fn custodian_withdrawal_close_reaches_the_requester_and_is_echoed() {
    let (mut requester, mut proxy) = established_runtimes();
    close_is_acknowledged(&mut proxy, &mut requester, CloseReason::ServiceWithdrawn);
    assert!(proxy.close_with_reason(CloseReason::Normal).is_err());
}

#[test]
fn requester_withdrawal_close_reaches_the_custodian_and_is_echoed() {
    let (mut requester, mut proxy) = established_runtimes();
    close_is_acknowledged(&mut requester, &mut proxy, CloseReason::ServiceWithdrawn);
    assert!(requester.close_with_reason(CloseReason::Normal).is_err());
}

#[test]
fn a_revocation_notice_is_echoed() {
    let (mut requester, mut proxy) = established_runtimes();
    close_is_acknowledged(&mut requester, &mut proxy, CloseReason::PairingRevoked);
}

#[test]
fn every_close_reason_is_echoed_and_the_echo_is_never_answered() {
    for reason in [
        CloseReason::Normal,
        CloseReason::Complete,
        CloseReason::UserDisconnect,
        CloseReason::Policy,
        CloseReason::ProtocolViolation,
        CloseReason::PairingRevoked,
        CloseReason::Shutdown,
        CloseReason::CardUnavailable,
        CloseReason::ServiceWithdrawn,
    ] {
        let (mut requester, mut proxy) = established_runtimes();
        close_is_acknowledged(&mut proxy, &mut requester, reason);
        assert!(
            proxy.close_with_reason(reason).is_err(),
            "nothing more is sent once the echo arrived"
        );
    }
}

#[test]
fn closes_that_cross_acknowledge_each_other() {
    let (mut requester, mut proxy) = established_runtimes();
    let from_requester = requester
        .close_with_reason(CloseReason::ServiceWithdrawn)
        .expect("requester close seals");
    let from_proxy = proxy
        .close_with_reason(CloseReason::PairingRevoked)
        .expect("custodian close seals");
    assert!(matches!(
        requester
            .receive(&from_proxy, SESSION_START_MS)
            .expect("opens"),
        RuntimeReceive::CloseAcknowledged {
            reason: CloseReason::PairingRevoked,
            crossing: true,
        }
    ));
    assert!(matches!(
        proxy
            .receive(&from_requester, SESSION_START_MS)
            .expect("opens"),
        RuntimeReceive::CloseAcknowledged {
            reason: CloseReason::ServiceWithdrawn,
            crossing: true,
        }
    ));
}

#[test]
fn a_closing_endpoint_ignores_everything_but_the_echo() {
    let (mut requester, mut proxy) = established_runtimes();
    let close = requester
        .close_with_reason(CloseReason::ServiceWithdrawn)
        .expect("requester close seals");
    let status = proxy
        .endpoint_mut()
        .send(&TypedMessage::CardStatus(
            refineid_rapp::CardStatusMessage {
                card: refineid_rapp::CardPresence::Absent,
                reader: refineid_rapp::CardReader::Absent,
            },
        ))
        .expect("card status seals");
    assert!(matches!(
        requester.receive(&status, SESSION_START_MS).expect("opens"),
        RuntimeReceive::IgnoredWhileClosing
    ));
    let RuntimeReceive::PeerClosed {
        echo: Some(echo), ..
    } = proxy.receive(&close, SESSION_START_MS).expect("opens")
    else {
        panic!("the close was not echoed");
    };
    assert!(matches!(
        requester.receive(&echo, SESSION_START_MS).expect("opens"),
        RuntimeReceive::CloseAcknowledged {
            reason: CloseReason::ServiceWithdrawn,
            crossing: false,
        }
    ));
}

#[test]
fn a_revoking_custodian_sends_the_close_in_place_of_ready() {
    let (requester_record, proxy_record) = paired_records();
    let (mut requester, mut proxy) = authenticating_sessions(&requester_record, &proxy_record);
    let notice = proxy
        .send_revocation_notice()
        .expect("the close is the custodian's first message");
    let echo = match requester
        .receive_ready(&notice, READY_AT_MS)
        .expect("requester reads the custodian's first message")
    {
        ReadyOutcome::PeerClosed {
            reason: CloseReason::PairingRevoked,
            echo: Some(echo),
        } => echo,
        other => panic!("the revocation close was not echoed: {other:?}"),
    };
    assert!(matches!(
        requester.into_established(),
        Err(SessionError::ReadyIncomplete)
    ));
    assert!(matches!(
        proxy.send_ready(ready_nonce(), &name(CUSTODIAN_NAME)),
        Err(SessionError::Closed)
    ));
    assert_eq!(
        proxy
            .receive_close_echo(&echo, READY_AT_MS)
            .expect("the custodian reads the echo"),
        CloseEcho::Acknowledged {
            reason: CloseReason::PairingRevoked,
            crossing: false,
        }
    );
}

#[test]
fn a_revoking_requester_sends_the_close_as_its_first_message() {
    let (requester_record, proxy_record) = paired_records();
    let (mut requester, mut proxy) = authenticating_sessions(&requester_record, &proxy_record);
    let ready = proxy
        .send_ready(ready_nonce(), &name(CUSTODIAN_NAME))
        .expect("custodian session.ready seals");
    let notice = requester
        .send_revocation_notice()
        .expect("the close is the requester's first message");
    let mut proxy = EstablishedSessionRuntime::new(
        proxy.into_established().expect("custodian is healthy"),
        SESSION_START_MS,
    );
    let RuntimeReceive::PeerClosed {
        reason: CloseReason::PairingRevoked,
        echo: Some(echo),
    } = proxy
        .receive(&notice, SESSION_START_MS)
        .expect("the close opens")
    else {
        panic!("the revocation close was not echoed");
    };
    assert_eq!(
        requester
            .receive_close_echo(&ready, SESSION_START_MS)
            .expect("the requester reads the ready"),
        CloseEcho::Ignored,
        "the custodian's session.ready is ignored while the echo is awaited"
    );
    assert_eq!(
        requester
            .receive_close_echo(&echo, SESSION_START_MS)
            .expect("the requester reads the echo"),
        CloseEcho::Acknowledged {
            reason: CloseReason::PairingRevoked,
            crossing: false,
        }
    );
}

#[test]
fn a_custodian_that_sent_ready_cannot_send_the_revocation_close_first() {
    let (requester_record, proxy_record) = paired_records();
    let (_, mut proxy) = authenticating_sessions(&requester_record, &proxy_record);
    proxy
        .send_ready(ready_nonce(), &name(CUSTODIAN_NAME))
        .expect("custodian session.ready seals");
    assert!(matches!(
        proxy.send_revocation_notice(),
        Err(SessionError::DuplicateReady)
    ));
}

#[test]
fn requester_close_reaches_the_custodian_with_its_reason() {
    let (mut requester, mut proxy) = established_runtimes();
    close_is_acknowledged(&mut requester, &mut proxy, CloseReason::UserDisconnect);
}

/// A requester whose first message is not `session.hello` or a
/// `pairing_revoked` close.
fn first_message_without_hello(message: &TypedMessage) -> ReceiveOutcome {
    let (pair_id, mut requester, proxy, _) = raw_established_channels();
    let mut proxy = healthy_proxy(pair_id, proxy);
    let frame = requester
        .seal(
            message.message_type(),
            message.to_wire_body().expect("the message encodes"),
        )
        .expect("the message seals");
    proxy.receive(&frame, SESSION_START_MS).expect("receive")
}

#[test]
fn the_custodian_admits_no_request_before_session_hello() {
    let request = OperationRequest::reconstruct(
        OperationId::from_array([0x70; 16]),
        ProfileName::CardStatus,
        400,
        5_000,
        CardOperation::ReadIdentity,
    )
    .expect("the typed read request is valid");
    for first in [
        TypedMessage::OperationRequest(request),
        TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::ServiceWithdrawn,
        }),
        TypedMessage::LivenessPing(refineid_rapp::LivenessMessage {
            challenge: refineid_rapp::PingChallenge::reconstruct([0x72; 32]),
        }),
    ] {
        let expected = first.message_type();
        match first_message_without_hello(&first) {
            ReceiveOutcome::ViolationClosed {
                violation: AuthenticatedViolation::UnexpectedPhase(message_type),
                notice,
                ..
            } => {
                assert_eq!(message_type, expected);
                assert!(notice.is_some(), "the protocol_violation close is sealed");
            }
            other => panic!("{expected:?} first was admitted: {other:?}"),
        }
    }
    assert!(matches!(
        first_message_without_hello(&TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::PairingRevoked,
        })),
        ReceiveOutcome::PeerClosed {
            reason: CloseReason::PairingRevoked,
            echo: Some(_),
        }
    ));
}

#[test]
fn a_second_session_hello_closes_the_session() {
    let (pair_id, mut requester, proxy, _) = raw_established_channels();
    let mut proxy = healthy_proxy(pair_id, proxy);
    greet(&mut requester, &mut proxy);
    let hello = TypedMessage::SessionHello(SessionHelloMessage {
        display_name: name(REQUESTER_NAME),
    });
    let frame = requester
        .seal(
            hello.message_type(),
            hello.to_wire_body().expect("session.hello encodes"),
        )
        .expect("session.hello seals");
    assert!(matches!(
        proxy.receive(&frame, SESSION_START_MS).expect("receive"),
        ReceiveOutcome::ViolationClosed {
            violation: AuthenticatedViolation::UnexpectedPhase(MessageType::SessionHello),
            ..
        }
    ));
}

#[test]
fn unauthenticated_ciphertext_failure_closes_only_session() {
    let (pair_id, mut sender, receiver, _) = raw_established_channels();
    let mut receiver = healthy_proxy(pair_id, receiver);
    let message = TypedMessage::CardStatus(refineid_rapp::CardStatusMessage {
        card: refineid_rapp::CardPresence::Absent,
        reader: refineid_rapp::CardReader::Absent,
    });
    let valid = sender
        .seal(
            message.message_type(),
            message.to_wire_body().expect("card status encodes"),
        )
        .expect("card status encrypts");
    let mut tampered = valid.as_bytes().to_vec();
    let last = tampered.last_mut().expect("Noise frame is nonempty");
    *last ^= 0x01;
    let tampered = BinaryFrame::reconstruct(tampered).expect("frame remains bounded");

    assert!(matches!(
        receiver
            .receive(&tampered, 20_000)
            .expect("integrity failure has a fail-closed outcome"),
        ReceiveOutcome::SessionClosed(_)
    ));
    assert_eq!(receiver.state().pairing, PairingState::PairedConnected);
}

#[test]
fn cpace_bootstrap_pairing_and_fresh_session_interoperate_end_to_end() {
    let pairing_code = PairingCode::parse("7KX4M9").expect("a valid pairing code");

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
    let Ok(BootstrapAnswer::Offer(requester_offer)) =
        BootstrapAnswer::from_bootstrap(&bootstrap, TransportProfile::Stream)
    else {
        panic!("the stream bootstrap decodes as the offer");
    };
    let offer_id = requester_offer.offer_id;

    let offer_hash = requester_offer.offer_hash().expect("offer hash succeeds");
    let context = standard_pairing_context_v2(
        &offer_hash,
        TransportProfile::Stream.name(),
        TransportProfile::Stream.candidate_id(),
    )
    .expect("context succeeds");

    // Phase 1: CPace KC2 3-step mutual confirmation exchange
    let (initiator, ya) = CpaceKc2Initiator::new(&pairing_code, &context, &offer_id, &[0x33; 64])
        .expect("alice cpace init succeeds");
    let step1_frame = encode_kc2_step1_frame(&ya).expect("alice writes step 1 frame");

    let (step2_frame, bob_waiting) = CpaceKc2Responder::process_step1_frame(
        &pairing_code,
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
        .send_hello(name(REQUESTER_NAME), "macOS".into())
        .expect("requester hello sends");
    proxy_confirm
        .receive_hello(&req_hello, 100)
        .expect("proxy receives hello");

    let proxy_hello = proxy_confirm
        .send_hello(name(CUSTODIAN_NAME), "iOS".into())
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

    let (requester_record, mut requester_storage) = requester_confirm
        .into_storage(200)
        .expect("requester builds its record");
    let (proxy_record, mut proxy_storage) = proxy_confirm
        .into_storage(200)
        .expect("proxy builds its record");
    let proxy_stored = proxy_storage.send_stored().expect("proxy confirms storage");
    requester_storage
        .receive_stored(&proxy_stored, 201)
        .expect("requester verifies the proxy's confirmation");
    let requester_stored = requester_storage
        .send_stored()
        .expect("requester confirms storage");
    proxy_storage
        .receive_stored(&requester_stored, 201)
        .expect("proxy verifies the requester's confirmation");
    let requester_record = requester_storage
        .into_active()
        .expect("requester pairing is active")
        .confirm(requester_record)
        .expect("the requester's record is confirmed");
    let proxy_record = proxy_storage
        .into_active()
        .expect("proxy pairing is active")
        .confirm(proxy_record)
        .expect("the proxy's record is confirmed");

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
