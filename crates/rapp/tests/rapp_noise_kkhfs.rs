// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Integration tests for hybrid post-quantum Noise_KKhfs_25519+MLKEM768_ChaChaPoly_SHA256.

use std::collections::BTreeMap;

use refineid_rapp::{
    GrantsHash, HandshakeRole, MANDATORY_SESSION_SUITE, MessageType, PairId,
    SessionHandshakeParameters, WireValue, generate_pair_key_material,
    noise::{MLKEM768_CIPHERTEXT_SIZE, MLKEM768_PUBLIC_KEY_SIZE, MLKEM768_SHARED_SECRET_SIZE},
};

#[test]
fn kkhfs_constants_conform_to_fips203() {
    assert_eq!(MLKEM768_PUBLIC_KEY_SIZE, 1184);
    assert_eq!(MLKEM768_CIPHERTEXT_SIZE, 1088);
    assert_eq!(MLKEM768_SHARED_SECRET_SIZE, 32);
    assert_eq!(
        MANDATORY_SESSION_SUITE,
        "Noise_KKhfs_25519+MLKEM768_ChaChaPoly_SHA512"
    );
}

#[test]
fn kkhfs_handshake_and_transport_round_trip() {
    let requester_keys = generate_pair_key_material().expect("requester keys");
    let proxy_keys = generate_pair_key_material().expect("proxy keys");
    let pair_id = PairId::from_array([1_u8; 16]);
    let grants_hash = GrantsHash::from_array([2_u8; 32]);
    let transport_profile = "relay-websocket-v1";

    let mut requester = refineid_rapp::HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Initiator,
        local_keys: &requester_keys,
        remote_public_key: proxy_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile,
    })
    .expect("requester handshake");

    let mut proxy = refineid_rapp::HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Responder,
        local_keys: &proxy_keys,
        remote_public_key: requester_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile,
    })
    .expect("proxy handshake");

    // Message 1: Initiator -> Responder
    let msg1 = requester.write_message().expect("write message 1");
    assert_eq!(
        msg1.as_bytes().len(),
        32 + MLKEM768_PUBLIC_KEY_SIZE + 16 + 16,
        "Message 1 must be 1248 bytes"
    );
    proxy.read_message(&msg1).expect("read message 1");

    // Message 2: Responder -> Initiator
    let msg2 = proxy.write_message().expect("write message 2");
    assert_eq!(
        msg2.as_bytes().len(),
        32 + MLKEM768_CIPHERTEXT_SIZE + 16 + 16,
        "Message 2 must be 1152 bytes"
    );
    requester.read_message(&msg2).expect("read message 2");

    assert!(requester.is_complete());
    assert!(proxy.is_complete());

    let requester_done = requester.complete().expect("requester complete");
    let proxy_done = proxy.complete().expect("proxy complete");

    // Both endpoints must derive the exact same session ID
    assert_eq!(requester_done.session_id, proxy_done.session_id);

    // Verify remote static key attribution
    assert_eq!(&requester_done.remote_static_key, proxy_keys.public_key());
    assert_eq!(&proxy_done.remote_static_key, requester_keys.public_key());

    // Verify post-handshake transport encryption and sequencing in both directions
    let mut requester_channel = requester_done.secure_channel;
    let mut proxy_channel = proxy_done.secure_channel;

    // Requester -> Proxy
    let mut req_body = BTreeMap::new();
    req_body.insert("challenge".to_owned(), WireValue::Bytes(vec![0xAA; 32]));
    req_body.insert("last_received_sequence".to_owned(), WireValue::Unsigned(0));
    let frame1 = requester_channel
        .seal(MessageType::LivenessPing, req_body.clone())
        .expect("seal frame 1");
    let opened1 = proxy_channel.open(&frame1).expect("open frame 1");
    assert_eq!(opened1.message_type, MessageType::LivenessPing);
    assert_eq!(opened1.sequence, 0);

    // Proxy -> Requester
    let mut resp_body = BTreeMap::new();
    resp_body.insert("challenge".to_owned(), WireValue::Bytes(vec![0xAA; 32]));
    resp_body.insert("last_received_sequence".to_owned(), WireValue::Unsigned(0));
    let frame2 = proxy_channel
        .seal(MessageType::LivenessPong, resp_body)
        .expect("seal frame 2");
    let opened2 = requester_channel.open(&frame2).expect("open frame 2");
    assert_eq!(opened2.message_type, MessageType::LivenessPong);
    assert_eq!(opened2.sequence, 0);

    // Next frame advances sequence
    let frame3 = requester_channel
        .seal(MessageType::LivenessPing, req_body)
        .expect("seal frame 3");
    let opened3 = proxy_channel.open(&frame3).expect("open frame 3");
    assert_eq!(opened3.sequence, 1);
}

#[test]
fn kkhfs_rejects_tampered_handshake_frame() {
    let requester_keys = generate_pair_key_material().expect("requester keys");
    let proxy_keys = generate_pair_key_material().expect("proxy keys");
    let pair_id = PairId::from_array([3_u8; 16]);
    let grants_hash = GrantsHash::from_array([4_u8; 32]);
    let transport_profile = "relay-websocket-v1";

    let mut requester = refineid_rapp::HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Initiator,
        local_keys: &requester_keys,
        remote_public_key: proxy_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile,
    })
    .expect("requester handshake");

    let mut proxy = refineid_rapp::HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Responder,
        local_keys: &proxy_keys,
        remote_public_key: requester_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile,
    })
    .expect("proxy handshake");

    let msg1 = requester.write_message().expect("write message 1");
    let mut tampered_bytes = msg1.as_bytes().to_vec();
    // Tamper with the ciphertext body
    let len = tampered_bytes.len();
    tampered_bytes[len - 1] ^= 0x01;
    let tampered_frame = refineid_rapp::BinaryFrame::reconstruct(tampered_bytes)
        .expect("reconstruct tampered frame");

    assert!(proxy.read_message(&tampered_frame).is_err());
}

#[test]
fn test_snow_supports_xxpsk3_sha512() {
    let params: Result<snow::params::NoiseParams, _> =
        "Noise_XXpsk3_25519_ChaChaPoly_SHA512".parse();
    assert!(params.is_ok(), "NoiseParams should parse SHA512");
    let builder = snow::Builder::new(params.expect("valid params"));
    let static_key = [7u8; 32];
    let hs = builder
        .local_private_key(&static_key)
        .expect("local key")
        .psk(3, &[9u8; 32])
        .expect("psk")
        .build_initiator();
    assert!(
        hs.is_ok(),
        "Snow should build Noise_XXpsk3_25519_ChaChaPoly_SHA512: {:?}",
        hs.err()
    );
}

#[test]
fn identifier_derivations_use_sha512_over_64_byte_handshake_hash() {
    let handshake_hash = [0x42_u8; 64];
    let session_id = refineid_rapp::derive_session_id(&handshake_hash);
    let pair_id = refineid_rapp::derive_pair_id(&handshake_hash);
    let rendezvous = refineid_rapp::derive_rendezvous_token(&handshake_hash);

    assert_eq!(session_id.as_bytes().len(), 16);
    assert_eq!(pair_id.as_bytes().len(), 16);
    assert_eq!(rendezvous.as_bytes().len(), 16);
    assert_ne!(session_id.as_bytes(), pair_id.as_bytes());
    assert_ne!(pair_id.as_bytes(), rendezvous.as_bytes());
}
