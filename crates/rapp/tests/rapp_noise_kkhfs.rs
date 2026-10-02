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
fn test_snow_supports_kk_sha512() {
    let params: Result<snow::params::NoiseParams, _> = "Noise_KK_25519_ChaChaPoly_SHA512".parse();
    assert!(params.is_ok(), "NoiseParams should parse KK SHA512");
    let init_builder = snow::Builder::new(
        params
            .as_ref()
            .expect("NoiseParams should parse KK SHA512")
            .clone(),
    );
    let resp_builder = snow::Builder::new(
        params
            .as_ref()
            .expect("NoiseParams should parse KK SHA512")
            .clone(),
    );

    let init_keypair = init_builder.generate_keypair().expect("init keypair");
    let resp_keypair = resp_builder.generate_keypair().expect("resp keypair");

    let mut init = init_builder
        .local_private_key(&init_keypair.private)
        .expect("init local priv")
        .remote_public_key(&resp_keypair.public)
        .expect("init remote pub")
        .build_initiator()
        .expect("build init");

    let mut resp = resp_builder
        .local_private_key(&resp_keypair.private)
        .expect("resp local priv")
        .remote_public_key(&init_keypair.public)
        .expect("resp remote pub")
        .build_responder()
        .expect("build resp");

    let mut msg1 = vec![0u8; 128];
    let len1 = init.write_message(&[], &mut msg1).expect("init write msg1");
    assert_eq!(len1, 48);

    let mut payload1 = vec![0u8; 128];
    let len_p1 = resp
        .read_message(&msg1[..len1], &mut payload1)
        .expect("resp read msg1");
    assert_eq!(len_p1, 0);

    let mut msg2 = vec![0u8; 128];
    let len2 = resp.write_message(&[], &mut msg2).expect("resp write msg2");
    assert_eq!(len2, 48);

    let mut payload2 = vec![0u8; 128];
    let len_p2 = init
        .read_message(&msg2[..len2], &mut payload2)
        .expect("init read msg2");
    assert_eq!(len_p2, 0);

    assert!(init.is_handshake_finished());
    assert!(resp.is_handshake_finished());

    let mut init_transport = init.into_transport_mode().expect("init transport");
    let mut resp_transport = resp.into_transport_mode().expect("resp transport");

    let mut buf = vec![0u8; 128];
    let len = init_transport
        .write_message(b"hello", &mut buf)
        .expect("write transport");
    let mut out = vec![0u8; 128];
    let plen = resp_transport
        .read_message(&buf[..len], &mut out)
        .expect("read transport");
    assert_eq!(&out[..plen], b"hello");
}

#[test]
fn test_generate_standard_noise_kk_vector() {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use refineid_rapp::noise::{NoiseSymmetricState, x25519_public_key};

    // Test fixed keys:
    let init_s_priv = [0x11_u8; 32];
    let init_s_pub = x25519_public_key(&init_s_priv);

    let resp_s_priv = [0x22_u8; 32];
    let resp_s_pub = x25519_public_key(&resp_s_priv);

    let init_e_priv = [0x33_u8; 32];
    let init_e_pub = x25519_public_key(&init_e_priv);

    let resp_e_priv = [0x44_u8; 32];
    let resp_e_pub = x25519_public_key(&resp_e_priv);

    let pair_id = hex::decode("8ab9b8bcde5c6eec845d9b1ca0d3a7be").expect("valid pair_id hex");
    let grants_hash = [0x77_u8; 32];

    // Normative RAPP session prologue (Section 4.3):
    let prologue_val = WireValue::Array(vec![
        WireValue::Text("RAPP-session-v1".to_string()),
        WireValue::Array(vec![
            WireValue::Unsigned(26),
            WireValue::Unsigned(10),
            WireValue::Unsigned(1),
        ]),
        WireValue::Text("Noise_KK_25519_ChaChaPoly_SHA512".to_string()),
        WireValue::Bytes(pair_id),
        WireValue::Bytes(grants_hash.to_vec()),
        WireValue::Text("fi.refineid.rapp.ble.v1".to_string()),
    ]);
    let prologue =
        refineid_rapp::encode_deterministic_cbor(&prologue_val).expect("encode prologue");

    // 1. Initialize symmetric state
    let protocol_name = b"Noise_KK_25519_ChaChaPoly_SHA512";
    let mut init_state = NoiseSymmetricState::new(protocol_name);
    let mut resp_state = NoiseSymmetricState::new(protocol_name);

    assert_eq!(init_state.handshake_hash(), resp_state.handshake_hash());

    // Mix prologue
    init_state.mix_hash(&prologue);
    resp_state.mix_hash(&prologue);

    // Pre-message static keys
    // -> s
    init_state.mix_hash(&init_s_pub);
    resp_state.mix_hash(&init_s_pub);
    // <- s
    init_state.mix_hash(&resp_s_pub);
    resp_state.mix_hash(&resp_s_pub);

    assert_eq!(init_state.handshake_hash(), resp_state.handshake_hash());

    // Message 1: -> e, es, ss
    // e:
    init_state.mix_hash(&init_e_pub);
    // es: DH(init_e_priv, resp_s_pub)
    let es_dh = MontgomeryPoint(resp_s_pub).mul_clamped(init_e_priv).0;
    init_state.mix_key(&es_dh);
    // ss: DH(init_s_priv, resp_s_pub)
    let ss_dh = MontgomeryPoint(resp_s_pub).mul_clamped(init_s_priv).0;
    init_state.mix_key(&ss_dh);
    // encrypt payload ("")
    let msg1_payload = init_state.encrypt_and_hash(&[]).expect("msg1 encrypt");
    assert_eq!(msg1_payload.len(), 16);
    let mut msg1_wire = Vec::new();
    msg1_wire.extend_from_slice(&init_e_pub);
    msg1_wire.extend_from_slice(&msg1_payload);
    assert_eq!(msg1_wire.len(), 48);

    // Responder reads Message 1
    resp_state.mix_hash(&init_e_pub);
    let resp_es_dh = MontgomeryPoint(init_e_pub).mul_clamped(resp_s_priv).0;
    assert_eq!(es_dh, resp_es_dh);
    resp_state.mix_key(&resp_es_dh);
    let resp_ss_dh = MontgomeryPoint(init_s_pub).mul_clamped(resp_s_priv).0;
    assert_eq!(ss_dh, resp_ss_dh);
    resp_state.mix_key(&resp_ss_dh);
    let decrypted_p1 = resp_state
        .decrypt_and_hash(&msg1_payload)
        .expect("msg1 decrypt");
    assert!(decrypted_p1.is_empty());
    assert_eq!(init_state.handshake_hash(), resp_state.handshake_hash());

    // Message 2: <- e, ee, se
    // e:
    resp_state.mix_hash(&resp_e_pub);
    // ee: DH(resp_e_priv, init_e_pub)
    let ee_dh = MontgomeryPoint(init_e_pub).mul_clamped(resp_e_priv).0;
    resp_state.mix_key(&ee_dh);
    // se: DH(resp_s_priv, init_e_pub)
    let se_dh = MontgomeryPoint(init_e_pub).mul_clamped(resp_s_priv).0;
    resp_state.mix_key(&se_dh);
    // encrypt payload ("")
    let msg2_payload = resp_state.encrypt_and_hash(&[]).expect("msg2 encrypt");
    assert_eq!(msg2_payload.len(), 16);
    let mut msg2_wire = Vec::new();
    msg2_wire.extend_from_slice(&resp_e_pub);
    msg2_wire.extend_from_slice(&msg2_payload);
    assert_eq!(msg2_wire.len(), 48);

    // Initiator reads Message 2
    init_state.mix_hash(&resp_e_pub);
    let init_ee_dh = MontgomeryPoint(resp_e_pub).mul_clamped(init_e_priv).0;
    assert_eq!(ee_dh, init_ee_dh);
    init_state.mix_key(&init_ee_dh);
    let init_se_dh = MontgomeryPoint(resp_s_pub).mul_clamped(init_e_priv).0;
    assert_eq!(se_dh, init_se_dh);
    init_state.mix_key(&init_se_dh);
    let decrypted_p2 = init_state
        .decrypt_and_hash(&msg2_payload)
        .expect("msg2 decrypt");
    assert!(decrypted_p2.is_empty());
    assert_eq!(init_state.handshake_hash(), resp_state.handshake_hash());

    // Split
    let (init_c1, init_c2) = init_state.split();
    let (resp_c1, resp_c2) = resp_state.split();
    assert_eq!(init_c1, resp_c1);
    assert_eq!(init_c2, resp_c2);

    let final_h = init_state.handshake_hash();
    let session_id = refineid_rapp::derive_session_id(&final_h);

    assert_eq!(
        hex::encode(msg1_wire),
        "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14b9cb8d7741b7e01e1d22ae0ba8162c7e"
    );
    assert_eq!(
        hex::encode(msg2_wire),
        "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b09563c45b010a21024391aba48b3e5d5"
    );
    assert_eq!(
        hex::encode(final_h),
        "0c9bb02d3c9dad8547295b18abf8fe059d7d05e09db3a80475fba9ecd2845b28a4507940006463e8e68fadf98bde037cfd382d5e2159a9f162e09f7ae5b13f4f"
    );
    assert_eq!(
        hex::encode(init_c1),
        "787a3019877a460c1eb3a7951a224d890ae8ac3241e2ec0f1d0a6593dc76a7c9"
    );
    assert_eq!(
        hex::encode(init_c2),
        "8332d92c006c218f67cd57b6b98c9a4be410be334f342d8b8e5b0d5991f48cca"
    );
    assert_eq!(
        hex::encode(session_id.as_bytes()),
        "e5d877e412bfa1cd123552614d4e9c94"
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
