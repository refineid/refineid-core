// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Noise handshake and derived-identifier conformance vectors.

use std::{fs, path::PathBuf};

use refineid_rapp::{
    MANDATORY_PAIRING_SUITE, MANDATORY_SESSION_SUITE, VISIBLE_WIRE_VERSION, WireValue,
    derive_pair_id, derive_rendezvous_token, derive_session_id, encode_deterministic_cbor,
};
use serde::Deserialize;
use snow::{
    Builder, HandshakeState,
    params::{DHChoice, NoiseParams},
    resolvers::{CryptoResolver, DefaultResolver},
};

#[derive(Deserialize)]
struct Corpus {
    noise_handshake: Vec<NoiseVector>,
}

#[derive(Deserialize)]
struct NoiseVector {
    name: String,
    suite: String,
    transport_profile: String,
    test_only_initiator_static_private_hex: String,
    initiator_static_public_hex: String,
    test_only_responder_static_private_hex: String,
    responder_static_public_hex: String,
    test_only_initiator_ephemeral_private_hex: String,
    test_only_responder_ephemeral_private_hex: String,
    prologue_hex: String,
    messages_hex: Vec<String>,
    handshake_hash_hex: String,
    session_id_hex: String,
    pair_id_hex: Option<String>,
    rendezvous_token_hex: Option<String>,
    test_only_pairing_secret_hex: Option<String>,
    offer_hash_hex: Option<String>,
    grants_hash_hex: Option<String>,
}

#[test]
fn fixed_noise_transcripts_match_the_versioned_corpus() {
    let corpus = load_corpus();
    assert_eq!(corpus.noise_handshake.len(), 2);
    for vector in &corpus.noise_handshake {
        match vector.name.as_str() {
            "pairing-xxpsk3-fixed-transcript" => verify_pairing(vector),
            "session-kk-fixed-transcript" => verify_session(vector),
            name => panic!("unknown Noise vector {name}"),
        }
    }
}

fn verify_pairing(vector: &NoiseVector) {
    assert_eq!(vector.suite, MANDATORY_PAIRING_SUITE);
    let initiator_static = fixed::<32>(&vector.test_only_initiator_static_private_hex);
    let responder_static = fixed::<32>(&vector.test_only_responder_static_private_hex);
    let initiator_ephemeral = fixed::<32>(&vector.test_only_initiator_ephemeral_private_hex);
    let responder_ephemeral = fixed::<32>(&vector.test_only_responder_ephemeral_private_hex);
    let pairing_secret = fixed::<32>(
        vector
            .test_only_pairing_secret_hex
            .as_deref()
            .expect("pairing PSK"),
    );
    let offer_hash = fixed::<32>(vector.offer_hash_hex.as_deref().expect("offer hash"));
    verify_static_public_keys(vector, &initiator_static, &responder_static);

    let prologue = encode_deterministic_cbor(&WireValue::Array(vec![
        WireValue::Text("RAPP-pairing-v1".to_owned()),
        version_value(),
        WireValue::Text(MANDATORY_PAIRING_SUITE.to_owned()),
        WireValue::Bytes(offer_hash.to_vec()),
        WireValue::Text(vector.transport_profile.clone()),
    ]))
    .expect("pairing prologue must encode");
    assert_eq!(encode_hex(&prologue), vector.prologue_hex);

    let params: NoiseParams = MANDATORY_PAIRING_SUITE.parse().expect("pairing suite");
    let mut initiator = Builder::new(params.clone())
        .local_private_key(&initiator_static)
        .expect("builder step")
        .fixed_ephemeral_key_for_testing_only(&initiator_ephemeral)
        .psk(3, &pairing_secret)
        .expect("builder step")
        .prologue(&prologue)
        .expect("builder step")
        .build_initiator()
        .expect("pairing initiator");
    let mut responder = Builder::new(params)
        .local_private_key(&responder_static)
        .expect("builder step")
        .fixed_ephemeral_key_for_testing_only(&responder_ephemeral)
        .psk(3, &pairing_secret)
        .expect("builder step")
        .prologue(&prologue)
        .expect("builder step")
        .build_responder()
        .expect("pairing responder");
    let messages = vec![
        transfer(&mut initiator, &mut responder),
        transfer(&mut responder, &mut initiator),
        transfer(&mut initiator, &mut responder),
    ];
    verify_completion(vector, &initiator, &responder, &messages);
    let handshake_hash = initiator.get_handshake_hash();
    assert_eq!(
        encode_hex(derive_pair_id(handshake_hash).as_bytes()),
        vector.pair_id_hex.as_deref().expect("pair ID")
    );
    assert_eq!(
        encode_hex(derive_rendezvous_token(handshake_hash).as_bytes()),
        vector
            .rendezvous_token_hex
            .as_deref()
            .expect("rendezvous token")
    );
}

fn verify_session(vector: &NoiseVector) {
    assert_eq!(vector.suite, MANDATORY_SESSION_SUITE);
    let initiator_static = fixed::<32>(&vector.test_only_initiator_static_private_hex);
    let responder_static = fixed::<32>(&vector.test_only_responder_static_private_hex);
    let initiator_ephemeral = fixed::<32>(&vector.test_only_initiator_ephemeral_private_hex);
    let responder_ephemeral = fixed::<32>(&vector.test_only_responder_ephemeral_private_hex);
    let pair_id = fixed::<16>(vector.pair_id_hex.as_deref().expect("pair ID"));
    let grants_hash = fixed::<32>(vector.grants_hash_hex.as_deref().expect("grants hash"));
    let initiator_public = verify_static_public_keys(vector, &initiator_static, &responder_static);
    let responder_public = public_key(&responder_static);

    let prologue = encode_deterministic_cbor(&WireValue::Array(vec![
        WireValue::Text("RAPP-session-v1".to_owned()),
        version_value(),
        WireValue::Text(MANDATORY_SESSION_SUITE.to_owned()),
        WireValue::Bytes(pair_id.to_vec()),
        WireValue::Bytes(grants_hash.to_vec()),
        WireValue::Text(vector.transport_profile.clone()),
    ]))
    .expect("session prologue must encode");
    assert_eq!(encode_hex(&prologue), vector.prologue_hex);

    let params: NoiseParams = MANDATORY_SESSION_SUITE.parse().expect("session suite");
    let mut initiator = Builder::new(params.clone())
        .local_private_key(&initiator_static)
        .expect("builder step")
        .remote_public_key(&responder_public)
        .expect("builder step")
        .fixed_ephemeral_key_for_testing_only(&initiator_ephemeral)
        .prologue(&prologue)
        .expect("builder step")
        .build_initiator()
        .expect("session initiator");
    let mut responder = Builder::new(params)
        .local_private_key(&responder_static)
        .expect("builder step")
        .remote_public_key(&initiator_public)
        .expect("builder step")
        .fixed_ephemeral_key_for_testing_only(&responder_ephemeral)
        .prologue(&prologue)
        .expect("builder step")
        .build_responder()
        .expect("session responder");
    let messages = vec![
        transfer(&mut initiator, &mut responder),
        transfer(&mut responder, &mut initiator),
    ];
    verify_completion(vector, &initiator, &responder, &messages);
}

fn verify_completion(
    vector: &NoiseVector,
    initiator: &HandshakeState,
    responder: &HandshakeState,
    messages: &[Vec<u8>],
) {
    assert!(initiator.is_handshake_finished());
    assert!(responder.is_handshake_finished());
    assert_eq!(
        initiator.get_handshake_hash(),
        responder.get_handshake_hash()
    );
    assert_eq!(
        encode_hex(initiator.get_handshake_hash()),
        vector.handshake_hash_hex
    );
    assert_eq!(
        messages
            .iter()
            .map(|message| encode_hex(message))
            .collect::<Vec<_>>(),
        vector.messages_hex
    );
    assert_eq!(
        encode_hex(derive_session_id(initiator.get_handshake_hash()).as_bytes()),
        vector.session_id_hex
    );
    assert_eq!(
        encode_hex(initiator.get_remote_static().expect("responder static")),
        vector.responder_static_public_hex
    );
    assert_eq!(
        encode_hex(responder.get_remote_static().expect("initiator static")),
        vector.initiator_static_public_hex
    );
}

fn verify_static_public_keys(
    vector: &NoiseVector,
    initiator_private: &[u8; 32],
    responder_private: &[u8; 32],
) -> Vec<u8> {
    let initiator_public = public_key(initiator_private);
    let responder_public = public_key(responder_private);
    assert_eq!(
        encode_hex(&initiator_public),
        vector.initiator_static_public_hex
    );
    assert_eq!(
        encode_hex(&responder_public),
        vector.responder_static_public_hex
    );
    initiator_public
}

fn public_key(private: &[u8; 32]) -> Vec<u8> {
    let mut dh = DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .expect("X25519 resolver");
    dh.set(private);
    dh.pubkey().to_vec()
}

fn transfer(writer: &mut HandshakeState, reader: &mut HandshakeState) -> Vec<u8> {
    let mut message = vec![0_u8; 65_535];
    let length = writer
        .write_message(&[], &mut message)
        .expect("write empty Noise payload");
    message.truncate(length);
    let mut payload = vec![0_u8; 65_535];
    let payload_length = reader
        .read_message(&message, &mut payload)
        .expect("read Noise message");
    assert_eq!(payload_length, 0, "RAPP forbids Noise handshake payloads");
    message
}

fn version_value() -> WireValue {
    WireValue::Array(vec![
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.0)),
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.1)),
        WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.2)),
    ])
}

fn fixed<const N: usize>(value: &str) -> [u8; N] {
    decode_hex(value)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} bytes, got {}", bytes.len()))
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "hex input must have complete bytes"
    );
    let (pairs, _) = value.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(digits, 16).expect("valid hex")
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

fn load_corpus() -> Corpus {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/protocols/vectors/rapp-v26.9.13.json");
    serde_json::from_slice(&fs::read(path).expect("read RAPP corpus")).expect("decode RAPP corpus")
}
