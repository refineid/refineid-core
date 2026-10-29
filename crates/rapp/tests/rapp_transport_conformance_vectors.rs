// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Replay of the RAPP v26.10.29 transport-bound corpus sections: pairing
//! offers, busy answers, CPace KC2 transcripts per transport, both Noise transcripts per
//! transport (cross-checked against snow).

use refineid_rapp::{
    BinaryFrame, BootstrapAnswer, CpaceKc2Initiator, CpaceKc2Responder, HandshakeRole, OfferId,
    PairingBusy, PairingOffer, TransportProfile,
    cpace::{calculate_generator_kc2, generator_string, prepend_len},
    derive_pair_id, derive_session_id, encode_kc2_step1_frame,
    noise::{KkHandshakeState, x25519_public_key},
    standard_pairing_context_v2,
};
use serde::Deserialize;
use sha2::{Sha512, digest::common::BlockSizeUser};

const CORPUS: &str = include_str!("../../../doc/protocols/vectors/rapp-v26.10.29.json");

#[derive(Deserialize)]
struct Corpus {
    pairing_offer: Vec<OfferVector>,
    pairing_busy: Vec<BusyVector>,
    rejected_pairing_busy: Vec<RejectedBusyVector>,
    cpace_kc2: Vec<Kc2Vector>,
    noise_handshake: Vec<NoiseVector>,
}

#[derive(Deserialize)]
struct OfferVector {
    name: String,
    offer_id_hex: String,
    profiles: Vec<String>,
    transport_profiles: Vec<String>,
    encoded_hex: String,
    encoded_length: usize,
    offer_hash_hex: String,
}

#[derive(Deserialize)]
struct BusyVector {
    name: String,
    retry_after_ms: u64,
    encoded_hex: String,
}

#[derive(Deserialize)]
struct RejectedBusyVector {
    name: String,
    encoded_hex: String,
    error: String,
}

#[derive(Deserialize)]
struct Kc2Vector {
    name: String,
    transport_profile: String,
    candidate_id: String,
    offer_hash_hex: String,
    offer_id_hex: String,
    pairing_code: String,
    context_hex: String,
    context_length: usize,
    generator_hex: String,
    test_only_initiator_random_hex: String,
    test_only_responder_random_hex: String,
    step1_hex: String,
    step2_hex: String,
    step3_hex: String,
}

#[derive(Deserialize)]
struct NoiseVector {
    name: String,
    suite: String,
    transport_profile: String,
    prologue_hex: String,
    messages_hex: Vec<String>,
    handshake_hash_hex: String,
    session_id_hex: String,
    #[serde(default)]
    pair_id_hex: Option<String>,
    #[serde(default)]
    test_only_pairing_secret_hex: Option<String>,
    test_only_initiator_static_private_hex: String,
    test_only_responder_static_private_hex: String,
    test_only_initiator_ephemeral_private_hex: String,
    test_only_responder_ephemeral_private_hex: String,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("the checked-in RAPP corpus must be valid JSON")
}

fn bytes(text: &str) -> Vec<u8> {
    hex::decode(text).expect("corpus hex is valid")
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    bytes(text)
        .try_into()
        .expect("corpus value has its fixed length")
}

fn profile(name: &str) -> TransportProfile {
    TransportProfile::parse(name).expect("corpus names a registered transport")
}

#[test]
fn offers_encode_decode_and_hash_to_the_corpus() {
    for vector in corpus().pairing_offer {
        let transports: Vec<_> = vector
            .transport_profiles
            .iter()
            .map(|name| profile(name))
            .collect();
        let offer = PairingOffer::create(
            OfferId::from_array(array(&vector.offer_id_hex)),
            vector.profiles.clone(),
            &transports,
        )
        .expect("corpus offer is valid");
        let encoded = offer.to_cbor().expect("offer encodes");
        assert_eq!(hex::encode(&encoded), vector.encoded_hex, "{}", vector.name);
        assert_eq!(encoded.len(), vector.encoded_length, "{}", vector.name);
        assert!(
            encoded.len() <= refineid_rapp::MAX_OFFER_SIZE,
            "{}",
            vector.name
        );
        assert_eq!(
            hex::encode(offer.offer_hash().expect("offer hashes")),
            vector.offer_hash_hex,
            "{}",
            vector.name
        );
        for transport in &transports {
            assert_eq!(
                BootstrapAnswer::from_bootstrap(&encoded, *transport).expect("bootstrap decodes"),
                BootstrapAnswer::Offer(offer.clone()),
                "{}",
                vector.name
            );
        }
    }
}

#[test]
fn kc2_transcripts_bind_the_transport_of_the_connection() {
    let corpus = corpus();
    assert_eq!(corpus.cpace_kc2.len(), 2);
    for vector in corpus.cpace_kc2 {
        let transport = profile(&vector.transport_profile);
        assert_eq!(transport.candidate_id(), vector.candidate_id);
        let context = standard_pairing_context_v2(
            &array(&vector.offer_hash_hex),
            transport.name(),
            transport.candidate_id(),
        )
        .expect("context encodes");
        assert_eq!(hex::encode(&context), vector.context_hex, "{}", vector.name);
        assert_eq!(context.len(), vector.context_length, "{}", vector.name);
        let offer_id = OfferId::from_array(array(&vector.offer_id_hex));
        let generator = calculate_generator_kc2(
            vector.pairing_code.as_bytes(),
            &context,
            offer_id.as_bytes(),
        )
        .expect("generator derives");
        assert_eq!(
            hex::encode(generator.compress().to_bytes()),
            vector.generator_hex,
            "{}",
            vector.name
        );
        let (initiator, step1_point) = CpaceKc2Initiator::new(
            &vector.pairing_code,
            &context,
            &offer_id,
            &array(&vector.test_only_initiator_random_hex),
        )
        .expect("initiator starts");
        let step1 = encode_kc2_step1_frame(&step1_point).expect("step 1 encodes");
        assert_eq!(
            hex::encode(step1.as_bytes()),
            vector.step1_hex,
            "{}",
            vector.name
        );
        let (step2, waiting) = CpaceKc2Responder::process_step1_frame(
            &vector.pairing_code,
            &context,
            &offer_id,
            &step1,
            &array(&vector.test_only_responder_random_hex),
        )
        .expect("responder answers");
        assert_eq!(
            hex::encode(step2.as_bytes()),
            vector.step2_hex,
            "{}",
            vector.name
        );
        let (step3, _) = initiator.process_step2_frame(&step2).expect("T_B verifies");
        assert_eq!(
            hex::encode(step3.as_bytes()),
            vector.step3_hex,
            "{}",
            vector.name
        );
        waiting
            .process_step3_frame(
                &BinaryFrame::reconstruct(bytes(&vector.step3_hex)).expect("frame fits"),
            )
            .expect("T_A verifies");
    }
}

/// The Ristretto255 domain separator of draft-irtf-cfrg-cpace-21 section 6.2.
const CPACE_DSI: &[u8] = b"CPaceRistretto255";

/// The generator string is lv(DSI) || lv(PRS) || lv(zero padding) || lv(C) ||
/// lv(SID), and its first three fields fill exactly one SHA-512 input block
/// (RAPP v26.10.29 section 6.1.2).
#[test]
fn generator_strings_fill_one_hash_block_before_the_context() {
    let block = <Sha512 as BlockSizeUser>::block_size();
    for vector in corpus().cpace_kc2 {
        let context = bytes(&vector.context_hex);
        let sid = bytes(&vector.offer_id_hex);
        assert_eq!(context.len(), vector.context_length, "{}", vector.name);
        let generator = generator_string(
            CPACE_DSI,
            vector.pairing_code.as_bytes(),
            &context,
            &sid,
            block,
        );
        let tail = [prepend_len(&context), prepend_len(&sid)].concat();
        assert!(generator.ends_with(&tail), "{}", vector.name);
        assert_eq!(generator.len() - tail.len(), block, "{}", vector.name);
    }
}

fn snow_transcript(vector: &NoiseVector) -> (Vec<String>, Vec<u8>) {
    let params: snow::params::NoiseParams = vector.suite.parse().expect("suite parses");
    let prologue = bytes(&vector.prologue_hex);
    let initiator_static = bytes(&vector.test_only_initiator_static_private_hex);
    let responder_static = bytes(&vector.test_only_responder_static_private_hex);
    let initiator_ephemeral = bytes(&vector.test_only_initiator_ephemeral_private_hex);
    let responder_ephemeral = bytes(&vector.test_only_responder_ephemeral_private_hex);
    let initiator_public =
        x25519_public_key(&array(&vector.test_only_initiator_static_private_hex));
    let responder_public =
        x25519_public_key(&array(&vector.test_only_responder_static_private_hex));
    let psk: Option<[u8; 32]> = vector.test_only_pairing_secret_hex.as_deref().map(array);
    let mut initiator = snow::Builder::new(params.clone())
        .local_private_key(&initiator_static)
        .expect("key")
        .fixed_ephemeral_key_for_testing_only(&initiator_ephemeral)
        .prologue(&prologue)
        .expect("prologue");
    let mut responder = snow::Builder::new(params)
        .local_private_key(&responder_static)
        .expect("key")
        .fixed_ephemeral_key_for_testing_only(&responder_ephemeral)
        .prologue(&prologue)
        .expect("prologue");
    if let Some(psk) = psk.as_ref() {
        initiator = initiator.psk(3, psk).expect("psk");
        responder = responder.psk(3, psk).expect("psk");
    } else {
        initiator = initiator.remote_public_key(&responder_public).expect("key");
        responder = responder.remote_public_key(&initiator_public).expect("key");
    }
    let mut initiator = initiator.build_initiator().expect("initiator");
    let mut responder = responder.build_responder().expect("responder");
    let mut buffer = [0_u8; 256];
    let mut payload = [0_u8; 256];
    let mut messages = Vec::new();
    for index in 0..vector.messages_hex.len() {
        let (writer, reader) = if index % 2 == 0 {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let length = writer.write_message(&[], &mut buffer).expect("write");
        messages.push(hex::encode(&buffer[..length]));
        reader
            .read_message(&buffer[..length], &mut payload)
            .expect("read");
    }
    (messages, initiator.get_handshake_hash().to_vec())
}

#[test]
fn noise_transcripts_match_snow_and_derive_their_identifiers() {
    let corpus = corpus();
    assert_eq!(corpus.noise_handshake.len(), 4);
    for vector in &corpus.noise_handshake {
        profile(&vector.transport_profile);
        let (messages, hash) = snow_transcript(vector);
        assert_eq!(messages, vector.messages_hex, "{}", vector.name);
        assert_eq!(
            hex::encode(&hash),
            vector.handshake_hash_hex,
            "{}",
            vector.name
        );
        assert_eq!(
            hex::encode(derive_session_id(&hash).as_bytes()),
            vector.session_id_hex,
            "{}",
            vector.name
        );
        if let Some(pair_id) = &vector.pair_id_hex
            && vector.test_only_pairing_secret_hex.is_some()
        {
            assert_eq!(
                &hex::encode(derive_pair_id(&hash).as_bytes()),
                pair_id,
                "{}",
                vector.name
            );
        }
    }
}

#[test]
fn native_kk_replays_the_session_transcripts() {
    for vector in corpus()
        .noise_handshake
        .iter()
        .filter(|vector| vector.test_only_pairing_secret_hex.is_none())
    {
        let prologue = bytes(&vector.prologue_hex);
        let initiator_static = array(&vector.test_only_initiator_static_private_hex);
        let responder_static = array(&vector.test_only_responder_static_private_hex);
        let mut initiator = KkHandshakeState::new(
            HandshakeRole::Initiator,
            &initiator_static,
            &x25519_public_key(&responder_static),
            &prologue,
        )
        .expect("initiator");
        initiator.set_fixed_ephemeral_for_testing(array(
            &vector.test_only_initiator_ephemeral_private_hex,
        ));
        let mut responder = KkHandshakeState::new(
            HandshakeRole::Responder,
            &responder_static,
            &x25519_public_key(&initiator_static),
            &prologue,
        )
        .expect("responder");
        responder.set_fixed_ephemeral_for_testing(array(
            &vector.test_only_responder_ephemeral_private_hex,
        ));
        let mut message = [0_u8; 64];
        let mut payload = [0_u8; 64];
        let length = initiator
            .write_message(&[], &mut message)
            .expect("message 1");
        assert_eq!(
            hex::encode(&message[..length]),
            vector.messages_hex[0],
            "{}",
            vector.name
        );
        responder
            .read_message(&message[..length], &mut payload)
            .expect("read 1");
        let length = responder
            .write_message(&[], &mut message)
            .expect("message 2");
        assert_eq!(
            hex::encode(&message[..length]),
            vector.messages_hex[1],
            "{}",
            vector.name
        );
        initiator
            .read_message(&message[..length], &mut payload)
            .expect("read 2");
        assert_eq!(
            hex::encode(initiator.handshake_hash()),
            vector.handshake_hash_hex,
            "{}",
            vector.name
        );
    }
}

#[test]
fn busy_answers_encode_and_decode_to_the_corpus() {
    let transports = [TransportProfile::Ble, TransportProfile::Stream];
    for vector in corpus().pairing_busy {
        let busy = PairingBusy::new(vector.retry_after_ms).expect("the corpus wait is in range");
        let encoded = bytes(&vector.encoded_hex);
        assert_eq!(
            busy.to_cbor().expect("busy encodes"),
            encoded,
            "{}",
            vector.name
        );
        for transport in transports {
            assert_eq!(
                BootstrapAnswer::from_bootstrap(&encoded, transport),
                Ok(BootstrapAnswer::Busy(busy)),
                "{}",
                vector.name
            );
        }
    }
}

#[test]
fn malformed_busy_answers_are_refused_for_their_stated_reason() {
    for vector in corpus().rejected_pairing_busy {
        let encoded = bytes(&vector.encoded_hex);
        let error = PairingBusy::from_cbor(&encoded).expect_err(&vector.name);
        assert_eq!(format!("{error:?}"), vector.error, "{}", vector.name);
        assert!(
            BootstrapAnswer::from_bootstrap(&encoded, TransportProfile::Stream).is_err(),
            "{}",
            vector.name
        );
    }
}
