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

//! Verification of the versioned, implementation-independent RAPP corpus.

use std::collections::{BTreeMap, HashSet};

use refineid_rapp::{
    OperationId, ProfileName, RendezvousToken, SessionId, StreamError, StreamRendezvous, WireValue,
    compute_grants_hash, compute_request_hash, decode_deterministic_cbor, derive_pair_id,
    derive_rendezvous_token, derive_session_id, encode_deterministic_cbor,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-v26.9.13.json");

#[derive(Debug, Deserialize)]
struct Corpus {
    format: String,
    protocol_document_version: String,
    deterministic_cbor: Vec<CborVector>,
    identifier_derivation: Vec<IdentifierVector>,
    grants_hash: Vec<GrantsVector>,
    request_hash: Vec<RequestVector>,
    rejected_cbor: Vec<RejectedCborVector>,
    stream_rendezvous: Vec<StreamVector>,
}

#[derive(Debug, Deserialize)]
struct CborVector {
    name: String,
    value: CorpusValue,
    encoded_hex: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CorpusValue {
    Unsigned { value: u64 },
    Negative { value: i64 },
    Bytes { hex: String },
    Text { value: String },
    Array { items: Vec<Self> },
    Map { entries: Vec<CorpusMapEntry> },
    Bool { value: bool },
    Null,
}

#[derive(Clone, Debug, Deserialize)]
struct CorpusMapEntry {
    key: String,
    value: CorpusValue,
}

#[derive(Debug, Deserialize)]
struct IdentifierVector {
    name: String,
    handshake_hash_hex: String,
    pair_id_hex: String,
    session_id_hex: String,
    rendezvous_token_hex: String,
}

#[derive(Debug, Deserialize)]
struct StreamVector {
    name: String,
    purpose: String,
    #[serde(default)]
    rendezvous_token_hex: Option<String>,
    encoded_hex: String,
    accepted: bool,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GrantsVector {
    name: String,
    profiles: Vec<String>,
    canonical_cbor_hex: String,
    sha256_hex: String,
}

#[derive(Debug, Deserialize)]
struct RequestVector {
    name: String,
    session_id_hex: String,
    operation_id_hex: String,
    profile: String,
    action: String,
    context: CorpusValue,
    payload: CorpusValue,
    preimage_cbor_hex: String,
    sha256_hex: String,
}

#[derive(Debug, Deserialize)]
struct RejectedCborVector {
    name: String,
    encoded_hex: String,
    error: String,
}

#[test]
fn corpus_metadata_and_names_are_stable() {
    let corpus = corpus();
    assert_eq!(corpus.format, "fi.refineid.rapp.conformance-v1");
    assert_eq!(corpus.protocol_document_version, "26.9.13");
    assert_eq!(corpus.deterministic_cbor.len(), 15);
    assert_eq!(corpus.identifier_derivation.len(), 2);
    assert_eq!(corpus.grants_hash.len(), 3);
    assert_eq!(corpus.request_hash.len(), 1);
    assert_eq!(corpus.rejected_cbor.len(), 8);
    assert_eq!(corpus.stream_rendezvous.len(), 5);

    let names = corpus
        .deterministic_cbor
        .iter()
        .map(|vector| vector.name.as_str())
        .chain(
            corpus
                .identifier_derivation
                .iter()
                .map(|vector| vector.name.as_str()),
        )
        .chain(corpus.grants_hash.iter().map(|vector| vector.name.as_str()))
        .chain(
            corpus
                .request_hash
                .iter()
                .map(|vector| vector.name.as_str()),
        )
        .chain(
            corpus
                .rejected_cbor
                .iter()
                .map(|vector| vector.name.as_str()),
        )
        .chain(
            corpus
                .stream_rendezvous
                .iter()
                .map(|vector| vector.name.as_str()),
        );
    let mut unique = HashSet::new();
    for name in names {
        assert!(unique.insert(name), "duplicate corpus vector name {name}");
    }
}

#[test]
fn deterministic_cbor_matches_golden_bytes_and_round_trips() {
    for vector in corpus().deterministic_cbor {
        let value = to_wire_value(vector.value);
        let expected = decode_hex(&vector.encoded_hex);
        let encoded = encode_deterministic_cbor(&value).expect("corpus value must encode");
        assert_eq!(encoded, expected, "{} encoded bytes", vector.name);
        let decoded = decode_deterministic_cbor(&expected).expect("golden CBOR must decode");
        assert_eq!(decoded, value, "{} decoded value", vector.name);
        assert_eq!(
            encode_deterministic_cbor(&decoded).expect("decoded value must re-encode"),
            expected,
            "{} canonical re-encoding",
            vector.name
        );
    }
}

#[test]
fn derived_identifiers_match_golden_values() {
    for vector in corpus().identifier_derivation {
        let handshake_hash = decode_hex(&vector.handshake_hash_hex);
        assert_eq!(
            derive_pair_id(&handshake_hash).as_bytes().as_slice(),
            decode_hex(&vector.pair_id_hex),
            "{} pair id",
            vector.name
        );
        assert_eq!(
            derive_session_id(&handshake_hash).as_bytes().as_slice(),
            decode_hex(&vector.session_id_hex),
            "{} session id",
            vector.name
        );
        assert_eq!(
            derive_rendezvous_token(&handshake_hash)
                .as_bytes()
                .as_slice(),
            decode_hex(&vector.rendezvous_token_hex),
            "{} rendezvous token",
            vector.name
        );
    }
}

#[test]
fn stream_rendezvous_preambles_match_golden_bytes_and_rejections() {
    for vector in corpus().stream_rendezvous {
        let encoded = decode_hex(&vector.encoded_hex);
        let outcome = StreamRendezvous::decode(&encoded);
        if vector.accepted {
            let decoded = outcome.expect("accepted preamble must decode");
            let expected = match vector.purpose.as_str() {
                "pairing" => StreamRendezvous::Pairing,
                "session" => StreamRendezvous::Session(
                    RendezvousToken::reconstruct(&decode_hex(
                        vector
                            .rendezvous_token_hex
                            .as_deref()
                            .expect("session token"),
                    ))
                    .expect("token length"),
                ),
                other => panic!("unregistered accepted purpose {other}"),
            };
            assert_eq!(decoded, expected, "{} decoded preamble", vector.name);
            assert_eq!(
                decoded.encode().expect("preamble must re-encode"),
                encoded,
                "{} canonical re-encoding",
                vector.name
            );
        } else {
            let error = outcome.expect_err("rejected preamble must not decode");
            let expected = match vector.error.as_deref().expect("rejection class") {
                "Malformed" => StreamError::Malformed,
                "Oversized" => StreamError::Oversized,
                "UnknownPurpose" => StreamError::UnknownPurpose,
                other => panic!("unregistered rejection class {other}"),
            };
            assert_eq!(error, expected, "{} rejection class", vector.name);
        }
    }
}

#[test]
fn grants_hash_normalizes_profile_order_and_matches_golden_values() {
    for vector in corpus().grants_hash {
        let profiles = vector
            .profiles
            .iter()
            .map(|name| ProfileName::parse(name).expect("registered profile"))
            .collect::<Vec<_>>();
        let actual = compute_grants_hash(&profiles).expect("grants hash must compute");
        assert_eq!(
            actual.as_bytes().as_slice(),
            decode_hex(&vector.sha256_hex),
            "{} digest",
            vector.name
        );

        let mut canonical_names = vector.profiles.clone();
        canonical_names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let preimage = WireValue::Array(canonical_names.into_iter().map(WireValue::Text).collect());
        assert_eq!(
            encode_deterministic_cbor(&preimage).expect("grants preimage must encode"),
            decode_hex(&vector.canonical_cbor_hex),
            "{} canonical preimage",
            vector.name
        );
    }
}

#[test]
fn request_hash_preimage_and_digest_match_golden_values() {
    for vector in corpus().request_hash {
        let session_bytes = decode_hex(&vector.session_id_hex);
        let operation_bytes = decode_hex(&vector.operation_id_hex);
        let session_id = SessionId::reconstruct(&session_bytes).expect("session id length");
        let operation_id = OperationId::reconstruct(&operation_bytes).expect("operation id length");
        let profile = ProfileName::parse(&vector.profile).expect("registered profile");
        let context = to_wire_map(vector.context.clone());
        let payload = to_wire_map(vector.payload.clone());

        let preimage = WireValue::Array(vec![
            WireValue::Text("RAPP-request-v1".into()),
            WireValue::Bytes(session_bytes),
            WireValue::Bytes(operation_bytes),
            WireValue::Text(profile.as_str().into()),
            WireValue::Text(vector.action.clone()),
            WireValue::Map(context.clone()),
            WireValue::Map(payload.clone()),
        ]);
        assert_eq!(
            encode_deterministic_cbor(&preimage).expect("request preimage must encode"),
            decode_hex(&vector.preimage_cbor_hex),
            "{} preimage",
            vector.name
        );

        let actual = compute_request_hash(
            session_id,
            operation_id,
            profile,
            &vector.action,
            context,
            payload,
        )
        .expect("request hash must compute");
        assert_eq!(
            actual.as_bytes().as_slice(),
            decode_hex(&vector.sha256_hex),
            "{} digest",
            vector.name
        );
    }
}

#[test]
fn forbidden_and_noncanonical_cbor_is_rejected_by_class() {
    for vector in corpus().rejected_cbor {
        let error = decode_deterministic_cbor(&decode_hex(&vector.encoded_hex))
            .expect_err("negative corpus value must be rejected");
        assert_eq!(format!("{error:?}"), vector.error, "{} error", vector.name);
    }
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("the checked-in RAPP corpus must be valid JSON")
}

fn to_wire_map(value: CorpusValue) -> BTreeMap<String, WireValue> {
    match to_wire_value(value) {
        WireValue::Map(map) => map,
        _ => panic!("corpus request context and payload must be maps"),
    }
}

fn to_wire_value(value: CorpusValue) -> WireValue {
    match value {
        CorpusValue::Unsigned { value } => WireValue::Unsigned(value),
        CorpusValue::Negative { value } => WireValue::Negative(value),
        CorpusValue::Bytes { hex } => WireValue::Bytes(decode_hex(&hex)),
        CorpusValue::Text { value } => WireValue::Text(value),
        CorpusValue::Array { items } => {
            WireValue::Array(items.into_iter().map(to_wire_value).collect())
        }
        CorpusValue::Map { entries } => WireValue::Map(
            entries
                .into_iter()
                .map(|entry| (entry.key, to_wire_value(entry.value)))
                .collect(),
        ),
        CorpusValue::Bool { value } => WireValue::Bool(value),
        CorpusValue::Null => WireValue::Null,
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "hex must have an even length"
    );
    let (pairs, _) = value.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("hex must be ASCII");
            u8::from_str_radix(pair, 16).expect("hex must contain only hexadecimal digits")
        })
        .collect()
}
