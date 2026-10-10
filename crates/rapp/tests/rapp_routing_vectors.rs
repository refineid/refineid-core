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

//! Discovery hints and session routing (RAPP v26.10.10 §2.2.1 and §4.3)
//! against their corpus.

use refineid_rapp::{
    AnnouncementCandidate, DiscoveryKey, DiscoveryRecord, PairId, RoutingKey, RoutingPreamble,
    RoutingReplayCache, SessionRouting, TransportProfile, discovery_epoch,
    noise::x25519_public_key, route_session,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-routing-v26.10.10.json");

#[derive(Deserialize)]
struct Corpus {
    format: String,
    protocol_document_version: String,
    pair_keys: Vec<KeyVector>,
    discovery_hint: Vec<HintVector>,
    discovery_acceptance: Vec<AcceptanceVector>,
    routing_tag: Vec<TagVector>,
    routing_preamble: Vec<PreambleVector>,
    routing_lookup: Vec<LookupVector>,
    discovery_record: Vec<RecordVector>,
    announcement_selection: Vec<SelectionVector>,
}

#[derive(Deserialize)]
struct RecordVector {
    name: String,
    txt: Vec<(String, String)>,
    #[serde(default)]
    hints_hex: Vec<String>,
    expected: String,
}

#[derive(Deserialize)]
struct SelectionVector {
    name: String,
    candidates: Vec<CandidateVector>,
    announced_hex: Vec<String>,
}

#[derive(Deserialize)]
struct CandidateVector {
    hint_hex: String,
    last_used_ms: u64,
}

#[derive(Deserialize)]
struct KeyVector {
    pair_id_hex: String,
    custodian_static_private_hex: String,
    requester_static_private_hex: String,
}

#[derive(Deserialize)]
struct HintVector {
    name: String,
    unix_time_seconds: u64,
    epoch: u64,
    discovery_hint_hex: String,
}

#[derive(Deserialize)]
struct AcceptanceVector {
    name: String,
    published_hint_hex: String,
    requester_epoch: u64,
    expected: String,
}

#[derive(Deserialize)]
struct TagVector {
    name: String,
    transport_profile: String,
    nonce_hex: String,
    routing_tag_hex: String,
}

#[derive(Deserialize)]
struct PreambleVector {
    name: String,
    transport_profile: String,
    purpose: String,
    #[serde(default)]
    nonce_hex: Option<String>,
    #[serde(default)]
    routing_tag_hex: Option<String>,
    encoded_hex: String,
}

#[derive(Deserialize)]
struct LookupVector {
    name: String,
    transport_profile: String,
    routing_hex: String,
    custodian_pair_ids_hex: Vec<String>,
    expected_index: Option<usize>,
}

/// The fixed endpoint keys of the corpus.
struct Endpoints {
    pair_id: PairId,
    custodian_private: [u8; 32],
    custodian_public: [u8; 32],
    requester_private: [u8; 32],
    requester_public: [u8; 32],
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("the checked-in routing corpus must be valid JSON")
}

fn bytes(text: &str) -> Vec<u8> {
    hex::decode(text).expect("corpus hex")
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    bytes(text).try_into().expect("corpus length")
}

fn pair_id(text: &str) -> PairId {
    PairId::reconstruct(&bytes(text)).expect("pair id length")
}

fn profile(name: &str) -> TransportProfile {
    TransportProfile::parse(name).expect("registered profile")
}

fn endpoints() -> Endpoints {
    let vector = corpus().pair_keys.remove(0);
    let custodian_private = array(&vector.custodian_static_private_hex);
    let requester_private = array(&vector.requester_static_private_hex);
    Endpoints {
        pair_id: pair_id(&vector.pair_id_hex),
        custodian_private,
        custodian_public: x25519_public_key(&custodian_private),
        requester_private,
        requester_public: x25519_public_key(&requester_private),
    }
}

fn custodian_routing_key(keys: &Endpoints, pair: PairId) -> RoutingKey {
    RoutingKey::from_parts(pair, &keys.custodian_private, &keys.requester_public).expect("key")
}

#[test]
fn corpus_names_its_version() {
    let corpus = corpus();
    assert_eq!(corpus.format, "fi.refineid.rapp.routing-vectors-v1");
    assert_eq!(corpus.protocol_document_version, "26.10.10");
}

#[test]
fn discovery_hints_match_on_both_endpoints() {
    let keys = endpoints();
    let custodian = DiscoveryKey::from_parts(
        keys.pair_id,
        &keys.custodian_private,
        &keys.requester_public,
    )
    .expect("key");
    let requester = DiscoveryKey::from_parts(
        keys.pair_id,
        &keys.requester_private,
        &keys.custodian_public,
    )
    .expect("key");
    for vector in corpus().discovery_hint {
        assert_eq!(
            discovery_epoch(vector.unix_time_seconds),
            vector.epoch,
            "{}",
            vector.name
        );
        for key in [&custodian, &requester] {
            assert_eq!(
                hex::encode(key.hint(vector.epoch)),
                vector.discovery_hint_hex,
                "{}",
                vector.name
            );
        }
    }
}

#[test]
fn discovery_acceptance_follows_the_corpus() {
    let keys = endpoints();
    let requester = DiscoveryKey::from_parts(
        keys.pair_id,
        &keys.requester_private,
        &keys.custodian_public,
    )
    .expect("key");
    for vector in corpus().discovery_acceptance {
        let accepted =
            requester.matches(&array(&vector.published_hint_hex), vector.requester_epoch);
        assert_eq!(accepted, vector.expected == "accepted", "{}", vector.name);
    }
}

#[test]
fn routing_tags_match_on_both_endpoints() {
    let keys = endpoints();
    let requester = RoutingKey::from_parts(
        keys.pair_id,
        &keys.requester_private,
        &keys.custodian_public,
    )
    .expect("key");
    let custodian = custodian_routing_key(&keys, keys.pair_id);
    for vector in corpus().routing_tag {
        let nonce = array(&vector.nonce_hex);
        let profile = profile(&vector.transport_profile);
        for key in [&requester, &custodian] {
            assert_eq!(
                hex::encode(key.tag(profile, &nonce)),
                vector.routing_tag_hex,
                "{}",
                vector.name
            );
        }
    }
}

#[test]
fn preambles_match_golden_bytes() {
    for vector in corpus().routing_preamble {
        let profile = profile(&vector.transport_profile);
        let encoded = bytes(&vector.encoded_hex);
        let decoded = RoutingPreamble::decode(profile, &encoded).expect("golden preamble decodes");
        let expected = match vector.purpose.as_str() {
            "pairing" => RoutingPreamble::Pairing,
            "session" => {
                let mut routing = bytes(vector.nonce_hex.as_deref().expect("nonce"));
                routing.extend(bytes(vector.routing_tag_hex.as_deref().expect("tag")));
                RoutingPreamble::Session(
                    SessionRouting::from_bytes(&routing).expect("routing length"),
                )
            }
            other => panic!("unregistered purpose {other}"),
        };
        assert_eq!(decoded, expected, "{}", vector.name);
        assert_eq!(
            decoded.encode(profile).expect("re-encode"),
            encoded,
            "{}",
            vector.name
        );
    }
}

#[test]
fn custodian_lookup_follows_the_corpus() {
    let keys = endpoints();
    for vector in corpus().routing_lookup {
        let routing = SessionRouting::from_bytes(&bytes(&vector.routing_hex)).expect("length");
        let stored = vector
            .custodian_pair_ids_hex
            .iter()
            .map(|text| custodian_routing_key(&keys, pair_id(text)))
            .collect::<Vec<_>>();
        assert_eq!(
            route_session(&stored, profile(&vector.transport_profile), &routing),
            vector.expected_index,
            "{}",
            vector.name
        );
    }
}

#[test]
fn a_routed_nonce_is_refused_the_second_time() {
    let vector = corpus().routing_lookup.remove(0);
    let routing = SessionRouting::from_bytes(&bytes(&vector.routing_hex)).expect("length");
    let mut cache = RoutingReplayCache::default();
    assert!(cache.admit(routing.nonce()));
    assert!(!cache.admit(routing.nonce()));
}

#[test]
fn session_records_parse_as_the_corpus_says() {
    for vector in corpus().discovery_record {
        let pairs: Vec<(&str, &str)> = vector
            .txt
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        match DiscoveryRecord::parse(&pairs) {
            Ok(record) => {
                assert_eq!(vector.expected, "accepted", "{}", vector.name);
                let hints = record.hints().iter().map(hex::encode).collect::<Vec<_>>();
                assert_eq!(hints, vector.hints_hex, "{}", vector.name);
            }
            Err(_) => assert_eq!(vector.expected, "rejected", "{}", vector.name),
        }
    }
}

#[test]
fn session_records_announce_the_most_recently_used_pairings() {
    for vector in corpus().announcement_selection {
        let candidates = vector
            .candidates
            .iter()
            .map(|candidate| AnnouncementCandidate {
                hint: array(&candidate.hint_hex),
                last_used_ms: candidate.last_used_ms,
            })
            .collect::<Vec<_>>();
        let record = DiscoveryRecord::assemble(&candidates);
        let announced = record.hints().iter().map(hex::encode).collect::<Vec<_>>();
        assert_eq!(announced, vector.announced_hex, "{}", vector.name);
    }
}
