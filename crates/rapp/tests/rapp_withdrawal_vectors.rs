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

//! Service withdrawal (RAPP v26.10.10 §4.5) against its corpus.

use refineid_rapp::{
    AnnouncementCandidate, CloseReason, InstanceName, PairId, SessionCloseMessage, TypedMessage,
    WireValue, WithdrawalKey, WithdrawnRecord, encode_deterministic_cbor, noise::x25519_public_key,
    withdrawal_counter,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-withdrawal-v26.10.10.json");

#[derive(Deserialize)]
struct Corpus {
    withdrawal_key: Vec<KeyVector>,
    withdrawal_hint: Vec<HintVector>,
    withdrawal_acceptance: Vec<AcceptanceVector>,
    withdrawn_record: Vec<RecordVector>,
    malformed_record: Vec<MalformedVector>,
    session_close: Vec<CloseVector>,
    announcement_selection: Vec<SelectionVector>,
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
    name: String,
    pair_id_hex: String,
    custodian_static_private_hex: String,
    custodian_static_public_hex: String,
    requester_static_private_hex: String,
    requester_static_public_hex: String,
}

#[derive(Deserialize)]
struct HintVector {
    name: String,
    instance_name: String,
    unix_time_seconds: u64,
    counter: u64,
    withdrawal_hint_hex: String,
}

#[derive(Deserialize)]
struct AcceptanceVector {
    name: String,
    published_instance: String,
    published_counter: u64,
    requester_instance: String,
    requester_counter: u64,
    requester_pair_id_hex: String,
    expected: String,
}

#[derive(Deserialize)]
struct RecordVector {
    name: String,
    instance_name: String,
    requester_counter: u64,
    txt: Vec<(String, String)>,
    expected: String,
}

#[derive(Deserialize)]
struct MalformedVector {
    name: String,
    txt: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct CloseVector {
    name: String,
    reason: String,
    last_received_sequence: u64,
    body_cbor_hex: String,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("withdrawal corpus parses")
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    hex::decode(text)
        .expect("hex")
        .try_into()
        .expect("fixed length")
}

fn pair_id(text: &str) -> PairId {
    PairId::reconstruct(&hex::decode(text).expect("pair id hex")).expect("pair id length")
}

/// The custodian's and the requester's keys for `pair`.
fn keys(vector: &KeyVector, pair: &str) -> (WithdrawalKey, WithdrawalKey) {
    let custodian: [u8; 32] = array(&vector.custodian_static_private_hex);
    let requester: [u8; 32] = array(&vector.requester_static_private_hex);
    (
        WithdrawalKey::from_parts(pair_id(pair), &custodian, &x25519_public_key(&requester))
            .expect("custodian key"),
        WithdrawalKey::from_parts(pair_id(pair), &requester, &x25519_public_key(&custodian))
            .expect("requester key"),
    )
}

fn instance(name: &str) -> InstanceName {
    InstanceName::new(name).expect("instance name")
}

fn pairs(txt: &[(String, String)]) -> Vec<(&str, &str)> {
    txt.iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
}

#[test]
fn static_keys_match_the_corpus() {
    for vector in corpus().withdrawal_key {
        let custodian: [u8; 32] = array(&vector.custodian_static_private_hex);
        let requester: [u8; 32] = array(&vector.requester_static_private_hex);
        assert_eq!(
            hex::encode(x25519_public_key(&custodian)),
            vector.custodian_static_public_hex,
            "{}",
            vector.name
        );
        assert_eq!(
            hex::encode(x25519_public_key(&requester)),
            vector.requester_static_public_hex,
            "{}",
            vector.name
        );
    }
}

#[test]
fn withdrawal_hints_match_the_corpus() {
    let corpus = corpus();
    let key_vector = &corpus.withdrawal_key[0];
    let (custodian, requester) = keys(key_vector, &key_vector.pair_id_hex);
    for vector in corpus.withdrawal_hint {
        assert_eq!(
            withdrawal_counter(vector.unix_time_seconds),
            vector.counter,
            "{}",
            vector.name
        );
        let name = instance(&vector.instance_name);
        assert_eq!(
            hex::encode(custodian.hint(&name, vector.counter)),
            vector.withdrawal_hint_hex,
            "{}",
            vector.name
        );
        assert_eq!(
            hex::encode(requester.hint(&name, vector.counter)),
            vector.withdrawal_hint_hex,
            "{}",
            vector.name
        );
    }
}

#[test]
fn acceptance_matches_the_corpus() {
    let corpus = corpus();
    let key_vector = &corpus.withdrawal_key[0];
    let (custodian, _) = keys(key_vector, &key_vector.pair_id_hex);
    for vector in corpus.withdrawal_acceptance {
        let published = custodian.hint(
            &instance(&vector.published_instance),
            vector.published_counter,
        );
        let candidate = AnnouncementCandidate {
            hint: published,
            last_used_ms: 0,
        };
        let record = WithdrawnRecord::assemble(&[candidate], |bytes| {
            bytes.fill(0);
            Ok(())
        })
        .expect("record");
        let (_, requester) = keys(key_vector, &vector.requester_pair_id_hex);
        let accepted = requester.matches(
            &record,
            &instance(&vector.requester_instance),
            vector.requester_counter,
        );
        assert_eq!(
            if accepted { "accepted" } else { "rejected" },
            vector.expected,
            "{}",
            vector.name
        );
    }
}

#[test]
fn published_records_match_the_corpus() {
    let corpus = corpus();
    let key_vector = &corpus.withdrawal_key[0];
    let (_, requester) = keys(key_vector, &key_vector.pair_id_hex);
    for vector in corpus.withdrawn_record {
        let record = WithdrawnRecord::parse(&pairs(&vector.txt)).expect("record parses");
        let accepted = requester.matches(
            &record,
            &instance(&vector.instance_name),
            vector.requester_counter,
        );
        assert_eq!(
            if accepted { "accepted" } else { "rejected" },
            vector.expected,
            "{}",
            vector.name
        );
    }
}

#[test]
fn malformed_records_are_refused() {
    for vector in corpus().malformed_record {
        assert!(
            WithdrawnRecord::parse(&pairs(&vector.txt)).is_err(),
            "{}",
            vector.name
        );
    }
}

#[test]
fn session_close_bodies_match_the_corpus() {
    for vector in corpus().session_close {
        assert_eq!(vector.reason, "service_withdrawn", "{}", vector.name);
        let message = TypedMessage::SessionClose(SessionCloseMessage {
            reason: CloseReason::ServiceWithdrawn,
            last_received_sequence: vector.last_received_sequence,
        });
        let body = message.to_wire_body().expect("body");
        let encoded = encode_deterministic_cbor(&WireValue::Map(body)).expect("encode");
        assert_eq!(
            hex::encode(encoded),
            vector.body_cbor_hex,
            "{}",
            vector.name
        );
    }
}

#[test]
fn the_most_recently_used_pairings_are_announced() {
    for vector in corpus().announcement_selection {
        let candidates = vector
            .candidates
            .iter()
            .map(|candidate| AnnouncementCandidate {
                hint: hex::decode(&candidate.hint_hex)
                    .expect("hex")
                    .try_into()
                    .expect("hint length"),
                last_used_ms: candidate.last_used_ms,
            })
            .collect::<Vec<_>>();
        let record = WithdrawnRecord::assemble(&candidates, |bytes| {
            bytes.fill(0);
            Ok(())
        })
        .expect("record");
        let mut announced = record.entries().iter().map(hex::encode).collect::<Vec<_>>();
        announced.sort();
        assert_eq!(announced, vector.announced_hex, "{}", vector.name);
    }
}
