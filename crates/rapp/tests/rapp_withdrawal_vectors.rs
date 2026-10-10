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
    CloseReason, RendezvousToken, SessionCloseMessage, TypedMessage, WireValue, discovery_hint,
    encode_deterministic_cbor, withdrawal_hint, withdrawal_hint_matches,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-withdrawal-v26.10.10.json");

#[derive(Deserialize)]
struct Corpus {
    withdrawal_hint: Vec<HintVector>,
    withdrawal_acceptance: Vec<AcceptanceVector>,
    session_close: Vec<CloseVector>,
}

#[derive(Deserialize)]
struct HintVector {
    name: String,
    rendezvous_token_hex: String,
    epoch: u64,
    discovery_hint_hex: String,
    withdrawal_hint_hex: String,
}

#[derive(Deserialize)]
struct AcceptanceVector {
    name: String,
    hint_epoch: u64,
    requester_epoch: u64,
    #[serde(default)]
    use_discovery_hint: bool,
    expected: String,
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

fn token(vector: &HintVector) -> RendezvousToken {
    RendezvousToken::reconstruct(&hex::decode(&vector.rendezvous_token_hex).expect("token hex"))
        .expect("token length")
}

#[test]
fn withdrawal_hints_match_the_corpus() {
    for vector in corpus().withdrawal_hint {
        let token = token(&vector);
        assert_eq!(
            hex::encode(withdrawal_hint(&token, vector.epoch)),
            vector.withdrawal_hint_hex,
            "{}",
            vector.name
        );
        assert_eq!(
            hex::encode(discovery_hint(&token, vector.epoch)),
            vector.discovery_hint_hex,
            "{}",
            vector.name
        );
    }
}

#[test]
fn acceptance_window_matches_the_corpus() {
    let corpus = corpus();
    let reference = &corpus.withdrawal_hint[0];
    let token = token(reference);
    for vector in corpus.withdrawal_acceptance {
        let published = if vector.use_discovery_hint {
            discovery_hint(&token, vector.hint_epoch)
        } else {
            withdrawal_hint(&token, vector.hint_epoch)
        };
        let accepted = withdrawal_hint_matches(&token, &published, vector.requester_epoch);
        assert_eq!(
            if accepted { "accepted" } else { "rejected" },
            vector.expected,
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
