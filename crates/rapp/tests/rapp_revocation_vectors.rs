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

//! Announced pairing revocation (RAPP v26.10.21 §4.6) against its corpus.

use refineid_rapp::{
    AnnouncementCandidate, DiscoveryRecord, EndpointRole, GrantsHash, InstanceName, PairId,
    PairRecord, ProfileName, RevocationKey, RevocationRetention, RevokedAnnouncement,
    discovery_epoch, noise::x25519_public_key,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-revocation-v26.10.21.json");

#[derive(Deserialize)]
struct Corpus {
    protocol_document_version: String,
    revocation_key: Vec<KeyVector>,
    revocation_hint: Vec<HintVector>,
    revocation_acceptance: Vec<AcceptanceVector>,
    session_record: Vec<RecordVector>,
    malformed_record: Vec<MalformedVector>,
    retention_window: Vec<WindowVector>,
    announcement_selection: Vec<SelectionVector>,
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
    epoch: u64,
    revocation_hint_hex: String,
}

#[derive(Deserialize)]
struct AcceptanceVector {
    name: String,
    published_instance: String,
    published_epoch: u64,
    requester_instance: String,
    requester_epoch: u64,
    requester_pair_id_hex: String,
    expected: String,
}

#[derive(Deserialize)]
struct RecordVector {
    name: String,
    instance_name: String,
    requester_epoch: u64,
    txt: Vec<(String, String)>,
    hints_hex: Vec<String>,
    expected: String,
}

#[derive(Deserialize)]
struct MalformedVector {
    name: String,
    txt: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct WindowVector {
    name: String,
    revoked_at_ms: u64,
    now_ms: u64,
    announced: bool,
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
    revoked_at_ms: u64,
}

/// The eight-byte filler every synthetic announcement is padded with.
const FILLER_BYTE: u8 = 0;

/// The grants hash byte of the synthetic custodian record.
const GRANTS_HASH_BYTE: u8 = 0x55;

/// Creation time of the synthetic custodian record.
const CREATED_AT_MS: u64 = 1;

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("revocation corpus parses")
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
fn keys(vector: &KeyVector, pair: &str) -> (RevocationKey, RevocationKey) {
    let custodian: [u8; 32] = array(&vector.custodian_static_private_hex);
    let requester: [u8; 32] = array(&vector.requester_static_private_hex);
    (
        RevocationKey::from_parts(pair_id(pair), &custodian, &x25519_public_key(&requester))
            .expect("custodian key"),
        RevocationKey::from_parts(pair_id(pair), &requester, &x25519_public_key(&custodian))
            .expect("requester key"),
    )
}

fn custodian_record(vector: &KeyVector) -> PairRecord {
    let custodian: [u8; 32] = array(&vector.custodian_static_private_hex);
    let requester: [u8; 32] = array(&vector.requester_static_private_hex);
    PairRecord::new(
        pair_id(&vector.pair_id_hex),
        EndpointRole::Proxy,
        custodian,
        x25519_public_key(&custodian),
        x25519_public_key(&requester),
        GrantsHash::from_array([GRANTS_HASH_BYTE; refineid_rapp::GRANTS_HASH_SIZE]),
        vec![ProfileName::CardStatus],
        CREATED_AT_MS,
    )
    .expect("record")
}

fn instance(name: &str) -> InstanceName {
    InstanceName::new(name).expect("instance name")
}

fn pairs(txt: &[(String, String)]) -> Vec<(&str, &str)> {
    txt.iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
}

fn fill(bytes: &mut [u8]) -> Result<(), refineid_rapp::RevocationError> {
    bytes.fill(FILLER_BYTE);
    Ok(())
}

#[test]
fn corpus_names_its_version() {
    assert_eq!(corpus().protocol_document_version, "26.10.21");
}

#[test]
fn static_keys_match_the_corpus() {
    for vector in corpus().revocation_key {
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
fn revocation_hints_match_the_corpus() {
    let corpus = corpus();
    let key_vector = &corpus.revocation_key[0];
    let (custodian, requester) = keys(key_vector, &key_vector.pair_id_hex);
    for vector in corpus.revocation_hint {
        assert_eq!(
            discovery_epoch(vector.unix_time_seconds),
            vector.epoch,
            "{}",
            vector.name
        );
        let name = instance(&vector.instance_name);
        assert_eq!(
            hex::encode(custodian.hint(&name, vector.epoch)),
            vector.revocation_hint_hex,
            "{}",
            vector.name
        );
        assert_eq!(
            hex::encode(requester.hint(&name, vector.epoch)),
            vector.revocation_hint_hex,
            "{}",
            vector.name
        );
    }
}

#[test]
fn a_retained_key_produces_the_corpus_hints() {
    let corpus = corpus();
    let key_vector = &corpus.revocation_key[0];
    let retention = RevocationRetention::derive(&custodian_record(key_vector), CREATED_AT_MS)
        .expect("retention");
    let encoded = refineid_rapp::encode_revocation_retention(&retention).expect("encode");
    let decoded = refineid_rapp::decode_revocation_retention(&encoded).expect("decode");
    for vector in corpus.revocation_hint {
        let name = instance(&vector.instance_name);
        assert_eq!(
            hex::encode(decoded.hint(&name, vector.epoch)),
            vector.revocation_hint_hex,
            "{}",
            vector.name
        );
    }
}

#[test]
fn acceptance_matches_the_corpus() {
    let corpus = corpus();
    let key_vector = &corpus.revocation_key[0];
    let (custodian, _) = keys(key_vector, &key_vector.pair_id_hex);
    for vector in corpus.revocation_acceptance {
        let published = custodian.hint(
            &instance(&vector.published_instance),
            vector.published_epoch,
        );
        let announcement = RevokedAnnouncement::assemble(
            &[AnnouncementCandidate {
                hint: published,
                last_used_ms: 0,
            }],
            fill,
        )
        .expect("announcement");
        let record = DiscoveryRecord::assemble(&[], Some(announcement));
        let (_, requester) = keys(key_vector, &vector.requester_pair_id_hex);
        let accepted = requester.matches(
            &record,
            &instance(&vector.requester_instance),
            vector.requester_epoch,
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
    let key_vector = &corpus.revocation_key[0];
    let (_, requester) = keys(key_vector, &key_vector.pair_id_hex);
    for vector in corpus.session_record {
        let record = DiscoveryRecord::parse(&pairs(&vector.txt)).expect("record parses");
        let hints = record.hints().iter().map(hex::encode).collect::<Vec<_>>();
        assert_eq!(hints, vector.hints_hex, "{}", vector.name);
        let accepted = requester.matches(
            &record,
            &instance(&vector.instance_name),
            vector.requester_epoch,
        );
        assert_eq!(
            if accepted { "accepted" } else { "no-match" },
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
            DiscoveryRecord::parse(&pairs(&vector.txt)).is_err(),
            "{}",
            vector.name
        );
    }
}

#[test]
fn a_revocation_is_announced_for_thirty_days() {
    let corpus = corpus();
    let key_vector = &corpus.revocation_key[0];
    for vector in corpus.retention_window {
        let retention =
            RevocationRetention::derive(&custodian_record(key_vector), vector.revoked_at_ms)
                .expect("retention");
        assert_eq!(
            retention.announces_at(vector.now_ms),
            vector.announced,
            "{}",
            vector.name
        );
    }
}

#[test]
fn the_most_recent_revocations_are_announced() {
    for vector in corpus().announcement_selection {
        let candidates = vector
            .candidates
            .iter()
            .map(|candidate| AnnouncementCandidate {
                hint: array(&candidate.hint_hex),
                last_used_ms: candidate.revoked_at_ms,
            })
            .collect::<Vec<_>>();
        let announcement = RevokedAnnouncement::assemble(&candidates, fill).expect("announcement");
        let mut announced = announcement
            .entries()
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>();
        announced.sort();
        assert_eq!(announced, vector.announced_hex, "{}", vector.name);
    }
}
