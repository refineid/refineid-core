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

//! Replays the `pairing_hello` and `session_name` vectors (RAPP v26.11.8
//! sections 4.3 items 3 and 4, and 7.1): every accepted envelope decodes
//! to the name it carries and the engine encodes the same bytes, every
//! rejected one is refused, and the pair record keeps or replaces its name
//! as the vector says.

use core::convert::Infallible;

use refineid_rapp::{
    DISPLAY_NAME_MAX_BYTES, DisplayName, EndpointRole, Envelope, GrantsHash, MessageType,
    NegotiatedParameters, PairId, PairRecord, PairingHelloMessage, ProfileName,
    SessionHelloMessage, SessionId, SessionParameters, SessionReadyMessage, TransportProfile,
    TypedMessage,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../doc/protocols/vectors/rapp-v26.11.8.json");

/// Monotonic instant the messages are read at; no operation is involved.
const RECEIVED_AT_MS: u64 = 1;
/// Fill bytes of the pair record the session vectors update; its keys
/// play no part in the name.
const RECORD_BYTE: u8 = 0x42;
const CREATED_AT_MS: u64 = 1;

#[derive(Deserialize)]
struct Corpus {
    pairing_hello: Vec<PairingHelloVector>,
    session_name: Vec<SessionNameVector>,
}

/// A vector's name: text, or text repeated to reach a length.
#[derive(Deserialize)]
#[serde(untagged)]
enum VectorName {
    Text(String),
    Repeated { text: String, repeat: usize },
}

impl VectorName {
    fn text(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Repeated { text, repeat } => text.repeat(*repeat),
        }
    }
}

#[derive(Deserialize)]
struct PairingHelloVector {
    name: String,
    sender: String,
    transport_profile: String,
    offer_hash_hex: String,
    session_id_hex: String,
    platform: String,
    display_name: Option<VectorName>,
    expected: String,
    requested_profiles: Option<Vec<String>>,
    display_name_utf8_length: Option<usize>,
    envelope_cbor_hex: String,
}

#[derive(Deserialize)]
struct SessionNameVector {
    name: String,
    message: String,
    session_id_hex: String,
    display_name: Option<VectorName>,
    record_name_before: String,
    expected: String,
    transport_profile: Option<String>,
    grants_hash_hex: Option<String>,
    nonce_hex: Option<String>,
    display_name_utf8_length: Option<usize>,
    record_name_after: String,
    record_rewritten: bool,
    envelope_cbor_hex: String,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("versioned RAPP corpus must parse")
}

fn bytes(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text).expect("vector hex decodes")
}

fn fixed<const N: usize>(hex_text: &str) -> [u8; N] {
    bytes(hex_text)
        .try_into()
        .expect("vector field has its fixed size")
}

fn display_name(text: &str) -> DisplayName {
    DisplayName::parse(text.to_owned()).expect("a valid name")
}

/// The typed message an envelope's bytes decode to, or `None` where the
/// wire or the message layer refuses it.
fn decoded(envelope_hex: &str) -> Option<TypedMessage> {
    let envelope = Envelope::decode(&bytes(envelope_hex)).ok()?;
    TypedMessage::from_envelope(envelope, RECEIVED_AT_MS).ok()
}

fn encoded(message: &TypedMessage, session_id_hex: &str) -> Vec<u8> {
    Envelope::reconstruct(
        message.message_type(),
        SessionId::from_array(fixed(session_id_hex)),
        0,
        message.to_wire_body().expect("the message encodes"),
    )
    .expect("the envelope is valid")
    .encode()
    .expect("the envelope encodes")
}

fn transport(name: &str) -> TransportProfile {
    TransportProfile::parse(name).expect("a registered transport profile")
}

#[test]
fn pairing_hello_names_replay() {
    let vectors = corpus().pairing_hello;
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name_text = vector.display_name.as_ref().map(VectorName::text);
        assert_eq!(
            name_text.as_ref().map(String::len),
            vector.display_name_utf8_length,
            "{}",
            vector.name
        );
        let received = decoded(&vector.envelope_cbor_hex);
        match vector.expected.as_str() {
            "accepted" => {
                let Some(TypedMessage::PairingHello(hello)) = received else {
                    panic!("{}: an accepted hello did not decode", vector.name);
                };
                let name_text = name_text.expect("an accepted hello carries a name");
                assert_eq!(hello.display_name.as_str(), name_text, "{}", vector.name);
                assert_eq!(hello.platform, vector.platform, "{}", vector.name);
                assert_eq!(
                    hello.requested_profiles.is_some(),
                    vector.sender == "requester",
                    "{}: only a requester's hello requests profiles",
                    vector.name
                );
                let transport = transport(&vector.transport_profile);
                let message = TypedMessage::PairingHello(PairingHelloMessage {
                    parameters: NegotiatedParameters {
                        offer_hash: fixed(&vector.offer_hash_hex),
                        transport_profile: transport.name().to_owned(),
                        candidate_id: transport.candidate_id().to_owned(),
                    },
                    display_name: display_name(&name_text),
                    platform: vector.platform.clone(),
                    requested_profiles: vector.requested_profiles.as_ref().map(|names| {
                        names
                            .iter()
                            .map(|name| ProfileName::parse(name).expect("a registered profile"))
                            .collect()
                    }),
                });
                assert_eq!(
                    encoded(&message, &vector.session_id_hex),
                    bytes(&vector.envelope_cbor_hex),
                    "{}: the engine encodes the vector's bytes",
                    vector.name
                );
            }
            "rejected" => {
                assert!(
                    !matches!(received, Some(TypedMessage::PairingHello(_))),
                    "{}: a rejected hello decoded",
                    vector.name
                );
                if let Some(text) = name_text {
                    assert!(DisplayName::parse(text).is_err(), "{}", vector.name);
                }
            }
            expected => panic!("{}: unknown expectation {expected}", vector.name),
        }
    }
}

fn record_named(name: &str) -> PairRecord {
    PairRecord::new(
        PairId::from_array([RECORD_BYTE; 16]),
        EndpointRole::Proxy,
        [RECORD_BYTE; 32],
        [RECORD_BYTE; 32],
        [RECORD_BYTE; 32],
        GrantsHash::from_array([RECORD_BYTE; 32]),
        vec![ProfileName::CardStatus],
        display_name(name),
        CREATED_AT_MS,
    )
    .expect("a valid record")
}

#[test]
fn session_names_replay_and_update_the_record() {
    let vectors = corpus().session_name;
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name_text = vector.display_name.as_ref().map(VectorName::text);
        assert_eq!(
            name_text.as_ref().map(String::len),
            vector.display_name_utf8_length,
            "{}",
            vector.name
        );
        let received = decoded(&vector.envelope_cbor_hex);
        let mut record = record_named(&vector.record_name_before);
        let mut stores = 0;
        match vector.expected.as_str() {
            "accepted" => {
                let (name, message) = match (vector.message.as_str(), received) {
                    ("session.ready", Some(TypedMessage::SessionReady(ready))) => {
                        let transport = transport(
                            vector
                                .transport_profile
                                .as_deref()
                                .expect("a ready names its transport"),
                        );
                        let message = TypedMessage::SessionReady(SessionReadyMessage {
                            parameters: SessionParameters {
                                transport_profile: transport.name().to_owned(),
                                candidate_id: transport.candidate_id().to_owned(),
                                grants_hash: GrantsHash::from_array(fixed(
                                    vector.grants_hash_hex.as_deref().expect("grants hash"),
                                )),
                            },
                            nonce: fixed(vector.nonce_hex.as_deref().expect("nonce")),
                            display_name: ready.display_name.clone(),
                        });
                        (ready.display_name, message)
                    }
                    ("session.hello", Some(TypedMessage::SessionHello(hello))) => {
                        let message = TypedMessage::SessionHello(SessionHelloMessage {
                            display_name: hello.display_name.clone(),
                        });
                        (hello.display_name, message)
                    }
                    (kind, other) => panic!("{}: {kind} decoded as {other:?}", vector.name),
                };
                assert_eq!(Some(name.as_str()), name_text.as_deref(), "{}", vector.name);
                assert_eq!(
                    encoded(&message, &vector.session_id_hex),
                    bytes(&vector.envelope_cbor_hex),
                    "{}: the engine encodes the vector's bytes",
                    vector.name
                );
                let rewritten = record
                    .record_peer_display_name(&name, |_| {
                        stores += 1;
                        Ok::<(), Infallible>(())
                    })
                    .expect("the store accepts");
                assert_eq!(rewritten, vector.record_rewritten, "{}", vector.name);
            }
            "rejected" => {
                let message_type = match vector.message.as_str() {
                    "session.ready" => MessageType::SessionReady,
                    "session.hello" => MessageType::SessionHello,
                    kind => panic!("{}: unknown message {kind}", vector.name),
                };
                assert!(
                    received
                        .as_ref()
                        .is_none_or(|message| message.message_type() != message_type),
                    "{}: a rejected name decoded",
                    vector.name
                );
                assert!(!vector.record_rewritten, "{}", vector.name);
            }
            expected => panic!("{}: unknown expectation {expected}", vector.name),
        }
        assert_eq!(
            record.peer_display_name().as_str(),
            vector.record_name_after,
            "{}",
            vector.name
        );
        assert_eq!(
            stores,
            usize::from(vector.record_rewritten),
            "{}: a store happens exactly when the name changes",
            vector.name
        );
    }
}

#[test]
fn the_name_bound_is_the_formal_constant() {
    let model = include_str!("../../../doc/protocols/rapp-state-machine-v26.11.8.yaml");
    let line = model
        .lines()
        .find_map(|line| line.trim().strip_prefix("display_name_max_bytes:"))
        .expect("the model states the bound");
    assert_eq!(
        line.trim().parse::<usize>().expect("a number"),
        DISPLAY_NAME_MAX_BYTES
    );
}
