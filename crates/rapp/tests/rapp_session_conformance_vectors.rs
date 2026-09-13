//! Portable conformance scenarios for authenticated session rejection.

use std::collections::BTreeMap;

use refineid_rapp::{
    CardOperation, Envelope, JournalRecord, JournalStore, MessageType, OperationId,
    OperationRequest, OperationResultMessage, PairId, ProfileName, ProxyDispatch, ProxyEngineError,
    ProxyOperationEngine, ProxyViolation, ResultJournalStore, SequenceGuard, SessionId,
    TypedMessage, WireError, WireValue, decode_deterministic_cbor, encode_deterministic_cbor,
};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-v26.9.7.70.json");

#[derive(Deserialize)]
struct Corpus {
    sequence_guard: Vec<SequenceVector>,
    wire_version: Vec<VersionVector>,
    grant_enforcement: Vec<GrantVector>,
}

#[derive(Deserialize)]
struct SequenceVector {
    name: String,
    guard_session_id_hex: String,
    accepted_sequences: Vec<u64>,
    incoming_session_id_hex: String,
    incoming_sequence: u64,
    expected: String,
    expected_next_receive: u64,
}

#[derive(Deserialize)]
struct VersionVector {
    name: String,
    version: Vec<u16>,
    expected: String,
}

#[derive(Deserialize)]
struct GrantVector {
    name: String,
    granted_profiles: Vec<String>,
    requested_profile: String,
    expected: String,
}

#[derive(Default)]
struct NoopStore;

impl JournalStore for NoopStore {
    type Error = core::convert::Infallible;

    fn persist(&mut self, _: &JournalRecord) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ResultJournalStore for NoopStore {
    fn persist_result(
        &mut self,
        _: &JournalRecord,
        _: &OperationResultMessage,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn retain_uncertain_result(&mut self, _: &JournalRecord) -> Result<(), Self::Error> {
        Ok(())
    }

    fn acknowledge_result(&mut self, _: &JournalRecord) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("versioned RAPP session corpus must parse")
}

#[test]
fn exact_directional_sequence_and_session_binding_match_the_corpus() {
    for vector in corpus().sequence_guard {
        let guard_session = session_id(&vector.guard_session_id_hex);
        let mut guard = SequenceGuard::new(guard_session);
        for sequence in vector.accepted_sequences {
            guard
                .accept_incoming(&envelope(guard_session, sequence))
                .unwrap_or_else(|error| {
                    panic!(
                        "{} invalid accepted prefix at {sequence}: {error:?}",
                        vector.name
                    )
                });
        }

        let incoming = envelope(
            session_id(&vector.incoming_session_id_hex),
            vector.incoming_sequence,
        );
        match vector.expected.as_str() {
            "accepted" => assert_eq!(guard.accept_incoming(&incoming), Ok(()), "{}", vector.name),
            "wrong_session" => assert_eq!(
                guard.accept_incoming(&incoming),
                Err(WireError::WrongSession),
                "{}",
                vector.name
            ),
            "wrong_sequence" => assert_eq!(
                guard.accept_incoming(&incoming),
                Err(WireError::WrongSequence {
                    expected: vector.expected_next_receive,
                    got: vector.incoming_sequence,
                }),
                "{}",
                vector.name
            ),
            expected => panic!("{} unknown sequence expectation {expected}", vector.name),
        }

        assert_eq!(
            guard.accept_incoming(&envelope(guard_session, vector.expected_next_receive,)),
            Ok(()),
            "{} candidate decision advanced the guard incorrectly",
            vector.name
        );
    }
}

#[test]
fn visible_wire_version_rejects_downgrades_and_unknown_upgrades() {
    for vector in corpus().wire_version {
        let encoded = envelope_with_version(&vector.version);
        match vector.expected.as_str() {
            "accepted" => assert!(Envelope::decode(&encoded).is_ok(), "{}", vector.name),
            "unsupported_version" => assert_eq!(
                Envelope::decode(&encoded),
                Err(WireError::UnsupportedVersion),
                "{}",
                vector.name
            ),
            expected => panic!("{} unknown version expectation {expected}", vector.name),
        }
    }
}

#[test]
fn proxy_rejects_every_operation_outside_the_authenticated_grant_set() {
    for vector in corpus().grant_enforcement {
        let granted_profiles = vector
            .granted_profiles
            .iter()
            .map(|name| ProfileName::parse(name).expect("registered granted profile"))
            .collect();
        let requested_profile =
            ProfileName::parse(&vector.requested_profile).expect("registered requested profile");
        let request = OperationRequest::reconstruct(
            OperationId::from_array([0x11; 16]),
            PairId::from_array([0x22; 16]),
            SessionId::from_array([0x33; 16]),
            requested_profile,
            1_000,
            5_000,
            CardOperation::InspectCard,
        )
        .expect("corpus operation request must be internally valid");
        let mut engine = ProxyOperationEngine::new(granted_profiles);
        let mut store = NoopStore;
        let result = engine.receive(
            &mut store,
            TypedMessage::OperationRequest(request),
            1_000,
            5_000,
        );

        match vector.expected.as_str() {
            "accepted" => assert!(
                matches!(result, Ok(ProxyDispatch::InspectPrerequisites(_))),
                "{}",
                vector.name
            ),
            "profile_not_granted" => assert!(
                matches!(
                    result,
                    Err(ProxyEngineError::AuthenticatedProtocolViolation(
                        ProxyViolation::ProfileNotGranted
                    ))
                ),
                "{}",
                vector.name
            ),
            expected => panic!("{} unknown grant expectation {expected}", vector.name),
        }
    }
}

fn envelope(session_id: SessionId, sequence: u64) -> Envelope {
    Envelope::reconstruct(
        MessageType::PairingAbort,
        session_id,
        sequence,
        BTreeMap::from([("reason".to_owned(), WireValue::Text("cancelled".to_owned()))]),
        Vec::new(),
        BTreeMap::new(),
    )
    .expect("valid sequence-test envelope")
}

fn envelope_with_version(version: &[u16]) -> Vec<u8> {
    let encoded = envelope(SessionId::from_array([0x44; 16]), 0)
        .encode()
        .expect("valid envelope encodes");
    let WireValue::Map(mut map) = decode_deterministic_cbor(&encoded).expect("valid envelope CBOR")
    else {
        panic!("envelope must encode as a map")
    };
    map.insert(
        "version".to_owned(),
        WireValue::Array(
            version
                .iter()
                .copied()
                .map(u64::from)
                .map(WireValue::Unsigned)
                .collect(),
        ),
    );
    encode_deterministic_cbor(&WireValue::Map(map)).expect("mutated envelope encodes")
}

fn session_id(hex: &str) -> SessionId {
    let bytes = hex_bytes(hex);
    SessionId::reconstruct(&bytes).expect("session identifier length")
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input must have complete bytes");
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("valid hex"))
        .collect()
}
