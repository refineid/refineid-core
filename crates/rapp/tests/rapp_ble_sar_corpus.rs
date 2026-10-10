// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Byte-exact replay of the RAPP v26.10.9 §5.3 BLE SAR corpus, generated
//! independently of this crate.

use refineid_rapp::ble_sar::{BleSarError, BleSarReassembler, payload_capacity, segment};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../../docs/protocols/vectors/rapp-ble-sar-v26.10.9.json");

#[derive(Deserialize)]
struct Corpus {
    format: String,
    protocol_document_version: String,
    header_size: usize,
    reassembly_timeout_ms: u64,
    capacity: Vec<CapacityVector>,
    segmentation: Vec<SegmentationVector>,
    receive: Vec<ReceiveVector>,
}

#[derive(Deserialize)]
struct CapacityVector {
    negotiated_att_mtu: usize,
    platform_value_limit: Option<usize>,
    capacity: Option<usize>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct SegmentationVector {
    name: String,
    capacity: usize,
    message_hex: String,
    fragments_hex: Vec<String>,
}

#[derive(Deserialize)]
struct Fragment {
    hex: String,
    at_ms: u64,
}

#[derive(Deserialize)]
struct ReceiveVector {
    name: String,
    capacity: usize,
    fragments: Vec<Fragment>,
    messages_hex: Vec<String>,
    error: Option<String>,
    at_fragment: Option<usize>,
}

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS).expect("the checked-in SAR corpus must be valid JSON")
}

/// The corpus's snake-case name for a receive rule.
fn error_name(error: BleSarError) -> &'static str {
    match error {
        BleSarError::AttMtuTooSmall => "att_mtu_too_small",
        BleSarError::EmptyFragment => "empty_fragment",
        BleSarError::FirstFragmentNotShorterThanTotal => "first_fragment_not_shorter_than_total",
        BleSarError::FirstFragmentTooShort => "first_fragment_too_short",
        BleSarError::FragmentOverCapacity => "fragment_over_capacity",
        BleSarError::HeaderTruncated => "header_truncated",
        BleSarError::IllegalFlags => "illegal_flags",
        BleSarError::IllegalTransition => "illegal_transition",
        BleSarError::IncompleteAtLast => "incomplete_at_last",
        BleSarError::InvalidCapacity => "invalid_capacity",
        BleSarError::InvalidMessageLength => "invalid_message_length",
        BleSarError::NonFinalFragmentTooShort => "non_final_fragment_too_short",
        BleSarError::Overflow => "overflow",
        BleSarError::ReassemblyTimeout => "reassembly_timeout",
        BleSarError::ReservedBitsSet => "reserved_bits_set",
        BleSarError::SequenceMismatch => "sequence_mismatch",
        BleSarError::SequenceOutOfBounds => "sequence_out_of_bounds",
        BleSarError::SingleLengthMismatch => "single_length_mismatch",
        BleSarError::TotalLengthChanged => "total_length_changed",
        BleSarError::UnexpectedInitialFragment => "unexpected_initial_fragment",
        BleSarError::ZeroTotalLength => "zero_total_length",
    }
}

#[test]
fn corpus_names_this_profile() {
    let corpus = corpus();
    assert_eq!(corpus.format, "fi.refineid.rapp.ble-sar-vectors-v1");
    assert_eq!(corpus.protocol_document_version, "26.10.9");
    assert_eq!(
        corpus.header_size,
        refineid_rapp::ble_sar::BLE_SAR_HEADER_SIZE
    );
    assert_eq!(
        corpus.reassembly_timeout_ms,
        refineid_rapp::ble_sar::BLE_SAR_REASSEMBLY_TIMEOUT_MS
    );
}

#[test]
fn capacities_follow_the_formula() {
    for vector in corpus().capacity {
        let actual = payload_capacity(vector.negotiated_att_mtu, vector.platform_value_limit);
        match (vector.capacity, vector.error.as_deref()) {
            (Some(expected), None) => assert_eq!(actual, Ok(expected)),
            (None, Some(name)) => {
                assert_eq!(actual.map_err(error_name), Err(name));
            }
            _ => panic!("capacity vector names neither a capacity nor an error"),
        }
    }
}

#[test]
fn segmentation_is_byte_exact() {
    for vector in corpus().segmentation {
        let message = hex::decode(&vector.message_hex).expect("valid hex");
        let fragments: Vec<String> = segment(&message, vector.capacity)
            .unwrap_or_else(|error| panic!("{} fails: {error:?}", vector.name))
            .iter()
            .map(hex::encode)
            .collect();
        assert_eq!(fragments, vector.fragments_hex, "{}", vector.name);
    }
}

#[test]
fn receive_rules_match_every_vector() {
    for vector in corpus().receive {
        let mut reassembler = BleSarReassembler::new();
        let mut delivered = Vec::new();
        let mut failure = None;
        for (index, fragment) in vector.fragments.iter().enumerate() {
            let bytes = hex::decode(&fragment.hex).expect("valid hex");
            match reassembler.receive(&bytes, vector.capacity, fragment.at_ms) {
                Ok(Some(message)) => delivered.push(hex::encode(message)),
                Ok(None) => {}
                Err(error) => {
                    failure = Some((index, error_name(error)));
                    break;
                }
            }
        }
        assert_eq!(delivered, vector.messages_hex, "{} messages", vector.name);
        assert_eq!(
            failure,
            vector.error.as_deref().map(|name| (
                vector.at_fragment.expect("an error names its fragment"),
                name
            )),
            "{} error",
            vector.name
        );
        if failure.is_some() {
            assert!(reassembler.is_idle(), "{} leaves state behind", vector.name);
        }
    }
}
