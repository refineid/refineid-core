// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Envelope rejection conformance vectors.

use std::{fs, path::PathBuf};

use refineid_rapp::Envelope;
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    rejected_envelope: Vec<RejectedEnvelope>,
}

#[derive(Deserialize)]
struct RejectedEnvelope {
    name: String,
    canonical_cbor_hex: String,
    supported_critical: Vec<String>,
    error: String,
}

#[test]
fn malformed_or_unsupported_envelopes_match_the_versioned_corpus() {
    let corpus = load_corpus();
    assert_eq!(corpus.rejected_envelope.len(), 12);
    for vector in corpus.rejected_envelope {
        let bytes = decode_hex(&vector.canonical_cbor_hex);
        let actual = match Envelope::decode(&bytes) {
            Ok(envelope) => envelope
                .require_supported_critical(vector.supported_critical.iter().map(String::as_str))
                .map_or_else(|error| format!("{error:?}"), |()| "Accepted".to_owned()),
            Err(error) => format!("{error:?}"),
        };
        assert_eq!(actual, vector.error, "{}", vector.name);
    }
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

fn load_corpus() -> Corpus {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/protocols/vectors/rapp-v26.9.13.json");
    serde_json::from_slice(&fs::read(path).expect("read RAPP corpus")).expect("decode RAPP corpus")
}
