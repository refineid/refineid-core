// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! Known-answer tests for the CPace KC2 Ristretto255 generator.
//!
//! The generator value `G` is the root of the KC2 transcript: every scalar
//! multiplication, both confirmation tags, and therefore session-key agreement
//! derive from it. A silent divergence here would be invisible to round-trip
//! tests, because both peers would agree on the same wrong generator while
//! failing to interoperate with any other implementation.
//!
//! These tests close that gap by pinning two independent facts:
//!
//! 1. `curve25519_dalek`'s `RistrettoPoint::from_uniform_bytes` reproduces the
//!    known-answer vector published in draft-irtf-cfrg-cpace-21 Appendix B.3.1.
//!    This is the trust anchor: it validates the upstream primitive rather than
//!    merely asserting our own code against itself.
//! 2. `calculate_generator_kc2` reproduces the generator pinned in the in-tree
//!    KC2 synthetic vectors, which is only meaningful once (1) holds.
//!
//! Both vectors are transcribed from the draft. See
//! <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21>.

use curve25519_dalek::ristretto::RistrettoPoint;
use refineid_rapp::cpace::{calculate_generator_kc2, standard_pairing_context_v2};
use sha2::{Digest, Sha512};

/// Unambiguous lowercase hex, avoiding a dependency on the `hex` crate.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("valid hex"))
        .collect()
}

/// Deterministic length-prefixed octet string, per CPace `prepend_len`.
fn length_prefixed(part: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut length = part.len();
    loop {
        let mut byte = (length & 0x7f) as u8;
        length >>= 7;
        if length != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if length == 0 {
            break;
        }
    }
    encoded.extend_from_slice(part);
    encoded
}

/// draft-irtf-cfrg-cpace-21 Appendix B.3.1 encodes `G` from this generator
/// string. Reproducing the published result validates both the byte-level
/// `gen_str` construction and the upstream hash-to-group mapping.
#[test]
fn dalek_from_uniform_bytes_matches_draft21_b31_vector() {
    let context = from_hex("0b415f696e69746961746f720b425f726573706f6e646572");
    let sid = from_hex("7e4b4791d6a8ef019b936c79fb7f2c57");
    let padding = [0_u8; 100];

    let mut gen_str = Vec::new();
    for part in [
        b"CPaceRistretto255".as_slice(),
        b"Password".as_slice(),
        padding.as_slice(),
        context.as_slice(),
        sid.as_slice(),
    ] {
        gen_str.extend_from_slice(&length_prefixed(part));
    }

    assert_eq!(gen_str.len(), 170, "draft vector generator string length");

    let hash: [u8; 64] = Sha512::digest(&gen_str).into();
    assert_eq!(
        to_hex(&hash),
        "da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288b6663af06\
         bf645c93cd1c51512307199c80e84908916d983b34af77205f90851a657ee27",
        "draft vector gen_str hash"
    );

    let generator = RistrettoPoint::from_uniform_bytes(&hash);
    assert_eq!(
        to_hex(&generator.compress().to_bytes()),
        "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56",
        "draft vector encoded generator"
    );
}

/// The generator pinned by the in-tree KC2 synthetic vectors must be
/// reproducible from the spec's own context and framing rules, so the golden
/// value is a checked-in expectation rather than an unfalsifiable constant.
#[test]
fn kc2_generator_reproduces_pinned_synthetic_vector() {
    let offer_hash: [u8; 32] =
        from_hex("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
            .try_into()
            .expect("32-byte offer hash");

    let context = standard_pairing_context_v2(&offer_hash).expect("standard pairing context");
    let sid = from_hex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");

    let generator =
        calculate_generator_kc2(b"7KX4M9", &context, &sid).expect("generator derivation");

    assert_eq!(
        to_hex(&generator.compress().to_bytes()),
        "6c94a85a14bcd59f7a698e52cf852cacbe664d68c16c2a0da7b0ac453fb98579"
    );
}
