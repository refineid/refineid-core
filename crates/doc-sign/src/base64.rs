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

//! Base64 coding (RFC 4648 sec.4) backed by [`base64ct`], for the places
//! a signature format insists on it.
//!
//! `ASiC` manifests and `XAdES` carry digests and certificates as base64
//! inside XML, because XML cannot hold arbitrary octets. Encoding serves
//! the writers; the strict decoder serves the offline verifier, which
//! consumes manifests it did not produce.

use base64ct::{Base64, Encoding as _};

/// Encode `input` as base64 with the standard alphabet and padding.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    Base64::encode_string(input)
}

/// Decode standard padded base64 (RFC 4648 sec.4).
///
/// Strict: the alphabet plus `=` padding only, length a multiple of
/// four, at most two padding characters, padding only at the end, and
/// the unused trailing bits of a padded quantum must be zero. Leading
/// and trailing ASCII whitespace is tolerated (XML pretty-printing);
/// interior whitespace is rejected.
///
/// # Errors
/// Any alphabet, padding, length, or trailing-bits violation.
pub(crate) fn decode(input: &str) -> Result<Vec<u8>, &'static str> {
    Base64::decode_vec(input.trim_ascii()).map_err(|_| "malformed base64")
}

/// Decode `xsd:base64Binary` text: the strict alphabet and padding of
/// [`decode`], with XML white space (space, tab, line feed, carriage
/// return) allowed anywhere between characters, as producers wrap long
/// values over lines.
///
/// # Errors
/// As [`decode`], over the text with the white space removed.
pub(crate) fn decode_wrapped(input: &str) -> Result<Vec<u8>, &'static str> {
    let compact: String = input
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t' | '\n' | '\r'))
        .collect();
    Base64::decode_vec(&compact).map_err(|_| "malformed base64")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoded character count for all 256 byte values (`ceil(256 / 3) * 4`).
    const ALL_OCTETS_ENCODED_LEN: usize = 344;

    #[test]
    fn matches_rfc_4648_vectors() {
        // RFC 4648 sec.10, verbatim.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn encodes_every_octet_value() {
        // All 256 values, so a sign-extension or alphabet-index slip
        // cannot hide in the range nothing else exercises.
        let all: Vec<u8> = (0..=u8::MAX).collect();
        let encoded = encode(&all);
        assert_eq!(encoded.len(), ALL_OCTETS_ENCODED_LEN);
        assert!(encoded.starts_with("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"));
        assert!(encoded.ends_with("+/w=="));
    }

    #[test]
    fn decodes_rfc_vectors() {
        for (encoded, expected) in [
            ("", b"".as_slice()),
            ("Zg==", b"f".as_slice()),
            ("Zm8=", b"fo".as_slice()),
            ("Zm9v", b"foo".as_slice()),
            ("Zm9vYg==", b"foob".as_slice()),
            ("Zm9vYmE=", b"fooba".as_slice()),
            ("Zm9vYmFy", b"foobar".as_slice()),
        ] {
            assert_eq!(decode(encoded).expect("valid base64"), expected);
        }
    }

    #[test]
    fn decode_round_trips_every_octet_value() {
        let all: Vec<u8> = (0..=u8::MAX).collect();
        let decoded = decode(&encode(&all)).expect("encoder output decodes");
        assert_eq!(decoded, all);
    }

    #[test]
    fn decode_rejects_malformed_input() {
        for bad in [
            "Zg",    // length not a multiple of four
            "Zg===", // too much padding
            "Z=g=",  // padding not trailing
            "====",  // padding only
            "Zm9!",  // alphabet violation
            "Zm9 v", // interior whitespace
            "Zh==",  // nonzero trailing bits (h = 33, low 4 bits set)
            "Zmx=",  // nonzero trailing bits (x = 49, low 2 bits set)
        ] {
            assert!(decode(bad).is_err(), "{bad} must not decode");
        }
        // "Zm9h" is well-formed ("foa") and must keep decoding.
        assert_eq!(decode("Zm9h").expect("control decodes"), b"foa");
    }

    #[test]
    fn wrapped_decoding_tolerates_line_breaks_and_keeps_strict_padding() {
        const NON_BREAKING_SPACE: u8 = 160;
        assert_eq!(decode(" \t\r\n ").expect("whitespace-only decodes"), b"");
        assert_eq!(
            decode(" \nZm9v\t ").expect("surrounding ASCII whitespace decodes"),
            b"foo"
        );
        assert_eq!(
            decode_wrapped(" \r\n\t ").expect("whitespace-only wrapped decodes"),
            b""
        );
        assert_eq!(
            decode_wrapped("Zm9v\nYmFy").expect("wrapped decodes"),
            b"foobar"
        );
        assert_eq!(
            decode_wrapped(" Zm9v\r\n\tYg==\n").expect("wrapped decodes"),
            b"foob"
        );
        let non_ascii_space = format!("{}Zm9v", char::from(NON_BREAKING_SPACE));
        assert!(
            decode(&non_ascii_space).is_err(),
            "non-ASCII whitespace must not be trimmed"
        );
        assert!(
            decode_wrapped(&non_ascii_space).is_err(),
            "non-ASCII whitespace is outside XML S"
        );
        for bad in ["Zh==", "Zg=", "Z===", "Zm9v!", "Zg==\nZg=="] {
            assert!(decode_wrapped(bad).is_err(), "{bad} must not decode");
        }
    }
}
