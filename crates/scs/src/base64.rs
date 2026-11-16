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

//! Base64 coding (RFC 4648), standard and URL-safe, backed by [`base64ct`].
//!
//! Certificates and signature content ride as padded standard base64
//! (RFC 4648 sec.4); JOSE segments ride unpadded URL-safe (RFC 7515
//! sec.2). The decoders are strict: canonical trailing zero bits
//! (RFC 4648 sec.3.5), the alphabet plus `=` padding only, correct
//! length, and padding only at the end. Whitespace is refused -- the
//! callers are machines, and what they send has none.

use base64ct::{Base64, Base64Url, Base64UrlUnpadded, Encoding as _};

/// A base64 text that is not well-formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed base64")
    }
}

impl core::error::Error for DecodeError {}

/// Encode `input` with the standard alphabet and padding.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    Base64::encode_string(input)
}

/// Decode padded standard base64.
///
/// # Errors
/// Returns [`DecodeError`] on any alphabet, length, padding, or
/// non-canonical trailing-bit violation.
pub fn decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    Base64::decode_vec(text).map_err(|_| DecodeError)
}

/// Encode `input` URL-safe without padding, the JOSE segment form.
#[must_use]
pub fn encode_url(input: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(input)
}

/// Decode URL-safe base64, padded or not.
///
/// # Errors
/// Returns [`DecodeError`] on any alphabet, length, padding, or
/// non-canonical trailing-bit violation.
pub fn decode_url(text: &str) -> Result<Vec<u8>, DecodeError> {
    let result = if text.ends_with('=') {
        Base64Url::decode_vec(text)
    } else {
        Base64UrlUnpadded::decode_vec(text)
    };
    result.map_err(|_| DecodeError)
}

#[cfg(test)]
mod tests {
    use super::{DecodeError, decode, decode_url, encode, encode_url};

    /// First octet of a two-octet fixture whose encoding exercises both
    /// alphabet differences (`+` -> `-` and `/` -> `_`).
    const SWAPPED_FIRST: u8 = 0xFB;
    /// Second octet of the alphabet-difference fixture.
    const SWAPPED_SECOND: u8 = 0xFF;

    /// Padded standard vectors (RFC 4648 sec.10).
    #[test]
    fn standard_round_trip_matches_the_rfc_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "encode {plain:?}");
            assert_eq!(
                decode(encoded).as_deref(),
                Ok(plain.as_bytes()),
                "decode {encoded:?}"
            );
        }
    }

    /// URL-safe form drops the padding and swaps two characters.
    #[test]
    fn url_safe_round_trip() {
        let swapped = [SWAPPED_FIRST, SWAPPED_SECOND];
        assert_eq!(encode_url(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode_url(b"f"), "Zg");
        assert_eq!(encode_url(&swapped), "-_8");
        assert_eq!(decode_url("Zm9vYmFy").as_deref(), Ok(b"foobar".as_slice()));
        assert_eq!(decode_url("Zg").as_deref(), Ok(b"f".as_slice()));
        assert_eq!(decode_url("-_8").as_deref(), Ok(swapped.as_slice()));
    }

    /// Padded URL-safe input is accepted too.
    #[test]
    fn url_safe_accepts_padding() {
        assert_eq!(decode_url("Zg==").as_deref(), Ok(b"f".as_slice()));
    }

    /// Bad alphabet, bad length, misplaced padding, and non-canonical
    /// trailing bits (RFC 4648 sec.3.5) are refused.
    #[test]
    fn malformed_input_is_refused() {
        for text in [
            "Zg",
            "Zg=",
            "Zm9vYmFy=",
            "Zm9!",
            "Zm9v\nYmFy",
            "Z=g=",
            "====",
            "Zh==",
            "Zmx=",
        ] {
            assert_eq!(decode(text), Err(DecodeError), "standard {text:?}");
        }
        for text in [
            "Z",
            "Zg=",
            "Zm9vY",
            "Zm9vYmFy=",
            "Zg*=",
            "Z=g",
            "====",
            "Zh==",
            "Zmx=",
            "Zh",
            "Zmx",
        ] {
            assert_eq!(decode_url(text), Err(DecodeError), "url-safe {text:?}");
        }
    }
}
