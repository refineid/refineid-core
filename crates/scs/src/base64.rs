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

//! Base64 coding (RFC 4648), standard and URL-safe.
//!
//! Certificates and signature content ride as padded standard base64
//! (RFC 4648 sec.4); JOSE segments ride unpadded URL-safe (RFC 7515
//! sec.2). The decoders are strict: the alphabet plus `=` padding
//! only, correct length, padding only at the end. Whitespace is
//! refused -- the callers are machines, and what they send has none.

/// Characters in a base64 alphabet.
const ALPHABET_LENGTH: usize = 64;

/// The standard alphabet (RFC 4648 sec.4).
const ALPHABET: &[u8; ALPHABET_LENGTH] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The URL-safe alphabet (RFC 4648 sec.5).
const ALPHABET_URL: &[u8; ALPHABET_LENGTH] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Input octets per encoded quantum.
const QUANTUM_IN: usize = 3;

/// Output characters per encoded quantum.
const QUANTUM_OUT: usize = 4;

/// Bits carried by one output character.
const BITS_PER_CHARACTER: usize = 6;

/// Mask selecting one output character's worth of bits.
const CHARACTER_MASK: usize = 0x3F;

/// Bits in an octet.
const BITS_PER_OCTET: usize = 8;

/// The padding character.
const PADDING: u8 = b'=';

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
    encode_with(input, ALPHABET, true)
}

/// Decode padded standard base64.
pub fn decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    decode_with(text.as_bytes(), ALPHABET, true)
}

/// Encode `input` URL-safe without padding, the JOSE segment form.
#[must_use]
pub fn encode_url(input: &[u8]) -> String {
    encode_with(input, ALPHABET_URL, false)
}

/// Decode URL-safe base64, padded or not.
pub fn decode_url(text: &str) -> Result<Vec<u8>, DecodeError> {
    decode_with(text.as_bytes(), ALPHABET_URL, false)
}

fn encode_with(input: &[u8], alphabet: &[u8; ALPHABET_LENGTH], padded: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(QUANTUM_IN) * QUANTUM_OUT);
    for chunk in input.chunks(QUANTUM_IN) {
        // Pack the chunk into a 24-bit accumulator, so a short final
        // chunk simply leaves the low bits zero.
        let mut packed = 0_usize;
        for index in 0..QUANTUM_IN {
            packed <<= BITS_PER_OCTET;
            packed |= usize::from(chunk.get(index).copied().unwrap_or(0));
        }
        // Every chunk yields four characters; the ones with no input
        // behind them become padding below, or are dropped unpadded.
        for index in 0..QUANTUM_OUT {
            let shift = BITS_PER_CHARACTER * (QUANTUM_OUT - 1 - index);
            let sextet = (packed >> shift) & CHARACTER_MASK;
            // `index <= chunk.len()` is the count of characters
            // carrying real input: one more than the octets supplied.
            if index <= chunk.len() {
                out.push(char::from(alphabet[sextet]));
            } else if padded {
                out.push(char::from(PADDING));
            }
        }
    }
    out
}

fn decode_with(
    input: &[u8],
    alphabet: &[u8; ALPHABET_LENGTH],
    padding_required: bool,
) -> Result<Vec<u8>, DecodeError> {
    let unpadded = input.strip_suffix(&[PADDING]).unwrap_or(input);
    let unpadded = unpadded.strip_suffix(&[PADDING]).unwrap_or(unpadded);
    if unpadded.len() == input.len() && padding_required {
        // Padded form: the length must already be whole quanta.
        if !input.len().is_multiple_of(QUANTUM_OUT) {
            return Err(DecodeError);
        }
    } else {
        // Padding was stripped, or the unpadded form is allowed: what
        // remains must be alphabet only, and the total must complete
        // whole quanta with at most two padding characters.
        if unpadded.contains(&PADDING) {
            return Err(DecodeError);
        }
        let missing = input.len() - unpadded.len();
        if missing > QUANTUM_IN - 1 {
            return Err(DecodeError);
        }
        let padded_len = unpadded.len() + missing;
        if padding_required && !padded_len.is_multiple_of(QUANTUM_OUT) {
            return Err(DecodeError);
        }
        if !padding_required {
            let remainder = unpadded.len() % QUANTUM_OUT;
            if remainder == 1 {
                return Err(DecodeError);
            }
            if !input.len().is_multiple_of(QUANTUM_OUT) && missing > 0 {
                return Err(DecodeError);
            }
        }
    }
    let mut sextets = Vec::with_capacity(unpadded.len());
    for byte in unpadded {
        let Some(position) = alphabet.iter().position(|candidate| candidate == byte) else {
            return Err(DecodeError);
        };
        sextets.push(position);
    }
    let mut out = Vec::with_capacity(sextets.len() / QUANTUM_OUT * QUANTUM_IN);
    for quantum in sextets.chunks(QUANTUM_OUT) {
        let mut packed = 0_usize;
        for sextet in quantum {
            packed <<= BITS_PER_CHARACTER;
            packed |= sextet;
        }
        packed <<= BITS_PER_CHARACTER * (QUANTUM_OUT - quantum.len());
        let bytes = packed.to_be_bytes();
        let start = bytes.len() - QUANTUM_IN;
        let take = quantum.len().saturating_sub(1);
        out.extend_from_slice(&bytes[start..start + take]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{DecodeError, decode, decode_url, encode, encode_url};

    /// Two octets whose URL-safe encoding swaps both alphabets.
    const SWAPPED: &[u8] = &[0xFB, 0xFF];

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
        assert_eq!(encode_url(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode_url(b"f"), "Zg");
        assert_eq!(encode_url(SWAPPED), "-_8");
        assert_eq!(decode_url("Zm9vYmFy").as_deref(), Ok(b"foobar".as_slice()));
        assert_eq!(decode_url("Zg").as_deref(), Ok(b"f".as_slice()));
        assert_eq!(decode_url("-_8").as_deref(), Ok(SWAPPED));
    }

    /// Padded URL-safe input is accepted too.
    #[test]
    fn url_safe_accepts_padding() {
        assert_eq!(decode_url("Zg==").as_deref(), Ok(b"f".as_slice()));
    }

    /// Bad alphabet, bad length, and misplaced padding are refused.
    #[test]
    fn malformed_input_is_refused() {
        for text in ["Zg", "Zg=", "Zm9vYmFy=", "Zm9!", "Zm9v\nYmFy", "Z=g="] {
            assert_eq!(decode(text), Err(DecodeError), "standard {text:?}");
        }
        for text in ["Z", "Zm9vY", "Zg*=", "Z=g"] {
            assert_eq!(decode_url(text), Err(DecodeError), "url-safe {text:?}");
        }
    }
}
