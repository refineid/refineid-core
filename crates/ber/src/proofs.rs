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

//! Kani proof harnesses for the BER-TLV decoder and encoder.
//!
//! Each harness states one claim about the border for every input up to
//! a named bound: the decoder returns a record or a typed error for any
//! bytes and the record lies inside them, a decoded record re-encodes
//! to bytes that decode back to it,
//! and an encoded record decodes to the tag and value it was built from.

use crate::{
    BerTlvAny, LONG_FORM_1B, LONG_FORM_2B, MULTI_BYTE_TAG_MASK, SHORT_FORM_CEILING,
    TAG_MORE_OCTETS, tlv, tlv2,
};

/// Longest input the decoding harness explores: a two-octet tag, the
/// four-octet long-form length marker with its four octets, and one
/// value octet. It covers the empty input, every length form and every
/// truncation point of each.
const MAX_INPUT_LEN: usize = 8;

/// Longest input whose decoded record the re-encoding harness re-encodes:
/// a one- or two-octet tag, a short-form length and the value octets it
/// declares. The long forms are proved by the long-form harness.
const MAX_REENCODE_INPUT_LEN: usize = 4;

/// The shortest value the one-octet long form carries: one past the
/// short form's largest length.
const ONE_OCTET_LONG_FORM_LEN: usize = SHORT_FORM_CEILING;

/// The shortest value the two-octet long form carries: one past the
/// largest length one octet holds.
const TWO_OCTET_LONG_FORM_LEN: usize = u8::MAX as usize + 1;

/// A value whose every octet is its own offset, wrapping at the octet
/// width, as long as the longest long-form value the harness wraps; its
/// octets include length- and tag-shaped ones.
const LONG_FORM_VALUE: [u8; TWO_OCTET_LONG_FORM_LEN] = offset_pattern();

const fn offset_pattern() -> [u8; TWO_OCTET_LONG_FORM_LEN] {
    let mut pattern = [0_u8; TWO_OCTET_LONG_FORM_LEN];
    let mut offset = 0;
    while offset < TWO_OCTET_LONG_FORM_LEN {
        pattern[offset] = offset.to_le_bytes()[0];
        offset += 1;
    }
    pattern
}

/// Longest value the encoding harnesses wrap: enough for an empty value,
/// a one-octet value and a value whose bytes include tag- and
/// length-shaped octets.
const MAX_VALUE_LEN: usize = 3;

/// Every prefix of `storage`, shortest first: each of concrete length
/// and symbolic contents.
fn prefixes<const N: usize>(storage: &[u8; N]) -> impl Iterator<Item = &[u8]> {
    (0..=N).map(|len| &storage[..len])
}

/// Re-encode a decoded record's tag and value in the shortest form, no
/// longer than the `size` it was decoded from, and decode it again.
fn assert_round_trip(tag: u16, value: &[u8], size: usize) {
    let encoded = match u8::try_from(tag) {
        Ok(one_octet) => tlv(one_octet, value),
        Err(_) => tlv2(tag, value),
    };
    assert!(encoded.is_ok());
    if let Ok(encoded) = encoded {
        assert!(encoded.len() <= size);
        let decoded = BerTlvAny::parse(&encoded);
        assert!(decoded.is_ok());
        if let Ok(decoded) = decoded {
            assert!(decoded.tag() == tag);
            assert!(decoded.value() == value);
            assert!(decoded.size() == encoded.len());
        }
    }
}

#[kani::proof]
fn decode_returns_a_record_inside_its_input() {
    let storage: [u8; MAX_INPUT_LEN] = kani::any();
    for input in prefixes(&storage) {
        if let Ok(record) = BerTlvAny::parse(input) {
            assert!(record.size() <= input.len());
            assert!(input[..record.size()].ends_with(record.value()));
        }
    }
}

#[kani::proof]
fn decoded_record_reencodes() {
    let storage: [u8; MAX_REENCODE_INPUT_LEN] = kani::any();
    for input in prefixes(&storage) {
        if let Ok(record) = BerTlvAny::parse(input) {
            // Re-encode at each concrete value length the record can have,
            // so the encoder's buffer is of concrete size.
            for value_len in 0..input.len() {
                if record.value().len() == value_len {
                    assert_round_trip(record.tag(), &record.value()[..value_len], record.size());
                }
            }
        }
    }
}

#[kani::proof]
fn one_octet_tag_encodes_and_decodes() {
    let tag: u8 = kani::any();
    let storage: [u8; MAX_VALUE_LEN] = kani::any();
    for value in prefixes(&storage) {
        let encoded = tlv(tag, value);
        let well_formed = tag & MULTI_BYTE_TAG_MASK != MULTI_BYTE_TAG_MASK;
        assert!(encoded.is_ok() == well_formed);
        if let Ok(encoded) = encoded {
            let decoded = BerTlvAny::parse(&encoded);
            assert!(decoded.is_ok());
            if let Ok(decoded) = decoded {
                assert!(decoded.tag() == u16::from(tag));
                assert!(decoded.value() == value);
                assert!(decoded.size() == encoded.len());
            }
        }
    }
}

#[kani::proof]
fn two_octet_tag_encodes_and_decodes() {
    let tag: u16 = kani::any();
    let storage: [u8; MAX_VALUE_LEN] = kani::any();
    for value in prefixes(&storage) {
        let encoded = tlv2(tag, value);
        let [leading, continuation] = tag.to_be_bytes();
        let well_formed = leading & MULTI_BYTE_TAG_MASK == MULTI_BYTE_TAG_MASK
            && continuation & TAG_MORE_OCTETS == 0;
        assert!(encoded.is_ok() == well_formed);
        if let Ok(encoded) = encoded {
            let decoded = BerTlvAny::parse(&encoded);
            assert!(decoded.is_ok());
            if let Ok(decoded) = decoded {
                assert!(decoded.tag() == tag);
                assert!(decoded.value() == value);
                assert!(decoded.size() == encoded.len());
            }
        }
    }
}

#[kani::proof]
fn long_form_lengths_encode_and_decode() {
    let tag: u8 = kani::any();
    kani::assume(tag & MULTI_BYTE_TAG_MASK != MULTI_BYTE_TAG_MASK);
    for (len, marker) in [
        (ONE_OCTET_LONG_FORM_LEN, LONG_FORM_1B),
        (TWO_OCTET_LONG_FORM_LEN, LONG_FORM_2B),
    ] {
        let value = &LONG_FORM_VALUE[..len];
        let encoded = tlv(tag, value);
        assert!(encoded.is_ok());
        if let Ok(encoded) = encoded {
            assert!(encoded.get(1) == Some(&marker));
            let decoded = BerTlvAny::parse(&encoded);
            assert!(decoded.is_ok());
            if let Ok(decoded) = decoded {
                // The value octets travel by the same copy the short-value
                // harnesses prove; here the decoded value is checked to be
                // exactly the trailing `len` octets of the encoding, which
                // pins the long-form length the encoder emitted.
                let value_start = encoded.len() - len;
                assert!(decoded.tag() == u16::from(tag));
                assert!(decoded.value().len() == len);
                assert!(core::ptr::eq(
                    decoded.value().as_ptr(),
                    encoded[value_start..].as_ptr()
                ));
                assert!(decoded.size() == encoded.len());
            }
        }
    }
}
