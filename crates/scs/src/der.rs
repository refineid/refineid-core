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

//! Small DER builders over [`refineid_ber`]: the constructed values
//! the CMS and localhost-certificate writers compose from.

/// DER tag: BOOLEAN.
pub const TAG_BOOLEAN: u8 = 0x01;

/// DER tag: INTEGER.
pub const TAG_INTEGER: u8 = 0x02;

/// DER tag: BIT STRING.
pub const TAG_BIT_STRING: u8 = 0x03;

/// DER tag: OCTET STRING.
pub const TAG_OCTET_STRING: u8 = 0x04;

/// DER tag: NULL.
pub const TAG_NULL: u8 = 0x05;

/// DER tag: OBJECT IDENTIFIER.
pub const TAG_OID: u8 = 0x06;

/// DER tag: UTF8String.
pub const TAG_UTF8_STRING: u8 = 0x0C;

/// DER tag: SEQUENCE.
pub const TAG_SEQUENCE: u8 = 0x30;

/// DER tag: SET.
pub const TAG_SET: u8 = 0x31;

/// DER tag: explicit [0], constructed.
pub const TAG_CONTEXT_ZERO: u8 = 0xA0;

/// DER tag: explicit [3], constructed.
pub const TAG_CONTEXT_THREE: u8 = 0xA3;

/// DER tag: explicit [2], primitive (a DNS name).
pub const TAG_CONTEXT_TWO: u8 = 0x82;

/// DER tag: explicit [7], primitive (an IP address).
pub const TAG_CONTEXT_SEVEN: u8 = 0x87;

/// BOOLEAN TRUE; DER never writes a default FALSE.
pub const BOOLEAN_TRUE: u8 = 0xFF;

/// BIT STRING content with no unused bits in the final octet.
pub const NO_UNUSED_BITS: u8 = 0;

/// The DER INTEGER sign bit.
pub const SIGN_BIT_MASK: u8 = 0x80;

/// Concatenate the element encodings.
fn join(elements: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for element in elements {
        body.extend_from_slice(element);
    }
    body
}

/// A SEQUENCE of the element encodings.
pub fn sequence(elements: &[&[u8]]) -> Result<Vec<u8>, ()> {
    refineid_ber::tlv(TAG_SEQUENCE, join(elements)).map_err(|_| ())
}

/// A SET OF already-encoded elements, sorted by encoding as DER
/// requires (X.690 sec.11.6).
pub fn set(elements: &[&[u8]]) -> Result<Vec<u8>, ()> {
    let mut sorted: Vec<&[u8]> = elements.to_vec();
    sorted.sort();
    refineid_ber::tlv(TAG_SET, join(&sorted)).map_err(|_| ())
}

/// An encoded value re-tagged: the first tag octet replaced,
/// for IMPLICIT context tags over a complete encoding.
pub fn retag(replacement: u8, encoded: &[u8]) -> Result<Vec<u8>, ()> {
    let Some((&first, _)) = encoded.split_first() else {
        return Err(());
    };
    if first != TAG_SEQUENCE && first != TAG_SET {
        return Err(());
    }
    let mut out = encoded.to_vec();
    out[0] = replacement;
    Ok(out)
}

/// An OBJECT IDENTIFIER from content bytes.
pub fn oid(content: &[u8]) -> Result<Vec<u8>, ()> {
    refineid_ber::tlv(TAG_OID, content).map_err(|_| ())
}

/// An OCTET STRING.
pub fn octet_string(content: &[u8]) -> Result<Vec<u8>, ()> {
    refineid_ber::tlv(TAG_OCTET_STRING, content).map_err(|_| ())
}

/// NULL, whose DER value has empty content.
pub fn null() -> Result<Vec<u8>, ()> {
    refineid_ber::tlv(TAG_NULL, []).map_err(|_| ())
}

/// BOOLEAN TRUE.
pub fn boolean_true() -> Result<Vec<u8>, ()> {
    refineid_ber::tlv(TAG_BOOLEAN, [BOOLEAN_TRUE]).map_err(|_| ())
}

/// A UTF8String.
pub fn utf8_string(content: &[u8]) -> Result<Vec<u8>, ()> {
    refineid_ber::tlv(TAG_UTF8_STRING, content).map_err(|_| ())
}

/// A BIT STRING with no unused bits.
pub fn bit_string(content: &[u8]) -> Result<Vec<u8>, ()> {
    let mut body = Vec::with_capacity(content.len() + 1);
    body.push(NO_UNUSED_BITS);
    body.extend_from_slice(content);
    refineid_ber::tlv(TAG_BIT_STRING, body).map_err(|_| ())
}

/// A BIT STRING whose content already carries its unused-bits octet.
pub fn bit_string_raw(content: &[u8]) -> Result<Vec<u8>, ()> {
    refineid_ber::tlv(TAG_BIT_STRING, content).map_err(|_| ())
}

/// Content under an explicit tag.
pub fn tagged(tag: u8, content: &[u8]) -> Result<Vec<u8>, ()> {
    refineid_ber::tlv(tag, content).map_err(|_| ())
}

/// A small non-negative INTEGER.
pub fn integer(value: u8) -> Result<Vec<u8>, ()> {
    unsigned_integer(&[value])
}

/// An INTEGER from magnitude bytes: leading zeros stripped, the sign
/// byte added when the high bit is set.
pub fn unsigned_integer(magnitude: &[u8]) -> Result<Vec<u8>, ()> {
    let stripped: Vec<u8> = magnitude
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    let mut bytes = Vec::with_capacity(stripped.len() + 1);
    if stripped.is_empty() || stripped[0] & SIGN_BIT_MASK != 0 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&stripped);
    refineid_ber::tlv(TAG_INTEGER, bytes).map_err(|_| ())
}
