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

//! BER-TLV decoding of arbitrary bytes: every decode returns, every
//! decoded record re-encodes through the crate's encoder, and the
//! re-encoding decodes back to the same tag and value.

#![no_main]

use refineid_ber::{BerTag, BerTlv, BerTlvAny, BerTlvIter, Sequence, tlv, tlv2};

/// Deepest nesting of constructed values the target descends into.
const MAX_DEPTH: usize = 8;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    match BerTlvAny::parse(bytes) {
        Ok(record) => {
            assert!(record.size() <= bytes.len());
            let framed = &bytes[..record.size()];
            assert!(framed.ends_with(record.value()));
            check_round_trip(record);
            let typed = BerTlv::<Sequence>::parse(bytes);
            assert_eq!(typed.is_ok(), record.tag() == <Sequence as BerTag>::TAG);
        }
        Err(_) => assert!(BerTlv::<Sequence>::parse(bytes).is_err()),
    }
    walk(bytes, MAX_DEPTH);
});

/// Decode `bytes` as a sequence of records and check each, descending
/// into every value as if it were constructed, `depth` levels deep.
fn walk(bytes: &[u8], depth: usize) {
    let Some(deeper) = depth.checked_sub(1) else {
        return;
    };
    for record in BerTlvIter::new(bytes).flatten() {
        check_round_trip(record);
        walk(record.value(), deeper);
    }
}

/// The record's tag and value re-encode, in the shortest length form,
/// to a record that decodes back to them.
fn check_round_trip(record: BerTlvAny<'_>) {
    let encoded = match u8::try_from(record.tag()) {
        Ok(tag) => tlv(tag, record.value()),
        Err(_) => tlv2(record.tag(), record.value()),
    };
    let encoded = encoded.expect("a decoded record re-encodes");
    assert!(encoded.len() <= record.size());
    let decoded = BerTlvAny::parse(&encoded).expect("an encoded record decodes");
    assert_eq!(decoded.tag(), record.tag());
    assert_eq!(decoded.value(), record.value());
    assert_eq!(decoded.size(), encoded.len());
}
