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

//! RAPP wire border: arbitrary authenticated plaintext presented to the
//! restricted deterministic-CBOR decoder and to the envelope decoder;
//! every accepted CBOR value re-encodes byte for byte, and both decoders
//! return a value or a typed error.

#![no_main]

use refineid_rapp::{Envelope, decode_deterministic_cbor, encode_deterministic_cbor};

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(value) = decode_deterministic_cbor(bytes) {
        let encoded = encode_deterministic_cbor(&value).expect("every decoded value re-encodes");
        assert_eq!(encoded, bytes, "accepted CBOR is already canonical");
    }
    let _ = Envelope::decode(bytes);
});
