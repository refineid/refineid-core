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

//! Kani proof harnesses for the eMRTD parsing borders.
//!
//! For every input up to the named bound the outer-length header decoder
//! returns a length no larger than the file ceiling or nothing, agrees
//! with the BER decoder wherever both accept, and the EF.COM parser
//! returns.

use refineid_ber::BerTlvAny;

use crate::reader::MAX_EMRTD_FILE_BYTES;
use crate::{DataGroupInventory, decode_outer_total_length};

/// Longest header the harness explores: a two-octet tag and the
/// two-octet long-form length marker with its octets. It covers the
/// short and both long length forms the decoder reads and each truncation
/// of them.
const MAX_INPUT_LEN: usize = 5;

/// Every prefix of `storage`, shortest first: each of concrete length
/// and symbolic contents.
fn prefixes<const N: usize>(storage: &[u8; N]) -> impl Iterator<Item = &[u8]> {
    (0..=N).map(|len| &storage[..len])
}

#[kani::proof]
fn outer_length_is_bounded_and_agrees_with_ber() {
    let storage: [u8; MAX_INPUT_LEN] = kani::any();
    for input in prefixes(&storage) {
        if let Some(total) = decode_outer_total_length(input) {
            assert!(total <= MAX_EMRTD_FILE_BYTES);
            if let Ok(record) = BerTlvAny::parse(input) {
                assert!(record.size() == total);
            }
        }
    }
}

#[kani::proof]
fn inventory_parse_returns() {
    let storage: [u8; MAX_INPUT_LEN] = kani::any();
    for input in prefixes(&storage) {
        let _ = DataGroupInventory::parse(input);
    }
}
