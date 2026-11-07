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

//! Kani proof harnesses for the PKCS#15 parsing borders.
//!
//! The `TokenInfo.version` INTEGER decodes to a `u32` exactly when it
//! fits one and is refused otherwise, and the password length range
//! holds its predicate for every pair of bounds. The EF.TokenInfo and
//! EF.AOD parsers build their child lists in vectors whose symbolic
//! execution does not finish at a bound that reaches an accepted object,
//! so those parsers are left to the fuzz target.

use refineid_ber::BerError;

use crate::PasswordLengthRange;
use crate::token_info::unsigned_version;

/// Longest version INTEGER content the version harness decodes: one
/// octet past the four a `u32` holds.
const MAX_VERSION_OCTETS: usize = 5;

/// Every prefix of `storage`, shortest first: each of concrete length
/// and symbolic contents.
fn prefixes<const N: usize>(storage: &[u8; N]) -> impl Iterator<Item = &[u8]> {
    (0..=N).map(|len| &storage[..len])
}

#[kani::proof]
fn version_fits_or_is_refused() {
    let storage: [u8; MAX_VERSION_OCTETS] = kani::any();
    for content in prefixes(&storage) {
        let fits = content.len() <= core::mem::size_of::<u32>()
            && content
                .first()
                .is_some_and(|&leading| leading.leading_zeros() > 0);
        match unsigned_version(content) {
            Ok(version) => {
                assert!(fits);
                let wire = version.to_be_bytes();
                assert!(wire.ends_with(content));
                assert!(
                    wire[..wire.len() - content.len()]
                        .iter()
                        .all(|&octet| octet == 0)
                );
            }
            Err(error) => assert!(!fits && error == BerError::IntegerOutOfRange),
        }
    }
}

#[kani::proof]
fn length_range_predicate() {
    let min: u8 = kani::any();
    let max: u8 = kani::any();
    match PasswordLengthRange::new(min, max) {
        Some(range) => {
            assert!(min >= 1 && min <= max);
            assert!(range.contains(range.min()) && range.contains(range.max()));
            assert!(range.intersection(range) == Some(range));
        }
        None => assert!(min == 0 || min > max),
    }
}
