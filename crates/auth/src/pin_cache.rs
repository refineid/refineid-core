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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing permissions and
// limitations under the License.

//! Process-lifetime negative PIN cache.
//!
//! A PIN1 or PIN2 value that a card has rejected is remembered until the
//! process exits and refused locally thereafter, so software never re-offers a
//! known-bad value and burns another card retry. A rejected value is retained
//! only as a keyed fingerprint under fresh process-local random material; the
//! raw PIN bytes are never stored by this cache, and the fingerprint
//! computation stays private to this crate.
//!
//! This module keeps no positive cache. Holding a PIN1 the card accepted is a
//! host's, under the credential custody contract: in process memory until an
//! invalidation event, with no idle window. PIN2 is never held between
//! operations.

use refineid_pkcs15::TokenSerial;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::credentials::{CACHE_FINGERPRINT_KEY_LEN, CACHE_FINGERPRINT_LEN, CachedPin, Pin1, Pin2};
use crate::verify::PinSlot;

/// Opaque keyed mark standing in for one card-rejected PIN value. Erases on
/// drop, so a discarded candidate mark leaves no residue.
#[derive(Zeroize, ZeroizeOnDrop)]
struct RejectedPinFingerprint([u8; CACHE_FINGERPRINT_LEN]);

/// Process-lifetime memory of PIN values a card has already rejected.
///
/// The cache never stores a raw PIN: a rejected value is represented only by an
/// HMAC-SHA-256 fingerprint keyed with fresh random material per cache instance,
/// and membership scans run in constant time over the retained entries. Because
/// each cache draws its own random key, fingerprints cannot be correlated across
/// runs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinSafetyCache {
    fingerprint_key: [u8; CACHE_FINGERPRINT_KEY_LEN],
    rejected_pin1: Vec<RejectedPinFingerprint>,
    rejected_pin2: Vec<RejectedPinFingerprint>,
}

impl PinSafetyCache {
    /// Construct an empty cache with a fresh random fingerprint key.
    ///
    /// # Errors
    /// Returns the operating-system random-source failure rather than creating a
    /// predictable rejection-fingerprint key.
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut fingerprint_key = [0_u8; CACHE_FINGERPRINT_KEY_LEN];
        if let Err(error) = getrandom::fill(&mut fingerprint_key) {
            fingerprint_key.zeroize();
            return Err(error);
        }
        Ok(Self {
            fingerprint_key,
            rejected_pin1: Vec::new(),
            rejected_pin2: Vec::new(),
        })
    }

    /// Whether `pin` has already been rejected as PIN1 by the card identified
    /// by `serial`. The comparison runs in constant time.
    #[must_use]
    pub fn is_rejected_pin1(&self, serial: &TokenSerial, pin: &Pin1) -> bool {
        self.is_rejected(serial, pin)
    }

    /// Whether `pin` has already been rejected as PIN2 by the card identified
    /// by `serial`. The comparison runs in constant time.
    #[must_use]
    pub fn is_rejected_pin2(&self, serial: &TokenSerial, pin: &Pin2) -> bool {
        self.is_rejected(serial, pin)
    }

    /// Remember a card-side wrong-PIN1 response for the rest of this process,
    /// so the same value is never offered again for this card and PIN1. A value
    /// already remembered is not stored twice.
    pub fn record_rejected_pin1(&mut self, serial: &TokenSerial, pin: &Pin1) {
        self.record_rejected(serial, pin);
    }

    /// Remember a card-side wrong-PIN2 response for the rest of this process,
    /// so the same value is never offered again for this card and PIN2. A value
    /// already remembered is not stored twice.
    pub fn record_rejected_pin2(&mut self, serial: &TokenSerial, pin: &Pin2) {
        self.record_rejected(serial, pin);
    }

    fn is_rejected(&self, serial: &TokenSerial, pin: &impl CachedPin) -> bool {
        let candidate = self.fingerprint(serial, pin);
        self.contains_fingerprint(pin.slot(), &candidate)
    }

    fn contains_fingerprint(&self, slot: PinSlot, candidate: &RejectedPinFingerprint) -> bool {
        self.rejected(slot)
            .iter()
            .fold(subtle::Choice::from(0), |matched, known| {
                matched | known.0.ct_eq(&candidate.0)
            })
            .into()
    }

    fn record_rejected(&mut self, serial: &TokenSerial, pin: &impl CachedPin) {
        let fingerprint = self.fingerprint(serial, pin);
        self.record_fingerprint(pin.slot(), fingerprint);
    }

    fn record_fingerprint(&mut self, slot: PinSlot, fingerprint: RejectedPinFingerprint) {
        if !self.contains_fingerprint(slot, &fingerprint) {
            self.rejected_mut(slot).push(fingerprint);
        }
    }

    /// The keyed mark for `pin` on the card identified by `serial`. Computed
    /// inside this crate as an HMAC-SHA-256 over a domain-separated preimage,
    /// so no two `(serial, slot, pin)` triples share a mark and no fingerprint
    /// crosses a crate boundary.
    fn fingerprint(&self, serial: &TokenSerial, pin: &impl CachedPin) -> RejectedPinFingerprint {
        RejectedPinFingerprint(
            pin.keyed_fingerprint(serial.as_str().as_bytes(), &self.fingerprint_key),
        )
    }

    fn rejected(&self, slot: PinSlot) -> &[RejectedPinFingerprint] {
        match slot {
            PinSlot::Pin1 => &self.rejected_pin1,
            PinSlot::Pin2 => &self.rejected_pin2,
        }
    }

    const fn rejected_mut(&mut self, slot: PinSlot) -> &mut Vec<RejectedPinFingerprint> {
        match slot {
            PinSlot::Pin1 => &mut self.rejected_pin1,
            PinSlot::Pin2 => &mut self.rejected_pin2,
        }
    }
}

impl core::fmt::Debug for PinSafetyCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinSafetyCache")
            .field("rejected_pin1_count", &self.rejected_pin1.len())
            .field("rejected_pin2_count", &self.rejected_pin2.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl PinSafetyCache {
    /// Install a fixed fingerprint key so tests observe deterministic marks.
    fn with_fixed_fingerprint_key(fingerprint_key: [u8; CACHE_FINGERPRINT_KEY_LEN]) -> Self {
        Self {
            fingerprint_key,
            rejected_pin1: Vec::new(),
            rejected_pin2: Vec::new(),
        }
    }

    /// How many rejection fingerprints are retained for `slot`.
    fn rejected_count(&self, slot: PinSlot) -> usize {
        self.rejected(slot).len()
    }
}

#[cfg(test)]
mod tests {
    use refineid_pkcs15::TokenSerial;

    use super::{CACHE_FINGERPRINT_KEY_LEN, PinSafetyCache};
    use crate::credentials::{PIN_MAX_LENGTH, Pin1, Pin2, UnvalidatedSecret};
    use crate::verify::PinSlot;

    /// Arbitrary fixed fingerprint-key byte, repeated across the key so that
    /// test fingerprints are reproducible without touching the OS random source.
    const TEST_FINGERPRINT_KEY_BYTE: u8 = 0xA5;
    const DECIMAL_DIGIT_RADIX: u8 = 10;

    /// Distinct synthetic card serials.
    const CARD_A_SERIAL: &str = "CARD-A-FULL-SERIAL";
    const CARD_B_SERIAL: &str = "CARD-B-FULL-SERIAL";

    fn cache() -> PinSafetyCache {
        PinSafetyCache::with_fixed_fingerprint_key(
            [TEST_FINGERPRINT_KEY_BYTE; CACHE_FINGERPRINT_KEY_LEN],
        )
    }

    fn serial(text: &str) -> TokenSerial {
        TokenSerial::new(text.to_owned())
    }

    fn random_digits() -> Vec<u8> {
        let mut bytes = vec![0_u8; PIN_MAX_LENGTH];
        getrandom::fill(&mut bytes).expect("operating system random source is available");
        for byte in &mut bytes {
            *byte = b'0' + (*byte % DECIMAL_DIGIT_RADIX);
        }
        bytes
    }

    fn pin1_with_digits(digits: Vec<u8>) -> Pin1 {
        Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(digits))
            .expect("random local input satisfies credential policy")
    }

    fn pin2_with_digits(digits: Vec<u8>) -> Pin2 {
        Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(digits))
            .expect("random local input satisfies credential policy")
    }

    fn pin1() -> Pin1 {
        pin1_with_digits(random_digits())
    }

    fn pin2() -> Pin2 {
        pin2_with_digits(random_digits())
    }

    #[test]
    fn new_draws_fresh_random_keys_across_instances() {
        let first = PinSafetyCache::new().expect("OS random source is available");
        let second = PinSafetyCache::new().expect("OS random source is available");
        assert!(first.fingerprint_key != second.fingerprint_key);
    }

    #[test]
    fn recorded_value_is_rejected_for_its_serial_and_slot() {
        let mut cache = cache();
        let pin = pin1();
        cache.record_rejected_pin1(&serial(CARD_A_SERIAL), &pin);
        assert!(cache.is_rejected_pin1(&serial(CARD_A_SERIAL), &pin));
    }

    #[test]
    fn recorded_pin2_value_is_rejected_and_deduped_for_its_serial_and_slot() {
        let mut cache = cache();
        let pin = pin2();
        cache.record_rejected_pin2(&serial(CARD_A_SERIAL), &pin);
        cache.record_rejected_pin2(&serial(CARD_A_SERIAL), &pin);
        assert_eq!(cache.rejected_count(PinSlot::Pin2), 1);
        assert!(cache.is_rejected_pin2(&serial(CARD_A_SERIAL), &pin));
    }

    #[test]
    fn a_different_value_is_not_rejected() {
        let mut cache = cache();
        let rejected_digits = random_digits();
        let different_digits = loop {
            let candidate = random_digits();
            if candidate != rejected_digits {
                break candidate;
            }
        };
        let rejected = pin1_with_digits(rejected_digits);
        let different = pin1_with_digits(different_digits);
        cache.record_rejected_pin1(&serial(CARD_A_SERIAL), &rejected);
        assert!(!cache.is_rejected_pin1(&serial(CARD_A_SERIAL), &different));
    }

    #[test]
    fn a_different_slot_is_not_rejected() {
        let mut cache = cache();
        let digits = random_digits();
        let pin = pin1_with_digits(digits.clone());
        let other_slot = pin2_with_digits(digits);
        cache.record_rejected_pin1(&serial(CARD_A_SERIAL), &pin);
        assert!(!cache.is_rejected_pin2(&serial(CARD_A_SERIAL), &other_slot));
    }

    #[test]
    fn a_different_serial_is_not_rejected() {
        let mut cache = cache();
        let pin = pin1();
        cache.record_rejected_pin1(&serial(CARD_A_SERIAL), &pin);
        assert!(!cache.is_rejected_pin1(&serial(CARD_B_SERIAL), &pin));
    }

    #[test]
    fn recording_the_same_value_twice_is_deduped() {
        let mut cache = cache();
        let pin = pin1();
        cache.record_rejected_pin1(&serial(CARD_A_SERIAL), &pin);
        cache.record_rejected_pin1(&serial(CARD_A_SERIAL), &pin);
        assert_eq!(cache.rejected_count(PinSlot::Pin1), 1);
        assert!(cache.is_rejected_pin1(&serial(CARD_A_SERIAL), &pin));
    }
}
