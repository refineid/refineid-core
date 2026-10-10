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

//! Announced service withdrawal (RAPP v26.10.10 §4.5).
//!
//! A custodian that deliberately stops serving replaces its stream discovery
//! record with a `mode=withdrawn` record. Each of its eight entries is either
//! the withdrawal hint of one stored pairing or a random filler. A hint is
//! keyed by the pairing's static X25519 agreement, which never crosses the
//! wire, and is bound to the advertised service instance name and a 60-second
//! counter. Record parsing and matching live here so that no platform parses
//! the record itself.

use core::fmt;

use curve25519_dalek::{montgomery::MontgomeryPoint, traits::Identity};
use hmac::{
    Hmac,
    digest::{KeyInit, Mac},
};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use super::{PairId, PairRecord, X25519_KEY_SIZE};

/// Byte length of one withdrawal hint.
pub const WITHDRAWAL_HINT_SIZE: usize = 8;

/// Seconds per withdrawal counter step.
pub const WITHDRAWAL_COUNTER_SECONDS: u64 = 60;

/// Entries in every `withdrawn=` value, hints and fillers together.
pub const WITHDRAWN_RECORD_ENTRIES: usize = 8;

/// Longest service instance name, one DNS label.
pub const MAX_INSTANCE_NAME_SIZE: usize = 63;

/// HKDF-Expand info naming the withdrawal key.
const WITHDRAWAL_KEY_INFO: &[u8] = b"RAPP-withdrawal-v1";

/// The single-block counter byte of HKDF-Expand for a 32-byte output.
const HKDF_FIRST_BLOCK: u8 = 1;

/// Byte length of the withdrawal key.
const WITHDRAWAL_KEY_SIZE: usize = 32;

/// TXT key and value naming the record version.
const TXT_VERSION_KEY: &str = "v";
const TXT_VERSION: &str = "1";

/// TXT key and value naming the withdrawn mode.
const TXT_MODE_KEY: &str = "mode";
const TXT_MODE_WITHDRAWN: &str = "withdrawn";

/// TXT key carrying the hint list.
const TXT_WITHDRAWN_KEY: &str = "withdrawn";

/// Separator between hint-list entries.
const ENTRY_SEPARATOR: char = ',';

/// Hexadecimal digits per encoded entry.
const ENTRY_HEX_DIGITS: usize = WITHDRAWAL_HINT_SIZE * 2;

/// Lowercase hexadecimal alphabet of the encoded entries.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Bits per hexadecimal digit.
const NIBBLE_BITS: u32 = 4;

/// Low-nibble mask.
const NIBBLE_MASK: u8 = 0x0f;

type HmacSha256 = Hmac<Sha256>;

/// Why a withdrawal value could not be formed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WithdrawalError {
    /// The static agreement is the identity point.
    DegenerateAgreement,
    /// The service instance name is empty or longer than one DNS label.
    InvalidInstanceName,
    /// More pairings than a record carries.
    TooManyHints,
    /// The platform random source failed.
    RandomUnavailable,
}

impl fmt::Display for WithdrawalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DegenerateAgreement => "static agreement is the identity point",
            Self::InvalidInstanceName => "service instance name is not one DNS label",
            Self::TooManyHints => "more pairings than a withdrawn record carries",
            Self::RandomUnavailable => "random source unavailable",
        })
    }
}

impl core::error::Error for WithdrawalError {}

/// The advertised DNS-SD service instance name a hint is bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceName(String);

impl InstanceName {
    /// Validates an instance name of 1 to 63 UTF-8 octets.
    ///
    /// # Errors
    /// [`WithdrawalError::InvalidInstanceName`] otherwise.
    pub fn new(name: &str) -> Result<Self, WithdrawalError> {
        if name.is_empty() || name.len() > MAX_INSTANCE_NAME_SIZE {
            return Err(WithdrawalError::InvalidInstanceName);
        }
        Ok(Self(name.to_owned()))
    }

    /// The name's UTF-8 octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The withdrawal counter for a Unix time: `floor(unix_time / 60)`.
#[must_use]
pub const fn withdrawal_counter(unix_time_seconds: u64) -> u64 {
    unix_time_seconds / WITHDRAWAL_COUNTER_SECONDS
}

/// One pairing's withdrawal key `K_wd`, equal on both endpoints.
pub struct WithdrawalKey(Zeroizing<[u8; WITHDRAWAL_KEY_SIZE]>);

impl fmt::Debug for WithdrawalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WithdrawalKey([redacted])")
    }
}

impl WithdrawalKey {
    /// Derives the key of a stored pairing.
    ///
    /// # Errors
    /// [`WithdrawalError::DegenerateAgreement`] when the static agreement is
    /// the identity point.
    pub fn derive(record: &PairRecord) -> Result<Self, WithdrawalError> {
        Self::from_parts(
            record.pair_id(),
            record.local_static_private(),
            record.remote_static_public(),
        )
    }

    /// Derives `K_wd = HKDF-SHA-256(salt = pair_id, IKM = X25519(local
    /// static private, peer static public), info = "RAPP-withdrawal-v1",
    /// L = 32)`.
    ///
    /// # Errors
    /// [`WithdrawalError::DegenerateAgreement`] when the agreement is the
    /// identity point.
    pub fn from_parts(
        pair_id: PairId,
        local_static_private: &[u8; X25519_KEY_SIZE],
        remote_static_public: &[u8; X25519_KEY_SIZE],
    ) -> Result<Self, WithdrawalError> {
        let agreement = MontgomeryPoint(*remote_static_public).mul_clamped(*local_static_private);
        if agreement == MontgomeryPoint::identity() {
            return Err(WithdrawalError::DegenerateAgreement);
        }
        let shared = Zeroizing::new(agreement.0);
        let mut extract = <HmacSha256 as KeyInit>::new_from_slice(pair_id.as_bytes())
            .expect("HMAC accepts any key length");
        extract.update(shared.as_slice());
        let mut prk = Zeroizing::new([0_u8; WITHDRAWAL_KEY_SIZE]);
        prk.copy_from_slice(&extract.finalize().into_bytes());
        let mut expand = <HmacSha256 as KeyInit>::new_from_slice(prk.as_slice())
            .expect("HMAC accepts any key length");
        expand.update(WITHDRAWAL_KEY_INFO);
        expand.update(&[HKDF_FIRST_BLOCK]);
        let mut key = Zeroizing::new([0_u8; WITHDRAWAL_KEY_SIZE]);
        key.copy_from_slice(&expand.finalize().into_bytes());
        Ok(Self(key))
    }

    /// First 8 bytes of `HMAC-SHA-256(K_wd, len(instance) || instance ||
    /// counter_be64)`, `len` one octet.
    #[must_use]
    pub fn hint(&self, instance: &InstanceName, counter: u64) -> [u8; WITHDRAWAL_HINT_SIZE] {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(self.0.as_slice())
            .expect("HMAC accepts any key length");
        let name = instance.as_bytes();
        let length = u8::try_from(name.len()).expect("an instance name is one DNS label");
        mac.update(&[length]);
        mac.update(name);
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let mut hint = [0_u8; WITHDRAWAL_HINT_SIZE];
        hint.copy_from_slice(&digest[..WITHDRAWAL_HINT_SIZE]);
        hint
    }

    /// Whether `record` carries this pairing's hint for `instance` at
    /// `counter` or an adjacent counter, compared in constant time.
    #[must_use]
    pub fn matches(&self, record: &WithdrawnRecord, instance: &InstanceName, counter: u64) -> bool {
        let mut matched = Choice::from(0);
        for candidate in [
            counter.checked_sub(1),
            Some(counter),
            counter.checked_add(1),
        ]
        .into_iter()
        .flatten()
        {
            let expected = self.hint(instance, candidate);
            for entry in &record.entries {
                matched |= expected.ct_eq(entry);
            }
        }
        bool::from(matched)
    }
}

/// A well-formed `mode=withdrawn` record: exactly eight entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawnRecord {
    entries: [[u8; WITHDRAWAL_HINT_SIZE]; WITHDRAWN_RECORD_ENTRIES],
}

/// Why a TXT record is not a well-formed withdrawn record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WithdrawnRecordError {
    /// A key other than `v`, `mode` and `withdrawn`, or a repeated key.
    UnexpectedKey,
    /// `v`, `mode` or `withdrawn` is missing or has another value.
    WrongHeader,
    /// The hint list is not eight lowercase 16-digit hexadecimal entries.
    MalformedEntries,
}

impl WithdrawnRecord {
    /// Assembles a record from the custodian's hints, filling the remaining
    /// entries with random values and shuffling all eight with `random`.
    ///
    /// # Errors
    /// [`WithdrawalError::TooManyHints`] for more than eight hints, and
    /// [`WithdrawalError::RandomUnavailable`] when `random` fails.
    pub fn assemble(
        hints: &[[u8; WITHDRAWAL_HINT_SIZE]],
        mut random: impl FnMut(&mut [u8]) -> Result<(), WithdrawalError>,
    ) -> Result<Self, WithdrawalError> {
        if hints.len() > WITHDRAWN_RECORD_ENTRIES {
            return Err(WithdrawalError::TooManyHints);
        }
        let mut keyed = [([0_u8; WITHDRAWAL_HINT_SIZE], [0_u8; WITHDRAWAL_HINT_SIZE]);
            WITHDRAWN_RECORD_ENTRIES];
        for (index, (order, entry)) in keyed.iter_mut().enumerate() {
            random(order)?;
            match hints.get(index) {
                Some(hint) => *entry = *hint,
                None => random(entry)?,
            }
        }
        keyed.sort_unstable_by_key(|(order, _)| *order);
        Ok(Self {
            entries: keyed.map(|(_, entry)| entry),
        })
    }

    /// Parses the TXT key/value pairs of a discovered record.
    ///
    /// # Errors
    /// [`WithdrawnRecordError`] for anything but exactly `v=1`,
    /// `mode=withdrawn` and eight lowercase entries in `withdrawn=`.
    pub fn parse(entries: &[(&str, &str)]) -> Result<Self, WithdrawnRecordError> {
        let mut version = None;
        let mut mode = None;
        let mut list = None;
        for &(key, value) in entries {
            let slot = match key {
                TXT_VERSION_KEY => &mut version,
                TXT_MODE_KEY => &mut mode,
                TXT_WITHDRAWN_KEY => &mut list,
                _ => return Err(WithdrawnRecordError::UnexpectedKey),
            };
            if slot.replace(value).is_some() {
                return Err(WithdrawnRecordError::UnexpectedKey);
            }
        }
        if version != Some(TXT_VERSION) || mode != Some(TXT_MODE_WITHDRAWN) {
            return Err(WithdrawnRecordError::WrongHeader);
        }
        let list = list.ok_or(WithdrawnRecordError::WrongHeader)?;
        let mut parsed = [[0_u8; WITHDRAWAL_HINT_SIZE]; WITHDRAWN_RECORD_ENTRIES];
        let mut count = 0;
        for text in list.split(ENTRY_SEPARATOR) {
            let slot = parsed
                .get_mut(count)
                .ok_or(WithdrawnRecordError::MalformedEntries)?;
            *slot = decode_entry(text).ok_or(WithdrawnRecordError::MalformedEntries)?;
            count += 1;
        }
        if count != WITHDRAWN_RECORD_ENTRIES {
            return Err(WithdrawnRecordError::MalformedEntries);
        }
        Ok(Self { entries: parsed })
    }

    /// The record's TXT key/value pairs, in publication order.
    #[must_use]
    pub fn txt_entries(&self) -> [(&'static str, String); 3] {
        let list = self
            .entries
            .iter()
            .map(encode_entry)
            .collect::<Vec<_>>()
            .join(&ENTRY_SEPARATOR.to_string());
        [
            (TXT_VERSION_KEY, TXT_VERSION.to_owned()),
            (TXT_MODE_KEY, TXT_MODE_WITHDRAWN.to_owned()),
            (TXT_WITHDRAWN_KEY, list),
        ]
    }

    /// The eight entries in publication order.
    #[must_use]
    pub const fn entries(&self) -> &[[u8; WITHDRAWAL_HINT_SIZE]; WITHDRAWN_RECORD_ENTRIES] {
        &self.entries
    }
}

fn encode_entry(entry: &[u8; WITHDRAWAL_HINT_SIZE]) -> String {
    let mut text = String::with_capacity(ENTRY_HEX_DIGITS);
    for byte in entry {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> NIBBLE_BITS)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & NIBBLE_MASK)]));
    }
    text
}

fn decode_entry(text: &str) -> Option<[u8; WITHDRAWAL_HINT_SIZE]> {
    let bytes = text.as_bytes();
    if bytes.len() != ENTRY_HEX_DIGITS {
        return None;
    }
    let mut entry = [0_u8; WITHDRAWAL_HINT_SIZE];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, [high, low]) in entry.iter_mut().zip(pairs) {
        let high = nibble(*high)?;
        let low = nibble(*low)?;
        *slot = (high << NIBBLE_BITS) | low;
    }
    Some(entry)
}

fn nibble(digit: u8) -> Option<u8> {
    HEX_DIGITS
        .iter()
        .position(|candidate| *candidate == digit)
        .and_then(|position| u8::try_from(position).ok())
}

#[cfg(test)]
mod tests {
    use super::{
        InstanceName, MAX_INSTANCE_NAME_SIZE, WITHDRAWAL_COUNTER_SECONDS, WITHDRAWAL_HINT_SIZE,
        WITHDRAWN_RECORD_ENTRIES, WithdrawalError, WithdrawalKey, WithdrawnRecord,
        WithdrawnRecordError, withdrawal_counter,
    };
    use crate::{PAIR_ID_SIZE, PairId, X25519_KEY_SIZE, noise::x25519_public_key};

    /// Synthetic static private keys and pair identifier bytes.
    const CUSTODIAN_PRIVATE_BYTE: u8 = 0x11;
    const REQUESTER_PRIVATE_BYTE: u8 = 0x22;
    const PAIR_ID_BYTE: u8 = 0x33;
    const FILLER_BYTE: u8 = 0x44;
    const INSTANCE: &str = "refineid-7f2a1c84";
    const OTHER_INSTANCE: &str = "refineid-b3d90e15";
    const COUNTER: u64 = 29_858_400;

    fn keys() -> (WithdrawalKey, WithdrawalKey) {
        let custodian = [CUSTODIAN_PRIVATE_BYTE; X25519_KEY_SIZE];
        let requester = [REQUESTER_PRIVATE_BYTE; X25519_KEY_SIZE];
        let pair_id = PairId::reconstruct(&[PAIR_ID_BYTE; PAIR_ID_SIZE]).expect("pair id");
        (
            WithdrawalKey::from_parts(pair_id, &custodian, &x25519_public_key(&requester))
                .expect("custodian key"),
            WithdrawalKey::from_parts(pair_id, &requester, &x25519_public_key(&custodian))
                .expect("requester key"),
        )
    }

    fn instance(name: &str) -> InstanceName {
        InstanceName::new(name).expect("instance")
    }

    fn record_with(hint: [u8; WITHDRAWAL_HINT_SIZE]) -> WithdrawnRecord {
        WithdrawnRecord::assemble(&[hint], |bytes| {
            bytes.fill(FILLER_BYTE);
            Ok(())
        })
        .expect("record")
    }

    #[test]
    fn both_endpoints_derive_one_key() {
        let (custodian, requester) = keys();
        let name = instance(INSTANCE);
        assert_eq!(
            custodian.hint(&name, COUNTER),
            requester.hint(&name, COUNTER)
        );
    }

    #[test]
    fn a_hint_matches_its_counter_and_both_neighbours_only() {
        let (custodian, requester) = keys();
        let name = instance(INSTANCE);
        let record = record_with(custodian.hint(&name, COUNTER));
        for counter in [COUNTER - 1, COUNTER, COUNTER + 1] {
            assert!(requester.matches(&record, &name, counter));
        }
        assert!(!requester.matches(&record, &name, COUNTER + 2));
        assert!(!requester.matches(&record, &name, COUNTER - 2));
    }

    #[test]
    fn a_hint_is_bound_to_its_instance() {
        let (custodian, requester) = keys();
        let record = record_with(custodian.hint(&instance(INSTANCE), COUNTER));
        assert!(!requester.matches(&record, &instance(OTHER_INSTANCE), COUNTER));
    }

    #[test]
    fn a_record_round_trips_through_txt() {
        let (custodian, requester) = keys();
        let name = instance(INSTANCE);
        let record = record_with(custodian.hint(&name, COUNTER));
        let entries = record.txt_entries();
        let pairs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let parsed = WithdrawnRecord::parse(&pairs).expect("parse");
        assert_eq!(parsed, record);
        assert!(requester.matches(&parsed, &name, COUNTER));
    }

    #[test]
    fn malformed_records_are_refused() {
        let entry = "0123456789abcdef";
        let eight = [entry; WITHDRAWN_RECORD_ENTRIES].join(",");
        let seven = [entry; WITHDRAWN_RECORD_ENTRIES - 1].join(",");
        let nine = [entry; WITHDRAWN_RECORD_ENTRIES + 1].join(",");
        let upper = eight.to_uppercase();
        let header = [("v", "1"), ("mode", "withdrawn")];
        let with = |list: &str| {
            let mut pairs = header.to_vec();
            pairs.push(("withdrawn", list));
            WithdrawnRecord::parse(&pairs)
        };
        assert!(with(&eight).is_ok());
        assert_eq!(with(&seven), Err(WithdrawnRecordError::MalformedEntries));
        assert_eq!(with(&nine), Err(WithdrawnRecordError::MalformedEntries));
        assert_eq!(with(&upper), Err(WithdrawnRecordError::MalformedEntries));
        assert_eq!(with(""), Err(WithdrawnRecordError::MalformedEntries));
        let mut hinted = header.to_vec();
        hinted.push(("withdrawn", &eight));
        hinted.push(("hints", entry));
        assert_eq!(
            WithdrawnRecord::parse(&hinted),
            Err(WithdrawnRecordError::UnexpectedKey)
        );
        assert_eq!(
            WithdrawnRecord::parse(&[("v", "1"), ("mode", "session"), ("withdrawn", &eight)]),
            Err(WithdrawnRecordError::WrongHeader)
        );
    }

    #[test]
    fn more_than_eight_hints_are_refused() {
        let hints = [[0_u8; WITHDRAWAL_HINT_SIZE]; WITHDRAWN_RECORD_ENTRIES + 1];
        assert_eq!(
            WithdrawnRecord::assemble(&hints, |_| Ok(())),
            Err(WithdrawalError::TooManyHints)
        );
    }

    #[test]
    fn instance_names_are_one_label() {
        assert_eq!(
            InstanceName::new(""),
            Err(WithdrawalError::InvalidInstanceName)
        );
        assert!(InstanceName::new(&"a".repeat(MAX_INSTANCE_NAME_SIZE)).is_ok());
        assert_eq!(
            InstanceName::new(&"a".repeat(MAX_INSTANCE_NAME_SIZE + 1)),
            Err(WithdrawalError::InvalidInstanceName)
        );
    }

    #[test]
    fn the_counter_steps_each_minute() {
        assert_eq!(withdrawal_counter(WITHDRAWAL_COUNTER_SECONDS - 1), 0);
        assert_eq!(withdrawal_counter(WITHDRAWAL_COUNTER_SECONDS), 1);
    }
}
