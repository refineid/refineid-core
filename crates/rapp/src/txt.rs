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

//! DNS-SD TXT conventions shared by the discovery and withdrawn records
//! (hierarchy specification §4.3).
//!
//! Keys compare case-insensitively (RFC 6763 §6.4); values compare exactly,
//! and hint lists are lowercase hexadecimal only.

/// Byte length of one published hint, discovery or withdrawal.
pub const HINT_SIZE: usize = 8;

/// TXT key naming the record version.
pub const VERSION_KEY: &str = "v";

/// The only record version.
pub const VERSION: &str = "1";

/// TXT key naming the discovery mode.
pub const MODE_KEY: &str = "mode";

/// Separator between hint-list entries.
pub const ENTRY_SEPARATOR: char = ',';

/// Hexadecimal digits per encoded entry.
const ENTRY_HEX_DIGITS: usize = HINT_SIZE * 2;

/// Lowercase hexadecimal alphabet of the encoded entries.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Bits per hexadecimal digit.
const NIBBLE_BITS: u32 = 4;

/// Low-nibble mask.
const NIBBLE_MASK: u8 = 0x0f;

/// One hint a custodian could announce, with the time that ranks it: the
/// pairing's most recent established session, or its creation when it has
/// had none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnnouncementCandidate {
    /// The pairing's hint for the record being published.
    pub hint: [u8; HINT_SIZE],
    /// Milliseconds since the Unix epoch of the pairing's last use.
    pub last_used_ms: u64,
}

/// The hints of the `limit` most recently used candidates, most recent
/// first; equal times order by the hint's bytes.
#[must_use]
pub fn most_recently_used(
    candidates: &[AnnouncementCandidate],
    limit: usize,
) -> Vec<[u8; HINT_SIZE]> {
    let mut ranked = candidates.to_vec();
    ranked.sort_unstable_by(|left, right| {
        right
            .last_used_ms
            .cmp(&left.last_used_ms)
            .then_with(|| left.hint.cmp(&right.hint))
    });
    ranked
        .into_iter()
        .take(limit)
        .map(|candidate| candidate.hint)
        .collect()
}

/// Collects the values of `keys` from `entries`, matching keys
/// case-insensitively. `None` when a key is repeated or not among `keys`.
pub fn values<'a, const N: usize>(
    entries: &[(&str, &'a str)],
    keys: [&str; N],
) -> Option<[Option<&'a str>; N]> {
    let mut values = [None; N];
    for &(key, value) in entries {
        let slot = keys
            .iter()
            .position(|known| known.eq_ignore_ascii_case(key))
            .and_then(|index| values.get_mut(index))?;
        if slot.replace(value).is_some() {
            return None;
        }
    }
    Some(values)
}

/// One hint as 16 lowercase hexadecimal digits.
#[must_use]
pub fn encode_entry(entry: &[u8; HINT_SIZE]) -> String {
    let mut text = String::with_capacity(ENTRY_HEX_DIGITS);
    for byte in entry {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> NIBBLE_BITS)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & NIBBLE_MASK)]));
    }
    text
}

/// A hint list joined by the entry separator.
#[must_use]
pub fn encode_list(entries: &[[u8; HINT_SIZE]]) -> String {
    entries
        .iter()
        .map(encode_entry)
        .collect::<Vec<_>>()
        .join(&ENTRY_SEPARATOR.to_string())
}

/// Parses 16 lowercase hexadecimal digits; anything else is `None`.
#[must_use]
pub fn decode_entry(text: &str) -> Option<[u8; HINT_SIZE]> {
    let bytes = text.as_bytes();
    if bytes.len() != ENTRY_HEX_DIGITS {
        return None;
    }
    let mut entry = [0_u8; HINT_SIZE];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, [high, low]) in entry.iter_mut().zip(pairs) {
        let high = nibble(*high)?;
        let low = nibble(*low)?;
        *slot = (high << NIBBLE_BITS) | low;
    }
    Some(entry)
}

/// Parses a hint list of 1 to `maximum` entries.
#[must_use]
pub fn decode_list(list: &str, maximum: usize) -> Option<Vec<[u8; HINT_SIZE]>> {
    let entries = list
        .split(ENTRY_SEPARATOR)
        .map(decode_entry)
        .collect::<Option<Vec<_>>>()?;
    (entries.len() <= maximum).then_some(entries)
}

fn nibble(digit: u8) -> Option<u8> {
    HEX_DIGITS
        .iter()
        .position(|candidate| *candidate == digit)
        .and_then(|position| u8::try_from(position).ok())
}

#[cfg(test)]
mod tests {
    use super::{AnnouncementCandidate, HINT_SIZE, decode_list, most_recently_used, values};

    const OLDER_MS: u64 = 1;
    const NEWER_MS: u64 = 2;
    const LOW_HINT: u8 = 0x01;
    const HIGH_HINT: u8 = 0x02;
    const NEWEST_HINT: u8 = 0x03;
    const LIMIT: usize = 2;
    const ENTRY: &str = "0123456789abcdef";

    #[test]
    fn the_most_recently_used_are_announced_with_ties_by_hint() {
        let candidate = |byte, last_used_ms| AnnouncementCandidate {
            hint: [byte; HINT_SIZE],
            last_used_ms,
        };
        let chosen = most_recently_used(
            &[
                candidate(HIGH_HINT, OLDER_MS),
                candidate(NEWEST_HINT, NEWER_MS),
                candidate(LOW_HINT, OLDER_MS),
            ],
            LIMIT,
        );
        assert_eq!(chosen, [[NEWEST_HINT; HINT_SIZE], [LOW_HINT; HINT_SIZE]]);
    }

    #[test]
    fn keys_match_without_regard_to_case_but_only_once() {
        assert_eq!(
            values(&[("V", "1"), ("Mode", "session")], ["v", "mode"]),
            Some([Some("1"), Some("session")])
        );
        assert_eq!(values(&[("v", "1"), ("V", "1")], ["v"]), None);
        assert_eq!(values(&[("x", "1")], ["v"]), None);
    }

    #[test]
    fn hint_lists_take_lowercase_entries_only() {
        assert!(decode_list(ENTRY, LIMIT).is_some());
        assert!(decode_list(&ENTRY.to_uppercase(), LIMIT).is_none());
        assert!(decode_list("", LIMIT).is_none());
        assert!(decode_list(&[ENTRY; LIMIT + 1].join(","), LIMIT).is_none());
    }
}
