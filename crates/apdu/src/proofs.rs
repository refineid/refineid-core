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

//! Kani proof harnesses for the APDU borders.
//!
//! The status word is proved for all sixteen-bit values; the command
//! builders are proved for every header and Le, with every data field up
//! to the named bound and offset-patterned fields at the short-form and
//! chaining edge lengths, each either refusing with the typed error its length
//! calls for or emitting wire that decodes, field by field, to its
//! inputs. The credential-command path is left to the fuzz target:
//! its zeroize-on-drop storage erases through an inline-assembly
//! barrier the model checker does not interpret.

use crate::command::{LC_LEN, LE_LEN};
use crate::{
    APDU_HEADER_LEN, Aid, ApduClass, CommandApdu, CommandDataError, CommandHeader,
    SHORT_APDU_DATA_MAX, Sfi, StatusWord,
};

/// Longest data field whose contents the layout harnesses keep symbolic:
/// the empty field, a one-octet field, and fields long enough to hold
/// header- and Lc-shaped octets.
const MAX_SYMBOLIC_DATA_LEN: usize = 3;

/// The data-field lengths at the edges of the short form: empty, one
/// octet, the full short-form capacity and one octet past it.
const SHORT_FORM_EDGE_LENGTHS: &[usize] = &[0, 1, SHORT_APDU_DATA_MAX, SHORT_APDU_DATA_MAX + 1];

/// The data-field lengths at the edges of command chaining: one command,
/// the largest single command, the shortest two-command chain, the
/// largest two-command chain and the shortest three-command chain.
const CHAIN_EDGE_LENGTHS: &[usize] = &[
    1,
    SHORT_APDU_DATA_MAX,
    SHORT_APDU_DATA_MAX + 1,
    SHORT_APDU_DATA_MAX + SHORT_APDU_DATA_MAX,
    SHORT_APDU_DATA_MAX + SHORT_APDU_DATA_MAX + 1,
];

/// Storage for the longest data field the chaining harness splits.
const MAX_CHAIN_DATA_LEN: usize = SHORT_APDU_DATA_MAX + SHORT_APDU_DATA_MAX + 1;

/// A data field whose every octet is its own offset, wrapping at the
/// octet width, so a chunk taken from the wrong offset differs from the
/// one expected.
const CHAIN_DATA: [u8; MAX_CHAIN_DATA_LEN] = offset_pattern();

const fn offset_pattern() -> [u8; MAX_CHAIN_DATA_LEN] {
    let mut pattern = [0_u8; MAX_CHAIN_DATA_LEN];
    let mut offset = 0;
    while offset < MAX_CHAIN_DATA_LEN {
        pattern[offset] = offset.to_le_bytes()[0];
        offset += 1;
    }
    pattern
}

/// Longest AID the length harness explores: one octet past the ISO 7816-5
/// maximum.
const MAX_AID_PROBE_LEN: usize = Aid::MAX_LENGTH + 1;

fn any_class() -> ApduClass {
    if kani::any() {
        ApduClass::Plain
    } else if kani::any() {
        ApduClass::SecureMessaging
    } else {
        ApduClass::ChainedFirst
    }
}

fn any_header() -> CommandHeader {
    CommandHeader {
        class: any_class(),
        instruction: kani::any(),
        p1: kani::any(),
        p2: kani::any(),
    }
}

/// Every prefix of `storage`, shortest first: each of concrete length
/// and symbolic contents.
fn prefixes<const N: usize>(storage: &[u8; N]) -> impl Iterator<Item = &[u8]> {
    (0..=N).map(|len| &storage[..len])
}

/// Whether `wire` is `header`, an Lc byte equal to `data`'s length,
/// `data`, and `le` when given.
fn is_short_wire(wire: &[u8], header: CommandHeader, data: &[u8], le: Option<u8>) -> bool {
    let le_len = if le.is_some() { LE_LEN } else { 0 };
    let lc_len = if data.is_empty() { 0 } else { LC_LEN };
    if wire.len() != APDU_HEADER_LEN + lc_len + data.len() + le_len {
        return false;
    }
    let (wire_header, rest) = wire.split_at(APDU_HEADER_LEN);
    if wire_header != header.to_bytes() {
        return false;
    }
    let (wire_lc, rest) = rest.split_at(lc_len);
    if wire_lc
        .first()
        .is_some_and(|&lc| usize::from(lc) != data.len())
    {
        return false;
    }
    let (wire_data, wire_le) = rest.split_at(data.len());
    wire_data == data && wire_le.first().copied() == le
}

#[kani::proof]
fn status_word_round_trips() {
    let sw1: u8 = kani::any();
    let sw2: u8 = kani::any();
    let raw = u16::from_be_bytes([sw1, sw2]);
    let status = StatusWord::from_bytes(sw1, sw2);
    assert!(status.as_u16() == raw);
    assert!(StatusWord::from_u16(raw) == status);
    assert!(status.is_success() == (status == StatusWord::Success));
}

#[kani::proof]
fn case_1_and_case_2_layout() {
    let header = any_header();
    let le: u8 = kani::any();
    assert!(is_short_wire(
        CommandApdu::case_1(header).as_bytes(),
        header,
        &[],
        None
    ));
    assert!(is_short_wire(
        CommandApdu::case_2(header, le).as_bytes(),
        header,
        &[],
        Some(le)
    ));
}

#[kani::proof]
fn case_3_and_case_4_layout() {
    let header = any_header();
    let le: u8 = kani::any();
    let storage: [u8; MAX_SYMBOLIC_DATA_LEN] = kani::any();
    for data in prefixes(&storage) {
        match CommandApdu::case_3(header, data) {
            Ok(command) => assert!(is_short_wire(command.as_bytes(), header, data, None)),
            Err(error) => assert!(data.is_empty() && error == CommandDataError::Empty),
        }
        match CommandApdu::case_4(header, data, le) {
            Ok(command) => assert!(is_short_wire(command.as_bytes(), header, data, Some(le))),
            Err(error) => assert!(data.is_empty() && error == CommandDataError::Empty),
        }
    }
}

#[kani::proof]
fn short_form_length_bound() {
    let header = any_header();
    let le: u8 = kani::any();
    for &len in SHORT_FORM_EDGE_LENGTHS {
        check_short_form_length(header, &CHAIN_DATA[..len], le);
    }
}

/// `case_3` and `case_4` accept `data` exactly when it fits the short
/// form, and refuse it with the error its length calls for otherwise.
fn check_short_form_length(header: CommandHeader, data: &[u8], le: u8) {
    let fits = !data.is_empty() && data.len() <= SHORT_APDU_DATA_MAX;
    let refusal = if data.is_empty() {
        CommandDataError::Empty
    } else {
        CommandDataError::TooLong { got: data.len() }
    };
    match CommandApdu::case_3(header, data) {
        Ok(command) => {
            assert!(fits);
            assert!(command.as_bytes().len() == APDU_HEADER_LEN + LC_LEN + data.len());
        }
        Err(error) => assert!(!fits && error == refusal),
    }
    match CommandApdu::case_4(header, data, le) {
        Ok(command) => {
            assert!(fits);
            let wire = command.as_bytes();
            assert!(wire.len() == APDU_HEADER_LEN + LC_LEN + data.len() + LE_LEN);
            assert!(wire.last() == Some(&le));
        }
        Err(error) => assert!(!fits && error == refusal),
    }
}

#[kani::proof]
fn command_chain_splits_at_the_short_form() {
    let header = any_header();
    let le: u8 = kani::any();
    for &len in CHAIN_EDGE_LENGTHS {
        check_chain(header, &CHAIN_DATA[..len], le);
    }
}

/// `command_chain` splits `data` into short-form commands under the
/// chaining class, the last carrying `header`'s class and `le`.
fn check_chain(header: CommandHeader, data: &[u8], le: u8) {
    let Ok(commands) = CommandApdu::command_chain(header, data, le) else {
        assert!(data.is_empty());
        return;
    };
    assert!(!data.is_empty());
    assert!(commands.len() == data.len().div_ceil(SHORT_APDU_DATA_MAX));
    let chained_header = CommandHeader {
        class: ApduClass::ChainedFirst,
        ..header
    };
    let mut carried = 0;
    for (index, command) in commands.iter().enumerate() {
        let is_last = index + 1 == commands.len();
        let chunk_len = (data.len() - carried).min(SHORT_APDU_DATA_MAX);
        let (expected_header, le_len) = if is_last {
            (header, LE_LEN)
        } else {
            (chained_header, 0)
        };
        let wire = command.as_bytes();
        assert!(wire.len() == APDU_HEADER_LEN + LC_LEN + chunk_len + le_len);
        assert!(wire[..APDU_HEADER_LEN] == expected_header.to_bytes());
        assert!(usize::from(wire[APDU_HEADER_LEN]) == chunk_len);
        let body_start = APDU_HEADER_LEN + LC_LEN;
        assert!(wire[body_start..body_start + chunk_len] == data[carried..carried + chunk_len]);
        assert!(!is_last || wire.last() == Some(&le));
        assert!(is_last || chunk_len == SHORT_APDU_DATA_MAX);
        carried += chunk_len;
    }
    assert!(carried == data.len());
}

#[kani::proof]
fn aid_length_bound() {
    let storage: [u8; MAX_AID_PROBE_LEN] = kani::any();
    for bytes in prefixes(&storage) {
        let in_range = bytes.len() >= Aid::MIN_LENGTH && bytes.len() <= Aid::MAX_LENGTH;
        match Aid::from_slice(bytes) {
            Ok(aid) => assert!(in_range && aid.as_bytes() == bytes),
            Err(_) => assert!(!in_range),
        }
    }
}

#[kani::proof]
fn sfi_range() {
    let value: u8 = kani::any();
    match Sfi::new(value) {
        Ok(sfi) => {
            assert!(value >= 1 && value <= Sfi::MAX);
            assert!(sfi.value() == value);
        }
        Err(_) => assert!(value == 0 || value > Sfi::MAX),
    }
}
