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

//! APDU borders: the status word decoded from arbitrary SW1-SW2 bytes
//! re-encodes to them, and every command builder fed an arbitrary header,
//! data field and Le either refuses with a typed error or emits wire that
//! decodes back, field by field, to its inputs.

#![no_main]

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use refineid_apdu::{
    APDU_HEADER_LEN, Aid, ApduClass, CREDENTIAL_BODY_MAX, CommandApdu, CommandDataError,
    CommandHeader, CredentialBody, CredentialBodyError, CredentialCommand, ResponseApdu,
    SHORT_APDU_DATA_MAX, Sfi, StatusWord, UnvalidatedCredentialBlock,
};

/// Every command class a header can carry.
const CLASSES: &[ApduClass] = &[
    ApduClass::Plain,
    ApduClass::SecureMessaging,
    ApduClass::ChainedFirst,
];

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let _ = run(Unstructured::new(bytes));
});

fn run(mut input: Unstructured<'_>) -> Result<()> {
    let sw1: u8 = input.arbitrary()?;
    let sw2: u8 = input.arbitrary()?;
    check_status_word(sw1, sw2);

    let header = CommandHeader {
        class: *input.choose(CLASSES)?,
        instruction: input.arbitrary()?,
        p1: input.arbitrary()?,
        p2: input.arbitrary()?,
    };
    let le: u8 = input.arbitrary()?;
    let declared: usize = input.arbitrary()?;
    let data = input.take_rest();

    check_short_cases(header, data, le);
    check_command_chain(header, data, le);
    check_credential_command(header, data, declared);
    check_aid(data);
    check_sfi(sw1);
    Ok(())
}

fn check_status_word(sw1: u8, sw2: u8) {
    let raw = u16::from_be_bytes([sw1, sw2]);
    let status = StatusWord::from_bytes(sw1, sw2);
    assert_eq!(status.as_u16(), raw);
    assert_eq!(StatusWord::from_u16(raw), status);
    assert_eq!(status.is_success(), status == StatusWord::Success);
    let response = ResponseApdu {
        body: Vec::new(),
        sw1,
        sw2,
    };
    assert_eq!(response.status_word(), status);
    assert_eq!(response.is_ok(), status.is_success());
    let _ = format!("{status} {response:?}");
}

/// Split a short-form wire command into its header, data field, and
/// trailing Le, checking the Lc byte against the data length.
fn decode_short(wire: &[u8], has_le: bool) -> ([u8; APDU_HEADER_LEN], &[u8], Option<u8>) {
    let (header, rest) = wire
        .split_first_chunk::<APDU_HEADER_LEN>()
        .expect("a command carries its header");
    let (body, le) = if has_le {
        let (le, body) = rest
            .split_last()
            .expect("a case-2 or case-4 command carries Le");
        (body, Some(*le))
    } else {
        (rest, None)
    };
    let data = match body.split_first() {
        Some((lc, data)) => {
            assert_eq!(usize::from(*lc), data.len());
            data
        }
        None => body,
    };
    (*header, data, le)
}

fn check_short_cases(header: CommandHeader, data: &[u8], le: u8) {
    assert_eq!(CommandApdu::case_1(header).as_bytes(), header.to_bytes());
    let case_2 = CommandApdu::case_2(header, le);
    assert_eq!(
        decode_short(case_2.as_bytes(), true),
        (header.to_bytes(), &[][..], Some(le))
    );

    let fits = !data.is_empty() && data.len() <= SHORT_APDU_DATA_MAX;
    match CommandApdu::case_3(header, data) {
        Ok(command) => {
            assert!(fits);
            assert_eq!(
                decode_short(command.as_bytes(), false),
                (header.to_bytes(), data, None)
            );
            assert!(command.corrected_wrong_le(le).is_none());
        }
        Err(error) => check_data_error(error, data),
    }
    match CommandApdu::case_4(header, data, le) {
        Ok(command) => {
            assert!(fits);
            assert_eq!(
                decode_short(command.as_bytes(), true),
                (header.to_bytes(), data, Some(le))
            );
        }
        Err(error) => check_data_error(error, data),
    }
}

fn check_data_error(error: CommandDataError, data: &[u8]) {
    match error {
        CommandDataError::Empty => assert!(data.is_empty()),
        CommandDataError::TooLong { got } => {
            assert_eq!(got, data.len());
            assert!(got > SHORT_APDU_DATA_MAX);
        }
    }
}

fn check_command_chain(header: CommandHeader, data: &[u8], le: u8) {
    let Ok(commands) = CommandApdu::command_chain(header, data, le) else {
        assert!(data.is_empty());
        return;
    };
    let (last, chained) = commands
        .split_last()
        .expect("a chain holds at least one command");
    let mut reassembled = Vec::new();
    let chained_header = CommandHeader {
        class: ApduClass::ChainedFirst,
        ..header
    };
    for command in chained {
        let (wire_header, chunk, _) = decode_short(command.as_bytes(), false);
        assert_eq!(wire_header, chained_header.to_bytes());
        assert_eq!(chunk.len(), SHORT_APDU_DATA_MAX);
        reassembled.extend_from_slice(chunk);
    }
    let (wire_header, chunk, last_le) = decode_short(last.as_bytes(), true);
    assert_eq!(wire_header, header.to_bytes());
    assert_eq!(last_le, Some(le));
    assert!(!chunk.is_empty() && chunk.len() <= SHORT_APDU_DATA_MAX);
    reassembled.extend_from_slice(chunk);
    assert_eq!(reassembled, data);
}

fn check_credential_command(header: CommandHeader, data: &[u8], declared: usize) {
    let filled = data.len().min(CREDENTIAL_BODY_MAX);
    let mut block = UnvalidatedCredentialBlock::zeroed();
    block.buffer()[..filled].copy_from_slice(&data[..filled]);
    block.set_filled(declared);
    let body = match CredentialBody::from_block(block) {
        Ok(body) => body,
        Err(error) => {
            let expected = if declared == 0 {
                CredentialBodyError::Empty
            } else {
                CredentialBodyError::TooLong
            };
            assert_eq!(error, expected);
            assert!(declared == 0 || declared > CREDENTIAL_BODY_MAX);
            return;
        }
    };
    assert_eq!(body.len(), declared);
    let mut expected = [0_u8; CREDENTIAL_BODY_MAX];
    expected[..filled].copy_from_slice(&data[..filled]);
    CredentialCommand::assemble(header, body).expose_wire(|wire| {
        assert_eq!(
            decode_short(wire, false),
            (header.to_bytes(), &expected[..declared], None)
        );
    });
}

fn check_aid(data: &[u8]) {
    match Aid::from_slice(data) {
        Ok(aid) => {
            assert_eq!(aid.as_bytes(), data);
            assert!((Aid::MIN_LENGTH..=Aid::MAX_LENGTH).contains(&aid.len()));
        }
        Err(_) => assert!(!(Aid::MIN_LENGTH..=Aid::MAX_LENGTH).contains(&data.len())),
    }
}

fn check_sfi(value: u8) {
    match Sfi::new(value) {
        Ok(sfi) => {
            assert_eq!(sfi.value(), value);
            assert!((1..=Sfi::MAX).contains(&value));
        }
        Err(_) => assert!(value == 0 || value > Sfi::MAX),
    }
}
