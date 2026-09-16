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

//! Scripted-transport tests for the PKCS#15 read flows.

use refineid_apdu::iso7816::{
    DirectOffset15, ReadBinary, ReadBinaryOffset, SelectByAidNoFci, SelectEfNoFci, SelectFile,
    SelectFileResponseMode, SelectFileTarget,
};
use refineid_apdu::{
    Aid, ApduClass, CardTransport, CommandApdu, CredentialCommand, FileId, ResponseApdu,
    StatusWord, TransportOutcome,
};
use refineid_ber::{BerTag, Sequence, tlv};
use refineid_pkcs15::{
    CertSlot, DF_ESIGN_FID, EF_TOKEN_INFO_FID, ESIGN_AID, PKCS15_AID, Pkcs15Error, Pkcs15Ops,
};

/// Chunk size the read loops request, mirroring the implementation; a
/// change there must fail these scripts loudly.
const READ_CHUNK_LEN: u8 = 0xDF;
/// Certificate content length that forces a two-chunk read.
const TWO_CHUNK_CONTENT_LEN: usize = 300;
/// Surplus bytes past the requested chunk a T=0 61xx chain may
/// deliver when the pending count exceeds the requested length.
const OVERLONG_EXTRA_BYTES: usize = 18;
/// Content length that fits one chunk.
const ONE_CHUNK_CONTENT_LEN: usize = 60;
/// Declared content length above the sixteen-kibibyte object cap.
const OVERSIZED_CONTENT_LEN: usize = 0x4000;
/// Filler byte for certificate bodies.
const FILLER: u8 = 0x5A;
/// P1 selecting a child DF, mirroring the implementation's fallback
/// variant per FINEID S1 v4.2 section 3.2.2.
const P1_SELECT_CHILD_DF: u8 = 0x01;
/// P1 selecting by name, mirroring the implementation's MF fallback.
const P1_SELECT_BY_NAME: u8 = 0x04;
/// BER long-form marker declaring two length octets.
const TWO_OCTET_LONG_FORM: u8 = 0x82;
/// Wire length of a status-word pair.
const SW_LEN: usize = 2;

fn success() -> [u8; SW_LEN] {
    StatusWord::Success.as_u16().to_be_bytes()
}

fn response(body: &[u8], sw: StatusWord) -> ResponseApdu {
    let [sw1, sw2] = sw.as_u16().to_be_bytes();
    ResponseApdu {
        body: body.to_vec(),
        sw1,
        sw2,
    }
}

fn ok_response(body: &[u8]) -> ResponseApdu {
    let [sw1, sw2] = success();
    ResponseApdu {
        body: body.to_vec(),
        sw1,
        sw2,
    }
}

struct ScriptedTransport {
    script: Vec<(Vec<u8>, ResponseApdu)>,
    cursor: usize,
}

impl ScriptedTransport {
    fn new(script: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
        Self { script, cursor: 0 }
    }

    fn assert_drained(&self) {
        assert_eq!(
            self.cursor,
            self.script.len(),
            "the flow must consume the whole script"
        );
    }
}

impl CardTransport for ScriptedTransport {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let (expected, scripted) = self
            .script
            .get(self.cursor)
            .ok_or_else(|| format!("script exhausted at step {}", self.cursor))?;
        assert_eq!(
            expected,
            command.as_bytes(),
            "unexpected command at step {}",
            self.cursor
        );
        self.cursor += 1;
        Ok(TransportOutcome::Response(scripted.clone()))
    }

    fn transmit_credential(
        &mut self,
        _command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        Err("the PKCS#15 read flows never issue a credential command".to_owned())
    }
}

fn pkcs15_aid() -> Aid {
    Aid::from_slice(PKCS15_AID).expect("published AID length is valid")
}

fn esign_aid() -> Aid {
    Aid::from_slice(ESIGN_AID).expect("published E.SIGN AID length is valid")
}

fn select_app_wire() -> Vec<u8> {
    SelectByAidNoFci { aid: pkcs15_aid() }
        .into_apdu()
        .as_bytes()
        .to_vec()
}

fn select_esign_wire() -> Vec<u8> {
    SelectByAidNoFci { aid: esign_aid() }
        .into_apdu()
        .as_bytes()
        .to_vec()
}

fn select_ef_wire(fid: FileId) -> Vec<u8> {
    SelectEfNoFci { fid }.into_apdu().as_bytes().to_vec()
}

fn select_any_by_fid_wire(fid: FileId) -> Vec<u8> {
    SelectFile {
        class: ApduClass::Plain,
        target: SelectFileTarget::AnyByFileId(Some(fid)),
        response_mode: SelectFileResponseMode::None,
    }
    .into_apdu()
    .as_bytes()
    .to_vec()
}

fn select_child_df_wire(fid: FileId) -> Vec<u8> {
    CommandApdu::case_3(
        refineid_apdu::CommandHeader {
            class: ApduClass::Plain,
            instruction: SelectFile::INS,
            p1: P1_SELECT_CHILD_DF,
            p2: SelectFileResponseMode::None.as_p2(),
        },
        fid.as_bytes(),
    )
    .expect("file identifiers fit a data field")
    .as_bytes()
    .to_vec()
}

fn read_wire(offset: usize, le: u8) -> Vec<u8> {
    let offset_wire = u16::try_from(offset).expect("test offsets fit the direct form");
    ReadBinary {
        class: ApduClass::Plain,
        offset: ReadBinaryOffset::Direct(
            DirectOffset15::try_new(offset_wire).expect("test offsets fit the direct form"),
        ),
        le,
    }
    .into_apdu()
    .as_bytes()
    .to_vec()
}

fn sequence_tag() -> u8 {
    u8::try_from(<Sequence as BerTag>::TAG).expect("universal tags fit one byte")
}

fn certificate_fixture(content_len: usize) -> Vec<u8> {
    tlv(sequence_tag(), vec![FILLER; content_len]).expect("fixture encodes")
}

#[test]
fn authentication_certificate_reads_across_chunks() {
    let der = certificate_fixture(TWO_CHUNK_CONTENT_LEN);
    let total = der.len();
    let first_chunk = &der[..usize::from(READ_CHUNK_LEN)];
    let second_chunk = &der[usize::from(READ_CHUNK_LEN)..];
    let second_len = u8::try_from(second_chunk.len()).expect("remainder fits one read");
    assert!(
        total > usize::from(READ_CHUNK_LEN),
        "fixture must span two chunks"
    );

    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (
            select_ef_wire(CertSlot::Authentication.fid()),
            ok_response(&[]),
        ),
        (read_wire(0, READ_CHUNK_LEN), ok_response(first_chunk)),
        (
            read_wire(usize::from(READ_CHUNK_LEN), second_len),
            ok_response(second_chunk),
        ),
    ]);

    let cert = transport
        .read_certificate(CertSlot::Authentication)
        .expect("scripted read succeeds");
    assert_eq!(cert.as_bytes(), der.as_slice());
    transport.assert_drained();
}

#[test]
fn signature_certificate_prefers_the_named_esign_directory() {
    let der = certificate_fixture(ONE_CHUNK_CONTENT_LEN);

    let mut transport = ScriptedTransport::new(vec![
        (select_any_by_fid_wire(FileId::MF), ok_response(&[])),
        (select_esign_wire(), ok_response(&[])),
        (select_ef_wire(CertSlot::Signature.fid()), ok_response(&[])),
        (read_wire(0, READ_CHUNK_LEN), ok_response(&der)),
    ]);

    let cert = transport
        .read_certificate(CertSlot::Signature)
        .expect("scripted read succeeds");
    assert_eq!(cert.as_bytes(), der.as_slice());
    assert!(CertSlot::Signature.requires_mf_traversal());
    assert!(!CertSlot::Authentication.requires_mf_traversal());
    transport.assert_drained();
}

#[test]
fn signature_certificate_falls_back_to_the_esign_file_identifier() {
    let der = certificate_fixture(ONE_CHUNK_CONTENT_LEN);

    let mut transport = ScriptedTransport::new(vec![
        (select_any_by_fid_wire(FileId::MF), ok_response(&[])),
        (select_esign_wire(), response(&[], StatusWord::FileNotFound)),
        (select_child_df_wire(DF_ESIGN_FID), ok_response(&[])),
        (select_ef_wire(CertSlot::Signature.fid()), ok_response(&[])),
        (read_wire(0, READ_CHUNK_LEN), ok_response(&der)),
    ]);

    let cert = transport
        .read_certificate(CertSlot::Signature)
        .expect("scripted read succeeds");
    assert_eq!(cert.as_bytes(), der.as_slice());
    assert!(CertSlot::Signature.requires_mf_traversal());
    assert!(!CertSlot::Authentication.requires_mf_traversal());
    transport.assert_drained();
}

#[test]
fn esign_file_identifier_falls_back_from_child_to_any_file() {
    let mut transport = ScriptedTransport::new(vec![
        (select_any_by_fid_wire(FileId::MF), ok_response(&[])),
        (select_esign_wire(), response(&[], StatusWord::FileNotFound)),
        (
            select_child_df_wire(DF_ESIGN_FID),
            response(&[], StatusWord::FileNotFound),
        ),
        (select_any_by_fid_wire(DF_ESIGN_FID), ok_response(&[])),
    ]);

    transport
        .select_esign_directory()
        .expect("the any-file fallback succeeds");
    transport.assert_drained();
}

#[test]
fn absent_slot_surfaces_file_not_found() {
    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (
            select_ef_wire(CertSlot::Authentication.fid()),
            response(&[], StatusWord::FileNotFound),
        ),
        (
            select_any_by_fid_wire(CertSlot::Authentication.fid()),
            response(&[], StatusWord::FileNotFound),
        ),
    ]);

    let error = transport
        .read_certificate(CertSlot::Authentication)
        .expect_err("absent slot must not read");
    assert!(matches!(
        error,
        Pkcs15Error::Status(StatusWord::FileNotFound)
    ));
    transport.assert_drained();
}

#[test]
fn select_mf_falls_back_to_the_by_name_variant() {
    let by_name_wire = CommandApdu::case_3(
        refineid_apdu::CommandHeader {
            class: ApduClass::Plain,
            instruction: SelectFile::INS,
            p1: P1_SELECT_BY_NAME,
            p2: SelectFileResponseMode::None.as_p2(),
        },
        FileId::MF.as_bytes(),
    )
    .expect("file identifiers fit a data field")
    .as_bytes()
    .to_vec();

    let mut transport = ScriptedTransport::new(vec![
        (
            select_any_by_fid_wire(FileId::MF),
            response(&[], StatusWord::FileNotFound),
        ),
        (by_name_wire, ok_response(&[])),
    ]);

    transport.select_mf().expect("fallback variant succeeds");
    transport.assert_drained();
}

#[test]
fn token_info_reads_and_parses() {
    let mut inner = refineid_ber::BerEncoder::default();
    inner
        .push_tlv(
            u8::try_from(<refineid_ber::Integer as BerTag>::TAG).expect("fits"),
            [1_u8],
        )
        .expect("fixture encodes");
    inner
        .push_tlv(
            u8::try_from(<refineid_ber::OctetString as BerTag>::TAG).expect("fits"),
            b"DEMO0001AB1234567".as_slice(),
        )
        .expect("fixture encodes");
    let der = tlv(sequence_tag(), inner.finish()).expect("fixture encodes");

    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (select_ef_wire(EF_TOKEN_INFO_FID), ok_response(&[])),
        (read_wire(0, READ_CHUNK_LEN), ok_response(&der)),
    ]);

    let info = transport.read_token_info().expect("scripted read succeeds");
    assert_eq!(info.version(), 1);
    let serial = refineid_pkcs15::render_token_serial(
        info.serial_number_hex()
            .cloned()
            .expect("fixture carries a serial"),
    );
    assert_eq!(serial, "DEMO0001AB1234567");
    transport.assert_drained();
}

#[test]
fn oversized_declared_object_is_rejected() {
    let mut oversized_header = tlv(sequence_tag(), vec![]).expect("fixture encodes");
    // Rewrite the empty object's length field into a two-octet long
    // form declaring a content length above the cap.
    oversized_header.truncate(1);
    oversized_header.push(TWO_OCTET_LONG_FORM);
    let declared = u16::try_from(OVERSIZED_CONTENT_LEN).expect("declared length fits two octets");
    oversized_header.extend_from_slice(&declared.to_be_bytes());
    oversized_header.resize(usize::from(READ_CHUNK_LEN), FILLER);

    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (
            select_ef_wire(CertSlot::Authentication.fid()),
            ok_response(&[]),
        ),
        (read_wire(0, READ_CHUNK_LEN), ok_response(&oversized_header)),
    ]);

    let error = transport
        .read_certificate(CertSlot::Authentication)
        .expect_err("oversized object must not read");
    assert!(matches!(error, Pkcs15Error::TooLarge));
    transport.assert_drained();
}

#[test]
fn empty_first_read_is_reported_as_empty() {
    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (
            select_ef_wire(CertSlot::Authentication.fid()),
            ok_response(&[]),
        ),
        (read_wire(0, READ_CHUNK_LEN), ok_response(&[])),
    ]);

    let error = transport
        .read_certificate(CertSlot::Authentication)
        .expect_err("an empty file must not read");
    assert!(matches!(error, Pkcs15Error::Empty));
    transport.assert_drained();
}

#[test]
fn overlong_first_chunk_is_accepted_and_advanced_past() {
    let der = certificate_fixture(TWO_CHUNK_CONTENT_LEN);
    let first_len = usize::from(READ_CHUNK_LEN) + OVERLONG_EXTRA_BYTES;
    let first_chunk = &der[..first_len];
    let second_chunk = &der[first_len..];
    let second_len = u8::try_from(second_chunk.len()).expect("remainder fits one read");
    assert!(
        first_len < der.len(),
        "fixture must still span two reads past the surplus"
    );

    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (
            select_ef_wire(CertSlot::Authentication.fid()),
            ok_response(&[]),
        ),
        (read_wire(0, READ_CHUNK_LEN), ok_response(first_chunk)),
        (read_wire(first_len, second_len), ok_response(second_chunk)),
    ]);

    let cert = transport
        .read_certificate(CertSlot::Authentication)
        .expect("a 61xx surplus must read");
    assert_eq!(cert.as_bytes(), der.as_slice());
    transport.assert_drained();
}
