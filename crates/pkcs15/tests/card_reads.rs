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
    AbsolutePath, DirectOffset15, ReadBinary, ReadBinaryOffset, SelectByAidNoFci, SelectEfNoFci,
    SelectFile, SelectFileResponseMode, SelectFileTarget,
};
use refineid_apdu::{
    Aid, ApduClass, CardTransport, CommandApdu, CredentialCommand, FileId, ResponseApdu,
    StatusWord, TransportOutcome,
};
use refineid_ber::{BerEncoder, BerTag, BitString, Integer, Sequence, tlv};
use refineid_pkcs15::{
    CertSlot, DF_ESIGN_FID, DF_ESTONIAN_PERSONAL_DATA_FID, DOCUMENT_NUMBER_CHARS, EF_AOD_FID,
    EF_ESTONIAN_AOD_FID, EF_ESTONIAN_AUTH_CERT_FID, EF_ESTONIAN_DOCUMENT_NUMBER_FID,
    EF_ESTONIAN_DOCUMENT_NUMBER_LEGACY_FID, EF_TOKEN_INFO_FID, ESIGN_AID, PKCS15_AID, Pkcs15Error,
    Pkcs15Ops,
};

/// Chunk size the read loops request, mirroring the implementation; a
/// change there must fail these scripts loudly.
const READ_CHUNK_LEN: u8 = 0xDF;
/// `Le = 0`, the full 256-byte short-response window used when a card
/// answers a shorter first read with end-of-file.
const READ_LE_256_LEN: u8 = 0x00;
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
/// One extra byte past a valid document number so an overlong EF.5007
/// is detected instead of truncated.
const DOCUMENT_NUMBER_PROBE_SLACK: usize = 1;
/// ASN.1 universal ENUMERATED tag for `pwdType` in EF.AOD fixtures.
const ENUMERATED_TAG: u8 = 0x0A;
/// PKCS#15 `typeAttributes [1]` constructed tag for EF.AOD fixtures.
const TYPE_ATTRIBUTES_TAG: u8 = 0xA1;
/// PKCS#15 `pwdReference [0]` tag for EF.AOD fixtures.
const PWD_REFERENCE_TAG: u8 = 0x80;
/// `pwdType` `ascii-numeric(1)` for EF.AOD fixtures.
const PASSWORD_TYPE_ASCII_NUMERIC: u8 = 1;
/// Estonian PIN1 reference in EF.AOD fixtures.
const ESTONIAN_PIN1_REFERENCE: u8 = 0x81;
/// Estonian PIN1 minimum length in EF.AOD fixtures.
const ESTONIAN_PIN1_MIN_LEN: u8 = 4;
/// Estonian PIN1 stored length in EF.AOD fixtures.
const ESTONIAN_PIN1_STORED_LEN: u8 = 12;
/// `pwdFlags` unused-bits octet in EF.AOD fixtures.
const FLAGS_UNUSED_BITS: u8 = 0;
/// `pwdFlags` value octet in EF.AOD fixtures.
const FLAGS_OCTET: u8 = 0;
/// Leading zero octet for DER positive INTEGER encoding with high bit set.
const DER_ZERO_PREFIX: u8 = 0x00;
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

enum ScriptReply {
    Response(ResponseApdu),
    Outcome(TransportOutcome),
    Error(&'static str),
}

impl From<ResponseApdu> for ScriptReply {
    fn from(response: ResponseApdu) -> Self {
        Self::Response(response)
    }
}

struct ScriptedTransport {
    script: Vec<(Vec<u8>, ScriptReply)>,
    cursor: usize,
}

impl ScriptedTransport {
    fn new(script: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
        Self {
            script: script
                .into_iter()
                .map(|(cmd, resp)| (cmd, ScriptReply::Response(resp)))
                .collect(),
            cursor: 0,
        }
    }

    fn with_replies(script: Vec<(Vec<u8>, ScriptReply)>) -> Self {
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
        match scripted {
            ScriptReply::Response(response) => Ok(TransportOutcome::Response(response.clone())),
            ScriptReply::Outcome(outcome) => match outcome {
                TransportOutcome::NoCard => Ok(TransportOutcome::NoCard),
                TransportOutcome::CardReset => Ok(TransportOutcome::CardReset),
                TransportOutcome::ReaderRemoved => Ok(TransportOutcome::ReaderRemoved),
                TransportOutcome::TimeoutUnknownState => Ok(TransportOutcome::TimeoutUnknownState),
                TransportOutcome::ProtocolDesync => Ok(TransportOutcome::ProtocolDesync),
                TransportOutcome::Response(response) => {
                    Ok(TransportOutcome::Response(response.clone()))
                }
            },
            ScriptReply::Error(message) => Err((*message).to_owned()),
        }
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

fn select_path_wire(path: &[FileId]) -> Vec<u8> {
    let absolute = AbsolutePath::new(path.to_vec()).expect("valid test path");
    let wire = SelectFile {
        class: ApduClass::Plain,
        target: SelectFileTarget::AbsolutePath(absolute.clone()),
        response_mode: SelectFileResponseMode::Fcp,
    }
    .into_apdu()
    .as_bytes()
    .to_vec();
    let mut expected = vec![
        ApduClass::Plain.as_byte(),
        SelectFile::INS,
        SelectFileTarget::AbsolutePath(absolute).as_p1(),
        SelectFileResponseMode::Fcp.as_p2(),
        u8::try_from(path.len().saturating_mul(FileId::LENGTH)).expect("test path fits short Lc"),
    ];
    for fid in path {
        expected.extend_from_slice(fid.as_bytes());
    }
    expected.push(SelectFile::LE_ANY);
    assert_eq!(wire, expected, "select_path wire must be Case 4 with FCP");
    wire
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
fn estonian_authentication_certificate_reads_from_ef_3411() {
    let der = certificate_fixture(ONE_CHUNK_CONTENT_LEN);

    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (
            select_ef_wire(CertSlot::EstonianAuthentication.fid()),
            ok_response(&[]),
        ),
        (read_wire(0, READ_CHUNK_LEN), ok_response(&der)),
    ]);

    assert_eq!(
        CertSlot::EstonianAuthentication.fid(),
        EF_ESTONIAN_AUTH_CERT_FID
    );
    let cert = transport
        .read_certificate(CertSlot::EstonianAuthentication)
        .expect("scripted read succeeds");
    assert_eq!(cert.as_bytes(), der.as_slice());
    assert!(!CertSlot::EstonianAuthentication.requires_mf_traversal());
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
fn token_info_reads_after_end_of_file_on_a_long_read() {
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
        (
            read_wire(0, READ_CHUNK_LEN),
            response(&[], StatusWord::EndOfFile),
        ),
        (read_wire(0, READ_LE_256_LEN), ok_response(&der)),
    ]);

    let info = transport
        .read_token_info()
        .expect("the full-window retry succeeds");
    assert_eq!(info.version(), 1);
    assert!(info.serial_number_hex().is_some());
    transport.assert_drained();
}

fn document_number_probe_len() -> u8 {
    u8::try_from(DOCUMENT_NUMBER_CHARS + DOCUMENT_NUMBER_PROBE_SLACK)
        .expect("document number probe length fits one read")
}

fn aod_fixture(reference: u8, min_len: u8, stored_len: u8) -> Vec<u8> {
    let bit_string_tag = u8::try_from(<BitString as BerTag>::TAG).expect("fits");
    let integer_tag = u8::try_from(<Integer as BerTag>::TAG).expect("fits");
    let mut attrs = BerEncoder::default();
    attrs
        .push_tlv(bit_string_tag, [FLAGS_UNUSED_BITS, FLAGS_OCTET])
        .expect("fixture encodes");
    attrs
        .push_tlv(ENUMERATED_TAG, [PASSWORD_TYPE_ASCII_NUMERIC])
        .expect("fixture encodes");
    attrs
        .push_tlv(integer_tag, [min_len])
        .expect("fixture encodes");
    attrs
        .push_tlv(integer_tag, [stored_len])
        .expect("fixture encodes");
    let ref_bytes = if reference.leading_zeros() == 0 {
        vec![DER_ZERO_PREFIX, reference]
    } else {
        vec![reference]
    };
    attrs
        .push_tlv(PWD_REFERENCE_TAG, ref_bytes)
        .expect("fixture encodes");
    let attrs_seq = tlv(sequence_tag(), attrs.finish()).expect("fixture encodes");
    let type_attrs = tlv(TYPE_ATTRIBUTES_TAG, attrs_seq).expect("fixture encodes");
    tlv(sequence_tag(), type_attrs).expect("fixture encodes")
}

#[test]
fn document_number_reads_from_the_2025_personal_data_file() {
    /// Synthetic printed document number: two letters and seven digits.
    const PRINTED_NUMBER: &str = "AB1234567";

    let mut transport = ScriptedTransport::new(vec![
        (
            select_path_wire(&[
                DF_ESTONIAN_PERSONAL_DATA_FID,
                EF_ESTONIAN_DOCUMENT_NUMBER_FID,
            ]),
            ok_response(&[]),
        ),
        (
            read_wire(0, document_number_probe_len()),
            response(PRINTED_NUMBER.as_bytes(), StatusWord::EndOfFile),
        ),
    ]);

    let number = transport
        .read_document_number()
        .expect("the document number reads");
    assert_eq!(number.as_str(), PRINTED_NUMBER);
    transport.assert_drained();
}

#[test]
fn document_number_retries_with_le_256_after_empty_end_of_file() {
    /// Synthetic printed document number: two letters and seven digits.
    const PRINTED_NUMBER: &str = "AB1234567";

    let mut transport = ScriptedTransport::new(vec![
        (
            select_path_wire(&[
                DF_ESTONIAN_PERSONAL_DATA_FID,
                EF_ESTONIAN_DOCUMENT_NUMBER_FID,
            ]),
            ok_response(&[]),
        ),
        (
            read_wire(0, document_number_probe_len()),
            response(&[], StatusWord::EndOfFile),
        ),
        (
            read_wire(0, READ_LE_256_LEN),
            ok_response(PRINTED_NUMBER.as_bytes()),
        ),
    ]);

    let number = transport
        .read_document_number()
        .expect("the full-window retry reads the document number");
    assert_eq!(number.as_str(), PRINTED_NUMBER);
    transport.assert_drained();
}

#[test]
fn document_number_rejects_overlong_ef_5007() {
    /// Synthetic overlong file content: ten ASCII characters instead of nine.
    const OVERLONG_NUMBER: &str = "AB12345670";

    let mut transport = ScriptedTransport::new(vec![
        (
            select_path_wire(&[
                DF_ESTONIAN_PERSONAL_DATA_FID,
                EF_ESTONIAN_DOCUMENT_NUMBER_FID,
            ]),
            ok_response(&[]),
        ),
        (
            read_wire(0, document_number_probe_len()),
            ok_response(OVERLONG_NUMBER.as_bytes()),
        ),
    ]);

    let error = transport
        .read_document_number()
        .expect_err("an overlong EF.5007 must be rejected, not truncated");
    assert!(matches!(error, Pkcs15Error::InvalidData("EF.5007")));
    transport.assert_drained();
}

#[test]
fn document_number_propagates_transport_and_outcome_errors() {
    let mut transport_err = ScriptedTransport::with_replies(vec![(
        select_path_wire(&[
            DF_ESTONIAN_PERSONAL_DATA_FID,
            EF_ESTONIAN_DOCUMENT_NUMBER_FID,
        ]),
        ScriptReply::Error("reader disconnected"),
    )]);
    let error = transport_err
        .read_document_number()
        .expect_err("transport error must propagate immediately");
    assert!(matches!(error, Pkcs15Error::Transport(_)));
    transport_err.assert_drained();

    let mut outcome_err = ScriptedTransport::with_replies(vec![(
        select_path_wire(&[
            DF_ESTONIAN_PERSONAL_DATA_FID,
            EF_ESTONIAN_DOCUMENT_NUMBER_FID,
        ]),
        ScriptReply::Outcome(TransportOutcome::CardReset),
    )]);
    let error = outcome_err
        .read_document_number()
        .expect_err("transport outcome must propagate immediately");
    assert!(matches!(
        error,
        Pkcs15Error::Outcome(TransportOutcome::CardReset)
    ));
    outcome_err.assert_drained();
}

#[test]
fn authentication_objects_reads_estonian_ef_5006_after_empty_end_of_file() {
    let aod = aod_fixture(
        ESTONIAN_PIN1_REFERENCE,
        ESTONIAN_PIN1_MIN_LEN,
        ESTONIAN_PIN1_STORED_LEN,
    );

    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (
            select_ef_wire(EF_AOD_FID),
            response(&[], StatusWord::FileNotFound),
        ),
        (
            select_any_by_fid_wire(EF_AOD_FID),
            response(&[], StatusWord::FileNotFound),
        ),
        (select_ef_wire(EF_ESTONIAN_AOD_FID), ok_response(&[])),
        (
            read_wire(0, READ_CHUNK_LEN),
            response(&[], StatusWord::EndOfFile),
        ),
        (read_wire(0, READ_LE_256_LEN), ok_response(&aod)),
    ]);

    let objects = transport
        .read_authentication_objects()
        .expect("Estonian EF.5006 must read after the full-window retry");
    assert!(objects.lists_reference(ESTONIAN_PIN1_REFERENCE));
    transport.assert_drained();
}

#[test]
fn authentication_objects_propagates_transport_and_outcome_errors() {
    let mut on_app = ScriptedTransport::with_replies(vec![(
        select_app_wire(),
        ScriptReply::Error("reader disconnected"),
    )]);
    let error = on_app
        .read_authentication_objects()
        .expect_err("transport error must propagate");
    assert!(matches!(error, Pkcs15Error::Transport(_)));
    on_app.assert_drained();

    let mut on_ef = ScriptedTransport::with_replies(vec![
        (select_app_wire(), ScriptReply::Response(ok_response(&[]))),
        (
            select_ef_wire(EF_AOD_FID),
            ScriptReply::Outcome(TransportOutcome::NoCard),
        ),
    ]);
    let error = on_ef
        .read_authentication_objects()
        .expect_err("card removal must propagate");
    assert!(matches!(
        error,
        Pkcs15Error::Outcome(TransportOutcome::NoCard)
    ));
    on_ef.assert_drained();

    let mut on_read = ScriptedTransport::with_replies(vec![
        (select_app_wire(), ScriptReply::Response(ok_response(&[]))),
        (
            select_ef_wire(EF_AOD_FID),
            ScriptReply::Response(ok_response(&[])),
        ),
        (
            read_wire(0, READ_CHUNK_LEN),
            ScriptReply::Outcome(TransportOutcome::CardReset),
        ),
    ]);
    let error = on_read
        .read_authentication_objects()
        .expect_err("card reset during read must propagate");
    assert!(matches!(
        error,
        Pkcs15Error::Outcome(TransportOutcome::CardReset)
    ));
    on_read.assert_drained();
}

#[test]
fn authentication_objects_reports_file_not_found_when_neither_file_exists() {
    let mut transport = ScriptedTransport::new(vec![
        (select_app_wire(), ok_response(&[])),
        (
            select_ef_wire(EF_AOD_FID),
            response(&[], StatusWord::FileNotFound),
        ),
        (
            select_any_by_fid_wire(EF_AOD_FID),
            response(&[], StatusWord::FileNotFound),
        ),
        (
            select_ef_wire(EF_ESTONIAN_AOD_FID),
            response(&[], StatusWord::FileNotFound),
        ),
        (
            select_any_by_fid_wire(EF_ESTONIAN_AOD_FID),
            response(&[], StatusWord::FileNotFound),
        ),
    ]);

    let error = transport
        .read_authentication_objects()
        .expect_err("missing EF.AOD must report FileNotFound");
    assert!(matches!(
        error,
        Pkcs15Error::Status(StatusWord::FileNotFound)
    ));
    transport.assert_drained();
}

#[test]
fn document_number_reads_from_the_legacy_tlv_file() {
    /// Synthetic printed document number: two letters and seven digits.
    const PRINTED_NUMBER: &str = "AB1234567";
    let tag = u8::try_from(<refineid_ber::OctetString as BerTag>::TAG).expect("tag fits one octet");
    let der = tlv(tag, PRINTED_NUMBER.as_bytes()).expect("fixture encodes");

    let mut transport = ScriptedTransport::new(vec![
        (
            select_path_wire(&[
                DF_ESTONIAN_PERSONAL_DATA_FID,
                EF_ESTONIAN_DOCUMENT_NUMBER_FID,
            ]),
            response(&[], StatusWord::FileNotFound),
        ),
        (select_any_by_fid_wire(FileId::MF), ok_response(&[])),
        (
            select_ef_wire(EF_ESTONIAN_DOCUMENT_NUMBER_LEGACY_FID),
            ok_response(&[]),
        ),
        (read_wire(0, READ_CHUNK_LEN), ok_response(&der)),
    ]);

    let number = transport
        .read_document_number()
        .expect("the document number reads");
    assert_eq!(number.as_str(), PRINTED_NUMBER);
    transport.assert_drained();
}

#[test]
fn a_card_without_a_document_number_file_reports_the_missing_file() {
    let mut transport = ScriptedTransport::new(vec![
        (
            select_path_wire(&[
                DF_ESTONIAN_PERSONAL_DATA_FID,
                EF_ESTONIAN_DOCUMENT_NUMBER_FID,
            ]),
            response(&[], StatusWord::FileNotFound),
        ),
        (select_any_by_fid_wire(FileId::MF), ok_response(&[])),
        (
            select_ef_wire(EF_ESTONIAN_DOCUMENT_NUMBER_LEGACY_FID),
            response(&[], StatusWord::FileNotFound),
        ),
        (
            select_any_by_fid_wire(EF_ESTONIAN_DOCUMENT_NUMBER_LEGACY_FID),
            response(&[], StatusWord::FileNotFound),
        ),
    ]);

    let error = transport
        .read_document_number()
        .expect_err("a card without either document-number file must report the missing file");
    assert!(matches!(
        error,
        Pkcs15Error::Status(StatusWord::FileNotFound)
    ));
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
