// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0.

//! A `sign_document` of a package carries the names of every file it
//! holds (RAPP v26.11.1 section 9.3): present exactly for a package, each
//! entry within the name bound, unique and outside `META-INF/`, and the
//! whole request within one frame (section 7.2 item 4). A single document
//! carries none.

use std::collections::BTreeMap;

use refineid_rapp::{
    CardKeyProfile, CardOperation, CardOperationError, ContainedFiles, Envelope, GrantsHash,
    HandshakeRole, MAX_FRAME_PLAINTEXT, MessageType, OPERATION_ID_SIZE, OperationId,
    OperationRequest, OperationRequestRefusal, PAIR_ID_SIZE, PairId, ProfileName, ProxyDispatch,
    ProxyOperationEngine, RequestError, RequesterEngineError, RequesterOperationEngine,
    ResultError, SESSION_ID_SIZE, SecureChannel, SessionHandshakeParameters, SessionId,
    SignatureAlgorithm, TypedMessage, WireValue, generate_pair_key_material,
};

const START_MS: u64 = 1_000;
const LIFETIME_MS: u64 = 60_000;
const SHA256_DIGEST_SIZE: usize = 32;
const DIGEST_BYTE: u8 = u8::MAX;
const OPERATION_BYTE: u8 = 1;
/// The longest name the custodian shows (sections 9.2 and 9.3).
const DISPLAY_NAME_LIMIT: usize = 256;
/// The letter a synthetic name is made of.
const NAME_LETTER: &str = "n";
const PACKAGE_NAME: &str = "Dossier.asice";
const TRANSPORT_PROFILE: &str = "relay-websocket-v1";

fn names(entries: &[&str]) -> Vec<String> {
    entries.iter().map(|entry| (*entry).to_owned()).collect()
}

/// A `sign_document` request, built without the admission check so that
/// a refused one can be offered to each border.
fn sign_document(document_name: &str, contained_files: Option<ContainedFiles>) -> OperationRequest {
    OperationRequest {
        operation_id: OperationId::from_array([OPERATION_BYTE; OPERATION_ID_SIZE]),
        profile: ProfileName::DocumentSigning,
        local_start_ms: START_MS,
        expires_after_ms: LIFETIME_MS,
        operation: CardOperation::SignDocument {
            document_name: document_name.to_owned(),
            contained_files,
            key_profile: CardKeyProfile::Rsa2048,
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest: vec![DIGEST_BYTE; SHA256_DIGEST_SIZE],
        },
    }
}

/// The `operation.request` body of `request` as the wire carries it.
fn wire_body(request: &OperationRequest) -> BTreeMap<String, WireValue> {
    let (action, context, payload) = request.wire_parts();
    let mut body = BTreeMap::new();
    body.insert(
        "operation_id".into(),
        WireValue::Bytes(request.operation_id.as_bytes().to_vec()),
    );
    body.insert(
        "profile".into(),
        WireValue::Text(request.profile.as_str().to_owned()),
    );
    body.insert("action".into(), WireValue::Text(action.to_owned()));
    body.insert(
        "expires_after_ms".into(),
        WireValue::Unsigned(request.expires_after_ms),
    );
    body.insert("context".into(), WireValue::Map(context));
    body.insert("payload".into(), WireValue::Map(payload));
    body
}

/// Whether the custodian admits `body`, or how it refuses it.
fn admit(body: BTreeMap<String, WireValue>) -> Result<OperationRequest, RequestError> {
    OperationRequest::from_wire_body(body, START_MS)
}

fn refusal(request: &OperationRequest) -> RequestError {
    RequestError::Refused(OperationRequestRefusal {
        operation_id: request.operation_id,
        error: ResultError::UnsupportedParameter,
    })
}

#[test]
fn a_single_document_carries_no_contained_files() {
    let request = sign_document("Contract.pdf", None);
    assert_eq!(request.validate(), Ok(()));
    let (_, context, _) = request.wire_parts();
    assert!(!context.contains_key("contained_files"));
    assert_eq!(
        admit(request.to_wire_body().expect("the request encodes")),
        Ok(request)
    );
}

#[test]
fn a_package_round_trips_every_file_in_container_order() {
    let files = ContainedFiles::reconstruct(names(&["Contract.pdf", "Annex.pdf", "a/b.txt"]))
        .expect("usable entry names");
    let request = sign_document(PACKAGE_NAME, Some(files.clone()));
    assert_eq!(request.validate(), Ok(()));
    let (_, context, _) = request.wire_parts();
    assert_eq!(
        context.get("contained_files"),
        Some(&WireValue::Array(
            files.names().iter().cloned().map(WireValue::Text).collect()
        ))
    );
    assert_eq!(
        admit(request.to_wire_body().expect("the request encodes")),
        Ok(request)
    );
}

#[test]
fn a_package_of_one_file_sends_its_one_entry() {
    let files = ContainedFiles::reconstruct(names(&["Contract.pdf"])).expect("one entry");
    let request = sign_document(PACKAGE_NAME, Some(files));
    assert_eq!(
        admit(request.to_wire_body().expect("the request encodes")),
        Ok(request)
    );
}

#[test]
fn contained_files_are_checked_at_their_border() {
    assert_eq!(
        ContainedFiles::reconstruct(Vec::new()),
        Err(CardOperationError::InvalidField("contained_files")),
        "a package holds at least one file"
    );
    assert_eq!(
        ContainedFiles::reconstruct(names(&["Contract.pdf", "Contract.pdf"])),
        Err(CardOperationError::InvalidField("contained_files")),
        "entries are unique"
    );
    for reserved in ["META-INF/signatures0.xml", "meta-inf/manifest.xml"] {
        assert_eq!(
            ContainedFiles::reconstruct(names(&["Contract.pdf", reserved])),
            Err(CardOperationError::InvalidField("contained_files")),
            "{reserved}: no entry lies under the reserved directory"
        );
    }
    assert_eq!(
        ContainedFiles::reconstruct(names(&["Contract.pdf", " "])),
        Err(CardOperationError::InvalidDisplayContext),
        "a blank entry names nothing"
    );
    let at_bound = NAME_LETTER.repeat(DISPLAY_NAME_LIMIT);
    let over = NAME_LETTER.repeat(DISPLAY_NAME_LIMIT + 1);
    assert_eq!(
        ContainedFiles::reconstruct(vec![at_bound.clone()])
            .expect("an entry at the bound")
            .names(),
        [at_bound]
    );
    assert_eq!(
        ContainedFiles::reconstruct(vec![over]),
        Err(CardOperationError::InvalidDisplayContext),
        "an entry over the bound is refused, never shortened"
    );
    assert_eq!(
        ContainedFiles::reconstruct(names(&["META-INF-notes.txt", "META-INF"]))
            .expect("names that merely begin like the directory are files")
            .names()
            .len(),
        2
    );
}

#[test]
fn a_malformed_contained_files_field_is_refused_on_the_wire() {
    let request = sign_document(PACKAGE_NAME, None);
    for malformed in [
        WireValue::Array(Vec::new()),
        WireValue::Array(vec![WireValue::Unsigned(1)]),
        WireValue::Array(vec![
            WireValue::Text("Contract.pdf".to_owned()),
            WireValue::Text("Contract.pdf".to_owned()),
        ]),
        WireValue::Array(vec![WireValue::Text("META-INF/signatures0.xml".to_owned())]),
        WireValue::Text("Contract.pdf".to_owned()),
    ] {
        let mut body = wire_body(&request);
        let Some(WireValue::Map(context)) = body.get_mut("context") else {
            panic!("the body carries a context");
        };
        context.insert("contained_files".to_owned(), malformed);
        assert_eq!(admit(body), Err(refusal(&request)));
    }
}

#[test]
fn display_names_follow_the_name_bound() {
    let at_bound = NAME_LETTER.repeat(DISPLAY_NAME_LIMIT);
    let over = NAME_LETTER.repeat(DISPLAY_NAME_LIMIT + 1);
    assert_eq!(sign_document(&at_bound, None).validate(), Ok(()));
    assert_eq!(
        sign_document(&over, None).validate(),
        Err(CardOperationError::InvalidDisplayContext)
    );
    let origin = OperationRequest {
        profile: ProfileName::Authentication,
        operation: CardOperation::BrowserAuthenticate {
            origin: over,
            key_profile: CardKeyProfile::Rsa2048,
            algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            digest: vec![DIGEST_BYTE; SHA256_DIGEST_SIZE],
        },
        ..sign_document(PACKAGE_NAME, None)
    };
    assert_eq!(
        origin.validate(),
        Err(CardOperationError::InvalidDisplayContext)
    );
}

/// Entry `index` of a synthetic package: its index padded to the bound.
fn long_entry(index: usize) -> String {
    let mut entry = index.to_string();
    while entry.len() < DISPLAY_NAME_LIMIT {
        entry.push_str(NAME_LETTER);
    }
    entry
}

/// A package of `count` entries at the name bound.
fn package(count: usize) -> OperationRequest {
    sign_document(
        PACKAGE_NAME,
        Some(ContainedFiles::reconstruct((0..count).map(long_entry).collect()).expect("entries")),
    )
}

/// The smallest package the request bound refuses.
fn first_refused_count() -> usize {
    let mut low = 1;
    let mut high = MAX_FRAME_PLAINTEXT;
    assert!(package(low).validate().is_ok());
    assert!(package(high).validate().is_err());
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if package(middle).validate().is_ok() {
            low = middle;
        } else {
            high = middle;
        }
    }
    high
}

/// Two ends of one operational session after the Noise KK handshake:
/// (requester, custodian).
fn session_channels() -> (SecureChannel, SecureChannel) {
    let requester_keys = generate_pair_key_material().expect("requester keys");
    let custodian_keys = generate_pair_key_material().expect("custodian keys");
    let pair_id = PairId::from_array([OPERATION_BYTE; PAIR_ID_SIZE]);
    let grants_hash = GrantsHash::from_array([OPERATION_BYTE; 32]);
    let mut requester = refineid_rapp::HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Initiator,
        local_keys: &requester_keys,
        remote_public_key: custodian_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile: TRANSPORT_PROFILE,
    })
    .expect("requester handshake");
    let mut custodian = refineid_rapp::HandshakeChannel::session(&SessionHandshakeParameters {
        role: HandshakeRole::Responder,
        local_keys: &custodian_keys,
        remote_public_key: requester_keys.public_key(),
        pair_id,
        grants_hash,
        transport_profile: TRANSPORT_PROFILE,
    })
    .expect("custodian handshake");
    let first = requester.write_message().expect("message 1");
    custodian.read_message(&first).expect("message 1 read");
    let second = custodian.write_message().expect("message 2");
    requester.read_message(&second).expect("message 2 read");
    (
        requester
            .complete()
            .expect("requester complete")
            .secure_channel,
        custodian
            .complete()
            .expect("custodian complete")
            .secure_channel,
    )
}

#[test]
fn a_package_whose_request_overflows_one_frame_is_refused_at_both_borders() {
    let refused = package(first_refused_count());
    assert_eq!(refused.validate(), Err(CardOperationError::PackageTooLarge));
    let mut requester = RequesterOperationEngine::new();
    assert_eq!(
        requester.begin(refused.clone()).err(),
        Some(RequesterEngineError::InvalidLocalRequest(
            CardOperationError::PackageTooLarge
        ))
    );
    assert_eq!(admit(wire_body(&refused)), Err(refusal(&refused)));
    let envelope = Envelope::reconstruct(
        MessageType::OperationRequest,
        SessionId::from_array([u8::MIN; SESSION_ID_SIZE]),
        u64::MAX,
        wire_body(&refused),
    )
    .expect("the body fits its schema");
    assert!(
        envelope.encode().is_err(),
        "the refused request does not encode in one frame"
    );
}

#[test]
fn the_largest_package_that_fits_travels_and_is_admitted() {
    let request = package(first_refused_count() - 1);
    let mut requester = RequesterOperationEngine::new();
    let wire = requester
        .begin(request.clone())
        .expect("the largest package that fits starts");
    let (mut requester_channel, mut custodian_channel) = session_channels();
    let frame = requester_channel
        .seal(
            wire.message_type(),
            wire.to_wire_body().expect("the request encodes"),
        )
        .expect("the request seals in one frame");
    let opened = custodian_channel
        .open(&frame)
        .expect("the custodian opens it");
    assert_eq!(opened.message_type, MessageType::OperationRequest);
    let received = admit(opened.body).expect("the custodian admits the package");
    assert_eq!(received.operation, request.operation);
    let mut engine = ProxyOperationEngine::new(vec![ProfileName::DocumentSigning]);
    assert!(matches!(
        engine.receive(TypedMessage::OperationRequest(received)),
        Ok(ProxyDispatch::InspectPrerequisites(_))
    ));
}
