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

//! Device-local durable operation storage for generated bindings.
//!
//! Swift and Kotlin store opaque deterministic-CBOR records. Rust remains the
//! only decoder and state-machine authority. Result methods are separate
//! atomic vault transactions because a completed result must be retained
//! before transmission and erased only with its exact acknowledgment.

use std::{collections::BTreeMap, sync::Arc};

use super::{
    CardIdentity, CardInspection, CardOperationResult, JournalRecord, JournalRecoveryStore,
    JournalStore, OperationId, OperationResultMessage, OperationState, PairId,
    RecoveredProxyRecord, RequestHash, RequesterJournalRecord, RequesterJournalStore,
    RequesterRecoveryStore, ResultJournalStore, SessionId, StatusReport, WireValue,
    bindings::{
        RappBindingError, RappVaultError, take_bytes, take_text, take_unsigned, take_value,
    },
    decode_deterministic_cbor, encode_deterministic_cbor,
};

const REQUESTER_JOURNAL_FORMAT_VERSION: u64 = 2;
const PROXY_JOURNAL_FORMAT_VERSION: u64 = 2;

/// One proxy recovery entry returned by an atomic platform load.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct RappStoredProxyJournal {
    /// Opaque non-secret operation journal record.
    pub record: Vec<u8>,
    /// Encrypted-at-rest retained result: a completed one while
    /// acknowledgment is pending or delivery became uncertain, or a failure
    /// that answers identical retransmissions.
    pub retained_result: Option<Vec<u8>>,
}

/// Platform-owned durable operation storage.
///
/// Every method is one atomic transaction. Records and retained results must
/// remain device-local, encrypted at rest, excluded from backup and migration,
/// and inaccessible to UI or logging code.
#[uniffi::export(with_foreign)]
pub trait RappOperationVault: Send + Sync {
    /// Persist the complete requester record before releasing its next frame.
    ///
    /// # Errors
    /// [`RappVaultError`] when the atomic storage transaction fails.
    fn persist_requester(
        &self,
        pair_id: Vec<u8>,
        operation_id: Vec<u8>,
        record: Vec<u8>,
    ) -> Result<(), RappVaultError>;

    /// Load all requester records for one pair during fail-closed recovery.
    ///
    /// # Errors
    /// [`RappVaultError`] when the atomic storage transaction fails.
    fn load_requester(&self, pair_id: Vec<u8>) -> Result<Vec<Vec<u8>>, RappVaultError>;

    /// Persist the complete proxy record before the corresponding transition.
    ///
    /// # Errors
    /// [`RappVaultError`] when the atomic storage transaction fails.
    fn persist_proxy(
        &self,
        pair_id: Vec<u8>,
        operation_id: Vec<u8>,
        record: Vec<u8>,
    ) -> Result<(), RappVaultError>;

    /// Atomically persist a proxy record and the complete result that reports
    /// it before releasing the result frame: a completed result pending
    /// acknowledgment, or a failure kept to answer identical
    /// retransmissions.
    ///
    /// # Errors
    /// [`RappVaultError`] when the atomic storage transaction fails.
    fn persist_proxy_result(
        &self,
        pair_id: Vec<u8>,
        operation_id: Vec<u8>,
        record: Vec<u8>,
        result: Vec<u8>,
    ) -> Result<(), RappVaultError>;

    /// Atomically retain the result while marking delivery uncertain.
    ///
    /// # Errors
    /// [`RappVaultError`] when the atomic storage transaction fails.
    fn retain_proxy_uncertain(
        &self,
        pair_id: Vec<u8>,
        operation_id: Vec<u8>,
        record: Vec<u8>,
    ) -> Result<(), RappVaultError>;

    /// Atomically mark completion and erase the retained result body.
    ///
    /// # Errors
    /// [`RappVaultError`] when the atomic storage transaction fails.
    fn acknowledge_proxy_result(
        &self,
        pair_id: Vec<u8>,
        operation_id: Vec<u8>,
        record: Vec<u8>,
    ) -> Result<(), RappVaultError>;

    /// Load all proxy records and retained results for one pair.
    ///
    /// # Errors
    /// [`RappVaultError`] when the atomic storage transaction fails.
    fn load_proxy(&self, pair_id: Vec<u8>) -> Result<Vec<RappStoredProxyJournal>, RappVaultError>;
}

pub(super) struct BindingOperationStore {
    pair_id: PairId,
    vault: Arc<dyn RappOperationVault>,
}

impl BindingOperationStore {
    pub(super) fn new(pair_id: PairId, vault: Arc<dyn RappOperationVault>) -> Self {
        Self { pair_id, vault }
    }

    fn require_pair(&self, pair_id: PairId) -> Result<(), RappVaultError> {
        if pair_id == self.pair_id {
            Ok(())
        } else {
            Err(RappVaultError::Unavailable)
        }
    }
}

impl RequesterJournalStore for BindingOperationStore {
    type Error = RappVaultError;

    fn persist(&mut self, record: &RequesterJournalRecord) -> Result<(), Self::Error> {
        self.require_pair(record.pair_id)?;
        let bytes = encode_requester_record(record).map_err(|_| RappVaultError::Unavailable)?;
        self.vault.persist_requester(
            record.pair_id.as_bytes().to_vec(),
            record.operation_id.as_bytes().to_vec(),
            bytes,
        )
    }
}

impl RequesterRecoveryStore for BindingOperationStore {
    fn load_all(&mut self) -> Result<Vec<RequesterJournalRecord>, Self::Error> {
        self.vault
            .load_requester(self.pair_id.as_bytes().to_vec())?
            .into_iter()
            .map(|bytes| {
                let record =
                    decode_requester_record(&bytes).map_err(|_| RappVaultError::Unavailable)?;
                self.require_pair(record.pair_id)?;
                Ok(record)
            })
            .collect()
    }
}

impl JournalStore for BindingOperationStore {
    type Error = RappVaultError;

    fn persist(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.require_pair(record.pair_id)?;
        let bytes = encode_proxy_record(record).map_err(|_| RappVaultError::Unavailable)?;
        self.vault.persist_proxy(
            record.pair_id.as_bytes().to_vec(),
            record.operation_id.as_bytes().to_vec(),
            bytes,
        )
    }
}

impl ResultJournalStore for BindingOperationStore {
    fn persist_result(
        &mut self,
        record: &JournalRecord,
        result: &OperationResultMessage,
    ) -> Result<(), Self::Error> {
        self.require_pair(record.pair_id)?;
        let pair_id = record.pair_id.as_bytes().to_vec();
        let operation_id = record.operation_id.as_bytes().to_vec();
        let record = encode_proxy_record(record).map_err(|_| RappVaultError::Unavailable)?;
        let result = encode_operation_result(result).map_err(|_| RappVaultError::Unavailable)?;
        self.vault
            .persist_proxy_result(pair_id, operation_id, record, result)
    }

    fn retain_uncertain_result(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.require_pair(record.pair_id)?;
        let pair_id = record.pair_id.as_bytes().to_vec();
        let operation_id = record.operation_id.as_bytes().to_vec();
        let record = encode_proxy_record(record).map_err(|_| RappVaultError::Unavailable)?;
        self.vault
            .retain_proxy_uncertain(pair_id, operation_id, record)
    }

    fn acknowledge_result(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
        self.require_pair(record.pair_id)?;
        let pair_id = record.pair_id.as_bytes().to_vec();
        let operation_id = record.operation_id.as_bytes().to_vec();
        let record = encode_proxy_record(record).map_err(|_| RappVaultError::Unavailable)?;
        self.vault
            .acknowledge_proxy_result(pair_id, operation_id, record)
    }
}

impl JournalRecoveryStore for BindingOperationStore {
    fn load_all(&mut self) -> Result<Vec<RecoveredProxyRecord>, Self::Error> {
        self.vault
            .load_proxy(self.pair_id.as_bytes().to_vec())?
            .into_iter()
            .map(|entry| {
                let record =
                    decode_proxy_record(&entry.record).map_err(|_| RappVaultError::Unavailable)?;
                self.require_pair(record.pair_id)?;
                let retained_result = entry
                    .retained_result
                    .map(|bytes| {
                        decode_operation_result(&bytes).map_err(|_| RappVaultError::Unavailable)
                    })
                    .transpose()?;
                Ok(RecoveredProxyRecord {
                    record,
                    retained_result,
                })
            })
            .collect()
    }
}

fn encode_requester_record(record: &RequesterJournalRecord) -> Result<Vec<u8>, RappBindingError> {
    let retained_result = record
        .retained_result
        .as_ref()
        .map_or(WireValue::Null, card_result_value);
    let reconciliation = record
        .reconciliation
        .as_ref()
        .map_or(WireValue::Null, status_report_value);
    encode_deterministic_cbor(&WireValue::Map(BTreeMap::from([
        (
            "format_version".to_owned(),
            WireValue::Unsigned(REQUESTER_JOURNAL_FORMAT_VERSION),
        ),
        ("pair_id".to_owned(), id_value(record.pair_id.as_bytes())),
        (
            "session_id".to_owned(),
            id_value(record.session_id.as_bytes()),
        ),
        (
            "operation_id".to_owned(),
            id_value(record.operation_id.as_bytes()),
        ),
        (
            "request_hash".to_owned(),
            id_value(record.request_hash.as_bytes()),
        ),
        (
            "state".to_owned(),
            WireValue::Text(operation_state_name(record.state).to_owned()),
        ),
        ("retained_result".to_owned(), retained_result),
        ("reconciliation".to_owned(), reconciliation),
    ])))
    .map_err(|_| RappBindingError::ProtocolFailure)
}

fn decode_requester_record(bytes: &[u8]) -> Result<RequesterJournalRecord, RappBindingError> {
    let mut map = decoded_map(bytes)?;
    require_version(&mut map, "format_version", REQUESTER_JOURNAL_FORMAT_VERSION)?;
    let pair_id = PairId::reconstruct(&take_bytes(&mut map, "pair_id")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let session_id = SessionId::reconstruct(&take_bytes(&mut map, "session_id")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let operation_id = OperationId::reconstruct(&take_bytes(&mut map, "operation_id")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let request_hash = RequestHash::reconstruct(&take_bytes(&mut map, "request_hash")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let state = parse_operation_state(&take_text(&mut map, "state")?)?;
    let retained_result = match take_value(&mut map, "retained_result")? {
        WireValue::Null => None,
        value => Some(parse_card_result(value)?),
    };
    let reconciliation = match take_value(&mut map, "reconciliation")? {
        WireValue::Null => None,
        value => Some(parse_status_report(value)?),
    };
    require_empty(&map)?;
    Ok(RequesterJournalRecord {
        pair_id,
        session_id,
        operation_id,
        request_hash,
        state,
        retained_result,
        reconciliation,
    })
}

fn encode_proxy_record(record: &JournalRecord) -> Result<Vec<u8>, RappBindingError> {
    encode_deterministic_cbor(&WireValue::Map(BTreeMap::from([
        (
            "format_version".to_owned(),
            WireValue::Unsigned(PROXY_JOURNAL_FORMAT_VERSION),
        ),
        ("pair_id".to_owned(), id_value(record.pair_id.as_bytes())),
        (
            "session_id".to_owned(),
            id_value(record.session_id.as_bytes()),
        ),
        (
            "operation_id".to_owned(),
            id_value(record.operation_id.as_bytes()),
        ),
        (
            "request_hash".to_owned(),
            id_value(record.request_hash.as_bytes()),
        ),
        (
            "state".to_owned(),
            WireValue::Text(operation_state_name(record.state).to_owned()),
        ),
        (
            "transmission_count".to_owned(),
            WireValue::Unsigned(u64::from(record.transmission_count)),
        ),
        (
            "automatic_retry_permitted".to_owned(),
            WireValue::Bool(record.automatic_retry_permitted),
        ),
    ])))
    .map_err(|_| RappBindingError::ProtocolFailure)
}

fn decode_proxy_record(bytes: &[u8]) -> Result<JournalRecord, RappBindingError> {
    let mut map = decoded_map(bytes)?;
    require_version(&mut map, "format_version", PROXY_JOURNAL_FORMAT_VERSION)?;
    let pair_id = PairId::reconstruct(&take_bytes(&mut map, "pair_id")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let session_id = SessionId::reconstruct(&take_bytes(&mut map, "session_id")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let operation_id = OperationId::reconstruct(&take_bytes(&mut map, "operation_id")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let request_hash = RequestHash::reconstruct(&take_bytes(&mut map, "request_hash")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let state = parse_operation_state(&take_text(&mut map, "state")?)?;
    let transmission_count = u8::try_from(take_unsigned(&mut map, "transmission_count")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let automatic_retry_permitted = take_bool(&mut map, "automatic_retry_permitted")?;
    require_empty(&map)?;
    Ok(JournalRecord {
        pair_id,
        session_id,
        operation_id,
        request_hash,
        state,
        transmission_count,
        automatic_retry_permitted,
    })
}

fn encode_operation_result(result: &OperationResultMessage) -> Result<Vec<u8>, RappBindingError> {
    let body = result
        .to_wire_body()
        .map_err(|_| RappBindingError::ProtocolFailure)?;
    encode_deterministic_cbor(&WireValue::Map(body)).map_err(|_| RappBindingError::ProtocolFailure)
}

fn decode_operation_result(bytes: &[u8]) -> Result<OperationResultMessage, RappBindingError> {
    OperationResultMessage::from_wire_body(decoded_map(bytes)?)
        .map_err(|_| RappBindingError::InvalidInput)
}

fn card_result_value(result: &CardOperationResult) -> WireValue {
    let map = match result {
        CardOperationResult::Inspection(inspection) => {
            let mut map = BTreeMap::from([
                ("kind".to_owned(), WireValue::Text("inspection".to_owned())),
                (
                    "atr".to_owned(),
                    WireValue::Bytes(inspection.answer_to_reset.clone()),
                ),
                (
                    "pin1_factory".to_owned(),
                    WireValue::Bool(inspection.pin1_factory),
                ),
                (
                    "pin2_factory".to_owned(),
                    WireValue::Bool(inspection.pin2_factory),
                ),
            ]);
            insert_attempt(&mut map, "pin1_attempts", inspection.pin1_attempts);
            insert_attempt(&mut map, "pin2_attempts", inspection.pin2_attempts);
            insert_attempt(&mut map, "puk_attempts", inspection.puk_attempts);
            map
        }
        CardOperationResult::Identity(identity) => {
            let mut map = BTreeMap::from([
                ("kind".to_owned(), WireValue::Text("identity".to_owned())),
                (
                    "holder_name".to_owned(),
                    WireValue::Text(identity.holder_name.clone()),
                ),
                (
                    "card_id".to_owned(),
                    WireValue::Text(identity.card_id.clone()),
                ),
                (
                    "issuance_date".to_owned(),
                    WireValue::Text(identity.issuance_date.clone()),
                ),
                (
                    "expiration_date".to_owned(),
                    WireValue::Text(identity.expiration_date.clone()),
                ),
                (
                    "certificates".to_owned(),
                    WireValue::Array(
                        identity
                            .certificates
                            .iter()
                            .cloned()
                            .map(WireValue::Bytes)
                            .collect(),
                    ),
                ),
            ]);
            if let Some(name) = &identity.token_display_name {
                map.insert(
                    "token_display_name".to_owned(),
                    WireValue::Text(name.clone()),
                );
            }
            map
        }
        CardOperationResult::Certificate(bytes) => BTreeMap::from([
            ("kind".to_owned(), WireValue::Text("certificate".to_owned())),
            ("bytes".to_owned(), WireValue::Bytes(bytes.clone())),
        ]),
        CardOperationResult::Signature(bytes) => BTreeMap::from([
            ("kind".to_owned(), WireValue::Text("signature".to_owned())),
            ("bytes".to_owned(), WireValue::Bytes(bytes.clone())),
        ]),
    };
    WireValue::Map(map)
}

fn parse_card_result(value: WireValue) -> Result<CardOperationResult, RappBindingError> {
    let WireValue::Map(mut map) = value else {
        return Err(RappBindingError::InvalidInput);
    };
    let result = match take_text(&mut map, "kind")?.as_str() {
        "inspection" => CardOperationResult::Inspection(CardInspection {
            answer_to_reset: take_bytes(&mut map, "atr")?,
            pin1_factory: take_bool(&mut map, "pin1_factory")?,
            pin2_factory: take_bool(&mut map, "pin2_factory")?,
            pin1_attempts: take_optional_attempt(&mut map, "pin1_attempts")?,
            pin2_attempts: take_optional_attempt(&mut map, "pin2_attempts")?,
            puk_attempts: take_optional_attempt(&mut map, "puk_attempts")?,
        }),
        "identity" => {
            let certificates = match take_value(&mut map, "certificates")? {
                WireValue::Array(values) => values
                    .into_iter()
                    .map(|value| match value {
                        WireValue::Bytes(bytes) => Ok(bytes),
                        _ => Err(RappBindingError::InvalidInput),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(RappBindingError::InvalidInput),
            };
            let token_display_name = match map.remove("token_display_name") {
                None => None,
                Some(WireValue::Text(value)) => Some(value),
                Some(_) => return Err(RappBindingError::InvalidInput),
            };
            CardOperationResult::Identity(
                CardIdentity::reconstruct(
                    take_text(&mut map, "holder_name")?,
                    take_text(&mut map, "card_id")?,
                    take_text(&mut map, "issuance_date")?,
                    take_text(&mut map, "expiration_date")?,
                    certificates,
                    token_display_name,
                )
                .map_err(|_| RappBindingError::InvalidInput)?,
            )
        }
        "certificate" => CardOperationResult::Certificate(take_bytes(&mut map, "bytes")?),
        "signature" => CardOperationResult::Signature(take_bytes(&mut map, "bytes")?),
        _ => return Err(RappBindingError::InvalidInput),
    };
    require_empty(&map)?;
    Ok(result)
}

fn status_report_value(report: &StatusReport) -> WireValue {
    WireValue::Map(BTreeMap::from([
        (
            "operation_id".to_owned(),
            id_value(report.operation_id.as_bytes()),
        ),
        ("known".to_owned(), WireValue::Bool(report.known)),
        (
            "state".to_owned(),
            report.state.map_or(WireValue::Null, |state| {
                WireValue::Text(operation_state_name(state).to_owned())
            }),
        ),
        (
            "request_hash".to_owned(),
            report
                .request_hash
                .map_or(WireValue::Null, |hash| id_value(hash.as_bytes())),
        ),
        ("retired".to_owned(), WireValue::Bool(report.retired)),
    ]))
}

fn parse_status_report(value: WireValue) -> Result<StatusReport, RappBindingError> {
    let WireValue::Map(mut map) = value else {
        return Err(RappBindingError::InvalidInput);
    };
    let operation_id = OperationId::reconstruct(&take_bytes(&mut map, "operation_id")?)
        .map_err(|_| RappBindingError::InvalidInput)?;
    let known = take_bool(&mut map, "known")?;
    let state = match take_value(&mut map, "state")? {
        WireValue::Null => None,
        WireValue::Text(value) => Some(parse_operation_state(&value)?),
        _ => return Err(RappBindingError::InvalidInput),
    };
    let request_hash = match take_value(&mut map, "request_hash")? {
        WireValue::Null => None,
        WireValue::Bytes(value) => {
            Some(RequestHash::reconstruct(&value).map_err(|_| RappBindingError::InvalidInput)?)
        }
        _ => return Err(RappBindingError::InvalidInput),
    };
    let retired = take_bool(&mut map, "retired")?;
    require_empty(&map)?;
    Ok(StatusReport {
        operation_id,
        known,
        state,
        request_hash,
        retired,
    })
}

const fn operation_state_name(state: OperationState) -> &'static str {
    match state {
        OperationState::None => "none",
        OperationState::Requested => "requested",
        OperationState::AwaitingConsent => "awaiting_consent",
        OperationState::Prepared => "prepared",
        OperationState::Committed => "committed",
        OperationState::Executing => "executing",
        OperationState::ResultPending => "result_pending",
        OperationState::Completed => "completed",
        OperationState::Denied => "denied",
        OperationState::Cancelled => "cancelled",
        OperationState::Rejected => "rejected",
        OperationState::CredentialRejected => "credential_rejected",
        OperationState::Ambiguous => "ambiguous",
        OperationState::DeliveryUncertain => "delivery_uncertain",
    }
}

fn parse_operation_state(value: &str) -> Result<OperationState, RappBindingError> {
    match value {
        "none" => Ok(OperationState::None),
        "requested" => Ok(OperationState::Requested),
        "awaiting_consent" => Ok(OperationState::AwaitingConsent),
        "prepared" => Ok(OperationState::Prepared),
        "committed" => Ok(OperationState::Committed),
        "executing" => Ok(OperationState::Executing),
        "result_pending" => Ok(OperationState::ResultPending),
        "completed" => Ok(OperationState::Completed),
        "denied" => Ok(OperationState::Denied),
        "cancelled" => Ok(OperationState::Cancelled),
        "rejected" => Ok(OperationState::Rejected),
        "credential_rejected" => Ok(OperationState::CredentialRejected),
        "ambiguous" => Ok(OperationState::Ambiguous),
        "delivery_uncertain" => Ok(OperationState::DeliveryUncertain),
        _ => Err(RappBindingError::InvalidInput),
    }
}

fn decoded_map(bytes: &[u8]) -> Result<BTreeMap<String, WireValue>, RappBindingError> {
    match decode_deterministic_cbor(bytes).map_err(|_| RappBindingError::InvalidInput)? {
        WireValue::Map(map) => Ok(map),
        _ => Err(RappBindingError::InvalidInput),
    }
}

fn require_version(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
    expected: u64,
) -> Result<(), RappBindingError> {
    if take_unsigned(map, key)? == expected {
        Ok(())
    } else {
        Err(RappBindingError::InvalidInput)
    }
}

fn require_empty(map: &BTreeMap<String, WireValue>) -> Result<(), RappBindingError> {
    if map.is_empty() {
        Ok(())
    } else {
        Err(RappBindingError::InvalidInput)
    }
}

fn id_value(bytes: &[u8]) -> WireValue {
    WireValue::Bytes(bytes.to_vec())
}

fn take_bool(map: &mut BTreeMap<String, WireValue>, key: &str) -> Result<bool, RappBindingError> {
    match take_value(map, key)? {
        WireValue::Bool(value) => Ok(value),
        _ => Err(RappBindingError::InvalidInput),
    }
}

fn insert_attempt(map: &mut BTreeMap<String, WireValue>, key: &str, value: Option<u8>) {
    if let Some(value) = value {
        map.insert(key.to_owned(), WireValue::Unsigned(u64::from(value)));
    }
}

fn take_optional_attempt(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<Option<u8>, RappBindingError> {
    let Some(value) = map.remove(key) else {
        return Ok(None);
    };
    let WireValue::Unsigned(value) = value else {
        return Err(RappBindingError::InvalidInput);
    };
    u8::try_from(value)
        .map(Some)
        .map_err(|_| RappBindingError::InvalidInput)
}
