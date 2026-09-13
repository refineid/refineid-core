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

//! Strict deterministic-CBOR wire representation for RAPP.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use super::{MAX_FRAME_PLAINTEXT, SESSION_ID_SIZE, SessionId, VISIBLE_WIRE_VERSION};

const MAX_NESTING_DEPTH: usize = 8;
const MAX_TEXT_SIZE: usize = 4_096;

/// CBOR additional-information values selecting the argument width (RFC 8949 section 3).
const ARGUMENT_IMMEDIATE_MAX: u8 = 23;
const ARGUMENT_ONE_BYTE: u8 = 24;
const ARGUMENT_TWO_BYTES: u8 = 25;
const ARGUMENT_FOUR_BYTES: u8 = 26;
const ARGUMENT_EIGHT_BYTES: u8 = 27;

/// Restricted CBOR value accepted by RAPP.
///
/// Floating point, tags, indefinite lengths, and non-text map keys cannot be
/// represented. Maps are encoded in RFC 8949 deterministic key order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireValue {
    /// Non-negative integer.
    Unsigned(u64),
    /// Negative integer.
    Negative(i64),
    /// Byte string.
    Bytes(Vec<u8>),
    /// UTF-8 text string.
    Text(String),
    /// Definite-length array.
    Array(Vec<Self>),
    /// Definite-length text-keyed map.
    Map(BTreeMap<String, Self>),
    /// Boolean.
    Bool(bool),
    /// Null.
    Null,
}

/// Stable RAPP message registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Authenticated pairing peer introduction.
    PairingHello,
    /// Explicit grant confirmation.
    PairingConfirm,
    /// Authenticated pairing cancellation.
    PairingAbort,
    /// Session-ready parameter echo.
    SessionReady,
    /// Authenticated close notice.
    SessionClose,
    /// Liveness challenge.
    LivenessPing,
    /// Liveness challenge echo.
    LivenessPong,
    /// Typed credential-operation request.
    OperationRequest,
    /// Proxy readiness to execute the committed request.
    OperationPrepared,
    /// Requester's point of no return.
    OperationCommit,
    /// Operation cancellation.
    OperationCancel,
    /// Profile-defined operation result.
    OperationResult,
    /// Acknowledgment of a completed result.
    OperationResultAck,
    /// Durable status reconciliation query.
    OperationStatusRequest,
    /// Durable status reconciliation answer.
    OperationStatus,
    /// Advisory operation progress update.
    OperationProgress,
    /// Stable generic protocol error.
    Error,
}

impl MessageType {
    /// Stable text discriminant used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PairingHello => "pairing.hello",
            Self::PairingConfirm => "pairing.confirm",
            Self::PairingAbort => "pairing.abort",
            Self::SessionReady => "session.ready",
            Self::SessionClose => "session.close",
            Self::LivenessPing => "liveness.ping",
            Self::LivenessPong => "liveness.pong",
            Self::OperationRequest => "operation.request",
            Self::OperationPrepared => "operation.prepared",
            Self::OperationCommit => "operation.commit",
            Self::OperationCancel => "operation.cancel",
            Self::OperationResult => "operation.result",
            Self::OperationResultAck => "operation.result_ack",
            Self::OperationStatusRequest => "operation.status_request",
            Self::OperationStatus => "operation.status",
            Self::OperationProgress => "operation.progress",
            Self::Error => "error",
        }
    }

    fn parse(value: &str) -> Result<Self, WireError> {
        match value {
            "pairing.hello" => Ok(Self::PairingHello),
            "pairing.confirm" => Ok(Self::PairingConfirm),
            "pairing.abort" => Ok(Self::PairingAbort),
            "session.ready" => Ok(Self::SessionReady),
            "session.close" => Ok(Self::SessionClose),
            "liveness.ping" => Ok(Self::LivenessPing),
            "liveness.pong" => Ok(Self::LivenessPong),
            "operation.request" => Ok(Self::OperationRequest),
            "operation.prepared" => Ok(Self::OperationPrepared),
            "operation.commit" => Ok(Self::OperationCommit),
            "operation.cancel" => Ok(Self::OperationCancel),
            "operation.result" => Ok(Self::OperationResult),
            "operation.result_ack" => Ok(Self::OperationResultAck),
            "operation.status_request" => Ok(Self::OperationStatusRequest),
            "operation.status" => Ok(Self::OperationStatus),
            "operation.progress" => Ok(Self::OperationProgress),
            "error" => Ok(Self::Error),
            _ => Err(WireError::UnknownMessageType),
        }
    }
}

/// One decrypted RAPP envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Registered message discriminant.
    pub message_type: MessageType,
    /// Derived identifier of this authenticated channel.
    pub session_id: SessionId,
    /// Strictly increasing directional sequence.
    pub sequence: u64,
    /// Message-specific, schema-validated body.
    pub body: BTreeMap<String, WireValue>,
    /// Extensions that an endpoint must understand.
    pub critical: Vec<String>,
    /// Registered extension values.
    pub extensions: BTreeMap<String, WireValue>,
}

impl Envelope {
    /// Construct and validate an outgoing envelope.
    ///
    /// # Errors
    /// [`WireError`] when the body or extensions violate the registered
    /// schema.
    pub fn reconstruct(
        message_type: MessageType,
        session_id: SessionId,
        sequence: u64,
        body: BTreeMap<String, WireValue>,
        critical: Vec<String>,
        extensions: BTreeMap<String, WireValue>,
    ) -> Result<Self, WireError> {
        validate_body(message_type, &body)?;
        validate_extensions(&critical, &extensions)?;
        Ok(Self {
            message_type,
            session_id,
            sequence,
            body,
            critical,
            extensions,
        })
    }

    /// Encode this envelope using strict deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`] on an unencodable value or a plaintext above the
    /// single-frame limit.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut map = BTreeMap::new();
        map.insert(
            "version".to_owned(),
            WireValue::Array(vec![
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.0)),
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.1)),
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.2)),
            ]),
        );
        map.insert(
            "type".to_owned(),
            WireValue::Text(self.message_type.as_str().to_owned()),
        );
        map.insert(
            "session_id".to_owned(),
            WireValue::Bytes(self.session_id.as_bytes().to_vec()),
        );
        map.insert("sequence".to_owned(), WireValue::Unsigned(self.sequence));
        map.insert("body".to_owned(), WireValue::Map(self.body.clone()));
        if !self.critical.is_empty() {
            map.insert(
                "critical".to_owned(),
                WireValue::Array(self.critical.iter().cloned().map(WireValue::Text).collect()),
            );
        }
        if !self.extensions.is_empty() {
            map.insert(
                "extensions".to_owned(),
                WireValue::Map(self.extensions.clone()),
            );
        }
        let encoded = encode_deterministic_cbor(&WireValue::Map(map))?;
        if encoded.len() > MAX_FRAME_PLAINTEXT {
            return Err(WireError::OversizedPlaintext { got: encoded.len() });
        }
        Ok(encoded)
    }

    /// Decode and fully validate a decrypted envelope.
    ///
    /// # Errors
    /// [`WireError`] on non-deterministic CBOR, a schema violation, or an
    /// unsupported version or message type.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_FRAME_PLAINTEXT {
            return Err(WireError::OversizedPlaintext { got: bytes.len() });
        }
        let WireValue::Map(mut map) = decode_deterministic_cbor(bytes)? else {
            return Err(WireError::WrongType { field: "envelope" });
        };
        reject_unknown_fields(
            &map,
            &[
                "version",
                "type",
                "session_id",
                "sequence",
                "body",
                "critical",
                "extensions",
            ],
        )?;

        let version = take_array(&mut map, "version")?;
        if version.as_slice()
            != [
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.0)),
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.1)),
                WireValue::Unsigned(u64::from(VISIBLE_WIRE_VERSION.2)),
            ]
        {
            return Err(WireError::UnsupportedVersion);
        }
        let message_type = MessageType::parse(&take_text(&mut map, "type")?)?;
        let session_bytes = take_bytes(&mut map, "session_id")?;
        let session_id =
            SessionId::reconstruct(&session_bytes).map_err(|_| WireError::WrongLength {
                field: "session_id",
                expected: SESSION_ID_SIZE,
                got: session_bytes.len(),
            })?;
        let sequence = take_unsigned(&mut map, "sequence")?;
        let body = take_map(&mut map, "body")?;
        let critical = match map.remove("critical") {
            None => Vec::new(),
            Some(WireValue::Array(values)) => values
                .into_iter()
                .map(|value| match value {
                    WireValue::Text(text) => Ok(text),
                    _ => Err(WireError::WrongType { field: "critical" }),
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(WireError::WrongType { field: "critical" }),
        };
        let extensions = match map.remove("extensions") {
            None => BTreeMap::new(),
            Some(WireValue::Map(values)) => values,
            Some(_) => {
                return Err(WireError::WrongType {
                    field: "extensions",
                });
            }
        };
        validate_body(message_type, &body)?;
        validate_extensions(&critical, &extensions)?;
        Ok(Self {
            message_type,
            session_id,
            sequence,
            body,
            critical,
            extensions,
        })
    }

    /// Reject critical extensions unsupported by the local endpoint.
    ///
    /// # Errors
    /// [`WireError::UnsupportedCriticalExtension`] when a critical name is
    /// not supported locally.
    pub fn require_supported_critical<'a>(
        &self,
        supported: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), WireError> {
        let supported: BTreeSet<&str> = supported.into_iter().collect();
        if self
            .critical
            .iter()
            .any(|name| !supported.contains(name.as_str()))
        {
            return Err(WireError::UnsupportedCriticalExtension);
        }
        Ok(())
    }
}

/// Independent directional envelope-sequence enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceGuard {
    session_id: SessionId,
    next_send: u64,
    next_receive: u64,
}

impl SequenceGuard {
    /// Start both directions at zero for a fresh authenticated channel.
    #[must_use]
    pub const fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            next_send: 0,
            next_receive: 0,
        }
    }

    /// Allocate the only legal sequence for the next outgoing message.
    ///
    /// # Errors
    /// [`WireError`] on sequence exhaustion or an invalid body.
    pub fn next_outgoing(
        &mut self,
        message_type: MessageType,
        body: BTreeMap<String, WireValue>,
    ) -> Result<Envelope, WireError> {
        let sequence = self.next_send;
        self.next_send = self
            .next_send
            .checked_add(1)
            .ok_or(WireError::SequenceWrapped)?;
        Envelope::reconstruct(
            message_type,
            self.session_id,
            sequence,
            body,
            Vec::new(),
            BTreeMap::new(),
        )
    }

    /// Verify session binding and exact next sequence after decryption.
    ///
    /// # Errors
    /// [`WireError`] on a wrong session, a sequence violation, or sequence
    /// exhaustion.
    pub fn accept_incoming(&mut self, envelope: &Envelope) -> Result<(), WireError> {
        if envelope.session_id != self.session_id {
            return Err(WireError::WrongSession);
        }
        if envelope.sequence != self.next_receive {
            return Err(WireError::WrongSequence {
                expected: self.next_receive,
                got: envelope.sequence,
            });
        }
        self.next_receive = self
            .next_receive
            .checked_add(1)
            .ok_or(WireError::SequenceWrapped)?;
        Ok(())
    }

    /// Most recently accepted peer sequence, if any.
    #[must_use]
    pub const fn last_received_sequence(&self) -> Option<u64> {
        self.next_receive.checked_sub(1)
    }
}

/// Strict wire-format failure. Once decryption succeeded, every variant is an
/// authenticated protocol violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Input ended inside an encoded item.
    Truncated,
    /// Bytes remain after the complete top-level item.
    TrailingData,
    /// Encoding is not the deterministic form.
    NonCanonical,
    /// CBOR type outside the restricted value set.
    ForbiddenCborType,
    /// Container nesting exceeds the fixed depth limit.
    NestingTooDeep,
    /// Text string exceeds the fixed size limit.
    TextTooLong {
        /// Declared text length in bytes.
        got: usize,
    },
    /// Declared collection length cannot fit the remaining input.
    CollectionTooLarge {
        /// Declared entry count.
        got: usize,
    },
    /// Text string is not valid UTF-8.
    InvalidUtf8,
    /// Map declares the same key twice.
    DuplicateMapKey,
    /// Map key is not a text string.
    NonTextMapKey,
    /// Required field is absent.
    MissingField {
        /// Name of the absent field.
        field: &'static str,
    },
    /// Field outside the registered schema.
    UnknownField,
    /// Field carries the wrong CBOR type.
    WrongType {
        /// Name of the mistyped field.
        field: &'static str,
    },
    /// Fixed-size field has the wrong length.
    WrongLength {
        /// Name of the mis-sized field.
        field: &'static str,
        /// Registered length in bytes.
        expected: usize,
        /// Received length in bytes.
        got: usize,
    },
    /// Field value is outside its registered set.
    InvalidValue {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// Envelope version differs from the supported wire version.
    UnsupportedVersion,
    /// Message type is outside the registry.
    UnknownMessageType,
    /// A named critical extension is not supported locally.
    UnsupportedCriticalExtension,
    /// A named critical extension has no extension value.
    CriticalExtensionMissing,
    /// Plaintext exceeds the single-frame envelope limit.
    OversizedPlaintext {
        /// Plaintext length in bytes.
        got: usize,
    },
    /// Envelope names a different session than this channel.
    WrongSession,
    /// Sequence is not the exact next value for its direction.
    WrongSequence {
        /// Only legal next sequence.
        expected: u64,
        /// Received sequence.
        got: u64,
    },
    /// Directional sequence space is exhausted.
    SequenceWrapped,
    /// Value does not fit the local integer representation.
    IntegerOverflow,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid RAPP wire message")
    }
}

impl core::error::Error for WireError {}

/// Encode a restricted value using RFC 8949 core deterministic encoding.
///
/// # Errors
/// [`WireError`] on excessive nesting, an oversized text, or an unencodable
/// integer.
pub fn encode_deterministic_cbor(value: &WireValue) -> Result<Vec<u8>, WireError> {
    let mut output = Vec::new();
    encode_value(value, &mut output, 0)?;
    Ok(output)
}

/// Decode a complete, strictly deterministic RAPP CBOR value.
///
/// # Errors
/// [`WireError`] on truncated, trailing, forbidden, oversized, or
/// non-canonical input.
pub fn decode_deterministic_cbor(bytes: &[u8]) -> Result<WireValue, WireError> {
    if bytes.len() > MAX_FRAME_PLAINTEXT {
        return Err(WireError::OversizedPlaintext { got: bytes.len() });
    }
    let mut decoder = Decoder { bytes, offset: 0 };
    let value = decoder.value(0)?;
    if decoder.offset != bytes.len() {
        return Err(WireError::TrailingData);
    }
    if encode_deterministic_cbor(&value)?.as_slice() != bytes {
        return Err(WireError::NonCanonical);
    }
    Ok(value)
}

fn encode_value(value: &WireValue, output: &mut Vec<u8>, depth: usize) -> Result<(), WireError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(WireError::NestingTooDeep);
    }
    match value {
        WireValue::Unsigned(value) => encode_argument(0, *value, output),
        WireValue::Negative(value) if *value < 0 => {
            let encoded = u64::try_from(-1_i128 - i128::from(*value))
                .map_err(|_| WireError::IntegerOverflow)?;
            encode_argument(1, encoded, output);
        }
        WireValue::Negative(_) => {
            return Err(WireError::InvalidValue { field: "integer" });
        }
        WireValue::Bytes(bytes) => {
            encode_argument(2, bytes.len() as u64, output);
            output.extend_from_slice(bytes);
        }
        WireValue::Text(text) => {
            if text.len() > MAX_TEXT_SIZE {
                return Err(WireError::TextTooLong { got: text.len() });
            }
            encode_argument(3, text.len() as u64, output);
            output.extend_from_slice(text.as_bytes());
        }
        WireValue::Array(values) => {
            encode_argument(4, values.len() as u64, output);
            for value in values {
                encode_value(value, output, depth + 1)?;
            }
        }
        WireValue::Map(values) => {
            encode_argument(5, values.len() as u64, output);
            let mut ordered = values
                .iter()
                .map(|(key, value)| {
                    let encoded = encode_deterministic_cbor(&WireValue::Text(key.clone()))?;
                    Ok((encoded, value))
                })
                .collect::<Result<Vec<_>, WireError>>()?;
            ordered.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            for (key, value) in ordered {
                output.extend_from_slice(&key);
                encode_value(value, output, depth + 1)?;
            }
        }
        WireValue::Bool(false) => output.push(0xf4),
        WireValue::Bool(true) => output.push(0xf5),
        WireValue::Null => output.push(0xf6),
    }
    Ok(())
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "each arm's range bounds the value to the cast width"
)]
fn encode_argument(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | ARGUMENT_ONE_BYTE, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | ARGUMENT_TWO_BYTES);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | ARGUMENT_FOUR_BYTES);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | ARGUMENT_EIGHT_BYTES);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<WireValue, WireError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(WireError::NestingTooDeep);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(WireValue::Unsigned(self.argument(additional)?)),
            1 => {
                let argument = self.argument(additional)?;
                let value = -1_i128 - i128::from(argument);
                let value = i64::try_from(value).map_err(|_| WireError::IntegerOverflow)?;
                Ok(WireValue::Negative(value))
            }
            2 => {
                let length = self.length(additional)?;
                Ok(WireValue::Bytes(self.take(length)?.to_vec()))
            }
            3 => {
                let length = self.length(additional)?;
                if length > MAX_TEXT_SIZE {
                    return Err(WireError::TextTooLong { got: length });
                }
                let value =
                    core::str::from_utf8(self.take(length)?).map_err(|_| WireError::InvalidUtf8)?;
                Ok(WireValue::Text(value.to_owned()))
            }
            4 => {
                let length = self.bounded_collection_length(additional, 1)?;
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push(self.value(depth + 1)?);
                }
                Ok(WireValue::Array(values))
            }
            5 => {
                let length = self.bounded_collection_length(additional, 2)?;
                let mut values = BTreeMap::new();
                for _ in 0..length {
                    let WireValue::Text(key) = self.value(depth + 1)? else {
                        return Err(WireError::NonTextMapKey);
                    };
                    let value = self.value(depth + 1)?;
                    if values.insert(key, value).is_some() {
                        return Err(WireError::DuplicateMapKey);
                    }
                }
                Ok(WireValue::Map(values))
            }
            7 if additional == 20 => Ok(WireValue::Bool(false)),
            7 if additional == 21 => Ok(WireValue::Bool(true)),
            7 if additional == 22 => Ok(WireValue::Null),
            _ => Err(WireError::ForbiddenCborType),
        }
    }

    fn byte(&mut self) -> Result<u8, WireError> {
        let byte = *self.bytes.get(self.offset).ok_or(WireError::Truncated)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&[u8], WireError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WireError::IntegerOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(WireError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn length(&mut self, additional: u8) -> Result<usize, WireError> {
        usize::try_from(self.argument(additional)?).map_err(|_| WireError::IntegerOverflow)
    }

    /// Decode a collection length only after proving that its minimum encoded
    /// representation fits in the bytes still available. Every array item
    /// occupies at least one byte; every map entry has at least a one-byte key
    /// and a one-byte value. This check prevents an attacker-controlled length
    /// from reaching `Vec::with_capacity` or a long decode loop.
    fn bounded_collection_length(
        &mut self,
        additional: u8,
        minimum_bytes_per_entry: usize,
    ) -> Result<usize, WireError> {
        let length = self.length(additional)?;
        let minimum_bytes = length
            .checked_mul(minimum_bytes_per_entry)
            .ok_or(WireError::CollectionTooLarge { got: length })?;
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if minimum_bytes > remaining {
            return Err(WireError::CollectionTooLarge { got: length });
        }
        Ok(length)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, WireError> {
        let value = match additional {
            value @ 0..=ARGUMENT_IMMEDIATE_MAX => u64::from(value),
            ARGUMENT_ONE_BYTE => u64::from(self.byte()?),
            ARGUMENT_TWO_BYTES => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().map_err(|_| WireError::Truncated)?,
            )),
            ARGUMENT_FOUR_BYTES => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| WireError::Truncated)?,
            )),
            ARGUMENT_EIGHT_BYTES => {
                u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| WireError::Truncated)?)
            }
            _ => return Err(WireError::ForbiddenCborType),
        };
        let non_minimal = matches!(additional, ARGUMENT_ONE_BYTE)
            && value <= u64::from(ARGUMENT_IMMEDIATE_MAX)
            || matches!(additional, ARGUMENT_TWO_BYTES) && value <= 0xff
            || matches!(additional, ARGUMENT_FOUR_BYTES) && value <= 0xffff
            || matches!(additional, ARGUMENT_EIGHT_BYTES) && value <= 0xffff_ffff;
        if non_minimal {
            return Err(WireError::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy)]
enum FieldType {
    Unsigned,
    Bytes(usize),
    Text,
    Array,
    Map,
    Bool,
}

struct FieldSpec {
    name: &'static str,
    field_type: FieldType,
    optional: bool,
}

const OPERATION_ID: FieldType = FieldType::Bytes(16);
const REQUEST_HASH: FieldType = FieldType::Bytes(32);

#[allow(
    clippy::too_many_lines,
    reason = "the match is the complete field-spec table for every message type; splitting it would scatter the wire schema"
)]
fn validate_body(
    message_type: MessageType,
    body: &BTreeMap<String, WireValue>,
) -> Result<(), WireError> {
    use FieldType as F;
    use MessageType as M;
    let specs: &[FieldSpec] = match message_type {
        M::PairingHello => &[
            FieldSpec {
                name: "parameters",
                field_type: F::Map,
                optional: false,
            },
            FieldSpec {
                name: "display_name",
                field_type: F::Text,
                optional: false,
            },
            FieldSpec {
                name: "platform",
                field_type: F::Text,
                optional: false,
            },
            FieldSpec {
                name: "requested_profiles",
                field_type: F::Array,
                optional: true,
            },
        ],
        M::PairingConfirm => &[FieldSpec {
            name: "granted_profiles",
            field_type: F::Array,
            optional: false,
        }],
        M::PairingAbort => &[FieldSpec {
            name: "reason",
            field_type: F::Text,
            optional: false,
        }],
        M::SessionReady => &[
            FieldSpec {
                name: "parameters",
                field_type: F::Map,
                optional: false,
            },
            FieldSpec {
                name: "nonce",
                field_type: F::Bytes(32),
                optional: false,
            },
        ],
        M::SessionClose => &[
            FieldSpec {
                name: "reason",
                field_type: F::Text,
                optional: false,
            },
            FieldSpec {
                name: "last_received_sequence",
                field_type: F::Unsigned,
                optional: false,
            },
        ],
        M::LivenessPing | M::LivenessPong => &[
            FieldSpec {
                name: "challenge",
                field_type: F::Bytes(32),
                optional: false,
            },
            FieldSpec {
                name: "last_received_sequence",
                field_type: F::Unsigned,
                optional: false,
            },
        ],
        M::OperationRequest => &[
            FieldSpec {
                name: "operation_id",
                field_type: OPERATION_ID,
                optional: false,
            },
            FieldSpec {
                name: "profile",
                field_type: F::Text,
                optional: false,
            },
            FieldSpec {
                name: "action",
                field_type: F::Text,
                optional: false,
            },
            FieldSpec {
                name: "request_hash",
                field_type: REQUEST_HASH,
                optional: false,
            },
            FieldSpec {
                name: "expires_after_ms",
                field_type: F::Unsigned,
                optional: false,
            },
            FieldSpec {
                name: "context",
                field_type: F::Map,
                optional: false,
            },
            FieldSpec {
                name: "payload",
                field_type: F::Map,
                optional: false,
            },
        ],
        M::OperationPrepared | M::OperationCommit | M::OperationResultAck => &[
            FieldSpec {
                name: "operation_id",
                field_type: OPERATION_ID,
                optional: false,
            },
            FieldSpec {
                name: "request_hash",
                field_type: REQUEST_HASH,
                optional: false,
            },
        ],
        M::OperationCancel => &[
            FieldSpec {
                name: "operation_id",
                field_type: OPERATION_ID,
                optional: false,
            },
            FieldSpec {
                name: "request_hash",
                field_type: REQUEST_HASH,
                optional: false,
            },
            FieldSpec {
                name: "reason",
                field_type: F::Text,
                optional: true,
            },
        ],
        M::OperationResult => &[
            FieldSpec {
                name: "operation_id",
                field_type: OPERATION_ID,
                optional: false,
            },
            FieldSpec {
                name: "request_hash",
                field_type: REQUEST_HASH,
                optional: false,
            },
            FieldSpec {
                name: "status",
                field_type: F::Text,
                optional: false,
            },
            FieldSpec {
                name: "error",
                field_type: F::Text,
                optional: true,
            },
            FieldSpec {
                name: "body",
                field_type: F::Map,
                optional: false,
            },
        ],
        M::OperationStatusRequest => &[FieldSpec {
            name: "operation_id",
            field_type: OPERATION_ID,
            optional: false,
        }],
        M::OperationStatus => &[
            FieldSpec {
                name: "operation_id",
                field_type: OPERATION_ID,
                optional: false,
            },
            FieldSpec {
                name: "known",
                field_type: F::Bool,
                optional: false,
            },
            FieldSpec {
                name: "state",
                field_type: F::Text,
                optional: true,
            },
            FieldSpec {
                name: "request_hash",
                field_type: REQUEST_HASH,
                optional: true,
            },
        ],
        M::OperationProgress => &[
            FieldSpec {
                name: "operation_id",
                field_type: OPERATION_ID,
                optional: false,
            },
            FieldSpec {
                name: "request_hash",
                field_type: REQUEST_HASH,
                optional: false,
            },
            FieldSpec {
                name: "event",
                field_type: F::Text,
                optional: false,
            },
        ],
        M::Error => &[
            FieldSpec {
                name: "error",
                field_type: F::Text,
                optional: false,
            },
            FieldSpec {
                name: "operation_id",
                field_type: OPERATION_ID,
                optional: true,
            },
        ],
    };

    if body
        .keys()
        .any(|key| !specs.iter().any(|spec| spec.name == key))
    {
        return Err(WireError::UnknownField);
    }
    for spec in specs {
        let Some(value) = body.get(spec.name) else {
            if spec.optional {
                continue;
            }
            return Err(WireError::MissingField { field: spec.name });
        };
        validate_field(spec, value)?;
    }
    validate_discriminants(message_type, body)
}

const fn validate_field(spec: &FieldSpec, value: &WireValue) -> Result<(), WireError> {
    let valid = match spec.field_type {
        FieldType::Unsigned => matches!(value, WireValue::Unsigned(_)),
        FieldType::Bytes(length) => {
            matches!(value, WireValue::Bytes(bytes) if bytes.len() == length)
        }
        FieldType::Text => matches!(value, WireValue::Text(_)),
        FieldType::Array => matches!(value, WireValue::Array(_)),
        FieldType::Map => matches!(value, WireValue::Map(_)),
        FieldType::Bool => matches!(value, WireValue::Bool(_)),
    };
    if valid {
        Ok(())
    } else {
        Err(WireError::WrongType { field: spec.name })
    }
}

fn validate_discriminants(
    message_type: MessageType,
    body: &BTreeMap<String, WireValue>,
) -> Result<(), WireError> {
    let text = |field| match body.get(field) {
        Some(WireValue::Text(value)) => Some(value.as_str()),
        _ => None,
    };
    match message_type {
        MessageType::SessionClose => {
            if !matches!(
                text("reason"),
                Some(
                    "user_disconnect"
                        | "policy"
                        | "credential_rejected"
                        | "protocol_violation"
                        | "pairing_revoked"
                        | "shutdown"
                )
            ) {
                return Err(WireError::InvalidValue { field: "reason" });
            }
        }
        MessageType::OperationResult => {
            if !matches!(
                text("status"),
                Some(
                    "completed"
                        | "denied"
                        | "cancelled"
                        | "rejected"
                        | "credential_rejected"
                        | "ambiguous"
                )
            ) {
                return Err(WireError::InvalidValue { field: "status" });
            }
        }
        MessageType::Error if !matches!(text("error"), Some("busy" | "unknown_operation")) => {
            return Err(WireError::InvalidValue { field: "error" });
        }
        _ => {}
    }
    Ok(())
}

fn validate_extensions(
    critical: &[String],
    extensions: &BTreeMap<String, WireValue>,
) -> Result<(), WireError> {
    let mut names = BTreeSet::new();
    for name in critical {
        if !names.insert(name) {
            return Err(WireError::DuplicateMapKey);
        }
        if !extensions.contains_key(name) {
            return Err(WireError::CriticalExtensionMissing);
        }
    }
    Ok(())
}

fn reject_unknown_fields(
    map: &BTreeMap<String, WireValue>,
    known: &[&str],
) -> Result<(), WireError> {
    if map.keys().any(|key| !known.contains(&key.as_str())) {
        Err(WireError::UnknownField)
    } else {
        Ok(())
    }
}

fn take_unsigned(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<u64, WireError> {
    match map.remove(field).ok_or(WireError::MissingField { field })? {
        WireValue::Unsigned(value) => Ok(value),
        _ => Err(WireError::WrongType { field }),
    }
}

fn take_text(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<String, WireError> {
    match map.remove(field).ok_or(WireError::MissingField { field })? {
        WireValue::Text(value) => Ok(value),
        _ => Err(WireError::WrongType { field }),
    }
}

fn take_bytes(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<u8>, WireError> {
    match map.remove(field).ok_or(WireError::MissingField { field })? {
        WireValue::Bytes(value) => Ok(value),
        _ => Err(WireError::WrongType { field }),
    }
}

fn take_array(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<Vec<WireValue>, WireError> {
    match map.remove(field).ok_or(WireError::MissingField { field })? {
        WireValue::Array(value) => Ok(value),
        _ => Err(WireError::WrongType { field }),
    }
}

fn take_map(
    map: &mut BTreeMap<String, WireValue>,
    field: &'static str,
) -> Result<BTreeMap<String, WireValue>, WireError> {
    match map.remove(field).ok_or(WireError::MissingField { field })? {
        WireValue::Map(value) => Ok(value),
        _ => Err(WireError::WrongType { field }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        Envelope, MessageType, SequenceGuard, WireError, WireValue, decode_deterministic_cbor,
        encode_deterministic_cbor,
    };
    use crate::SessionId;

    #[test]
    fn deterministic_map_round_trips() {
        let mut map = BTreeMap::new();
        map.insert("longer".to_owned(), WireValue::Unsigned(2));
        map.insert("a".to_owned(), WireValue::Unsigned(1));
        let value = WireValue::Map(map);
        let encoded = encode_deterministic_cbor(&value).expect("valid value");
        assert_eq!(decode_deterministic_cbor(&encoded), Ok(value));
    }

    #[test]
    fn noncanonical_integer_is_rejected() {
        assert_eq!(
            decode_deterministic_cbor(&[0x18, 0x01]),
            Err(WireError::NonCanonical)
        );
    }

    #[test]
    fn sequence_mismatch_is_attributable_after_decryption() {
        let session = SessionId::from_array([7; 16]);
        let mut guard = SequenceGuard::new(session);
        let envelope = Envelope::reconstruct(
            MessageType::PairingAbort,
            session,
            1,
            BTreeMap::from([("reason".to_owned(), WireValue::Text("cancelled".to_owned()))]),
            Vec::new(),
            BTreeMap::new(),
        )
        .expect("valid body");
        assert_eq!(
            guard.accept_incoming(&envelope),
            Err(WireError::WrongSequence {
                expected: 0,
                got: 1
            })
        );
    }
}
