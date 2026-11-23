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

//! Command ownership paths.
//!
//! Outgoing commands have exactly two representations. Replay-safe public
//! commands use the debuggable [`CommandApdu`]; it is built through the
//! ISO 7816-4 case constructors or the typed builders in
//! [`crate::iso7816`], never from an opaque byte blob. Credential-bearing
//! commands use the separate [`CredentialCommand`]; it is zeroizing,
//! non-clonable, non-debuggable, and consumed by an at-most-once transport
//! operation.

use core::fmt;
use zeroize::ZeroizeOnDrop;

/// ISO 7816-4 short-form command header length: CLA, INS, P1, P2.
pub const APDU_HEADER_LEN: usize = 4;

/// Length of the short-form Lc field.
pub(crate) const LC_LEN: usize = 1;

/// Length of the short-form Le field.
pub(crate) const LE_LEN: usize = 1;

/// Maximum data-field length of a short-form command APDU.
pub const SHORT_APDU_DATA_MAX: usize = 255;

/// Command class byte, per FINEID S1 v4.2 section 3 and ISO 7816-4
/// section 5.4.
///
/// The secure-messaging wrap itself is applied by the PACE crate's session
/// layer; this enum picks which class byte goes on the wire before that
/// wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduClass {
    /// Plain command: no secure messaging, no chaining, logical channel 0.
    Plain,
    /// Secure messaging applies, with the command header authenticated.
    SecureMessaging,
    /// First portion of a command-chained body; the card waits for the
    /// final portion (FINEID S1 v4.2 section 3.6.2).
    ChainedFirst,
    /// Command-chained portion protected by secure messaging, with the
    /// command header authenticated (ISO/IEC 7816-4 section 5.4.1).
    ChainedSecureMessaging,
}

impl ApduClass {
    /// Class byte for [`ApduClass::Plain`].
    const CLA_PLAIN: u8 = 0x00;
    /// Class byte for [`ApduClass::SecureMessaging`].
    const CLA_SECURE_MESSAGING: u8 = 0x0C;
    /// Class byte for [`ApduClass::ChainedFirst`].
    const CLA_CHAINED_FIRST: u8 = 0x10;
    /// Class byte for [`ApduClass::ChainedSecureMessaging`]: combines
    /// command chaining with secure messaging.
    const CLA_CHAINED_SECURE_MESSAGING: u8 = Self::CLA_CHAINED_FIRST | Self::CLA_SECURE_MESSAGING;

    /// Wire byte for this class.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Plain => Self::CLA_PLAIN,
            Self::SecureMessaging => Self::CLA_SECURE_MESSAGING,
            Self::ChainedFirst => Self::CLA_CHAINED_FIRST,
            Self::ChainedSecureMessaging => Self::CLA_CHAINED_SECURE_MESSAGING,
        }
    }

    /// Promote this class byte into its ISO/IEC 7816-4 secure-messaging
    /// counterpart while preserving the command-chaining bit.
    #[must_use]
    pub const fn with_secure_messaging(self) -> Self {
        match self {
            Self::Plain | Self::SecureMessaging => Self::SecureMessaging,
            Self::ChainedFirst | Self::ChainedSecureMessaging => Self::ChainedSecureMessaging,
        }
    }
}

/// The four header bytes of an ISO 7816-4 command.
///
/// Instruction and parameter bytes are protocol-specific; callers name them
/// as constants traced to the governing specification, as this repository's
/// numeric policy enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHeader {
    /// Command class.
    pub class: ApduClass,
    /// Instruction byte (INS).
    pub instruction: u8,
    /// First parameter byte (P1).
    pub p1: u8,
    /// Second parameter byte (P2).
    pub p2: u8,
}

impl CommandHeader {
    /// The header as its four wire bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; APDU_HEADER_LEN] {
        [self.class.as_byte(), self.instruction, self.p1, self.p2]
    }
}

/// Structural reason a command data field was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandDataError {
    /// The data field was empty; case 1 or case 2 has no data field.
    Empty,
    /// The data field exceeds the short-form capacity of
    /// [`SHORT_APDU_DATA_MAX`] bytes.
    TooLong {
        /// Rejected data length in bytes.
        got: usize,
    },
}

impl fmt::Display for CommandDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("command data field cannot be empty"),
            Self::TooLong { got } => write!(
                f,
                "command data field of {got} bytes exceeds the short-form \
                 capacity of {SHORT_APDU_DATA_MAX} bytes"
            ),
        }
    }
}

impl core::error::Error for CommandDataError {}

/// One outgoing replay-safe command APDU.
///
/// The type deliberately has no constructor from raw bytes and does not
/// implement `Clone`: a command buffer is built once, through a case
/// constructor or a typed builder, and adapters transmit through a borrow.
/// The only sanctioned duplicate is the single corrected command returned
/// by [`CommandApdu::corrected_wrong_le`].
///
/// Credential-bearing commands must never pass through this type; they use
/// [`CredentialCommand`].
#[derive(Debug, PartialEq, Eq)]
pub struct CommandApdu {
    /// Wire bytes: CLA INS P1 P2, then Lc + data and/or Le by case.
    bytes: Vec<u8>,
    /// Whether a T=0 adapter may correct Le once after a wrong-Le status.
    /// Only typed, read-only case-2 builders opt in.
    wrong_le_retry: bool,
}

/// Length of a short case-2 command: header plus Le.
const SHORT_CASE_2_LEN: usize = APDU_HEADER_LEN + LE_LEN;

impl CommandApdu {
    /// Case 1: header only; no data field, no response data expected.
    #[must_use]
    pub fn case_1(header: CommandHeader) -> Self {
        Self::from_wire(header.to_bytes().to_vec())
    }

    /// Case 2: header plus Le; response data expected. An Le byte of zero
    /// asks for as many bytes as the card has, up to the short-form
    /// maximum.
    #[must_use]
    pub fn case_2(header: CommandHeader, le: u8) -> Self {
        let mut bytes = header.to_bytes().to_vec();
        bytes.push(le);
        Self::from_wire(bytes)
    }

    /// Case 3: header plus Lc and data; no response data expected.
    ///
    /// # Errors
    ///
    /// Returns [`CommandDataError`] when `data` is empty or exceeds
    /// [`SHORT_APDU_DATA_MAX`] bytes.
    pub fn case_3(header: CommandHeader, data: &[u8]) -> Result<Self, CommandDataError> {
        let lc = Self::short_form_lc(data)?;
        let mut bytes = Vec::with_capacity(APDU_HEADER_LEN + LC_LEN + data.len());
        bytes.extend_from_slice(&header.to_bytes());
        bytes.push(lc);
        bytes.extend_from_slice(data);
        Ok(Self::from_wire(bytes))
    }

    /// Case 4: header plus Lc, data, and Le; response data expected.
    ///
    /// # Errors
    ///
    /// Returns [`CommandDataError`] when `data` is empty or exceeds
    /// [`SHORT_APDU_DATA_MAX`] bytes.
    pub fn case_4(header: CommandHeader, data: &[u8], le: u8) -> Result<Self, CommandDataError> {
        let lc = Self::short_form_lc(data)?;
        let mut bytes = Vec::with_capacity(APDU_HEADER_LEN + LC_LEN + data.len() + LE_LEN);
        bytes.extend_from_slice(&header.to_bytes());
        bytes.push(lc);
        bytes.extend_from_slice(data);
        bytes.push(le);
        Ok(Self::from_wire(bytes))
    }

    /// Split a large data field into a command-chained sequence under one
    /// instruction (ISO 7816-4 section 5.1.1.1). Every command but the
    /// last sets the chaining class and carries a short-form-sized chunk;
    /// only the last carries `le` and `header`'s own class, so the card
    /// reassembles the chunks and processes the whole. A data field that
    /// already fits the short form yields a single case-4 command.
    ///
    /// The caller transmits the commands in order: each non-final command
    /// draws a success status, and the final one carries the response.
    ///
    /// # Errors
    ///
    /// Returns [`CommandDataError::Empty`] when `data` is empty.
    pub fn command_chain(
        header: CommandHeader,
        data: &[u8],
        le: u8,
    ) -> Result<Vec<Self>, CommandDataError> {
        Self::command_chain_with_max_chunk(header, data, le, SHORT_APDU_DATA_MAX)
    }

    /// Split a large data field into a command-chained sequence whose
    /// chunks never exceed `max_chunk` bytes (`1..=SHORT_APDU_DATA_MAX`).
    ///
    /// Use a chunk ceiling below [`SHORT_APDU_DATA_MAX`] when the commands
    /// may travel over short-form ISO 7816-4 secure messaging so each
    /// encrypted `DO87` + `DO97` + `DO8E` wrapper still fits in one short
    /// `Lc` octet.
    ///
    /// # Errors
    ///
    /// Returns [`CommandDataError::Empty`] when `data` is empty or
    /// `max_chunk` is zero, and [`CommandDataError::TooLong`] when
    /// `max_chunk` exceeds [`SHORT_APDU_DATA_MAX`].
    pub fn command_chain_with_max_chunk(
        header: CommandHeader,
        data: &[u8],
        le: u8,
        max_chunk: usize,
    ) -> Result<Vec<Self>, CommandDataError> {
        if data.is_empty() || max_chunk == 0 {
            return Err(CommandDataError::Empty);
        }
        if max_chunk > SHORT_APDU_DATA_MAX {
            return Err(CommandDataError::TooLong { got: max_chunk });
        }
        let mut commands = Vec::new();
        let mut chunks = data.chunks(max_chunk).peekable();
        while let Some(chunk) = chunks.next() {
            if chunks.peek().is_some() {
                let chained = CommandHeader {
                    class: ApduClass::ChainedFirst,
                    ..header
                };
                commands.push(Self::case_3(chained, chunk)?);
            } else {
                commands.push(Self::case_4(header, chunk, le)?);
            }
        }
        Ok(commands)
    }

    /// Validate a short-form data field and return its Lc byte.
    fn short_form_lc(data: &[u8]) -> Result<u8, CommandDataError> {
        if data.is_empty() {
            return Err(CommandDataError::Empty);
        }
        if data.len() > SHORT_APDU_DATA_MAX {
            return Err(CommandDataError::TooLong { got: data.len() });
        }
        match u8::try_from(data.len()) {
            Ok(lc) => Ok(lc),
            Err(_) => Err(CommandDataError::TooLong { got: data.len() }),
        }
    }

    /// Wrap wire bytes produced by an in-crate typed builder. The builders
    /// are the boundary that guarantees a well-formed command shape.
    pub(crate) const fn from_wire(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            wrong_le_retry: false,
        }
    }

    /// Mark a builder-proven short case-2 command as safe for one
    /// corrected-Le retry. Crate-private so callers cannot opt arbitrary
    /// commands into replay; the length check keeps the permission
    /// unreachable for any non-case-2 shape.
    #[must_use]
    pub(crate) fn allow_wrong_le_retry(mut self) -> Self {
        self.wrong_le_retry = self.bytes.len() == SHORT_CASE_2_LEN;
        self
    }

    /// The single corrected command permitted after a wrong-Le status.
    /// The returned command cannot be corrected again, so an adapter
    /// cannot replay indefinitely. Returns `None` for every command whose
    /// builder did not opt into the retry.
    #[must_use]
    pub fn corrected_wrong_le(&self, le: u8) -> Option<Self> {
        if !self.wrong_le_retry {
            return None;
        }
        let mut bytes = self.bytes.clone();
        let last = bytes.last_mut()?;
        *last = le;
        Some(Self {
            bytes,
            wrong_le_retry: false,
        })
    }

    /// Borrow the wire bytes for transmission.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Capacity of a credential command's data field: two stored-length
/// credential blocks. FINEID S4-1 v4.2 section 4.1 stores each PIN in a
/// twelve-byte block, and the largest credential payload carries an
/// old-and-new block pair.
pub const CREDENTIAL_BODY_MAX: usize = 24;

/// Capacity of a plain, unwrapped credential command: header, Lc, and
/// data field. Credential commands are case 3; they carry no Le.
pub const CREDENTIAL_APDU_MAX: usize = APDU_HEADER_LEN + LC_LEN + CREDENTIAL_BODY_MAX;

/// Storage capacity of a [`CredentialCommand`], sized for the largest
/// form it must hold. A secure-messaging wrap of the largest plain
/// credential command encrypts the padded data field into a `DO87`
/// object and appends a `DO8E` message-authentication object, so the
/// wrapped command is larger than the plain one; this ceiling covers
/// that worst case with headroom, and the fixed array keeps credential
/// wire off the heap where a reallocation could leave a copy.
pub const CREDENTIAL_WIRE_MAX: usize = 64;

// The wrapped-command storage must cover the plain command it may also
// hold; a shrink below that would silently truncate an assembled
// credential command.
const _CREDENTIAL_WIRE_COVERS_PLAIN: () = assert!(CREDENTIAL_WIRE_MAX >= CREDENTIAL_APDU_MAX);

/// Structural reason credential data was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialBodyError {
    /// No bytes were supplied.
    Empty,
    /// The credential data exceeds [`CREDENTIAL_BODY_MAX`] bytes.
    TooLong,
    /// The assembled wire command exceeds [`CREDENTIAL_WIRE_MAX`] bytes.
    WireTooLong,
}

impl fmt::Display for CredentialBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("credential data cannot be empty"),
            Self::TooLong => write!(
                f,
                "credential data exceeds the capacity of {CREDENTIAL_BODY_MAX} bytes"
            ),
            Self::WireTooLong => write!(
                f,
                "credential wire command exceeds the capacity of {CREDENTIAL_WIRE_MAX} bytes"
            ),
        }
    }
}

impl core::error::Error for CredentialBodyError {}

/// Unvalidated credential octets on their way to becoming a
/// [`CredentialBody`], owned in a zeroizing fixed-capacity buffer.
///
/// This is the single nominal border for raw credential bytes: an
/// assembler takes a zeroed block, writes the credential octets into its
/// [`buffer`](Self::buffer), records how many with
/// [`set_filled`](Self::set_filled), and hands the whole block to
/// [`CredentialBody::from_block`], which validates and takes custody. The
/// buffer erases on drop, so a block that is abandoned or rejected leaves
/// no residue, and no `&mut [u8]` seam carries the raw bytes across the
/// validation border. The type is not `Clone`, not `Copy`, and not
/// raw-debuggable.
#[derive(ZeroizeOnDrop)]
pub struct UnvalidatedCredentialBlock {
    /// Fixed-capacity storage; only the first `length` bytes are meant to
    /// be credential data once the assembler has filled them.
    bytes: [u8; CREDENTIAL_BODY_MAX],
    /// Count of leading octets the assembler declared as credential data.
    length: usize,
}

impl Default for UnvalidatedCredentialBlock {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl UnvalidatedCredentialBlock {
    /// A zeroed block for an assembler to fill in place.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            bytes: [0_u8; CREDENTIAL_BODY_MAX],
            length: 0,
        }
    }

    /// The writable octet buffer. The assembler writes the credential
    /// octets from the start and then declares their count with
    /// [`set_filled`](Self::set_filled).
    pub const fn buffer(&mut self) -> &mut [u8; CREDENTIAL_BODY_MAX] {
        &mut self.bytes
    }

    /// Declare how many leading octets are credential data. A count past
    /// the buffer is preserved verbatim and rejected by
    /// [`CredentialBody::from_block`] rather than silently truncated.
    pub const fn set_filled(&mut self, length: usize) {
        self.length = length;
    }
}

impl fmt::Debug for UnvalidatedCredentialBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnvalidatedCredentialBlock([redacted])")
    }
}

/// Validated data field of one credential command.
///
/// Construction takes custody from an [`UnvalidatedCredentialBlock`],
/// which erases its own buffer on drop, so no raw credential representation
/// lingers beside the typed body. The type is not `Clone`, not `Copy`, not
/// raw-debuggable, and zeroizes its own storage on drop.
#[derive(ZeroizeOnDrop)]
pub struct CredentialBody {
    /// Fixed-capacity storage; only the first `length` bytes are wire
    /// data.
    bytes: [u8; CREDENTIAL_BODY_MAX],
    /// Wire data length in bytes.
    length: u8,
}

impl CredentialBody {
    /// Take custody of an assembled credential block. Validates the
    /// declared length and copies the credential octets into fixed-capacity
    /// storage; the block's own buffer erases when it drops at the end of
    /// this call.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialBodyError::Empty`] when the block declares no
    /// octets, or [`CredentialBodyError::TooLong`] when it declares more
    /// than [`CREDENTIAL_BODY_MAX`].
    pub fn from_block(block: UnvalidatedCredentialBlock) -> Result<Self, CredentialBodyError> {
        let declared = block.length;
        if declared == 0 {
            return Err(CredentialBodyError::Empty);
        }
        if declared > CREDENTIAL_BODY_MAX {
            return Err(CredentialBodyError::TooLong);
        }
        // The guard above bounds the conversion and the slice; the fallible
        // form keeps an `as` cast from silently truncating the length.
        let length = u8::try_from(declared).map_err(|_overflow| CredentialBodyError::TooLong)?;
        let mut bytes = [0_u8; CREDENTIAL_BODY_MAX];
        bytes[..declared].copy_from_slice(&block.bytes[..declared]);
        Ok(Self { bytes, length })
    }

    /// Number of wire data bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    /// `false` by construction; retained for idiomatic pairing with
    /// [`CredentialBody::len`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl fmt::Debug for CredentialBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialBody([redacted])")
    }
}

/// One credential-bearing command APDU.
///
/// This is the second ownership path mandated by the migration policy: a
/// zeroizing, non-clonable type whose debug rendering is redacted, consumed
/// exactly once by
/// [`CardTransport::transmit_credential`](crate::transport::CardTransport::transmit_credential).
/// It never enters generic tracing before redaction, and no raw-byte
/// accessor exists; the only wire access is the consuming
/// [`CredentialCommand::expose_wire`].
#[derive(ZeroizeOnDrop)]
pub struct CredentialCommand {
    /// Fixed-capacity wire storage; only the first `length` bytes are the
    /// command.
    bytes: [u8; CREDENTIAL_WIRE_MAX],
    /// Wire length in bytes.
    length: u8,
}

/// Wire bytes preceding the data field of a credential command: the header
/// and the Lc byte.
const CREDENTIAL_WIRE_PREFIX: u8 = 5;

impl CredentialCommand {
    /// Assemble a case-3 credential command from a header and a validated
    /// data field. The body is consumed; its storage zeroizes on drop.
    #[must_use]
    pub fn assemble(header: CommandHeader, body: CredentialBody) -> Self {
        let mut bytes = [0_u8; CREDENTIAL_WIRE_MAX];
        bytes[..APDU_HEADER_LEN].copy_from_slice(&header.to_bytes());
        bytes[APDU_HEADER_LEN] = body.length;
        let data_len = usize::from(body.length);
        let body_start = APDU_HEADER_LEN + LC_LEN;
        bytes[body_start..body_start + data_len].copy_from_slice(&body.bytes[..data_len]);
        let length = CREDENTIAL_WIRE_PREFIX + body.length;
        Self { bytes, length }
    }

    /// Assemble the secure-messaging-protected form of a credential
    /// command from the parts its wrap produces: the secure-messaging
    /// header, the protected body objects, and the expected-length byte.
    /// The result is the case-4 wire to send to the card, and it lives
    /// only in this type's zeroizing storage -- the wrapped credential wire
    /// never passes through an ordinary [`CommandApdu`] or a heap copy on
    /// the way here.
    ///
    /// `body` is the already-protected wire (the encrypted, authenticated
    /// objects); it is read, not retained. The caller owns its buffer and
    /// its erasure, holding it in a zeroizing buffer for its lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialBodyError::Empty`] when `body` is empty, or
    /// [`CredentialBodyError::WireTooLong`] when the assembled wire exceeds
    /// [`CREDENTIAL_WIRE_MAX`] bytes.
    pub fn from_protected_parts(
        header: CommandHeader,
        body: &[u8],
        le: u8,
    ) -> Result<Self, CredentialBodyError> {
        if body.is_empty() {
            return Err(CredentialBodyError::Empty);
        }
        let total = APDU_HEADER_LEN
            .checked_add(LC_LEN)
            .and_then(|n| n.checked_add(body.len()))
            .and_then(|n| n.checked_add(LE_LEN))
            .filter(|&n| n <= CREDENTIAL_WIRE_MAX)
            .ok_or(CredentialBodyError::WireTooLong)?;
        // The capacity guard above bounds both conversions; they are
        // fallible so no `as` cast can silently truncate the wire.
        let lc = u8::try_from(body.len()).map_err(|_overflow| CredentialBodyError::WireTooLong)?;
        let length = u8::try_from(total).map_err(|_overflow| CredentialBodyError::WireTooLong)?;
        let mut bytes = [0_u8; CREDENTIAL_WIRE_MAX];
        bytes[..APDU_HEADER_LEN].copy_from_slice(&header.to_bytes());
        bytes[APDU_HEADER_LEN] = lc;
        let body_start = APDU_HEADER_LEN + LC_LEN;
        bytes[body_start..body_start + body.len()].copy_from_slice(body);
        bytes[body_start + body.len()] = le;
        Ok(Self { bytes, length })
    }

    /// Wire length of the assembled command in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    /// `false` by construction; retained for idiomatic pairing with
    /// [`CredentialCommand::len`].
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Consume the command and expose its wire bytes to a transport
    /// adapter for one transmission.
    ///
    /// The storage zeroizes when the call returns. The adapter must hand
    /// the bytes to its send path without retaining a copy, must zeroize
    /// any scratch buffer it fills from them, and must never route them
    /// through logging or tracing.
    pub fn expose_wire<R>(self, adapter_send: impl FnOnce(&[u8]) -> R) -> R {
        let wire_len = usize::from(self.length);
        adapter_send(&self.bytes[..wire_len])
    }
}

impl fmt::Debug for CredentialCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialCommand([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        APDU_HEADER_LEN, ApduClass, CREDENTIAL_APDU_MAX, CREDENTIAL_BODY_MAX, CREDENTIAL_WIRE_MAX,
        CommandApdu, CommandDataError, CommandHeader, CredentialBody, CredentialBodyError,
        CredentialCommand, LC_LEN, LE_LEN, SHORT_APDU_DATA_MAX, UnvalidatedCredentialBlock,
    };

    /// Assemble a credential block from octets that fit the capacity, for
    /// the border tests.
    fn credential_block(octets: &[u8]) -> UnvalidatedCredentialBlock {
        let mut block = UnvalidatedCredentialBlock::zeroed();
        block.buffer()[..octets.len()].copy_from_slice(octets);
        block.set_filled(octets.len());
        block
    }

    /// Synthetic instruction byte for shape tests. The value has no
    /// protocol meaning; command semantics are out of scope here.
    const TEST_INS: u8 = 0xEE;
    /// Synthetic P1 byte for shape tests.
    const TEST_P1: u8 = 0x01;
    /// Synthetic P2 byte for shape tests.
    const TEST_P2: u8 = 0x02;
    /// Synthetic Le byte for case-2 and case-4 shape tests.
    const TEST_LE: u8 = 0x10;
    /// Corrected Le reported by a card via a wrong-Le status.
    const CORRECTED_LE: u8 = 0x2C;
    /// Data length above the short-form capacity.
    const OVER_SHORT_CAPACITY: usize = SHORT_APDU_DATA_MAX + 1;
    /// Data length above the credential-body capacity.
    const OVER_CREDENTIAL_CAPACITY: usize = CREDENTIAL_BODY_MAX + 1;
    /// Filler byte for the command-chaining shape tests.
    const CHAIN_FILL: u8 = 0x5A;
    /// Tail chunk length for the two-command chaining test, so the total
    /// data field spans one full short-form chunk plus this tail.
    const CHAIN_TAIL_LEN: usize = 130;
    /// Commands a two-chunk chain produces.
    const TWO_CHUNKS: usize = 2;
    /// A data length that fits the short form in one command.
    const SHORT_FIELD_LEN: usize = 8;

    fn header() -> CommandHeader {
        CommandHeader {
            class: ApduClass::Plain,
            instruction: TEST_INS,
            p1: TEST_P1,
            p2: TEST_P2,
        }
    }

    fn expected_prefix() -> Vec<u8> {
        vec![ApduClass::Plain.as_byte(), TEST_INS, TEST_P1, TEST_P2]
    }

    #[test]
    fn command_chain_splits_a_large_field_across_the_chaining_class() {
        let data = vec![CHAIN_FILL; SHORT_APDU_DATA_MAX + CHAIN_TAIL_LEN];
        let chain =
            CommandApdu::command_chain(header(), &data, TEST_LE).expect("non-empty data chains");
        assert_eq!(chain.len(), TWO_CHUNKS);

        // First command: chaining class, a full short-form chunk, no Le.
        let first = chain[0].as_bytes();
        assert_eq!(first[0], ApduClass::ChainedFirst.as_byte());
        assert_eq!(first[1], TEST_INS);
        assert_eq!(usize::from(first[APDU_HEADER_LEN]), SHORT_APDU_DATA_MAX);
        assert_eq!(first.len(), APDU_HEADER_LEN + LC_LEN + SHORT_APDU_DATA_MAX);

        // Last command: the header's own (plain) class, the tail, then Le.
        let last = chain[1].as_bytes();
        assert_eq!(last[0], ApduClass::Plain.as_byte());
        assert_eq!(usize::from(last[APDU_HEADER_LEN]), CHAIN_TAIL_LEN);
        assert_eq!(last.last().copied(), Some(TEST_LE));
    }

    #[test]
    fn command_chain_of_a_short_field_is_a_single_case_4() {
        let data = vec![CHAIN_FILL; SHORT_FIELD_LEN];
        let chain = CommandApdu::command_chain(header(), &data, TEST_LE).expect("chains");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].as_bytes()[0], ApduClass::Plain.as_byte());
        assert_eq!(chain[0].as_bytes().last().copied(), Some(TEST_LE));
    }

    #[test]
    fn command_chain_rejects_empty_data() {
        let result = CommandApdu::command_chain(header(), &[], TEST_LE);
        assert_eq!(result, Err(CommandDataError::Empty));
    }

    #[test]
    fn apdu_class_with_secure_messaging_preserves_chaining_bit() {
        assert_eq!(
            ApduClass::Plain.with_secure_messaging(),
            ApduClass::SecureMessaging
        );
        assert_eq!(
            ApduClass::SecureMessaging.with_secure_messaging(),
            ApduClass::SecureMessaging
        );
        assert_eq!(
            ApduClass::ChainedFirst.with_secure_messaging(),
            ApduClass::ChainedSecureMessaging
        );
        assert_eq!(
            ApduClass::ChainedSecureMessaging.with_secure_messaging(),
            ApduClass::ChainedSecureMessaging
        );
        assert_eq!(
            ApduClass::ChainedSecureMessaging.as_byte(),
            ApduClass::ChainedFirst.as_byte() | ApduClass::SecureMessaging.as_byte()
        );
    }

    #[test]
    fn command_chain_with_max_chunk_respects_custom_ceiling() {
        const CUSTOM_CHUNK: usize = 223;
        const CUSTOM_TAIL: usize = 162;
        let data = vec![CHAIN_FILL; CUSTOM_CHUNK + CUSTOM_TAIL];
        let chain =
            CommandApdu::command_chain_with_max_chunk(header(), &data, TEST_LE, CUSTOM_CHUNK)
                .expect("custom ceiling chains");
        assert_eq!(chain.len(), TWO_CHUNKS);
        assert_eq!(chain[0].as_bytes()[0], ApduClass::ChainedFirst.as_byte());
        assert_eq!(
            usize::from(chain[0].as_bytes()[APDU_HEADER_LEN]),
            CUSTOM_CHUNK
        );
        assert_eq!(chain[1].as_bytes()[0], ApduClass::Plain.as_byte());
        assert_eq!(
            usize::from(chain[1].as_bytes()[APDU_HEADER_LEN]),
            CUSTOM_TAIL
        );
        assert_eq!(
            CommandApdu::command_chain_with_max_chunk(header(), &data, TEST_LE, 0),
            Err(CommandDataError::Empty)
        );
        assert_eq!(
            CommandApdu::command_chain_with_max_chunk(
                header(),
                &data,
                TEST_LE,
                OVER_SHORT_CAPACITY,
            ),
            Err(CommandDataError::TooLong {
                got: OVER_SHORT_CAPACITY,
            })
        );
    }

    #[test]
    fn apdu_class_bytes_are_distinct() {
        assert_eq!(ApduClass::Plain.as_byte(), 0);
        assert!(ApduClass::Plain.as_byte() != ApduClass::SecureMessaging.as_byte());
        assert!(ApduClass::SecureMessaging.as_byte() != ApduClass::ChainedFirst.as_byte());
    }

    #[test]
    fn case_1_is_header_only() {
        let apdu = CommandApdu::case_1(header());
        assert_eq!(apdu.as_bytes(), expected_prefix().as_slice());
        assert_eq!(apdu.as_bytes().len(), APDU_HEADER_LEN);
    }

    #[test]
    fn case_2_appends_le() {
        let apdu = CommandApdu::case_2(header(), TEST_LE);
        let mut expected = expected_prefix();
        expected.push(TEST_LE);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn case_3_appends_lc_and_data() -> Result<(), CommandDataError> {
        let data = [TEST_P1, TEST_P2, TEST_LE];
        let apdu = CommandApdu::case_3(header(), &data)?;
        let mut expected = expected_prefix();
        expected.push(u8::try_from(data.len()).expect("fixture data fits an Lc byte"));
        expected.extend_from_slice(&data);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
        Ok(())
    }

    #[test]
    fn case_4_appends_lc_data_and_le() -> Result<(), CommandDataError> {
        let data = [TEST_P1, TEST_P2];
        let apdu = CommandApdu::case_4(header(), &data, TEST_LE)?;
        let mut expected = expected_prefix();
        expected.push(u8::try_from(data.len()).expect("fixture data fits an Lc byte"));
        expected.extend_from_slice(&data);
        expected.push(TEST_LE);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
        Ok(())
    }

    #[test]
    fn data_field_boundaries_are_enforced() {
        assert!(matches!(
            CommandApdu::case_3(header(), &[]),
            Err(CommandDataError::Empty)
        ));
        let max = vec![TEST_P1; SHORT_APDU_DATA_MAX];
        assert!(CommandApdu::case_3(header(), &max).is_ok());
        let over = vec![TEST_P1; OVER_SHORT_CAPACITY];
        assert!(matches!(
            CommandApdu::case_3(header(), &over),
            Err(CommandDataError::TooLong {
                got: OVER_SHORT_CAPACITY
            })
        ));
        assert!(matches!(
            CommandApdu::case_4(header(), &[], TEST_LE),
            Err(CommandDataError::Empty)
        ));
    }

    #[test]
    fn wrong_le_correction_requires_builder_opt_in() {
        let plain = CommandApdu::case_2(header(), TEST_LE);
        assert!(plain.corrected_wrong_le(CORRECTED_LE).is_none());

        let retryable = CommandApdu::case_2(header(), TEST_LE).allow_wrong_le_retry();
        let corrected = retryable
            .corrected_wrong_le(CORRECTED_LE)
            .expect("builder opted the case-2 command into one correction");
        let mut expected = expected_prefix();
        expected.push(CORRECTED_LE);
        assert_eq!(corrected.as_bytes(), expected.as_slice());
        assert!(
            corrected.corrected_wrong_le(TEST_LE).is_none(),
            "a corrected command cannot be corrected again"
        );
    }

    #[test]
    fn wrong_le_opt_in_is_unreachable_for_non_case_2_shapes() {
        let data = [TEST_P1];
        let case_3 = CommandApdu::case_3(header(), &data)
            .expect("fixture data fits an Lc byte")
            .allow_wrong_le_retry();
        assert!(case_3.corrected_wrong_le(CORRECTED_LE).is_none());
    }

    #[test]
    fn credential_body_takes_custody_of_a_block() {
        let octets = [TEST_P1, TEST_P2, TEST_LE];
        let body =
            CredentialBody::from_block(credential_block(&octets)).expect("fixture length is valid");
        assert_eq!(body.len(), octets.len());
        assert!(!body.is_empty());
    }

    #[test]
    fn credential_body_boundaries_are_enforced() {
        assert!(matches!(
            CredentialBody::from_block(UnvalidatedCredentialBlock::zeroed()),
            Err(CredentialBodyError::Empty)
        ));

        let full = [TEST_P1; CREDENTIAL_BODY_MAX];
        assert!(CredentialBody::from_block(credential_block(&full)).is_ok());

        // A block that declares more octets than fit is refused, not read
        // out of bounds and not truncated.
        let mut over = UnvalidatedCredentialBlock::zeroed();
        over.set_filled(OVER_CREDENTIAL_CAPACITY);
        assert!(matches!(
            CredentialBody::from_block(over),
            Err(CredentialBodyError::TooLong)
        ));
    }

    #[test]
    fn credential_command_assembles_a_case_3_wire_shape() {
        let octets = [TEST_P1, TEST_P2];
        let data_len = octets.len();
        let body =
            CredentialBody::from_block(credential_block(&octets)).expect("fixture length is valid");
        let command = CredentialCommand::assemble(header(), body);
        assert_eq!(command.len(), APDU_HEADER_LEN + LC_LEN + data_len);
        assert!(!command.is_empty());
        assert!(command.len() <= CREDENTIAL_APDU_MAX);

        command.expose_wire(|wire| {
            let mut expected = expected_prefix();
            expected.push(u8::try_from(data_len).expect("fixture data fits an Lc byte"));
            expected.extend_from_slice(&octets);
            assert_eq!(wire, expected.as_slice());
        });
    }

    #[test]
    fn credential_types_debug_is_always_redacted() {
        assert_eq!(
            format!("{:?}", UnvalidatedCredentialBlock::zeroed()),
            "UnvalidatedCredentialBlock([redacted])"
        );

        let body = CredentialBody::from_block(credential_block(&[TEST_P1, TEST_P2]))
            .expect("fixture length is valid");
        assert_eq!(format!("{body:?}"), "CredentialBody([redacted])");

        let command = CredentialCommand::assemble(header(), body);
        assert_eq!(format!("{command:?}"), "CredentialCommand([redacted])");
    }

    #[test]
    fn credential_capacity_covers_a_block_pair_and_nothing_more() {
        assert_eq!(
            CREDENTIAL_APDU_MAX,
            APDU_HEADER_LEN + LC_LEN + CREDENTIAL_BODY_MAX
        );
        assert_eq!(
            usize::from(super::CREDENTIAL_WIRE_PREFIX),
            APDU_HEADER_LEN + LC_LEN
        );
        assert_eq!(LE_LEN, LC_LEN);
    }

    #[test]
    fn protected_parts_assemble_the_case_4_wire() {
        let body = [TEST_P1, TEST_P2, TEST_INS];
        let command = CredentialCommand::from_protected_parts(header(), &body, TEST_LE)
            .expect("within capacity");
        assert_eq!(
            command.len(),
            APDU_HEADER_LEN + LC_LEN + body.len() + LE_LEN
        );
        assert!(!command.is_empty());

        command.expose_wire(|wire| {
            let mut expected = expected_prefix();
            expected.push(u8::try_from(body.len()).expect("fixture body fits an Lc byte"));
            expected.extend_from_slice(&body);
            expected.push(TEST_LE);
            assert_eq!(wire, expected.as_slice());
        });
    }

    #[test]
    fn protected_parts_boundaries_are_enforced() {
        assert!(matches!(
            CredentialCommand::from_protected_parts(header(), &[], TEST_LE),
            Err(CredentialBodyError::Empty)
        ));

        // A body that overflows the fixed wire capacity is refused, not
        // truncated.
        let over = vec![TEST_P1; CREDENTIAL_WIRE_MAX];
        assert!(matches!(
            CredentialCommand::from_protected_parts(header(), &over, TEST_LE),
            Err(CredentialBodyError::WireTooLong)
        ));
    }

    #[test]
    fn credential_body_error_format_does_not_leak_candidate_length() {
        let empty = CredentialBodyError::Empty;
        assert_eq!(format!("{empty}"), "credential data cannot be empty");
        assert_eq!(format!("{empty:?}"), "Empty");

        let too_long = CredentialBodyError::TooLong;
        assert_eq!(
            format!("{too_long}"),
            format!("credential data exceeds the capacity of {CREDENTIAL_BODY_MAX} bytes")
        );
        assert_eq!(format!("{too_long:?}"), "TooLong");

        let wire_too_long = CredentialBodyError::WireTooLong;
        assert_eq!(
            format!("{wire_too_long}"),
            format!("credential wire command exceeds the capacity of {CREDENTIAL_WIRE_MAX} bytes")
        );
        assert_eq!(format!("{wire_too_long:?}"), "WireTooLong");
    }
}
