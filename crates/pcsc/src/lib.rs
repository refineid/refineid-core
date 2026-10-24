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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! PC/SC smart card adapter that implements [`ReaderBackend`] and
//! [`refineid_apdu::CardTransport`] over the cross-platform `pcsc` crate.
//!
//! Two T=0 transport conventions live here rather than leaking up
//! into use cases:
//!
//! - **`SW=61xx` `GET RESPONSE` chaining.** The card signals "more
//!   bytes available, ask with `Le=xx`". The adapter loops until
//!   the chain terminates and surfaces a single concatenated
//!   body to the caller.
//! - **`SW=6Cxx` wrong-Le retry.** A typed read-only case-2
//!   command may be corrected and resent exactly once via
//!   [`CommandApdu::corrected_wrong_le`]. Credential-bearing commands
//!   treat `6Cxx` as terminal and never retry.
//!
//! Both paths are bounded so a pathological card cannot deadlock
//! the session: the correction permission is consumed by its one
//! use, and the `61xx` chain is bounded by progress plus the
//! `EXTENDED_RESPONSE_DATA_MAX_BYTES` ceiling.
//!
//! ATR and status snapshots are taken with `SCardGetStatusChange`
//! and `SCardStatus2` so the same handle can be reused across
//! many `transmit` calls without an `SCardReconnect`.
//!
//! Every card is connected in shared mode, and the access
//! capability a session is opened with decides what may travel
//! on it:
//!
//! - A [`ReaderAccessCap::Read`] session carries replay-safe
//!   commands only. Each APDU runs in its own PC/SC transaction
//!   (`SCardBeginTransaction`/`SCardEndTransaction` via the
//!   `pcsc` crate's `Card::transaction()`), so one command stream
//!   is atomic against concurrent peers. A credential command is
//!   refused on it.
//! - A [`ReaderAccessCap::PinSequence`] session carries a
//!   credential only inside [`PcscCard::pin_sequence`]: one PC/SC
//!   transaction spans the whole sequence (application selection,
//!   counter probe, VERIFY and the key operation), the transaction
//!   ends with a card reset so no verified state outlives it, and
//!   the handle is released. No other PC/SC client can interleave
//!   a command between the VERIFY and the operation it authorizes,
//!   or use the verified state afterwards.

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::ffi::CString;

use pcsc::{
    Card, Context, Disposition, Protocol, Protocols, ReaderState, Scope, ShareMode, State,
    Transaction,
};

use refineid_apdu::iso7816::GetResponse;
use refineid_apdu::{
    ApduClass, CardTransport, CommandApdu, CredentialCommand, ResponseApdu, TransportErrorExt,
    TransportErrorKind, TransportOutcome,
};
use refineid_atr::{Atr, AtrError};

/// Receive-buffer size for one PC/SC `transmit` call, sized to
/// hold the ISO 7816-4 extended-length APDU max response data
/// field. ISO 7816-4 §5.3.2 caps the extended Le response at
/// `2^16` bytes (encoded as `00 00 00` in the trailing Le); the
/// 2-byte trailing SW1 SW2 lives outside the data field for the
/// purposes of PC/SC's `transmit` accounting. Allocated on the
/// heap so transmitting a max-length response cannot stack-bust
/// on embedded targets.
const EXTENDED_RESPONSE_DATA_MAX_BYTES: usize = 1 << 16;

/// ISO 7816-3 T=0 procedure-byte `SW1` prefixes the transport loop
/// acts on. `61xx` -- more response bytes available; drive
/// `GET RESPONSE` with `SW2` as `Le`. `6Cxx` -- wrong `Le`; resend
/// the same command with `SW2` as the corrected `Le`. Every other
/// `SW1` is terminal and handed back to the caller.
const SW1_BYTES_AVAILABLE: u8 = 0x61;
/// See [`SW1_BYTES_AVAILABLE`]: `6Cxx` wrong-`Le` retry prefix.
const SW1_WRONG_LE: u8 = 0x6C;

/// Convert one short ISO 7816 case-4 command into the case-3 command
/// Windows PC/SC accepts for T=0. The card then announces the response
/// with `61xx`, which [`run_t0_exchange`] continues with `GET RESPONSE`.
///
/// Returns `None` for case-1/2/3 commands and extended-length shapes.
fn t0_case3_from_short_case4(apdu: &[u8]) -> Option<Vec<u8>> {
    const HEADER_AND_LC_BYTES: usize = 5;
    const TRAILING_LE_BYTES: usize = 1;

    let lc = usize::from(*apdu.get(4)?);
    if lc == 0 {
        return None;
    }
    let case4_len = HEADER_AND_LC_BYTES
        .checked_add(lc)?
        .checked_add(TRAILING_LE_BYTES)?;
    if apdu.len() != case4_len {
        return None;
    }
    Some(apdu[..apdu.len() - 1].to_vec())
}

// ----- Errors -----

/// PC/SC adapter errors.
#[derive(Debug)]
pub enum PcscError {
    /// Underlying `pcsc` crate error (`SCardConnect` /
    /// `SCardTransmit` / `SCardGetStatusChange` / ...).
    Pcsc(pcsc::Error),
    /// Transport-layer logic error with no direct `pcsc::Error`
    /// counterpart (response shorter than 2 bytes, retry-loop
    /// ceiling exceeded, etc.).
    Transport(String),
    /// A credential command was offered outside a PIN-sequence
    /// transaction. Credentials travel only inside
    /// [`PcscCard::pin_sequence`].
    CredentialOutsideTransaction,
    /// [`PcscCard::pin_sequence`] was asked of a session opened
    /// for card-public reads.
    NotAPinSession,
}

impl From<pcsc::Error> for PcscError {
    fn from(e: pcsc::Error) -> Self {
        Self::Pcsc(e)
    }
}

impl core::fmt::Display for PcscError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pcsc(e) => write!(f, "PCSC: {e}"),
            Self::Transport(s) => write!(f, "PCSC transport: {s}"),
            Self::CredentialOutsideTransaction => {
                f.write_str("PCSC: credential command outside a PIN-sequence transaction")
            }
            Self::NotAPinSession => f.write_str("PCSC: PIN sequence on a read-only session"),
        }
    }
}

impl core::error::Error for PcscError {}

impl TransportErrorExt for PcscError {
    fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Pcsc(pcsc::Error::NoSmartcard) => TransportErrorKind::NoCard,
            Self::Pcsc(pcsc::Error::RemovedCard) => TransportErrorKind::ReaderRemoved,
            Self::Pcsc(pcsc::Error::ResetCard) => TransportErrorKind::CardReset,
            Self::Transport(_)
            | Self::Pcsc(_)
            | Self::CredentialOutsideTransaction
            | Self::NotAPinSession => TransportErrorKind::Backend,
        }
    }
}

// ----- Context + enumeration helpers -----

/// Establish a fresh PC/SC user-scope context.
///
/// # Errors
/// PC/SC service unavailable or platform-level failure.
pub fn establish_context() -> Result<Context, PcscError> {
    Ok(Context::establish(Scope::User)?)
}

/// Enumerate reader names. Returns an empty `Vec` when no
/// readers are connected (rather than the `NoReadersAvailable`
/// PC/SC error), so callers can treat "no readers" as a normal
/// empty-state.
///
/// # Errors
/// PC/SC service errors other than `NoReadersAvailable`.
pub(crate) fn list_readers(ctx: &Context) -> Result<Vec<String>, PcscError> {
    let mut buffer = [0_u8; 4096];
    let readers = match ctx.list_readers(&mut buffer) {
        Ok(it) => it,
        Err(pcsc::Error::NoReadersAvailable) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(readers.map(|r| r.to_string_lossy().into_owned()).collect())
}

/// Connect to a card on `cstr`, falling back to single-protocol
/// offers if multi-protocol negotiation fails.
///
/// The multi-protocol mask (`Protocols::ANY`) is offered first,
/// the normal desktop path. A no-name "Generic EMV Smartcard
/// Reader" (field-observed 2026-08-12) botches that negotiation
/// and reports the card unresponsive, yet connects cleanly when
/// offered one protocol at a time -- so on exactly the
/// `UnresponsiveCard` failure the connect is retried with T=0
/// then T=1 before giving up. `Ok(None)` means the slot is empty.
fn connect_resilient(ctx: &Context, cstr: &CString) -> Result<Option<Card>, PcscError> {
    for protocols in [Protocols::ANY, Protocols::T0, Protocols::T1] {
        match ctx.connect(cstr, ShareMode::Shared, protocols) {
            Ok(card) => return Ok(Some(card)),
            Err(pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard) => return Ok(None),
            // Fall through to the next, narrower protocol offer
            // only on the unresponsive-reset failure the flaky
            // firmware raises.
            Err(pcsc::Error::UnresponsiveCard) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(PcscError::Pcsc(pcsc::Error::UnresponsiveCard))
}

/// Open a card on `reader` in shared mode, for `access`.
///
/// Returns `Ok(Some(_))` when a card is present, `Ok(None)`
/// when the reader is empty / just removed. Callers translate
/// `None` into "slot present, token absent".
///
/// The connection is shared with PC/SC's normal arbitration.
/// Every replay-safe APDU runs inside its own transaction; a
/// PIN sequence runs inside one transaction for all of its
/// commands (see [`PcscCard::pin_sequence`]).
///
/// # Errors
/// Reader name has interior NUL, PC/SC connect failure other
/// than "no card present", or status query failure.
pub(crate) fn connect(
    ctx: &Context,
    reader: &str,
    access: ReaderAccessCap,
) -> Result<Option<PcscCard>, PcscError> {
    let cstr = CString::new(reader)
        .map_err(|e| PcscError::Transport(format!("reader name has interior NUL: {e}")))?;
    let card = match connect_resilient(ctx, &cstr) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut names_buf = [0_u8; 256];
    let mut atr_buf = [0_u8; pcsc::MAX_ATR_SIZE];
    let status = card.status2(&mut names_buf, &mut atr_buf)?;
    let atr = status.atr().to_vec();
    let protocol = status
        .protocol2()
        .ok_or_else(|| PcscError::Transport("connected card has no active protocol".into()))?;
    Ok(Some(PcscCard {
        card,
        atr,
        protocol,
        access,
    }))
}

// ----- Connected card -----

/// The single-protocol `Protocols` mask for an already-negotiated
/// [`Protocol`], for a reconnect that must not renegotiate.
pub(crate) const fn protocols_mask(protocol: Protocol) -> Protocols {
    match protocol {
        Protocol::T1 => Protocols::T1,
        // T=0 and the raw/undefined shapes reconnect as T=0; a
        // FINEID card is contact T=0 or contactless-as-T=1, both
        // covered by this and the `other_protocols_mask` fallback.
        Protocol::T0 | Protocol::RAW => Protocols::T0,
    }
}

/// The opposite single-protocol mask, tried when a reconnect on
/// the active protocol still reports the card unresponsive.
pub(crate) const fn other_protocols_mask(protocol: Protocol) -> Protocols {
    match protocol {
        Protocol::T1 => Protocols::T0,
        Protocol::T0 | Protocol::RAW => Protocols::T1,
    }
}

/// Connected card wrapped around a `pcsc::Card`, opened with one
/// [`ReaderAccessCap`].
///
/// Replay-safe commands run one PC/SC transaction each. A
/// credential command is refused on this type; it travels only
/// inside [`PcscCard::pin_sequence`], which a `PinSequence`
/// session alone can enter. Dropping the card releases the
/// handle through the `pcsc` crate's `Card` drop, which is
/// `SCardDisconnect(SCARD_RESET_CARD)`.
pub struct PcscCard {
    /// Owned `pcsc::Card` handle.
    card: Card,
    /// Card's Answer-To-Reset bytes, captured at connect time
    /// via `SCardStatus`. Cached so the ATR-classification
    /// step doesn't have to re-call into the PC/SC service mid-session.
    atr: Vec<u8>,
    /// Active protocol captured from `SCardStatus`.
    protocol: Protocol,
    /// What the session was opened for; decides whether a PIN
    /// sequence may run on it.
    access: ReaderAccessCap,
}

impl PcscCard {
    /// Run one PIN-bearing command sequence inside a single PC/SC
    /// transaction and reset the card when it ends.
    ///
    /// `body` receives the only transport that accepts a credential
    /// command. The transaction begins before the body runs and
    /// ends with `SCARD_RESET_CARD` on every path out of the body,
    /// so the verified state a VERIFY established serves this
    /// sequence alone and does not outlive it. The card handle is
    /// consumed: nothing can be sent on it after the reset.
    ///
    /// # Errors
    /// [`PcscError::NotAPinSession`] when the session was opened
    /// with [`ReaderAccessCap::Read`]; the PC/SC error when the
    /// transaction cannot begin, or cannot end with the reset. In
    /// the last case the body's result is withheld, because the
    /// sequence did not deliver its guarantee, and the handle's
    /// release attempts the reset once more.
    pub fn pin_sequence<R>(
        self,
        body: impl FnOnce(PcscTransactionCard<'_, '_>) -> R,
    ) -> Result<R, PcscError> {
        pin_sequence_permitted(self.access)?;
        let Self {
            mut card, protocol, ..
        } = self;
        let result = {
            let tx = card.transaction()?;
            let result = body(PcscTransactionCard { tx: &tx, protocol });
            tx.end(Disposition::ResetCard)
                .map_err(|(_ended_without_reset, error)| error)?;
            result
        };
        // The transaction's reset already cleared the card, so the
        // handle is released without a second reset. A refused
        // release hands the handle back; its drop releases it with
        // a reset.
        if let Err((card, _release_error)) = card.disconnect(Disposition::LeaveCard) {
            drop(card);
        }
        Ok(result)
    }
    /// Reset the card, returning it to its post-ATR state.
    ///
    /// # Errors
    /// `SCardReconnect` or the follow-up `SCardStatus` failing.
    pub fn reset(&mut self) -> Result<(), PcscError> {
        // Reconnect on the protocol the card already negotiated
        // rather than re-offering the ANY mask: the card's
        // protocol has not changed across a power cycle, and the
        // ANY renegotiation is exactly what the no-name "Generic
        // EMV Smartcard Reader" firmware botches (it reports the
        // card unresponsive). Falls back to the other protocol on
        // that specific failure.
        let active = protocols_mask(self.protocol);
        match self
            .card
            .reconnect(ShareMode::Shared, active, Disposition::UnpowerCard)
        {
            Ok(()) => {}
            Err(pcsc::Error::UnresponsiveCard) => {
                self.card.reconnect(
                    ShareMode::Shared,
                    other_protocols_mask(self.protocol),
                    Disposition::UnpowerCard,
                )?;
            }
            Err(e) => return Err(e.into()),
        }
        let mut names_buf = [0_u8; 256];
        let mut atr_buf = [0_u8; pcsc::MAX_ATR_SIZE];
        let status = self.card.status2(&mut names_buf, &mut atr_buf)?;
        self.atr = status.atr().to_vec();
        self.protocol = status.protocol2().ok_or_else(|| {
            PcscError::Transport("reconnected card has no active protocol".into())
        })?;
        Ok(())
    }

    /// Parse the card's Answer-to-Reset bytes.
    ///
    /// # Errors
    /// [`AtrError`] when the ATR structure or checksum is invalid.
    pub fn atr(&self) -> Result<Atr, AtrError> {
        Atr::new(&self.atr)
    }

    /// Borrow the raw ATR bytes.
    #[must_use]
    pub fn atr_bytes(&self) -> &[u8] {
        &self.atr
    }
}

impl core::fmt::Debug for PcscCard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PcscCard")
            .field("card", &"<pcsc handle>")
            .field("atr_len", &self.atr.len())
            .field("protocol", &self.protocol)
            .finish()
    }
}

// ----- T=0 transport loop (61xx chaining + 6Cxx retry) -----

/// The single low-level "send one C-APDU, receive its raw R-APDU"
/// primitive the T=0 transport loop drives.
trait T0Transmitter {
    fn transmit<'buf>(
        &mut self,
        apdu: &[u8],
        buf: &'buf mut [u8],
    ) -> Result<&'buf [u8], TransmitBreak>;
}

/// Non-continuable result of one [`T0Transmitter::transmit`] call:
/// either a terminal [`TransportOutcome`] to hand straight back to
/// the caller, or a hard [`PcscError`].
enum TransmitBreak {
    Outcome(TransportOutcome),
    Error(PcscError),
}

/// Production [`T0Transmitter`] over a live PC/SC transaction.
struct PcscTransmitter<'tx, 'card>(&'tx Transaction<'card>);

impl T0Transmitter for PcscTransmitter<'_, '_> {
    fn transmit<'buf>(
        &mut self,
        apdu: &[u8],
        buf: &'buf mut [u8],
    ) -> Result<&'buf [u8], TransmitBreak> {
        match self.0.transmit(apdu, buf) {
            Ok(response) => Ok(response),
            Err(pcsc::Error::NoSmartcard) => Err(TransmitBreak::Outcome(TransportOutcome::NoCard)),
            Err(pcsc::Error::RemovedCard) => {
                Err(TransmitBreak::Outcome(TransportOutcome::ReaderRemoved))
            }
            Err(pcsc::Error::ResetCard) => Err(TransmitBreak::Outcome(TransportOutcome::CardReset)),
            Err(e) => Err(TransmitBreak::Error(e.into())),
        }
    }
}

/// Drive one logical APDU exchange over `transmitter`, handling `SW=61xx`
/// `GET RESPONSE` chaining (inner loop bounded by progress plus the
/// [`EXTENDED_RESPONSE_DATA_MAX_BYTES`] ceiling).
fn run_t0_exchange<T: T0Transmitter>(
    transmitter: &mut T,
    apdu_bytes: &[u8],
) -> Result<TransportOutcome, PcscError> {
    let mut recv_buf = vec![0_u8; EXTENDED_RESPONSE_DATA_MAX_BYTES];
    let mut chain_buf = vec![0_u8; EXTENDED_RESPONSE_DATA_MAX_BYTES];

    let response = match transmitter.transmit(apdu_bytes, &mut recv_buf) {
        Ok(response) => response,
        Err(TransmitBreak::Outcome(outcome)) => return Ok(outcome),
        Err(TransmitBreak::Error(e)) => return Err(e),
    };

    let Some((body, sw_bytes)) = response.split_last_chunk::<2>() else {
        return Ok(TransportOutcome::ProtocolDesync);
    };
    let [sw1, sw2] = *sw_bytes;

    if sw1 == SW1_BYTES_AVAILABLE {
        let mut combined: Vec<u8> = body.to_vec();
        let mut next_le = sw2;
        let mut chained_sw1: u8;
        let mut chained_sw2: u8;
        loop {
            let get_resp = GetResponse {
                class: ApduClass::Plain,
                le: next_le,
            }
            .into_apdu();
            let chain_resp = match transmitter.transmit(get_resp.as_bytes(), &mut chain_buf) {
                Ok(response) => response,
                Err(TransmitBreak::Outcome(outcome)) => return Ok(outcome),
                Err(TransmitBreak::Error(e)) => return Err(e),
            };
            let Some((chain_body, chain_sw)) = chain_resp.split_last_chunk::<2>() else {
                return Ok(TransportOutcome::ProtocolDesync);
            };
            let progressed = !chain_body.is_empty();
            let Some(next_len) = combined.len().checked_add(chain_body.len()) else {
                return Err(PcscError::Transport(
                    "61xx GET RESPONSE chain exceeded 64 KiB".into(),
                ));
            };
            if next_len > EXTENDED_RESPONSE_DATA_MAX_BYTES {
                return Err(PcscError::Transport(
                    "61xx GET RESPONSE chain exceeded 64 KiB".into(),
                ));
            }
            combined.extend_from_slice(chain_body);
            chained_sw1 = chain_sw[0];
            chained_sw2 = chain_sw[1];
            if chained_sw1 == SW1_BYTES_AVAILABLE {
                if !progressed {
                    return Err(PcscError::Transport(
                        "card signalled 61xx but returned no bytes (stalled chain)".into(),
                    ));
                }
                next_le = chained_sw2;
                continue;
            }
            break;
        }
        return Ok(TransportOutcome::Response(ResponseApdu {
            body: combined,
            sw1: chained_sw1,
            sw2: chained_sw2,
        }));
    }

    Ok(TransportOutcome::Response(ResponseApdu {
        body: body.to_vec(),
        sw1,
        sw2,
    }))
}

/// Whether a session opened with `access` may run a PIN sequence.
fn pin_sequence_permitted(access: ReaderAccessCap) -> Result<(), PcscError> {
    match access {
        ReaderAccessCap::PinSequence => Ok(()),
        ReaderAccessCap::Read => Err(PcscError::NotAPinSession),
    }
}

/// Begin a PC/SC transaction on `card`, mapping the card-state
/// failures to their [`TransportOutcome`] transitions.
fn begin_transaction(card: &mut Card) -> Result<Transaction<'_>, TransmitBreak> {
    match card.transaction() {
        Ok(tx) => Ok(tx),
        Err(pcsc::Error::NoSmartcard) => Err(TransmitBreak::Outcome(TransportOutcome::NoCard)),
        Err(pcsc::Error::RemovedCard) => {
            Err(TransmitBreak::Outcome(TransportOutcome::ReaderRemoved))
        }
        Err(pcsc::Error::ResetCard) => Err(TransmitBreak::Outcome(TransportOutcome::CardReset)),
        Err(e) => Err(TransmitBreak::Error(e.into())),
    }
}

/// The T=0 case-4 adaptation for `apdu`, when the active protocol
/// needs it.
fn t0_adaptation(protocol: Protocol, apdu: &[u8]) -> Option<Vec<u8>> {
    if protocol == Protocol::T0 {
        t0_case3_from_short_case4(apdu)
    } else {
        None
    }
}

/// One replay-safe exchange: the T=0 case-4 adaptation, the `61xx`
/// chain, and the single wrong-Le correction a case-2 builder
/// opted into.
fn exchange_plain<T: T0Transmitter>(
    transmitter: &mut T,
    protocol: Protocol,
    command: &CommandApdu,
) -> Result<TransportOutcome, PcscError> {
    let t0_adapted = t0_adaptation(protocol, command.as_bytes());
    let bytes_to_send = t0_adapted.as_deref().unwrap_or_else(|| command.as_bytes());
    let outcome = run_t0_exchange(transmitter, bytes_to_send)?;

    if let TransportOutcome::Response(ref resp) = outcome
        && resp.sw1 == SW1_WRONG_LE
        && let Some(corrected) = command.corrected_wrong_le(resp.sw2)
    {
        let retry_t0 = t0_adaptation(protocol, corrected.as_bytes());
        let retry_bytes = retry_t0.as_deref().unwrap_or_else(|| corrected.as_bytes());
        return run_t0_exchange(transmitter, retry_bytes);
    }

    Ok(outcome)
}

/// One credential exchange: sent exactly once with the `61xx`
/// chain settled, never corrected and never resent.
fn exchange_credential<T: T0Transmitter>(
    transmitter: &mut T,
    protocol: Protocol,
    command: CredentialCommand,
) -> Result<TransportOutcome, PcscError> {
    command.expose_wire(|wire| {
        let t0_adapted = t0_adaptation(protocol, wire);
        let bytes_to_send = t0_adapted.as_deref().unwrap_or(wire);
        run_t0_exchange(transmitter, bytes_to_send)
    })
}

impl CardTransport for PcscCard {
    type Error = PcscError;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let tx = match begin_transaction(&mut self.card) {
            Ok(tx) => tx,
            Err(TransmitBreak::Outcome(outcome)) => return Ok(outcome),
            Err(TransmitBreak::Error(e)) => return Err(e),
        };
        let mut transmitter = PcscTransmitter(&tx);
        exchange_plain(&mut transmitter, self.protocol, command)
    }

    /// Refused: a credential travels only inside
    /// [`PcscCard::pin_sequence`]. The command is consumed and its
    /// storage zeroizes.
    fn transmit_credential(
        &mut self,
        _command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        Err(PcscError::CredentialOutsideTransaction)
    }
}

/// A card inside one PC/SC transaction, handed to the body of
/// [`PcscCard::pin_sequence`].
///
/// This is the only transport on which a credential command
/// travels. It offers no reset and no way out of the transaction,
/// which ends with a card reset when the body returns.
pub struct PcscTransactionCard<'tx, 'card> {
    tx: &'tx Transaction<'card>,
    protocol: Protocol,
}

impl CardTransport for PcscTransactionCard<'_, '_> {
    type Error = PcscError;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let mut transmitter = PcscTransmitter(self.tx);
        exchange_plain(&mut transmitter, self.protocol, command)
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        let mut transmitter = PcscTransmitter(self.tx);
        exchange_credential(&mut transmitter, self.protocol, command)
    }
}

impl core::fmt::Debug for PcscTransactionCard<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PcscTransactionCard")
            .field("tx", &"<pcsc transaction>")
            .field("protocol", &self.protocol)
            .finish()
    }
}

// ----- ReaderBackend and reader management -----

/// Stand-in identifier for a PC/SC reader.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReaderId(pub String);

impl ReaderId {
    /// Wrap a platform-reported reader name.
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self(name)
    }

    /// Borrow the underlying reader-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Read-only metadata about a connected reader.
#[derive(Debug, Clone)]
pub struct ReaderInfo {
    /// Platform-reported reader name.
    pub id: ReaderId,
    /// Whether a card is currently presented in this reader.
    pub card_present: bool,
    /// How many card insertions and removals the platform has counted
    /// for this reader: the event counter `SCardGetStatusChange` reports
    /// in the upper half of `dwEventState`. A change between two reads
    /// means a card arrived or left in between; a platform that keeps no
    /// count reports zero throughout.
    pub card_events: u32,
}

/// Access permission requested when opening a card on a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderAccessCap {
    /// Card-public reads only (eMRTD via PACE, ATR-derived metadata,
    /// cert reads). A credential command is refused on the session.
    Read,
    /// A PIN-bearing command sequence: the session may enter
    /// [`PcscCard::pin_sequence`], one transaction for the whole
    /// sequence, ended with a card reset.
    PinSequence,
}

/// Hardware reader backend trait.
pub trait ReaderBackend {
    /// Transport type returned when opening a card session.
    type Transport: CardTransport;
    /// Error type for reader backend operations.
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Enumerate all visible readers and their card-present status.
    fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error>;

    /// The card insertion and removal count of the named reader, as
    /// [`ReaderInfo::card_events`] reports it, read now. Two equal
    /// reads bracket a span in which the platform saw no card arrive
    /// or leave.
    ///
    /// # Errors
    /// The platform cannot report the reader's state.
    fn card_events(&self, reader: &ReaderId) -> Result<u32, Self::Error>;

    /// Open a session on the named reader for `access`. The PC/SC
    /// backend connects in shared mode; `access` decides whether
    /// the session may run a PIN sequence.
    fn open_exclusive(
        &self,
        reader: &ReaderId,
        access: ReaderAccessCap,
    ) -> Result<Self::Transport, Self::Error>;

    /// Open a session on the named reader. Defaults to `open_exclusive`.
    fn open_session(
        &self,
        reader: &ReaderId,
        access: ReaderAccessCap,
    ) -> Result<Self::Transport, Self::Error> {
        self.open_exclusive(reader, access)
    }
}

/// Errors surfaced by `pick_single_reader` when the count of
/// card-present readers can't be reduced to exactly one
/// unambiguously.
///
/// The rule the picker enforces is the project's universal
/// multi-card-safety policy: when more than one card is
/// inserted across the connected readers, the caller MUST
/// disambiguate via `--reader SUBSTR`. The picker never guesses;
/// guessing could fire a card-state-changing APDU (PIN verify,
/// signature, PUK rotation) against the wrong physical card.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReaderPickError {
    /// `backend.enumerate()` returned no readers at all.
    NoReaders,
    /// One or more readers connected, none with a card inserted.
    NoCardPresent,
    /// More than one card-present reader, and the caller didn't
    /// supply a `--reader` filter. `available` lists every
    /// card-present reader name so the caller can surface an
    /// actionable error message.
    MultipleReadersNoFilter {
        /// Connected card-present reader names. Tier 0
        /// `Vec<String>`; presentational.
        available: Vec<String>,
    },
    /// `filter` was supplied but matched no card-present reader.
    NoMatchingReader {
        /// The filter string the operator supplied. Tier 0
        /// `String`; presentational.
        filter: String,
        /// Connected card-present reader names presented back
        /// so the operator can correct the filter.
        available: Vec<String>,
    },
    /// `filter` was supplied and matched more than one
    /// card-present reader. The caller has to narrow it.
    AmbiguousFilter {
        /// The filter string the operator supplied.
        filter: String,
        /// Card-present reader names that matched the filter.
        matched: Vec<String>,
    },
    /// Cards are inserted, but none of them respond as FINEID
    /// when probed (no SELECT PKCS#15 success). Surfaced only
    /// by `pkcs15::pick_fineid_reader`, which probes
    /// every card-present reader to skip non-FINEID tokens like
    /// YubiKey-in-CCID-mode.
    NoFineidCard {
        /// Card-present reader names that didn't respond as
        /// FINEID. Helps the operator see which readers had
        /// non-FINEID tokens.
        available: Vec<String>,
    },
}

impl core::fmt::Display for ReaderPickError {
    #[expect(
        clippy::use_debug,
        reason = "operator-supplied --reader filter strings are rendered with Debug-quoting so whitespace-only / empty / control-character inputs surface visibly in diagnostics; `{filter}` would silently drop those distinctions"
    )]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoReaders => write!(f, "no PC/SC readers connected"),
            Self::NoCardPresent => write!(f, "no card present in any reader"),
            Self::MultipleReadersNoFilter { available } => write!(
                f,
                "{} cards present; pass --reader SUBSTR to pick one: [{}]",
                available.len(),
                available.join(", ")
            ),
            Self::NoMatchingReader { filter, available } => write!(
                f,
                "no card-present reader matched --reader {filter:?}; \
                 connected card-present readers: [{}]",
                available.join(", ")
            ),
            Self::AmbiguousFilter { filter, matched } => write!(
                f,
                "--reader {filter:?} matched more than one card-present reader: \
                 [{}] -- narrow the substring",
                matched.join(", ")
            ),
            Self::NoFineidCard { available } => write!(
                f,
                "no FINEID-format card responded to probe; readers had cards \
                 but none accepted SELECT PKCS#15: [{}]",
                available.join(", ")
            ),
        }
    }
}

impl core::error::Error for ReaderPickError {}

/// Operator-supplied reader-name substring filter, typed at the
/// trust boundary.
///
/// Used by the `--reader SUBSTR` CLI option and by the
/// programmatic picker entry points to narrow which card-present
/// reader the operation targets. The constructor is the single
/// place an arbitrary string crosses into "matches an actual
/// reader name" semantics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReaderFilter(String);

impl ReaderFilter {
    /// Wrap an owned filter string. No structural validation:
    /// the substring will be matched against
    /// `ReaderInfo::id.as_str().contains(filter)`, so an empty
    /// string matches every reader (which is rarely useful, but
    /// not an error -- callers usually skip the filter
    /// altogether for that case).
    #[must_use]
    pub fn new<S: AsRef<str>>(s: S) -> Self {
        Self(s.as_ref().to_owned())
    }

    /// Borrow the underlying filter string for matching.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ReaderFilter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Pick exactly one card-present reader, enforcing the project's
/// universal multi-card-safety rule.
pub fn pick_single_reader<B: ReaderBackend>(
    backend: &B,
    filter: Option<ReaderFilter>,
) -> Result<ReaderId, ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    let present: Vec<ReaderInfo> = readers.into_iter().filter(|r| r.card_present).collect();
    if present.is_empty() {
        return Err(ReaderPickError::NoCardPresent);
    }

    filter.map_or_else(
        || match present.as_slice() {
            [single] => Ok(single.id.clone()),
            many => Err(ReaderPickError::MultipleReadersNoFilter {
                available: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
            }),
        },
        |f| {
            let needle = f.as_str();
            let matched: Vec<&ReaderInfo> = present
                .iter()
                .filter(|r| r.id.as_str().contains(needle))
                .collect();
            match matched.as_slice() {
                [] => Err(ReaderPickError::NoMatchingReader {
                    filter: needle.to_owned(),
                    available: present.iter().map(|r| r.id.as_str().to_owned()).collect(),
                }),
                [single] => Ok(single.id.clone()),
                many => Err(ReaderPickError::AmbiguousFilter {
                    filter: needle.to_owned(),
                    matched: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
                }),
            }
        },
    )
}

/// Extension trait that hosts the multi-card-safety picker on
/// every [`ReaderBackend`].
pub trait ReaderBackendOps: ReaderBackend
where
    Self::Error: core::fmt::Display,
{
    /// See [`pick_single_reader`].
    ///
    /// # Errors
    /// As for [`pick_single_reader`].
    fn pick_single_reader(&self, filter: Option<ReaderFilter>) -> Result<ReaderId, ReaderPickError>
    where
        Self: Sized,
    {
        pick_single_reader(self, filter)
    }
}

impl<B: ReaderBackend + ?Sized> ReaderBackendOps for B where B::Error: core::fmt::Display {}

/// Reader (IFD) hardware version from `SCARD_ATTR_VENDOR_IFD_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfdVersion {
    /// Version major.
    pub major: u8,
    /// Version minor.
    pub minor: u8,
}

/// Reader identity attributes for one physical device.
#[derive(Debug, Clone, Default)]
pub struct ReaderIdentity {
    /// `SCARD_ATTR_VENDOR_NAME`: the reader vendor, trimmed.
    pub vendor_name: Option<String>,
    /// `SCARD_ATTR_VENDOR_IFD_VERSION`, parsed.
    pub ifd_version: Option<IfdVersion>,
}

/// Read the reader's own identity attributes via `SCardGetAttrib`
/// on a direct-mode (card-less) connection.
#[must_use]
pub fn read_reader_identity(reader: &ReaderId) -> ReaderIdentity {
    let Ok(ctx) = establish_context() else {
        return ReaderIdentity::default();
    };
    let Ok(cstr) = CString::new(reader.as_str()) else {
        return ReaderIdentity::default();
    };
    let Ok(card) = ctx.connect(&cstr, ShareMode::Direct, Protocols::UNDEFINED) else {
        return ReaderIdentity::default();
    };
    let mut vendor_buf = [0_u8; 128];
    let vendor_name = card
        .get_attribute(pcsc::Attribute::VendorName, &mut vendor_buf)
        .ok()
        .map(|bytes| {
            String::from_utf8_lossy(bytes)
                .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_owned()
        })
        .filter(|name| !name.is_empty());
    let mut version_buf = [0_u8; 16];
    let ifd_version = card
        .get_attribute(pcsc::Attribute::VendorIfdVersion, &mut version_buf)
        .ok()
        .and_then(|bytes| match bytes {
            [_build_lo, _build_hi, minor, major, ..] => Some(IfdVersion {
                major: *major,
                minor: *minor,
            }),
            _short => None,
        });
    ReaderIdentity {
        vendor_name,
        ifd_version,
    }
}

/// One reader's state as `SCardGetStatusChange` reports it now.
struct ReaderStatus {
    /// A card is in the reader.
    card_present: bool,
    /// The reader's card insertion and removal count
    /// ([`ReaderInfo::card_events`]).
    card_events: u32,
}

/// Query the named reader's state once, without waiting for a change.
fn reader_status(ctx: &Context, reader: &str) -> Result<ReaderStatus, PcscError> {
    let cstr = CString::new(reader)
        .map_err(|e| PcscError::Transport(format!("reader name has interior NUL: {e}")))?;
    let mut states = [ReaderState::new(cstr, State::UNAWARE)];
    match ctx.get_status_change(core::time::Duration::ZERO, &mut states) {
        Ok(()) | Err(pcsc::Error::Timeout) => {}
        Err(e) => return Err(e.into()),
    }
    let [state] = &states;
    let event = state.event_state();
    Ok(ReaderStatus {
        card_present: event.contains(State::PRESENT) && !event.contains(State::EMPTY),
        card_events: state.event_count(),
    })
}

/// Default desktop PC/SC reader backend implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct PcscBackend;

impl ReaderBackend for PcscBackend {
    type Transport = PcscCard;
    type Error = PcscError;

    fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
        let ctx = establish_context()?;
        let names = list_readers(&ctx)?;
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let status = reader_status(&ctx, name.as_str())?;
            out.push(ReaderInfo {
                id: ReaderId::new(name),
                card_present: status.card_present,
                card_events: status.card_events,
            });
        }
        Ok(out)
    }

    fn card_events(&self, reader: &ReaderId) -> Result<u32, Self::Error> {
        let ctx = establish_context()?;
        Ok(reader_status(&ctx, reader.as_str())?.card_events)
    }

    fn open_exclusive(
        &self,
        reader: &ReaderId,
        access: ReaderAccessCap,
    ) -> Result<Self::Transport, Self::Error> {
        let ctx = establish_context()?;
        connect(&ctx, reader.as_str(), access)?.ok_or(PcscError::Pcsc(pcsc::Error::NoSmartcard))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PcscError, ReaderAccessCap, SW1_WRONG_LE, T0Transmitter, TransmitBreak, TransportOutcome,
        exchange_credential, exchange_plain, pin_sequence_permitted, run_t0_exchange,
        t0_case3_from_short_case4,
    };
    use pcsc::Protocol;
    use refineid_apdu::iso7816::GetResponse;
    use refineid_apdu::status_word::StatusWord;
    use refineid_apdu::{
        ApduClass, CommandHeader, CredentialBody, CredentialCommand, UnvalidatedCredentialBlock,
    };

    /// Le the scripted card asks for in its `6Cxx` answer.
    const CORRECTED_LE: u8 = 0x05;
    /// Le the scripted `GET RESPONSE` starts with.
    const INITIAL_LE: u8 = 0x10;
    /// Synthetic instruction byte of the scripted credential command.
    const TEST_CREDENTIAL_INS: u8 = 0xEE;
    /// Synthetic credential octet; never a real credential value.
    const TEST_CREDENTIAL_OCTET: u8 = 0x2A;
    /// Octets the scripted credential command carries.
    const TEST_CREDENTIAL_LEN: usize = 4;

    #[allow(dead_code)]
    enum Step {
        Reply(Vec<u8>),
        Outcome(TransportOutcome),
        Error(PcscError),
    }

    struct ScriptedCard {
        steps: Vec<Step>,
        sent: Vec<Vec<u8>>,
    }

    impl ScriptedCard {
        fn new(mut steps: Vec<Step>) -> Self {
            steps.reverse();
            Self {
                steps,
                sent: Vec::new(),
            }
        }
    }

    impl T0Transmitter for ScriptedCard {
        fn transmit<'buf>(
            &mut self,
            apdu: &[u8],
            buf: &'buf mut [u8],
        ) -> Result<&'buf [u8], TransmitBreak> {
            self.sent.push(apdu.to_vec());
            match self.steps.pop().expect("scripted card: no step queued") {
                Step::Reply(bytes) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    Ok(&buf[..bytes.len()])
                }
                Step::Outcome(outcome) => Err(TransmitBreak::Outcome(outcome)),
                Step::Error(err) => Err(TransmitBreak::Error(err)),
            }
        }
    }

    #[test]
    fn single_exchange_returns_response() {
        let mut card = ScriptedCard::new(vec![Step::Reply(vec![0x01, 0x02, 0x90, 0x00])]);
        let outcome =
            run_t0_exchange(&mut card, &[0x00, 0xA4, 0x00, 0x00]).expect("exchange succeeds");
        match outcome {
            TransportOutcome::Response(resp) => {
                assert_eq!(resp.body, vec![0x01, 0x02]);
                assert_eq!(resp.sw1, 0x90);
                assert_eq!(resp.sw2, 0x00);
            }
            other => panic!("expected response, got {other:?}"),
        }
        assert_eq!(card.sent.len(), 1);
    }

    #[test]
    fn response_chaining_61xx_collects_body() {
        let mut card = ScriptedCard::new(vec![
            Step::Reply(vec![0xAA, 0x61, 0x02]),
            Step::Reply(vec![0xBB, 0xCC, 0x90, 0x00]),
        ]);
        let outcome = run_t0_exchange(&mut card, &[0x00, 0xC0, 0x00, 0x00])
            .expect("chaining exchange succeeds");
        match outcome {
            TransportOutcome::Response(resp) => {
                assert_eq!(resp.body, vec![0xAA, 0xBB, 0xCC]);
                assert_eq!(resp.sw1, 0x90);
                assert_eq!(resp.sw2, 0x00);
            }
            other => panic!("expected response, got {other:?}"),
        }
        assert_eq!(card.sent.len(), 2);
        let get_resp = GetResponse {
            class: ApduClass::Plain,
            le: 0x02,
        }
        .into_apdu();
        assert_eq!(card.sent[1], get_resp.as_bytes());
    }

    #[test]
    fn stalled_61xx_chain_fails() {
        let mut card = ScriptedCard::new(vec![
            Step::Reply(vec![0x61, 0x02]),
            Step::Reply(vec![0x61, 0x02]),
        ]);
        let err = run_t0_exchange(&mut card, &[0x00, 0xC0, 0x00, 0x00])
            .expect_err("stalled exchange must fail");
        assert!(matches!(err, PcscError::Transport(_)));
    }

    #[test]
    fn short_case4_to_case3_conversion() {
        let case4 = vec![0x00, 0x2A, 0x90, 0xA0, 0x02, 0xAA, 0xBB, 0x00];
        let case3 = t0_case3_from_short_case4(&case4).expect("valid short case 4 APDU");
        assert_eq!(case3, vec![0x00, 0x2A, 0x90, 0xA0, 0x02, 0xAA, 0xBB]);
    }

    fn success_bytes() -> Vec<u8> {
        StatusWord::Success.as_u16().to_be_bytes().to_vec()
    }

    fn scripted_credential() -> CredentialCommand {
        let header = CommandHeader {
            class: ApduClass::Plain,
            instruction: TEST_CREDENTIAL_INS,
            p1: 0,
            p2: 0,
        };
        let mut block = UnvalidatedCredentialBlock::zeroed();
        block.buffer()[..TEST_CREDENTIAL_LEN].fill(TEST_CREDENTIAL_OCTET);
        block.set_filled(TEST_CREDENTIAL_LEN);
        let body = CredentialBody::from_block(block).expect("scripted credential body");
        CredentialCommand::assemble(header, body)
    }

    #[test]
    fn plain_exchange_corrects_wrong_le_once_for_an_opted_in_read() {
        let command = GetResponse {
            class: ApduClass::Plain,
            le: INITIAL_LE,
        }
        .into_apdu();
        let mut card = ScriptedCard::new(vec![
            Step::Reply(vec![SW1_WRONG_LE, CORRECTED_LE]),
            Step::Reply(success_bytes()),
        ]);
        let outcome = exchange_plain(&mut card, Protocol::T1, &command).expect("exchange succeeds");
        match outcome {
            TransportOutcome::Response(resp) => assert!(resp.is_ok()),
            other => panic!("expected response, got {other:?}"),
        }
        let corrected = command
            .corrected_wrong_le(CORRECTED_LE)
            .expect("GET RESPONSE opts into the correction");
        assert_eq!(card.sent.len(), 2);
        assert_eq!(card.sent[0], command.as_bytes());
        assert_eq!(card.sent[1], corrected.as_bytes());
    }

    #[test]
    fn credential_exchange_sends_once_and_never_corrects_wrong_le() {
        let mut card = ScriptedCard::new(vec![Step::Reply(vec![SW1_WRONG_LE, CORRECTED_LE])]);
        let outcome = exchange_credential(&mut card, Protocol::T1, scripted_credential())
            .expect("exchange succeeds");
        match outcome {
            TransportOutcome::Response(resp) => {
                assert_eq!(resp.sw1, SW1_WRONG_LE);
                assert_eq!(resp.sw2, CORRECTED_LE);
            }
            other => panic!("expected response, got {other:?}"),
        }
        assert_eq!(card.sent.len(), 1);
    }

    #[test]
    fn credential_exchange_on_t0_sends_the_case3_wire_unchanged() {
        // A credential command is case 3 already, so the T=0
        // adaptation leaves it alone.
        let mut card = ScriptedCard::new(vec![Step::Reply(success_bytes())]);
        let expected_wire = scripted_credential().expose_wire(<[u8]>::to_vec);
        exchange_credential(&mut card, Protocol::T0, scripted_credential())
            .expect("exchange succeeds");
        assert_eq!(card.sent, vec![expected_wire]);
    }

    #[test]
    fn pin_sequence_is_permitted_only_on_a_pin_session() {
        assert!(pin_sequence_permitted(ReaderAccessCap::PinSequence).is_ok());
        assert!(matches!(
            pin_sequence_permitted(ReaderAccessCap::Read),
            Err(PcscError::NotAPinSession)
        ));
    }

    #[test]
    fn protocols_mask_and_fallback_mapping() {
        use super::{other_protocols_mask, protocols_mask};
        use pcsc::{Protocol, Protocols};

        assert_eq!(protocols_mask(Protocol::T0), Protocols::T0);
        assert_eq!(protocols_mask(Protocol::T1), Protocols::T1);
        assert_eq!(protocols_mask(Protocol::RAW), Protocols::T0);

        assert_eq!(other_protocols_mask(Protocol::T0), Protocols::T1);
        assert_eq!(other_protocols_mask(Protocol::T1), Protocols::T0);
        assert_eq!(other_protocols_mask(Protocol::RAW), Protocols::T1);
    }
}
