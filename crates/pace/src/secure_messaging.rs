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

//! ISO 7816-4 secure messaging over the AES-256 session keys PACE
//! produces (BSI TR-03110-3 section F).
//!
//! A wrapped command sets the secure-messaging class, steps the send
//! sequence counter, encrypts any command data into a cryptogram
//! object, protects the expected-length byte, and appends a
//! message-authentication object over the counter, padded header, and
//! objects. A wrapped response is authenticated the same way before its
//! cryptogram is decrypted and its status object is read. A failed
//! authentication breaks the channel.
//!
//! [`SmTransport`] is itself a card transport, so the layers above it
//! see an ordinary transport and the secure-messaging mechanics stay
//! invisible. Credential commands are protected the same way and remain
//! consumed exactly once end to end.

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use refineid_apdu::iso7816::ReadBinary;
use refineid_apdu::{
    ApduClass, CardTransport, CommandApdu, CommandHeader, CredentialCommand, ResponseApdu,
    StatusWord, TransportErrorExt, TransportErrorKind, TransportOutcome,
};
use refineid_ber::BerTlvIter;

use crate::crypto::container::{AesCbc, Ciphertext};
use crate::crypto::symmetric::{
    AES_BLOCK, Aes256Key, aes256_cbc_decrypt_no_padding, aes256_cbc_encrypt_no_padding,
    aes256_cmac_truncated, aes256_ecb_encrypt_block,
};
use crate::handshake::{PaceSession, Ssc};

/// Cryptogram object tag: the encrypted, padded command or response
/// body. The first value byte is the padding-content indicator.
const TAG_CRYPTOGRAM: u8 = 0x87;
/// Protected expected-length object tag.
const TAG_PROTECTED_LE: u8 = 0x97;
/// Protected status-word object tag.
const TAG_PROTECTED_STATUS: u8 = 0x99;
/// Message-authentication object tag.
const TAG_MAC: u8 = 0x8E;

/// Padding-content indicator for ISO 7816-4 padding.
const PADDING_INDICATOR: u8 = 0x01;
/// ISO 7816-4 padding marker byte.
const PAD_MARKER: u8 = 0x80;
/// ISO 7816-4 padding filler byte.
const PAD_FILLER: u8 = 0x00;

/// Expected-length byte requesting every available response byte.
const SM_LE_ANY: u8 = 0x00;

/// Largest READ BINARY length the protected channel issues on the
/// wire. Observed on production hardware against a low-cost TPDU
/// reader, a 224-byte READ BINARY under secure messaging returns a
/// 61F2-pending response whose recovered bytes fail framing, while
/// the same span read at 128 bytes per exchange succeeds; whether
/// the card or the reader mangles the longer span is unproven.
/// Plain transports are unaffected and keep their own chunk sizes;
/// only the wrapped command fragments here.
const SM_READ_BINARY_MAX_LE: u8 = 0x80;
/// READ BINARY lengths are case-2 commands: the four header bytes
/// plus the Le byte.
const CASE2_COMMAND_LEN: usize = 5;
/// Class index in a raw command.
const CLA_INDEX: usize = 0;
/// Instruction index in a raw command.
const INS_INDEX: usize = 1;
/// P1 index in a raw command.
const P1_INDEX: usize = 2;
/// P2 index in a raw command.
const P2_INDEX: usize = 3;
/// Le index in a case-2 command.
const LE_INDEX: usize = 4;
/// P1 flag selecting the short-file-identifier offset form.
const P1_SFI_FORM_FLAG: u8 = 0x80;
/// P1 low bits carrying the offset high bits in the SFI form.
const P1_SFI_OFFSET_HIGH_MASK: u8 = 0x07;
/// Short-form Le byte meaning "all", 256 bytes.
const LE_ALL_BYTES: usize = 256;
/// Largest direct-form offset: fifteen bits.
const DIRECT_OFFSET_MAX: u16 = 0x7FFF;
/// Largest SFI-form offset: eleven bits.
const SFI_OFFSET_MAX: u16 = 0x07FF;

/// The command-header length in bytes.
const HEADER_LEN: usize = 4;
/// Length of a protected status word, in bytes.
const STATUS_LEN: usize = 2;
/// Length of the truncated message-authentication tag, in bytes.
const MAC_LEN: usize = 8;

/// A secure-messaging channel over a raw transport with an established
/// PACE session.
///
/// No `Debug`: the channel holds the session keys, which must never
/// reach a formatter.
pub struct SmTransport<T: CardTransport> {
    inner: T,
    k_enc: Aes256Key,
    k_mac: Aes256Key,
    ssc: Ssc,
}

/// A failure from the secure-messaging layer.
#[derive(Debug)]
pub enum SmError<E> {
    /// An adapter-level transport failure.
    Transport(E),
    /// A malformed command or response at a named point.
    Malformed(&'static str),
    /// The card's message-authentication tag did not match; the channel
    /// is broken.
    MacMismatch,
    /// The response carried no secure-messaging protection. On an
    /// established channel every response carries the protected status
    /// object and the authentication object (ISO 7816-4; BSI TR-03110-3
    /// section F); a response without them cannot be authenticated. The
    /// enclosed status word is unauthenticated -- it may be exactly what
    /// the card sent or exactly what an active attacker chose, and nothing
    /// in the response distinguishes the two, so it must never be read as a
    /// result. The only safe response is to abandon the channel.
    Unprotected(StatusWord),
    /// A wrapped command exceeded the short form.
    CommandTooLong,
}

impl<E: core::fmt::Display> core::fmt::Display for SmError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "SM transport: {e}"),
            Self::Malformed(what) => write!(f, "SM: malformed {what}"),
            Self::MacMismatch => f.write_str("SM: card authentication tag did not match"),
            Self::Unprotected(_) => f.write_str("SM: response carried no authentication"),
            Self::CommandTooLong => f.write_str("SM: wrapped command exceeds the short form"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for SmError<E> {}

impl<E: TransportErrorExt> TransportErrorExt for SmError<E> {
    fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Transport(error) => error.kind(),
            Self::Malformed(_) | Self::MacMismatch | Self::Unprotected(_) => {
                TransportErrorKind::ProtocolDesync
            }
            Self::CommandTooLong => TransportErrorKind::Backend,
        }
    }
}

impl<T: CardTransport> SmTransport<T> {
    /// Adopt the keys and counter from a completed PACE handshake. The
    /// session is consumed, so the caller keeps no copy of the keys.
    pub fn new(inner: T, session: PaceSession) -> Self {
        Self {
            inner,
            k_enc: session.k_enc,
            k_mac: session.k_mac,
            ssc: session.ssc,
        }
    }

    /// Drop the secure-messaging layer and return the raw transport.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Split into the raw transport and the live session keys and counter, so
    /// a caller that holds the field open can rebuild the channel on the next
    /// exchange without a fresh PACE handshake. The returned [`PaceSession`]
    /// carries the advanced send-sequence counter, so the rebuilt channel stays
    /// in step with the card. It is the inverse of [`Self::new`].
    pub fn into_parts(self) -> (T, PaceSession) {
        (
            self.inner,
            PaceSession {
                k_enc: self.k_enc,
                k_mac: self.k_mac,
                ssc: self.ssc,
            },
        )
    }

    /// Wrap a plain command APDU into a secure-messaging command,
    /// returning its header and protected body. The command data, when
    /// present, is encrypted; the padded plaintext is held in a
    /// zeroizing buffer and wiped before return.
    fn wrap(&mut self, plain: &[u8]) -> Result<(CommandHeader, Vec<u8>), SmError<T::Error>> {
        let header: [u8; HEADER_LEN] = plain
            .get(..HEADER_LEN)
            .and_then(|slice| <[u8; HEADER_LEN]>::try_from(slice).ok())
            .ok_or(SmError::Malformed("command shorter than its header"))?;
        let [_class, instruction, p1, p2] = header;
        let sm_header = CommandHeader {
            class: ApduClass::SecureMessaging,
            instruction,
            p1,
            p2,
        };

        let (data, le) = decode_short_apdu(plain)
            .ok_or(SmError::Malformed("command is not a short-form case"))?;

        self.ssc.increment();

        let cryptogram = if data.is_empty() {
            Vec::new()
        } else {
            let padded = Zeroizing::new(iso7816_4_pad(data));
            let block_iv = aes256_ecb_encrypt_block(self.k_enc.as_bytes(), self.ssc.as_bytes());
            let cipher = aes256_cbc_encrypt_no_padding(self.k_enc.as_bytes(), &block_iv, &padded)
                .map_err(|_unaligned| {
                SmError::Malformed("padded plaintext not block-aligned")
            })?;
            let mut value = Vec::with_capacity(1_usize.saturating_add(cipher.as_bytes().len()));
            value.push(PADDING_INDICATOR);
            value.extend_from_slice(cipher.as_bytes());
            refineid_ber::tlv(TAG_CRYPTOGRAM, &value)
                .map_err(|_too_long| SmError::CommandTooLong)?
        };

        let protected_le = match le {
            Some(le_byte) => refineid_ber::tlv(TAG_PROTECTED_LE, [le_byte])
                .map_err(|_too_long| SmError::CommandTooLong)?,
            None => Vec::new(),
        };

        let sm_header_bytes = [ApduClass::SecureMessaging.as_byte(), instruction, p1, p2];
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(self.ssc.as_bytes());
        mac_input.extend_from_slice(&iso7816_4_pad(&sm_header_bytes));
        mac_input.extend_from_slice(&cryptogram);
        mac_input.extend_from_slice(&protected_le);
        let mac_input = iso7816_4_pad(&mac_input);
        let tag = aes256_cmac_truncated(self.k_mac.as_bytes(), &mac_input);
        let mac_object = refineid_ber::tlv(TAG_MAC, tag.as_bytes())
            .map_err(|_too_long| SmError::CommandTooLong)?;

        let mut body = Vec::with_capacity(
            cryptogram
                .len()
                .saturating_add(protected_le.len())
                .saturating_add(mac_object.len()),
        );
        body.extend_from_slice(&cryptogram);
        body.extend_from_slice(&protected_le);
        body.extend_from_slice(&mac_object);
        Ok((sm_header, body))
    }

    /// Verify and decrypt a secure-messaging response body, returning the
    /// recovered data and the protected status word.
    fn unwrap(&mut self, response: &[u8]) -> Result<(Vec<u8>, StatusWord), SmError<T::Error>> {
        self.ssc.increment();

        let mut cryptogram: Option<Vec<u8>> = None;
        let mut status: Option<Vec<u8>> = None;
        let mut mac: Option<Vec<u8>> = None;

        for parsed in BerTlvIter::new(response) {
            let tlv = parsed.map_err(|_ber| SmError::Malformed("response BER parse"))?;
            let tag = tlv.tag();
            if tag == u16::from(TAG_CRYPTOGRAM) {
                cryptogram = Some(tlv.value().to_vec());
            } else if tag == u16::from(TAG_PROTECTED_STATUS) {
                status = Some(tlv.value().to_vec());
            } else if tag == u16::from(TAG_MAC) {
                mac = Some(tlv.value().to_vec());
            }
        }

        let status = status.ok_or(SmError::Malformed("no protected status object"))?;
        let mac = mac.ok_or(SmError::Malformed("no authentication object"))?;
        let status_bytes: [u8; STATUS_LEN] = status
            .as_slice()
            .try_into()
            .map_err(|_len| SmError::Malformed("status object wrong length"))?;
        let mac_bytes: [u8; MAC_LEN] = mac
            .as_slice()
            .try_into()
            .map_err(|_len| SmError::Malformed("authentication object wrong length"))?;

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(self.ssc.as_bytes());
        if let Some(ref value) = cryptogram {
            let object = refineid_ber::tlv(TAG_CRYPTOGRAM, value)
                .map_err(|_too_long| SmError::Malformed("cryptogram too long to re-encode"))?;
            mac_input.extend_from_slice(&object);
        }
        let status_object = refineid_ber::tlv(TAG_PROTECTED_STATUS, &status)
            .map_err(|_too_long| SmError::Malformed("status too long to re-encode"))?;
        mac_input.extend_from_slice(&status_object);
        let mac_input = iso7816_4_pad(&mac_input);
        let computed = aes256_cmac_truncated(self.k_mac.as_bytes(), &mac_input);
        let authenticated = bool::from(computed.as_bytes().ct_eq(mac_bytes.as_slice()));
        if !authenticated {
            return Err(SmError::MacMismatch);
        }

        let body = match cryptogram {
            Some(value) => {
                let (indicator, cipher_bytes) = value
                    .split_first()
                    .ok_or(SmError::Malformed("cryptogram empty"))?;
                let indicator_ok = *indicator == PADDING_INDICATOR;
                if !indicator_ok {
                    return Err(SmError::Malformed("cryptogram padding indicator"));
                }
                if !cipher_bytes.len().is_multiple_of(AES_BLOCK) {
                    return Err(SmError::Malformed("cryptogram not whole blocks"));
                }
                let cipher = Ciphertext::<AesCbc>::new(cipher_bytes.to_vec());
                let block_iv = aes256_ecb_encrypt_block(self.k_enc.as_bytes(), self.ssc.as_bytes());
                let plain =
                    aes256_cbc_decrypt_no_padding(self.k_enc.as_bytes(), &block_iv, &cipher)
                        .map_err(|_unaligned| SmError::Malformed("cryptogram not whole blocks"))?;
                iso7816_4_unpad(&plain)
            }
            None => Vec::new(),
        };

        let status_word = StatusWord::from_bytes(status_bytes[0], status_bytes[1]);
        Ok((body, status_word))
    }

    /// Send a wrapped response outcome back through the unwrap path.
    fn finish(&mut self, raw: TransportOutcome) -> Result<TransportOutcome, SmError<T::Error>> {
        let response = match raw {
            TransportOutcome::Response(response) => response,
            other => return Ok(other),
        };
        // Secure messaging protects every response: each carries the
        // protected status object and the authentication object (ISO
        // 7816-4; BSI TR-03110-3 section F). A response with an empty body
        // carries neither, so there is nothing to authenticate; its status
        // word is unverified and must not pass through as a result.
        if response.body.is_empty() {
            return Err(SmError::Unprotected(response.status_word()));
        }
        let (body, sw) = self.unwrap(&response.body)?;
        let [sw1, sw2] = sw.as_u16().to_be_bytes();
        Ok(TransportOutcome::Response(ResponseApdu { body, sw1, sw2 }))
    }
}

impl<T: CardTransport> SmTransport<T> {
    /// One protected exchange: wrap, transmit, authenticate.
    fn transmit_single(&mut self, plain: &[u8]) -> Result<TransportOutcome, SmError<T::Error>> {
        let (header, body) = self.wrap(plain)?;
        let wrapped = CommandApdu::case_4(header, &body, SM_LE_ANY)
            .map_err(|_too_long| SmError::CommandTooLong)?;
        let raw = self.inner.transmit(&wrapped).map_err(SmError::Transport)?;
        self.finish(raw)
    }

    /// Two protected reads covering one overlong READ BINARY span.
    /// The second exchange runs only when the first returns a full
    /// fragment: a short read is end-of-file and an overlong body is
    /// the card's 61xx surplus, which the caller above consumes by its
    /// actual length, so either returns as the outcome without a
    /// second exchange that would re-read or skip bytes.
    fn transmit_fragmented_read(
        &mut self,
        first: &[u8; CASE2_COMMAND_LEN],
        second: &[u8; CASE2_COMMAND_LEN],
    ) -> Result<TransportOutcome, SmError<T::Error>> {
        let first_response = match self.transmit_single(first)? {
            TransportOutcome::Response(response) => response,
            fault => return Ok(fault),
        };
        if !first_response.is_ok()
            || first_response.body.len() != usize::from(SM_READ_BINARY_MAX_LE)
        {
            return Ok(TransportOutcome::Response(first_response));
        }
        let second_response = match self.transmit_single(second)? {
            TransportOutcome::Response(response) => response,
            fault => return Ok(fault),
        };
        let mut body = first_response.body;
        body.extend_from_slice(&second_response.body);
        Ok(TransportOutcome::Response(ResponseApdu {
            body,
            sw1: second_response.sw1,
            sw2: second_response.sw2,
        }))
    }
}

/// Two case-2 wire reads covering one overlong READ BINARY span.
type FragmentPair = ([u8; CASE2_COMMAND_LEN], [u8; CASE2_COMMAND_LEN]);

/// Split a case-2 READ BINARY whose Le exceeds
/// [`SM_READ_BINARY_MAX_LE`] into two wire reads covering the same
/// span: a full first fragment plus the remainder. Every other
/// command transmits as one exchange. An Le of zero reads all 256
/// short-form bytes as two full fragments.
fn split_protected_read<E>(command: &[u8]) -> Result<Option<FragmentPair>, SmError<E>> {
    if command.len() != CASE2_COMMAND_LEN || command[INS_INDEX] != ReadBinary::INS {
        return Ok(None);
    }
    let le = command[LE_INDEX];
    let total = if le == SM_LE_ANY {
        LE_ALL_BYTES
    } else {
        usize::from(le)
    };
    let first_len = usize::from(SM_READ_BINARY_MAX_LE);
    if total <= first_len {
        return Ok(None);
    }
    let p1 = command[P1_INDEX];
    let p2 = command[P2_INDEX];
    let offset = if p1 & P1_SFI_FORM_FLAG == 0 {
        (u16::from(p1) << u8::BITS) | u16::from(p2)
    } else {
        (u16::from(p1 & P1_SFI_OFFSET_HIGH_MASK) << u8::BITS) | u16::from(p2)
    };
    let ceiling = if p1 & P1_SFI_FORM_FLAG == 0 {
        DIRECT_OFFSET_MAX
    } else {
        SFI_OFFSET_MAX
    };
    let second_offset = offset
        .checked_add(u16::from(SM_READ_BINARY_MAX_LE))
        .filter(|advanced| *advanced <= ceiling)
        .ok_or(SmError::Malformed("fragmented read offset out of form"))?;
    let second_le =
        u8::try_from(total - first_len).map_err(|_| SmError::Malformed("fragment too long"))?;
    let (second_p1, second_p2) = if p1 & P1_SFI_FORM_FLAG == 0 {
        ((second_offset >> u8::BITS) as u8, second_offset as u8)
    } else {
        (
            (p1 & !P1_SFI_OFFSET_HIGH_MASK)
                | ((second_offset >> u8::BITS) as u8 & P1_SFI_OFFSET_HIGH_MASK),
            second_offset as u8,
        )
    };
    let class = command[CLA_INDEX];
    Ok(Some((
        [class, ReadBinary::INS, p1, p2, SM_READ_BINARY_MAX_LE],
        [class, ReadBinary::INS, second_p1, second_p2, second_le],
    )))
}

impl<T: CardTransport> CardTransport for SmTransport<T> {
    type Error = SmError<T::Error>;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        match split_protected_read(command.as_bytes())? {
            Some((first, second)) => self.transmit_fragmented_read(&first, &second),
            None => self.transmit_single(command.as_bytes()),
        }
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        // Wrap the credential command, then assemble the protected wire
        // straight into custody storage. The wrapped wire never lands in an
        // ordinary CommandApdu or a heap copy: the protected body is held
        // in a zeroizing buffer only until it is copied into the wrapped
        // credential command.
        let (header, body) = command.expose_wire(|plain| self.wrap(plain))?;
        let body = Zeroizing::new(body);
        let wrapped_credential = CredentialCommand::from_protected_parts(header, &body, SM_LE_ANY)
            .map_err(|_too_long| SmError::CommandTooLong)?;
        let raw = self
            .inner
            .transmit_credential(wrapped_credential)
            .map_err(SmError::Transport)?;
        self.finish(raw)
    }
}

/// ISO 7816-4 padding: append the marker, then filler to the next block
/// boundary. Padding is never empty.
fn iso7816_4_pad(data: &[u8]) -> Vec<u8> {
    let full_blocks = data.len().div_euclid(AES_BLOCK);
    let capacity = full_blocks.saturating_add(1).saturating_mul(AES_BLOCK);
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(data);
    out.push(PAD_MARKER);
    while !out.len().is_multiple_of(AES_BLOCK) {
        out.push(PAD_FILLER);
    }
    out
}

/// Inverse of [`iso7816_4_pad`]: strip trailing filler and the marker.
/// A malformed padding leaves the input unchanged.
fn iso7816_4_unpad(data: &[u8]) -> Vec<u8> {
    let trailing_filler = data
        .iter()
        .rev()
        .take_while(|&&byte| byte == PAD_FILLER)
        .count();
    let Some(from_end) = trailing_filler.checked_add(1) else {
        return data.to_vec();
    };
    let Some(marker_pos) = data.len().checked_sub(from_end) else {
        return data.to_vec();
    };
    match data.get(marker_pos) {
        Some(&PAD_MARKER) => data
            .get(..marker_pos)
            .map_or_else(|| data.to_vec(), <[u8]>::to_vec),
        _ => data.to_vec(),
    }
}

/// Decode a short-form APDU into its data field and optional
/// expected-length byte. `None` when the length does not match a
/// short-form case.
fn decode_short_apdu(apdu: &[u8]) -> Option<(&[u8], Option<u8>)> {
    let case_1_len = HEADER_LEN;
    let case_2_len = HEADER_LEN + 1;
    if apdu.len() == case_1_len {
        return Some((&[], None));
    }
    if apdu.len() == case_2_len {
        return apdu.get(HEADER_LEN).map(|&le| (&[][..], Some(le)));
    }
    let lc = usize::from(*apdu.get(HEADER_LEN)?);
    let body_start = HEADER_LEN + 1;
    let body_end = body_start.checked_add(lc)?;
    let data = apdu.get(body_start..body_end)?;
    if apdu.len() == body_end {
        Some((data, None))
    } else if apdu.len() == body_end.checked_add(1)? {
        let le = *apdu.get(body_end)?;
        Some((data, Some(le)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AES_BLOCK, Aes256Key, PaceSession, SM_READ_BINARY_MAX_LE, SmError, SmTransport, Ssc,
        TAG_CRYPTOGRAM, TAG_MAC, TAG_PROTECTED_STATUS, aes256_cbc_encrypt_no_padding,
        aes256_cmac_truncated, aes256_ecb_encrypt_block, decode_short_apdu, iso7816_4_pad,
        iso7816_4_unpad, split_protected_read,
    };
    use refineid_apdu::{
        ApduClass, CardTransport, CommandApdu, CommandHeader, CredentialCommand, ResponseApdu,
        StatusWord, TransportOutcome,
    };

    /// Non-sentinel test encryption key filler.
    const K_ENC_FILL: u8 = 0x42;
    /// Non-sentinel test authentication key filler.
    const K_MAC_FILL: u8 = 0x77;
    /// Test key length in bytes.
    const KEY_LEN: usize = 32;
    /// A warning status word the card can return with a protected body.
    const WARNING_SW: u16 = 0x6282;

    /// Counter steps a full command-and-response exchange takes.
    const EXCHANGE_STEPS: u32 = 2;
    /// A parameter byte of zero.
    const P_ZERO: u8 = 0x00;
    /// READ BINARY instruction.
    const READ_BINARY_INS: u8 = 0xB0;
    /// SELECT instruction.
    const SELECT_INS: u8 = 0xA4;
    /// SELECT P1 for an EF under the current directory.
    const SELECT_EF_P1: u8 = 0x02;
    /// SELECT P2 requesting no response data.
    const NO_RESPONSE_P2: u8 = 0x0C;
    /// A two-byte read length.
    const READ_LE_TWO: u8 = 0x02;
    /// A synthetic file-identifier high byte.
    const FID_HIGH: u8 = 0x50;
    /// A synthetic file-identifier low byte.
    const FID_LOW: u8 = 0x31;
    /// Status-word length in bytes.
    const SW_LEN: usize = 2;
    /// A decrypted response payload; the ASCII value is synthetic.
    const RESPONSE_PAYLOAD: &[u8] = b"TEST";
    /// A short decrypted response payload; the ASCII value is synthetic.
    const SHORT_PAYLOAD: &[u8] = b"hi";
    /// A command data field; the ASCII value is synthetic.
    const COMMAND_DATA: &[u8] = b"go";
    /// A case-2 expected-length fixture.
    const CASE2_LE: u8 = 0x10;
    /// A synthetic data-carrying instruction.
    const DATA_INS: u8 = 0x20;
    /// The length octet for the case fixtures: [`CASE_DATA`]'s length.
    const CASE_LC: u8 = 0x04;
    /// A data field for the case fixtures; the ASCII value is synthetic.
    const CASE_DATA: &[u8] = b"data";
    /// Case-1 fixture APDU: header only.
    const CASE1_APDU: &[u8] = &[P_ZERO, SELECT_INS, P_ZERO, P_ZERO];
    /// Case-2 fixture APDU: header and expected length.
    const CASE2_APDU: &[u8] = &[P_ZERO, READ_BINARY_INS, P_ZERO, P_ZERO, CASE2_LE];
    /// Case-3 fixture APDU: header, length, and the data field.
    fn case3_apdu() -> Vec<u8> {
        let mut wire = vec![P_ZERO, DATA_INS, P_ZERO, P_ZERO, CASE_LC];
        wire.extend_from_slice(CASE_DATA);
        wire
    }
    /// Case-4 fixture APDU: the case-3 body followed by the expected
    /// length.
    fn case4_apdu() -> Vec<u8> {
        let mut wire = case3_apdu();
        wire.push(P_ZERO);
        wire
    }
    /// A SELECT-EF plain command for the class-check test.
    const SELECT_EF_APDU: &[u8] = &[
        P_ZERO,
        SELECT_INS,
        SELECT_EF_P1,
        NO_RESPONSE_P2,
        READ_LE_TWO,
        FID_HIGH,
        FID_LOW,
    ];

    fn read_binary_header() -> CommandHeader {
        CommandHeader {
            class: ApduClass::Plain,
            instruction: READ_BINARY_INS,
            p1: P_ZERO,
            p2: P_ZERO,
        }
    }

    fn session() -> PaceSession {
        PaceSession {
            k_enc: Aes256Key::from_bytes([K_ENC_FILL; KEY_LEN]).expect("non-sentinel key"),
            k_mac: Aes256Key::from_bytes([K_MAC_FILL; KEY_LEN]).expect("non-sentinel key"),
            ssc: Ssc::INITIAL,
        }
    }

    /// A transport that hands back one prepared response.
    struct FixedResponse {
        response: Option<ResponseApdu>,
    }

    impl CardTransport for FixedResponse {
        type Error = String;

        fn transmit(&mut self, _command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.response
                .take()
                .map(TransportOutcome::Response)
                .ok_or_else(|| "fixed response already consumed".to_owned())
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("no credential in this test".to_owned())
        }
    }

    /// A transport that never answers; used to drive wrap and unwrap
    /// directly.
    struct Null;

    impl CardTransport for Null {
        type Error = String;

        fn transmit(&mut self, _command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            Err("null transport".to_owned())
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("null transport".to_owned())
        }
    }

    #[test]
    fn padding_round_trips() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abcdef",
            b"0123456789abcdef",
            b"0123456789abcdef0",
        ];
        for &case in cases {
            let padded = iso7816_4_pad(case);
            assert!(padded.len().is_multiple_of(AES_BLOCK));
            let grew = padded.len() > case.len();
            assert!(grew);
            assert_eq!(iso7816_4_unpad(&padded), case.to_vec());
        }
    }

    #[test]
    fn decode_short_apdu_covers_every_case() {
        assert_eq!(decode_short_apdu(CASE1_APDU), Some((&[][..], None)));
        assert_eq!(
            decode_short_apdu(CASE2_APDU),
            Some((&[][..], Some(CASE2_LE)))
        );
        assert_eq!(decode_short_apdu(&case3_apdu()), Some((CASE_DATA, None)));
        assert_eq!(
            decode_short_apdu(&case4_apdu()),
            Some((CASE_DATA, Some(P_ZERO)))
        );
    }

    /// Build a card-side response for a body the terminal will decrypt,
    /// mirroring the unwrap inverse: the counter is stepped, the body is
    /// encrypted, and the objects are authenticated.
    fn card_response(counter_steps: u32, payload: &[u8], sw: StatusWord) -> Vec<u8> {
        let mut ssc = Ssc::INITIAL;
        for _step in 0..counter_steps {
            ssc.increment();
        }
        let k_enc = [K_ENC_FILL; KEY_LEN];
        let k_mac = [K_MAC_FILL; KEY_LEN];
        let padded = iso7816_4_pad(payload);
        let block_iv = aes256_ecb_encrypt_block(&k_enc, ssc.as_bytes());
        let cipher = aes256_cbc_encrypt_no_padding(&k_enc, &block_iv, &padded)
            .expect("padded payload is aligned");
        let mut value = vec![super::PADDING_INDICATOR];
        value.extend_from_slice(cipher.as_bytes());
        let cryptogram = refineid_ber::tlv(TAG_CRYPTOGRAM, &value).expect("encodes");
        let [sw1, sw2] = sw.as_u16().to_be_bytes();
        let status = refineid_ber::tlv(TAG_PROTECTED_STATUS, [sw1, sw2]).expect("encodes");

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(ssc.as_bytes());
        mac_input.extend_from_slice(&cryptogram);
        mac_input.extend_from_slice(&status);
        let mac_input = iso7816_4_pad(&mac_input);
        let tag = aes256_cmac_truncated(&k_mac, &mac_input);
        let mac_object = refineid_ber::tlv(TAG_MAC, tag.as_bytes()).expect("encodes");

        let mut body = Vec::new();
        body.extend_from_slice(&cryptogram);
        body.extend_from_slice(&status);
        body.extend_from_slice(&mac_object);
        body
    }

    fn success_bytes() -> [u8; SW_LEN] {
        StatusWord::Success.as_u16().to_be_bytes()
    }

    #[test]
    fn wrap_sets_the_secure_messaging_class() {
        let mut terminal = SmTransport::new(Null, session());
        let (header, _body) = terminal.wrap(SELECT_EF_APDU).expect("wrap succeeds");
        assert_eq!(header.class, ApduClass::SecureMessaging);
        assert_eq!(header.instruction, SELECT_INS);
    }

    #[test]
    fn round_trip_through_a_card_peer() {
        // The terminal wraps a command (stepping its counter once), then
        // the card responds (stepping the shared counter a second time).
        let response_body = card_response(EXCHANGE_STEPS, RESPONSE_PAYLOAD, StatusWord::Success);
        let [sw1, sw2] = success_bytes();
        let mut terminal = SmTransport::new(
            FixedResponse {
                response: Some(ResponseApdu {
                    body: response_body,
                    sw1,
                    sw2,
                }),
            },
            session(),
        );
        let command =
            CommandApdu::case_3(read_binary_header(), COMMAND_DATA).expect("command encodes");
        let outcome = terminal.transmit(&command).expect("round trip succeeds");
        let response = outcome.into_response().expect("real response");
        assert!(response.is_ok());
        assert_eq!(response.body.as_slice(), RESPONSE_PAYLOAD);
    }

    #[test]
    fn protected_warning_body_is_still_unwrapped() {
        let warning = StatusWord::from_u16(WARNING_SW);
        let response_body = card_response(EXCHANGE_STEPS, SHORT_PAYLOAD, warning);
        let [sw1, sw2] = WARNING_SW.to_be_bytes();
        let mut terminal = SmTransport::new(
            FixedResponse {
                response: Some(ResponseApdu {
                    body: response_body,
                    sw1,
                    sw2,
                }),
            },
            session(),
        );
        let command = CommandApdu::case_2(read_binary_header(), READ_LE_TWO);
        let outcome = terminal
            .transmit(&command)
            .expect("warning body is accepted");
        let response = outcome.into_response().expect("real response");
        assert_eq!(response.status_word(), warning);
        assert_eq!(response.body.as_slice(), SHORT_PAYLOAD);
    }

    #[test]
    fn tampered_authentication_tag_is_rejected() {
        let mut response_body = card_response(EXCHANGE_STEPS, COMMAND_DATA, StatusWord::Success);
        // Flip the last byte, which lands in the authentication object.
        let last = response_body.len() - 1;
        response_body[last] ^= u8::MAX;
        let [sw1, sw2] = success_bytes();
        let mut terminal = SmTransport::new(
            FixedResponse {
                response: Some(ResponseApdu {
                    body: response_body,
                    sw1,
                    sw2,
                }),
            },
            session(),
        );
        let command = CommandApdu::case_2(read_binary_header(), READ_LE_TWO);
        let error = terminal
            .transmit(&command)
            .expect_err("a tampered tag breaks the channel");
        assert!(matches!(error, SmError::MacMismatch));
    }

    #[test]
    fn unprotected_response_is_refused() {
        // A response with a status word but no protected objects carries no
        // authentication. The channel must refuse it rather than surface an
        // unverified status word as a result.
        let [sw1, sw2] = success_bytes();
        let mut terminal = SmTransport::new(
            FixedResponse {
                response: Some(ResponseApdu {
                    body: Vec::new(),
                    sw1,
                    sw2,
                }),
            },
            session(),
        );
        let command = CommandApdu::case_2(read_binary_header(), READ_LE_TWO);
        let error = terminal
            .transmit(&command)
            .expect_err("an unprotected response is refused");
        assert!(matches!(error, SmError::Unprotected(sw) if sw == StatusWord::Success));
    }

    /// Total length the fragmentation tests request, mirroring the
    /// file-read chunk sizes above this layer.
    const SPLIT_TOTAL_LE: u8 = 0xE0;
    /// Second-fragment length for a full-size split.
    const SECOND_FRAGMENT_LEN: usize = SPLIT_TOTAL_LE as usize - SM_READ_BINARY_MAX_LE as usize;
    /// Nonzero direct offset high byte for the split tests.
    const SPLIT_OFFSET_HIGH: u8 = 0x01;
    /// P1 selecting short file identifier 2 at offset high 0.
    const SFI_PROBE_P1: u8 = 0x90;
    /// Direct offset high byte whose fragment would leave the
    /// fifteen-bit form.
    const OVERFLOW_OFFSET_HIGH: u8 = 0x7F;
    /// P1 whose SFI fragment would leave the eleven-bit form: short
    /// file identifier 2 at offset high 7 with low byte 128.
    const SFI_OVERFLOW_P1: u8 = 0x97;
    /// Transmit count for one unfragmented exchange.
    const SINGLE_EXCHANGE_COUNT: usize = 1;
    /// Transmit count for one fragmented exchange.
    const FRAGMENTED_EXCHANGE_COUNT: usize = 2;
    /// First-fragment payload filler.
    const FIRST_FILL: u8 = 0x41;
    /// Second-fragment payload filler.
    const SECOND_FILL: u8 = 0x43;
    /// Bytes past a full fragment a 61xx surplus may add.
    const SURPLUS_EXTRA_LEN: usize = 12;

    fn read_command(p1: u8, p2: u8, le: u8) -> CommandApdu {
        CommandApdu::case_2(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: READ_BINARY_INS,
                p1,
                p2,
            },
            le,
        )
    }

    #[test]
    fn direct_read_splits_at_the_fragment_ceiling() {
        let command = read_command(SPLIT_OFFSET_HIGH, P_ZERO, SPLIT_TOTAL_LE);
        let (first, second) = split_protected_read::<String>(command.as_bytes())
            .expect("splittable")
            .expect("a 224-byte read must split");
        assert_eq!(
            first,
            [
                P_ZERO,
                READ_BINARY_INS,
                SPLIT_OFFSET_HIGH,
                P_ZERO,
                SM_READ_BINARY_MAX_LE
            ]
        );
        assert_eq!(
            second,
            [
                P_ZERO,
                READ_BINARY_INS,
                SPLIT_OFFSET_HIGH,
                SM_READ_BINARY_MAX_LE,
                SPLIT_TOTAL_LE - SM_READ_BINARY_MAX_LE
            ]
        );
    }

    #[test]
    fn sfi_read_keeps_its_selector_across_fragments() {
        let command = read_command(SFI_PROBE_P1, P_ZERO, SPLIT_TOTAL_LE);
        let (first, second) = split_protected_read::<String>(command.as_bytes())
            .expect("splittable")
            .expect("an SFI read must split");
        assert_eq!(
            first,
            [
                P_ZERO,
                READ_BINARY_INS,
                SFI_PROBE_P1,
                P_ZERO,
                SM_READ_BINARY_MAX_LE
            ]
        );
        assert_eq!(
            second,
            [
                P_ZERO,
                READ_BINARY_INS,
                SFI_PROBE_P1,
                SM_READ_BINARY_MAX_LE,
                SPLIT_TOTAL_LE - SM_READ_BINARY_MAX_LE
            ]
        );
    }

    #[test]
    fn le_zero_reads_all_as_two_full_fragments() {
        let command = read_command(P_ZERO, P_ZERO, P_ZERO);
        let (first, second) = split_protected_read::<String>(command.as_bytes())
            .expect("splittable")
            .expect("an Le-zero read must split");
        assert_eq!(first[LE_INDEX_TEST], SM_READ_BINARY_MAX_LE);
        assert_eq!(second[LE_INDEX_TEST], SM_READ_BINARY_MAX_LE);
        assert_eq!(second[P1_INDEX_TEST], P_ZERO);
        assert_eq!(second[P2_INDEX_TEST], SM_READ_BINARY_MAX_LE);
    }

    /// Le index in a raw case-2 command under test.
    const LE_INDEX_TEST: usize = 4;
    /// P1 index in a raw case-2 command under test.
    const P1_INDEX_TEST: usize = 2;
    /// P2 index in a raw case-2 command under test.
    const P2_INDEX_TEST: usize = 3;

    #[test]
    fn short_reads_and_other_commands_transmit_whole() {
        for le in [P_ZERO + 1, SM_READ_BINARY_MAX_LE] {
            let command = read_command(P_ZERO, P_ZERO, le);
            assert!(
                split_protected_read::<String>(command.as_bytes())
                    .expect("decodable")
                    .is_none(),
                "Le {le} must not split"
            );
        }
        assert!(
            split_protected_read::<String>(SELECT_EF_APDU)
                .expect("decodable")
                .is_none(),
            "a SELECT must not split"
        );
    }

    #[test]
    fn fragment_leaving_its_offset_form_is_rejected() {
        let direct = read_command(OVERFLOW_OFFSET_HIGH, SM_READ_BINARY_MAX_LE, SPLIT_TOTAL_LE);
        let error = split_protected_read::<String>(direct.as_bytes())
            .expect_err("a direct overflow must fail");
        assert!(matches!(error, SmError::Malformed(_)));

        let sfi = read_command(SFI_OVERFLOW_P1, SM_READ_BINARY_MAX_LE, SPLIT_TOTAL_LE);
        let error =
            split_protected_read::<String>(sfi.as_bytes()).expect_err("an SFI overflow must fail");
        assert!(matches!(error, SmError::Malformed(_)));
    }

    /// A transport replaying scripted outcomes while recording every
    /// command it receives.
    struct ScriptedInner {
        script: Vec<TransportOutcome>,
        seen: Vec<Vec<u8>>,
    }

    impl CardTransport for ScriptedInner {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.seen.push(command.as_bytes().to_vec());
            self.script
                .get(self.seen.len() - 1)
                .cloned()
                .ok_or_else(|| "script exhausted".to_owned())
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("no credential in this test".to_owned())
        }
    }

    /// The protected Le byte a wrapped command carries in its
    /// expected-length object.
    fn protected_le(wire: &[u8]) -> Option<u8> {
        const LEN_OCTET_SKIP: usize = 2;
        let at = wire
            .iter()
            .position(|byte| *byte == super::TAG_PROTECTED_LE)?;
        wire.get(at + LEN_OCTET_SKIP).copied()
    }

    fn scripted_response(payload: &[u8], steps: u32) -> TransportOutcome {
        let [sw1, sw2] = success_bytes();
        TransportOutcome::Response(ResponseApdu {
            body: card_response(steps, payload, StatusWord::Success),
            sw1,
            sw2,
        })
    }

    #[test]
    fn fragmented_read_combines_both_fragments() {
        let first_payload = vec![FIRST_FILL; SM_READ_BINARY_MAX_LE as usize];
        let second_payload = vec![SECOND_FILL; SECOND_FRAGMENT_LEN];
        let mut terminal = SmTransport::new(
            ScriptedInner {
                script: vec![
                    scripted_response(&first_payload, EXCHANGE_STEPS),
                    scripted_response(&second_payload, EXCHANGE_STEPS + EXCHANGE_STEPS),
                ],
                seen: Vec::new(),
            },
            session(),
        );
        let command = read_command(P_ZERO, P_ZERO, SPLIT_TOTAL_LE);
        let outcome = terminal.transmit(&command).expect("fragments combine");
        let response = outcome.into_response().expect("real response");
        assert!(response.is_ok());
        let mut combined = first_payload;
        combined.extend_from_slice(&second_payload);
        assert_eq!(response.body, combined);

        let seen = terminal.into_inner().seen;
        assert_eq!(seen.len(), FRAGMENTED_EXCHANGE_COUNT);
        assert_eq!(
            protected_le(&seen[0]).expect("first Le"),
            SM_READ_BINARY_MAX_LE
        );
        assert_eq!(
            protected_le(&seen[1]).expect("second Le"),
            SPLIT_TOTAL_LE - SM_READ_BINARY_MAX_LE
        );
        assert_eq!(seen[1][P1_INDEX_TEST], P_ZERO);
        assert_eq!(seen[1][P2_INDEX_TEST], SM_READ_BINARY_MAX_LE);
    }

    #[test]
    fn short_first_fragment_returns_without_a_second_exchange() {
        let mut terminal = SmTransport::new(
            ScriptedInner {
                script: vec![scripted_response(SHORT_PAYLOAD, EXCHANGE_STEPS)],
                seen: Vec::new(),
            },
            session(),
        );
        let command = read_command(P_ZERO, P_ZERO, SPLIT_TOTAL_LE);
        let outcome = terminal.transmit(&command).expect("short read ends");
        let response = outcome.into_response().expect("real response");
        assert_eq!(response.body.as_slice(), SHORT_PAYLOAD);
        assert_eq!(terminal.into_inner().seen.len(), SINGLE_EXCHANGE_COUNT);
    }

    #[test]
    fn overlong_first_fragment_returns_without_a_second_exchange() {
        let surplus_len = SM_READ_BINARY_MAX_LE as usize + SURPLUS_EXTRA_LEN;
        let surplus = vec![FIRST_FILL; surplus_len];
        let mut terminal = SmTransport::new(
            ScriptedInner {
                script: vec![scripted_response(&surplus, EXCHANGE_STEPS)],
                seen: Vec::new(),
            },
            session(),
        );
        let command = read_command(P_ZERO, P_ZERO, SPLIT_TOTAL_LE);
        let outcome = terminal
            .transmit(&command)
            .expect("a surplus ends the span");
        let response = outcome.into_response().expect("real response");
        assert_eq!(response.body, surplus);
        assert_eq!(terminal.into_inner().seen.len(), SINGLE_EXCHANGE_COUNT);
    }

    #[test]
    fn fault_first_fragment_returns_the_fault() {
        let mut terminal = SmTransport::new(
            ScriptedInner {
                script: vec![TransportOutcome::NoCard],
                seen: Vec::new(),
            },
            session(),
        );
        let command = read_command(P_ZERO, P_ZERO, SPLIT_TOTAL_LE);
        let outcome = terminal.transmit(&command).expect("fault passes through");
        assert!(matches!(outcome, TransportOutcome::NoCard));
        assert_eq!(terminal.into_inner().seen.len(), SINGLE_EXCHANGE_COUNT);
    }
}
