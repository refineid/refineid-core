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

//! A synthetic organizational card for the tests of the crates layered
//! on the secure channel. Test-only: never enabled by a production
//! build.
//!
//! [`OrganizationalCard`] answers a real [`crate::run_pace`] honestly
//! over NIST P-384 -- the suite the organizational card's EF.CardAccess
//! leads with -- and then plays the card side of secure messaging: it
//! authenticates and decrypts every protected command, records the plain
//! command it carried, and answers it with the next scripted plain
//! response, protected. So a test drives the real terminal handshake and
//! the real channel and asserts the plain wire the card received.
//!
//! The emulator mints no session and no password proof; only the
//! terminal's own handshake does.

use std::collections::VecDeque;

use elliptic_curve::Scalar;
use refineid_apdu::{
    APDU_HEADER_LEN, ApduClass, CardTransport, CommandApdu, CredentialCommand, ResponseApdu,
    StatusWord, TransportOutcome,
};
use refineid_ber::{BerEncoder, BerTag, BerTlv, BerTlvIter, Integer, Oid, Sequence, Set};

use crate::card_access::{
    CardAccess, PACE_ECDH_GM_AES_256_OID, PACE_INFO_VERSION, PaceDomain, PaceInfo,
    UnvalidatedCardAccess,
};
use crate::commands::MseSetAt;
use crate::crypto::container::{AesCbc, Ciphertext};
use crate::crypto::curve::Point;
use crate::crypto::symmetric::{
    AES_BLOCK, Aes256Key, KdfParam, aes256_cbc_decrypt_no_padding, aes256_cbc_encrypt_no_padding,
    aes256_cmac_truncated, aes256_ecb_encrypt_block, kdf_aes256,
};
use crate::handshake::{
    AuthTokenOut, BSI_TR03110_ZERO_IV, DynamicAuthData, EncryptedNonce, KeyAgreeOut,
    MappingDataOut, Ssc, TAG_AUTH_TOKEN_PCD, TAG_DYNAMIC_AUTH, TAG_KEY_AGREE_PCD_PUBLIC,
    TAG_MAP_PCD_PUBLIC, TAG_MSE_DOMAIN, TAG_MSE_MECHANISM, TAG_MSE_PASSWORD, encode_auth_token,
    scalar_from_nonce,
};
use crate::secure_messaging::{
    HEADER_LEN, PADDING_INDICATOR, TAG_CRYPTOGRAM, TAG_MAC, TAG_PROTECTED_LE, TAG_PROTECTED_STATUS,
    iso7816_4_pad, iso7816_4_unpad,
};

/// The curve the emulator runs: the organizational card's preferred
/// generic-mapping domain.
type Curve = p384::NistP384;

/// The card's synthetic mapping private scalar.
const CARD_MAPPING_SCALAR: u64 = 7_340_033;
/// The card's synthetic key-agreement private scalar.
const CARD_KEY_AGREEMENT_SCALAR: u64 = 9_437_189;
/// The card's synthetic nonce, two AES blocks of ASCII, as the
/// organizational card sends.
const CARD_NONCE: &[u8; AES_BLOCK + AES_BLOCK] = b"emulated organizational nonce...";

/// Exchange index of the opening `MSE:Set AT`.
const EXCHANGE_MSE: usize = 0;
/// Exchange index of the encrypted-nonce round.
const EXCHANGE_NONCE: usize = 1;
/// Exchange index of the mapping round.
const EXCHANGE_MAPPING: usize = 2;
/// Exchange index of the key-agreement round.
const EXCHANGE_KEY_AGREEMENT: usize = 3;
/// Exchange index of the mutual-authentication round.
const EXCHANGE_TOKENS: usize = 4;

/// Width of the short-form Lc field (ISO/IEC 7816-4 section 5.1).
const LC_LEN: usize = 1;
/// Width of the short-form Le field (ISO/IEC 7816-4 section 5.1).
const LE_LEN: usize = 1;

/// A one-byte tag of a universal-class ASN.1 type.
fn universal_tag(marker: u16) -> u8 {
    u8::try_from(marker).unwrap_or(u8::MAX)
}

/// The organizational card's EF.CardAccess reduced to the suite the
/// emulator runs: generic mapping over NIST P-384 (FINEID S4-2 v4.0
/// section 6).
///
/// # Panics
///
/// Never for this fixed fixture; a failure is a defect in the fixture.
#[must_use]
pub fn organizational_card_access() -> CardAccess {
    let mut fields = BerEncoder::default();
    fields
        .push_tlv(universal_tag(Oid::TAG), PACE_ECDH_GM_AES_256_OID)
        .expect("the OID encodes");
    fields
        .push_tlv(universal_tag(Integer::TAG), [PACE_INFO_VERSION])
        .expect("the version encodes");
    fields
        .push_tlv(
            universal_tag(Integer::TAG),
            [PaceDomain::NistP384.parameter_id()],
        )
        .expect("the parameter encodes");
    let info =
        refineid_ber::tlv(universal_tag(Sequence::TAG), fields.finish()).expect("PACEInfo encodes");
    let file = refineid_ber::tlv(universal_tag(Set::TAG), info).expect("the SET encodes");
    CardAccess::parse(UnvalidatedCardAccess::from_card_bytes(file)).expect("the fixture parses")
}

/// The card's live secure-messaging state after the handshake.
struct Channel {
    k_enc: Aes256Key,
    k_mac: Aes256Key,
    ssc: Ssc,
}

/// A synthetic organizational card that runs PACE with one password and
/// then answers protected commands from a script.
pub struct OrganizationalCard {
    suite: PaceInfo,
    password_reference: u8,
    password: Vec<u8>,
    exchanges: usize,
    mapped_generator: Option<Point<Curve>>,
    terminal_key_agreement: Option<Point<Curve>>,
    card_key_agreement: Option<Point<Curve>>,
    k_mac: Option<Aes256Key>,
    channel: Option<Channel>,
    answers: VecDeque<ResponseApdu>,
    protected_commands: Vec<Vec<u8>>,
    credential_commands: usize,
}

impl OrganizationalCard {
    /// A card whose PACE password is `password` -- ASCII digits, the
    /// character string the card derives the nonce key from (BSI
    /// TR-03110-3 table 5) -- under `password_reference`, and which
    /// answers the protected commands after the handshake with `answers`,
    /// in order.
    ///
    /// # Panics
    ///
    /// When the fixed card access names no generic-mapping suite, a
    /// defect in the fixture.
    #[must_use]
    pub fn new(password_reference: u8, password: &[u8], answers: Vec<ResponseApdu>) -> Self {
        let suite = organizational_card_access()
            .generic_mapping_suite()
            .expect("the fixture lists the P-384 generic suite");
        Self {
            suite,
            password_reference,
            password: password.to_vec(),
            exchanges: 0,
            mapped_generator: None,
            terminal_key_agreement: None,
            card_key_agreement: None,
            k_mac: None,
            channel: None,
            answers: answers.into(),
            protected_commands: Vec::new(),
            credential_commands: 0,
        }
    }

    /// Every plain command the card recovered from the protected
    /// channel, in order, credential commands included.
    #[must_use]
    pub fn protected_commands(&self) -> &[Vec<u8>] {
        &self.protected_commands
    }

    /// How many commands arrived on the credential path.
    #[must_use]
    pub const fn credential_commands(&self) -> usize {
        self.credential_commands
    }

    /// How many scripted answers are still unused.
    #[must_use]
    pub fn answers_left(&self) -> usize {
        self.answers.len()
    }

    /// The `MSE:Set AT` the terminal must open with, assembled as the
    /// handshake assembles it.
    fn expected_mse(&self) -> Result<Vec<u8>, String> {
        let mechanism = self.suite.protocol_oid();
        let mut encoder = BerEncoder::with_capacity(mechanism.len());
        encoder
            .push_tlv(TAG_MSE_MECHANISM, mechanism)
            .and_then(|()| encoder.push_tlv(TAG_MSE_PASSWORD, [self.password_reference]))
            .and_then(|()| encoder.push_tlv(TAG_MSE_DOMAIN, [self.suite.domain().parameter_id()]))
            .map_err(|_e| "MSE:Set AT does not encode".to_owned())?;
        let command = MseSetAt {
            data: encoder.finish(),
        }
        .into_apdu()
        .map_err(|_e| "MSE:Set AT does not encode".to_owned())?;
        Ok(command.as_bytes().to_vec())
    }

    /// The value of the terminal's `tag` object inside a `GENERAL
    /// AUTHENTICATE` command.
    fn terminal_object(command: &CommandApdu, tag: u8) -> Result<Vec<u8>, String> {
        let bytes = command.as_bytes();
        let data = bytes
            .get(APDU_HEADER_LEN + LC_LEN..bytes.len().saturating_sub(LE_LEN))
            .ok_or_else(|| "GENERAL AUTHENTICATE too short".to_owned())?;
        let outer = BerTlv::<DynamicAuthData>::parse(data).map_err(|e| e.to_string())?;
        let inner = BerTlvIter::new(outer.value())
            .next()
            .ok_or_else(|| "no terminal object".to_owned())?
            .map_err(|e| e.to_string())?;
        if inner.tag() != u16::from(tag) {
            return Err("unexpected terminal object".to_owned());
        }
        Ok(inner.value().to_vec())
    }

    /// A `GENERAL AUTHENTICATE` answer carrying one `T` object.
    fn answer<T: BerTag>(value: &[u8]) -> Result<TransportOutcome, String> {
        let tag = u8::try_from(T::TAG).map_err(|e| e.to_string())?;
        let inner = refineid_ber::tlv(tag, value).map_err(|e| e.to_string())?;
        let body = refineid_ber::tlv(TAG_DYNAMIC_AUTH, inner).map_err(|e| e.to_string())?;
        Ok(TransportOutcome::Response(success(body)))
    }

    fn encode(point: &Point<Curve>) -> Result<Vec<u8>, String> {
        point
            .encode_uncompressed()
            .map(|encoded| encoded.as_bytes().to_vec())
            .ok_or_else(|| "point at infinity".to_owned())
    }

    fn decode(bytes: &[u8]) -> Result<Point<Curve>, String> {
        Point::decode_uncompressed(bytes).ok_or_else(|| "terminal point off the curve".to_owned())
    }

    fn encrypted_nonce(&self) -> Result<TransportOutcome, String> {
        let k_pi = kdf_aes256(&self.password, KdfParam::Password);
        let cipher =
            aes256_cbc_encrypt_no_padding(k_pi.as_bytes(), &BSI_TR03110_ZERO_IV, CARD_NONCE)
                .map_err(|_e| "nonce not block-aligned".to_owned())?;
        Self::answer::<EncryptedNonce>(cipher.as_bytes())
    }

    fn map(&mut self, command: &CommandApdu) -> Result<TransportOutcome, String> {
        let terminal = Self::decode(&Self::terminal_object(command, TAG_MAP_PCD_PUBLIC)?)?;
        let card_scalar = Scalar::<Curve>::from(CARD_MAPPING_SCALAR);
        let card_public = Point::<Curve>::generator().scalar_mul(&card_scalar);
        let shared = terminal.scalar_mul(&card_scalar);
        let nonce_point =
            Point::<Curve>::generator().scalar_mul(&scalar_from_nonce::<Curve>(CARD_NONCE));
        self.mapped_generator = Some(nonce_point.add(&shared));
        Self::answer::<MappingDataOut>(&Self::encode(&card_public)?)
    }

    fn agree(&mut self, command: &CommandApdu) -> Result<TransportOutcome, String> {
        let terminal = Self::decode(&Self::terminal_object(command, TAG_KEY_AGREE_PCD_PUBLIC)?)?;
        let card_scalar = Scalar::<Curve>::from(CARD_KEY_AGREEMENT_SCALAR);
        let card_public = self
            .mapped_generator
            .as_ref()
            .ok_or_else(|| "key agreement before mapping".to_owned())?
            .scalar_mul(&card_scalar);
        let shared_x = terminal
            .scalar_mul(&card_scalar)
            .x_coordinate()
            .ok_or_else(|| "shared point at infinity".to_owned())?;
        self.k_mac = Some(kdf_aes256(shared_x.as_slice(), KdfParam::Mac));
        self.channel = Some(Channel {
            k_enc: kdf_aes256(shared_x.as_slice(), KdfParam::Encryption),
            k_mac: kdf_aes256(shared_x.as_slice(), KdfParam::Mac),
            ssc: Ssc::INITIAL,
        });
        let answer = Self::answer::<KeyAgreeOut>(&Self::encode(&card_public)?);
        self.terminal_key_agreement = Some(terminal);
        self.card_key_agreement = Some(card_public);
        answer
    }

    fn authenticate(&self, command: &CommandApdu) -> Result<TransportOutcome, String> {
        let missing = || "authentication before key agreement".to_owned();
        let k_mac = self.k_mac.as_ref().ok_or_else(missing)?;
        let card_public = self.card_key_agreement.as_ref().ok_or_else(missing)?;
        let terminal = self.terminal_key_agreement.as_ref().ok_or_else(missing)?;
        let token_input = encode_auth_token(self.suite, card_public).ok_or_else(missing)?;
        let expected = aes256_cmac_truncated(k_mac.as_bytes(), &token_input);
        if Self::terminal_object(command, TAG_AUTH_TOKEN_PCD)? != expected.as_bytes() {
            return Err("the terminal token does not verify".to_owned());
        }
        let card_input = encode_auth_token(self.suite, terminal).ok_or_else(missing)?;
        let t_picc = aes256_cmac_truncated(k_mac.as_bytes(), &card_input);
        Self::answer::<AuthTokenOut>(t_picc.as_bytes())
    }

    /// Authenticate and decrypt one protected command, returning the
    /// plain command it carries.
    fn unwrap_command(&mut self, wire: &[u8]) -> Result<Vec<u8>, String> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| "protected command before the handshake".to_owned())?;
        let header: [u8; HEADER_LEN] = wire
            .get(..HEADER_LEN)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| "protected command shorter than its header".to_owned())?;
        let [class, instruction, p1, p2] = header;
        if class != ApduClass::SecureMessaging.as_byte() {
            return Err("command not under secure messaging".to_owned());
        }
        let lc = usize::from(
            *wire
                .get(HEADER_LEN)
                .ok_or_else(|| "protected command without Lc".to_owned())?,
        );
        let body_start = HEADER_LEN + LC_LEN;
        let body = wire
            .get(body_start..body_start + lc)
            .ok_or_else(|| "protected body truncated".to_owned())?;
        channel.ssc.increment();

        let mut cryptogram = None;
        let mut protected_le = None;
        let mut mac = None;
        for parsed in BerTlvIter::new(body) {
            let tlv = parsed.map_err(|e| e.to_string())?;
            let tag = tlv.tag();
            if tag == u16::from(TAG_CRYPTOGRAM) {
                cryptogram = Some(tlv.value().to_vec());
            } else if tag == u16::from(TAG_PROTECTED_LE) {
                protected_le = Some(tlv.value().to_vec());
            } else if tag == u16::from(TAG_MAC) {
                mac = Some(tlv.value().to_vec());
            } else {
                return Err("unexpected protected object".to_owned());
            }
        }

        let mut mac_input = channel.ssc.as_bytes().to_vec();
        mac_input.extend_from_slice(&iso7816_4_pad(&header));
        if let Some(value) = &cryptogram {
            mac_input.extend(refineid_ber::tlv(TAG_CRYPTOGRAM, value).map_err(|e| e.to_string())?);
        }
        if let Some(value) = &protected_le {
            mac_input
                .extend(refineid_ber::tlv(TAG_PROTECTED_LE, value).map_err(|e| e.to_string())?);
        }
        let computed = aes256_cmac_truncated(channel.k_mac.as_bytes(), &iso7816_4_pad(&mac_input));
        if mac.as_deref() != Some(computed.as_bytes()) {
            return Err("protected command authentication failed".to_owned());
        }

        let data = match cryptogram {
            Some(value) => {
                let (indicator, cipher) = value
                    .split_first()
                    .ok_or_else(|| "empty cryptogram".to_owned())?;
                if *indicator != PADDING_INDICATOR {
                    return Err("cryptogram padding indicator".to_owned());
                }
                let iv = aes256_ecb_encrypt_block(channel.k_enc.as_bytes(), channel.ssc.as_bytes());
                let plain = aes256_cbc_decrypt_no_padding(
                    channel.k_enc.as_bytes(),
                    &iv,
                    &Ciphertext::<AesCbc>::new(cipher.to_vec()),
                )
                .map_err(|_e| "cryptogram not whole blocks".to_owned())?;
                iso7816_4_unpad(&plain)
            }
            None => Vec::new(),
        };

        let mut plain = vec![ApduClass::Plain.as_byte(), instruction, p1, p2];
        if !data.is_empty() {
            plain.push(u8::try_from(data.len()).map_err(|e| e.to_string())?);
            plain.extend_from_slice(&data);
        }
        if let Some(le) = protected_le {
            plain.extend_from_slice(&le);
        }
        Ok(plain)
    }

    /// Protect one plain answer for the terminal.
    fn wrap_response(&mut self, answer: &ResponseApdu) -> Result<ResponseApdu, String> {
        let channel = self
            .channel
            .as_mut()
            .ok_or_else(|| "protected answer before the handshake".to_owned())?;
        channel.ssc.increment();
        let mut objects = Vec::new();
        if !answer.body.is_empty() {
            let iv = aes256_ecb_encrypt_block(channel.k_enc.as_bytes(), channel.ssc.as_bytes());
            let cipher = aes256_cbc_encrypt_no_padding(
                channel.k_enc.as_bytes(),
                &iv,
                &iso7816_4_pad(&answer.body),
            )
            .map_err(|_e| "padded answer not block-aligned".to_owned())?;
            let mut value = vec![PADDING_INDICATOR];
            value.extend_from_slice(cipher.as_bytes());
            objects.extend(refineid_ber::tlv(TAG_CRYPTOGRAM, value).map_err(|e| e.to_string())?);
        }
        objects.extend(
            refineid_ber::tlv(TAG_PROTECTED_STATUS, [answer.sw1, answer.sw2])
                .map_err(|e| e.to_string())?,
        );
        let mut mac_input = channel.ssc.as_bytes().to_vec();
        mac_input.extend_from_slice(&objects);
        let tag = aes256_cmac_truncated(channel.k_mac.as_bytes(), &iso7816_4_pad(&mac_input));
        objects.extend(refineid_ber::tlv(TAG_MAC, tag.as_bytes()).map_err(|e| e.to_string())?);
        Ok(success(objects))
    }

    /// Recover, record and answer one protected command.
    fn protected(&mut self, wire: &[u8]) -> Result<TransportOutcome, String> {
        let plain = self.unwrap_command(wire)?;
        self.protected_commands.push(plain);
        let answer = self
            .answers
            .pop_front()
            .ok_or_else(|| "the script has no answer left".to_owned())?;
        Ok(TransportOutcome::Response(self.wrap_response(&answer)?))
    }
}

fn success(body: Vec<u8>) -> ResponseApdu {
    let [sw1, sw2] = StatusWord::Success.as_u16().to_be_bytes();
    ResponseApdu { body, sw1, sw2 }
}

impl CardTransport for OrganizationalCard {
    type Error = String;

    fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let index = self.exchanges;
        self.exchanges = self.exchanges.saturating_add(1);
        match index {
            EXCHANGE_MSE => {
                if command.as_bytes() != self.expected_mse()?.as_slice() {
                    return Err("unexpected MSE:Set AT".to_owned());
                }
                Ok(TransportOutcome::Response(success(Vec::new())))
            }
            EXCHANGE_NONCE => self.encrypted_nonce(),
            EXCHANGE_MAPPING => self.map(command),
            EXCHANGE_KEY_AGREEMENT => self.agree(command),
            EXCHANGE_TOKENS => self.authenticate(command),
            _ => self.protected(command.as_bytes()),
        }
    }

    fn transmit_credential(
        &mut self,
        command: CredentialCommand,
    ) -> Result<TransportOutcome, Self::Error> {
        self.credential_commands = self.credential_commands.saturating_add(1);
        let wire = command.expose_wire(<[u8]>::to_vec);
        self.protected(&wire)
    }
}
