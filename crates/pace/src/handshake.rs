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

//! The PACE handshake driver.
//!
//! PACE authenticates a card session from a password before any
//! application command is exchanged; the FINEID cards require it on the
//! contactless interface. The citizen cards take the Card Access Number
//! as the password; the organizational cards take PIN 1 or PIN 2
//! instead (FINEID S1 v4.0, organizational cards, section 2.1, and
//! FINEID S4-2 v4.0 section 6). This driver runs
//! `id-PACE-ECDH-GM-AES-CBC-CMAC-256` (BSI TR-03110-3 section A.5, ICAO
//! Doc 9303 Part 11 section 4.4) over the standardized domain parameter
//! the card's EF.CardAccess lists, preferring NIST P-384, then
//! brainpoolP384r1, then NIST P-256. On success it returns the two
//! session keys and the initial send sequence counter for the
//! secure-messaging layer.
//!
//! The wire flow is `MSE:Set AT` followed by four `GENERAL AUTHENTICATE`
//! rounds: fetch and decrypt the card nonce; map the nonce to a session
//! generator; agree an ephemeral shared point; and exchange and verify
//! mutual authentication tokens. With a PIN as the password the card
//! spends a try on a failed handshake, so `MSE:Set AT`'s answer is read
//! as the PIN's tries left and the retry floor decides before the first
//! `GENERAL AUTHENTICATE` is sent.

use elliptic_curve::ff::Field as _;
use elliptic_curve::{FieldBytes, NonZeroScalar, Scalar};
use subtle::ConstantTimeEq as _;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use refineid_apdu::{
    CardTransport, CommandDataError, PinRetries, ResponseApdu, StatusWord, TransportOutcome,
};
use refineid_auth::{
    FlooredCredential, PacePasswordKey, Pin1, Pin2, PinReferenceScheme, PinSlot, PinStatus,
    RetryFloorRefusal, check_retry_floor,
};
use refineid_ber::{BerEncodeError, BerError, BerTag, BerTlv};
use refineid_pkcs15::Pkcs15Error;

use crate::can::Can;
use crate::card_access::{CardAccess, CardAccessError, PaceDomain, PaceInfo};
use crate::commands::{GeneralAuthenticate, MseSetAt};
use crate::crypto::container::{AesCbc, Ciphertext};
use crate::crypto::curve::{PaceCurve, Point};
use crate::crypto::symmetric::{
    AES_BLOCK, AES_KEY_LEN, Aes256Key, CMAC_TAG_TRUNCATED, KdfParam, aes256_cbc_decrypt_no_padding,
    aes256_cmac_truncated, kdf_aes256,
};
use crate::rng;

/// Dynamic-authentication-data template tag, wrapping every round's
/// payload (BSI TR-03110-3 section A.5).
struct DynamicAuthData;
impl BerTag for DynamicAuthData {
    const TAG: u16 = 0x7C;
}

/// The card's encrypted-nonce response payload.
struct EncryptedNonce;
impl BerTag for EncryptedNonce {
    const TAG: u16 = 0x80;
}

/// The card's mapping-data response.
struct MappingDataOut;
impl BerTag for MappingDataOut {
    const TAG: u16 = 0x82;
}

/// The card's key-agreement response.
struct KeyAgreeOut;
impl BerTag for KeyAgreeOut {
    const TAG: u16 = 0x84;
}

/// The card's authentication-token response.
struct AuthTokenOut;
impl BerTag for AuthTokenOut {
    const TAG: u16 = 0x86;
}

/// Password reference for the printed Card Access Number (BSI
/// TR-03110-3 section B.14.1).
pub const PASSWORD_REF_CAN: u8 = 0x02;

/// The tries a PIN of the organizational card starts with (FINEID S4-2
/// v4.0 sections 4.3.1 and 4.3.3). `MSE:Set AT` answers success, rather
/// than a counter, while a PIN still has them (BSI TR-03110-3 section
/// B.14.1).
const ORGANIZATIONAL_PIN_INITIAL_TRIES: u8 = 5;

/// `MSE:Set AT` warning: the password is deactivated (BSI TR-03110-3
/// section B.14.1).
const SW_PASSWORD_DEACTIVATED: u16 = 0x6283;

/// All-zero initialisation vector for the encrypted-nonce decryption
/// (BSI TR-03110-3 section A.5.1.2).
const BSI_TR03110_ZERO_IV: [u8; AES_BLOCK] = [0_u8; AES_BLOCK];

/// The longest encrypted nonce accepted. The chip chooses the nonce
/// length as a multiple of the block size (ICAO Doc 9303 Part 11 section
/// 4.4.3.3); the citizen cards send one AES block and the
/// organizational card two. Four blocks bound what is buffered.
const NONCE_MAX_LEN: usize = 4 * AES_BLOCK;

/// The radix of one nonce octet in the big-endian integer the nonce
/// encodes.
const OCTET_RADIX: u64 = 1 << u8::BITS;

/// The card's mutual-authentication token length.
const AUTH_TOKEN_LEN: usize = CMAC_TAG_TRUNCATED;

/// Mechanism-reference object tag inside `MSE:Set AT`.
pub(crate) const TAG_MSE_MECHANISM: u8 = 0x80;
/// Password-reference object tag inside `MSE:Set AT`.
pub(crate) const TAG_MSE_PASSWORD: u8 = 0x83;
/// Domain-reference object tag inside `MSE:Set AT`.
pub(crate) const TAG_MSE_DOMAIN: u8 = 0x84;
/// The dynamic-authentication-data envelope tag as a one-byte value.
const TAG_DYNAMIC_AUTH: u8 = 0x7C;
/// Map-nonce request object tag: the terminal's ephemeral public key.
const TAG_MAP_PCD_PUBLIC: u8 = 0x81;
/// Key-agreement request object tag: the terminal's ephemeral public
/// key.
const TAG_KEY_AGREE_PCD_PUBLIC: u8 = 0x83;
/// Mutual-authentication request object tag: the terminal's token.
const TAG_AUTH_TOKEN_PCD: u8 = 0x85;
/// Public-key data template tag (BSI TR-03110-3 section B.7).
const TAG_PUBLIC_KEY_TEMPLATE: u16 = 0x7F49;
/// ASN.1 universal object-identifier tag.
const TAG_ASN1_OID: u8 = 0x06;
/// EC-point object tag inside the public-key template.
const TAG_PUBLIC_KEY_POINT: u8 = 0x86;

/// The password a PACE handshake authenticates the channel with.
///
/// Borrowed: PACE never sends the password, it derives the nonce key
/// from it, and the holder keeps custody -- an organizational card's PIN
/// is still needed for the VERIFY that follows on the channel.
#[derive(Debug)]
pub enum PacePassword<'a> {
    /// The Card Access Number printed on a citizen card.
    Can(&'a Can),
    /// PIN 1 of an organizational card.
    Pin1(&'a Pin1),
    /// PIN 2 of an organizational card.
    Pin2(&'a Pin2),
}

impl PacePassword<'_> {
    /// The `MSE:Set AT` password reference. The organizational card
    /// enables PACE under the security-data-object identifier of the PIN
    /// (FINEID S4-2 v4.0 section 6), the PIN AUTH and PIN SIG
    /// identifiers its VERIFY uses (section 4.3); BSI TR-03110-3 section
    /// B.14.1 assigns the same two references.
    const fn reference(&self) -> u8 {
        match self {
            Self::Can(_) => PASSWORD_REF_CAN,
            Self::Pin1(_) => PinReferenceScheme::Organizational.reference(PinSlot::Pin1),
            Self::Pin2(_) => PinReferenceScheme::Organizational.reference(PinSlot::Pin2),
        }
    }

    /// The PIN whose retry counter a failed handshake spends; `None` for
    /// the Card Access Number, which has no counter.
    const fn floored_credential(&self) -> Option<FlooredCredential> {
        match self {
            Self::Can(_) => None,
            Self::Pin1(_) => Some(FlooredCredential::Pin1),
            Self::Pin2(_) => Some(FlooredCredential::Pin2),
        }
    }

    /// `K_pi`, the nonce key (BSI TR-03110-3 section A.2.3): the
    /// password's character string under the password counter. A PIN's
    /// key is derived inside the crate that owns the PIN.
    fn key(&self) -> PasswordKey {
        match self {
            Self::Can(can) => {
                PasswordKey::Can(kdf_aes256(can.password_bytes(), KdfParam::Password))
            }
            Self::Pin1(pin) => PasswordKey::Pin(pin.pace_password_key()),
            Self::Pin2(pin) => PasswordKey::Pin(pin.pace_password_key()),
        }
    }
}

/// A derived nonce key, from either password class; both zeroize on
/// drop.
enum PasswordKey {
    Can(Aes256Key),
    Pin(PacePasswordKey),
}

impl PasswordKey {
    const fn as_bytes(&self) -> &[u8; AES_KEY_LEN] {
        match self {
            Self::Can(key) => key.as_bytes(),
            Self::Pin(key) => key.as_bytes(),
        }
    }
}

/// The two session keys and the send sequence counter a completed PACE
/// handshake produces.
///
/// Not clonable: one PACE run establishes one channel, and duplicating the
/// keys would let two channels share a send sequence counter -- a repeated
/// CBC IV and CMAC input. The fields are crate-private; the only sink is
/// [`crate::SmTransport::new`], which consumes the session.
pub struct PaceSession {
    /// The AES-256 secure-messaging encryption key.
    pub(crate) k_enc: Aes256Key,
    /// The AES-256 secure-messaging message-authentication key.
    pub(crate) k_mac: Aes256Key,
    /// The send sequence counter, initially zero.
    pub(crate) ssc: Ssc,
}

impl core::fmt::Debug for PaceSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PaceSession([redacted])")
    }
}

/// The secure-messaging send sequence counter (BSI TR-03110-3 section
/// F.4): a big-endian counter stepped before every wrap and unwrap, the
/// terminal and card advancing it in lockstep.
///
/// A distinct type from an initialisation vector or a cipher block,
/// which are also block-sized and also start all-zero, so the counter
/// cannot be fed where one of those belongs, and the increment lives in
/// one place.
///
/// Neither `Copy` nor `Clone`: the counter has a single owner that
/// advances in lockstep with the card. A duplicate could advance
/// independently, and a reused counter repeats the CBC initialisation
/// vector and the CMAC input under the session key.
#[derive(Debug, PartialEq, Eq)]
pub struct Ssc([u8; AES_BLOCK]);

impl Ssc {
    /// The fresh-session counter, all zero.
    pub const INITIAL: Self = Self([0_u8; AES_BLOCK]);

    /// Step the counter by one, big-endian, wrapping at the block
    /// boundary as the card's arithmetic does.
    pub fn increment(&mut self) {
        for byte in self.0.iter_mut().rev() {
            if *byte == u8::MAX {
                *byte = 0;
            } else {
                *byte = byte.wrapping_add(1);
                return;
            }
        }
    }

    /// Borrow the counter bytes for initialisation-vector derivation and
    /// message-authentication input.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AES_BLOCK] {
        &self.0
    }
}

/// A failure from the PACE handshake.
#[derive(Debug)]
pub enum PaceError<E> {
    /// Adapter-level transport failure.
    Transport(E),
    /// A transport-level state transition instead of a response.
    Outcome(TransportOutcome),
    /// Selecting or reading EF.CardAccess failed.
    CardAccessRead(Pkcs15Error<E>),
    /// EF.CardAccess did not parse.
    CardAccess(CardAccessError),
    /// EF.CardAccess lists no generic-mapping AES-256 suite over a
    /// domain parameter this crate implements.
    NoSupportedSuite,
    /// The retry floor refused the PIN before any `GENERAL
    /// AUTHENTICATE` was sent: the card reported two, one or no tries
    /// left, or the PIN blocked.
    RetryFloor(RetryFloorRefusal),
    /// The card reports the PIN password deactivated (BSI TR-03110-3
    /// section B.14.1); nothing was sent after `MSE:Set AT`.
    PasswordDeactivated,
    /// The card refused the handshake with a PIN password and reports
    /// the tries left (BSI TR-03110-3 section B.14.2): a wrong PIN.
    WrongPin {
        /// The tries the card reports left.
        retries_left: PinRetries,
    },
    /// A BER parse failure on a card response.
    Ber(BerError),
    /// A command or object could not be encoded within the short form.
    Encoding,
    /// The card returned a non-success status word at a named stage.
    Status(&'static str, StatusWord),
    /// A card response did not match the expected shape at a named
    /// stage.
    UnexpectedResponse(&'static str),
    /// The card sent an off-curve or mis-encoded EC point.
    InvalidPoint,
    /// The card answered with the terminal's own ephemeral public key
    /// (ICAO Doc 9303 Part 11 section 4.4.1, step 4 d).
    ReflectedKey,
    /// The mutual-authentication token did not match; the terminal and
    /// card derived different keys, almost always a wrong password.
    AuthMismatch,
    /// The operating-system random-number generator was unavailable.
    Random(rng::Failure),
}

impl<E: core::fmt::Display> core::fmt::Display for PaceError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "PACE transport: {e}"),
            Self::Outcome(outcome) => write!(f, "PACE transport state: {outcome}"),
            Self::CardAccessRead(e) => write!(f, "PACE: reading EF.CardAccess: {e}"),
            Self::CardAccess(e) => write!(f, "PACE: {e}"),
            Self::NoSupportedSuite => {
                f.write_str("PACE: EF.CardAccess lists no suite this software runs")
            }
            Self::RetryFloor(refusal) => write!(f, "{refusal}"),
            Self::PasswordDeactivated => f.write_str("PACE: the card reports the PIN deactivated"),
            Self::WrongPin { retries_left } => {
                write!(
                    f,
                    "PACE: the card refused the PIN, {retries_left} tries left"
                )
            }
            Self::Ber(e) => write!(f, "PACE BER: {e}"),
            Self::Encoding => f.write_str("PACE: object exceeds the short form"),
            Self::Status(stage, sw) => write!(f, "PACE {stage}: card returned {sw}"),
            Self::UnexpectedResponse(what) => write!(f, "PACE unexpected response: {what}"),
            Self::InvalidPoint => f.write_str("PACE: card sent an off-curve EC point"),
            Self::ReflectedKey => f.write_str("PACE: card echoed the terminal's ephemeral key"),
            Self::AuthMismatch => f.write_str("PACE: mutual authentication token did not match"),
            Self::Random(e) => write!(f, "PACE random: {e}"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for PaceError<E> {}

impl<E> From<BerError> for PaceError<E> {
    fn from(error: BerError) -> Self {
        Self::Ber(error)
    }
}

impl<E> From<BerEncodeError> for PaceError<E> {
    fn from(_error: BerEncodeError) -> Self {
        Self::Encoding
    }
}

impl<E> From<CommandDataError> for PaceError<E> {
    fn from(_error: CommandDataError) -> Self {
        Self::Encoding
    }
}

/// The steps one through four state carried into the mutual-auth round.
///
/// No `Debug`: the state holds the ephemeral private scalar, which must
/// never reach a formatter. Every field zeroizes on drop, so the scalar
/// and the points it was combined with do not outlive the handshake.
#[derive(ZeroizeOnDrop)]
pub(crate) struct PaceMidwayState<C: PaceCurve> {
    /// The card's key-agreement public point.
    v_picc: Point<C>,
    /// The terminal's ephemeral private scalar.
    u_pcd: NonZeroScalar<C>,
    /// The terminal's key-agreement public point.
    u_pcd_public: Point<C>,
}

/// The source of the terminal's ephemeral scalars: fills a buffer with
/// random bytes, or fails.
pub(crate) type ScalarSource<'a> = &'a mut dyn FnMut(&mut [u8]) -> Result<(), rng::Failure>;

/// Run the PACE handshake.
///
/// Picks the generic-mapping suite from `card_access` (read it with
/// [`crate::read_card_access`]) and authenticates the channel with
/// `password`. The card must be at master-file level; a FINEID card
/// refuses the opening command from an application context, so select
/// the master file first when the prior state is unknown. On success,
/// wrap the same transport in the secure-messaging layer and run the
/// protected command chain through it.
///
/// A wrong Card Access Number spends no counter and surfaces as a
/// status-word or token-mismatch failure. A PIN password is checked
/// against the retry floor before the first `GENERAL AUTHENTICATE`: at
/// two, one or no tries left, or a blocked or deactivated PIN, nothing
/// further is sent. A wrong PIN surfaces as [`PaceError::WrongPin`] with
/// the tries the card reports left.
///
/// # Errors
///
/// Any EF.CardAccess, retry-floor, transport, BER, status-word,
/// off-curve-point, or token-mismatch failure encountered during the
/// handshake; see [`PaceError`].
pub fn run_pace<T: CardTransport>(
    transport: &mut T,
    card_access: &CardAccess,
    password: PacePassword<'_>,
) -> Result<PaceSession, PaceError<T::Error>> {
    run_pace_drawing(transport, card_access, &password, &mut rng::fill)
}

/// [`run_pace`] with the terminal's scalars drawn from `draw`.
pub(crate) fn run_pace_drawing<T: CardTransport>(
    transport: &mut T,
    card_access: &CardAccess,
    password: &PacePassword<'_>,
    draw: ScalarSource<'_>,
) -> Result<PaceSession, PaceError<T::Error>> {
    let suite = card_access
        .generic_mapping_suite()
        .ok_or(PaceError::NoSupportedSuite)?;
    match suite.domain() {
        PaceDomain::NistP256 => handshake::<p256::NistP256, T>(transport, suite, password, draw),
        PaceDomain::NistP384 => handshake::<p384::NistP384, T>(transport, suite, password, draw),
        PaceDomain::BrainpoolP384r1 => {
            handshake::<bp384::BrainpoolP384r1, T>(transport, suite, password, draw)
        }
    }
}

/// The handshake over the curve the suite's domain parameter names.
fn handshake<C: PaceCurve, T: CardTransport>(
    transport: &mut T,
    suite: PaceInfo,
    password: &PacePassword<'_>,
    draw: ScalarSource<'_>,
) -> Result<PaceSession, PaceError<T::Error>> {
    set_authentication_template(transport, suite, password)?;
    // The mapping nonce lives in a scrubbed buffer for its whole lifetime.
    let nonce = get_encrypted_nonce(transport, password)?;
    let state = map_nonce_and_key_agreement::<C, T>(transport, password, &nonce, draw)?;
    run_mutual_authentication(transport, suite, password, state)
}

/// Transmit a replay-safe command and demand a real response.
fn transmit<T: CardTransport>(
    transport: &mut T,
    command: &refineid_apdu::CommandApdu,
) -> Result<ResponseApdu, PaceError<T::Error>> {
    transport
        .transmit(command)
        .map_err(PaceError::Transport)?
        .into_response()
        .map_err(PaceError::Outcome)
}

/// Transmit one `GENERAL AUTHENTICATE` round and demand success. With a
/// PIN password, a counter answer names a wrong PIN (BSI TR-03110-3
/// section B.14.2).
fn exchange_round<T: CardTransport>(
    transport: &mut T,
    password: &PacePassword<'_>,
    command: &refineid_apdu::CommandApdu,
    stage: &'static str,
) -> Result<ResponseApdu, PaceError<T::Error>> {
    let response = transmit(transport, command)?;
    if response.is_ok() {
        return Ok(response);
    }
    match (password.floored_credential(), response.status_word()) {
        (Some(_pin), StatusWord::PinIncorrect { retries }) => Err(PaceError::WrongPin {
            retries_left: retries,
        }),
        (_, status) => Err(PaceError::Status(stage, status)),
    }
}

/// Step one: announce the mechanism, password reference, and domain,
/// then, for a PIN, read the answer as the PIN's tries left and apply
/// the retry floor.
fn set_authentication_template<T: CardTransport>(
    transport: &mut T,
    suite: PaceInfo,
    password: &PacePassword<'_>,
) -> Result<(), PaceError<T::Error>> {
    let mechanism = suite.protocol_oid();
    let mut encoder = refineid_ber::BerEncoder::with_capacity(mechanism.len());
    encoder.push_tlv(TAG_MSE_MECHANISM, mechanism)?;
    encoder.push_tlv(TAG_MSE_PASSWORD, [password.reference()])?;
    encoder.push_tlv(TAG_MSE_DOMAIN, [suite.domain().parameter_id()])?;
    let command = MseSetAt {
        data: encoder.finish(),
    }
    .into_apdu()?;
    let response = transmit(transport, &command)?;
    let status = response.status_word();
    let Some(credential) = password.floored_credential() else {
        return if response.is_ok() {
            Ok(())
        } else {
            Err(PaceError::Status("MSE:Set AT", status))
        };
    };
    let pin_status = match status {
        StatusWord::Success => PinRetries::from_nibble(ORGANIZATIONAL_PIN_INITIAL_TRIES)
            .map_or(PinStatus::NoInfo, PinStatus::Remaining),
        StatusWord::PinIncorrect { retries } if retries.is_exhausted() => PinStatus::Locked,
        StatusWord::PinIncorrect { retries } => PinStatus::Remaining(retries),
        StatusWord::Other(SW_PASSWORD_DEACTIVATED) => return Err(PaceError::PasswordDeactivated),
        other => return Err(PaceError::Status("MSE:Set AT", other)),
    };
    check_retry_floor(credential, pin_status).map_err(PaceError::RetryFloor)
}

/// Step two: fetch and decrypt the card's nonce: a non-zero multiple of
/// the AES block, up to [`NONCE_MAX_LEN`], decrypted in CBC mode with
/// the all-zero IV over every block (ICAO Doc 9303 Part 11 section
/// 4.4.3.3).
fn get_encrypted_nonce<T: CardTransport>(
    transport: &mut T,
    password: &PacePassword<'_>,
) -> Result<Zeroizing<Vec<u8>>, PaceError<T::Error>> {
    let request = refineid_ber::tlv(TAG_DYNAMIC_AUTH, [])?;
    let command = GeneralAuthenticate {
        chain: true,
        payload: request,
    }
    .into_apdu()?;
    let response = exchange_round(transport, password, &command, "GA-1 encrypted nonce")?;

    let outer = BerTlv::<DynamicAuthData>::parse(&response.body)?;
    let inner = BerTlv::<EncryptedNonce>::parse(outer.value())?;
    let length = inner.value().len();
    if length == 0 || length % AES_BLOCK != 0 || length > NONCE_MAX_LEN {
        return Err(PaceError::UnexpectedResponse(
            "encrypted nonce wrong length",
        ));
    }

    let k_pi = password.key();
    let ciphertext = Ciphertext::<AesCbc>::new(inner.value().to_vec());
    // The decrypted nonce is the PACE mapping secret; the buffer that
    // carries it is erased on drop.
    let nonce = Zeroizing::new(
        aes256_cbc_decrypt_no_padding(k_pi.as_bytes(), &BSI_TR03110_ZERO_IV, &ciphertext).map_err(
            |_unaligned| PaceError::UnexpectedResponse("encrypted nonce not block-aligned"),
        )?,
    );
    if nonce.len() != length {
        return Err(PaceError::UnexpectedResponse(
            "decrypted nonce wrong length",
        ));
    }
    Ok(nonce)
}

/// Steps three and four: map the nonce to a session generator by the
/// generic mapping, `G' = s * G + H` with `H` the anonymous
/// Diffie-Hellman point (ICAO Doc 9303 Part 11 section 4.4.3.3.1), then
/// run the ephemeral ECDH on it.
fn map_nonce_and_key_agreement<C: PaceCurve, T: CardTransport>(
    transport: &mut T,
    password: &PacePassword<'_>,
    nonce: &[u8],
    draw: ScalarSource<'_>,
) -> Result<PaceMidwayState<C>, PaceError<T::Error>> {
    let x_pcd = random_scalar_mod_n::<C, T::Error>(draw)?;
    let x_pcd_public = Point::<C>::generator().scalar_mul(&x_pcd);
    let x_pcd_bytes = x_pcd_public
        .encode_uncompressed()
        .ok_or(PaceError::InvalidPoint)?;
    let payload = refineid_ber::tlv(
        TAG_DYNAMIC_AUTH,
        refineid_ber::tlv(TAG_MAP_PCD_PUBLIC, x_pcd_bytes.as_bytes())?,
    )?;
    let command = GeneralAuthenticate {
        chain: true,
        payload,
    }
    .into_apdu()?;
    let response = exchange_round(transport, password, &command, "GA-2 map nonce")?;
    let outer = BerTlv::<DynamicAuthData>::parse(&response.body)?;
    let card_y = BerTlv::<MappingDataOut>::parse(outer.value())?;
    let y_picc = Point::<C>::decode_uncompressed(card_y.value()).ok_or(PaceError::InvalidPoint)?;
    reject_reflection(&x_pcd_public, &y_picc)?;

    // The mapped generator and everything it is built from depend on
    // the nonce and the private scalar; each lives in a scrubbed owner.
    let h = Zeroizing::new(y_picc.scalar_mul(&x_pcd));
    let s_scalar = scalar_from_nonce::<C>(nonce);
    let s_g = Zeroizing::new(Point::<C>::generator().scalar_mul(&s_scalar));
    let mapped_g = Zeroizing::new(s_g.add(&h));

    let u_pcd = random_scalar_mod_n::<C, T::Error>(draw)?;
    let u_pcd_public = mapped_g.scalar_mul(&u_pcd);
    let u_pcd_bytes = u_pcd_public
        .encode_uncompressed()
        .ok_or(PaceError::InvalidPoint)?;
    let payload = refineid_ber::tlv(
        TAG_DYNAMIC_AUTH,
        refineid_ber::tlv(TAG_KEY_AGREE_PCD_PUBLIC, u_pcd_bytes.as_bytes())?,
    )?;
    let command = GeneralAuthenticate {
        chain: true,
        payload,
    }
    .into_apdu()?;
    let response = exchange_round(transport, password, &command, "GA-3 key agreement")?;
    let outer = BerTlv::<DynamicAuthData>::parse(&response.body)?;
    let card_v = BerTlv::<KeyAgreeOut>::parse(outer.value())?;
    let v_picc = Point::<C>::decode_uncompressed(card_v.value()).ok_or(PaceError::InvalidPoint)?;
    reject_reflection(&u_pcd_public, &v_picc)?;

    Ok(PaceMidwayState {
        v_picc,
        u_pcd: *u_pcd,
        u_pcd_public,
    })
}

/// Step five: exchange and verify the mutual-authentication tokens, then
/// derive the session keys.
pub(crate) fn run_mutual_authentication<C: PaceCurve, T: CardTransport>(
    transport: &mut T,
    suite: PaceInfo,
    password: &PacePassword<'_>,
    state: PaceMidwayState<C>,
) -> Result<PaceSession, PaceError<T::Error>> {
    let shared = Zeroizing::new(state.v_picc.scalar_mul(&state.u_pcd));
    let shared_x_bytes = shared.x_coordinate().ok_or(PaceError::InvalidPoint)?;

    let k_enc = kdf_aes256(shared_x_bytes.as_slice(), KdfParam::Encryption);
    let k_mac = kdf_aes256(shared_x_bytes.as_slice(), KdfParam::Mac);

    let token_for_card = encode_auth_token(suite, &state.v_picc).ok_or(PaceError::InvalidPoint)?;
    let t_pcd = aes256_cmac_truncated(k_mac.as_bytes(), &token_for_card);

    let payload = refineid_ber::tlv(
        TAG_DYNAMIC_AUTH,
        refineid_ber::tlv(TAG_AUTH_TOKEN_PCD, t_pcd.as_bytes())?,
    )?;
    let command = GeneralAuthenticate {
        chain: false,
        payload,
    }
    .into_apdu()?;
    let response = exchange_round(transport, password, &command, "GA-4 mutual authentication")?;

    let outer = BerTlv::<DynamicAuthData>::parse(&response.body)?;
    let card_tag = BerTlv::<AuthTokenOut>::parse(outer.value())?;
    if card_tag.value().len() != AUTH_TOKEN_LEN {
        return Err(PaceError::UnexpectedResponse("card token wrong length"));
    }

    let token_for_us =
        encode_auth_token(suite, &state.u_pcd_public).ok_or(PaceError::InvalidPoint)?;
    let expected = aes256_cmac_truncated(k_mac.as_bytes(), &token_for_us);
    let tokens_match = expected.as_bytes().ct_eq(card_tag.value()).unwrap_u8() == 1;
    if !tokens_match {
        return Err(PaceError::AuthMismatch);
    }

    Ok(PaceSession {
        k_enc,
        k_mac,
        ssc: Ssc::INITIAL,
    })
}

/// Build the authentication-token message-authentication input over a
/// public point with the suite's protocol identifier (BSI TR-03110-3
/// section A.2.4). `None` for the point at infinity, a degenerate input.
fn encode_auth_token<C: PaceCurve>(suite: PaceInfo, point: &Point<C>) -> Option<Vec<u8>> {
    let mechanism = suite.protocol_oid();
    let point_bytes = point.encode_uncompressed()?;
    let mut inner = refineid_ber::BerEncoder::with_capacity(mechanism.len());
    inner.push_tlv(TAG_ASN1_OID, mechanism).ok()?;
    inner
        .push_tlv(TAG_PUBLIC_KEY_POINT, point_bytes.as_bytes())
        .ok()?;
    refineid_ber::tlv2(TAG_PUBLIC_KEY_TEMPLATE, inner.finish()).ok()
}

/// Refuse a card point equal to the terminal's own point for the same
/// step. ICAO Doc 9303 Part 11 section 4.4.1, step 4 d, has both parties
/// check that the two key-agreement public keys differ; the mapping
/// exchange gets the same check. Both run before anything derived from
/// the card's point is computed or sent.
fn reject_reflection<C: PaceCurve, E>(
    ours: &Point<C>,
    theirs: &Point<C>,
) -> Result<(), PaceError<E>> {
    if bool::from(ours.ct_eq(theirs)) {
        return Err(PaceError::ReflectedKey);
    }
    Ok(())
}

/// Draw a random scalar in the range one up to the subgroup order minus
/// one, by rejection sampling: a draw is kept only when its big-endian
/// value is a canonical, nonzero scalar. The draw buffer and the scalar
/// are both scrubbed owners: the scalar is a private key for the rest of
/// the handshake.
fn random_scalar_mod_n<C: PaceCurve, E>(
    draw: ScalarSource<'_>,
) -> Result<Zeroizing<NonZeroScalar<C>>, PaceError<E>> {
    loop {
        let mut buffer = Zeroizing::new(FieldBytes::<C>::default());
        draw(buffer.as_mut_slice()).map_err(PaceError::Random)?;
        if let Some(scalar) = NonZeroScalar::<C>::from_repr(*buffer).into_option() {
            return Ok(Zeroizing::new(scalar));
        }
    }
}

/// Lift a nonce to the mapping scalar: the nonce read as a big-endian
/// integer, reduced modulo the subgroup order. The generic mapping
/// multiplies the generator by `s` (ICAO Doc 9303 Part 11 section
/// 4.4.3.3.1), and `s * G` equals `(s mod n) * G`, so a nonce wider than
/// the order maps the same as its reduction. The reduction is Horner's
/// rule in the library's scalar field, one octet at a time. The scalar
/// is the password-protected mapping secret, so it is a scrubbed owner.
fn scalar_from_nonce<C: PaceCurve>(nonce: &[u8]) -> Zeroizing<Scalar<C>> {
    let radix = Scalar::<C>::from(OCTET_RADIX);
    let mut scalar = Zeroizing::new(Scalar::<C>::ZERO);
    for &octet in nonce {
        let shifted: Scalar<C> = *scalar * radix;
        let digit = Scalar::<C>::from(u64::from(octet));
        *scalar = shifted + digit;
    }
    scalar
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_TOKEN_LEN, BSI_TR03110_ZERO_IV, DynamicAuthData, KdfParam, NonZeroScalar,
        PASSWORD_REF_CAN, PaceError, PaceMidwayState, PacePassword, Point, SW_PASSWORD_DEACTIVATED,
        Scalar, Ssc, TAG_AUTH_TOKEN_PCD, TAG_DYNAMIC_AUTH, TAG_MSE_DOMAIN, TAG_MSE_MECHANISM,
        TAG_MSE_PASSWORD, aes256_cmac_truncated, encode_auth_token, kdf_aes256,
        random_scalar_mod_n, reject_reflection, run_pace_drawing, scalar_from_nonce,
    };
    use crate::can::{Can, UnvalidatedCan};
    use crate::card_access::tests::{
        card_access_file, citizen_card_access, organizational_card_access, pace_info,
    };
    use crate::card_access::{
        CardAccess, PACE_ECDH_GM_AES_256_OID, PACE_INFO_VERSION, PaceDomain, PaceInfo,
        UnvalidatedCardAccess,
    };
    use crate::commands::{GeneralAuthenticate, MSE_INS, MSE_P1_SET_AT, MSE_P2_AUTH_TEMPLATE};
    use crate::crypto::curve::PaceCurve;
    use crate::crypto::symmetric::{Aes256Key, aes256_cbc_encrypt_no_padding};
    use elliptic_curve::Curve as _;
    use elliptic_curve::bigint::{ArrayEncoding as _, U384};
    use elliptic_curve::ff::PrimeField as _;
    use refineid_apdu::{
        APDU_HEADER_LEN, ApduClass, CardTransport, CommandApdu, CredentialCommand, PinRetries,
        ResponseApdu, StatusWord, TransportOutcome,
    };
    use refineid_auth::{
        FlooredCredential, Pin1, Pin2, PinReferenceScheme, PinSlot, RetryFloorRefusal,
        UnvalidatedSecret,
    };
    use refineid_ber::{BerTag, BerTlv};

    /// The card-response authentication-token tag as a one-byte value.
    const TAG_AUTH_TOKEN_PICC: u8 = 0x86;
    /// The card-response encrypted-nonce tag as a one-byte value.
    const TAG_ENCRYPTED_NONCE: u8 = 0x80;
    /// The card-response mapping-data tag as a one-byte value.
    const TAG_MAPPING_PICC: u8 = 0x82;
    /// The card-response key-agreement tag as a one-byte value.
    const TAG_KEY_AGREE_PICC: u8 = 0x84;
    /// Nonce byte count for the lift test.
    const NONCE_LEN: usize = 16;
    /// High-half byte count of the lifted P-384 scalar.
    const SCALAR_HIGH_ZEROS: usize = 32;
    /// Rounds of the random-scalar range check.
    const SCALAR_ROUNDS: u8 = 8;
    /// Length of the two-byte public-key template tag.
    const TEMPLATE_TAG_LEN: usize = 2;
    /// High byte of the public-key template tag.
    const TEMPLATE_TAG_HIGH: u8 = 0x7F;
    /// Low byte of the public-key template tag.
    const TEMPLATE_TAG_LOW: u8 = 0x49;
    /// Start of the object-identifier body inside the encoded token.
    const OID_BODY_START: usize = 5;
    /// End of the object-identifier body inside the encoded token.
    const OID_BODY_END: usize = 15;
    /// A synthetic card-side mapping private scalar.
    const CARD_SCALAR: u64 = 0x0123_4567;
    /// A synthetic terminal-side private scalar.
    const TERMINAL_SCALAR: u64 = 0x0FED_CBA9;
    /// A synthetic card-side key-agreement private scalar.
    const CARD_KEY_AGREEMENT_SCALAR: u64 = 7_654_321;
    /// Width of the short-form Lc field (ISO/IEC 7816-4 section 5.1).
    const LC_LEN: usize = 1;
    /// Width of the short-form Le field (ISO/IEC 7816-4 section 5.1).
    const LE_LEN: usize = 1;
    /// Offset of the data field in a short command (ISO/IEC 7816-4
    /// section 5.1): the header, then Lc.
    const DATA_OFFSET: usize = APDU_HEADER_LEN + LC_LEN;
    /// A synthetic password: six ASCII digits, valid as a CAN and as a
    /// PIN.
    const PASSWORD_TEXT: &str = "123456";
    /// A synthetic nonce, one AES block of ASCII.
    const SYNTHETIC_NONCE: &[u8; NONCE_LEN] = b"synthetic nonce.";
    /// A synthetic nonce, two AES blocks of ASCII, as the organizational
    /// card sends.
    const TWO_BLOCK_NONCE: &[u8; NONCE_LEN + NONCE_LEN] = b"a two-block synthetic nonce here";
    /// A nonce length that is not a whole number of AES blocks.
    const PART_BLOCK_NONCE_LEN: usize = 24;
    /// Exchanges up to and including GA-1: MSE:Set AT and GA-1.
    const EXCHANGES_THROUGH_NONCE: usize = 2;
    /// Exchanges up to and including the mapping round: MSE:Set AT,
    /// GA-1 and GA-2.
    const EXCHANGES_THROUGH_MAPPING: usize = 3;
    /// Exchanges up to and including the key-agreement round.
    const EXCHANGES_THROUGH_KEY_AGREEMENT: usize = 4;
    /// Exchanges of a complete handshake, the token round included.
    const EXCHANGES_THROUGH_TOKENS: usize = 5;
    /// Exchanges when the handshake stops at MSE:Set AT.
    const EXCHANGES_THROUGH_MSE: usize = 1;
    /// Tries left the floor serves at its lowest.
    const TRIES_AT_FLOOR: u8 = 3;
    /// Tries left just below the floor.
    const TRIES_BELOW_FLOOR: u8 = 2;
    /// Tries left when the PIN is suspended (BSI TR-03110-3 section
    /// B.14.1).
    const TRIES_SUSPENDED: u8 = 1;
    /// Tries left after one wrong attempt.
    const TRIES_AFTER_ONE_WRONG: u8 = 4;
    /// The first byte the deterministic scalar source writes, for the
    /// first draw; each later draw starts one higher.
    const DETERMINISTIC_SEED: u8 = 0x21;

    /// The length octet of a one-octet BER-TLV value.
    const ONE_OCTET_VALUE: u8 = 1;

    /// Exchange index of the opening MSE:Set AT.
    const EXCHANGE_MSE: usize = 0;
    /// Exchange index of GA-1.
    const EXCHANGE_NONCE: usize = 1;
    /// Exchange index of GA-2.
    const EXCHANGE_MAPPING: usize = 2;
    /// Exchange index of GA-3.
    const EXCHANGE_KEY_AGREEMENT: usize = 3;
    /// Exchange index of GA-4.
    const EXCHANGE_TOKENS: usize = 4;

    /// The terminal's mapping-data object inside a GA-2 command.
    struct MapPcdPublic;
    impl BerTag for MapPcdPublic {
        const TAG: u16 = 0x81;
    }

    /// The terminal's key-agreement object inside a GA-3 command.
    struct KeyAgreePcdPublic;
    impl BerTag for KeyAgreePcdPublic {
        const TAG: u16 = 0x83;
    }

    /// The terminal's authentication token inside a GA-4 command.
    struct AuthTokenPcd;
    impl BerTag for AuthTokenPcd {
        const TAG: u16 = TAG_AUTH_TOKEN_PCD as u16;
    }

    fn can() -> Can {
        Can::reconstruct(UnvalidatedCan::from_owned_text(PASSWORD_TEXT.to_owned()))
            .expect("fixture is a valid CAN")
    }

    fn pin1() -> Pin1 {
        Pin1::reconstruct(UnvalidatedSecret::from_owned_bytes(
            PASSWORD_TEXT.as_bytes().to_vec(),
        ))
        .expect("fixture is a valid PIN 1")
    }

    fn pin2() -> Pin2 {
        Pin2::reconstruct(UnvalidatedSecret::from_owned_bytes(
            PASSWORD_TEXT.as_bytes().to_vec(),
        ))
        .expect("fixture is a valid PIN 2")
    }

    fn access(bytes: Vec<u8>) -> CardAccess {
        CardAccess::parse(UnvalidatedCardAccess::from_card_bytes(bytes)).expect("parses")
    }

    /// EF.CardAccess listing generic mapping over NIST P-256 only.
    fn p256_only_access() -> CardAccess {
        access(card_access_file(&[pace_info(
            &PACE_ECDH_GM_AES_256_OID,
            PACE_INFO_VERSION,
            Some(PaceDomain::NistP256.parameter_id()),
        )]))
    }

    fn generic(domain: PaceDomain, card_access: &CardAccess) -> PaceInfo {
        let suite = card_access
            .generic_mapping_suite()
            .expect("a generic suite");
        assert_eq!(suite.domain(), domain);
        suite
    }

    fn response(body: Vec<u8>, status: StatusWord) -> ResponseApdu {
        let [sw1, sw2] = status.as_u16().to_be_bytes();
        ResponseApdu { body, sw1, sw2 }
    }

    fn success_response(body: Vec<u8>) -> ResponseApdu {
        response(body, StatusWord::Success)
    }

    fn counter(tries: u8) -> StatusWord {
        StatusWord::PinIncorrect {
            retries: PinRetries::from_nibble(tries).expect("a nibble"),
        }
    }

    /// The expected MSE:Set AT wire for a suite and password reference,
    /// assembled from the named header, tag and value constants: header,
    /// Lc, then the mechanism, password and domain objects.
    fn expected_mse_wire(suite: PaceInfo, password_ref: u8) -> Vec<u8> {
        let mechanism = suite.protocol_oid();
        let mut data = vec![
            TAG_MSE_MECHANISM,
            u8::try_from(mechanism.len()).expect("short"),
        ];
        data.extend_from_slice(mechanism);
        data.extend_from_slice(&[TAG_MSE_PASSWORD, ONE_OCTET_VALUE, password_ref]);
        data.extend_from_slice(&[
            TAG_MSE_DOMAIN,
            ONE_OCTET_VALUE,
            suite.domain().parameter_id(),
        ]);
        let mut wire = vec![
            ApduClass::Plain.as_byte(),
            MSE_INS,
            MSE_P1_SET_AT,
            MSE_P2_AUTH_TEMPLATE,
            u8::try_from(data.len()).expect("short"),
        ];
        wire.extend_from_slice(&data);
        wire
    }

    /// The value of the `T` object inside a General Authenticate
    /// command's dynamic-authentication-data template.
    fn terminal_object<T: BerTag>(command: &CommandApdu) -> Vec<u8> {
        let bytes = command.as_bytes();
        let data = &bytes[DATA_OFFSET..bytes.len() - LE_LEN];
        let outer = BerTlv::<DynamicAuthData>::parse(data).expect("dynamic auth data");
        BerTlv::<T>::parse(outer.value())
            .expect("terminal object")
            .value()
            .to_vec()
    }

    /// A General Authenticate answer carrying one `tag` object.
    fn card_answer(tag: u8, value: &[u8]) -> TransportOutcome {
        let body = refineid_ber::tlv(
            TAG_DYNAMIC_AUTH,
            refineid_ber::tlv(tag, value).expect("encodes"),
        )
        .expect("encodes");
        TransportOutcome::Response(success_response(body))
    }

    /// A deterministic scalar source: each draw fills the buffer with an
    /// ascending byte run starting one above the previous draw's start.
    /// Every byte stays below the leading byte of each curve order, so
    /// every draw is a canonical nonzero scalar.
    struct Deterministic {
        draws: u8,
    }

    impl Deterministic {
        fn fill(&mut self, buffer: &mut [u8]) {
            let start = DETERMINISTIC_SEED.wrapping_add(self.draws);
            for (offset, byte) in buffer.iter_mut().enumerate() {
                *byte = start.wrapping_add(u8::try_from(offset).unwrap_or(0));
            }
            self.draws += 1;
        }

        /// The scalar the `index`-th draw yields on `C`.
        fn scalar<C: PaceCurve>(index: u8) -> Scalar<C> {
            let mut source = Self { draws: index };
            let mut repr = elliptic_curve::FieldBytes::<C>::default();
            source.fill(repr.as_mut_slice());
            Option::from(Scalar::<C>::from_repr(repr)).expect("canonical")
        }
    }

    /// A card emulator that knows the password and runs every round
    /// honestly over `C`: it checks the opening command, answers it with
    /// `mse_status`, encrypts [`SYNTHETIC_NONCE`] under the password key,
    /// maps the nonce with its own scalars, checks the terminal's token
    /// and answers with its own (ICAO Doc 9303 Part 11 section 4.4) --
    /// or with `token_status` in place of its token.
    struct HonestCard<C: PaceCurve> {
        expected_mse: Vec<u8>,
        mse_status: StatusWord,
        token_status: StatusWord,
        suite: PaceInfo,
        exchanges: usize,
        commands: Vec<Vec<u8>>,
        mapped_generator: Option<Point<C>>,
        terminal_key_agreement: Option<Point<C>>,
        card_key_agreement: Option<Point<C>>,
        k_mac: Option<Aes256Key>,
        nonce: Vec<u8>,
        nonce_reply: Option<Vec<u8>>,
    }

    impl<C: PaceCurve> HonestCard<C> {
        fn new(suite: PaceInfo, password_ref: u8) -> Self {
            Self {
                expected_mse: expected_mse_wire(suite, password_ref),
                mse_status: StatusWord::Success,
                token_status: StatusWord::Success,
                suite,
                exchanges: 0,
                commands: Vec::new(),
                mapped_generator: None,
                terminal_key_agreement: None,
                card_key_agreement: None,
                k_mac: None,
                nonce: SYNTHETIC_NONCE.to_vec(),
                nonce_reply: None,
            }
        }

        fn decode(bytes: &[u8]) -> Point<C> {
            Point::decode_uncompressed(bytes).expect("terminal point decodes")
        }

        fn encode(point: &Point<C>) -> Vec<u8> {
            point
                .encode_uncompressed()
                .expect("finite point")
                .as_bytes()
                .to_vec()
        }

        /// The nonce encrypted under `K_pi`, derived here from the
        /// password's ASCII digits with this crate's own KDF, so a PIN
        /// password is checked against the CAN encoding.
        fn encrypted_nonce(&self) -> Vec<u8> {
            let k_pi = kdf_aes256(PASSWORD_TEXT.as_bytes(), KdfParam::Password);
            aes256_cbc_encrypt_no_padding(k_pi.as_bytes(), &BSI_TR03110_ZERO_IV, &self.nonce)
                .expect("one block")
                .as_bytes()
                .to_vec()
        }

        fn mse(&self, command: &CommandApdu) -> Result<TransportOutcome, String> {
            if command.as_bytes() != self.expected_mse.as_slice() {
                return Err("unexpected MSE:Set AT".to_owned());
            }
            Ok(TransportOutcome::Response(response(
                Vec::new(),
                self.mse_status,
            )))
        }

        fn map(&mut self, command: &CommandApdu) -> TransportOutcome {
            let terminal = Self::decode(&terminal_object::<MapPcdPublic>(command));
            let card_scalar = Scalar::<C>::from(CARD_SCALAR);
            let card_public = Point::<C>::generator().scalar_mul(&card_scalar);
            let shared = terminal.scalar_mul(&card_scalar);
            let nonce_point =
                Point::<C>::generator().scalar_mul(&scalar_from_nonce::<C>(&self.nonce));
            self.mapped_generator = Some(nonce_point.add(&shared));
            card_answer(TAG_MAPPING_PICC, &Self::encode(&card_public))
        }

        fn agree(&mut self, command: &CommandApdu) -> TransportOutcome {
            let terminal = Self::decode(&terminal_object::<KeyAgreePcdPublic>(command));
            let card_scalar = Scalar::<C>::from(CARD_KEY_AGREEMENT_SCALAR);
            let card_public = self
                .mapped_generator
                .as_ref()
                .expect("mapping ran")
                .scalar_mul(&card_scalar);
            let shared_x = terminal
                .scalar_mul(&card_scalar)
                .x_coordinate()
                .expect("shared point is finite");
            self.k_mac = Some(kdf_aes256(shared_x.as_slice(), KdfParam::Mac));
            self.terminal_key_agreement = Some(terminal);
            let answer = card_answer(TAG_KEY_AGREE_PICC, &Self::encode(&card_public));
            self.card_key_agreement = Some(card_public);
            answer
        }

        fn authenticate(&self, command: &CommandApdu) -> Result<TransportOutcome, String> {
            if self.token_status != StatusWord::Success {
                return Ok(TransportOutcome::Response(response(
                    Vec::new(),
                    self.token_status,
                )));
            }
            let k_mac = self.k_mac.as_ref().expect("key agreement ran");
            let card_public = self.card_key_agreement.as_ref().expect("key agreement ran");
            let terminal = self
                .terminal_key_agreement
                .as_ref()
                .expect("key agreement ran");
            let expected = aes256_cmac_truncated(
                k_mac.as_bytes(),
                &encode_auth_token(self.suite, card_public).expect("card point encodes"),
            );
            if terminal_object::<AuthTokenPcd>(command) != expected.as_bytes() {
                return Err("the terminal token does not verify".to_owned());
            }
            let t_picc = aes256_cmac_truncated(
                k_mac.as_bytes(),
                &encode_auth_token(self.suite, terminal).expect("terminal point encodes"),
            );
            Ok(card_answer(TAG_AUTH_TOKEN_PICC, t_picc.as_bytes()))
        }
    }

    impl<C: PaceCurve> CardTransport for HonestCard<C> {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let index = self.exchanges;
            self.exchanges += 1;
            self.commands.push(command.as_bytes().to_vec());
            match index {
                EXCHANGE_MSE => self.mse(command),
                EXCHANGE_NONCE => {
                    let reply = self
                        .nonce_reply
                        .clone()
                        .unwrap_or_else(|| self.encrypted_nonce());
                    Ok(card_answer(TAG_ENCRYPTED_NONCE, &reply))
                }
                EXCHANGE_MAPPING => Ok(self.map(command)),
                EXCHANGE_KEY_AGREEMENT => Ok(self.agree(command)),
                EXCHANGE_TOKENS => self.authenticate(command),
                _ => Err("the handshake is over".to_owned()),
            }
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("the handshake issues no credential command".to_owned())
        }
    }

    fn run<C: PaceCurve>(
        card: &mut HonestCard<C>,
        card_access: &CardAccess,
        password: &PacePassword<'_>,
    ) -> Result<super::PaceSession, PaceError<String>> {
        run_pace_drawing(card, card_access, password, &mut super::rng::fill)
    }

    fn pin1_ref() -> u8 {
        PinReferenceScheme::Organizational.reference(PinSlot::Pin1)
    }

    fn pin2_ref() -> u8 {
        PinReferenceScheme::Organizational.reference(PinSlot::Pin2)
    }

    #[test]
    fn can_on_the_citizen_card_access_runs_over_brainpool_p384() {
        let card_access = access(citizen_card_access());
        let suite = generic(PaceDomain::BrainpoolP384r1, &card_access);
        let mut card = HonestCard::<bp384::BrainpoolP384r1>::new(suite, PASSWORD_REF_CAN);
        let can = can();
        let session = run(&mut card, &card_access, &PacePassword::Can(&can)).expect("succeeds");
        assert_eq!(card.exchanges, EXCHANGES_THROUGH_TOKENS);
        assert_eq!(session.ssc, Ssc::INITIAL);
        assert_eq!(
            session.k_mac.as_bytes(),
            card.k_mac.expect("key agreement ran").as_bytes()
        );
    }

    #[test]
    fn pin2_on_a_p256_card_access_runs_over_p256() {
        let card_access = p256_only_access();
        let suite = generic(PaceDomain::NistP256, &card_access);
        let mut card = HonestCard::<p256::NistP256>::new(suite, pin2_ref());
        let pin = pin2();
        let session = run(&mut card, &card_access, &PacePassword::Pin2(&pin)).expect("succeeds");
        assert_eq!(card.exchanges, EXCHANGES_THROUGH_TOKENS);
        assert_eq!(
            session.k_mac.as_bytes(),
            card.k_mac.expect("key agreement ran").as_bytes()
        );
    }

    /// The full generic-mapping run on the organizational card's suite,
    /// NIST P-384 with PIN 1, with the terminal's scalars from a
    /// deterministic source: every terminal point on the wire is
    /// recomputed from the known scalars and the card's answers.
    fn pin1_over_p384_deterministically(nonce: &[u8]) {
        type C = p384::NistP384;
        let card_access = access(organizational_card_access());
        let suite = generic(PaceDomain::NistP384, &card_access);
        let mut card = HonestCard::<C>::new(suite, pin1_ref());
        card.nonce = nonce.to_vec();
        let pin = pin1();
        let mut source = Deterministic { draws: 0 };
        let session = run_pace_drawing(
            &mut card,
            &card_access,
            &PacePassword::Pin1(&pin),
            &mut |buffer| {
                source.fill(buffer);
                Ok(())
            },
        )
        .expect("succeeds");
        assert_eq!(card.exchanges, EXCHANGES_THROUGH_TOKENS);

        let x_pcd = Deterministic::scalar::<C>(0);
        let u_pcd = Deterministic::scalar::<C>(1);
        let g = Point::<C>::generator();

        // GA-2 carries x * G.
        let expected_map = g.scalar_mul(&x_pcd);
        let map_command = &card.commands[EXCHANGE_MAPPING];
        let map_data = &map_command[DATA_OFFSET..map_command.len() - LE_LEN];
        let map_object = BerTlv::<MapPcdPublic>::parse(
            BerTlv::<DynamicAuthData>::parse(map_data)
                .expect("template")
                .value(),
        )
        .expect("object")
        .value()
        .to_vec();
        assert_eq!(
            map_object,
            expected_map
                .encode_uncompressed()
                .expect("finite")
                .as_bytes()
        );

        // GA-3 carries u * (s * G + x * Y_card).
        let card_mapping_public = g.scalar_mul(&Scalar::<C>::from(CARD_SCALAR));
        let mapped = g
            .scalar_mul(&scalar_from_nonce::<C>(nonce))
            .add(&card_mapping_public.scalar_mul(&x_pcd));
        let expected_agree = mapped.scalar_mul(&u_pcd);
        let agree_command = &card.commands[EXCHANGE_KEY_AGREEMENT];
        let agree_data = &agree_command[DATA_OFFSET..agree_command.len() - LE_LEN];
        let agree_object = BerTlv::<KeyAgreePcdPublic>::parse(
            BerTlv::<DynamicAuthData>::parse(agree_data)
                .expect("template")
                .value(),
        )
        .expect("object")
        .value()
        .to_vec();
        assert_eq!(
            agree_object,
            expected_agree
                .encode_uncompressed()
                .expect("finite")
                .as_bytes()
        );

        // Both sides hold the same session keys.
        let card_agreement_public =
            mapped.scalar_mul(&Scalar::<C>::from(CARD_KEY_AGREEMENT_SCALAR));
        let shared_x = card_agreement_public
            .scalar_mul(&u_pcd)
            .x_coordinate()
            .expect("finite");
        assert_eq!(
            session.k_enc.as_bytes(),
            kdf_aes256(shared_x.as_slice(), KdfParam::Encryption).as_bytes()
        );
        assert_eq!(
            session.k_mac.as_bytes(),
            card.k_mac.expect("key agreement ran").as_bytes()
        );
    }

    #[test]
    fn pin1_on_the_organizational_card_access_runs_over_p384_deterministically() {
        pin1_over_p384_deterministically(SYNTHETIC_NONCE);
    }

    /// The organizational card sends a two-block nonce.
    #[test]
    fn a_two_block_nonce_runs_over_p384_deterministically() {
        pin1_over_p384_deterministically(TWO_BLOCK_NONCE);
    }

    /// A card answering GA-1 with an encrypted nonce of `length` bytes.
    fn nonce_length_run(length: usize) -> (usize, Result<(), PaceError<String>>) {
        let card_access = access(organizational_card_access());
        let suite = generic(PaceDomain::NistP384, &card_access);
        let mut card = HonestCard::<p384::NistP384>::new(suite, pin1_ref());
        card.nonce_reply = Some(vec![u8::MAX; length]);
        let pin = pin1();
        let result = run(&mut card, &card_access, &PacePassword::Pin1(&pin)).map(|_session| ());
        (card.exchanges, result)
    }

    #[test]
    fn a_nonce_that_is_not_whole_blocks_is_refused_before_any_further_command() {
        for length in [0, PART_BLOCK_NONCE_LEN, super::NONCE_MAX_LEN + NONCE_LEN] {
            let (exchanges, result) = nonce_length_run(length);
            assert_eq!(exchanges, EXCHANGES_THROUGH_NONCE);
            assert!(matches!(
                result,
                Err(PaceError::UnexpectedResponse(
                    "encrypted nonce wrong length"
                ))
            ));
        }
    }

    #[test]
    fn the_longest_nonce_is_accepted() {
        let (exchanges, result) = nonce_length_run(super::NONCE_MAX_LEN);
        // A nonce not encrypted under the password maps to a generator the
        // card does not share; the terminal still reaches the token round.
        assert_eq!(exchanges, EXCHANGES_THROUGH_TOKENS);
        assert!(result.is_err());
    }

    #[test]
    fn a_two_block_nonce_lifts_as_the_library_reduces_it() {
        type C = p384::NistP384;
        let mut padded = elliptic_curve::FieldBytes::<C>::default();
        let start = padded.len() - TWO_BLOCK_NONCE.len();
        padded[start..].copy_from_slice(TWO_BLOCK_NONCE);
        let expected = <Scalar<C> as elliptic_curve::bigint::Reduce<
            elliptic_curve::FieldBytes<C>,
        >>::reduce(&padded);
        assert_eq!(*scalar_from_nonce::<C>(TWO_BLOCK_NONCE), expected);
    }

    #[test]
    fn a_long_nonce_lifts_to_its_integer_modulo_the_order() {
        type C = p256::NistP256;
        // The full-width nonce exceeds the P-256 order; split it as
        // high || low and recombine in the scalar field.
        let nonce = [u8::MAX; super::NONCE_MAX_LEN];
        let (high, low) = nonce.split_at(NONCE_LEN);
        let mut shift = Scalar::<C>::ONE;
        for _octet in low {
            shift *= Scalar::<C>::from(super::OCTET_RADIX);
        }
        let expected = *scalar_from_nonce::<C>(high) * shift + *scalar_from_nonce::<C>(low);
        assert_eq!(*scalar_from_nonce::<C>(&nonce), expected);
    }

    #[test]
    fn the_mse_wire_names_mechanism_password_and_domain() {
        // Asserted inside the honest card for every run; here for each
        // password reference against one suite.
        let card_access = access(organizational_card_access());
        let suite = generic(PaceDomain::NistP384, &card_access);
        for (password_ref, credential) in [
            (pin1_ref(), PasswordKind::Pin1),
            (pin2_ref(), PasswordKind::Pin2),
            (PASSWORD_REF_CAN, PasswordKind::Can),
        ] {
            let mut card = HonestCard::<p384::NistP384>::new(suite, password_ref);
            let (can, pin1, pin2) = (can(), pin1(), pin2());
            let password = match credential {
                PasswordKind::Can => PacePassword::Can(&can),
                PasswordKind::Pin1 => PacePassword::Pin1(&pin1),
                PasswordKind::Pin2 => PacePassword::Pin2(&pin2),
            };
            run(&mut card, &card_access, &password).expect("succeeds");
            assert_eq!(
                card.commands[EXCHANGE_MSE],
                expected_mse_wire(suite, password_ref)
            );
        }
    }

    #[derive(Clone, Copy)]
    enum PasswordKind {
        Can,
        Pin1,
        Pin2,
    }

    #[test]
    fn the_organizational_pin_references_are_the_tr03110_pin_and_puk_references() {
        /// BSI TR-03110-3 section B.14.1 password reference "PIN".
        const TR03110_PASSWORD_REF_PIN: u8 = 3;
        /// BSI TR-03110-3 section B.14.1 password reference "PUK".
        const TR03110_PASSWORD_REF_PUK: u8 = 4;
        assert_eq!(pin1_ref(), TR03110_PASSWORD_REF_PIN);
        assert_eq!(pin2_ref(), TR03110_PASSWORD_REF_PUK);
    }

    fn pin1_run_with_mse_status(status: StatusWord) -> (usize, Result<(), PaceError<String>>) {
        let card_access = access(organizational_card_access());
        let suite = generic(PaceDomain::NistP384, &card_access);
        let mut card = HonestCard::<p384::NistP384>::new(suite, pin1_ref());
        card.mse_status = status;
        let pin = pin1();
        let result = run(&mut card, &card_access, &PacePassword::Pin1(&pin)).map(|_session| ());
        (card.exchanges, result)
    }

    #[test]
    fn the_floor_serves_a_pin_at_three_tries_left() {
        let (exchanges, result) = pin1_run_with_mse_status(counter(TRIES_AT_FLOOR));
        assert!(result.is_ok());
        assert_eq!(exchanges, EXCHANGES_THROUGH_TOKENS);
    }

    #[test]
    fn the_floor_refuses_two_tries_left_and_sends_nothing_further() {
        let (exchanges, result) = pin1_run_with_mse_status(counter(TRIES_BELOW_FLOOR));
        assert_eq!(exchanges, EXCHANGES_THROUGH_MSE);
        assert!(matches!(
            result,
            Err(PaceError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
                credential: FlooredCredential::Pin1,
                remaining,
            })) if remaining.get() == TRIES_BELOW_FLOOR
        ));
    }

    #[test]
    fn the_floor_refuses_a_suspended_pin_and_sends_nothing_further() {
        let (exchanges, result) = pin1_run_with_mse_status(counter(TRIES_SUSPENDED));
        assert_eq!(exchanges, EXCHANGES_THROUGH_MSE);
        assert!(matches!(
            result,
            Err(PaceError::RetryFloor(RetryFloorRefusal::TriesBelowFloor {
                credential: FlooredCredential::Pin1,
                remaining,
            })) if remaining.get() == TRIES_SUSPENDED
        ));
    }

    #[test]
    fn the_floor_refuses_a_blocked_pin_and_sends_nothing_further() {
        let (exchanges, result) = pin1_run_with_mse_status(counter(0));
        assert_eq!(exchanges, EXCHANGES_THROUGH_MSE);
        assert!(matches!(
            result,
            Err(PaceError::RetryFloor(RetryFloorRefusal::Blocked {
                credential: FlooredCredential::Pin1,
            }))
        ));
    }

    #[test]
    fn a_deactivated_pin_is_refused_and_nothing_further_is_sent() {
        let (exchanges, result) =
            pin1_run_with_mse_status(StatusWord::from_u16(SW_PASSWORD_DEACTIVATED));
        assert_eq!(exchanges, EXCHANGES_THROUGH_MSE);
        assert!(matches!(result, Err(PaceError::PasswordDeactivated)));
    }

    #[test]
    fn another_mse_refusal_names_the_stage() {
        let (exchanges, result) = pin1_run_with_mse_status(StatusWord::ReferenceDataNotFound);
        assert_eq!(exchanges, EXCHANGES_THROUGH_MSE);
        assert!(matches!(
            result,
            Err(PaceError::Status(
                "MSE:Set AT",
                StatusWord::ReferenceDataNotFound
            ))
        ));
    }

    #[test]
    fn a_counter_answer_to_a_can_is_a_status_failure() {
        let card_access = access(citizen_card_access());
        let suite = generic(PaceDomain::BrainpoolP384r1, &card_access);
        let mut card = HonestCard::<bp384::BrainpoolP384r1>::new(suite, PASSWORD_REF_CAN);
        card.mse_status = counter(TRIES_BELOW_FLOOR);
        let can = can();
        let result = run(&mut card, &card_access, &PacePassword::Can(&can));
        assert_eq!(card.exchanges, EXCHANGES_THROUGH_MSE);
        assert!(matches!(result, Err(PaceError::Status("MSE:Set AT", _))));
    }

    #[test]
    fn a_counter_answer_to_the_token_round_is_a_wrong_pin() {
        let card_access = access(organizational_card_access());
        let suite = generic(PaceDomain::NistP384, &card_access);
        let mut card = HonestCard::<p384::NistP384>::new(suite, pin2_ref());
        card.token_status = counter(TRIES_AFTER_ONE_WRONG);
        let pin = pin2();
        let result = run(&mut card, &card_access, &PacePassword::Pin2(&pin));
        assert_eq!(card.exchanges, EXCHANGES_THROUGH_TOKENS);
        assert!(matches!(
            result,
            Err(PaceError::WrongPin { retries_left }) if retries_left.get() == TRIES_AFTER_ONE_WRONG
        ));
    }

    #[test]
    fn a_card_access_without_a_generic_suite_sends_nothing() {
        let card_access = access(card_access_file(&[]));
        let suite = generic(PaceDomain::NistP384, &access(organizational_card_access()));
        let mut card = HonestCard::<p384::NistP384>::new(suite, pin1_ref());
        let pin = pin1();
        let result = run(&mut card, &card_access, &PacePassword::Pin1(&pin));
        assert_eq!(card.exchanges, 0);
        assert!(matches!(result, Err(PaceError::NoSupportedSuite)));
    }

    #[test]
    fn a_pin_and_a_can_with_the_same_digits_derive_the_same_nonce_key() {
        let can = can();
        let pin = pin1();
        assert_eq!(
            PacePassword::Can(&can).key().as_bytes(),
            PacePassword::Pin1(&pin).key().as_bytes()
        );
    }

    #[test]
    fn reject_reflection_refuses_an_equal_point() {
        let g = Point::<p384::NistP384>::generator();
        assert!(matches!(
            reject_reflection::<_, core::convert::Infallible>(&g, &g),
            Err(PaceError::ReflectedKey)
        ));
        assert!(reject_reflection::<_, core::convert::Infallible>(&g, &g.add(&g)).is_ok());
    }

    /// Which round the reflecting peer echoes back.
    #[derive(Clone, Copy)]
    enum Reflect {
        Mapping,
        KeyAgreement,
    }

    /// A card emulator that does not know the password: it answers GA-1
    /// with a fixed block, GA-2 with the generator or the terminal's own
    /// point, and GA-3 with the terminal's own point.
    struct ReflectingPeer {
        reflect: Reflect,
        exchanges: usize,
    }

    impl CardTransport for ReflectingPeer {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let index = self.exchanges;
            self.exchanges += 1;
            match index {
                EXCHANGE_MSE => Ok(TransportOutcome::Response(success_response(Vec::new()))),
                EXCHANGE_NONCE => Ok(card_answer(TAG_ENCRYPTED_NONCE, SYNTHETIC_NONCE)),
                EXCHANGE_MAPPING => Ok(match self.reflect {
                    Reflect::Mapping => {
                        card_answer(TAG_MAPPING_PICC, &terminal_object::<MapPcdPublic>(command))
                    }
                    Reflect::KeyAgreement => {
                        let generator = Point::<bp384::BrainpoolP384r1>::generator()
                            .encode_uncompressed()
                            .expect("generator encodes");
                        card_answer(TAG_MAPPING_PICC, generator.as_bytes())
                    }
                }),
                EXCHANGE_KEY_AGREEMENT => Ok(card_answer(
                    TAG_KEY_AGREE_PICC,
                    &terminal_object::<KeyAgreePcdPublic>(command),
                )),
                _ => Err("ReflectingPeer has no answer for the token round".to_owned()),
            }
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("the handshake issues no credential command".to_owned())
        }
    }

    fn run_reflecting(reflect: Reflect) -> (usize, Result<(), PaceError<String>>) {
        let mut peer = ReflectingPeer {
            reflect,
            exchanges: 0,
        };
        let can = can();
        let result = run_pace_drawing(
            &mut peer,
            &access(citizen_card_access()),
            &PacePassword::Can(&can),
            &mut super::rng::fill,
        )
        .map(|_session| ());
        (peer.exchanges, result)
    }

    #[test]
    fn reflected_key_agreement_point_aborts_before_the_token_round() {
        let (exchanges, result) = run_reflecting(Reflect::KeyAgreement);
        assert!(matches!(result, Err(PaceError::ReflectedKey)));
        assert_eq!(exchanges, EXCHANGES_THROUGH_KEY_AGREEMENT);
    }

    #[test]
    fn reflected_mapping_point_aborts() {
        let (exchanges, result) = run_reflecting(Reflect::Mapping);
        assert!(matches!(result, Err(PaceError::ReflectedKey)));
        assert_eq!(exchanges, EXCHANGES_THROUGH_MAPPING);
    }

    #[test]
    fn random_scalars_are_in_range() {
        let order = p384::NistP384::ORDER.get();
        for _round in 0..SCALAR_ROUNDS {
            let scalar = random_scalar_mod_n::<p384::NistP384, core::convert::Infallible>(
                &mut super::rng::fill,
            )
            .expect("scalar generation succeeds");
            let value = U384::from_be_byte_array(scalar.to_repr());
            let nonzero = value != U384::ZERO;
            let in_range = value < order;
            assert!(nonzero);
            assert!(in_range);
        }
    }

    #[test]
    fn nonce_lifts_to_a_zero_padded_scalar() {
        let nonce: [u8; NONCE_LEN] = core::array::from_fn(|i| u8::try_from(i + 1).unwrap_or(0));
        let scalar = scalar_from_nonce::<p384::NistP384>(&nonce);
        let padded = scalar_from_nonce::<p384::NistP384>(&[[0_u8; NONCE_LEN], nonce].concat());
        assert_eq!(*scalar, *padded);
        let bytes = scalar.to_repr();
        assert!(bytes[..SCALAR_HIGH_ZEROS].iter().all(|&b| b == 0));
        assert_eq!(&bytes[SCALAR_HIGH_ZEROS..], &nonce[..]);
    }

    #[test]
    fn midway_state_is_zeroize_on_drop() {
        fn require_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        require_zeroize_on_drop::<PaceMidwayState<p256::NistP256>>();
        require_zeroize_on_drop::<PaceMidwayState<p384::NistP384>>();
        require_zeroize_on_drop::<PaceMidwayState<bp384::BrainpoolP384r1>>();
    }

    #[test]
    fn auth_token_wraps_the_oid_and_point() {
        let suite = generic(PaceDomain::NistP384, &access(organizational_card_access()));
        let token = encode_auth_token(suite, &Point::<p384::NistP384>::generator())
            .expect("generator encodes");
        // The two-byte public-key template tag, then a short-form length.
        assert_eq!(
            &token[..TEMPLATE_TAG_LEN],
            &[TEMPLATE_TAG_HIGH, TEMPLATE_TAG_LOW]
        );
        assert_eq!(
            &token[OID_BODY_START..OID_BODY_END],
            &PACE_ECDH_GM_AES_256_OID
        );
    }

    /// A one-shot transport playing a card-side PACE peer for the
    /// mutual-authentication round.
    struct StepFiveMock {
        expected: Vec<u8>,
        response: ResponseApdu,
        called: bool,
    }

    impl CardTransport for StepFiveMock {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            if self.called {
                return Err("StepFiveMock called twice".to_owned());
            }
            if command.as_bytes() != self.expected.as_slice() {
                return Err("StepFiveMock unexpected command".to_owned());
            }
            self.called = true;
            Ok(TransportOutcome::Response(self.response.clone()))
        }

        fn transmit_credential(
            &mut self,
            _command: CredentialCommand,
        ) -> Result<TransportOutcome, Self::Error> {
            Err("StepFiveMock does not carry a credential command".to_owned())
        }
    }

    type MutualCurve = bp384::BrainpoolP384r1;

    fn mutual_auth_state() -> (PaceMidwayState<MutualCurve>, Vec<u8>) {
        // A card-side scalar and a terminal-side scalar; the resulting
        // shared point is the same from either side by ECDH, so the
        // derived keys and the exchanged tokens agree.
        let v_scalar = Scalar::<MutualCurve>::from(CARD_SCALAR);
        let u_scalar = Scalar::<MutualCurve>::from(TERMINAL_SCALAR);
        let g = Point::<MutualCurve>::generator();
        let v_picc = g.scalar_mul(&v_scalar);
        let u_pcd_public = g.scalar_mul(&u_scalar);
        let shared = u_pcd_public.scalar_mul(&v_scalar);
        let shared_x = shared.x_coordinate().expect("shared point is finite");
        (
            PaceMidwayState {
                v_picc,
                u_pcd: NonZeroScalar::new(u_scalar).expect("fixture scalar is nonzero"),
                u_pcd_public,
            },
            shared_x.as_slice().to_vec(),
        )
    }

    fn mutual_auth_transport(
        suite: PaceInfo,
        state: &PaceMidwayState<MutualCurve>,
        shared_x: &[u8],
        card_token: Option<[u8; AUTH_TOKEN_LEN]>,
    ) -> StepFiveMock {
        let k_mac = kdf_aes256(shared_x, KdfParam::Mac);
        let token_for_card = encode_auth_token(suite, &state.v_picc).expect("card point encodes");
        let t_pcd = aes256_cmac_truncated(k_mac.as_bytes(), &token_for_card);
        let request_payload = refineid_ber::tlv(
            TAG_DYNAMIC_AUTH,
            refineid_ber::tlv(TAG_AUTH_TOKEN_PCD, t_pcd.as_bytes()).expect("encodes"),
        )
        .expect("encodes");
        let expected = GeneralAuthenticate {
            chain: false,
            payload: request_payload,
        }
        .into_apdu()
        .expect("command encodes");
        let token_for_us =
            encode_auth_token(suite, &state.u_pcd_public).expect("terminal point encodes");
        let t_picc = aes256_cmac_truncated(k_mac.as_bytes(), &token_for_us);
        let token = card_token.map_or_else(|| t_picc.as_bytes().to_vec(), |bad| bad.to_vec());
        let response_body = refineid_ber::tlv(
            TAG_DYNAMIC_AUTH,
            refineid_ber::tlv(TAG_AUTH_TOKEN_PICC, token).expect("encodes"),
        )
        .expect("encodes");
        StepFiveMock {
            expected: expected.as_bytes().to_vec(),
            response: success_response(response_body),
            called: false,
        }
    }

    #[test]
    fn mutual_authentication_round_trips_against_a_peer() {
        let suite = generic(PaceDomain::BrainpoolP384r1, &access(citizen_card_access()));
        let (state, shared_x) = mutual_auth_state();
        let mut transport = mutual_auth_transport(suite, &state, &shared_x, None);
        let can = can();
        let session = super::run_mutual_authentication(
            &mut transport,
            suite,
            &PacePassword::Can(&can),
            state,
        )
        .expect("round succeeds");
        assert!(transport.called);
        assert_eq!(session.ssc, Ssc::INITIAL);
        assert_eq!(
            session.k_mac.as_bytes(),
            kdf_aes256(&shared_x, KdfParam::Mac).as_bytes()
        );
    }

    #[test]
    fn mutual_authentication_rejects_a_tampered_token() {
        let suite = generic(PaceDomain::BrainpoolP384r1, &access(citizen_card_access()));
        let (state, shared_x) = mutual_auth_state();
        let mut bad_token = [0_u8; AUTH_TOKEN_LEN];
        bad_token[0] = u8::MAX;
        let mut transport = mutual_auth_transport(suite, &state, &shared_x, Some(bad_token));
        let can = can();
        let error = super::run_mutual_authentication(
            &mut transport,
            suite,
            &PacePassword::Can(&can),
            state,
        )
        .expect_err("a tampered token fails the check");
        assert!(matches!(error, PaceError::AuthMismatch));
    }
}
