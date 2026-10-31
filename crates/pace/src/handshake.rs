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
//! PACE authenticates a card session from the Card Access Number before
//! any application command is exchanged; the FINEID card requires it on
//! the contactless interface and accepts it on contact for protected
//! reads. This driver runs the variant the FINEID cards advertise:
//! `id-PACE-ECDH-GM-AES-CBC-CMAC-256` over brainpoolP384r1 with the CAN
//! as the password (BSI TR-03110-3 section A.5, ICAO Doc 9303 Part 11
//! section 9.7.1). On success it returns the two session keys and the
//! initial send sequence counter for the secure-messaging layer.
//!
//! The wire flow is `MSE:Set AT` followed by four `GENERAL AUTHENTICATE`
//! rounds: fetch and decrypt the card nonce; map the nonce to a
//! session generator; agree an ephemeral shared point; and exchange and
//! verify mutual authentication tokens.

use bp384::elliptic_curve::bigint::Reduce as _;
use subtle::ConstantTimeEq as _;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use refineid_apdu::{CardTransport, CommandDataError, ResponseApdu, StatusWord, TransportOutcome};
use refineid_ber::{BerEncodeError, BerError, BerTag, BerTlv};

use crate::can::Can;
use crate::commands::{GeneralAuthenticate, MseSetAt};
use crate::crypto::brainpool_p384::{FieldBytes, NonZeroScalar, Point, Scalar};
use crate::crypto::container::{AesCbc, Ciphertext};
use crate::crypto::symmetric::{
    AES_BLOCK, Aes256Key, CMAC_TAG_TRUNCATED, KdfParam, aes256_cbc_decrypt_no_padding,
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
/// TR-03110-3 section B.11.1).
pub const PASSWORD_REF_CAN: u8 = 0x02;

/// FINEID's card-specific PACE domain-parameter identifier for
/// brainpoolP384r1. FINEID cards declare this value in their card-access
/// data, which is not the standardized-registry value, so it is pinned
/// to what the cards actually accept.
pub const DOMAIN_REF_BRAINPOOL_P384_R1: u8 = 0x10;

/// Length of the PACE mechanism object-identifier body, in bytes.
const PACE_MECHANISM_OID_LEN: usize = 10;
/// DER object identifier body for `id-PACE-ECDH-GM-AES-CBC-CMAC-256`
/// (OID 0.4.0.127.0.7.2.2.4.2.4), without the tag and length octets.
const PACE_MECHANISM_OID: [u8; PACE_MECHANISM_OID_LEN] =
    [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];

/// All-zero initialisation vector for the encrypted-nonce decryption
/// (BSI TR-03110-3 section A.5.1.2).
const BSI_TR03110_ZERO_IV: [u8; AES_BLOCK] = [0_u8; AES_BLOCK];

/// The encrypted-nonce length: one AES block.
const NONCE_LEN: usize = AES_BLOCK;

/// The card's mutual-authentication token length.
const AUTH_TOKEN_LEN: usize = CMAC_TAG_TRUNCATED;

/// Mechanism-reference object tag inside `MSE:Set AT`.
const TAG_MSE_MECHANISM: u8 = 0x80;
/// Password-reference object tag inside `MSE:Set AT`.
const TAG_MSE_PASSWORD: u8 = 0x83;
/// Domain-reference object tag inside `MSE:Set AT`.
const TAG_MSE_DOMAIN: u8 = 0x84;
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
    /// card derived different keys, almost always a wrong CAN.
    AuthMismatch,
    /// The operating-system random-number generator was unavailable.
    Random(rng::Failure),
}

impl<E: core::fmt::Display> core::fmt::Display for PaceError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "PACE transport: {e}"),
            Self::Outcome(outcome) => write!(f, "PACE transport state: {outcome}"),
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
pub(crate) struct PaceMidwayState {
    /// The card's key-agreement public point.
    v_picc: Point,
    /// The terminal's ephemeral private scalar.
    u_pcd: NonZeroScalar,
    /// The terminal's key-agreement public point.
    u_pcd_public: Point,
}

/// Run the full PACE-with-CAN handshake.
///
/// The card must be at master-file level; a FINEID card refuses the
/// opening command from an application context, so select the master
/// file first when the prior state is unknown. On success, wrap the same
/// transport in the secure-messaging layer and run the protected command
/// chain through it. A wrong CAN consumes no retry counter but surfaces
/// as a status-word or token-mismatch failure.
///
/// # Errors
///
/// Any transport, BER, status-word, off-curve-point, or token-mismatch
/// failure encountered during the handshake; see [`PaceError`].
pub fn run_pace_with_can<T: CardTransport>(
    transport: &mut T,
    can: Can,
) -> Result<PaceSession, PaceError<T::Error>> {
    set_authentication_template(transport, PASSWORD_REF_CAN)?;
    // Own the mapping nonce in a scrubbed buffer for its whole lifetime.
    let nonce = Zeroizing::new(get_encrypted_nonce(transport, &can)?);
    let state = map_nonce_and_key_agreement(transport, &nonce)?;
    run_mutual_authentication(transport, state)
}

/// Transmit a replay-safe command and demand a real response.
fn exchange<T: CardTransport>(
    transport: &mut T,
    command: &refineid_apdu::CommandApdu,
    stage: &'static str,
) -> Result<ResponseApdu, PaceError<T::Error>> {
    let response = transport
        .transmit(command)
        .map_err(PaceError::Transport)?
        .into_response()
        .map_err(PaceError::Outcome)?;
    if !response.is_ok() {
        return Err(PaceError::Status(stage, response.status_word()));
    }
    Ok(response)
}

/// Step one: announce the mechanism, password reference, and domain.
fn set_authentication_template<T: CardTransport>(
    transport: &mut T,
    password_ref: u8,
) -> Result<(), PaceError<T::Error>> {
    let mut encoder = refineid_ber::BerEncoder::with_capacity(PACE_MECHANISM_OID.len());
    encoder.push_tlv(TAG_MSE_MECHANISM, PACE_MECHANISM_OID)?;
    encoder.push_tlv(TAG_MSE_PASSWORD, [password_ref])?;
    encoder.push_tlv(TAG_MSE_DOMAIN, [DOMAIN_REF_BRAINPOOL_P384_R1])?;
    let command = MseSetAt {
        data: encoder.finish(),
    }
    .into_apdu()?;
    exchange(transport, &command, "MSE:Set AT")?;
    Ok(())
}

/// Step two: fetch and decrypt the card's nonce.
fn get_encrypted_nonce<T: CardTransport>(
    transport: &mut T,
    can: &Can,
) -> Result<[u8; NONCE_LEN], PaceError<T::Error>> {
    let request = refineid_ber::tlv(TAG_DYNAMIC_AUTH, [])?;
    let command = GeneralAuthenticate {
        chain: true,
        payload: request,
    }
    .into_apdu()?;
    let response = exchange(transport, &command, "GA-1 encrypted nonce")?;

    let outer = BerTlv::<DynamicAuthData>::parse(&response.body)?;
    let inner = BerTlv::<EncryptedNonce>::parse(outer.value())?;
    if inner.value().len() != NONCE_LEN {
        return Err(PaceError::UnexpectedResponse(
            "encrypted nonce wrong length",
        ));
    }

    let k_pi = kdf_aes256(can.password_bytes(), KdfParam::Password);
    let ciphertext = Ciphertext::<AesCbc>::new(inner.value().to_vec());
    // The decrypted nonce is the PACE mapping secret; erase the heap
    // buffer that carried it once the fixed-width nonce is lifted out.
    let plaintext = Zeroizing::new(
        aes256_cbc_decrypt_no_padding(k_pi.as_bytes(), &BSI_TR03110_ZERO_IV, &ciphertext).map_err(
            |_unaligned| PaceError::UnexpectedResponse("encrypted nonce not block-aligned"),
        )?,
    );
    let nonce: [u8; NONCE_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_len| PaceError::UnexpectedResponse("decrypted nonce wrong length"))?;
    Ok(nonce)
}

/// Steps three and four: map the nonce to a session generator, then run
/// the ephemeral ECDH on it.
fn map_nonce_and_key_agreement<T: CardTransport>(
    transport: &mut T,
    nonce: &[u8; NONCE_LEN],
) -> Result<PaceMidwayState, PaceError<T::Error>> {
    let x_pcd = random_scalar_mod_n()?;
    let x_pcd_public = Point::generator().scalar_mul(&x_pcd);
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
    let response = exchange(transport, &command, "GA-2 map nonce")?;
    let outer = BerTlv::<DynamicAuthData>::parse(&response.body)?;
    let card_y = BerTlv::<MappingDataOut>::parse(outer.value())?;
    let y_picc = Point::decode_uncompressed(card_y.value()).ok_or(PaceError::InvalidPoint)?;
    reject_reflection(&x_pcd_public, &y_picc)?;

    // The mapped generator and everything it is built from depend on
    // the nonce and the private scalar; each lives in a scrubbed owner.
    let h = Zeroizing::new(y_picc.scalar_mul(&x_pcd));
    let s_scalar = scalar_from_nonce(nonce);
    let s_g = Zeroizing::new(Point::generator().scalar_mul(&s_scalar));
    let mapped_g = Zeroizing::new(s_g.add(&h));

    let u_pcd = random_scalar_mod_n()?;
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
    let response = exchange(transport, &command, "GA-3 key agreement")?;
    let outer = BerTlv::<DynamicAuthData>::parse(&response.body)?;
    let card_v = BerTlv::<KeyAgreeOut>::parse(outer.value())?;
    let v_picc = Point::decode_uncompressed(card_v.value()).ok_or(PaceError::InvalidPoint)?;
    reject_reflection(&u_pcd_public, &v_picc)?;

    Ok(PaceMidwayState {
        v_picc,
        u_pcd: *u_pcd,
        u_pcd_public,
    })
}

/// Step five: exchange and verify the mutual-authentication tokens, then
/// derive the session keys.
pub(crate) fn run_mutual_authentication<T: CardTransport>(
    transport: &mut T,
    state: PaceMidwayState,
) -> Result<PaceSession, PaceError<T::Error>> {
    let shared = Zeroizing::new(state.v_picc.scalar_mul(&state.u_pcd));
    let shared_x_bytes = shared.x_coordinate().ok_or(PaceError::InvalidPoint)?;

    let k_enc = kdf_aes256(shared_x_bytes.as_slice(), KdfParam::Encryption);
    let k_mac = kdf_aes256(shared_x_bytes.as_slice(), KdfParam::Mac);

    let token_for_card = encode_auth_token(&state.v_picc).ok_or(PaceError::InvalidPoint)?;
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
    let response = exchange(transport, &command, "GA-4 mutual authentication")?;

    let outer = BerTlv::<DynamicAuthData>::parse(&response.body)?;
    let card_tag = BerTlv::<AuthTokenOut>::parse(outer.value())?;
    if card_tag.value().len() != AUTH_TOKEN_LEN {
        return Err(PaceError::UnexpectedResponse("card token wrong length"));
    }

    let token_for_us = encode_auth_token(&state.u_pcd_public).ok_or(PaceError::InvalidPoint)?;
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
/// public point with the PACE mechanism identifier (BSI TR-03110-3
/// section A.2.4). `None` for the point at infinity, a degenerate input.
fn encode_auth_token(point: &Point) -> Option<Vec<u8>> {
    let point_bytes = point.encode_uncompressed()?;
    let mut inner = refineid_ber::BerEncoder::with_capacity(PACE_MECHANISM_OID.len());
    inner.push_tlv(TAG_ASN1_OID, PACE_MECHANISM_OID).ok()?;
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
fn reject_reflection<E>(ours: &Point, theirs: &Point) -> Result<(), PaceError<E>> {
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
fn random_scalar_mod_n<E>() -> Result<Zeroizing<NonZeroScalar>, PaceError<E>> {
    loop {
        let mut buffer = Zeroizing::new(FieldBytes::default());
        rng::fill(buffer.as_mut_slice()).map_err(PaceError::Random)?;
        if let Some(scalar) = NonZeroScalar::from_repr(*buffer).into_option() {
            return Ok(Zeroizing::new(scalar));
        }
    }
}

/// Lift a nonce to a scalar by left-padding with zeros to the scalar
/// width; the value is always below the subgroup order, so the reduction
/// leaves it unchanged. The scalar is the CAN-protected mapping secret,
/// so it is a scrubbed owner.
fn scalar_from_nonce(nonce: &[u8; NONCE_LEN]) -> Zeroizing<Scalar> {
    let mut padded = Zeroizing::new(FieldBytes::default());
    let pad = padded.len() - NONCE_LEN;
    padded[pad..].copy_from_slice(nonce);
    Zeroizing::new(Scalar::reduce(&*padded))
}

#[cfg(test)]
mod tests {
    use super::{
        AUTH_TOKEN_LEN, BSI_TR03110_ZERO_IV, DynamicAuthData, KdfParam, NONCE_LEN as AES_NONCE_LEN,
        NonZeroScalar, PACE_MECHANISM_OID, PaceError, PaceMidwayState, Point, Scalar, Ssc,
        TAG_AUTH_TOKEN_PCD, TAG_DYNAMIC_AUTH, aes256_cmac_truncated, encode_auth_token, kdf_aes256,
        random_scalar_mod_n, reject_reflection, scalar_from_nonce,
    };
    use crate::can::{Can, UnvalidatedCan};
    use crate::commands::GeneralAuthenticate;
    use crate::crypto::symmetric::{Aes256Key, aes256_cbc_encrypt_no_padding};
    use bp384::elliptic_curve::Curve as _;
    use bp384::elliptic_curve::ff::PrimeField as _;
    use bp384::{ArrayEncoding as _, BrainpoolP384r1, U384};
    use refineid_apdu::{
        APDU_HEADER_LEN, CardTransport, CommandApdu, CredentialCommand, ResponseApdu,
        TransportOutcome,
    };
    use refineid_ber::{BerTag, BerTlv};

    /// The card-response authentication-token tag as a one-byte value.
    const TAG_AUTH_TOKEN_PICC: u8 = 0x86;
    /// Nonce byte count for the lift test.
    const NONCE_LEN: usize = 16;
    /// High-half byte count of the lifted scalar.
    const SCALAR_HIGH_ZEROS: usize = 32;
    /// Expected object-identifier body length.
    const OID_BODY_LEN: usize = 10;
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
    /// Scalar width in bytes for the shared-secret fixture.
    const SHARED_X_LEN: usize = 48;
    /// A synthetic card-side private scalar.
    const CARD_SCALAR: u64 = 0x0123_4567;
    /// A synthetic terminal-side private scalar.
    const TERMINAL_SCALAR: u64 = 0x0FED_CBA9;
    /// The card-response encrypted-nonce tag as a one-byte value.
    const TAG_ENCRYPTED_NONCE: u8 = 0x80;
    /// The card-response mapping-data tag as a one-byte value.
    const TAG_MAPPING_PICC: u8 = 0x82;
    /// The card-response key-agreement tag as a one-byte value.
    const TAG_KEY_AGREE_PICC: u8 = 0x84;
    /// Width of the short-form Lc field (ISO/IEC 7816-4 section 5.1).
    const LC_LEN: usize = 1;
    /// Width of the short-form Le field (ISO/IEC 7816-4 section 5.1).
    const LE_LEN: usize = 1;
    /// Offset of the data field in a short case 4 command (ISO/IEC
    /// 7816-4 section 5.1): the header, then Lc.
    const CASE4_DATA_OFFSET: usize = APDU_HEADER_LEN + LC_LEN;
    /// A synthetic Card Access Number.
    const CAN_TEXT: &str = "123456";
    /// A synthetic encrypted nonce, one AES block of ASCII.
    const SYNTHETIC_NONCE: &[u8; AES_NONCE_LEN] = b"synthetic nonce.";
    /// Exchanges up to and including the mapping round: MSE:Set AT,
    /// GA-1 and GA-2.
    const EXCHANGES_THROUGH_MAPPING: usize = 3;
    /// Exchanges up to and including the key-agreement round.
    const EXCHANGES_THROUGH_KEY_AGREEMENT: usize = 4;
    /// Exchanges of a complete handshake, the token round included.
    const EXCHANGES_THROUGH_TOKENS: usize = 5;
    /// A synthetic card-side key-agreement private scalar.
    const CARD_KEY_AGREEMENT_SCALAR: u64 = 7_654_321;

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

    /// The value of the `T` object inside a General Authenticate
    /// command's dynamic-authentication-data template.
    fn terminal_object<T: BerTag>(command: &CommandApdu) -> Vec<u8> {
        let bytes = command.as_bytes();
        let data = &bytes[CASE4_DATA_OFFSET..bytes.len() - LE_LEN];
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

    /// Which round the reflecting peer echoes back.
    #[derive(Clone, Copy)]
    enum Reflect {
        Mapping,
        KeyAgreement,
    }

    /// A card emulator that does not know the CAN: it answers GA-1 with
    /// a fixed block, GA-2 with the generator or the terminal's own
    /// point, and GA-3 with the terminal's own point.
    struct ReflectingPeer {
        reflect: Reflect,
        exchanges: usize,
    }

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
                        let generator = Point::generator()
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

    /// A card emulator that knows the CAN and runs every round honestly:
    /// it encrypts [`SYNTHETIC_NONCE`] under the CAN key, maps the nonce
    /// with its own scalars, checks the terminal's token and answers with
    /// its own (ICAO Doc 9303 Part 11 section 4.4).
    struct HonestCard {
        exchanges: usize,
        mapped_generator: Option<Point>,
        terminal_key_agreement: Option<Point>,
        card_key_agreement: Option<Point>,
        k_mac: Option<Aes256Key>,
    }

    impl HonestCard {
        fn new() -> Self {
            Self {
                exchanges: 0,
                mapped_generator: None,
                terminal_key_agreement: None,
                card_key_agreement: None,
                k_mac: None,
            }
        }

        fn decode(bytes: &[u8]) -> Point {
            Point::decode_uncompressed(bytes).expect("terminal point decodes")
        }

        fn encode(point: &Point) -> Vec<u8> {
            point
                .encode_uncompressed()
                .expect("finite point")
                .as_bytes()
                .to_vec()
        }

        fn encrypted_nonce() -> Vec<u8> {
            let k_pi = kdf_aes256(synthetic_can().password_bytes(), KdfParam::Password);
            aes256_cbc_encrypt_no_padding(k_pi.as_bytes(), &BSI_TR03110_ZERO_IV, SYNTHETIC_NONCE)
                .expect("one block")
                .as_bytes()
                .to_vec()
        }

        fn map(&mut self, command: &CommandApdu) -> TransportOutcome {
            let terminal = Self::decode(&terminal_object::<MapPcdPublic>(command));
            let card_scalar = Scalar::from(CARD_SCALAR);
            let card_public = Point::generator().scalar_mul(&card_scalar);
            let shared = terminal.scalar_mul(&card_scalar);
            let nonce_point = Point::generator().scalar_mul(&scalar_from_nonce(SYNTHETIC_NONCE));
            self.mapped_generator = Some(nonce_point.add(&shared));
            card_answer(TAG_MAPPING_PICC, &Self::encode(&card_public))
        }

        fn agree(&mut self, command: &CommandApdu) -> TransportOutcome {
            let terminal = Self::decode(&terminal_object::<KeyAgreePcdPublic>(command));
            let card_scalar = Scalar::from(CARD_KEY_AGREEMENT_SCALAR);
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
            let k_mac = self.k_mac.as_ref().expect("key agreement ran");
            let card_public = self.card_key_agreement.as_ref().expect("key agreement ran");
            let terminal = self
                .terminal_key_agreement
                .as_ref()
                .expect("key agreement ran");
            let expected = aes256_cmac_truncated(
                k_mac.as_bytes(),
                &encode_auth_token(card_public).expect("card point encodes"),
            );
            if terminal_object::<AuthTokenPcd>(command) != expected.as_bytes() {
                return Err("the terminal token does not verify".to_owned());
            }
            let t_picc = aes256_cmac_truncated(
                k_mac.as_bytes(),
                &encode_auth_token(terminal).expect("terminal point encodes"),
            );
            Ok(card_answer(TAG_AUTH_TOKEN_PICC, t_picc.as_bytes()))
        }
    }

    impl CardTransport for HonestCard {
        type Error = String;

        fn transmit(&mut self, command: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            let index = self.exchanges;
            self.exchanges += 1;
            match index {
                EXCHANGE_MSE => Ok(TransportOutcome::Response(success_response(Vec::new()))),
                EXCHANGE_NONCE => Ok(card_answer(TAG_ENCRYPTED_NONCE, &Self::encrypted_nonce())),
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

    fn synthetic_can() -> Can {
        Can::reconstruct(UnvalidatedCan::from_owned_text(CAN_TEXT.to_owned()))
            .expect("fixture is a valid CAN")
    }

    #[test]
    fn reject_reflection_refuses_an_equal_point() {
        let g = Point::generator();
        assert!(matches!(
            reject_reflection::<core::convert::Infallible>(&g, &g),
            Err(PaceError::ReflectedKey)
        ));
        assert!(reject_reflection::<core::convert::Infallible>(&g, &g.add(&g)).is_ok());
    }

    #[test]
    fn honest_card_completes_the_handshake() {
        let mut card = HonestCard::new();
        let session =
            super::run_pace_with_can(&mut card, synthetic_can()).expect("the handshake succeeds");
        assert_eq!(card.exchanges, EXCHANGES_THROUGH_TOKENS);
        assert_eq!(session.ssc, Ssc::INITIAL);
        assert_eq!(
            session.k_mac.as_bytes(),
            card.k_mac.expect("key agreement ran").as_bytes()
        );
    }

    #[test]
    fn reflected_key_agreement_point_aborts_before_the_token_round() {
        let mut peer = ReflectingPeer {
            reflect: Reflect::KeyAgreement,
            exchanges: 0,
        };
        let result = super::run_pace_with_can(&mut peer, synthetic_can());
        assert!(matches!(result, Err(PaceError::ReflectedKey)));
        assert_eq!(peer.exchanges, EXCHANGES_THROUGH_KEY_AGREEMENT);
    }

    #[test]
    fn reflected_mapping_point_aborts() {
        let mut peer = ReflectingPeer {
            reflect: Reflect::Mapping,
            exchanges: 0,
        };
        let result = super::run_pace_with_can(&mut peer, synthetic_can());
        assert!(matches!(result, Err(PaceError::ReflectedKey)));
        assert_eq!(peer.exchanges, EXCHANGES_THROUGH_MAPPING);
    }

    #[test]
    fn mechanism_oid_body_is_ten_bytes() {
        assert_eq!(PACE_MECHANISM_OID.len(), OID_BODY_LEN);
    }

    #[test]
    fn random_scalars_are_in_range() {
        let order = BrainpoolP384r1::ORDER.get();
        for _round in 0..SCALAR_ROUNDS {
            let scalar = random_scalar_mod_n::<core::convert::Infallible>()
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
        let scalar = scalar_from_nonce(&nonce);
        let bytes = scalar.to_repr();
        assert!(bytes[..SCALAR_HIGH_ZEROS].iter().all(|&b| b == 0));
        assert_eq!(&bytes[SCALAR_HIGH_ZEROS..], &nonce[..]);
    }

    #[test]
    fn midway_state_is_zeroize_on_drop() {
        fn require_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        require_zeroize_on_drop::<PaceMidwayState>();
    }

    #[test]
    fn auth_token_wraps_the_oid_and_point() {
        let token = encode_auth_token(&Point::generator()).expect("generator encodes");
        // The two-byte public-key template tag, then a short-form length.
        assert_eq!(
            &token[..TEMPLATE_TAG_LEN],
            &[TEMPLATE_TAG_HIGH, TEMPLATE_TAG_LOW]
        );
        assert_eq!(&token[OID_BODY_START..OID_BODY_END], &PACE_MECHANISM_OID);
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

    fn success_response(body: Vec<u8>) -> ResponseApdu {
        let [sw1, sw2] = refineid_apdu::StatusWord::Success.as_u16().to_be_bytes();
        ResponseApdu { body, sw1, sw2 }
    }

    fn mutual_auth_state() -> (PaceMidwayState, [u8; SHARED_X_LEN]) {
        // A card-side scalar and a terminal-side scalar; the resulting
        // shared point is the same from either side by ECDH, so the
        // derived keys and the exchanged tokens agree.
        let v_scalar = Scalar::from(CARD_SCALAR);
        let u_scalar = Scalar::from(TERMINAL_SCALAR);
        let g = Point::generator();
        let v_picc = g.scalar_mul(&v_scalar);
        let u_pcd_public = g.scalar_mul(&u_scalar);
        let shared = u_pcd_public.scalar_mul(&v_scalar);
        let shared_x = shared.x_coordinate().expect("shared point is finite");
        let mut x_bytes = [0_u8; SHARED_X_LEN];
        x_bytes.copy_from_slice(shared_x.as_slice());
        (
            PaceMidwayState {
                v_picc,
                u_pcd: NonZeroScalar::new(u_scalar).expect("fixture scalar is nonzero"),
                u_pcd_public,
            },
            x_bytes,
        )
    }

    #[test]
    fn mutual_authentication_round_trips_against_a_peer() {
        let (state, shared_x) = mutual_auth_state();
        let k_mac = kdf_aes256(&shared_x, KdfParam::Mac);

        // The terminal will send its token over the card's public point.
        let token_for_card = encode_auth_token(&state.v_picc).expect("card point encodes");
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

        // The card replies with its token over the terminal's point.
        let token_for_us = encode_auth_token(&state.u_pcd_public).expect("terminal point encodes");
        let t_picc = aes256_cmac_truncated(k_mac.as_bytes(), &token_for_us);
        let response_body = refineid_ber::tlv(
            TAG_DYNAMIC_AUTH,
            refineid_ber::tlv(TAG_AUTH_TOKEN_PICC, t_picc.as_bytes()).expect("encodes"),
        )
        .expect("encodes");

        let mut transport = StepFiveMock {
            expected: expected.as_bytes().to_vec(),
            response: success_response(response_body),
            called: false,
        };
        let session =
            super::run_mutual_authentication(&mut transport, state).expect("round succeeds");
        assert!(transport.called);
        assert_eq!(session.ssc, Ssc::INITIAL);
        assert_eq!(
            session.k_mac.as_bytes(),
            kdf_aes256(&shared_x, KdfParam::Mac).as_bytes()
        );
        assert_eq!(AUTH_TOKEN_LEN, t_picc.as_bytes().len());
    }

    #[test]
    fn mutual_authentication_rejects_a_tampered_token() {
        let (state, shared_x) = mutual_auth_state();
        let k_mac = kdf_aes256(&shared_x, KdfParam::Mac);
        let token_for_card = encode_auth_token(&state.v_picc).expect("card point encodes");
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

        let mut bad_token = [0_u8; AUTH_TOKEN_LEN];
        bad_token[0] = u8::MAX;
        let response_body = refineid_ber::tlv(
            TAG_DYNAMIC_AUTH,
            refineid_ber::tlv(TAG_AUTH_TOKEN_PICC, bad_token).expect("encodes"),
        )
        .expect("encodes");

        let mut transport = StepFiveMock {
            expected: expected.as_bytes().to_vec(),
            response: success_response(response_body),
            called: false,
        };
        let error = super::run_mutual_authentication(&mut transport, state)
            .expect_err("a tampered token fails the check");
        assert!(matches!(error, PaceError::AuthMismatch));
    }
}
