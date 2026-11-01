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

//! Card-side signing and RSA decipher for FINEID.
//!
//! The card holds the private key and performs the private-key
//! operation; the host computes the digest and drives the MANAGE
//! SECURITY ENVIRONMENT / PERFORM SECURITY OPERATION choreography. The
//! shape follows the card family the session resolved (see
//! [`SignScheme`]): the citizen card loads the digest with PSO:HASH and
//! signs an empty PSO:CDS, while the organizational card carries the
//! digest inline in a single PSO:CDS and issues no PSO:HASH. Both
//! families set the digital-signature template for either key. The
//! signing commands carry no credential material and use the plain
//! transport path.
//!
//! A signature is made through a [`SigningKey`]. The authentication key
//! is named with PIN 1 already verified by the caller. The qualified key
//! exists only where PIN 2 was presented for it, and only in the
//! directory it lives in -- DF.ESIGN on the organizational card: from
//! [`SignOps::unlock_qualified_key`], which enters that directory and
//! sends VERIFY PIN 2 there, or from
//! [`Pin2ChannelSignOps::qualified_key_after_pin2_pace`] on a secure
//! channel PIN 2 itself opened, which enters the directory and sends no
//! PIN at all. A channel the Card Access Number or PIN 1 opened has no
//! such method, so it cannot reach the qualified key without a VERIFY.
//!
//! The pre-hashed signing chains all fit the short-form command:
//! RSASSA-PKCS1-v1_5 and RSASSA-PSS over SHA-256, SHA-384, or SHA-512
//! for the RSA keys, and ECDSA over P-384 with SHA-256 or SHA-384 for the
//! newer keys. PSS is a
//! card-native scheme -- the card applies the padding from the digest, so
//! the choreography is the pre-hashed chain with a different algorithm
//! reference, not a host-encoded block.
//!
//! RSA decipher is the other private-key operation here: `decipher_rsa`
//! sets the confidentiality template and ships the modulus-wide cryptogram
//! by command chaining (its data field exceeds the short form), and the
//! card returns the recovered plaintext.

pub mod commands;
pub mod container;

use refineid_apdu::{CardTransport, CommandDataError, ResponseApdu, StatusWord, TransportOutcome};
use refineid_auth::{AuthError, Pin2, PinOps as _, PinReferenceScheme, VerifyOutcome};
use refineid_pace::{OpenedByPin2, Pin2PresentationSpent, SmTransport};
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops as _};
use zeroize::Zeroizing;

use commands::{
    DecipherAlgRef, ExternalHashValue, MseSet, MseSetCt, PsoComputeDigitalSignature, PsoDecipher,
    PsoHashExternal, SHA256_LEN, SHA384_LEN, SHA512_LEN, SignatureAlgRef, expected_length_le,
};
pub use container::{
    CryptogramLengthError, EcdsaP256, EcdsaP384, RecoveredPlaintext, RsaCryptogram, RsaPkcs1Sha256,
    RsaPkcs1Sha384, RsaPkcs1Sha512, RsaPssSha256, RsaPssSha384, RsaPssSha512, Signature,
    SignatureLength, SignatureLengthError,
};

/// PKCS#15 key reference for the authentication key (PIN1-gated).
pub const KEY_REF_AUTH: u8 = 0x01;
/// PKCS#15 key reference for the qualified-signature key (PIN2-gated).
pub const KEY_REF_SIGN: u8 = 0x02;
/// Organizational card's qualified-signature key reference. That key is
/// local to DF.ESIGN, and a local security-data-object reference sets
/// bit 8 over the object number (IAS-ECC v1.0.1 section 4.4); the global
/// form names no key and the signature answers `6A88`.
pub const ORG_QUALIFIED_KEY_REF: u8 = 0x82;

/// Which card family's signing chain and key numbering to drive.
///
/// The citizen card loads the host digest with PSO:HASH and signs an
/// empty PSO:CDS; the organizational card carries the digest inline in
/// PSO:CDS and names its qualified key by the local reference. The family
/// is resolved once - the auth crate's counter-safe probe settles it when
/// a PIN is verified - and passed to the signing entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignScheme {
    /// FINEID S1 numbering and chain: the citizen cards.
    Citizen,
    /// FINEID S4 numbering and chain: the organizational cards.
    Organizational,
}

impl SignScheme {
    /// The credential numbering of the same card family.
    const fn pin_numbering(self) -> PinReferenceScheme {
        match self {
            Self::Citizen => PinReferenceScheme::Citizen,
            Self::Organizational => PinReferenceScheme::Organizational,
        }
    }
}

impl From<PinReferenceScheme> for SignScheme {
    /// The signing family of the card whose credential numbering the
    /// session resolved.
    fn from(numbering: PinReferenceScheme) -> Self {
        match numbering {
            PinReferenceScheme::Citizen => Self::Citizen,
            PinReferenceScheme::Organizational => Self::Organizational,
        }
    }
}

/// RSA-3072 modulus width in bytes. The signature and the decipher
/// cryptogram are each exactly one modulus-wide block.
pub const RSA_3072_MODULUS_BYTES: usize = 384;
/// Expected RSA-3072 signature length in bytes.
pub const RSA_3072_SIG_BYTES: usize = RSA_3072_MODULUS_BYTES;
/// Expected ECDSA P-384 raw signature length in bytes.
pub const ECDSA_P384_SIG_BYTES: usize = 96;
/// Expected ECDSA P-256 raw signature length in bytes.
pub const ECDSA_P256_SIG_BYTES: usize = 64;

/// The FINEID private-key reference, typed at the sign-API boundary so
/// the chain refuses an arbitrary byte. The card publishes exactly two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRef {
    /// The authentication key, PIN1-gated.
    Auth,
    /// The qualified-signature key, PIN2-gated.
    Sign,
}

impl KeyRef {
    /// The card-side reference byte under the citizen numbering.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Auth => KEY_REF_AUTH,
            Self::Sign => KEY_REF_SIGN,
        }
    }

    /// The card-side reference byte under `scheme`. The organizational
    /// qualified-signature key is local to DF.ESIGN and named by
    /// [`ORG_QUALIFIED_KEY_REF`]; every other key keeps its own
    /// reference.
    #[must_use]
    pub const fn reference(self, scheme: SignScheme) -> u8 {
        match (scheme, self) {
            (SignScheme::Organizational, Self::Sign) => ORG_QUALIFIED_KEY_REF,
            _ => self.as_byte(),
        }
    }
}

/// A signing-path failure.
#[derive(Debug)]
pub enum SignError<E> {
    /// An adapter-level transport failure.
    Transport(E),
    /// A transport-level state transition instead of a response.
    Outcome(TransportOutcome),
    /// The card returned a non-success status word at a named stage.
    Status(&'static str, StatusWord),
    /// A command could not be assembled; unreachable for the fixed
    /// signing bodies, kept fail-closed.
    Command(CommandDataError),
    /// The card returned a signature of an unexpected length for the
    /// selected algorithm.
    UnexpectedSignatureLength {
        /// The length the card returned.
        got: usize,
        /// The length the algorithm requires.
        expected: usize,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for SignError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "sign transport: {e}"),
            Self::Outcome(outcome) => write!(f, "sign transport state: {outcome}"),
            Self::Status(stage, sw) => write!(f, "sign {stage}: card returned {sw}"),
            Self::Command(e) => write!(f, "sign command: {e}"),
            Self::UnexpectedSignatureLength { got, expected } => {
                write!(
                    f,
                    "sign: card returned a {got}-byte signature, expected {expected}"
                )
            }
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for SignError<E> {}

impl<E> From<container::SignatureLengthError> for SignError<E> {
    fn from(error: container::SignatureLengthError) -> Self {
        Self::UnexpectedSignatureLength {
            got: error.got,
            expected: error.expected,
        }
    }
}

/// Why the qualified-signature key was not made ready to sign.
#[derive(Debug)]
pub enum QualifiedUnlockError<E> {
    /// DF.ESIGN could not be made current; PIN 2 was not sent.
    Directory(Pkcs15Error<E>),
    /// VERIFY PIN 2 failed in transport or assembly.
    Verify(AuthError<E>),
    /// The card refused PIN 2. Never [`VerifyOutcome::Ok`].
    PinRefused(VerifyOutcome),
}

impl<E: core::fmt::Display> core::fmt::Display for QualifiedUnlockError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Directory(e) => write!(f, "select DF.ESIGN: {e}"),
            Self::Verify(e) => write!(f, "VERIFY PIN 2: {e}"),
            Self::PinRefused(outcome) => write!(f, "the card refused PIN 2: {outcome:?}"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error
    for QualifiedUnlockError<E>
{
}

/// Why the qualified-signature key was not made ready on a secure channel
/// PIN 2 opened.
#[derive(Debug)]
pub enum Pin2ChannelError<E> {
    /// The channel's PIN 2 presentation was already spent on an earlier
    /// qualified key; nothing was sent. A further signature on the channel
    /// takes [`SignOps::unlock_qualified_key`].
    PresentationSpent(Pin2PresentationSpent),
    /// DF.ESIGN could not be made current.
    Directory(Pkcs15Error<E>),
}

impl<E: core::fmt::Display> core::fmt::Display for Pin2ChannelError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PresentationSpent(e) => write!(f, "{e}"),
            Self::Directory(e) => write!(f, "select DF.ESIGN: {e}"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error
    for Pin2ChannelError<E>
{
}

/// The qualified-signature key on a PACE secure channel that PIN 2
/// opened.
///
/// Implemented only for `SmTransport<T, OpenedByPin2>`: the channel's type
/// is the proof that the card authenticated PACE with PIN 2, which only
/// `refineid_pace::run_pace` given a [`Pin2`] produces. A channel the Card
/// Access Number or PIN 1 opened does not implement it.
pub trait Pin2ChannelSignOps: CardTransport + Sized {
    /// Enter DF.ESIGN and hand back the qualified-signature key, ready to
    /// sign one digest, without sending PIN 2 again.
    ///
    /// PACE with PIN 2 is the organizational card's PIN 2 presentation:
    /// the card enables PACE under the PIN SIG reference (FINEID S4-2 v4.0
    /// section 6) and counts PIN 2 verified on the channel, so a VERIFY
    /// would transmit the PIN once more for nothing. The key is local to
    /// DF.ESIGN (section 4.2), so this selects DF.ESIGN by name from the
    /// MF, as [`SignOps::unlock_qualified_key`] does, and names the key by
    /// [`ORG_QUALIFIED_KEY_REF`] in the organizational chain. PIN PACE
    /// exists only on the organizational card, so the chain is not a
    /// parameter.
    ///
    /// The channel carries one PIN 2 presentation and this spends it,
    /// before any command, whatever follows: one presentation, one
    /// signature. The returned key borrows the channel exclusively and
    /// signing consumes it.
    ///
    /// # Errors
    ///
    /// [`Pin2ChannelError::PresentationSpent`] when the presentation was
    /// already spent (nothing is sent), and
    /// [`Pin2ChannelError::Directory`] when DF.ESIGN cannot be made
    /// current.
    fn qualified_key_after_pin2_pace(
        &mut self,
    ) -> Result<SigningKey<'_, Self>, Pin2ChannelError<Self::Error>>;
}

impl<T: CardTransport> Pin2ChannelSignOps for SmTransport<T, OpenedByPin2> {
    fn qualified_key_after_pin2_pace(
        &mut self,
    ) -> Result<SigningKey<'_, Self>, Pin2ChannelError<Self::Error>> {
        self.spend_pin2_presentation()
            .map_err(Pin2ChannelError::PresentationSpent)?;
        self.select_esign_directory()
            .map_err(Pin2ChannelError::Directory)?;
        Ok(SigningKey {
            transport: self,
            scheme: SignScheme::Organizational,
            key: KeyRef::Sign,
        })
    }
}

/// Card-side private-key operations -- signing and RSA decipher --
/// layered as default methods on every [`CardTransport`].
///
/// Bring the trait into scope to use the methods; the blanket
/// implementation applies to every transport, so a plain contact
/// transport and a PACE secure-messaging transport both gain the same
/// operations. A signature is made through a [`SigningKey`]:
/// [`SignOps::authentication_key`] names the PIN 1 key, and
/// [`SignOps::unlock_qualified_key`] verifies PIN 2 in the context the
/// qualified key lives in and hands back that key.
pub trait SignOps: CardTransport {
    /// The authentication key, ready to sign one digest.
    ///
    /// PIN 1 must already be verified in the card session, and `scheme`
    /// must be the family the session resolved. The key keeps its own
    /// reference under both numberings and is reached from the PKCS#15
    /// application.
    fn authentication_key(&mut self, scheme: SignScheme) -> SigningKey<'_, Self>
    where
        Self: Sized,
    {
        SigningKey {
            transport: self,
            scheme,
            key: KeyRef::Auth,
        }
    }

    /// VERIFY PIN 2 where the qualified-signature key lives and hand back
    /// that key, ready to sign one digest.
    ///
    /// On the organizational card the qualified key and PIN 2 are local
    /// to DF.ESIGN (FINEID S4-2 v4.0 section 4.2, SE#7 "local Signature
    /// PIN SIG"; IAS-ECC v1.0.1 section 4.4 for the local key
    /// reference), and the card answers `6A88` to the signature unless
    /// DF.ESIGN is the current DF. So this selects DF.ESIGN by name from
    /// the MF first and only then sends PIN 2. The citizen card is sent
    /// PIN 2 in the context the caller selected, as before.
    ///
    /// The returned key borrows the transport exclusively, so no command
    /// can move the card out of that context between the VERIFY and the
    /// signature, and signing consumes it: one verification, one
    /// signature. The caller applies the retry floor before calling.
    ///
    /// # Errors
    ///
    /// [`QualifiedUnlockError::Directory`] when DF.ESIGN cannot be made
    /// current (PIN 2 is not sent), [`QualifiedUnlockError::Verify`] on a
    /// VERIFY transport failure, and [`QualifiedUnlockError::PinRefused`]
    /// when the card refuses PIN 2.
    fn unlock_qualified_key(
        &mut self,
        scheme: SignScheme,
        pin: Pin2,
    ) -> Result<SigningKey<'_, Self>, QualifiedUnlockError<Self::Error>>
    where
        Self: Sized,
    {
        if scheme == SignScheme::Organizational {
            self.select_esign_directory()
                .map_err(QualifiedUnlockError::Directory)?;
        }
        let outcome = self
            .verify_pin2_with_scheme(scheme.pin_numbering(), pin)
            .map_err(QualifiedUnlockError::Verify)?;
        match outcome {
            VerifyOutcome::Ok => Ok(SigningKey {
                transport: self,
                scheme,
                key: KeyRef::Sign,
            }),
            refused @ (VerifyOutcome::WrongPin { .. }
            | VerifyOutcome::Locked
            | VerifyOutcome::Other(_)) => Err(QualifiedUnlockError::PinRefused(refused)),
        }
    }

    /// Decipher an RSA cryptogram with a card private key, returning the
    /// recovered plaintext; the card strips the padding.
    ///
    /// The key's PIN must already be verified in the card session, and
    /// `scheme` must be the family the session resolved. `algorithm` names
    /// the padding the card expects (see [`DecipherAlgRef`]). The
    /// modulus-wide cryptogram is shipped by command chaining, so the
    /// caller need not manage extended-length APDUs. The recovered
    /// plaintext comes back in [`RecoveredPlaintext`], which zeroises its
    /// storage on drop.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word at MSE:SET or any chained PSO:DECIPHER command.
    fn decipher_rsa(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        algorithm: DecipherAlgRef,
        cryptogram: &RsaCryptogram,
    ) -> Result<RecoveredPlaintext, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let mse = MseSetCt {
            alg_ref: algorithm,
            key_ref: key.reference(scheme),
        }
        .into_apdu()
        .map_err(SignError::Command)?;
        self.exchange(&mse, "MSE:Set CT")?;

        let chain = PsoDecipher { cryptogram }
            .into_chain()
            .map_err(SignError::Command)?;
        let (last, leading) = chain
            .split_last()
            .ok_or(SignError::Command(CommandDataError::Empty))?;
        for command in leading {
            // A non-final chained command draws a status only; any body
            // the card does return is decipher output and is zeroised
            // before the next exchange.
            let body = Zeroizing::new(self.exchange(command, "PSO:DECIPHER")?.body);
            drop(body);
        }
        let plaintext = self.exchange(last, "PSO:DECIPHER")?.body;
        Ok(RecoveredPlaintext::new(plaintext))
    }

    /// Transmit one signing command and demand a success response.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn exchange(
        &mut self,
        command: &refineid_apdu::CommandApdu,
        stage: &'static str,
    ) -> Result<ResponseApdu, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let response = self
            .transmit(command)
            .map_err(SignError::Transport)?
            .into_response()
            .map_err(SignError::Outcome)?;
        if !response.is_ok() {
            return Err(SignError::Status(stage, response.status_word()));
        }
        Ok(response)
    }
}

impl<T: CardTransport + ?Sized> SignOps for T {}

/// A card private key ready to sign one digest: the transport, borrowed
/// exclusively, with the card in the context the key is reached from.
///
/// Obtained from [`SignOps::authentication_key`] or, for the qualified
/// key, from [`SignOps::unlock_qualified_key`] or
/// [`Pin2ChannelSignOps::qualified_key_after_pin2_pace`] -- there is no
/// other constructor, so the qualified key cannot be named without PIN 2
/// presented for it, by VERIFY or by the PACE that opened the channel,
/// and its directory current. Each signing method consumes the key, so
/// one key signs one digest.
#[must_use = "a signing key does nothing until it signs"]
pub struct SigningKey<'t, T: CardTransport> {
    transport: &'t mut T,
    scheme: SignScheme,
    key: KeyRef,
}

impl<T: CardTransport> core::fmt::Debug for SigningKey<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("scheme", &self.scheme)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl<T: CardTransport> SigningKey<'_, T> {
    /// Sign a SHA-256 digest with an RSA-3072 key, returning its 384-byte
    /// signature.
    ///
    /// The length is fixed to RSA-3072 because that is the only RSA size the
    /// two key references [`KeyRef`] names carry on the cards that expose
    /// them; a card exposing an RSA-4096 signing key here would first need
    /// this length generalised to the key's modulus width.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    pub fn sign_prehashed_sha256_rsa(
        self,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<T::Error>> {
        let bytes = self.drive_chain(
            SignatureAlgRef::SHA256_RSA_PKCS1,
            ExternalHashValue::Sha256(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-384 digest with an RSA-3072 key under
    /// RSASSA-PKCS1-v1_5, returning its 384-byte signature.
    ///
    /// Qualified document signatures use SHA-384 for both RSA and ECDSA
    /// card profiles.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    pub fn sign_prehashed_sha384_rsa(
        self,
        digest: [u8; SHA384_LEN],
    ) -> Result<Signature<RsaPkcs1Sha384>, SignError<T::Error>> {
        let bytes = self.drive_chain(
            SignatureAlgRef::SHA384_RSA_PKCS1,
            ExternalHashValue::Sha384(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-512 digest with an RSA-3072 key under
    /// RSASSA-PKCS1-v1_5, returning its 384-byte signature.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    pub fn sign_prehashed_sha512_rsa(
        self,
        digest: [u8; SHA512_LEN],
    ) -> Result<Signature<RsaPkcs1Sha512>, SignError<T::Error>> {
        let bytes = self.drive_chain(
            SignatureAlgRef::SHA512_RSA_PKCS1,
            ExternalHashValue::Sha512(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-256 digest with an RSA-3072 key under RSASSA-PSS,
    /// returning its 384-byte signature.
    ///
    /// The card applies the PSS padding itself, so the chain matches the
    /// pre-hashed PKCS#1 path -- only the algorithm reference differs.
    /// PSS uses a card-generated salt, so signing the same digest twice
    /// yields different bytes. As for the PKCS#1 path, the length is fixed
    /// to RSA-3072, the only RSA size the key references expose.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    pub fn sign_prehashed_sha256_rsa_pss(
        self,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<RsaPssSha256>, SignError<T::Error>> {
        let bytes = self.drive_chain(
            SignatureAlgRef::SHA256_RSA_PSS,
            ExternalHashValue::Sha256(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-384 digest with an RSA-3072 key under RSASSA-PSS,
    /// returning its 384-byte signature.
    ///
    /// The card applies PSS with SHA-384, MGF1-SHA-384, and a 48-byte
    /// salt.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    pub fn sign_prehashed_sha384_rsa_pss(
        self,
        digest: [u8; SHA384_LEN],
    ) -> Result<Signature<RsaPssSha384>, SignError<T::Error>> {
        let bytes = self.drive_chain(
            SignatureAlgRef::SHA384_RSA_PSS,
            ExternalHashValue::Sha384(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-512 digest with an RSA-3072 key under RSASSA-PSS,
    /// returning its 384-byte signature.
    ///
    /// The card applies PSS with SHA-512, MGF1-SHA-512, and a 64-byte
    /// salt.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    pub fn sign_prehashed_sha512_rsa_pss(
        self,
        digest: [u8; SHA512_LEN],
    ) -> Result<Signature<RsaPssSha512>, SignError<T::Error>> {
        let bytes = self.drive_chain(
            SignatureAlgRef::SHA512_RSA_PSS,
            ExternalHashValue::Sha512(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-256 digest with a P-384 key, returning the raw ECDSA
    /// `r || s` signature.
    ///
    /// TLS 1.2 peers may negotiate ECDSA with SHA-256 even when the
    /// certificate carries a P-384 key. The curve fixes the signature
    /// width; the negotiated hash fixes this method's digest width and
    /// algorithm reference.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`ECDSA_P384_SIG_BYTES`].
    pub fn sign_prehashed_sha256_ecdsa(
        self,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<EcdsaP384>, SignError<T::Error>> {
        let bytes = self.drive_chain(
            SignatureAlgRef::SHA256_ECDSA,
            ExternalHashValue::Sha256(digest),
            expected_length_le(ECDSA_P384_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-384 digest with a P-384 key, returning the raw ECDSA
    /// `r || s` signature.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`ECDSA_P384_SIG_BYTES`].
    pub fn sign_prehashed_sha384_ecdsa(
        self,
        digest: [u8; SHA384_LEN],
    ) -> Result<Signature<EcdsaP384>, SignError<T::Error>> {
        let bytes = self.drive_chain(
            SignatureAlgRef::SHA384_ECDSA,
            ExternalHashValue::Sha384(digest),
            expected_length_le(ECDSA_P384_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Drive the resolved signing chain end to end and return the raw
    /// signature bytes: MSE:Set, then either PSO:HASH plus an empty
    /// PSO:CDS (citizen) or a single inline-digest PSO:CDS
    /// (organizational).
    fn drive_chain(
        self,
        alg_ref: SignatureAlgRef,
        hash: ExternalHashValue,
        le: u8,
    ) -> Result<Vec<u8>, SignError<T::Error>> {
        let mse = MseSet {
            alg_ref,
            key_ref: self.key.reference(self.scheme),
        }
        .into_apdu()
        .map_err(SignError::Command)?;
        self.transport.exchange(&mse, "MSE:Set")?;
        let signature = match self.scheme {
            SignScheme::Citizen => {
                let load = PsoHashExternal { hash }
                    .into_apdu()
                    .map_err(SignError::Command)?;
                self.transport.exchange(&load, "PSO:HASH")?;
                PsoComputeDigitalSignature.into_apdu(le)
            }
            SignScheme::Organizational => PsoComputeDigitalSignature
                .into_apdu_with_digest(hash, le)
                .map_err(SignError::Command)?,
        };
        Ok(self.transport.exchange(&signature, "PSO:CDS")?.body)
    }
}
