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
//! families set the digital-signature template for either key. The PIN
//! that gates the key must already be verified in the card session;
//! these commands carry no credential material and use the plain
//! transport path.
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

/// Card-side private-key operations -- signing and RSA decipher --
/// layered as default methods on every [`CardTransport`].
///
/// Bring the trait into scope to use the methods; the blanket
/// implementation applies to every transport, so a plain contact
/// transport and a PACE secure-messaging transport both gain the same
/// operations.
pub trait SignOps: CardTransport {
    /// Set the security environment for a signing key.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn mse_set(
        &mut self,
        scheme: SignScheme,
        alg_ref: SignatureAlgRef,
        key: KeyRef,
    ) -> Result<(), SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = MseSet {
            alg_ref,
            key_ref: key.reference(scheme),
        }
        .into_apdu()
        .map_err(SignError::Command)?;
        self.exchange(&command, "MSE:Set").map(drop)
    }

    /// Ship a host-computed digest to the card.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn pso_hash(&mut self, hash: ExternalHashValue) -> Result<(), SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = PsoHashExternal { hash }
            .into_apdu()
            .map_err(SignError::Command)?;
        self.exchange(&command, "PSO:HASH").map(drop)
    }

    /// Have the card sign the previously stored hash and return the raw
    /// signature bytes.
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn pso_compute_signature(&mut self, le: u8) -> Result<Vec<u8>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = PsoComputeDigitalSignature.into_apdu(le);
        Ok(self.exchange(&command, "PSO:CDS")?.body)
    }

    /// Ship the host digest inline and have the card sign it in one
    /// PSO:CDS, the organizational chain's single signing command. The
    /// digest arrives as [`ExternalHashValue`], so its wire length is the
    /// one its hash function fixes; `le` is the expected-length byte for
    /// the signature (see [`expected_length_le`]).
    ///
    /// # Errors
    ///
    /// Transport failures, a state transition, or a non-success status
    /// word.
    fn pso_compute_signature_over_digest(
        &mut self,
        hash: ExternalHashValue,
        le: u8,
    ) -> Result<Vec<u8>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let command = PsoComputeDigitalSignature
            .into_apdu_with_digest(hash, le)
            .map_err(SignError::Command)?;
        Ok(self.exchange(&command, "PSO:CDS")?.body)
    }

    /// Sign a SHA-256 digest with an RSA-3072 key, returning its 384-byte
    /// signature.
    ///
    /// The length is fixed to RSA-3072 because that is the only RSA size the
    /// two key references [`KeyRef`] names carry on the cards that expose
    /// them; a card exposing an RSA-4096 signing key here would first need
    /// this length generalised to the key's modulus width. The key's PIN
    /// must already be verified in the card session, and `scheme` must be
    /// the family the session resolved. On an organizational card the
    /// qualified key is local to DF.ESIGN, so that directory must be the
    /// selected DF.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha256_rsa(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA256_RSA_PKCS1,
            key,
            ExternalHashValue::Sha256(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-384 digest with an RSA-3072 key under
    /// RSASSA-PKCS1-v1_5, returning its 384-byte signature.
    ///
    /// Qualified document signatures use SHA-384 for both RSA and ECDSA
    /// card profiles. The key's PIN must already be verified in the card
    /// session, and `scheme` must be the family the session resolved. On an
    /// organizational card the qualified key is local to DF.ESIGN, so that
    /// directory must be the selected DF.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha384_rsa(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA384_LEN],
    ) -> Result<Signature<RsaPkcs1Sha384>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA384_RSA_PKCS1,
            key,
            ExternalHashValue::Sha384(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-512 digest with an RSA-3072 key under
    /// RSASSA-PKCS1-v1_5, returning its 384-byte signature.
    ///
    /// The key's PIN must already be verified in the card session, and
    /// `scheme` must be the family the session resolved. On an
    /// organizational card the qualified key is local to DF.ESIGN, so
    /// that directory must be the selected DF.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha512_rsa(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA512_LEN],
    ) -> Result<Signature<RsaPkcs1Sha512>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA512_RSA_PKCS1,
            key,
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
    /// to RSA-3072, the only RSA size the key references expose. The key's
    /// PIN must already be verified in the card session, and `scheme` must
    /// be the family the session resolved.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha256_rsa_pss(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<RsaPssSha256>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA256_RSA_PSS,
            key,
            ExternalHashValue::Sha256(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-384 digest with an RSA-3072 key under RSASSA-PSS,
    /// returning its 384-byte signature.
    ///
    /// The card applies PSS with SHA-384, MGF1-SHA-384, and a 48-byte
    /// salt. The key's PIN must already be verified in the card session,
    /// and `scheme` must be the family the session resolved.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha384_rsa_pss(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA384_LEN],
    ) -> Result<Signature<RsaPssSha384>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA384_RSA_PSS,
            key,
            ExternalHashValue::Sha384(digest),
            expected_length_le(RSA_3072_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-512 digest with an RSA-3072 key under RSASSA-PSS,
    /// returning its 384-byte signature.
    ///
    /// The card applies PSS with SHA-512, MGF1-SHA-512, and a 64-byte
    /// salt. The key's PIN must already be verified in the card session,
    /// and `scheme` must be the family the session resolved.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_prehashed_sha512_rsa_pss(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA512_LEN],
    ) -> Result<Signature<RsaPssSha512>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA512_RSA_PSS,
            key,
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
    /// algorithm reference. The key's PIN must already be verified in the
    /// card session, and `scheme` must be the family the session resolved.
    /// On an organizational card the qualified key is local to DF.ESIGN, so
    /// that directory must be the selected DF.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`ECDSA_P384_SIG_BYTES`].
    fn sign_prehashed_sha256_ecdsa(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA256_LEN],
    ) -> Result<Signature<EcdsaP384>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA256_ECDSA,
            key,
            ExternalHashValue::Sha256(digest),
            expected_length_le(ECDSA_P384_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
    }

    /// Sign a SHA-384 digest with a P-384 key, returning the raw ECDSA
    /// `r || s` signature.
    ///
    /// The key's PIN must already be verified in the card session, and
    /// `scheme` must be the family the session resolved. On an
    /// organizational card the qualified key is local to DF.ESIGN, so
    /// that directory must be the selected DF.
    ///
    /// # Errors
    ///
    /// Any stage failure, or a signature length other than
    /// [`ECDSA_P384_SIG_BYTES`].
    fn sign_prehashed_sha384_ecdsa(
        &mut self,
        scheme: SignScheme,
        key: KeyRef,
        digest: [u8; SHA384_LEN],
    ) -> Result<Signature<EcdsaP384>, SignError<Self::Error>>
    where
        Self: Sized,
    {
        let bytes = drive_chain(
            self,
            scheme,
            SignatureAlgRef::SHA384_ECDSA,
            key,
            ExternalHashValue::Sha384(digest),
            expected_length_le(ECDSA_P384_SIG_BYTES),
        )?;
        Ok(Signature::from_card_bytes(bytes)?)
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

/// Drive the resolved signing chain end to end and return the raw
/// signature bytes: MSE:Set, then either PSO:HASH plus an empty PSO:CDS
/// (citizen) or a single inline-digest PSO:CDS (organizational).
fn drive_chain<T: SignOps>(
    transport: &mut T,
    scheme: SignScheme,
    alg_ref: SignatureAlgRef,
    key: KeyRef,
    hash: ExternalHashValue,
    le: u8,
) -> Result<Vec<u8>, SignError<T::Error>> {
    transport.mse_set(scheme, alg_ref, key)?;
    match scheme {
        SignScheme::Citizen => {
            transport.pso_hash(hash)?;
            transport.pso_compute_signature(le)
        }
        SignScheme::Organizational => transport.pso_compute_signature_over_digest(hash, le),
    }
}
