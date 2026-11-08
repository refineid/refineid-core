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

//! Typed remote-operation vocabulary for the Remote Authorization Proxy
//! Protocol (RAPP).
//!
//! RAPP lets a machine without a card reader ask the holder's phone for a
//! typed credential operation; the phone talks to the card and returns
//! only the profile-defined result. This crate is the closed vocabulary of
//! those operations -- the credential-profile, action, key-profile, and
//! signature-algorithm registries of RAPP review draft 26.8.17.135 section
//! 13.2.1, with their invariants carried by construction: a signature
//! request cannot exist with a digest of the wrong length or an algorithm
//! its key profile does not support, and consent display text cannot be
//! empty or unbounded.
//!
//! The crate deliberately holds names and invariants only. Wire encoding,
//! cryptographic channels, transports, engines, and stores live outside
//! this core; a local card session and a remote requester share this
//! vocabulary so an operation means the same thing on both paths. No CAN,
//! PIN, or PUK value has any representation here: RAPP never transports
//! them.

use core::fmt;

use refineid_digest::{SHA256_LEN, SHA384_LEN, SHA512_LEN};

/// SHA-224 digest length in bytes (FIPS 180-4 section 1: a 224-bit digest).
pub const SHA224_LEN: usize = 28;

/// Maximum UTF-8 bytes of one consent display text (RAPP 26.8.17.135
/// section 7.4, `MAX_TEXT_SIZE`).
pub const DISPLAY_TEXT_MAX: usize = 4_096;

/// The closed credential-profile registry (RAPP section 13.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteProfile {
    /// Inspect supported card and retry state.
    CardStatus,
    /// Browser or application authentication.
    Authentication,
    /// Qualified document signing.
    DocumentSigning,
}

impl RemoteProfile {
    /// The registered profile name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CardStatus => "fi.refineid.card-status.v1",
            Self::Authentication => "fi.refineid.authentication.v1",
            Self::DocumentSigning => "fi.refineid.document-signing.v1",
        }
    }

    /// Parses a registered profile name.
    ///
    /// # Errors
    ///
    /// Fails on any name outside the closed registry.
    pub fn parse(name: &str) -> Result<Self, RemoteOperationError> {
        match name {
            "fi.refineid.card-status.v1" => Ok(Self::CardStatus),
            "fi.refineid.authentication.v1" => Ok(Self::Authentication),
            "fi.refineid.document-signing.v1" => Ok(Self::DocumentSigning),
            _ => Err(RemoteOperationError::UnknownName),
        }
    }
}

/// Certificate selected for a public-data read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateKind {
    /// The authentication certificate, associated with PIN 1.
    Authentication,
    /// The qualified-signature certificate, associated with PIN 2.
    Signature,
}

impl CertificateKind {
    /// The registered wire text of the kind.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Signature => "signature",
        }
    }

    /// Parses a registered certificate kind.
    ///
    /// # Errors
    ///
    /// Fails on any name outside the closed registry.
    pub fn parse(name: &str) -> Result<Self, RemoteOperationError> {
        match name {
            "authentication" => Ok(Self::Authentication),
            "signature" => Ok(Self::Signature),
            _ => Err(RemoteOperationError::UnknownName),
        }
    }
}

/// The closed public-key profile registry (RAPP section 13.2.1).
///
/// The requester asserts the profile it expects; the phone independently
/// resolves the card certificate and refuses a mismatch before any PIN or
/// private-key command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteKeyProfile {
    /// ECDSA P-256.
    EcdsaP256,
    /// ECDSA P-384.
    EcdsaP384,
    /// RSA 2048-bit.
    Rsa2048,
    /// RSA 3072-bit.
    Rsa3072,
}

impl RemoteKeyProfile {
    /// The registered wire text of the profile.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa_p256",
            Self::EcdsaP384 => "ecdsa_p384",
            Self::Rsa2048 => "rsa_2048",
            Self::Rsa3072 => "rsa_3072",
        }
    }

    /// Parses a registered key profile.
    ///
    /// # Errors
    ///
    /// Fails on any name outside the closed registry.
    pub fn parse(name: &str) -> Result<Self, RemoteOperationError> {
        match name {
            "ecdsa_p256" => Ok(Self::EcdsaP256),
            "ecdsa_p384" => Ok(Self::EcdsaP384),
            "rsa_2048" => Ok(Self::Rsa2048),
            "rsa_3072" => Ok(Self::Rsa3072),
            _ => Err(RemoteOperationError::UnknownName),
        }
    }
}

/// The closed signature-algorithm registry (RAPP section 13.2.1). A digest
/// family alone is insufficient: PKCS #1, PSS, and ECDSA are distinct card
/// commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteSignatureAlgorithm {
    /// ECDSA over a SHA-224 digest.
    EcdsaSha224,
    /// ECDSA over a SHA-256 digest.
    EcdsaSha256,
    /// ECDSA over a SHA-384 digest.
    EcdsaSha384,
    /// ECDSA over a SHA-512 digest.
    EcdsaSha512,
    /// RSASSA-PKCS1-v1_5 over a SHA-256 digest.
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 over a SHA-384 digest.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 over a SHA-512 digest.
    RsaPkcs1Sha512,
    /// RSASSA-PSS over a SHA-256 digest.
    RsaPssSha256,
}

impl RemoteSignatureAlgorithm {
    /// The registered wire text of the algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EcdsaSha224 => "ecdsa_sha224",
            Self::EcdsaSha256 => "ecdsa_sha256",
            Self::EcdsaSha384 => "ecdsa_sha384",
            Self::EcdsaSha512 => "ecdsa_sha512",
            Self::RsaPkcs1Sha256 => "rsa_pkcs1_sha256",
            Self::RsaPkcs1Sha384 => "rsa_pkcs1_sha384",
            Self::RsaPkcs1Sha512 => "rsa_pkcs1_sha512",
            Self::RsaPssSha256 => "rsa_pss_sha256",
        }
    }

    /// Parses a registered algorithm.
    ///
    /// # Errors
    ///
    /// Fails on any name outside the closed registry.
    pub fn parse(name: &str) -> Result<Self, RemoteOperationError> {
        match name {
            "ecdsa_sha224" => Ok(Self::EcdsaSha224),
            "ecdsa_sha256" => Ok(Self::EcdsaSha256),
            "ecdsa_sha384" => Ok(Self::EcdsaSha384),
            "ecdsa_sha512" => Ok(Self::EcdsaSha512),
            "rsa_pkcs1_sha256" => Ok(Self::RsaPkcs1Sha256),
            "rsa_pkcs1_sha384" => Ok(Self::RsaPkcs1Sha384),
            "rsa_pkcs1_sha512" => Ok(Self::RsaPkcs1Sha512),
            "rsa_pss_sha256" => Ok(Self::RsaPssSha256),
            _ => Err(RemoteOperationError::UnknownName),
        }
    }

    /// The exact digest length the algorithm requires.
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::EcdsaSha224 => SHA224_LEN,
            Self::EcdsaSha256 | Self::RsaPkcs1Sha256 | Self::RsaPssSha256 => SHA256_LEN,
            Self::EcdsaSha384 | Self::RsaPkcs1Sha384 => SHA384_LEN,
            Self::EcdsaSha512 | Self::RsaPkcs1Sha512 => SHA512_LEN,
        }
    }

    /// Whether the algorithm is registered for the key profile.
    #[must_use]
    pub const fn supports(self, profile: RemoteKeyProfile) -> bool {
        matches!(
            (self, profile),
            (
                Self::EcdsaSha224 | Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512,
                RemoteKeyProfile::EcdsaP256 | RemoteKeyProfile::EcdsaP384
            ) | (
                Self::RsaPkcs1Sha256
                    | Self::RsaPkcs1Sha384
                    | Self::RsaPkcs1Sha512
                    | Self::RsaPssSha256,
                RemoteKeyProfile::Rsa2048 | RemoteKeyProfile::Rsa3072
            )
        )
    }
}

/// Bounded, non-empty consent display text: a relying-party origin or a
/// document name. The phone shows this text to the holder; nothing else
/// about the request is human-readable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayText(String);

impl DisplayText {
    /// Validates consent display text once at the boundary.
    ///
    /// # Errors
    ///
    /// Fails when the text is empty or exceeds [`DISPLAY_TEXT_MAX`] UTF-8
    /// bytes.
    pub fn new(text: String) -> Result<Self, RemoteOperationError> {
        if text.is_empty() {
            return Err(RemoteOperationError::EmptyDisplayText);
        }
        if text.len() > DISPLAY_TEXT_MAX {
            return Err(RemoteOperationError::DisplayTextTooLong);
        }
        Ok(Self(text))
    }

    /// The validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One digest-signing request whose invariants held at construction: the
/// digest has the algorithm's exact length and the algorithm is registered
/// for the asserted key profile. Documents and unhashed input never enter
/// RAPP; this type cannot carry them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureRequest {
    key_profile: RemoteKeyProfile,
    algorithm: RemoteSignatureAlgorithm,
    digest: Vec<u8>,
}

impl SignatureRequest {
    /// Validates the combination once at the boundary.
    ///
    /// # Errors
    ///
    /// Fails when the algorithm is not registered for the key profile or
    /// the digest length is not the algorithm's registered length.
    pub fn new(
        key_profile: RemoteKeyProfile,
        algorithm: RemoteSignatureAlgorithm,
        digest: Vec<u8>,
    ) -> Result<Self, RemoteOperationError> {
        if !algorithm.supports(key_profile) {
            return Err(RemoteOperationError::IncompatibleAlgorithm);
        }
        if digest.len() != algorithm.digest_len() {
            return Err(RemoteOperationError::DigestLength {
                expected: algorithm.digest_len(),
                got: digest.len(),
            });
        }
        Ok(Self {
            key_profile,
            algorithm,
            digest,
        })
    }

    /// The asserted key profile.
    #[must_use]
    pub const fn key_profile(&self) -> RemoteKeyProfile {
        self.key_profile
    }

    /// The exact signature algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> RemoteSignatureAlgorithm {
        self.algorithm
    }

    /// The already-hashed input of the registered length.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

/// One typed remote card operation of the closed action registry
/// (RAPP section 13.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteOperation {
    /// Read activation and retry state without touching a credential.
    InspectCard,
    /// Read the public identity fields.
    ReadIdentity,
    /// Read one public certificate; owned by the profile whose key the
    /// certificate serves, so a requester never learns a certificate whose
    /// key it could not ask to use.
    ReadCertificate(CertificateKind),
    /// Authenticate a browser challenge after holder consent on the phone.
    BrowserAuthenticate {
        /// The requester's own label for what is asking; it names no site
        /// and is not shown to the holder (RAPP section 11 item 1).
        origin: DisplayText,
        /// The validated digest-signing request.
        request: SignatureRequest,
    },
    /// Sign a document digest after holder consent on the phone.
    SignDocument {
        /// Document name shown to the holder.
        document_name: DisplayText,
        /// The validated digest-signing request.
        request: SignatureRequest,
    },
}

impl RemoteOperation {
    /// The credential profile that owns this action.
    #[must_use]
    pub const fn profile(&self) -> RemoteProfile {
        match self {
            Self::InspectCard | Self::ReadIdentity => RemoteProfile::CardStatus,
            Self::ReadCertificate(CertificateKind::Authentication)
            | Self::BrowserAuthenticate { .. } => RemoteProfile::Authentication,
            Self::ReadCertificate(CertificateKind::Signature) | Self::SignDocument { .. } => {
                RemoteProfile::DocumentSigning
            }
        }
    }

    /// The registered action name.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        match self {
            Self::InspectCard => "inspect_card",
            Self::ReadIdentity => "read_identity",
            Self::ReadCertificate(_) => "read_certificate",
            Self::BrowserAuthenticate { .. } => "browser_authenticate",
            Self::SignDocument { .. } => "sign_document",
        }
    }

    /// Whether the action carries a consequential credential command: a
    /// PIN verification and a private-key operation on the card.
    #[must_use]
    pub const fn is_consequential(&self) -> bool {
        matches!(
            self,
            Self::BrowserAuthenticate { .. } | Self::SignDocument { .. }
        )
    }
}

/// Why a vocabulary value could not be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteOperationError {
    /// The name is outside its closed registry.
    UnknownName,
    /// Consent display text was empty.
    EmptyDisplayText,
    /// Consent display text exceeded [`DISPLAY_TEXT_MAX`] UTF-8 bytes.
    DisplayTextTooLong,
    /// The algorithm is not registered for the key profile.
    IncompatibleAlgorithm,
    /// The digest length is not the algorithm's registered length.
    DigestLength {
        /// The algorithm's registered digest length.
        expected: usize,
        /// The rejected input length.
        got: usize,
    },
}

impl fmt::Display for RemoteOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownName => formatter.write_str("name outside the closed registry"),
            Self::EmptyDisplayText => formatter.write_str("consent display text is empty"),
            Self::DisplayTextTooLong => {
                formatter.write_str("consent display text exceeds the bound")
            }
            Self::IncompatibleAlgorithm => {
                formatter.write_str("algorithm not registered for the key profile")
            }
            Self::DigestLength { expected, got } => {
                write!(
                    formatter,
                    "digest length {got} where {expected} is registered"
                )
            }
        }
    }
}

impl core::error::Error for RemoteOperationError {}

#[cfg(test)]
mod tests {
    use refineid_digest::Sha256;

    use super::{
        CertificateKind, DisplayText, RemoteKeyProfile, RemoteOperation, RemoteOperationError,
        RemoteProfile, RemoteSignatureAlgorithm, SignatureRequest,
    };

    /// Deterministic non-secret test digest input.
    const DIGEST_INPUT: &[u8] = b"refineid-remote vocabulary test input";

    fn valid_request() -> SignatureRequest {
        SignatureRequest::new(
            RemoteKeyProfile::Rsa3072,
            RemoteSignatureAlgorithm::RsaPkcs1Sha256,
            Sha256::of(DIGEST_INPUT).into_bytes().to_vec(),
        )
        .expect("registered combination")
    }

    #[test]
    fn registry_names_round_trip() {
        for profile in [
            RemoteProfile::CardStatus,
            RemoteProfile::Authentication,
            RemoteProfile::DocumentSigning,
        ] {
            assert_eq!(RemoteProfile::parse(profile.name()), Ok(profile));
        }
        for algorithm in [
            RemoteSignatureAlgorithm::EcdsaSha224,
            RemoteSignatureAlgorithm::EcdsaSha256,
            RemoteSignatureAlgorithm::EcdsaSha384,
            RemoteSignatureAlgorithm::EcdsaSha512,
            RemoteSignatureAlgorithm::RsaPkcs1Sha256,
            RemoteSignatureAlgorithm::RsaPkcs1Sha384,
            RemoteSignatureAlgorithm::RsaPkcs1Sha512,
            RemoteSignatureAlgorithm::RsaPssSha256,
        ] {
            assert_eq!(
                RemoteSignatureAlgorithm::parse(algorithm.name()),
                Ok(algorithm)
            );
        }
        assert_eq!(
            RemoteProfile::parse("fi.refineid.apdu-tunnel.v1"),
            Err(RemoteOperationError::UnknownName)
        );
    }

    #[test]
    fn certificate_reads_are_owned_by_the_key_matching_profile() {
        assert_eq!(
            RemoteOperation::ReadCertificate(CertificateKind::Authentication).profile(),
            RemoteProfile::Authentication
        );
        assert_eq!(
            RemoteOperation::ReadCertificate(CertificateKind::Signature).profile(),
            RemoteProfile::DocumentSigning
        );
        assert!(!RemoteOperation::InspectCard.is_consequential());
    }

    #[test]
    fn signature_requests_hold_their_invariants_by_construction() {
        let request = valid_request();
        assert_eq!(request.digest().len(), request.algorithm().digest_len());

        let incompatible = SignatureRequest::new(
            RemoteKeyProfile::EcdsaP384,
            RemoteSignatureAlgorithm::RsaPssSha256,
            Sha256::of(DIGEST_INPUT).into_bytes().to_vec(),
        );
        assert_eq!(
            incompatible,
            Err(RemoteOperationError::IncompatibleAlgorithm)
        );

        let truncated = {
            let mut digest = Sha256::of(DIGEST_INPUT).into_bytes().to_vec();
            digest.pop();
            SignatureRequest::new(
                RemoteKeyProfile::Rsa3072,
                RemoteSignatureAlgorithm::RsaPkcs1Sha256,
                digest,
            )
        };
        assert!(matches!(
            truncated,
            Err(RemoteOperationError::DigestLength { .. })
        ));
    }

    #[test]
    fn display_text_is_bounded_and_non_empty() {
        assert_eq!(
            DisplayText::new(String::new()),
            Err(RemoteOperationError::EmptyDisplayText)
        );
        let oversized = "a".repeat(super::DISPLAY_TEXT_MAX + 1);
        assert_eq!(
            DisplayText::new(oversized),
            Err(RemoteOperationError::DisplayTextTooLong)
        );
        let origin =
            DisplayText::new("kortti.tunnistautuminen.suomi.fi".to_owned()).expect("bounded text");
        let operation = RemoteOperation::BrowserAuthenticate {
            origin,
            request: valid_request(),
        };
        assert_eq!(operation.action(), "browser_authenticate");
        assert_eq!(operation.profile(), RemoteProfile::Authentication);
        assert!(operation.is_consequential());
    }
}
