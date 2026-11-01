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

use core::fmt;
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

/// RAPP v26.11.1 wire version triple [Year, Month, Day].
pub const WIRE_VERSION_V26_11_1: (u16, u16, u16) = (26, 11, 1);
/// Mandatory RAPP pairing Noise suite.
pub const MANDATORY_PAIRING_SUITE: &str = "Noise_XXpsk3_25519_ChaChaPoly_SHA512";
/// Mandatory RAPP session Noise suite (RAPP v26.11.1 section 6.3).
pub const MANDATORY_SESSION_SUITE: &str = "Noise_KK_25519_ChaChaPoly_SHA512";
/// Byte length of an X25519 public or private key.
pub const X25519_KEY_SIZE: usize = 32;
/// Byte length of a Noise ChaCha20Poly1305 authentication tag.
pub const NOISE_TAG_SIZE: usize = 16;
/// Maximum encoded Noise frame size.
pub const MAX_FRAME_SIZE: usize = 65_535;
/// Maximum plaintext carried by one Noise transport message.
pub const MAX_FRAME_PLAINTEXT: usize = 65_519;
/// Maximum simultaneously active operations at an authorization proxy.
pub const MAX_ACTIVE_OPERATIONS: usize = 1;
/// Pairing-offer lifetime in milliseconds (RAPP v26.11.1 §3.3, §4.2).
pub const OFFER_TTL_MS: u64 = 300_000;
/// Fewest tries left at which a Custodian sends a PIN verification (RAPP
/// v26.11.1 section 10.2). The floor itself is `check_retry_floor` in
/// `refineid-auth`, which every surface applies.
pub const MINIMUM_REMAINING_ATTEMPTS: u8 = 3;
/// How long a requester keeps offering a confirmed certificate with no
/// session open or the card reported absent (RAPP v26.11.1 section 8.4
/// item 3).
pub const IDENTITY_OFFER_GRACE_MS: u64 = 120_000;
/// How long a requester that quits waits for its `service_withdrawn` closes
/// to leave before it exits (RAPP v26.11.1 section 4.5 item 8), and one
/// whose holder turned remote use off waits for its `pairing_revoked` closes
/// (section 4.6 item 6).
pub const QUIT_WITHDRAWAL_BOUND_MS: u64 = 1_000;

/// Byte length of an offer identifier.
pub const OFFER_ID_SIZE: usize = 32;
/// Byte length of a pair identifier.
pub const PAIR_ID_SIZE: usize = 16;
/// Byte length of a session identifier.
pub const SESSION_ID_SIZE: usize = 16;
/// Byte length of an operation identifier.
pub const OPERATION_ID_SIZE: usize = 16;
/// Byte length of a certificate fingerprint.
pub const CERTIFICATE_FINGERPRINT_SIZE: usize = 32;
/// Byte length of a grant-set hash.
pub const GRANTS_HASH_SIZE: usize = 32;
/// Byte length of the one-use QR pairing secret.
pub const PAIRING_SECRET_SIZE: usize = 32;
/// Byte length of a fresh bilateral session-ready nonce.
pub const SESSION_READY_NONCE_SIZE: usize = 32;
/// Byte length of a fresh authenticated liveness challenge.
pub const LIVENESS_CHALLENGE_SIZE: usize = 32;

/// Structural error while reconstructing a fixed-size protocol value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentifierError {
    /// Required byte length.
    pub expected: usize,
    /// Supplied byte length.
    pub got: usize,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "identifier requires {} bytes, got {}",
            self.expected, self.got
        )
    }
}

impl core::error::Error for IdentifierError {}

macro_rules! public_identifier {
    ($name:ident, $size:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $size]);

        impl $name {
            /// Reconstruct an identifier from an exact-size byte slice.
            ///
            /// # Errors
            /// [`IdentifierError`] when the slice has the wrong length.
            pub fn reconstruct(bytes: &[u8]) -> Result<Self, IdentifierError> {
                let value: [u8; $size] = bytes.try_into().map_err(|_| IdentifierError {
                    expected: $size,
                    got: bytes.len(),
                })?;
                Ok(Self(value))
            }

            /// Construct an identifier from an exact-size array.
            #[must_use]
            pub const fn from_array(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            /// Public protocol bytes. Identifiers are not credentials.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "("))?;
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                formatter.write_str(")")
            }
        }
    };
}

public_identifier!(
    OfferId,
    OFFER_ID_SIZE,
    "Random identifier for one pairing offer."
);
public_identifier!(
    PairId,
    PAIR_ID_SIZE,
    "Derived identifier for one stored pairing."
);
public_identifier!(
    SessionId,
    SESSION_ID_SIZE,
    "Derived identifier for one secure channel."
);
public_identifier!(
    OperationId,
    OPERATION_ID_SIZE,
    "Random identifier for one semantic operation."
);
public_identifier!(
    CertificateFingerprint,
    CERTIFICATE_FINGERPRINT_SIZE,
    "SHA-256 of the DER encoding of a card's authentication certificate (section 8.4)."
);

impl CertificateFingerprint {
    /// The fingerprint of a DER-encoded certificate.
    #[must_use]
    pub fn of_certificate(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }
}
public_identifier!(
    GrantsHash,
    GRANTS_HASH_SIZE,
    "Hash binding the granted profile set."
);

/// One-use 256-bit pairing bearer secret.
///
/// It is non-clonable, always redacted, and zeroized on drop. Only the RAPP
/// cryptographic layer can borrow its bytes.
#[derive(PartialEq, Eq, ZeroizeOnDrop)]
pub struct PairingSecret([u8; PAIRING_SECRET_SIZE]);

impl PairingSecret {
    /// Take ownership of fresh random bytes supplied by a platform CSPRNG.
    #[must_use]
    pub const fn from_random_bytes(bytes: [u8; PAIRING_SECRET_SIZE]) -> Self {
        Self(bytes)
    }

    pub(super) const fn expose(&self) -> &[u8; PAIRING_SECRET_SIZE] {
        &self.0
    }
}

impl fmt::Debug for PairingSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingSecret([redacted])")
    }
}

/// Registered credential profile name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProfileName {
    /// Safe card and retry-state inspection.
    CardStatus,
    /// Browser or application authentication using PIN 1.
    Authentication,
    /// Document-digest signing using PIN 2.
    DocumentSigning,
}

impl ProfileName {
    /// Every registered profile, in registry order (section 9).
    pub const ALL: [Self; 3] = [
        Self::CardStatus,
        Self::Authentication,
        Self::DocumentSigning,
    ];

    /// Stable wire registry name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CardStatus => "fi.refineid.card-status",
            Self::Authentication => "fi.refineid.authentication",
            Self::DocumentSigning => "fi.refineid.document-signing",
        }
    }

    /// Parse a registered wire profile name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fi.refineid.card-status" => Some(Self::CardStatus),
            "fi.refineid.authentication" => Some(Self::Authentication),
            "fi.refineid.document-signing" => Some(Self::DocumentSigning),
            _ => None,
        }
    }
}

/// Stable session-close reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Orderly close, such as a sequence or lifetime restart.
    Normal,
    /// The session's work is complete.
    Complete,
    /// Explicit user disconnect.
    UserDisconnect,
    /// Local policy refusal.
    Policy,
    /// Authenticated peer protocol violation.
    ProtocolViolation,
    /// Deliberate pairing revocation.
    PairingRevoked,
    /// Local process shutdown.
    Shutdown,
    /// The custodian can no longer serve the card.
    CardUnavailable,
    /// The sender withdrew: a custodian stopped serving, or a requester
    /// stopped using, every pairing (section 4.5).
    ServiceWithdrawn,
}
