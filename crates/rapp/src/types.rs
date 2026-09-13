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
use zeroize::ZeroizeOnDrop;

/// RAPP wire version implemented by this module.
pub const VISIBLE_WIRE_VERSION: (u16, u16, u16) = (26, 9, 13);
/// Mandatory RAPP 26.9 pairing Noise suite.
pub const MANDATORY_PAIRING_SUITE: &str = "Noise_XXpsk3_25519_ChaChaPoly_SHA256";
/// Mandatory RAPP 26.9 session Noise suite.
pub const MANDATORY_SESSION_SUITE: &str = "Noise_KK_25519_ChaChaPoly_SHA256";
/// Maximum encoded Noise frame size.
pub const MAX_FRAME_SIZE: usize = 65_535;
/// Maximum plaintext carried by one Noise transport message.
pub const MAX_FRAME_PLAINTEXT: usize = 65_519;
/// Maximum simultaneously active operations at an authorization proxy.
pub const MAX_ACTIVE_OPERATIONS: usize = 1;
/// Maximum transport candidates accepted in a pairing offer.
pub const MAX_TRANSPORT_CANDIDATES: usize = 8;
/// Maximum pairing-offer lifetime in milliseconds.
pub const OFFER_TTL_MAX_MS: u64 = 180_000;
/// Minimum retry count on the credential that a command can decrement.
pub const MINIMUM_REMAINING_ATTEMPTS: u8 = 3;
/// Authentication failures after which re-pairing may be suggested.
pub const CANDIDATE_FAILURE_HINT_THRESHOLD: u8 = 3;

/// Byte length of an offer identifier.
pub const OFFER_ID_SIZE: usize = 32;
/// Byte length of a pair identifier.
pub const PAIR_ID_SIZE: usize = 16;
/// Byte length of a session identifier.
pub const SESSION_ID_SIZE: usize = 16;
/// Byte length of a pair-specific transport rendezvous token.
pub const RENDEZVOUS_TOKEN_SIZE: usize = 16;
/// Byte length of an operation identifier.
pub const OPERATION_ID_SIZE: usize = 16;
/// Byte length of a request hash.
pub const REQUEST_HASH_SIZE: usize = 32;
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
    RendezvousToken,
    RENDEZVOUS_TOKEN_SIZE,
    "Derived pair-specific rendezvous value for transports that must name a pairing on the wire without exposing its identifier."
);
public_identifier!(
    OperationId,
    OPERATION_ID_SIZE,
    "Random identifier for one semantic operation."
);
public_identifier!(
    RequestHash,
    REQUEST_HASH_SIZE,
    "Hash binding an operation request."
);
public_identifier!(
    GrantsHash,
    GRANTS_HASH_SIZE,
    "Hash binding the granted profile set."
);

/// One-use 256-bit pairing bearer secret.
///
/// It is non-clonable, always redacted, and zeroized on drop. Only the RAPP
/// cryptographic layer can borrow its bytes.
#[derive(ZeroizeOnDrop)]
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
    /// Stable wire registry name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CardStatus => "fi.refineid.card-status.v1",
            Self::Authentication => "fi.refineid.authentication.v1",
            Self::DocumentSigning => "fi.refineid.document-signing.v1",
        }
    }

    /// Parse a registered wire profile name.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fi.refineid.card-status.v1" => Some(Self::CardStatus),
            "fi.refineid.authentication.v1" => Some(Self::Authentication),
            "fi.refineid.document-signing.v1" => Some(Self::DocumentSigning),
            _ => None,
        }
    }
}

/// Result of checking the counter that a proposed command can decrement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// The command may be offered to the user.
    Permit,
    /// The counter is unavailable, so the command must not be sent.
    RefuseUnavailable,
    /// Only one or two attempts remain, so the command must not be sent.
    RefuseNearLockout {
        /// Remaining attempts reported by the credential.
        remaining: u8,
    },
    /// The checked credential is blocked and cannot be verified.
    RefuseBlocked,
}

impl RetryDecision {
    /// Apply RAPP retry policy to the counter that the command would consume.
    ///
    /// A blocked target PIN does not use this decision when a PUK reset is
    /// requested. In that operation the PUK counter is the decrementing
    /// counter and is checked instead.
    #[must_use]
    pub const fn for_decrementing_counter(remaining: Option<u8>) -> Self {
        match remaining {
            None => Self::RefuseUnavailable,
            Some(0) => Self::RefuseBlocked,
            Some(value) if value < MINIMUM_REMAINING_ATTEMPTS => {
                Self::RefuseNearLockout { remaining: value }
            }
            Some(_) => Self::Permit,
        }
    }
}

/// Stable session-close reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Explicit user disconnect.
    UserDisconnect,
    /// Local policy refusal.
    Policy,
    /// CAN, PIN 1, or PIN 2 rejection.
    CredentialRejected,
    /// Authenticated peer protocol violation.
    ProtocolViolation,
    /// Deliberate pairing revocation.
    PairingRevoked,
    /// Local process shutdown.
    Shutdown,
}

/// Total unexpected-input classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Invalid input before peer authentication.
    PreAuthenticationInvalidInput,
    /// Framing or authenticated-decryption failure on an established channel.
    EstablishedChannelIntegrityFailure,
    /// Unknown/terminal operation reference or unmatched pong.
    StaleReferenceRace,
    /// Nonconforming message proven to come from the paired peer.
    AuthenticatedProtocolViolation,
    /// Local invariant failure.
    LocalInternalFault,
    /// Input arriving after a session became terminal.
    TrafficAfterClosed,
}

/// User-visible RAPP connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibleConnectionState {
    /// Durable pairing exists without a live session.
    PairedDisconnected,
    /// Transport establishment is in progress.
    Connecting,
    /// The mutually authenticated channel is being verified.
    VerifyingSecureConnection,
    /// Recent cryptographic liveness has been proven.
    Connected,
    /// Liveness recovery is in progress and operations are blocked.
    CheckingConnection,
    /// Session closure is in progress.
    Disconnecting,
    /// Session has stopped.
    ConnectionStopped,
    /// Pairing is permanently revoked and requires manual re-pairing.
    PairingRevoked,
}
