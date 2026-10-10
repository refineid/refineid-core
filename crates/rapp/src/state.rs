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

use super::CloseReason;

/// Local projection of the distributed state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    /// Device asking for a credential operation.
    Requester,
    /// Device holding credentials and communicating with the card.
    Proxy,
}

/// Runtime facts referenced by formal transition guards.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each field is an independent guard fact from the formal transition model, not a state encoding"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Guards {
    /// Event was initiated by an explicit local user action.
    pub user_initiated: bool,
    /// Pairing offer is structurally valid and locally supported.
    pub offer_valid_and_supported: bool,
    /// Pairing offer remains live.
    pub offer_live: bool,
    /// Handshake transcript matches the expected prologue and empty payloads.
    pub transcript_matches: bool,
    /// Both confirmation messages contain exactly the same grant set.
    pub granted_sets_equal: bool,
    /// Pairing is confirmed.
    pub pairing_paired: bool,
    /// Session initiation satisfies the explicit-user-intent policy.
    pub initiation_permitted: bool,
    /// Session-ready parameter echo equals the local view.
    pub ready_parameters_match: bool,
    /// Liveness hard deadline has not expired.
    pub deadline_not_expired: bool,
    /// A healthy/checking session already exists for this pair.
    pub another_session_live: bool,
    /// Pair, session, profile grant, and active-operation admission all pass.
    pub admission_permitted: bool,
    /// Received request-hash echo equals the journal.
    pub hash_echo_matches: bool,
    /// Commit hash equals the prepared request hash.
    pub hash_matches: bool,
    /// No physical credential command has been transmitted.
    pub zero_transmissions: bool,
    /// Zero transmissions can be proved durably.
    pub proven_no_transmission: bool,
    /// Profile action has no consequential credential command.
    pub profile_has_no_consequential_command: bool,
}

/// Pairing component state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// No peer key material exists.
    Unpaired,
    /// A manual QR offer is live on a requester.
    OfferActive,
    /// Pairing Noise handshake is active.
    Handshaking,
    /// Authenticated peer confirmation is active.
    Confirming,
    /// Durable pairing exists without a healthy session.
    PairedDisconnected,
    /// Durable pairing has a healthy/checking session.
    PairedConnected,
    /// Fail-stop state; keys cannot be restored.
    Revoked,
}

/// Session component state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No live session instance.
    Absent,
    /// Requester transport establishment.
    Connecting,
    /// Noise and parameter-echo authentication.
    Authenticating,
    /// Recent cryptographic liveness proven.
    Healthy,
    /// Liveness recovery; new operations blocked.
    Checking,
    /// Close classification and key destruction.
    Closing,
    /// Terminal session record.
    Closed,
}

/// Operation component state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    /// Admission state for a new operation instance.
    None,
    /// Request sent or received.
    Requested,
    /// Proxy performs safe reads, consent, and local credential entry.
    AwaitingConsent,
    /// Approved with zero physical transmissions.
    Prepared,
    /// Durable point of no return recorded.
    Committed,
    /// One credential command may be in flight.
    Executing,
    /// Result exists and awaits acknowledgment.
    ResultPending,
    /// Completed terminal result.
    Completed,
    /// User-denied terminal result.
    Denied,
    /// Safely cancelled terminal result.
    Cancelled,
    /// Policy/card rejection terminal result.
    Rejected,
    /// CAN, PIN 1, or PIN 2 rejection terminal result.
    CredentialRejected,
    /// Completion cannot be proven and retry is forbidden.
    Ambiguous,
    /// Result exists but delivery was not acknowledged.
    DeliveryUncertain,
}

impl OperationState {
    /// Whether this state is a permanent journal terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Denied
                | Self::Cancelled
                | Self::Rejected
                | Self::CredentialRejected
                | Self::Ambiguous
                | Self::DeliveryUncertain
        )
    }
}

/// Pairing-machine input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingEvent {
    /// Explicit user action creates one manual QR offer.
    CreateOffer,
    /// Proxy scanned and validated a pairing offer QR.
    OfferScanned,
    /// A transport candidate connected while the offer is live.
    CandidateConnected,
    /// Offer reached its monotonic expiry or was cancelled.
    OfferExpiredOrCancelled,
    /// Pairing Noise handshake completed with a matching transcript.
    HandshakeAuthenticated,
    /// Pairing Noise handshake failed before authentication.
    HandshakeFailed,
    /// Both endpoints confirmed the same granted profile set.
    BothUsersConfirmed,
    /// Confirmation was denied, aborted, or exceeded local policy time.
    DeniedAbortedOrTimedOut,
    /// A session for this pairing reached the healthy state.
    SessionHealthy,
    /// The pairing's session closed.
    SessionClosed,
    /// Explicit user action removes the stored pairing.
    ForgetPairing,
    /// Successfully decrypted traffic violated the protocol.
    AuthenticatedProtocolViolation,
    /// Explicit user action revokes the pairing.
    LocalRevoke,
    /// Authenticated peer close carried a revocation reason.
    PeerRevocationNotice,
}

/// Session-machine input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// Explicit action initiates a new session transport.
    Connect,
    /// Accepting endpoint received an inbound transport connection.
    TransportAccepted,
    /// Requester transport establishment completed.
    TransportConnected,
    /// Transport was lost or could not be established.
    TransportFailed,
    /// Explicit local user disconnect.
    UserDisconnect,
    /// Session Noise handshake completed.
    HandshakeComplete,
    /// A live session already exists for the same pairing.
    SecondSessionDetected,
    /// Received session-ready parameters equal the local view.
    ReadyVerified,
    /// Candidate connection failed during authentication.
    CandidateFailure,
    /// Authenticated busy error arrived on the candidate session.
    BusyReceived,
    /// Authenticated peer close notice arrived.
    PeerCloseReceived,
    /// Successfully decrypted message violated the protocol.
    AuthenticatedProtocolViolation,
    /// A liveness exchange went unanswered.
    LivenessMissed,
    /// An exact challenge echo restored liveness.
    LivenessRestored,
    /// The local liveness hard deadline passed.
    LivenessDeadlineExpired,
    /// Local endpoint requested an orderly close.
    LocalCloseRequested,
    /// Card rejected the CAN, PIN 1, or PIN 2.
    CredentialRejected,
    /// Card completion can no longer be proven.
    CardCompletionAmbiguous,
    /// A frame failed authenticated decryption or framing.
    SessionIntegrityFailed,
    /// Pairing machine requested this session to close.
    CloseRequestedByPairing,
    /// Local internal fault stops RAPP.
    LocalSecurityShutdown,
    /// Close notice finished or the closing deadline passed.
    CloseCompleteOrDeadline,
}

/// Operation-machine input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationEvent {
    /// Requester sent the operation request.
    RequestSent,
    /// Proxy received the operation request.
    RequestReceived,
    /// Request passed schema, hash, expiry, and context validation.
    RequestValid,
    /// Request failed validation or names an unsupported profile or action.
    RequestInvalidOrUnsupported,
    /// Peer cancellation arrived.
    CancelReceived,
    /// Local monotonic request expiry elapsed.
    RequestExpired,
    /// Human authorizer denied the operation.
    UserDenied,
    /// Fewer than three attempts remain on the decrementable counter.
    RetryPolicyRefused,
    /// Card rejected the CAN, PIN 1, or PIN 2.
    InvalidCanOrPin1OrPin2,
    /// Safe prerequisite reads finished for an action with no consequential
    /// command.
    SafeReadsComplete,
    /// Human approved and the proxy can execute the exact request.
    UserApprovedAndProxyReady,
    /// Commit whose hash equals the prepared request hash arrived.
    ValidCommit,
    /// Proxy begins the single credential-command transmission.
    BeginCardCommand,
    /// Restart found a committed or executing record without a terminal
    /// result.
    CrashRecoveredWithoutTerminalResult,
    /// Card completed the consequential command.
    CardSuccess,
    /// Card refused the command for a non-credential reason.
    CardPolicyRejection,
    /// Card left before transmission provably began.
    CardRemovedBeforeTransmit,
    /// Card removal or transport loss left completion unproven.
    CardRemovedOrTransportUncertain,
    /// Session closed after the commit point.
    SessionClosedPostCommit,
    /// Result acknowledgment echoing the request hash arrived.
    ValidResultAck,
    /// Session closed with a completed result unacknowledged.
    SessionClosedBeforeAck,
    /// Prepared echo arrived on the requester.
    PreparedReceived,
    /// Requester cancelled or its local expiry elapsed.
    CancelSentOrRequestExpired,
    /// Requester sent the commit; the point of no return.
    CommitSent,
    /// Result with completed status arrived.
    ResultCompletedReceived,
    /// Result with denied status arrived.
    ResultDeniedReceived,
    /// Result with cancelled status arrived.
    ResultCancelledReceived,
    /// Result with rejected status arrived.
    ResultRejectedReceived,
    /// Result with credential-rejected status arrived.
    ResultCredentialRejectedReceived,
    /// Result with ambiguous status arrived.
    ResultAmbiguousReceived,
    /// Session closed before the commit point.
    SessionClosedPreCommit,
}

/// Protocol side effect emitted by a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Generate a fresh random offer identifier.
    GenerateOfferId,
    /// Generate the fresh random bearer pairing secret.
    GeneratePairingSecret,
    /// Start the offer's monotonic expiry clock.
    StartOfferExpiry,
    /// Display the pairing code.
    DisplayPairingCode,
    /// Stop displaying the pairing code.
    HidePairingCode,
    /// Select exactly one offered transport candidate.
    SelectOneCandidate,
    /// Connect the selected transport candidate.
    ConnectCandidate,
    /// Prepare the pairing Noise responder role.
    PreparePairingResponder,
    /// Begin the pairing Noise handshake as initiator.
    BeginPairingHandshakeInitiator,
    /// Derive the channel identifiers from the handshake hash.
    DeriveChannelIdentifiers,
    /// Destroy the pairing secret.
    DestroyPairingSecret,
    /// Stop accepting further candidates for this offer.
    StopAcceptingCandidates,
    /// Send the pairing hello with the negotiated-parameter echo.
    SendPairingHello,
    /// Display the peer and the proposed grant set.
    ShowPeerAndRequestedGrants,
    /// Discard the failed candidate connection.
    DiscardCandidate,
    /// Keep the offer live for further candidates.
    RetainOffer,
    /// Invalidate the pairing offer.
    InvalidateOffer,
    /// Close the candidate connection.
    CloseCandidate,
    /// Atomically store keys, pair identifier, grants, and metadata.
    StorePairRecordAtomically,
    /// Close the pairing channel; operations use fresh sessions.
    ClosePairingChannel,
    /// Send the pairing abort on a best-effort basis.
    SendPairingAbortBestEffort,
    /// Destroy the candidate pairing keys.
    DestroyCandidateKeys,
    /// Present the Connected liveness state.
    ShowConnected,
    /// Present the Paired, disconnected liveness state.
    ShowPairedDisconnected,
    /// Present the Checking connection liveness state.
    ShowChecking,
    /// Present the Disconnecting liveness state.
    ShowDisconnecting,
    /// Present the Connection stopped liveness state.
    ShowConnectionStopped,
    /// Present the Pairing revoked liveness state.
    ShowRevoked,
    /// Send the session close with this reason on a best-effort basis.
    SendCloseBestEffort(CloseReason),
    /// Close the active session.
    CloseSession,
    /// Destroy the pair-specific static keys.
    DestroyPairKeys,
    /// Destroy the pairing's rendezvous tokens.
    DestroyRelayTokens,
    /// Clear stored pairing metadata.
    ClearPairMetadata,
    /// Clear the residual record of a revoked pairing.
    ClearResidualPairRecord,
    /// Record that the peer initiated the revocation.
    RecordPeerInitiated,
    /// Select one mutually stored transport profile.
    SelectOneTransport,
    /// Open the selected transport.
    OpenTransport,
    /// Associate the connection with the stored pairing its routing preamble names.
    AssociatePairingFromRendezvous,
    /// Begin the session Noise handshake as initiator.
    BeginKkInitiator,
    /// Begin the session Noise handshake as responder.
    BeginKkResponder,
    /// Derive the session identifier from the handshake hash.
    DeriveSessionIdentifiers,
    /// Send the encrypted session-ready parameter echo.
    SendSessionReady,
    /// Send the authenticated busy error.
    SendErrorBusy,
    /// Start authenticated liveness probing.
    StartAuthenticatedLiveness,
    /// Block admission of new operations.
    BlockNewOperations,
    /// Start liveness backoff and the hard deadline.
    StartBackoffAndDeadline,
    /// Reset the liveness backoff.
    ResetBackoff,
    /// Record the peer's close reason.
    RecordPeerCloseReason,
    /// Count a candidate authentication failure toward the re-pairing hint.
    CountCandidateFailureHint,
    /// Note that no close notice can reach the peer.
    NoteCloseNoticeImpossible,
    /// Continue closing without a peer notice.
    ProceedWithoutCloseNotice,
    /// Abort the candidate connection attempt.
    AbortCandidate,
    /// Destroy session keys and handshake material.
    DestroySessionMaterial,
    /// Destroy collected credential buffers.
    DestroyCredentialBuffers,
    /// Persist the terminal session record.
    PersistTerminalSessionRecord,
    /// Validate request schema, hash, expiry, and context.
    ValidateSchemaHashExpiryAndContext,
    /// Start the operation's monotonic expiry clock.
    StartExpiryClock,
    /// Begin the profile's safe prerequisite reads.
    BeginSafePrerequisiteReads,
    /// Present profile-defined consent context.
    PresentConsentPerProfile,
    /// Dismiss any open consent prompt.
    DismissConsent,
    /// Destroy credentials collected for this operation.
    ClearOperationCredentials,
    /// Destroy every credential value in the active flow.
    ClearAllActiveCredentials,
    /// Remove cached values for the rejected credential and derived state.
    RemoveRejectedCredentialAndDerivedState,
    /// Send the prepared echo.
    SendPrepared,
    /// Send the result with completed status.
    SendResultCompleted,
    /// Send the result with denied status.
    SendResultDenied,
    /// Send the result with cancelled status.
    SendResultCancelled,
    /// Send the result with rejected status.
    SendResultRejected,
    /// Send the rejected result for a retry-policy refusal.
    SendResultRetryPolicyRefused,
    /// Send the bounded credential-rejected result on a best-effort basis.
    SendResultCredentialRejectedBestEffort,
    /// Send the ambiguous result on a best-effort basis.
    SendResultAmbiguousBestEffort,
    /// Ask the session machine for an explicit close.
    RequestSessionClose,
    /// Ask the session machine to close after credential rejection.
    RequestSessionCloseCredentialRejected,
    /// Revoke the pairing after a credential rejection.
    RevokePairAfterCredentialRejection,
    /// Ask the session machine to close after card ambiguity.
    RequestSessionCloseAmbiguous,
    /// Send the operation cancellation.
    SendOperationCancel,
    /// Durably write the commit record before any transmission.
    DurablyWriteCommitBeforeTransmission,
    /// Consume the non-clonable command object.
    ConsumeNonClonableCommand,
    /// Count the single permitted transmission.
    IncrementTransmissionCountOnce,
    /// Record the post-commit cancel as advisory.
    RecordAdvisoryCancel,
    /// Let the in-flight card exchange finish locally.
    ContinueCardExchangeLocally,
    /// Note that the result can no longer be delivered.
    NoteResultDeliveryImpossible,
    /// Persist the card result.
    PersistResult,
    /// Persist the rejected terminal state.
    PersistRejection,
    /// Persist the cancelled terminal state.
    PersistCancelled,
    /// Persist the ambiguous terminal state.
    PersistAmbiguous,
    /// Persist the completed terminal state.
    PersistCompleted,
    /// Persist the delivery-uncertain terminal state.
    PersistDeliveryUncertain,
    /// Release the acknowledged result.
    ReleaseResult,
    /// Retain the result encrypted under local platform storage.
    RetainResultUnderLocalStorage,
    /// Forbid any retry of this operation.
    ProhibitRetry,
    /// Forbid repeating the card command.
    ProhibitCardRetry,
    /// Compute the deterministic request hash.
    ComputeRequestHash,
    /// Journal the request.
    JournalRequest,
    /// Journal the prepared state.
    JournalPrepared,
    /// Durably journal the commit intent.
    JournalCommitIntentDurably,
    /// Journal the completed terminal state.
    JournalCompleted,
    /// Journal the denied terminal state.
    JournalDenied,
    /// Journal the cancelled terminal state.
    JournalCancelled,
    /// Journal the rejected terminal state.
    JournalRejected,
    /// Journal the credential-rejected terminal state.
    JournalCredentialRejected,
    /// Journal the ambiguous terminal state.
    JournalAmbiguous,
    /// Send the result acknowledgment.
    SendResultAck,
}

/// Successful transition and its ordered effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition<S> {
    /// Resulting component state.
    pub state: S,
    /// Ordered effects the adapter must execute.
    pub actions: &'static [Action],
}

/// A guard or machine-domain rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// This endpoint role does not implement the selected transition.
    WrongRole,
    /// A named formal guard failed.
    GuardFailed,
    /// No legal transition exists; authenticated input is a violation unless
    /// separately classified as a stale-reference race.
    UnexpectedInput,
    /// Terminal operation references are stale races, not violations.
    TerminalOperation,
}

const fn require(condition: bool) -> Result<(), TransitionError> {
    if condition {
        Ok(())
    } else {
        Err(TransitionError::GuardFailed)
    }
}

impl PairingState {
    /// Apply one transition from the normative pairing projection.
    ///
    /// # Errors
    /// [`TransitionError`] on a wrong role, a failed guard, or input with no
    /// legal transition.
    #[allow(
        clippy::too_many_lines,
        reason = "the match is one pairing state machine projection and reads best unsplit"
    )]
    #[allow(
        clippy::match_same_arms,
        reason = "arms mirror the normative pairing transition table; distinct transitions stay distinct even when action lists coincide"
    )]
    pub fn transition(
        self,
        role: EndpointRole,
        event: PairingEvent,
        guards: Guards,
    ) -> Result<Transition<Self>, TransitionError> {
        use Action as A;
        use PairingEvent as E;

        let transition = match (self, event) {
            (Self::Unpaired, E::CreateOffer) => {
                require(role == EndpointRole::Requester && guards.user_initiated)?;
                Transition {
                    state: Self::OfferActive,
                    actions: &[
                        A::GenerateOfferId,
                        A::GeneratePairingSecret,
                        A::StartOfferExpiry,
                        A::DisplayPairingCode,
                    ],
                }
            }
            (Self::Unpaired, E::OfferScanned) => {
                require(role == EndpointRole::Proxy && guards.offer_valid_and_supported)?;
                Transition {
                    state: Self::Handshaking,
                    actions: &[
                        A::SelectOneCandidate,
                        A::ConnectCandidate,
                        A::PreparePairingResponder,
                    ],
                }
            }
            (Self::OfferActive, E::CandidateConnected) => {
                require(role == EndpointRole::Requester && guards.offer_live)?;
                Transition {
                    state: Self::Handshaking,
                    actions: &[A::BeginPairingHandshakeInitiator],
                }
            }
            (Self::OfferActive, E::OfferExpiredOrCancelled) => {
                require(role == EndpointRole::Requester)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[
                        A::DestroyPairingSecret,
                        A::InvalidateOffer,
                        A::HidePairingCode,
                    ],
                }
            }
            (Self::Handshaking, E::OfferExpiredOrCancelled) => {
                require(role == EndpointRole::Requester)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[
                        A::DestroyPairingSecret,
                        A::InvalidateOffer,
                        A::CloseCandidate,
                    ],
                }
            }
            (Self::Handshaking, E::HandshakeAuthenticated) => {
                require(guards.transcript_matches)?;
                Transition {
                    state: Self::Confirming,
                    actions: &[
                        A::DeriveChannelIdentifiers,
                        A::DestroyPairingSecret,
                        A::StopAcceptingCandidates,
                        A::HidePairingCode,
                        A::SendPairingHello,
                        A::ShowPeerAndRequestedGrants,
                    ],
                }
            }
            (Self::Handshaking, E::HandshakeFailed) if role == EndpointRole::Requester => {
                Transition {
                    state: Self::OfferActive,
                    actions: &[A::DiscardCandidate, A::RetainOffer],
                }
            }
            (Self::Handshaking, E::HandshakeFailed) if role == EndpointRole::Proxy => Transition {
                state: Self::Unpaired,
                actions: &[A::DiscardCandidate],
            },
            (Self::Confirming, E::BothUsersConfirmed) => {
                require(guards.granted_sets_equal)?;
                Transition {
                    state: Self::PairedDisconnected,
                    actions: &[
                        A::StorePairRecordAtomically,
                        A::InvalidateOffer,
                        A::ClosePairingChannel,
                    ],
                }
            }
            (Self::Confirming, E::DeniedAbortedOrTimedOut) => Transition {
                state: Self::Unpaired,
                actions: &[
                    A::SendPairingAbortBestEffort,
                    A::DestroyCandidateKeys,
                    A::InvalidateOffer,
                    A::CloseCandidate,
                ],
            },
            (Self::PairedDisconnected, E::SessionHealthy) => Transition {
                state: Self::PairedConnected,
                actions: &[A::ShowConnected],
            },
            (Self::PairedConnected, E::SessionClosed) => Transition {
                state: Self::PairedDisconnected,
                actions: &[A::ShowPairedDisconnected],
            },
            (Self::PairedDisconnected, E::ForgetPairing) => {
                require(guards.user_initiated)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[
                        A::DestroyPairKeys,
                        A::DestroyRelayTokens,
                        A::ClearPairMetadata,
                    ],
                }
            }
            (Self::PairedConnected, E::ForgetPairing) => {
                require(guards.user_initiated)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[
                        A::CloseSession,
                        A::DestroyPairKeys,
                        A::DestroyRelayTokens,
                        A::ClearPairMetadata,
                    ],
                }
            }
            (Self::PairedConnected, E::AuthenticatedProtocolViolation) => Transition {
                state: Self::Revoked,
                actions: &[
                    A::SendCloseBestEffort(CloseReason::ProtocolViolation),
                    A::CloseSession,
                    A::DestroyPairKeys,
                    A::ShowRevoked,
                ],
            },
            (Self::PairedConnected, E::LocalRevoke) => {
                require(guards.user_initiated)?;
                Transition {
                    state: Self::Revoked,
                    actions: &[
                        A::SendCloseBestEffort(CloseReason::PairingRevoked),
                        A::CloseSession,
                        A::DestroyPairKeys,
                        A::ShowRevoked,
                    ],
                }
            }
            (Self::PairedDisconnected, E::LocalRevoke) => {
                require(guards.user_initiated)?;
                Transition {
                    state: Self::Revoked,
                    actions: &[A::DestroyPairKeys, A::ShowRevoked],
                }
            }
            (Self::PairedConnected, E::PeerRevocationNotice) => Transition {
                state: Self::Revoked,
                actions: &[
                    A::RecordPeerInitiated,
                    A::CloseSession,
                    A::DestroyPairKeys,
                    A::ShowRevoked,
                ],
            },
            (Self::Revoked, E::ForgetPairing) => {
                require(guards.user_initiated)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[A::ClearResidualPairRecord],
                }
            }
            _ => return Err(TransitionError::UnexpectedInput),
        };
        Ok(transition)
    }
}

impl SessionState {
    /// Apply one transition from the normative session projection.
    ///
    /// # Errors
    /// [`TransitionError`] on a wrong role, a failed guard, or input with no
    /// legal transition.
    #[allow(
        clippy::too_many_lines,
        reason = "the match is one session state machine projection and reads best unsplit"
    )]
    #[allow(
        clippy::match_same_arms,
        reason = "arms mirror the normative session transition table; distinct transitions stay distinct even when action lists coincide"
    )]
    pub fn transition(
        self,
        role: EndpointRole,
        event: SessionEvent,
        guards: Guards,
    ) -> Result<Transition<Self>, TransitionError> {
        use Action as A;
        use SessionEvent as E;

        let transition = match (self, event) {
            (Self::Absent, E::Connect) => {
                require(role == EndpointRole::Requester && guards.initiation_permitted)?;
                Transition {
                    state: Self::Connecting,
                    actions: &[A::SelectOneTransport, A::OpenTransport],
                }
            }
            (Self::Absent, E::TransportAccepted) => {
                require(role == EndpointRole::Proxy && guards.pairing_paired)?;
                Transition {
                    state: Self::Authenticating,
                    actions: &[A::AssociatePairingFromRendezvous, A::BeginKkResponder],
                }
            }
            (Self::Connecting, E::TransportConnected) => {
                require(role == EndpointRole::Requester)?;
                Transition {
                    state: Self::Authenticating,
                    actions: &[A::BeginKkInitiator],
                }
            }
            (Self::Connecting, E::TransportFailed) => {
                require(role == EndpointRole::Requester)?;
                Transition {
                    state: Self::Closed,
                    actions: &[A::DestroySessionMaterial, A::ShowConnectionStopped],
                }
            }
            (Self::Connecting, E::UserDisconnect) => {
                require(role == EndpointRole::Requester)?;
                Transition {
                    state: Self::Closed,
                    actions: &[
                        A::AbortCandidate,
                        A::DestroySessionMaterial,
                        A::ShowConnectionStopped,
                    ],
                }
            }
            (Self::Authenticating, E::HandshakeComplete) => Transition {
                state: Self::Authenticating,
                actions: &[A::DeriveSessionIdentifiers, A::SendSessionReady],
            },
            (Self::Authenticating, E::SecondSessionDetected) => {
                require(role == EndpointRole::Proxy && guards.another_session_live)?;
                Transition {
                    state: Self::Closed,
                    actions: &[
                        A::SendErrorBusy,
                        A::DestroySessionMaterial,
                        A::CloseCandidate,
                    ],
                }
            }
            (Self::Authenticating, E::ReadyVerified) => {
                require(guards.ready_parameters_match)?;
                Transition {
                    state: Self::Healthy,
                    actions: &[A::StartAuthenticatedLiveness, A::ShowConnected],
                }
            }
            (Self::Authenticating, E::CandidateFailure) => Transition {
                state: Self::Closed,
                actions: &[
                    A::DestroySessionMaterial,
                    A::CloseCandidate,
                    A::CountCandidateFailureHint,
                    A::ShowConnectionStopped,
                ],
            },
            (Self::Authenticating, E::TransportFailed) => Transition {
                state: Self::Closed,
                actions: &[A::DestroySessionMaterial, A::ShowConnectionStopped],
            },
            (Self::Authenticating, E::BusyReceived) => {
                require(role == EndpointRole::Requester)?;
                Transition {
                    state: Self::Closed,
                    actions: &[
                        A::DestroySessionMaterial,
                        A::CloseCandidate,
                        A::ShowConnectionStopped,
                    ],
                }
            }
            (Self::Authenticating, E::PeerCloseReceived) => Transition {
                state: Self::Closed,
                actions: &[
                    A::RecordPeerCloseReason,
                    A::DestroySessionMaterial,
                    A::CloseCandidate,
                    A::ShowConnectionStopped,
                ],
            },
            (Self::Authenticating, E::AuthenticatedProtocolViolation) => Transition {
                state: Self::Closing,
                actions: &[
                    A::SendCloseBestEffort(CloseReason::ProtocolViolation),
                    A::ShowDisconnecting,
                ],
            },
            (Self::Healthy, E::LivenessMissed) => Transition {
                state: Self::Checking,
                actions: &[
                    A::BlockNewOperations,
                    A::StartBackoffAndDeadline,
                    A::ShowChecking,
                ],
            },
            (Self::Checking, E::LivenessRestored) => {
                require(guards.deadline_not_expired)?;
                Transition {
                    state: Self::Healthy,
                    actions: &[A::ResetBackoff, A::ShowConnected],
                }
            }
            (Self::Checking, E::LivenessDeadlineExpired) => Transition {
                state: Self::Closing,
                actions: &[A::ShowDisconnecting],
            },
            (Self::Healthy | Self::Checking, E::UserDisconnect | E::LocalCloseRequested) => {
                Transition {
                    state: Self::Closing,
                    actions: &[
                        A::SendCloseBestEffort(CloseReason::UserDisconnect),
                        A::ShowDisconnecting,
                    ],
                }
            }
            (Self::Healthy | Self::Checking, E::PeerCloseReceived) => Transition {
                state: Self::Closing,
                actions: &[A::RecordPeerCloseReason, A::ShowDisconnecting],
            },
            (Self::Closing, E::PeerCloseReceived) => Transition {
                state: Self::Closing,
                actions: &[],
            },
            (Self::Healthy | Self::Checking, E::CredentialRejected) => {
                require(role == EndpointRole::Proxy)?;
                Transition {
                    state: Self::Closing,
                    actions: &[
                        A::DestroyPairKeys,
                        A::ShowRevoked,
                        A::SendCloseBestEffort(CloseReason::CredentialRejected),
                        A::ShowDisconnecting,
                    ],
                }
            }
            (Self::Healthy | Self::Checking, E::CardCompletionAmbiguous) => {
                require(role == EndpointRole::Proxy)?;
                Transition {
                    state: Self::Closing,
                    actions: &[A::ShowDisconnecting],
                }
            }
            (
                Self::Healthy | Self::Checking,
                E::TransportFailed | E::SessionIntegrityFailed | E::LocalSecurityShutdown,
            ) => Transition {
                state: Self::Closing,
                actions: &[A::NoteCloseNoticeImpossible, A::ShowDisconnecting],
            },
            (Self::Healthy | Self::Checking, E::AuthenticatedProtocolViolation) => Transition {
                state: Self::Closing,
                actions: &[
                    A::SendCloseBestEffort(CloseReason::ProtocolViolation),
                    A::ShowDisconnecting,
                ],
            },
            (Self::Healthy | Self::Checking, E::CloseRequestedByPairing) => Transition {
                state: Self::Closing,
                actions: &[A::ShowDisconnecting],
            },
            (Self::Connecting | Self::Authenticating, E::CloseRequestedByPairing) => Transition {
                state: Self::Closed,
                actions: &[
                    A::DestroySessionMaterial,
                    A::CloseCandidate,
                    A::ShowConnectionStopped,
                ],
            },
            (Self::Connecting | Self::Authenticating, E::LocalSecurityShutdown) => Transition {
                state: Self::Closed,
                actions: &[A::DestroySessionMaterial, A::ShowConnectionStopped],
            },
            (Self::Closing, E::TransportFailed) => Transition {
                state: Self::Closing,
                actions: &[A::ProceedWithoutCloseNotice],
            },
            (Self::Closing, E::CloseCompleteOrDeadline) => Transition {
                state: Self::Closed,
                actions: &[
                    A::DestroySessionMaterial,
                    A::DestroyCredentialBuffers,
                    A::PersistTerminalSessionRecord,
                    A::ShowConnectionStopped,
                ],
            },
            _ => return Err(TransitionError::UnexpectedInput),
        };
        Ok(transition)
    }
}

impl OperationState {
    /// Apply one transition from the normative operation projection.
    ///
    /// # Errors
    /// [`TransitionError`] on a terminal operation, a failed guard, or input
    /// with no legal transition.
    #[allow(
        clippy::too_many_lines,
        reason = "the match is one operation state machine projection and reads best unsplit"
    )]
    #[allow(
        clippy::match_same_arms,
        reason = "arms mirror the normative operation transition table; distinct transitions stay distinct even when action lists coincide"
    )]
    pub fn transition(
        self,
        role: EndpointRole,
        event: OperationEvent,
        guards: Guards,
    ) -> Result<Transition<Self>, TransitionError> {
        use Action as A;
        use OperationEvent as E;

        if self.is_terminal() {
            return Err(TransitionError::TerminalOperation);
        }

        let transition = match (self, event, role) {
            (Self::None, E::RequestSent, EndpointRole::Requester) => {
                require(guards.admission_permitted)?;
                Transition {
                    state: Self::Requested,
                    actions: &[
                        A::ComputeRequestHash,
                        A::JournalRequest,
                        A::StartExpiryClock,
                    ],
                }
            }
            (Self::None, E::RequestReceived, EndpointRole::Proxy) => {
                require(guards.admission_permitted)?;
                Transition {
                    state: Self::Requested,
                    actions: &[A::ValidateSchemaHashExpiryAndContext, A::StartExpiryClock],
                }
            }
            (Self::Requested, E::RequestValid, EndpointRole::Proxy) => Transition {
                state: Self::AwaitingConsent,
                actions: &[A::BeginSafePrerequisiteReads, A::PresentConsentPerProfile],
            },
            (Self::Requested, E::RequestInvalidOrUnsupported, EndpointRole::Proxy) => Transition {
                state: Self::Rejected,
                actions: &[A::SendResultRejected],
            },
            (
                Self::Requested | Self::AwaitingConsent,
                E::CancelReceived | E::RequestExpired,
                EndpointRole::Proxy,
            ) => Transition {
                state: Self::Cancelled,
                actions: &[
                    A::ClearOperationCredentials,
                    A::DismissConsent,
                    A::SendResultCancelled,
                ],
            },
            (Self::AwaitingConsent, E::UserDenied, EndpointRole::Proxy) => Transition {
                state: Self::Denied,
                actions: &[A::ClearOperationCredentials, A::SendResultDenied],
            },
            (Self::AwaitingConsent, E::RetryPolicyRefused, EndpointRole::Proxy) => Transition {
                state: Self::Rejected,
                actions: &[
                    A::ClearOperationCredentials,
                    A::SendResultRetryPolicyRefused,
                    A::RequestSessionClose,
                ],
            },
            (
                Self::AwaitingConsent | Self::Executing,
                E::InvalidCanOrPin1OrPin2,
                EndpointRole::Proxy,
            ) => Transition {
                state: Self::CredentialRejected,
                actions: &[
                    A::ClearAllActiveCredentials,
                    A::RemoveRejectedCredentialAndDerivedState,
                    A::SendResultCredentialRejectedBestEffort,
                    A::RevokePairAfterCredentialRejection,
                    A::RequestSessionCloseCredentialRejected,
                ],
            },
            (Self::AwaitingConsent, E::SafeReadsComplete, EndpointRole::Proxy) => {
                require(guards.profile_has_no_consequential_command)?;
                Transition {
                    state: Self::ResultPending,
                    actions: &[A::PersistResult, A::SendResultCompleted],
                }
            }
            (Self::AwaitingConsent, E::UserApprovedAndProxyReady, EndpointRole::Proxy) => {
                require(guards.zero_transmissions)?;
                Transition {
                    state: Self::Prepared,
                    actions: &[A::SendPrepared],
                }
            }
            (Self::Prepared, E::CancelReceived | E::RequestExpired, EndpointRole::Proxy) => {
                Transition {
                    state: Self::Cancelled,
                    actions: &[A::ClearOperationCredentials, A::SendResultCancelled],
                }
            }
            (Self::Prepared, E::ValidCommit, EndpointRole::Proxy) => {
                require(guards.hash_matches)?;
                Transition {
                    state: Self::Committed,
                    actions: &[A::DurablyWriteCommitBeforeTransmission],
                }
            }
            (Self::Committed, E::BeginCardCommand, EndpointRole::Proxy) => {
                require(guards.zero_transmissions)?;
                Transition {
                    state: Self::Executing,
                    actions: &[
                        A::ConsumeNonClonableCommand,
                        A::IncrementTransmissionCountOnce,
                    ],
                }
            }
            (Self::Committed, E::CancelReceived, EndpointRole::Proxy) => {
                require(guards.proven_no_transmission)?;
                Transition {
                    state: Self::Cancelled,
                    actions: &[
                        A::PersistCancelled,
                        A::ClearOperationCredentials,
                        A::SendResultCancelled,
                    ],
                }
            }
            (Self::Committed | Self::Executing, E::CrashRecoveredWithoutTerminalResult, _) => {
                Transition {
                    state: Self::Ambiguous,
                    actions: &[A::PersistAmbiguous, A::ProhibitRetry],
                }
            }
            (Self::Executing, E::CardSuccess, EndpointRole::Proxy) => Transition {
                state: Self::ResultPending,
                actions: &[
                    A::PersistResult,
                    A::ClearOperationCredentials,
                    A::SendResultCompleted,
                ],
            },
            (Self::Executing, E::CardPolicyRejection, EndpointRole::Proxy) => Transition {
                state: Self::Rejected,
                actions: &[
                    A::ClearOperationCredentials,
                    A::PersistRejection,
                    A::SendResultRejected,
                ],
            },
            (Self::Executing, E::CardRemovedBeforeTransmit, EndpointRole::Proxy) => {
                require(guards.proven_no_transmission)?;
                Transition {
                    state: Self::Cancelled,
                    actions: &[
                        A::PersistCancelled,
                        A::ClearOperationCredentials,
                        A::SendResultCancelled,
                    ],
                }
            }
            (Self::Executing, E::CardRemovedOrTransportUncertain, EndpointRole::Proxy) => {
                Transition {
                    state: Self::Ambiguous,
                    actions: &[
                        A::ClearOperationCredentials,
                        A::PersistAmbiguous,
                        A::ProhibitRetry,
                        A::SendResultAmbiguousBestEffort,
                        A::RequestSessionCloseAmbiguous,
                    ],
                }
            }
            (Self::Executing, E::CancelReceived, EndpointRole::Proxy) => Transition {
                state: Self::Executing,
                actions: &[A::RecordAdvisoryCancel],
            },
            (Self::Executing, E::SessionClosedPostCommit, EndpointRole::Proxy) => Transition {
                state: Self::Executing,
                actions: &[
                    A::ContinueCardExchangeLocally,
                    A::NoteResultDeliveryImpossible,
                ],
            },
            (Self::ResultPending, E::ValidResultAck, EndpointRole::Proxy) => Transition {
                state: Self::Completed,
                actions: &[A::PersistCompleted, A::ReleaseResult],
            },
            (Self::ResultPending, E::SessionClosedBeforeAck, EndpointRole::Proxy) => Transition {
                state: Self::DeliveryUncertain,
                actions: &[
                    A::PersistDeliveryUncertain,
                    A::ProhibitCardRetry,
                    A::RetainResultUnderLocalStorage,
                ],
            },
            (Self::Committed, E::SessionClosedPostCommit, EndpointRole::Proxy) => Transition {
                state: Self::Cancelled,
                actions: &[A::PersistCancelled, A::ClearOperationCredentials],
            },
            (Self::Requested, E::PreparedReceived, EndpointRole::Requester) => {
                require(guards.hash_echo_matches)?;
                Transition {
                    state: Self::Prepared,
                    actions: &[A::JournalPrepared],
                }
            }
            (
                Self::Requested | Self::Prepared,
                E::CancelSentOrRequestExpired,
                EndpointRole::Requester,
            ) => Transition {
                state: Self::Cancelled,
                actions: &[A::SendOperationCancel, A::JournalCancelled],
            },
            (Self::Prepared, E::CommitSent, EndpointRole::Requester) => Transition {
                state: Self::Committed,
                actions: &[A::JournalCommitIntentDurably],
            },
            (Self::Requested, E::ResultCompletedReceived, EndpointRole::Requester) => {
                require(guards.profile_has_no_consequential_command)?;
                Transition {
                    state: Self::Completed,
                    actions: &[A::SendResultAck, A::JournalCompleted],
                }
            }
            (
                Self::Requested | Self::Prepared,
                E::ResultDeniedReceived,
                EndpointRole::Requester,
            ) => Transition {
                state: Self::Denied,
                actions: &[A::JournalDenied],
            },
            (
                Self::Requested | Self::Prepared | Self::Committed,
                E::ResultCancelledReceived,
                EndpointRole::Requester,
            ) => Transition {
                state: Self::Cancelled,
                actions: &[A::JournalCancelled],
            },
            (
                Self::Requested | Self::Prepared | Self::Committed,
                E::ResultRejectedReceived,
                EndpointRole::Requester,
            ) => Transition {
                state: Self::Rejected,
                actions: &[A::JournalRejected],
            },
            (
                Self::Requested | Self::Prepared | Self::Committed,
                E::ResultCredentialRejectedReceived,
                EndpointRole::Requester,
            ) => Transition {
                state: Self::CredentialRejected,
                actions: &[
                    A::JournalCredentialRejected,
                    A::RevokePairAfterCredentialRejection,
                ],
            },
            (Self::Committed, E::ResultCompletedReceived, EndpointRole::Requester) => Transition {
                state: Self::Completed,
                actions: &[A::SendResultAck, A::JournalCompleted],
            },
            (
                Self::Committed,
                E::ResultAmbiguousReceived | E::SessionClosedPostCommit,
                EndpointRole::Requester,
            ) => Transition {
                state: Self::Ambiguous,
                actions: &[A::JournalAmbiguous, A::ProhibitRetry],
            },
            (
                Self::Requested | Self::AwaitingConsent | Self::Prepared,
                E::SessionClosedPreCommit,
                _,
            ) => Transition {
                state: Self::Cancelled,
                actions: &[A::ClearOperationCredentials, A::PersistCancelled],
            },
            _ => return Err(TransitionError::UnexpectedInput),
        };
        Ok(transition)
    }
}

/// Product state coordinating pairing, session, and one active operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RappState {
    /// Local endpoint projection.
    pub role: EndpointRole,
    /// Pairing component.
    pub pairing: PairingState,
    /// Session component.
    pub session: SessionState,
    /// Active operation component.
    pub operation: OperationState,
    /// Credential rejection requires a new explicit user action.
    pub requires_user_intent: bool,
}

/// Security-event result spanning multiple component machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityOutcome {
    /// Ordered security effects the adapter must execute.
    pub actions: Vec<Action>,
}

impl RappState {
    /// Construct an endpoint without a pairing.
    #[must_use]
    pub const fn unpaired(role: EndpointRole) -> Self {
        Self {
            role,
            pairing: PairingState::Unpaired,
            session: SessionState::Absent,
            operation: OperationState::None,
            requires_user_intent: false,
        }
    }

    /// Check the global operation-admission invariant.
    #[must_use]
    pub const fn operation_admission_permitted(&self) -> bool {
        matches!(self.pairing, PairingState::PairedConnected)
            && matches!(self.session, SessionState::Healthy)
            && matches!(self.operation, OperationState::None)
    }

    /// Apply an authenticated protocol violation.
    ///
    /// The first attributable violation revokes a stored pairing. Before a
    /// pairing is stored it aborts only that pairing attempt.
    pub fn authenticated_protocol_violation(&mut self) -> SecurityOutcome {
        let mut actions = Vec::new();
        match self.pairing {
            PairingState::PairedConnected | PairingState::PairedDisconnected => {
                if !matches!(self.session, SessionState::Absent | SessionState::Closed) {
                    actions.push(Action::SendCloseBestEffort(CloseReason::ProtocolViolation));
                    actions.push(Action::CloseSession);
                    self.classify_operation_for_close(&mut actions);
                    self.session = SessionState::Closing;
                }
                self.pairing = PairingState::Revoked;
                actions.push(Action::DestroyPairKeys);
                actions.push(Action::ShowRevoked);
            }
            PairingState::Handshaking | PairingState::Confirming | PairingState::OfferActive => {
                self.pairing = PairingState::Unpaired;
                self.session = SessionState::Closed;
                actions.extend([
                    Action::SendPairingAbortBestEffort,
                    Action::DestroyPairingSecret,
                    Action::DestroyCandidateKeys,
                    Action::DiscardCandidate,
                ]);
            }
            PairingState::Unpaired | PairingState::Revoked => {}
        }
        SecurityOutcome { actions }
    }

    /// Apply an established-channel integrity failure.
    ///
    /// This event is not attributable to the authenticated peer, so it closes
    /// only the session and never revokes the pairing.
    pub fn session_integrity_failed(&mut self) -> SecurityOutcome {
        let mut actions = Vec::new();
        if matches!(self.session, SessionState::Healthy | SessionState::Checking) {
            self.classify_operation_for_close(&mut actions);
            self.session = SessionState::Closing;
            actions.push(Action::ShowDisconnecting);
        }
        SecurityOutcome { actions }
    }

    /// An unanswered authenticated liveness probe blocks new operations while
    /// preserving the pairing and current session keys.
    pub fn liveness_missed(&mut self) -> SecurityOutcome {
        let mut actions = Vec::new();
        if self.session == SessionState::Healthy {
            self.session = SessionState::Checking;
            actions.extend([
                Action::BlockNewOperations,
                Action::StartBackoffAndDeadline,
                Action::ShowChecking,
            ]);
        }
        SecurityOutcome { actions }
    }

    /// Exact authenticated pong restores operation admission.
    pub fn liveness_restored(&mut self) -> SecurityOutcome {
        let mut actions = Vec::new();
        if self.session == SessionState::Checking {
            self.session = SessionState::Healthy;
            actions.extend([Action::ResetBackoff, Action::ShowConnected]);
        }
        SecurityOutcome { actions }
    }

    /// Apply invalid CAN, PIN 1, or PIN 2 handling across the product state.
    pub fn credential_rejected(&mut self) -> SecurityOutcome {
        let mut actions = vec![
            Action::ClearAllActiveCredentials,
            Action::RemoveRejectedCredentialAndDerivedState,
            Action::SendResultCredentialRejectedBestEffort,
            Action::RevokePairAfterCredentialRejection,
            Action::DestroyPairKeys,
            Action::ShowRevoked,
        ];
        self.pairing = PairingState::Revoked;
        self.operation = OperationState::CredentialRejected;
        self.requires_user_intent = false;
        if matches!(self.session, SessionState::Healthy | SessionState::Checking) {
            self.session = SessionState::Closing;
            actions.extend([
                Action::SendCloseBestEffort(CloseReason::CredentialRejected),
                Action::ShowDisconnecting,
            ]);
        }
        SecurityOutcome { actions }
    }

    fn classify_operation_for_close(&mut self, actions: &mut Vec<Action>) {
        match self.operation {
            OperationState::Requested
            | OperationState::AwaitingConsent
            | OperationState::Prepared => {
                self.operation = OperationState::Cancelled;
                actions.extend([Action::ClearOperationCredentials, Action::PersistCancelled]);
            }
            OperationState::Committed if self.role == EndpointRole::Requester => {
                self.operation = OperationState::Ambiguous;
                actions.extend([Action::PersistAmbiguous, Action::ProhibitRetry]);
            }
            OperationState::Committed => {
                self.operation = OperationState::Cancelled;
                actions.extend([Action::PersistCancelled, Action::ClearOperationCredentials]);
            }
            OperationState::Executing => {
                actions.extend([
                    Action::ContinueCardExchangeLocally,
                    Action::NoteResultDeliveryImpossible,
                ]);
            }
            OperationState::ResultPending => {
                self.operation = OperationState::DeliveryUncertain;
                actions.extend([
                    Action::PersistDeliveryUncertain,
                    Action::ProhibitRetry,
                    Action::RetainResultUnderLocalStorage,
                ]);
            }
            OperationState::None
            | OperationState::Completed
            | OperationState::Denied
            | OperationState::Cancelled
            | OperationState::Rejected
            | OperationState::CredentialRejected
            | OperationState::Ambiguous
            | OperationState::DeliveryUncertain => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EndpointRole, OperationState, PairingState, RappState, SessionState};

    #[test]
    fn first_authenticated_violation_revokes_pairing() {
        let mut state = RappState {
            role: EndpointRole::Requester,
            pairing: PairingState::PairedConnected,
            session: SessionState::Healthy,
            operation: OperationState::None,
            requires_user_intent: false,
        };

        let outcome = state.authenticated_protocol_violation();

        assert_eq!(state.pairing, PairingState::Revoked);
        assert_eq!(state.session, SessionState::Closing);
        assert!(outcome.actions.contains(&super::Action::DestroyPairKeys));
    }

    #[test]
    fn integrity_failure_never_revokes_pairing() {
        let mut state = RappState {
            role: EndpointRole::Proxy,
            pairing: PairingState::PairedConnected,
            session: SessionState::Healthy,
            operation: OperationState::None,
            requires_user_intent: false,
        };

        state.session_integrity_failed();

        assert_eq!(state.pairing, PairingState::PairedConnected);
        assert_eq!(state.session, SessionState::Closing);
    }

    #[test]
    fn credential_rejection_revokes_pairing_on_the_first_incident() {
        let mut state = RappState {
            role: EndpointRole::Proxy,
            pairing: PairingState::PairedConnected,
            session: SessionState::Healthy,
            operation: OperationState::Executing,
            requires_user_intent: false,
        };

        let outcome = state.credential_rejected();

        assert_eq!(state.pairing, PairingState::Revoked);
        assert_eq!(state.session, SessionState::Closing);
        assert_eq!(state.operation, OperationState::CredentialRejected);
        assert!(!state.requires_user_intent);
        assert!(outcome.actions.contains(&super::Action::DestroyPairKeys));
        assert!(outcome.actions.contains(&super::Action::ShowRevoked));
    }
}
