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

//! The pairing, session and operation machines of the RAPP state model
//! (`doc/protocols/rapp-state-machine-v26.10.22.yaml`), and the runtime state
//! an endpoint keeps. No failure revokes a pairing; a user does, idle expiry
//! does, and the peer's revocation notice does.

/// Local projection of the distributed state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    /// The computer asking for a credential operation.
    Requester,
    /// The custodian: the phone holding the card.
    Proxy,
}

/// Runtime facts the formal transition guards name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each field is an independent guard fact from the formal model, not a state encoding"
)]
pub struct Guards {
    /// An explicit local user action started this event.
    pub user_initiated: bool,
    /// The event originates from the local user, never the peer.
    pub local_user_action: bool,
    /// The completed handshake used the expected prologue and empty handshake payloads.
    pub transcript_matches: bool,
    /// Both pairing.confirm granted_profiles sets are equal.
    pub granted_sets_equal: bool,
    /// The requester's remote use is on, no card is in a reader attached to
    /// it, a stored pairing is active, or forgotten and owing its revocation
    /// close, and its custodian's discovery hint is in sight.
    pub initiation_permitted: bool,
    /// The routing tag matched an active stored pairing and its nonce is not in the replay memory.
    pub pairing_routed: bool,
    /// Received session.ready parameters equal the local view.
    pub ready_parameters_match: bool,
    /// The requester's remote use is on, no card is in a reader attached to
    /// it, an endpoint found in pairing mode is not yet opened for the typed
    /// code, and fewer than `pairing_candidates_max` pairing connections
    /// were opened for it.
    pub untried_pairing_candidate: bool,
}

/// Pairing component state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    /// No pairing exists.
    Unpaired,
    /// The custodian shows the pairing code and accepts attempts.
    Offering,
    /// A CPace attempt is running.
    Exchanging,
    /// The Noise_XXpsk3 pairing handshake is running.
    Handshaking,
    /// The endpoints exchange pairing.hello and pairing.confirm.
    Confirming,
    /// The record is stored and awaits the peer's pairing.stored.
    StorageConfirming,
    /// The pairing is active and no session is healthy.
    PairedDisconnected,
    /// The pairing is active and a session is healthy.
    PairedConnected,
    /// The record is revoked; its key is kept only to deliver the pairing_revoked close.
    Revoking,
    /// The record is revoked and its key destroyed.
    Revoked,
}

/// Session component state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No session instance exists.
    Absent,
    /// The requester connects to the custodian.
    Connecting,
    /// The Noise_KK handshake and the session.ready echo are running.
    Authenticating,
    /// The session carries operations.
    Healthy,
    /// The session is closing.
    Closing,
    /// The session ended.
    Closed,
}

/// Operation component state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    /// No live operation instance.
    None,
    /// The request is admitted and waits for the card.
    Requested,
    /// Another session's operation holds the card.
    Queued,
    /// The custodian takes the PIN, asking the holder when it does not
    /// hold it.
    AwaitingConsent,
    /// The card is commanded.
    Executing,
    /// The operation completed.
    Completed,
    /// The operation was refused or failed.
    Rejected,
    /// The deadline passed before the card was commanded.
    Cancelled,
}

impl OperationState {
    /// Whether the operation has its result.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Rejected | Self::Cancelled)
    }
}

/// Pairing-machine input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingEvent {
    /// The holder starts a pairing on the custodian.
    StartPairing,
    /// The offer lived out its lifetime or was cancelled.
    OfferExpiredOrCancelled,
    /// A requester began a CPace attempt.
    AttemptStarted,
    /// The user typed the pairing code on the requester.
    CodeEntered,
    /// A CPace attempt failed to confirm the key. On the requester: the
    /// endpoint opened did not take the code, because its custodian refused
    /// it or it served no offer the requester could try.
    AttemptFailed,
    /// The offer's last CPace attempt failed.
    LastAttemptFailed,
    /// Every custodian the requester tried refused the code, and no endpoint
    /// is left to open.
    LastCandidateFailed,
    /// No endpoint served an offer the requester could try, and its search
    /// ended.
    NoCustodianTried,
    /// Remote use stopped being available during the requester's search: a
    /// card in a reader attached to it, or the holder turned remote use off.
    /// The search ends; the code entry is offered again once remote use
    /// resumes.
    SearchInterrupted,
    /// Both CPace confirmation tags verified.
    KeyConfirmed,
    /// The pairing handshake completed.
    HandshakeAuthenticated,
    /// The pairing handshake failed.
    HandshakeFailed,
    /// The custodian verified pairing.hello against its offer.
    HelloVerified,
    /// Both pairing.confirm messages arrived.
    BothConfirmed,
    /// The pairing was aborted, denied, or missed its deadline.
    DeniedAbortedOrTimedOut,
    /// The peer's pairing.stored arrived.
    PeerStorageConfirmed,
    /// A session of the pairing became healthy.
    SessionHealthy,
    /// The session closed.
    SessionClosed,
    /// The local user forgot the pairing; on a requester, by turning remote
    /// use off, which forgets every pairing it holds and, with no session
    /// open, owes the custodian nothing (section 4.6 item 6).
    ForgetPairing,
    /// The idle-expiry sweep, with a session to the pairing established or
    /// with none and the pairing short of the idle limit (section 4.6 item
    /// 5).
    ExpiryCheck,
    /// The idle-expiry sweep found no session established and the pairing
    /// `pairing_idle_expiry_days` of wall-clock time past its latest
    /// recorded session, or its creation (section 4.6 item 5).
    IdleExpired,
    /// The revocation close went out as a session's first message.
    RevocationNoticeSent,
    /// The revocation notice window passed.
    NoticeWindowExpired,
    /// A session.close with reason pairing_revoked arrived.
    PeerRevocationNotice,
    /// The requester closed the session with reason service_withdrawn: the
    /// computer withdrew (section 4.5 item 9).
    PeerWithdrawalNotice,
}

/// Session-machine input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The requester dials the custodian.
    Connect,
    /// The custodian received a session routing preamble.
    PreambleReceived,
    /// The requester's connection is up.
    TransportConnected,
    /// The connection was lost or could not be made.
    TransportFailed,
    /// The Noise_KK handshake completed.
    HandshakeComplete,
    /// The Noise_KK handshake completed for a pairing this endpoint is
    /// revoking.
    HandshakeCompleteWhileRevoking,
    /// The requester verified session.ready.
    ReadyVerified,
    /// Input before authentication was invalid.
    CandidateFailure,
    /// An authenticated message violated the protocol.
    AuthenticatedProtocolViolation,
    /// Nothing arrived for the liveness ping interval.
    PeerSilent,
    /// Nothing arrived for the session silence limit.
    SilenceLimitReached,
    /// The local user disconnected.
    UserDisconnect,
    /// The endpoint closes the session in order.
    LocalCloseRequested,
    /// The endpoint withdraws (section 4.5): a custodian's user turned
    /// remote access off, a card in a reader attached to a requester
    /// suspends its remote use, or the user quit the application.
    ServiceWithdrawn,
    /// The custodian can no longer serve any card.
    CardUnavailable,
    /// An authenticated session.close arrived.
    PeerCloseReceived,
    /// A frame failed authenticated decryption or framing.
    SessionIntegrityFailed,
    /// The pairing machine asked the session to close.
    CloseRequestedByPairing,
    /// The close finished or its deadline passed.
    CloseCompleteOrDeadline,
}

/// Operation-machine input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationEvent {
    /// An admissible operation.request arrived.
    RequestReceived,
    /// A request reused an identifier the session has seen.
    RequestDuplicate,
    /// A request arrived while another operation is live.
    RequestWhileBusy,
    /// A request named a profile the pairing does not grant.
    RequestUnauthorized,
    /// A request named a lifetime or parameter the custodian cannot serve.
    RequestUnsupported,
    /// Another session's operation holds the card.
    CardHeldElsewhere,
    /// The card is free for an operation that needs consent.
    CardAcquiredForConsent,
    /// The card is free for a read.
    CardAcquiredForRead,
    /// The holder declined.
    UserDenied,
    /// The holder approved.
    UserApproved,
    /// The custodian waits for the holder to present the card.
    WaitingForCard,
    /// The card was found.
    CardFound,
    /// The card refused the PIN and attempts remain above the floor.
    WrongPin,
    /// The retry floor refused the PIN verification.
    RetryFloorRefused,
    /// The card answered.
    CardSuccess,
    /// The card did not answer.
    CardError,
    /// The deadline passed before the card was commanded.
    RequestExpired,
    /// The session closed.
    SessionClosed,
    /// The requester sent the request.
    RequestSent,
    /// An operation.progress arrived.
    ProgressReceived,
    /// A completed operation.result arrived.
    ResultCompletedReceived,
    /// A rejected operation.result, or an error busy or duplicate_operation, arrived.
    ResultRejectedReceived,
    /// A cancelled operation.result arrived.
    ResultCancelledReceived,
}

/// Effect a transition asks the endpoint to carry out, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Create the offer with a fresh random offer_id and offer_ttl_ms.
    GenerateOffer,
    /// Draw the 6-character pairing code.
    GeneratePairingCode,
    /// Publish the mode=pairing record.
    AdvertisePairingMode,
    /// Show the pairing code on the custodian.
    DisplayPairingCode,
    /// Remove the pairing code from the screen.
    HidePairingCode,
    /// Erase the offer and its pairing code and stop advertising it.
    DestroyOffer,
    /// Stop offering and back off exponentially before the next offer.
    StartPairingBackoff,
    /// Tell the holder that the offer used its attempts.
    ShowAttemptsExhausted,
    /// Obtain the offer over the pairing connection and validate it.
    ReadOffer,
    /// Send CPace step 1 from the typed pairing code.
    BeginCpaceInitiator,
    /// Open a pairing connection to the next endpoint found in pairing mode
    /// and not yet opened for the typed code.
    TryNextCandidate,
    /// Count the attempt before sending CPace step 2 and arm its deadline.
    ReserveAttempt,
    /// Record the failed attempt; the offer stays.
    CountFailedAttempt,
    /// Tell the user the pairing code was not accepted, naming no custodian.
    ShowWrongCode,
    /// Tell the user that no custodian in pairing mode was found.
    ShowNoneInPairingMode,
    /// Mark the offer consumed once T_A verified.
    ConsumeOffer,
    /// Derive the PSK for the pairing handshake from the CPace key schedule.
    DerivePairingSecret,
    /// Run Noise_XXpsk3 with the PSK.
    BeginPairingHandshake,
    /// Derive session_id and pair_id from the handshake hash.
    DeriveChannelIdentifiers,
    /// Erase the PSK and the CPace intermediate values.
    DestroyPairingSecret,
    /// Send pairing.hello with the negotiated-parameter echo.
    SendPairingHello,
    /// Grant the requested profiles the offer allows and send pairing.confirm.
    SendPairingConfirm,
    /// Send pairing.abort if the channel is usable.
    SendPairingAbortBestEffort,
    /// Erase unstored static and ephemeral keys.
    DestroyCandidateKeys,
    /// Close the candidate connection.
    CloseCandidate,
    /// Store pair keys, pair_id, grants, grants_hash and the unconfirmed mark in one commit.
    StorePairRecordAtomically,
    /// Send pairing.stored carrying the derived pair_id.
    SendPairingStored,
    /// Rewrite the stored record as confirmed.
    MarkRecordConfirmed,
    /// Close the authenticated pairing channel.
    ClosePairingChannel,
    /// Revoke the stored record the peer never confirmed.
    RevokeUnconfirmedPairRecord,
    /// Mark the record revoked; it serves nothing from now on and its key is kept only for the close.
    MarkRecordRevoked,
    /// Send session.close with reason pairing_revoked as the session's first or next message.
    SendClosePairingRevoked,
    /// Raise close_requested_by_pairing for the live session.
    CloseSession,
    /// Erase the pairing's static private key.
    DestroyPairKeys,
    /// Keep the wall-clock time in the record as the latest time the
    /// pairing had an established session.
    RecordLastSession,
    /// Stop offering the pairing's credentials to local consumers.
    WithdrawIdentity,
    /// Show that the paired peer is connected.
    ShowConnected,
    /// Show that the paired peer is not connected.
    ShowPairedDisconnected,
    /// Show that this endpoint forgot the peer.
    ShowForgotten,
    /// Show that the peer forgot this endpoint.
    ShowPeerForgot,
    /// Show the paired computer as off, not merely disconnected, until the
    /// pairing's next session.
    ShowPeerWithdrawn,
    /// Erase the revoked record.
    ClearResidualPairRecord,
    /// Connect to the custodian's advertised endpoint or peripheral.
    OpenTransport,
    /// Send the session routing preamble with a fresh routing tag.
    SendSessionPreamble,
    /// Start the session handshake in the initiator role.
    BeginKkInitiator,
    /// Start the session handshake in the responder role.
    BeginKkResponder,
    /// Derive session_id from the handshake hash.
    DeriveSessionIdentifiers,
    /// Send session.ready with the session-parameter echo.
    SendSessionReady,
    /// Send card.status with presence, reader attachment and the certificate
    /// fingerprint.
    SendCardStatus,
    /// Start the 5-second silence ping and the 30-second silence limit.
    StartLiveness,
    /// Send liveness.ping with a fresh challenge.
    SendLivenessPing,
    /// Keep the received close reason for the user.
    RecordPeerCloseReason,
    /// Send session.close with reason user_disconnect.
    SendCloseUserDisconnect,
    /// Send session.close with reason normal.
    SendCloseNormal,
    /// Send session.close with reason protocol_violation.
    SendCloseProtocolViolation,
    /// Send session.close with reason service_withdrawn.
    SendCloseServiceWithdrawn,
    /// Send session.close with reason card_unavailable.
    SendCloseCardUnavailable,
    /// Record that no close notice can be sent.
    NoteCloseNoticeImpossible,
    /// Continue closing without further sends.
    ProceedWithoutCloseNotice,
    /// Erase session keys, handshake state and buffers.
    DestroySessionMaterial,
    /// Erase credential buffers tied to the session.
    DestroyCredentialBuffers,
    /// Show that the session is closing.
    ShowDisconnecting,
    /// Show that the session ended.
    ShowConnectionStopped,
    /// Take the deadline on the continuous clock.
    StartExpiryClock,
    /// Send error busy naming the operation.
    SendErrorBusy,
    /// Send error duplicate_operation naming the operation.
    SendErrorDuplicateOperation,
    /// Send operation.result rejected with unauthorized.
    SendResultUnauthorized,
    /// Send operation.result rejected with unsupported_parameter or invalid_lifetime.
    SendResultUnsupportedParameter,
    /// Send operation.progress queued, once.
    SendProgressQueued,
    /// Ask the holder for a PIN the custodian does not hold, showing the
    /// admitted request.
    PresentConsent,
    /// Send operation.progress consent_shown once a PIN prompt is on screen.
    SendProgressConsentShown,
    /// Remove the PIN prompt.
    DismissConsent,
    /// Run the read-only card commands.
    ExecuteRead,
    /// Read the remaining attempts of the PIN the command needs.
    CheckRetryFloor,
    /// Consume the one-shot card command.
    ConsumeCardCommand,
    /// Send operation.progress waiting_for_card.
    SendProgressWaitingForCard,
    /// Send operation.progress card_wait_ended.
    SendProgressCardWaitEnded,
    /// Tell the holder the PIN was wrong, with the attempts left, and prompt again.
    PromptPinAgain,
    /// Send operation.result completed with the response.
    SendResultCompleted,
    /// Send operation.result rejected with user_cancelled.
    SendResultUserCancelled,
    /// Send operation.result rejected with retry_floor.
    SendResultRetryFloor,
    /// Send operation.result rejected with card_error.
    SendResultCardError,
    /// Send operation.result cancelled with operation_expired.
    SendResultOperationExpired,
    /// Zeroize credentials collected for the operation.
    ClearOperationCredentials,
    /// Let the card command finish; never interrupt or repeat it.
    ContinueCardExchangeLocally,
    /// Drop the card's answer; no session carries it.
    DiscardAnswer,
    /// Let the next queued operation take the card.
    ReleaseCard,
    /// Show the operation's progress to the user.
    ShowProgress,
    /// Hand the response to the requesting application.
    ReleaseResult,
    /// Tell the requesting application why the operation ended.
    ReleaseFailure,
    /// Tell the requesting application that the operation ended with its session.
    ReportOperationLost,
}

/// Successful transition and its ordered effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition<S> {
    /// Resulting component state.
    pub state: S,
    /// Ordered effects the endpoint carries out.
    pub actions: &'static [Action],
}

/// Why a transition does not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// This endpoint role does not implement the transition.
    WrongRole,
    /// A named guard failed.
    GuardFailed,
    /// No transition exists for this input.
    UnexpectedInput,
    /// The operation already has its result.
    TerminalOperation,
}

const fn require(condition: bool) -> Result<(), TransitionError> {
    if condition {
        Ok(())
    } else {
        Err(TransitionError::GuardFailed)
    }
}

const fn require_role(role: EndpointRole, expected: EndpointRole) -> Result<(), TransitionError> {
    if matches!(
        (role, expected),
        (EndpointRole::Requester, EndpointRole::Requester)
            | (EndpointRole::Proxy, EndpointRole::Proxy)
    ) {
        Ok(())
    } else {
        Err(TransitionError::WrongRole)
    }
}

impl PairingState {
    /// Apply one transition of the pairing machine.
    ///
    /// # Errors
    /// [`TransitionError`] on a wrong role, a failed guard, or input with no
    /// transition.
    #[allow(
        clippy::too_many_lines,
        reason = "the match is the pairing machine's transition table and reads best whole"
    )]
    #[allow(
        clippy::match_same_arms,
        reason = "arms mirror the formal transition table; distinct transitions stay distinct"
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
            (Self::Unpaired, E::StartPairing) => {
                require_role(role, EndpointRole::Proxy)?;
                require(guards.user_initiated)?;
                Transition {
                    state: Self::Offering,
                    actions: &[
                        A::GenerateOffer,
                        A::GeneratePairingCode,
                        A::AdvertisePairingMode,
                        A::DisplayPairingCode,
                    ],
                }
            }
            (Self::Offering, E::OfferExpiredOrCancelled) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[A::DestroyOffer, A::HidePairingCode],
                }
            }
            (Self::Offering, E::AttemptStarted) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Exchanging,
                    actions: &[A::ReserveAttempt],
                }
            }
            (Self::Unpaired, E::CodeEntered) => {
                require_role(role, EndpointRole::Requester)?;
                require(guards.user_initiated)?;
                Transition {
                    state: Self::Exchanging,
                    actions: &[A::ReadOffer, A::BeginCpaceInitiator],
                }
            }
            (Self::Exchanging, E::AttemptFailed) => match role {
                EndpointRole::Proxy => Transition {
                    state: Self::Offering,
                    actions: &[A::CountFailedAttempt],
                },
                EndpointRole::Requester => {
                    require(guards.untried_pairing_candidate)?;
                    Transition {
                        state: Self::Exchanging,
                        actions: &[
                            A::CloseCandidate,
                            A::TryNextCandidate,
                            A::ReadOffer,
                            A::BeginCpaceInitiator,
                        ],
                    }
                }
            },
            (Self::Exchanging, E::LastCandidateFailed) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[A::CloseCandidate, A::ShowWrongCode],
                }
            }
            (Self::Exchanging, E::NoCustodianTried) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[A::CloseCandidate, A::ShowNoneInPairingMode],
                }
            }
            (Self::Exchanging, E::SearchInterrupted) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[A::CloseCandidate],
                }
            }
            (Self::Exchanging, E::LastAttemptFailed) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[
                        A::DestroyOffer,
                        A::HidePairingCode,
                        A::StartPairingBackoff,
                        A::ShowAttemptsExhausted,
                    ],
                }
            }
            (Self::Exchanging, E::OfferExpiredOrCancelled) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Unpaired,
                    actions: &[A::DestroyOffer, A::HidePairingCode, A::CloseCandidate],
                }
            }
            (Self::Exchanging, E::KeyConfirmed) => match role {
                EndpointRole::Proxy => Transition {
                    state: Self::Handshaking,
                    actions: &[
                        A::ConsumeOffer,
                        A::HidePairingCode,
                        A::DerivePairingSecret,
                        A::BeginPairingHandshake,
                    ],
                },
                EndpointRole::Requester => Transition {
                    state: Self::Handshaking,
                    actions: &[A::DerivePairingSecret, A::BeginPairingHandshake],
                },
            },
            (Self::Handshaking, E::HandshakeAuthenticated) => match role {
                EndpointRole::Requester => {
                    require(guards.transcript_matches)?;
                    Transition {
                        state: Self::Confirming,
                        actions: &[
                            A::DeriveChannelIdentifiers,
                            A::DestroyPairingSecret,
                            A::SendPairingHello,
                        ],
                    }
                }
                EndpointRole::Proxy => {
                    require(guards.transcript_matches)?;
                    Transition {
                        state: Self::Confirming,
                        actions: &[A::DeriveChannelIdentifiers, A::DestroyPairingSecret],
                    }
                }
            },
            (Self::Handshaking, E::HandshakeFailed) => Transition {
                state: Self::Unpaired,
                actions: &[
                    A::DestroyPairingSecret,
                    A::DestroyCandidateKeys,
                    A::CloseCandidate,
                ],
            },
            (Self::Confirming, E::HelloVerified) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Confirming,
                    actions: &[A::SendPairingConfirm],
                }
            }
            (Self::Confirming, E::BothConfirmed) => {
                require(guards.granted_sets_equal)?;
                Transition {
                    state: Self::StorageConfirming,
                    actions: &[A::StorePairRecordAtomically, A::SendPairingStored],
                }
            }
            (Self::Confirming, E::DeniedAbortedOrTimedOut) => Transition {
                state: Self::Unpaired,
                actions: &[
                    A::SendPairingAbortBestEffort,
                    A::DestroyCandidateKeys,
                    A::CloseCandidate,
                ],
            },
            (Self::StorageConfirming, E::PeerStorageConfirmed) => Transition {
                state: Self::PairedDisconnected,
                actions: &[A::MarkRecordConfirmed, A::ClosePairingChannel],
            },
            (Self::StorageConfirming, E::DeniedAbortedOrTimedOut) => Transition {
                state: Self::Unpaired,
                actions: &[
                    A::RevokeUnconfirmedPairRecord,
                    A::DestroyPairKeys,
                    A::CloseCandidate,
                ],
            },
            (Self::PairedDisconnected, E::SessionHealthy) => Transition {
                state: Self::PairedConnected,
                actions: &[A::RecordLastSession, A::ShowConnected],
            },
            (Self::PairedConnected, E::SessionClosed) => Transition {
                state: Self::PairedDisconnected,
                actions: &[A::RecordLastSession, A::ShowPairedDisconnected],
            },
            (Self::PairedConnected, E::PeerWithdrawalNotice) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::PairedDisconnected,
                    actions: &[A::RecordLastSession, A::ShowPeerWithdrawn],
                }
            }
            (Self::PairedConnected, E::ForgetPairing) => {
                require(guards.local_user_action)?;
                Transition {
                    state: Self::Revoked,
                    actions: &[
                        A::MarkRecordRevoked,
                        A::SendClosePairingRevoked,
                        A::CloseSession,
                        A::DestroyPairKeys,
                        A::WithdrawIdentity,
                        A::ShowForgotten,
                    ],
                }
            }
            (Self::PairedDisconnected, E::ForgetPairing) => {
                require(guards.local_user_action)?;
                match role {
                    EndpointRole::Proxy => Transition {
                        state: Self::Revoking,
                        actions: &[A::MarkRecordRevoked, A::WithdrawIdentity, A::ShowForgotten],
                    },
                    EndpointRole::Requester => Transition {
                        state: Self::Revoked,
                        actions: &[
                            A::MarkRecordRevoked,
                            A::DestroyPairKeys,
                            A::WithdrawIdentity,
                            A::ShowForgotten,
                        ],
                    },
                }
            }
            (Self::PairedConnected, E::ExpiryCheck) => Transition {
                state: Self::PairedConnected,
                actions: &[A::RecordLastSession],
            },
            (Self::PairedDisconnected, E::ExpiryCheck) => Transition {
                state: Self::PairedDisconnected,
                actions: &[],
            },
            (Self::PairedDisconnected, E::IdleExpired) => Transition {
                state: Self::Revoking,
                actions: &[A::MarkRecordRevoked, A::WithdrawIdentity],
            },
            (Self::Revoking, E::RevocationNoticeSent) => Transition {
                state: Self::Revoked,
                actions: &[A::DestroyPairKeys],
            },
            (Self::Revoking, E::NoticeWindowExpired) => Transition {
                state: Self::Revoked,
                actions: &[A::DestroyPairKeys],
            },
            (Self::PairedDisconnected, E::PeerRevocationNotice) => Transition {
                state: Self::Revoked,
                actions: &[
                    A::MarkRecordRevoked,
                    A::CloseSession,
                    A::DestroyPairKeys,
                    A::WithdrawIdentity,
                    A::ShowPeerForgot,
                ],
            },
            (Self::PairedConnected, E::PeerRevocationNotice) => Transition {
                state: Self::Revoked,
                actions: &[
                    A::MarkRecordRevoked,
                    A::CloseSession,
                    A::DestroyPairKeys,
                    A::WithdrawIdentity,
                    A::ShowPeerForgot,
                ],
            },
            (Self::Revoking, E::PeerRevocationNotice) => Transition {
                state: Self::Revoked,
                actions: &[
                    A::MarkRecordRevoked,
                    A::CloseSession,
                    A::DestroyPairKeys,
                    A::WithdrawIdentity,
                    A::ShowPeerForgot,
                ],
            },
            (Self::Revoked, E::ForgetPairing) => {
                require(guards.local_user_action)?;
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
    /// Apply one transition of the session machine.
    ///
    /// # Errors
    /// [`TransitionError`] on a wrong role, a failed guard, or input with no
    /// transition.
    #[allow(
        clippy::too_many_lines,
        reason = "the match is the session machine's transition table and reads best whole"
    )]
    #[allow(
        clippy::match_same_arms,
        reason = "arms mirror the formal transition table; distinct transitions stay distinct"
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
                require_role(role, EndpointRole::Requester)?;
                require(guards.initiation_permitted)?;
                Transition {
                    state: Self::Connecting,
                    actions: &[A::OpenTransport],
                }
            }
            (Self::Absent, E::PreambleReceived) => {
                require_role(role, EndpointRole::Proxy)?;
                require(guards.pairing_routed)?;
                Transition {
                    state: Self::Authenticating,
                    actions: &[A::BeginKkResponder],
                }
            }
            (Self::Connecting, E::TransportConnected) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Authenticating,
                    actions: &[A::SendSessionPreamble, A::BeginKkInitiator],
                }
            }
            (Self::Connecting, E::TransportFailed) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Closed,
                    actions: &[A::DestroySessionMaterial, A::ShowConnectionStopped],
                }
            }
            (Self::Authenticating, E::HandshakeComplete) => match role {
                EndpointRole::Proxy => Transition {
                    state: Self::Healthy,
                    actions: &[
                        A::DeriveSessionIdentifiers,
                        A::SendSessionReady,
                        A::SendCardStatus,
                        A::StartLiveness,
                    ],
                },
                EndpointRole::Requester => Transition {
                    state: Self::Authenticating,
                    actions: &[A::DeriveSessionIdentifiers],
                },
            },
            (Self::Authenticating, E::HandshakeCompleteWhileRevoking) => Transition {
                state: Self::Closed,
                actions: &[
                    A::DeriveSessionIdentifiers,
                    A::SendClosePairingRevoked,
                    A::DestroySessionMaterial,
                ],
            },
            (Self::Authenticating, E::PeerCloseReceived) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Closed,
                    actions: &[A::RecordPeerCloseReason, A::DestroySessionMaterial],
                }
            }
            (Self::Authenticating, E::ReadyVerified) => {
                require_role(role, EndpointRole::Requester)?;
                require(guards.ready_parameters_match)?;
                Transition {
                    state: Self::Healthy,
                    actions: &[A::StartLiveness, A::ShowConnected],
                }
            }
            (Self::Authenticating, E::CandidateFailure) => Transition {
                state: Self::Closed,
                actions: &[A::DestroySessionMaterial, A::CloseCandidate],
            },
            (Self::Authenticating, E::TransportFailed) => Transition {
                state: Self::Closed,
                actions: &[A::DestroySessionMaterial, A::ShowConnectionStopped],
            },
            (Self::Authenticating, E::AuthenticatedProtocolViolation) => Transition {
                state: Self::Closing,
                actions: &[A::SendCloseProtocolViolation, A::ShowDisconnecting],
            },
            (Self::Healthy, E::PeerSilent) => Transition {
                state: Self::Healthy,
                actions: &[A::SendLivenessPing],
            },
            (Self::Healthy, E::SilenceLimitReached) => Transition {
                state: Self::Closing,
                actions: &[A::NoteCloseNoticeImpossible, A::ShowDisconnecting],
            },
            (Self::Healthy, E::UserDisconnect) => Transition {
                state: Self::Closing,
                actions: &[A::SendCloseUserDisconnect, A::ShowDisconnecting],
            },
            (Self::Healthy, E::LocalCloseRequested) => Transition {
                state: Self::Closing,
                actions: &[A::SendCloseNormal, A::ShowDisconnecting],
            },
            (Self::Healthy, E::ServiceWithdrawn) => Transition {
                state: Self::Closing,
                actions: &[A::SendCloseServiceWithdrawn, A::ShowDisconnecting],
            },
            (Self::Connecting | Self::Authenticating, E::ServiceWithdrawn) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Closed,
                    actions: &[
                        A::DestroySessionMaterial,
                        A::CloseCandidate,
                        A::ShowConnectionStopped,
                    ],
                }
            }
            (Self::Healthy, E::CardUnavailable) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Closing,
                    actions: &[A::SendCloseCardUnavailable, A::ShowDisconnecting],
                }
            }
            (Self::Healthy, E::PeerCloseReceived) => Transition {
                state: Self::Closing,
                actions: &[A::RecordPeerCloseReason, A::ShowDisconnecting],
            },
            (Self::Healthy, E::TransportFailed) => Transition {
                state: Self::Closing,
                actions: &[A::NoteCloseNoticeImpossible, A::ShowDisconnecting],
            },
            (Self::Healthy, E::SessionIntegrityFailed) => Transition {
                state: Self::Closing,
                actions: &[A::NoteCloseNoticeImpossible, A::ShowDisconnecting],
            },
            (Self::Healthy, E::AuthenticatedProtocolViolation) => Transition {
                state: Self::Closing,
                actions: &[A::SendCloseProtocolViolation, A::ShowDisconnecting],
            },
            (Self::Healthy, E::CloseRequestedByPairing) => Transition {
                state: Self::Closing,
                actions: &[A::ShowDisconnecting],
            },
            (Self::Connecting, E::CloseRequestedByPairing) => Transition {
                state: Self::Closed,
                actions: &[
                    A::DestroySessionMaterial,
                    A::CloseCandidate,
                    A::ShowConnectionStopped,
                ],
            },
            (Self::Authenticating, E::CloseRequestedByPairing) => Transition {
                state: Self::Closed,
                actions: &[
                    A::DestroySessionMaterial,
                    A::CloseCandidate,
                    A::ShowConnectionStopped,
                ],
            },
            (Self::Closing, E::PeerCloseReceived) => Transition {
                state: Self::Closing,
                actions: &[],
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
                    A::ShowConnectionStopped,
                ],
            },
            _ => return Err(TransitionError::UnexpectedInput),
        };
        Ok(transition)
    }
}

impl OperationState {
    /// Apply one transition of the operation machine.
    ///
    /// # Errors
    /// [`TransitionError`] on a wrong role, a failed guard, or input with no
    /// transition.
    #[allow(
        clippy::too_many_lines,
        reason = "the match is the operation machine's transition table and reads best whole"
    )]
    #[allow(
        clippy::match_same_arms,
        reason = "arms mirror the formal transition table; distinct transitions stay distinct"
    )]
    pub fn transition(
        self,
        role: EndpointRole,
        event: OperationEvent,
        _guards: Guards,
    ) -> Result<Transition<Self>, TransitionError> {
        use Action as A;
        use OperationEvent as E;

        let transition = match (self, event) {
            (Self::None, E::RequestReceived) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Requested,
                    actions: &[A::StartExpiryClock],
                }
            }
            (Self::None, E::RequestDuplicate) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::None,
                    actions: &[A::SendErrorDuplicateOperation],
                }
            }
            (Self::None, E::RequestWhileBusy) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::None,
                    actions: &[A::SendErrorBusy],
                }
            }
            (Self::None, E::RequestUnauthorized) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Rejected,
                    actions: &[A::SendResultUnauthorized],
                }
            }
            (Self::None, E::RequestUnsupported) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Rejected,
                    actions: &[A::SendResultUnsupportedParameter],
                }
            }
            (Self::Requested, E::CardHeldElsewhere) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Queued,
                    actions: &[A::SendProgressQueued],
                }
            }
            (Self::Requested, E::CardAcquiredForConsent) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::AwaitingConsent,
                    actions: &[A::PresentConsent, A::SendProgressConsentShown],
                }
            }
            (Self::Queued, E::CardAcquiredForConsent) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::AwaitingConsent,
                    actions: &[A::PresentConsent, A::SendProgressConsentShown],
                }
            }
            (Self::Requested, E::CardAcquiredForRead) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Executing,
                    actions: &[A::ExecuteRead],
                }
            }
            (Self::Queued, E::CardAcquiredForRead) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Executing,
                    actions: &[A::ExecuteRead],
                }
            }
            (Self::AwaitingConsent, E::UserDenied) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Rejected,
                    actions: &[
                        A::DismissConsent,
                        A::SendResultUserCancelled,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::AwaitingConsent, E::UserApproved) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Executing,
                    actions: &[A::DismissConsent, A::CheckRetryFloor, A::ConsumeCardCommand],
                }
            }
            (Self::Executing, E::WaitingForCard) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Executing,
                    actions: &[A::SendProgressWaitingForCard],
                }
            }
            (Self::Executing, E::CardFound) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Executing,
                    actions: &[A::SendProgressCardWaitEnded],
                }
            }
            (Self::Executing, E::WrongPin) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Executing,
                    actions: &[A::PromptPinAgain],
                }
            }
            (Self::Executing, E::RetryFloorRefused) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Rejected,
                    actions: &[
                        A::ClearOperationCredentials,
                        A::SendResultRetryFloor,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::Executing, E::CardSuccess) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Completed,
                    actions: &[
                        A::ClearOperationCredentials,
                        A::SendResultCompleted,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::Executing, E::CardError) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Rejected,
                    actions: &[
                        A::ClearOperationCredentials,
                        A::SendResultCardError,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::Requested, E::RequestExpired) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Cancelled,
                    actions: &[
                        A::DismissConsent,
                        A::SendResultOperationExpired,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::Queued, E::RequestExpired) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Cancelled,
                    actions: &[
                        A::DismissConsent,
                        A::SendResultOperationExpired,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::AwaitingConsent, E::RequestExpired) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::Cancelled,
                    actions: &[
                        A::DismissConsent,
                        A::SendResultOperationExpired,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::Requested, E::SessionClosed) => match role {
                EndpointRole::Proxy => Transition {
                    state: Self::None,
                    actions: &[
                        A::DismissConsent,
                        A::ClearOperationCredentials,
                        A::ReleaseCard,
                    ],
                },
                EndpointRole::Requester => Transition {
                    state: Self::None,
                    actions: &[A::ReportOperationLost],
                },
            },
            (Self::Queued, E::SessionClosed) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::None,
                    actions: &[
                        A::DismissConsent,
                        A::ClearOperationCredentials,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::AwaitingConsent, E::SessionClosed) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::None,
                    actions: &[
                        A::DismissConsent,
                        A::ClearOperationCredentials,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::Executing, E::SessionClosed) => {
                require_role(role, EndpointRole::Proxy)?;
                Transition {
                    state: Self::None,
                    actions: &[
                        A::ContinueCardExchangeLocally,
                        A::DiscardAnswer,
                        A::ClearOperationCredentials,
                        A::ReleaseCard,
                    ],
                }
            }
            (Self::None, E::RequestSent) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Requested,
                    actions: &[],
                }
            }
            (Self::Requested, E::ProgressReceived) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Requested,
                    actions: &[A::ShowProgress],
                }
            }
            (Self::Requested, E::ResultCompletedReceived) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Completed,
                    actions: &[A::ReleaseResult],
                }
            }
            (Self::Requested, E::ResultRejectedReceived) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Rejected,
                    actions: &[A::ReleaseFailure],
                }
            }
            (Self::Requested, E::ResultCancelledReceived) => {
                require_role(role, EndpointRole::Requester)?;
                Transition {
                    state: Self::Cancelled,
                    actions: &[A::ReleaseFailure],
                }
            }
            (Self::Completed | Self::Rejected | Self::Cancelled, _) => {
                return Err(TransitionError::TerminalOperation);
            }
            _ => return Err(TransitionError::UnexpectedInput),
        };
        Ok(transition)
    }
}

/// What an endpoint keeps of one pairing and its session. The session's
/// operation lives in the operation engines, which end it when the session
/// closes (cross-component rule X-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RappState {
    /// Local endpoint projection.
    pub role: EndpointRole,
    /// Pairing component.
    pub pairing: PairingState,
    /// Session component.
    pub session: SessionState,
}

/// Ordered effects of a security event that spans the machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityOutcome {
    /// Ordered effects the endpoint carries out.
    pub actions: Vec<Action>,
}

impl RappState {
    /// An endpoint without a pairing.
    #[must_use]
    pub const fn unpaired(role: EndpointRole) -> Self {
        Self {
            role,
            pairing: PairingState::Unpaired,
            session: SessionState::Absent,
        }
    }

    /// The pairing and session half of operation admission (cross-component
    /// rule X-03); the operation engines refuse a second live operation.
    #[must_use]
    pub const fn operation_admission_permitted(&self) -> bool {
        matches!(self.pairing, PairingState::PairedConnected)
            && matches!(self.session, SessionState::Healthy)
    }

    /// An authenticated message violated the protocol. The session closes
    /// and the pairing stays; during a pairing, the attempt aborts (section
    /// 10.1). This state holds no pairing candidates, so a requester's
    /// ceremony ends with the attempt; trying the next custodian in pairing
    /// mode is [`crate::PairingCandidates`]'s.
    pub fn authenticated_protocol_violation(&mut self) -> SecurityOutcome {
        let pairing_event = match self.pairing {
            PairingState::Handshaking => Some(PairingEvent::HandshakeFailed),
            PairingState::Confirming | PairingState::StorageConfirming => {
                Some(PairingEvent::DeniedAbortedOrTimedOut)
            }
            PairingState::Exchanging => Some(match self.role {
                EndpointRole::Proxy => PairingEvent::AttemptFailed,
                EndpointRole::Requester => PairingEvent::LastCandidateFailed,
            }),
            _ => None,
        };
        if let Some(event) = pairing_event {
            let mut actions = Vec::new();
            if let Ok(transition) = self.pairing.transition(self.role, event, Guards::default()) {
                self.pairing = transition.state;
                actions.extend_from_slice(transition.actions);
            }
            return SecurityOutcome { actions };
        }
        self.close_session(SessionEvent::AuthenticatedProtocolViolation)
    }

    /// A frame failed authenticated decryption or framing; the session
    /// closes and the pairing stays.
    pub fn session_integrity_failed(&mut self) -> SecurityOutcome {
        self.close_session(SessionEvent::SessionIntegrityFailed)
    }

    /// Nothing arrived for the session silence limit; the session closes and
    /// the pairing stays (section 8.3).
    pub fn silence_limit_reached(&mut self) -> SecurityOutcome {
        self.close_session(SessionEvent::SilenceLimitReached)
    }

    fn close_session(&mut self, event: SessionEvent) -> SecurityOutcome {
        let mut actions = Vec::new();
        if let Ok(transition) = self.session.transition(self.role, event, Guards::default()) {
            self.session = transition.state;
            actions.extend_from_slice(transition.actions);
        }
        SecurityOutcome { actions }
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, EndpointRole, PairingState, RappState, SessionState};

    const fn connected(role: EndpointRole) -> RappState {
        RappState {
            role,
            pairing: PairingState::PairedConnected,
            session: SessionState::Healthy,
        }
    }

    #[test]
    fn an_authenticated_violation_closes_the_session_and_keeps_the_pairing() {
        let mut state = connected(EndpointRole::Requester);
        let outcome = state.authenticated_protocol_violation();
        assert_eq!(state.pairing, PairingState::PairedConnected);
        assert_eq!(state.session, SessionState::Closing);
        assert!(
            outcome
                .actions
                .contains(&Action::SendCloseProtocolViolation)
        );
        assert!(!outcome.actions.contains(&Action::DestroyPairKeys));
    }

    #[test]
    fn an_integrity_failure_keeps_the_pairing() {
        let mut state = connected(EndpointRole::Proxy);
        state.session_integrity_failed();
        assert_eq!(state.pairing, PairingState::PairedConnected);
        assert_eq!(state.session, SessionState::Closing);
    }

    #[test]
    fn a_violation_during_pairing_aborts_the_attempt() {
        let mut state = RappState {
            role: EndpointRole::Requester,
            pairing: PairingState::Confirming,
            session: SessionState::Absent,
        };
        state.authenticated_protocol_violation();
        assert_eq!(state.pairing, PairingState::Unpaired);
    }
}
