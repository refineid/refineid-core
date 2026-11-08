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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The seam through which a paired phone becomes a slot.
//!
//! The module knows nothing of the Remote Authorization Proxy
//! Protocol's wire, channels, transports or stores; those live in the
//! host that loads it. What the module needs is small: whether one
//! paired phone is offering a card right now, with which
//! authentication certificate, and a way to hand that phone a
//! [`SignatureRequest`] and get the signature bytes back. A host
//! installs one [`RemoteTokenSource`] before the function list is
//! handed out; the module reads the offer from it at every call that
//! can tell a caller whether the phone's token is there or what it
//! holds, and dispatches `C_Sign` to it for a remote slot.
//!
//! A browser asks for the token at a time of its own choosing and may
//! ask only once: during a TLS handshake Firefox learns whether the
//! token is there from `C_GetSlotInfo`, and reads it through
//! `C_GetTokenInfo`, `C_OpenSession` and the object search; it lists
//! the slots only every few seconds, so a handshake may make no
//! `C_GetSlotList` call at all, and it keeps the answer it got. A
//! reading on each of these calls may therefore
//! wait, for at most [`REMOTE_WAKE_WAIT`], while the source dials the
//! phone and a session confirms the card (RAPP v26.11.8 section 8.4
//! item 3: a request with no session open dials the Custodian and is
//! held). No call is granted a wait for [`REMOTE_WAKE_MEMO`] after a
//! wait that raised the token, nor for [`REMOTE_WAKE_QUIET`] after one
//! that raised none, so the many calls of one handshake, and a
//! browser polling the slot, answer at once; a call made while
//! another waits waits with it, never longer than the bound from its
//! own start. The non-blocking slot-event poll never waits. The
//! module offers only what the source offers on that reading, and the
//! source offers only a certificate the phone confirmed on a session;
//! the wait is for that confirmation, and discovery alone never raises
//! a token.
//!
//! A token is offered on a certificate whose fingerprint the phone
//! confirmed on a session, and the module follows the offer: the token
//! exists while the offer carries a certificate. The host keeps
//! offering it between sessions as RAPP v26.11.8 section 8.4 item 3
//! says, until the phone has been out of reach or has reported no card
//! for the grace that section fixes (`IDENTITY_OFFER_GRACE_MS` in
//! `refineid-rapp`) with no report of the card present in that time,
//! until the pairing is forgotten or revoked, or until a session
//! reports a different card. Each `C_Sign` is one call to the source
//! with the module's deadline; an answer that misses the deadline, or
//! an outcome the source cannot classify, is reported and never
//! retried.
//!
//! The source is the only producer of a [`RemoteSlotId`], so holding
//! a remote slot is proof that the host admitted a pairing. The source
//! never sees a PIN: the phone verifies PIN 1 on the device, which is
//! why a remote token reports a protected authentication path and
//! `C_Login` reads nothing.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use refineid_remote::{DisplayText, SignatureRequest};

use crate::ck::{
    CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_MECHANISM_INVALID,
    CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_TOKEN_NOT_PRESENT, CkRv,
};
use crate::slot_kind::RemoteSlotId;

/// How long one remote signature may take, from the moment the module
/// hands the request to the source to the moment the signature is
/// back: the holder's time to answer on the phone and the card's,
/// within what a TLS peer waits for the handshake. It travels with
/// every request as the operation's lifetime.
pub const REMOTE_SIGN_DEADLINE: Duration = Duration::from_secs(30);

/// The longest one PKCS#11 call waits for the paired phone to raise
/// its token: the source dials the phone and reads its card within it
/// on a local network, and a browser's TLS handshake tolerates it.
/// The one bound on every wait for the token, whichever call asks.
pub const REMOTE_WAKE_WAIT: Duration = Duration::from_secs(3);

/// After a wait that raised the token, how long later calls read the
/// source without being granted a wait: the calls of one handshake
/// that follow it answer at once from what the wait found.
pub const REMOTE_WAKE_MEMO: Duration = Duration::from_secs(5);

/// After a wait that raised no token, how long later calls read the
/// source without waiting: longer than one handshake's calls and a
/// browser's slot polling between them, so a phone out of reach holds
/// a browser for one [`REMOTE_WAKE_WAIT`] at a time. The source keeps
/// dialing meanwhile and raises the token when a session confirms the
/// card.
pub const REMOTE_WAKE_QUIET: Duration = Duration::from_secs(30);

/// The authentication certificate of the card the phone serves: one
/// whose fingerprint the phone confirmed on a session (RAPP v26.11.8
/// section 8.4 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCertificate(Vec<u8>);

impl SessionCertificate {
    /// The certificate's DER, confirmed by fingerprint on a session.
    #[must_use]
    pub const fn new(der: Vec<u8>) -> Self {
        Self(der)
    }

    /// The certificate's DER.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

/// What one paired phone offers at the moment it is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOffer {
    pair_id: RemoteSlotId,
    label: String,
    context: DisplayText,
    certificate: Option<SessionCertificate>,
}

impl RemoteOffer {
    /// Describes the offered pairing.
    ///
    /// `context` names this computer to the holder on the phone's
    /// consent view; it travels with every signature request.
    /// `certificate` is present while the source offers the card: a
    /// certificate whose fingerprint the phone confirmed on a session,
    /// kept between sessions until the offer is withdrawn as RAPP
    /// v26.11.8 section 8.4 item 3 says. The token exists exactly then.
    #[must_use]
    pub const fn new(
        pair_id: RemoteSlotId,
        label: String,
        context: DisplayText,
        certificate: Option<SessionCertificate>,
    ) -> Self {
        Self {
            pair_id,
            label,
            context,
            certificate,
        }
    }

    /// The pairing the offer belongs to.
    #[must_use]
    pub const fn pair_id(&self) -> &RemoteSlotId {
        &self.pair_id
    }

    /// The name the phone is shown under.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The text naming this computer to the holder.
    #[must_use]
    pub const fn context(&self) -> &DisplayText {
        &self.context
    }

    /// The certificate the phone confirmed on a session, while the
    /// source offers it.
    #[must_use]
    pub const fn certificate(&self) -> Option<&SessionCertificate> {
        self.certificate.as_ref()
    }
}

/// Why a remote signature did not come back.
///
/// The host maps the outcomes of its own protocol onto this closed
/// set; the module maps each member onto one PKCS#11 return value in
/// [`RemoteSignError::ck_rv`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSignError {
    /// No session to the phone could be opened or kept.
    Unreachable,
    /// The phone no longer holds the pairing.
    Withdrawn,
    /// The phone holds no card in its field.
    CardAbsent,
    /// The holder cancelled or declined on the phone.
    Cancelled,
    /// No answer arrived within the deadline the request carried.
    Expired,
    /// The phone reports that the credential was rejected.
    CredentialRejected,
    /// The phone reports that the credential is locked.
    CredentialLocked,
    /// The phone refused the request's parameters.
    Unsupported,
    /// The session ended with the outcome unknown.
    Ambiguous,
}

impl RemoteSignError {
    /// Every member, for exhaustive tests of the mapping.
    pub const ALL: [Self; 9] = [
        Self::Unreachable,
        Self::Withdrawn,
        Self::CardAbsent,
        Self::Cancelled,
        Self::Expired,
        Self::CredentialRejected,
        Self::CredentialLocked,
        Self::Unsupported,
        Self::Ambiguous,
    ];

    /// The PKCS#11 return value the member maps to (OASIS PKCS#11
    /// v2.40 section 5.1).
    #[must_use]
    pub const fn ck_rv(self) -> CkRv {
        match self {
            Self::Unreachable | Self::Withdrawn => CKR_DEVICE_REMOVED,
            Self::CardAbsent => CKR_TOKEN_NOT_PRESENT,
            Self::Cancelled | Self::Expired => CKR_FUNCTION_CANCELED,
            Self::CredentialRejected => CKR_PIN_INCORRECT,
            Self::CredentialLocked => CKR_PIN_LOCKED,
            Self::Unsupported => CKR_MECHANISM_INVALID,
            Self::Ambiguous => CKR_DEVICE_ERROR,
        }
    }
}

impl core::fmt::Display for RemoteSignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Unreachable => "the phone could not be reached",
            Self::Withdrawn => "the phone no longer holds the pairing",
            Self::CardAbsent => "the phone holds no card",
            Self::Cancelled => "the request was cancelled on the phone",
            Self::Expired => "no answer arrived within the deadline",
            Self::CredentialRejected => "the phone rejected the credential",
            Self::CredentialLocked => "the credential is locked",
            Self::Unsupported => "the phone refused the request's parameters",
            Self::Ambiguous => "the session ended with the outcome unknown",
        })
    }
}

impl core::error::Error for RemoteSignError {}

/// A host's paired phone, as the module sees it.
///
/// Every method may be called from any thread the host runs PKCS#11
/// on, and each runs with the module lock released.
/// [`RemoteTokenSource::offered`] answers from state the host already
/// holds, waiting only as long as it is told. [`RemoteTokenSource::sign`]
/// may take as long as the holder takes to answer on the phone, up to
/// the deadline it is given.
pub trait RemoteTokenSource: Send + Sync {
    /// The one pairing offered right now, or none.
    ///
    /// The offer carries a certificate while the source offers the
    /// card under RAPP v26.11.8 section 8.4 item 3, between sessions
    /// included; the module withdraws the token the moment the offer
    /// carries none, and raises a new token, with new object handles,
    /// when a certificate is offered again.
    ///
    /// When the pairing's slot stands without a token and no session
    /// to the phone is open, the call is a request for the card: the
    /// source dials the phone (RAPP v26.11.8 section 8.3) and waits up
    /// to `wait` for a session to confirm the card, then answers with
    /// what it offers. It answers at once otherwise, and always within
    /// `wait`, its own start-up included; a zero `wait` never blocks
    /// and dials nothing. The module passes at most
    /// [`REMOTE_WAKE_WAIT`].
    fn offered(&self, wait: Duration) -> Option<RemoteOffer>;

    /// Asks the phone of `pair_id` to sign `request`, showing
    /// `context` to the holder, and returns the signature bytes in
    /// the registered encoding: the PKCS#1 block for RSA, the
    /// fixed-width `r || s` for ECDSA.
    ///
    /// With no session open, the source dials the phone and holds the
    /// request until a session opens or `deadline` passes. The source
    /// answers within `deadline` or reports
    /// [`RemoteSignError::Expired`]; the module issues one call per
    /// `C_Sign` and never repeats it.
    ///
    /// # Errors
    ///
    /// One member of [`RemoteSignError`].
    fn sign(
        &self,
        pair_id: &RemoteSlotId,
        request: &SignatureRequest,
        context: &DisplayText,
        deadline: Duration,
    ) -> Result<Vec<u8>, RemoteSignError>;

    /// Ends whatever the source keeps running; called from
    /// `C_Finalize`.
    fn stop(&self);
}

/// The installed source, for the lifetime of the process.
static REMOTE_SOURCE: OnceLock<Box<dyn RemoteTokenSource>> = OnceLock::new();

/// A second installation was attempted; the first stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSourceInstalled;

impl core::fmt::Display for RemoteSourceInstalled {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a remote token source is already installed")
    }
}

impl core::error::Error for RemoteSourceInstalled {}

/// Installs the process's one [`RemoteTokenSource`].
///
/// A host calls this once, before it hands out the function list.
///
/// # Errors
///
/// [`RemoteSourceInstalled`] when a source is already installed; the
/// installed one keeps serving.
pub fn install_remote_source(
    source: Box<dyn RemoteTokenSource>,
) -> Result<(), RemoteSourceInstalled> {
    REMOTE_SOURCE
        .set(source)
        .map_err(|_second| RemoteSourceInstalled)
}

/// The installed source, if a host installed one.
pub(crate) fn installed() -> Option<&'static dyn RemoteTokenSource> {
    REMOTE_SOURCE.get().map(AsRef::as_ref)
}

/// Whether a reading may wait for the phone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Patience {
    /// The caller asks for the token: the reading may wait as the
    /// [`WakeGate`] allows.
    Wake,
    /// The caller must not block: the reading answers at once.
    AtOnce,
}

/// What one reading of the installed source found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RemoteReading {
    /// No host installed a source: no remote slot exists.
    NoSource,
    /// The source's offer on this reading.
    Offer(Option<RemoteOffer>),
}

/// The last wait a [`WakeGate`] granted.
#[derive(Debug, Clone, Copy)]
struct GrantedWait {
    /// When the reading that was granted it began.
    at: Instant,
    /// Whether the reading ended with a token offered.
    raised: bool,
}

/// Grants the waits of the readings: at most `wait` from a reading's
/// own start, none for `memo` after a wait that raised the token, and
/// none for `quiet` after a wait that raised none.
///
/// A waiting reading holds the gate, so a reading that arrives
/// meanwhile waits for its answer instead of starting a wait of its
/// own, and reads at once when the gate opens.
#[derive(Debug)]
pub(crate) struct WakeGate {
    wait: Duration,
    memo: Duration,
    quiet: Duration,
    last: Mutex<Option<GrantedWait>>,
}

impl WakeGate {
    /// A gate granting `wait` per reading, none for `memo` after a
    /// wait that raised the token and none for `quiet` after one that
    /// raised none.
    pub(crate) const fn new(wait: Duration, memo: Duration, quiet: Duration) -> Self {
        Self {
            wait,
            memo,
            quiet,
            last: Mutex::new(None),
        }
    }

    /// Reads `source` with the wait this gate grants.
    pub(crate) fn read(
        &self,
        source: &dyn RemoteTokenSource,
        patience: Patience,
    ) -> Option<RemoteOffer> {
        if patience == Patience::AtOnce {
            return source.offered(Duration::ZERO);
        }
        let asked = Instant::now();
        let Ok(mut last) = self.last.lock() else {
            return source.offered(Duration::ZERO);
        };
        let now = Instant::now();
        let resting = last.is_some_and(|granted| {
            let window = if granted.raised {
                self.memo
            } else {
                self.quiet
            };
            now.saturating_duration_since(granted.at) < window
        });
        let wait = if resting {
            Duration::ZERO
        } else {
            self.wait
                .saturating_sub(now.saturating_duration_since(asked))
        };
        if wait.is_zero() {
            drop(last);
            return source.offered(Duration::ZERO);
        }
        let offer = source.offered(wait);
        *last = Some(GrantedWait {
            at: now,
            raised: offer.as_ref().and_then(RemoteOffer::certificate).is_some(),
        });
        offer
    }

    /// Forgets the last granted wait.
    #[cfg(test)]
    pub(crate) fn reset(&self) {
        if let Ok(mut last) = self.last.lock() {
            *last = None;
        }
    }
}

/// The gate every reading of the installed source passes.
static WAKE_GATE: WakeGate = WakeGate::new(REMOTE_WAKE_WAIT, REMOTE_WAKE_MEMO, REMOTE_WAKE_QUIET);

/// Reads the installed source through the process's [`WakeGate`].
///
/// Never called with the module lock held: a reading may wait.
pub(crate) fn read_installed(patience: Patience) -> RemoteReading {
    installed().map_or(RemoteReading::NoSource, |source| {
        RemoteReading::Offer(WAKE_GATE.read(source, patience))
    })
}

/// Forgets the process gate's last granted wait, for tests that
/// drive the entry points one after another.
#[cfg(test)]
pub(crate) fn reset_wake_gate_for_test() {
    WAKE_GATE.reset();
}

#[cfg(test)]
mod tests {
    use super::{
        Duration, Instant, Patience, RemoteOffer, RemoteSignError, RemoteTokenSource,
        SessionCertificate, WakeGate,
    };
    use std::sync::Mutex;
    use std::sync::mpsc::{Sender, channel};

    /// The bound the tested gates grant a reading.
    const TEST_WAIT: Duration = Duration::from_millis(200);
    /// The tested gates' rest after a wait that raised the token.
    const TEST_MEMO: Duration = Duration::from_millis(300);
    /// The tested gates' rest after a wait that raised none.
    const TEST_QUIET: Duration = Duration::from_millis(600);
    /// How long into a wait an answering phone's session confirms the
    /// card.
    const ANSWERS_AFTER: Duration = Duration::from_millis(50);
    /// What the scheduler may add to a reading beyond its wait.
    const SCHEDULING_SLACK: Duration = Duration::from_millis(500);

    fn test_gate() -> WakeGate {
        WakeGate::new(TEST_WAIT, TEST_MEMO, TEST_QUIET)
    }

    /// A phone the gate is read against: its session confirms the card
    /// `answers_after` into a wait long enough, or never, and it holds
    /// a wait it cannot answer to its end, as a source must not exceed.
    struct GatePhone {
        answers_after: Option<Duration>,
        raised: Mutex<bool>,
        waits: Mutex<Vec<Duration>>,
        /// Told when a reading starts a wait.
        began: Mutex<Option<Sender<()>>>,
    }

    impl GatePhone {
        fn new(answers_after: Option<Duration>) -> Self {
            Self {
                answers_after,
                raised: Mutex::new(false),
                waits: Mutex::new(Vec::new()),
                began: Mutex::new(None),
            }
        }

        fn offer(raised: bool) -> RemoteOffer {
            RemoteOffer::new(
                crate::slot_kind::RemoteSlotId::parse(&"a5".repeat(crate::slot_kind::PAIR_ID_SIZE))
                    .expect("valid pair id"),
                "Alpha Phone".to_owned(),
                refineid_remote::DisplayText::new("alpha-desk".to_owned()).expect("bounded text"),
                raised.then(|| SessionCertificate::new(b"confirmed certificate".to_vec())),
            )
        }

        /// The waits granted that were not zero.
        fn granted(&self) -> Vec<Duration> {
            self.waits
                .lock()
                .expect("waits lock")
                .iter()
                .copied()
                .filter(|wait| !wait.is_zero())
                .collect()
        }
    }

    impl RemoteTokenSource for GatePhone {
        fn offered(&self, wait: Duration) -> Option<RemoteOffer> {
            self.waits.lock().expect("waits lock").push(wait);
            let raised = *self.raised.lock().expect("raised lock");
            if raised || wait.is_zero() {
                return Some(Self::offer(raised));
            }
            if let Some(began) = self.began.lock().expect("began lock").as_ref() {
                let _ = began.send(());
            }
            match self.answers_after {
                Some(after) if after <= wait => {
                    std::thread::sleep(after);
                    *self.raised.lock().expect("raised lock") = true;
                    Some(Self::offer(true))
                }
                _ => {
                    std::thread::sleep(wait);
                    Some(Self::offer(false))
                }
            }
        }

        fn sign(
            &self,
            _pair_id: &crate::slot_kind::RemoteSlotId,
            _request: &refineid_remote::SignatureRequest,
            _context: &refineid_remote::DisplayText,
            _deadline: Duration,
        ) -> Result<Vec<u8>, RemoteSignError> {
            Err(RemoteSignError::Unreachable)
        }

        fn stop(&self) {}
    }

    fn carries_token(offer: Option<&RemoteOffer>) -> bool {
        offer.and_then(RemoteOffer::certificate).is_some()
    }

    /// A phone out of reach holds a reading no longer than the bound,
    /// and the readings after it answer at once until the quiet ends;
    /// then a reading may wait again.
    #[test]
    fn an_absent_phone_holds_one_reading_per_quiet() {
        let gate = test_gate();
        let phone = GatePhone::new(None);
        let started = Instant::now();
        assert!(!carries_token(gate.read(&phone, Patience::Wake).as_ref()));
        assert!(started.elapsed() < TEST_WAIT + SCHEDULING_SLACK);

        let again = Instant::now();
        assert!(!carries_token(gate.read(&phone, Patience::Wake).as_ref()));
        assert!(!carries_token(gate.read(&phone, Patience::Wake).as_ref()));
        assert!(again.elapsed() < SCHEDULING_SLACK);
        assert_eq!(phone.granted().len(), 1);
        assert!(phone.granted().iter().all(|wait| *wait <= TEST_WAIT));

        std::thread::sleep(TEST_QUIET);
        let _ = gate.read(&phone, Patience::Wake);
        assert_eq!(phone.granted().len(), 2);
    }

    /// A phone that answers raises the token within the bound, and the
    /// readings after it are granted no wait until the memo ends.
    #[test]
    fn a_raised_token_answers_the_readings_after_it_at_once() {
        let gate = test_gate();
        let phone = GatePhone::new(Some(ANSWERS_AFTER));
        let started = Instant::now();
        assert!(carries_token(gate.read(&phone, Patience::Wake).as_ref()));
        assert!(started.elapsed() < TEST_WAIT);
        assert!(carries_token(gate.read(&phone, Patience::Wake).as_ref()));
        assert_eq!(phone.granted().len(), 1);

        std::thread::sleep(TEST_MEMO);
        assert!(carries_token(gate.read(&phone, Patience::Wake).as_ref()));
        assert_eq!(phone.granted().len(), 2);
    }

    /// A reading that arrives while another waits shares that wait:
    /// it answers within the bound from its own start, and starts no
    /// wait of its own.
    #[test]
    fn a_reading_during_a_wait_shares_it() {
        let gate = std::sync::Arc::new(test_gate());
        let phone = std::sync::Arc::new(GatePhone::new(None));
        let (began, waiting) = channel();
        *phone.began.lock().expect("began lock") = Some(began);
        let first = {
            let gate = std::sync::Arc::clone(&gate);
            let phone = std::sync::Arc::clone(&phone);
            std::thread::spawn(move || gate.read(phone.as_ref(), Patience::Wake))
        };
        waiting.recv().expect("the first reading waits");
        let started = Instant::now();
        assert!(!carries_token(
            gate.read(phone.as_ref(), Patience::Wake).as_ref()
        ));
        assert!(started.elapsed() < TEST_WAIT + SCHEDULING_SLACK);
        assert!(!carries_token(
            first.join().expect("first reading").as_ref()
        ));
        assert_eq!(phone.granted().len(), 1);
    }

    /// A reading that must not block is granted no wait, even with the
    /// gate open.
    #[test]
    fn a_reading_that_must_not_block_waits_for_nothing() {
        let gate = test_gate();
        let phone = GatePhone::new(None);
        let started = Instant::now();
        assert!(!carries_token(gate.read(&phone, Patience::AtOnce).as_ref()));
        assert!(started.elapsed() < SCHEDULING_SLACK);
        assert!(phone.granted().is_empty());
    }
    use crate::ck::{
        CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_MECHANISM_INVALID,
        CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_TOKEN_NOT_PRESENT,
    };

    #[test]
    fn every_error_maps_as_the_table_says() {
        let expected = [
            (RemoteSignError::Unreachable, CKR_DEVICE_REMOVED),
            (RemoteSignError::Withdrawn, CKR_DEVICE_REMOVED),
            (RemoteSignError::CardAbsent, CKR_TOKEN_NOT_PRESENT),
            (RemoteSignError::Cancelled, CKR_FUNCTION_CANCELED),
            (RemoteSignError::Expired, CKR_FUNCTION_CANCELED),
            (RemoteSignError::CredentialRejected, CKR_PIN_INCORRECT),
            (RemoteSignError::CredentialLocked, CKR_PIN_LOCKED),
            (RemoteSignError::Unsupported, CKR_MECHANISM_INVALID),
            (RemoteSignError::Ambiguous, CKR_DEVICE_ERROR),
        ];
        assert_eq!(expected.len(), RemoteSignError::ALL.len());
        for (error, rv) in expected {
            assert_eq!(error.ck_rv(), rv, "{error}");
            assert!(RemoteSignError::ALL.contains(&error));
        }
    }
}
