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
//! handed out; the module reads offers from it at every slot refresh
//! and dispatches `C_Sign` to it for a remote slot.
//!
//! A token is offered on a certificate whose fingerprint the phone
//! confirmed on a session, and the module follows the offer: the token
//! exists while the offer carries a certificate. The host keeps
//! offering it between sessions as RAPP v26.11.1 section 8.4 item 3
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
use std::sync::OnceLock;

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

/// The authentication certificate of the card the phone serves: one
/// whose fingerprint the phone confirmed on a session (RAPP v26.11.1
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

/// What one paired phone offers at the moment of a slot refresh.
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
    /// v26.11.1 section 8.4 item 3 says. The token exists exactly then.
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
/// on. [`RemoteTokenSource::offered`] runs under the module lock at
/// every slot refresh and so answers from state the host already
/// holds, without a network round trip. [`RemoteTokenSource::sign`]
/// runs with the module lock released and may take as long as the
/// holder takes to answer on the phone, up to the deadline it is
/// given.
pub trait RemoteTokenSource: Send + Sync {
    /// The one pairing offered right now, or none.
    ///
    /// The offer carries a certificate while the source offers the
    /// card under RAPP v26.11.1 section 8.4 item 3, between sessions
    /// included; the module withdraws the token the moment the offer
    /// carries none, and raises a new token, with new object handles,
    /// when a certificate is offered again.
    fn offered(&self) -> Option<RemoteOffer>;

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

#[cfg(test)]
mod tests {
    use super::RemoteSignError;
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
