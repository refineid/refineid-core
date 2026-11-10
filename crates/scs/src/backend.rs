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

//! The signing seam behind the SCS protocol surface.
//!
//! The dispatcher and the transaction flow are pure protocol logic;
//! everything that touches a card -- certificates, key algorithms, the
//! PIN-gated sign itself -- crosses this seam. The production backend
//! drives a card session; tests supply canned material so the whole
//! protocol surface is exercised without hardware.

use refineid_digest::HashAlg;

use crate::purpose::{KeyAlgorithm, SignPurpose};
use crate::values;

/// One signature the SCS has been asked to produce.
///
/// The payload, the key that signs it, and the origin that asked are
/// bound together because the end user has to be told all three before
/// a PIN is asked for: which site wants a signature, and what it is
/// about to sign (DVV SCS specification v1.3 sec.2.1). Carrying the
/// origin here rather than passing it alongside keeps the two from
/// being confused at a call site that signs a derived payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// The key the sign uses.
    pub purpose: SignPurpose,
    /// The hash applied to `data` before the card signs the digest.
    pub hash: HashAlg,
    /// The bytes to be signed.
    pub data: Vec<u8>,
    /// The Origin header of the request that asked, or `None` when
    /// the request carried none.
    pub origin: Option<String>,
}

/// Why the signing backend refused an SCS sign.
///
/// The protocol maps these to the specification's reason codes: a
/// credential refusal answers 401, everything else 500 (DVV SCS
/// specification v1.3 sec.2.6.3). The text rides in `reasonText` and
/// never carries a credential or a serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendFailure {
    /// The credential was refused, missing, or not entered.
    CredentialRefused(String),
    /// The card, reader, or sign chain failed.
    SigningUnavailable(String),
}

impl BackendFailure {
    /// The specification reason code for this failure.
    pub(crate) fn reason_code(&self) -> u16 {
        match self {
            Self::CredentialRefused(_) => values::REASON_UNAUTHORIZED,
            Self::SigningUnavailable(_) => values::REASON_INTERNAL_ERROR,
        }
    }

    /// The reason-text prefix plus detail for this failure.
    pub(crate) fn reason_text(&self) -> String {
        match self {
            Self::CredentialRefused(detail) => "Unauthorized: ".to_owned() + detail,
            Self::SigningUnavailable(detail) => "Internal Server Error: ".to_owned() + detail,
        }
    }
}

impl core::fmt::Display for BackendFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.reason_text())
    }
}

impl core::error::Error for BackendFailure {}

/// The signing seam behind the SCS protocol surface.
pub trait SigningBackend: Send + Sync {
    /// The DER certificate chain for `purpose`, leaf first.
    fn certificate_chain(&self, purpose: SignPurpose) -> Vec<Vec<u8>>;

    /// The key algorithm behind `purpose`, for the response's
    /// `signatureAlgorithm` field.
    fn key_algorithm(&self, purpose: SignPurpose) -> KeyAlgorithm;

    /// Sign `request` with the `purpose` key after hashing its data.
    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, BackendFailure>;
}
