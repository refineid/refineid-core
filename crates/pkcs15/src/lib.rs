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

//! PKCS#15 file-system reads for FINEID cards.
//!
//! The operations layer on any `refineid-apdu` transport as default
//! trait methods and issue only replay-safe typed commands; certificate
//! files on FINEID cards are public and nothing here touches a
//! credential path. Consumers receive DER bytes and typed serials;
//! X.509 interpretation, reader discovery, and generation
//! classification from certificate contents stay outside this crate.

pub mod fs;
pub mod token_info;
pub mod token_serial;

pub use fs::{
    CertSlot, DF_ESIGN_FID, EF_AUTH_CERT_ALT_FID, EF_AUTH_CERT_FID, EF_ISSUING_CA_ECC_FID,
    EF_ROOT_CA_FID, EF_SIGN_CERT_ALT_FID, EF_SIGN_CERT_FID, EF_TOKEN_INFO_FID, ESIGN_AID,
    PKCS15_AID, Pkcs15Error, Pkcs15Ops,
};
pub use refineid_x509::UnvalidatedCertificate;
pub use token_info::TokenInfo;
pub use token_serial::{PrintedSerial, TokenSerial, derive_printed_serial, render_token_serial};

/// Digits in the older generation's activation PIN.
const OLDER_ACTIVATION_PIN_DIGITS: usize = 8;
/// Digits in the newer generation's one-time activation PIN.
const NEWER_ACTIVATION_PIN_DIGITS: usize = 7;

/// Which FINEID card generation a card belongs to.
///
/// The shipped generations differ in activation-PIN length, and the
/// card rejects wrong-length input while consuming a retry, so the host
/// must know the correct length before sending anything. Classification
/// is a higher-layer concern (certificate issuance date or issuer
/// family); this crate carries only the typed outcome and its
/// length policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardGeneration {
    /// Older generation: eight-digit activation PIN.
    Older,
    /// Newer generation: seven-digit one-time activation PIN.
    Newer,
    /// Not classified; callers must not infer an activation-PIN
    /// length.
    Unknown,
}

impl CardGeneration {
    /// Activation-PIN length for this generation, or `None` when the
    /// generation did not classify and guessing would burn a retry.
    #[must_use]
    pub const fn activation_pin_length(self) -> Option<usize> {
        match self {
            Self::Older => Some(OLDER_ACTIVATION_PIN_DIGITS),
            Self::Newer => Some(NEWER_ACTIVATION_PIN_DIGITS),
            Self::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CardGeneration, NEWER_ACTIVATION_PIN_DIGITS, OLDER_ACTIVATION_PIN_DIGITS};

    #[test]
    fn activation_pin_lengths_follow_the_generation() {
        assert_eq!(
            CardGeneration::Older.activation_pin_length(),
            Some(OLDER_ACTIVATION_PIN_DIGITS)
        );
        assert_eq!(
            CardGeneration::Newer.activation_pin_length(),
            Some(NEWER_ACTIVATION_PIN_DIGITS)
        );
        assert_eq!(CardGeneration::Unknown.activation_pin_length(), None);
    }
}
