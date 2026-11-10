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

//! Which card key an SCS request selects, and the algorithm behind it.

use refineid_digest::HashAlg;

use crate::hash;

/// Which card key an SCS request selects.
///
/// The request's selector names key usages; `nonRepudiation` selects
/// the qualified-signature key and everything else the authentication
/// key (DVV SCS specification v1.3 sec.2.6.2). The two keys carry
/// different obligations: an authentication signature must only ever
/// cover an origin-bound challenge, a qualified signature covers the
/// document the holder chose to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignPurpose {
    /// The PIN1-gated authentication key.
    Authentication,
    /// The PIN2-gated qualified-signature key.
    Qualified,
}

/// The key algorithm behind an SCS signature, as the protocol names
/// it.
///
/// The response's `signatureAlgorithm` field composes the digest and
/// key names in the `SHA256withRSA` Java convention (DVV SCS
/// specification v1.3 sec.2.6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// An elliptic-curve card key.
    Ecdsa,
    /// An RSA card key.
    Rsa,
}

impl KeyAlgorithm {
    /// The composed `signatureAlgorithm` response value for this key
    /// under `hash`.
    #[must_use]
    pub fn scs_name(self, hash: HashAlg) -> String {
        let key = match self {
            Self::Ecdsa => "ECDSA",
            Self::Rsa => "RSA",
        };
        hash::scs_name(hash).to_owned() + "with" + key
    }
}

#[cfg(test)]
mod tests {
    use super::KeyAlgorithm;
    use refineid_digest::HashAlg;

    /// The composed names follow the Java convention.
    #[test]
    fn composed_names() {
        assert_eq!(
            KeyAlgorithm::Rsa.scs_name(HashAlg::Sha256),
            "SHA256withRSA".to_owned()
        );
        assert_eq!(
            KeyAlgorithm::Ecdsa.scs_name(HashAlg::Sha384),
            "SHA384withECDSA".to_owned()
        );
    }
}
