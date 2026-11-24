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

//! Minimal identity types for document signing and verification.

use core::fmt;

pub use crate::email::EmailAddress;
pub use refineid_cms::identity::{
    AdditionalName, CommonName, FREE_TEXT_MAX_BYTES, FirstName, FreeTextError, GivenNamesText,
    NativeName, OrganizationName, PEUIN_LEN, Peuin, PeuinError, SecondName, SplitGivenNames,
    SubjectIdentity, Surname, holder_line,
};

#[cfg(feature = "pcsc")]
pub use refineid_pkcs15::{TokenSerial, render_token_serial};

/// Serial number of an X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertSerial(Vec<u8>);

impl CertSerial {
    /// Wrap a byte iterator into a certificate serial number.
    #[must_use]
    pub fn from_bytes<I>(bytes: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        Self(bytes.into_iter().collect())
    }

    /// Borrow the raw integer content bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for CertSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
