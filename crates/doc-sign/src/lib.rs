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

//! Document signing: PAdES, ASiC-E, CAdES, and XAdES over FINEID credentials.
//!
//! Provides cross-platform incremental PDF signing, ASiC-E container creation,
//! CAdES/XAdES generation, RFC 3161 timestamps, and long-term validation (LTA)
//! evidence collection.

#![forbid(unsafe_code)]

pub mod asic;
pub mod asic_verify;
pub mod base64;
/// Canonical BER encoding and parsing primitives re-exported from `refineid_ber`.
pub(crate) mod ber {
    pub use refineid_ber::*;

    /// Wrap `value` in a single-byte-tag TLV and return as a fresh `Vec<u8>`.
    ///
    /// # Panics
    /// Panics if `tag` is a multi-byte tag leader (0x1F bits all set) or `value`
    /// exceeds the four-byte long form (4 GiB). All call sites within `doc-sign`
    /// pass standard ASN.1 single-byte universal or context tags (0x01..=0x31,
    /// 0x80..=0xAF) with bounded in-memory payload buffers, satisfying these
    /// preconditions statically.
    #[must_use]
    pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        refineid_ber::tlv(tag, value).expect("BER encode invariant: tag is valid single-byte identifier and length fits 32-bit bound")
    }
}
pub mod cades;
pub use refineid_cms::container;
pub use refineid_cms::signed_data as cms;
pub mod crl;
pub use refineid_digest as digest;
pub mod document;
pub use refineid_cms::ecdsa;
pub mod email;
pub mod hexcodec;
pub mod http;
pub mod identity;
pub mod material;
pub mod ocsp;
pub mod oids;
pub mod pades;
pub mod pin;
pub mod revocation;
pub mod rng;
pub use refineid_cms::rsa;
#[cfg(feature = "pcsc")]
pub mod service;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
pub(crate) mod test_util;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod text;
pub mod timestamp;
pub mod trust;
pub mod trust_roots;
pub mod uri;
pub mod validation;
pub mod verification;
pub mod verify;
pub mod x509_ext;
pub mod xades;
pub use crate::material::now_date_time;
pub use crate::x509_ext::{CertificateExt, NameExt};
pub use refineid_cms::x509;
