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
//! X.509 interpretation and reader discovery stay outside this crate.

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
