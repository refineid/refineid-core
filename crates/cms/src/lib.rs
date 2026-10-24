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

//! Strict-DER CMS `SignedData` parsing and offline signature verification.
//!
//! The host-side certificate and signature checks: X.509 parsing
//! and chain hops, CMS `SignedData` signer verification, and the RSA
//! and ECDSA primitives under them. Parsing is strict DER over
//! [`refineid_ber`]; signature verification is implemented here over
//! [`crypto_bigint`] with no platform crypto dependency, so every
//! platform verifies bytes identically.

pub mod container;
pub mod ecdsa;
mod hex;
pub mod oid;
pub mod rsa;
pub mod signed_data;
pub mod x509;
