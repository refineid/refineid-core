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

//! The Signature Creation Service: the localhost signing interface
//! Finnish web services call at `https://127.0.0.1:53952` (DVV SCS
//! specification v1.3).
//!
//! This crate is the platform-independent half: the HTTP framing, the
//! request documents, the origin-bound challenge rules, the JWT
//! transaction flow, the JOSE envelopes, the detached CMS builder,
//! and the localhost certificate builder. Everything that touches a
//! card -- certificates, key algorithms, the PIN-gated sign itself --
//! crosses the [`SigningBackend`] seam, which the platform implements;
//! the TLS listener, the identity storage, and the PIN prompt are
//! platform glue and live outside this crate.
//!
//! The surface is `GET /version`, `POST /sign` (JSON, or the JWT
//! transaction flow selected by its content type), and the CORS
//! preflight. Sign outcomes always ride in an HTTP 200 whose JSON
//! reason triple carries the result; only an unknown route answers
//! 404. The Swift engine in `refineid-apple` (`CardCore`) implements
//! the same surface against the same specification.

pub mod backend;
pub mod dispatcher;
pub mod error;
pub mod http;
pub mod localhost;
pub mod purpose;
pub mod transaction;
pub mod values;

mod base64;
mod begin;
mod challenge;
mod cms;
mod codec;
mod der;
mod document;
mod execution;
mod hash;
mod jwe;
mod jws;
#[cfg(test)]
pub(crate) mod test_support;
mod time;

pub use backend::{BackendFailure, SignRequest, SigningBackend};
pub use dispatcher::dispatch;
pub use error::TransactionError;
pub use purpose::{KeyAlgorithm, SignPurpose};
pub use transaction::TransactionManager;
