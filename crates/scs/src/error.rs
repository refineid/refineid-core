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

//! A refused SCS step, as the specification's reason pair.
//!
//! The code follows the same classes as the JSON `/sign` path: 400
//! malformed, 401 credential, 403 policy, 500 internal, 501
//! unimplemented (DVV SCS specification v1.3 sec.2.6.3).

use crate::backend::BackendFailure;
use crate::values;

/// A refused SCS step, as the specification's reason pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionError {
    /// The specification reason code.
    pub code: u16,
    /// The human-readable reason.
    pub message: String,
}

impl TransactionError {
    /// A malformed-request refusal.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: values::REASON_BAD_REQUEST,
            message: message.into(),
        }
    }

    /// A policy refusal.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            code: values::REASON_FORBIDDEN,
            message: message.into(),
        }
    }

    /// An internal failure.
    pub fn internal_error(message: impl Into<String>) -> Self {
        Self {
            code: values::REASON_INTERNAL_ERROR,
            message: message.into(),
        }
    }

    /// A valid request for an unimplemented capability.
    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self {
            code: values::REASON_NOT_IMPLEMENTED,
            message: message.into(),
        }
    }

    /// Wrap a signing-backend refusal in its specification reason
    /// pair.
    pub fn wrapping(failure: BackendFailure) -> Self {
        Self {
            code: failure.reason_code(),
            message: failure.reason_text(),
        }
    }
}

impl core::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl core::error::Error for TransactionError {}
