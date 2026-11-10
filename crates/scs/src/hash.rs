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

//! The SCS digest-name gate: the protocol's exact spellings to the
//! shared [`HashAlg`](refineid_digest::HashAlg).
//!
//! Matching is exact: the surface accepts SHA-256, SHA-384 and
//! SHA-512 spelled exactly so (v1.3 sec.2.5.2; SHA-1 support was
//! removed in v1.2). The value that crosses is the shared algorithm
//! type, so its digest length rides along by construction.

use refineid_digest::HashAlg;

/// The protocol's SHA-1 spelling.
const SHA1_NAME: &str = "SHA1";

/// The protocol's SHA-256 spelling.
const SHA256_NAME: &str = "SHA256";

/// The protocol's SHA-384 spelling.
const SHA384_NAME: &str = "SHA384";

/// The protocol's SHA-512 spelling.
const SHA512_NAME: &str = "SHA512";

/// Parse the protocol's digest-name spelling; `None` when the surface
/// does not serve it.
#[must_use]
pub fn hash_named(name: &str) -> Option<HashAlg> {
    match name {
        SHA256_NAME => Some(HashAlg::Sha256),
        SHA384_NAME => Some(HashAlg::Sha384),
        SHA512_NAME => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// The protocol's digest-name spelling for `hash`.
#[must_use]
pub const fn scs_name(hash: HashAlg) -> &'static str {
    match hash {
        HashAlg::Sha1 => SHA1_NAME,
        HashAlg::Sha256 => SHA256_NAME,
        HashAlg::Sha384 => SHA384_NAME,
        HashAlg::Sha512 => SHA512_NAME,
    }
}

#[cfg(test)]
mod tests {
    use super::{hash_named, scs_name};
    use refineid_digest::HashAlg;

    /// The three served spellings parse; anything else does not.
    #[test]
    fn exact_spellings_parse() {
        for (name, hash) in [
            ("SHA256", HashAlg::Sha256),
            ("SHA384", HashAlg::Sha384),
            ("SHA512", HashAlg::Sha512),
        ] {
            assert_eq!(hash_named(name), Some(hash), "{name}");
            assert_eq!(scs_name(hash), name, "{name:?}");
        }
        for name in ["", "SHA1", "sha256", "SHA-256", "SHA224", "MD5"] {
            assert_eq!(hash_named(name), None, "{name:?}");
        }
    }
}
