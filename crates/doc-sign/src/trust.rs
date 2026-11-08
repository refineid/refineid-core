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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! The certificates that bootstrap the EU trusted lists.
//!
//! The only certificates this core ships are the six the Official
//! Journal of the European Union publishes as entitled to sign the EU
//! List of Trusted Lists (LOTL), in `crates/doc-sign/trust-anchors/`.
//! They are end-entity signing certificates that no operating-system
//! root store carries, so no other bootstrap exists: the list of the
//! lists verifies under them, each national list verifies under the
//! certificates the list of the lists names for it, and every other
//! trust anchor comes from those lists at runtime
//! ([`crate::verification::TrustAnchors::from_trusted_lists`]) or,
//! when a card is present, from the card itself (`EF.4334` root CA,
//! `EF.4336` issuing CA). The shell fetches and caches the lists
//! ([`crate::verification::trusted_list::TrustedLists::fetch`] over
//! the crate's HTTP transport, or `read` on bytes it fetched itself,
//! and `from_cache` on the records it stored); the verifier reads the
//! lists it is handed and does no network access of its own. No CA
//! root, fingerprint or pin is shipped beside the six.
//!
//! The owner decided this on 2026-11-07 after reading the lists: the
//! Finnish trusted list names DVV's services by their issuing CA
//! certificates ("DVV Citizen Certificates - G4E" and "- G4R", "VRK
//! Gov. CA for Citizen Certificates - G3", the organisational and
//! service CAs), the certificates a card's own chain starts at, so a
//! shipped DVV root would anchor nothing the list does not; the
//! Spanish trusted list names Sectigo (Europe) SL's qualified
//! time-stamping service by "Sectigo Qualified Time Stamping CA R35",
//! the CA that signs its time-stamp units, so a shipped Sectigo root
//! is redundant too. A fresh install therefore verifies a signature
//! made without a card present only after it has fetched the lists
//! once; from then on it works offline from the cache.
//!
//! Fingerprints are typed [`Sha256`] values rather than raw
//! `[u8; 32]` so the type system enforces "compare a SHA-256
//! against a SHA-256 pin" -- mixing a different-shape hash
//! against a pin won't compile. See
//! [`doc/architecture/refinement-types.md`][typing] for the broader
//! framing.
//!
//! [typing]: ../../../../doc/architecture/refinement-types.md

use refineid_digest::Sha256;

/// The certificates entitled to sign the EU List of Trusted Lists
/// (LOTL), as `(label, sha256)` pairs.
///
/// ETSI TS 119 612 V2.3.1 clause 5.3.13 and annex A.1: the LOTL is
/// authenticated under the certificates the Official Journal of the
/// European Union publishes for it, the notice the LOTL's own scheme
/// information URI names: OJ C, C/2026/1944
/// (`https://eur-lex.europa.eu/eli/C/2026/1944/oj`), the source of
/// these certificates. The notice lists six certificates by SHA-256
/// and SHA-1 digest, and each fingerprint here equals one of its
/// SHA-256 digests; its electronic edition is authenticated by the
/// Publications Office's XAdES seal over a manifest of its language
/// versions. A future set is re-checked by comparing the SHA-256
/// digests the new notice lists with the certificates the LOTL
/// carries. The LOTL repeats the same
/// set in the pointer to itself, and that pointer at LOTL sequence
/// number 397 is the copy these bytes were taken from; the set equals
/// the one the pivot LOTL 378 carries. The labels number the
/// certificates in the order that pointer lists them.
pub const LOTL_SIGNER_SHA256: &[(&str, Sha256)] = &[
    (
        "EU list of the lists signer 1",
        Sha256::from_bytes([
            0xD2, 0x06, 0x4F, 0xDD, 0x70, 0xF6, 0x98, 0x2D, 0xCC, 0x51, 0x6B, 0x86, 0xD9, 0xD5,
            0xC5, 0x6A, 0xEA, 0x93, 0x94, 0x17, 0xC6, 0x24, 0xB2, 0xE4, 0x78, 0xC0, 0xB2, 0x9D,
            0xE5, 0x4F, 0x84, 0x74,
        ]),
    ),
    (
        "EU list of the lists signer 2",
        Sha256::from_bytes([
            0xE0, 0xA6, 0x20, 0xFB, 0xB6, 0x74, 0x73, 0x62, 0xBB, 0x93, 0x3A, 0xC4, 0x41, 0x69,
            0xD6, 0x76, 0xA5, 0x53, 0x44, 0x47, 0x16, 0xCF, 0x5F, 0x31, 0x60, 0x5F, 0x12, 0xA2,
            0x2B, 0x83, 0x96, 0xB1,
        ]),
    ),
    (
        "EU list of the lists signer 3",
        Sha256::from_bytes([
            0xC0, 0x64, 0x1C, 0x4F, 0x7D, 0x56, 0xC4, 0x31, 0xB1, 0xC9, 0x24, 0x74, 0x2D, 0xB7,
            0xFC, 0xE9, 0xC1, 0xEE, 0xF7, 0xD7, 0xFD, 0x21, 0x21, 0x13, 0xA2, 0x76, 0x84, 0x86,
            0xB3, 0xAB, 0xCD, 0xC5,
        ]),
    ),
    (
        "EU list of the lists signer 4",
        Sha256::from_bytes([
            0xDF, 0x7E, 0x29, 0x36, 0x0C, 0x34, 0xB2, 0xB8, 0xD6, 0xD5, 0xF4, 0x03, 0x25, 0xC1,
            0xD4, 0xD1, 0x2C, 0x99, 0x22, 0xCE, 0xCD, 0x33, 0xB7, 0x40, 0x76, 0x74, 0xA7, 0x4B,
            0x2B, 0x3C, 0xA1, 0xE5,
        ]),
    ),
    (
        "EU list of the lists signer 5",
        Sha256::from_bytes([
            0xB6, 0x3D, 0x41, 0x67, 0x44, 0xE7, 0x09, 0x8B, 0xF9, 0xEC, 0x2C, 0xAA, 0x59, 0x6A,
            0x93, 0xBC, 0x24, 0x68, 0xE3, 0x7F, 0x82, 0x84, 0xBA, 0x65, 0xEC, 0xC0, 0x61, 0x71,
            0x1B, 0xCB, 0xAA, 0x18,
        ]),
    ),
    (
        "EU list of the lists signer 6",
        Sha256::from_bytes([
            0x23, 0x61, 0x03, 0xF0, 0x3A, 0x80, 0x31, 0xAE, 0x8F, 0x47, 0xF9, 0x05, 0x9B, 0xF8,
            0xDE, 0x38, 0x56, 0x4C, 0xDB, 0xFE, 0xBE, 0xDD, 0xE4, 0xA5, 0x97, 0xD5, 0x0F, 0x89,
            0x80, 0xAA, 0x65, 0x3B,
        ]),
    ),
];

/// Embedded DER for every certificate in [`LOTL_SIGNER_SHA256`], in
/// the same order; the fingerprints are cross-checked at test time.
pub const LOTL_SIGNER_DER: &[(&str, &[u8])] = &[
    (
        "EU list of the lists signer 1",
        include_bytes!("../trust-anchors/eu-lotl-signer-1.der"),
    ),
    (
        "EU list of the lists signer 2",
        include_bytes!("../trust-anchors/eu-lotl-signer-2.der"),
    ),
    (
        "EU list of the lists signer 3",
        include_bytes!("../trust-anchors/eu-lotl-signer-3.der"),
    ),
    (
        "EU list of the lists signer 4",
        include_bytes!("../trust-anchors/eu-lotl-signer-4.der"),
    ),
    (
        "EU list of the lists signer 5",
        include_bytes!("../trust-anchors/eu-lotl-signer-5.der"),
    ),
    (
        "EU list of the lists signer 6",
        include_bytes!("../trust-anchors/eu-lotl-signer-6.der"),
    ),
];

#[cfg(test)]
mod tests {
    use super::{LOTL_SIGNER_DER, LOTL_SIGNER_SHA256};
    use crate::test_util::{TestResult, check, check_true};
    use refineid_digest::Sha256;

    /// The embedded DER of each LOTL signer must hash to the pinned
    /// fingerprint, and each must parse as a certificate. A mismatch
    /// means somebody swapped a file in `trust-anchors/` without
    /// updating the pin (or vice versa).
    #[test]
    fn lotl_signer_fingerprints_match_pins() -> TestResult {
        check(
            &LOTL_SIGNER_DER.len(),
            &LOTL_SIGNER_SHA256.len(),
            "LOTL_SIGNER_DER and LOTL_SIGNER_SHA256 must have the same length",
        )?;
        for ((label_der, der), (label_pin, pin)) in
            LOTL_SIGNER_DER.iter().zip(LOTL_SIGNER_SHA256.iter())
        {
            check(label_der, label_pin, "label order must match")?;
            check(
                &Sha256::of(der),
                pin,
                &format!("fingerprint mismatch for {label_der}"),
            )?;
            check_true(
                refineid_cms::x509::OwnedCert::from_der(der).is_ok(),
                &format!("{label_der} parses as a certificate"),
            )?;
        }
        Ok(())
    }

    /// The shipped directory holds the LOTL signers and nothing else:
    /// every certificate the crate embeds from it is in the table.
    #[test]
    fn the_lotl_signers_are_the_only_shipped_certificates() -> TestResult {
        let mut shipped: Vec<String> =
            std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/trust-anchors"))?
                .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
                .collect::<Result<_, std::io::Error>>()?;
        shipped.sort();
        let listed: Vec<String> = (1..=LOTL_SIGNER_DER.len())
            .map(|index| format!("eu-lotl-signer-{index}.der"))
            .collect();
        check(
            &shipped,
            &listed,
            "shipped certificates are the LOTL signers",
        )
    }
}
