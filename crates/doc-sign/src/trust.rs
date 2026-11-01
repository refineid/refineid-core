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

//! Pinned trust anchors for cert-chain verification.
//!
//! Pin tables hold typed [`Sha256`] values rather than raw
//! `[u8; 32]` so the type system enforces "compare a SHA-256
//! against a SHA-256 pin" -- mixing a different-shape hash
//! against a pin won't compile. See
//! [`doc/typing-discipline.md`][typing] and
//! [`doc/fineid-s2-cert-profile.md`][s2] for the broader
//! framing.
//!
//! The pin tables are the only trust anchors. The on-card root
//! cert at `EF.4334` and the issuing CA at `EF.4336` are
//! distribution copies: [`crate::trust_roots`] admits them only
//! when the root's SHA-256 is in [`PINNED_ROOT_SHA256`] and the
//! issuing CA chains to it, and no lookup here consults that
//! cache. A card with a substituted root cert therefore cannot
//! fool the verifier, and nothing an application injects at
//! start can widen the anchor set.
//!
//! DVV runs **two parallel G3 roots** since 2021-05-06, one
//! per key family (RSA / ECC). Both are pinned: an RSA-keyed
//! citizen card chains to `DVV Gov. Root CA - G3 RSA`, an
//! ECC-keyed card chains to `DVV Gov. Root CA - G3 ECC`, and
//! the two roots have different SHA-256 fingerprints.
//! Refusing one would silently break half the in-field
//! citizen-card population.
//!
//! [typing]: ../../../../doc/typing-discipline.md
//! [s2]: ../../../../doc/fineid-s2-cert-profile.md

use refineid_digest::Sha256;

/// Accepted on-card root certs as `(label, sha256)` pairs.
///
/// The label is the DVV-published canonical name and is
/// surfaced in trust attestations / audit events. Empty list
/// = "trust whatever the card publishes" -- never the
/// production default.
///
/// Fingerprints sourced from FINEID S2 v5.2 §8.2 (Root and
/// CA Certificate Fingerprints). Cross-checked against a
/// live OMNIKEY card (G3 RSA root) on 2026-05-23.
pub const PINNED_ROOT_SHA256: &[(&str, Sha256)] = &[
    (
        "DVV Gov. Root CA - G3 RSA",
        Sha256::from_bytes([
            0xD3, 0xED, 0x3F, 0xC4, 0x0A, 0xD2, 0x6B, 0x52, 0xE0, 0x01, 0xE1, 0xE1, 0x8F, 0x4B,
            0x94, 0x49, 0x52, 0x9D, 0xEB, 0x75, 0xA8, 0x1D, 0x5E, 0xB6, 0x80, 0xD7, 0xB6, 0x2D,
            0xB2, 0x3B, 0xA9, 0x6D,
        ]),
    ),
    (
        "DVV Gov. Root CA - G3 ECC",
        Sha256::from_bytes([
            0x55, 0x46, 0xA5, 0x25, 0x04, 0xFB, 0xA7, 0x4F, 0x61, 0xFF, 0xD4, 0x89, 0x00, 0x67,
            0x52, 0x9A, 0xDE, 0x3B, 0x9C, 0x9D, 0x07, 0xE5, 0x02, 0x59, 0x28, 0x31, 0xCC, 0xDA,
            0x9B, 0x36, 0x9F, 0xD3,
        ]),
    ),
];

/// `true` if `fingerprint` matches one of the pinned roots.
#[must_use]
pub fn is_pinned_root(fingerprint: Sha256) -> bool {
    PINNED_ROOT_SHA256
        .iter()
        .any(|(_, pinned)| *pinned == fingerprint)
}

/// Return the label of the pinned root matching
/// `fingerprint`, or `None` if no pin matches.
#[must_use]
pub fn pinned_root_label(fingerprint: Sha256) -> Option<&'static str> {
    PINNED_ROOT_SHA256
        .iter()
        .find(|(_, fp)| *fp == fingerprint)
        .map(|(label, _)| *label)
}

/// Embedded DER bytes for every pinned DVV root CA.
///
/// `PINNED_ROOT_SHA256` carries the fingerprint pins (one-way
/// hash); this table additionally embeds the actual cert DER so
/// the cert-chain walker can use any pinned root as a trust
/// anchor when the relevant on-card root is missing or carries
/// the wrong algorithm.
///
/// Motivating case: FINEID S4-1 v4.2 §4.5 says **both** the G3
/// ECC and G3 RSA roots should be stored on the card, but DVV's
/// in-field 2026-vintage citizen cards ship with only the
/// primary G3 ECC root in EF.4334. The RSA-3072 backup cert in
/// EF.4333 chains to the G3 RSA root which is *not* on the
/// card. Without this embedded DER, the chain walker would
/// fail at the intermediate->root hop ("issuer SPKI shape
/// doesn't match the signature alg") because it tried to verify
/// an RSA-signed intermediate against the on-card ECC root.
///
/// Both DERs are public DVV CA certs sourced from
/// `proxy.fineid.fi/ca/dvvroot3ec.crt` and
/// `proxy.fineid.fi/ca/dvvroot3rc.crt` (FINEID S2 v5.2 §8.5
/// canonical URLs). Bit-identical to the on-card EF.4334 copy
/// for the ECC root, verified 2026-05-28. Fingerprints
/// cross-checked against [`PINNED_ROOT_SHA256`] at test time.
pub const PINNED_ROOT_DER: &[(&str, &[u8])] = &[
    (
        "DVV Gov. Root CA - G3 RSA",
        include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der"),
    ),
    (
        "DVV Gov. Root CA - G3 ECC",
        include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-ecc.der"),
    ),
];

/// Return the embedded DER bytes of the pinned root with the
/// given SHA-256 fingerprint, or `None` if no pin matches.
///
/// Used by the cert-chain walker as a fallback trust anchor
/// when the on-card root cert isn't the right one for the
/// chain under verification (e.g. an RSA intermediate signed
/// by the G3 RSA root on a card that only carries the G3 ECC
/// root in EF.4334).
#[must_use]
pub fn pinned_root_der_by_fingerprint(fingerprint: Sha256) -> Option<&'static [u8]> {
    PINNED_ROOT_SHA256
        .iter()
        .zip(PINNED_ROOT_DER.iter())
        .find(|((_, fp), _)| *fp == fingerprint)
        .map(|(_, (_, der))| *der)
}

/// Accepted qualified Time Stamping Authority (TSA) root certs as
/// `(label, sha256)` pairs.
///
/// Fingerprints sourced from Sectigo official root publication
/// and verified against the canonical DER at
/// `https://crt.sectigo.com/SectigoQualifiedTimeStampingRootR45.crt`.
pub const PINNED_TSA_ROOT_SHA256: &[(&str, Sha256)] = &[(
    "Sectigo Qualified Time Stamping Root R45",
    Sha256::from_bytes([
        0xF8, 0x71, 0xF8, 0x97, 0x6B, 0x40, 0x68, 0xD7, 0x00, 0xD5, 0xF2, 0x81, 0x08, 0x4B, 0x4A,
        0x29, 0xEA, 0xF4, 0xB8, 0xF3, 0x57, 0x43, 0x33, 0x0B, 0xA0, 0x62, 0xFA, 0xB4, 0x6F, 0x58,
        0xC2, 0xED,
    ]),
)];

/// Embedded DER bytes for every pinned TSA root CA.
pub const PINNED_TSA_ROOT_DER: &[(&str, &[u8])] = &[(
    "Sectigo Qualified Time Stamping Root R45",
    include_bytes!("../trust-anchors/sectigo-qualified-time-stamping-root-r45.der"),
)];

/// `true` if `fingerprint` matches one of the pinned TSA roots.
#[must_use]
pub fn is_pinned_tsa_root(fingerprint: Sha256) -> bool {
    PINNED_TSA_ROOT_SHA256
        .iter()
        .any(|(_, pinned)| *pinned == fingerprint)
}

/// Return the label of the pinned TSA root matching
/// `fingerprint`, or `None` if no pin matches.
#[must_use]
pub fn pinned_tsa_root_label(fingerprint: Sha256) -> Option<&'static str> {
    PINNED_TSA_ROOT_SHA256
        .iter()
        .find(|(_, fp)| *fp == fingerprint)
        .map(|(label, _)| *label)
}

/// Return the embedded DER bytes of the pinned TSA root with the
/// given SHA-256 fingerprint, or `None` if no pin matches.
#[must_use]
pub fn pinned_tsa_root_der_by_fingerprint(fingerprint: Sha256) -> Option<&'static [u8]> {
    PINNED_TSA_ROOT_SHA256
        .iter()
        .zip(PINNED_TSA_ROOT_DER.iter())
        .find(|((_, fp), _)| *fp == fingerprint)
        .map(|(_, (_, der))| *der)
}

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
    use super::{
        LOTL_SIGNER_DER, LOTL_SIGNER_SHA256, PINNED_ROOT_DER, PINNED_ROOT_SHA256,
        PINNED_TSA_ROOT_DER, PINNED_TSA_ROOT_SHA256, is_pinned_root, is_pinned_tsa_root,
        pinned_root_der_by_fingerprint, pinned_root_label, pinned_tsa_root_der_by_fingerprint,
        pinned_tsa_root_label,
    };
    use crate::test_util::{TestResult, check, check_true};
    use refineid_digest::Sha256;

    /// The embedded DER bytes for each pinned root must hash to
    /// the fingerprint stated in `PINNED_ROOT_SHA256`. A mismatch
    /// means somebody swapped the file in `trust-anchors/`
    /// without updating the pin (or vice versa); the chain
    /// walker would then verify against an unpinned anchor.
    #[test]
    fn pinned_der_fingerprints_match_pins() -> TestResult {
        check(
            &PINNED_ROOT_DER.len(),
            &PINNED_ROOT_SHA256.len(),
            "PINNED_ROOT_DER and PINNED_ROOT_SHA256 must have the same length",
        )?;
        for ((label_der, der), (label_pin, pin)) in
            PINNED_ROOT_DER.iter().zip(PINNED_ROOT_SHA256.iter())
        {
            check(label_der, label_pin, "label order must match")?;
            let computed = Sha256::of(der);
            check(
                &computed,
                pin,
                &format!("fingerprint mismatch for {label_der}"),
            )?;
        }
        Ok(())
    }

    /// `pinned_root_der_by_fingerprint` returns the right DER
    /// for a known pin and `None` for an unknown one.
    #[test]
    fn lookup_by_fingerprint_round_trips() -> TestResult {
        for (label, pin) in PINNED_ROOT_SHA256 {
            let der = pinned_root_der_by_fingerprint(*pin)
                .ok_or_else(|| format!("DER missing for pin labelled {label}"))?;
            let recomputed = Sha256::of(der);
            check(&recomputed, pin, &format!("recompute for {label}"))?;
        }
        let bogus = Sha256::from_bytes([0_u8; 32]);
        check_true(
            pinned_root_der_by_fingerprint(bogus).is_none(),
            "bogus pin returns None",
        )
    }

    /// Only the pin table answers: every pinned fingerprint is a
    /// root, and a well-formed certificate outside the table (the
    /// TSA root) is not, whatever any cache holds.
    #[test]
    fn is_pinned_root_true_only_for_pin_table() -> TestResult {
        for (label, pin) in PINNED_ROOT_SHA256 {
            check_true(is_pinned_root(*pin), &format!("{label} is pinned"))?;
        }
        let tsa_root = Sha256::of(PINNED_TSA_ROOT_DER[0].1);
        check_true(
            !is_pinned_root(tsa_root),
            "a certificate outside the pin table is not a root",
        )?;
        let bogus = Sha256::from_bytes([0_u8; 32]);
        check_true(!is_pinned_root(bogus), "bogus fingerprint is not a root")
    }

    /// The label comes from the pin table and from nowhere else.
    #[test]
    fn pinned_root_label_only_from_pin_table() -> TestResult {
        for (label, pin) in PINNED_ROOT_SHA256 {
            check(
                &pinned_root_label(*pin),
                &Some(*label),
                "label of a pinned root",
            )?;
        }
        let tsa_root = Sha256::of(PINNED_TSA_ROOT_DER[0].1);
        check(
            &pinned_root_label(tsa_root),
            &None,
            "no label for a certificate outside the pin table",
        )
    }

    /// The embedded DER bytes for each pinned TSA root must hash to
    /// the fingerprint stated in `PINNED_TSA_ROOT_SHA256`.
    #[test]
    fn pinned_tsa_der_fingerprints_match_pins() -> TestResult {
        check(
            &PINNED_TSA_ROOT_DER.len(),
            &PINNED_TSA_ROOT_SHA256.len(),
            "PINNED_TSA_ROOT_DER and PINNED_TSA_ROOT_SHA256 must have the same length",
        )?;
        for ((label_der, der), (label_pin, pin)) in PINNED_TSA_ROOT_DER
            .iter()
            .zip(PINNED_TSA_ROOT_SHA256.iter())
        {
            check(label_der, label_pin, "label order must match")?;
            let computed = Sha256::of(der);
            check(
                &computed,
                pin,
                &format!("fingerprint mismatch for {label_der}"),
            )?;
        }
        Ok(())
    }

    /// `pinned_tsa_root_der_by_fingerprint` and `is_pinned_tsa_root` round-trip.
    #[test]
    fn tsa_lookup_by_fingerprint_round_trips() -> TestResult {
        for (label, pin) in PINNED_TSA_ROOT_SHA256 {
            let der = pinned_tsa_root_der_by_fingerprint(*pin)
                .ok_or_else(|| format!("DER missing for pin labelled {label}"))?;
            let recomputed = Sha256::of(der);
            check(&recomputed, pin, &format!("recompute for {label}"))?;
            check(
                &pinned_tsa_root_label(*pin),
                &Some(*label),
                "pinned_tsa_root_label matches label",
            )?;
            check_true(is_pinned_tsa_root(*pin), "is_pinned_tsa_root true for pin")?;
        }
        let bogus = Sha256::from_bytes([0_u8; 32]);
        check_true(
            pinned_tsa_root_der_by_fingerprint(bogus).is_none(),
            "bogus pin returns None",
        )?;
        check_true(
            !is_pinned_tsa_root(bogus),
            "is_pinned_tsa_root false for bogus",
        )?;
        check(
            &pinned_tsa_root_label(bogus),
            &None,
            "pinned_tsa_root_label None for bogus",
        )
    }

    /// The embedded DER of each LOTL signer must hash to the pinned
    /// fingerprint, and each must parse as a certificate.
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
}
