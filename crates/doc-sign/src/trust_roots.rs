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

//! Distribution cache for the FINEID root and issuing CA certificates.
//!
//! The certificates arrive from the card (`EF.4334` for the root CA,
//! `EF.4336` for the issuing CA) or from the application when it starts,
//! for example over RAPP. The source is a distribution channel, never a
//! trust decision: a collection exists only once [`RootCertificates::admit`]
//! has checked the root against the pin table in [`crate::trust`] and the
//! issuing CA against that root. The pin table alone decides what anchors a
//! chain; this module hands out the matching DER for distribution.
//!
//! The admitted collection is held in a `OnceLock` so every later lookup
//! is instant and thread-safe.

use core::fmt;
use std::sync::OnceLock;

#[cfg(feature = "pcsc")]
use refineid_apdu::CardTransport;
use refineid_cms::x509::{OwnedCert, PathExtensionError, path_extension_profile};
use refineid_digest::Sha256;
#[cfg(feature = "pcsc")]
use refineid_pkcs15::{CertSlot, Pkcs15Ops};

use crate::trust::PINNED_ROOT_SHA256;

/// Global in-memory cache of the admitted collection.
static ROOT_CERTIFICATES: OnceLock<Box<RootCertificates>> = OnceLock::new();

/// Why a certificate collection was refused at admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRootError {
    /// Neither a root nor an issuing CA certificate was supplied.
    Empty,
    /// The root certificate does not parse as an X.509 certificate.
    RootMalformed,
    /// The root certificate's SHA-256 is not in the pin table.
    RootNotPinned,
    /// An issuing CA certificate was supplied without a root to check it against.
    IntermediateWithoutRoot,
    /// The issuing CA certificate does not parse as an X.509 certificate.
    IntermediateMalformed,
    /// The issuing CA certificate is not named and signed by the admitted root.
    IntermediateNotIssuedByRoot,
    /// The issuing CA certificate's extensions are malformed, duplicated,
    /// or carry a critical extension the path policy does not handle.
    IntermediateExtensions(PathExtensionError),
    /// The issuing CA certificate is not a CA: Basic Constraints is absent
    /// or `cA` is false, or Key Usage is present without `keyCertSign`.
    IntermediateNotCa,
}

impl fmt::Display for TrustRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "no CA certificate supplied",
            Self::RootMalformed => "root CA certificate does not parse",
            Self::RootNotPinned => "root CA certificate is not a pinned root",
            Self::IntermediateWithoutRoot => "issuing CA certificate supplied without a root",
            Self::IntermediateMalformed => "issuing CA certificate does not parse",
            Self::IntermediateNotIssuedByRoot => {
                "issuing CA certificate is not issued by the pinned root"
            }
            Self::IntermediateExtensions(error) => {
                return write!(f, "issuing CA certificate extensions: {error}");
            }
            Self::IntermediateNotCa => "issuing CA certificate is not a CA",
        })
    }
}

impl std::error::Error for TrustRootError {}

/// A pinned root CA certificate and, optionally, the issuing CA it signed.
///
/// A value exists only through [`RootCertificates::admit`], so holding one
/// proves the root is in [`PINNED_ROOT_SHA256`] and the issuing CA, when
/// present, chains to it.
#[derive(Debug)]
pub struct RootCertificates {
    /// The pinned root CA certificate (`EF.4334`).
    root_ca: OwnedCert,
    /// The issuing CA certificate (`EF.4336`), signed by `root_ca`.
    intermediate_ca: Option<OwnedCert>,
}

impl RootCertificates {
    /// Admit a root and an optional issuing CA certificate, both as DER.
    ///
    /// The root must parse and its SHA-256 must match an entry of
    /// [`PINNED_ROOT_SHA256`]. The issuing CA, when present, must parse,
    /// name the root as its issuer, carry a signature the root's key
    /// verifies, and be a CA under the path policy: Basic Constraints with
    /// `cA` true, Key Usage (when present) with `keyCertSign`, and no
    /// unsupported critical extension (RFC 5280 sections 4.2.1.3, 4.2.1.9
    /// and 4.2). An issuing CA without a root has nothing to chain to and
    /// is refused.
    ///
    /// Validity in time is not checked here: this is distribution
    /// material, and the chain walker that makes the trust decision
    /// checks validity against its own reference time.
    ///
    /// # Errors
    /// [`TrustRootError`] naming the first failed check.
    pub fn admit(
        root_ca: Option<Vec<u8>>,
        intermediate_ca: Option<Vec<u8>>,
    ) -> Result<Self, TrustRootError> {
        let root_der = match (root_ca, intermediate_ca.is_some()) {
            (Some(root), _) => root,
            (None, true) => return Err(TrustRootError::IntermediateWithoutRoot),
            (None, false) => return Err(TrustRootError::Empty),
        };
        let root_ca =
            OwnedCert::from_der(&root_der).map_err(|_err| TrustRootError::RootMalformed)?;
        let root_fingerprint = Sha256::of(root_ca.as_der());
        if !PINNED_ROOT_SHA256
            .iter()
            .any(|(_label, pinned)| *pinned == root_fingerprint)
        {
            return Err(TrustRootError::RootNotPinned);
        }
        let intermediate_ca = match intermediate_ca {
            None => None,
            Some(der) => {
                let intermediate = OwnedCert::from_der(&der)
                    .map_err(|_err| TrustRootError::IntermediateMalformed)?;
                let root_view = root_ca.view();
                let intermediate_view = intermediate.view();
                if intermediate_view.issuer != root_view.subject
                    || intermediate_view.verify_signed_by(root_view).is_err()
                {
                    return Err(TrustRootError::IntermediateNotIssuedByRoot);
                }
                let profile = path_extension_profile(intermediate_view.extensions.unwrap_or(&[]))
                    .map_err(TrustRootError::IntermediateExtensions)?;
                let constraints = profile.basic_constraints;
                let signs_certificates = profile
                    .key_usage
                    .is_none_or(|usage| usage.key_usage.key_cert_sign);
                if !constraints.present || !constraints.ca || !signs_certificates {
                    return Err(TrustRootError::IntermediateNotCa);
                }
                Some(intermediate)
            }
        };
        Ok(Self {
            root_ca,
            intermediate_ca,
        })
    }

    /// The DER of every admitted certificate, root first.
    #[must_use]
    pub fn certs(&self) -> Vec<&[u8]> {
        let mut list = vec![self.root_ca.as_der()];
        if let Some(intermediate) = &self.intermediate_ca {
            list.push(intermediate.as_der());
        }
        list
    }

    /// Encodes the admitted certificates into a PKCS#7 (CMS)
    /// certs-only `SignedData` structure for distribution.
    #[must_use]
    pub fn to_pkcs7_bundle(&self) -> Vec<u8> {
        let certs = self.certs();
        build_pkcs7_certs_bundle(&certs)
    }
}

/// Stores an admitted collection into the global in-memory cache.
///
/// # Errors
///
/// Returns `Err("already initialized")` if the cache was previously set.
pub fn set_root_certificates(roots: RootCertificates) -> Result<(), &'static str> {
    ROOT_CERTIFICATES
        .set(Box::new(roots))
        .map_err(|_| "already initialized")
}

/// Returns a reference to the cached collection, if one was admitted.
#[must_use]
pub fn active_root_certificates() -> Option<&'static RootCertificates> {
    ROOT_CERTIFICATES.get().map(|b| &**b)
}

/// Reads the root CA and issuing CA from the card, admits them, and
/// populates the global in-memory cache.
///
/// If the cache is already populated, returns the cached instance
/// immediately. A collection the card supplies that fails admission is
/// not cached and `None` is returned.
#[cfg(feature = "pcsc")]
pub fn fetch_and_cache_from_card<T: CardTransport>(
    transport: &mut T,
) -> Option<&'static RootCertificates> {
    if let Some(cached) = active_root_certificates() {
        return Some(cached);
    }

    let root_ca = transport
        .read_certificate(CertSlot::RootCa)
        .ok()
        .map(|c| c.as_bytes().to_vec());
    let intermediate_ca = transport
        .read_certificate(CertSlot::IssuingCaEcc)
        .ok()
        .map(|c| c.as_bytes().to_vec());

    let roots = RootCertificates::admit(root_ca, intermediate_ca).ok()?;
    let _already_set = set_root_certificates(roots);

    active_root_certificates()
}

/// Encodes a sequence of X.509 DER certificates into a PKCS#7 (CMS)
/// certs-only `SignedData` structure.
#[must_use]
pub fn build_pkcs7_certs_bundle(certs: &[&[u8]]) -> Vec<u8> {
    let mut certificates_bytes = Vec::new();
    for cert in certs {
        certificates_bytes.extend_from_slice(cert);
    }

    let certificates_tagged = encode_tlv(0xA0, &certificates_bytes);

    let signed_data_version = vec![0x02, 0x01, 0x01];
    let digest_algorithms_empty_set = vec![0x31, 0x00];
    let content_info_pkcs7_data = vec![
        0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    ];
    let signer_infos_empty_set = vec![0x31, 0x00];

    let mut signed_data_content = Vec::new();
    signed_data_content.extend_from_slice(&signed_data_version);
    signed_data_content.extend_from_slice(&digest_algorithms_empty_set);
    signed_data_content.extend_from_slice(&content_info_pkcs7_data);
    signed_data_content.extend_from_slice(&certificates_tagged);
    signed_data_content.extend_from_slice(&signer_infos_empty_set);

    let signed_data_seq = encode_tlv(0x30, &signed_data_content);
    let signed_data_oid = vec![
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];
    let content_explicit = encode_tlv(0xA0, &signed_data_seq);

    let mut content_info_content = Vec::new();
    content_info_content.extend_from_slice(&signed_data_oid);
    content_info_content.extend_from_slice(&content_explicit);

    encode_tlv(0x30, &content_info_content)
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    let len = value.len();
    if let Ok(l) = u8::try_from(len) {
        if l >= 0x80 {
            out.push(0x81);
        }
        out.push(l);
    } else if let Ok(l) = u16::try_from(len) {
        out.push(0x82);
        out.extend_from_slice(&l.to_be_bytes());
    } else if let Ok(l) = u32::try_from(len) {
        if l <= 0x00FF_FFFF {
            out.push(0x83);
            out.extend_from_slice(&l.to_be_bytes()[1..]);
        } else {
            out.push(0x84);
            out.extend_from_slice(&l.to_be_bytes());
        }
    }
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        RootCertificates, TrustRootError, active_root_certificates, build_pkcs7_certs_bundle,
        set_root_certificates,
    };
    use crate::test_util::{TestResult, check, check_true};
    use crate::trust::{
        PINNED_ROOT_DER, PINNED_ROOT_SHA256, PINNED_TSA_ROOT_DER, is_pinned_root, pinned_root_label,
    };
    use refineid_digest::Sha256;

    /// A well-formed certificate that is not a pinned FINEID root.
    fn unpinned_certificate() -> Vec<u8> {
        PINNED_TSA_ROOT_DER[0].1.to_vec()
    }

    fn pinned_root(index: usize) -> Vec<u8> {
        PINNED_ROOT_DER[index].1.to_vec()
    }

    #[test]
    fn admit_accepts_every_pinned_root() -> TestResult {
        for (label, der) in PINNED_ROOT_DER {
            let roots = RootCertificates::admit(Some(der.to_vec()), None)
                .map_err(|error| format!("{label}: {error}"))?;
            check(&roots.certs(), &vec![*der], &format!("{label}: root DER"))?;
        }
        Ok(())
    }

    #[test]
    fn admit_refuses_unpinned_root() -> TestResult {
        let refused = RootCertificates::admit(Some(unpinned_certificate()), None)
            .err()
            .ok_or("an unpinned root must be refused")?;
        check(&refused, &TrustRootError::RootNotPinned, "unpinned root")
    }

    #[test]
    fn admit_refuses_malformed_root() -> TestResult {
        let refused = RootCertificates::admit(Some(b"not a certificate".to_vec()), None)
            .err()
            .ok_or("bytes that are not a certificate must be refused")?;
        check(&refused, &TrustRootError::RootMalformed, "malformed root")
    }

    #[test]
    fn admit_refuses_empty_collection() -> TestResult {
        let refused = RootCertificates::admit(None, None)
            .err()
            .ok_or("an empty collection must be refused")?;
        check(&refused, &TrustRootError::Empty, "empty collection")
    }

    #[test]
    fn admit_refuses_intermediate_without_root() -> TestResult {
        let refused = RootCertificates::admit(None, Some(pinned_root(0)))
            .err()
            .ok_or("an issuing CA without a root must be refused")?;
        check(
            &refused,
            &TrustRootError::IntermediateWithoutRoot,
            "intermediate without root",
        )
    }

    #[test]
    fn admit_refuses_intermediate_not_issued_by_root() -> TestResult {
        // The two pinned roots are each self-signed, so neither is
        // issued by the other.
        let refused = RootCertificates::admit(Some(pinned_root(0)), Some(pinned_root(1)))
            .err()
            .ok_or("an issuing CA the root did not sign must be refused")?;
        check(
            &refused,
            &TrustRootError::IntermediateNotIssuedByRoot,
            "intermediate not issued by root",
        )
    }

    #[test]
    fn admit_refuses_malformed_intermediate() -> TestResult {
        let refused =
            RootCertificates::admit(Some(pinned_root(0)), Some(b"not a certificate".to_vec()))
                .err()
                .ok_or("an issuing CA that does not parse must be refused")?;
        check(
            &refused,
            &TrustRootError::IntermediateMalformed,
            "malformed intermediate",
        )
    }

    /// No issued FINEID issuing CA certificate is in the tree, so the
    /// signature check is exercised with the self-signed root in the
    /// issuing position: it names itself as issuer and verifies under its
    /// own key.
    #[test]
    fn admit_accepts_intermediate_signed_by_root() -> TestResult {
        for (label, der) in PINNED_ROOT_DER {
            let roots = RootCertificates::admit(Some(der.to_vec()), Some(der.to_vec()))
                .map_err(|error| format!("{label}: {error}"))?;
            check(
                &roots.certs().len(),
                &2,
                &format!("{label}: two certificates"),
            )?;
        }
        Ok(())
    }

    /// The pinned root with the last octet of its signature value
    /// inverted: it still parses, still names the root as its issuer,
    /// and no longer verifies under the root's key.
    fn root_with_broken_signature(index: usize) -> Vec<u8> {
        let mut der = pinned_root(index);
        let last = der.len() - 1;
        der[last] = !der[last];
        der
    }

    #[test]
    fn admit_refuses_intermediate_with_root_issuer_name_but_foreign_signature() -> TestResult {
        for index in 0..PINNED_ROOT_DER.len() {
            let refused = RootCertificates::admit(
                Some(pinned_root(index)),
                Some(root_with_broken_signature(index)),
            )
            .err()
            .ok_or("an issuing CA the root's key does not verify must be refused")?;
            check(
                &refused,
                &TrustRootError::IntermediateNotIssuedByRoot,
                "same issuer name, foreign signature",
            )?;
        }
        Ok(())
    }

    /// With the process-global cache populated by an admitted root, the
    /// pin lookups still answer from the pin table alone.
    #[test]
    fn pin_lookups_ignore_populated_cache() -> TestResult {
        let (label, der) = PINNED_ROOT_DER[0];
        let (_pin_label, pin) = PINNED_ROOT_SHA256[0];
        let admitted = RootCertificates::admit(Some(der.to_vec()), None)?;
        // Another test in this process may have populated the cache
        // first with the same admitted root; either outcome leaves it
        // populated with pinned material.
        let _already_set = set_root_certificates(admitted);
        let cached = active_root_certificates().ok_or("cache populated")?;
        check(&cached.certs(), &vec![der], "cache holds the admitted root")?;
        check(
            &pinned_root_label(pin),
            &Some(label),
            "label from the pin table",
        )?;
        let tsa_root = Sha256::of(PINNED_TSA_ROOT_DER[0].1);
        check_true(
            !is_pinned_root(tsa_root),
            "an unpinned certificate is not a root while the cache is populated",
        )
    }

    #[test]
    fn pkcs7_bundle_carries_admitted_certificates() -> TestResult {
        let roots = RootCertificates::admit(Some(pinned_root(0)), None)?;
        let bundle = roots.to_pkcs7_bundle();
        let direct = build_pkcs7_certs_bundle(&[PINNED_ROOT_DER[0].1]);
        check(&bundle, &direct, "bundle of the admitted root")?;
        check_true(
            bundle
                .windows(PINNED_ROOT_DER[0].1.len())
                .any(|window| window == PINNED_ROOT_DER[0].1),
            "bundle embeds the root DER",
        )
    }
}
