// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! A live revocation answer for a judged signature whose file says
//! nothing about its signer's status.
//!
//! [`live_revocation`] asks the responders each certificate of the
//! signature's anchored path names -- OCSP first (RFC 6960), then the
//! CRL distribution points (RFC 5280 sec.4.2.1.13) -- adds what they
//! answer to an evidence pool beside the path and the anchors, and
//! judges the signer again with the verifier's own trust judgement, the
//! path at the report's validation time and the answers' freshness at
//! `now`. Each answer is held to what the signing flow holds its own
//! to: signed by the issuer or its delegated responder, about this
//! certificate, current at `now`, and for OCSP echoing the request's
//! nonce. A responder that does not answer, or answers with something
//! that does not hold up, adds nothing and the next address is asked;
//! with no usable answer the status is [`Revocation::Unavailable`],
//! never guessed.
//!
//! This is the one place the verifier goes to the network, and only on
//! the caller's request: the result is what
//! [`super::DocumentReport::with_live_revocation`] takes.

use super::SignatureReport;
use super::trust::{self, AnchorRole, CertificationPath, MaterialPool, Revocation, TrustAnchors};
use crate::http;
use crate::material::{MaterialError, NoncePolicy, check_crl, check_response};
use crate::ocsp;
use crate::uri::Uri;
use crate::validation::ValidationMaterial;
use crate::x509_ext::CertificateExt;
use refineid_cms::x509::{Certificate, DateTime};

/// Most bytes read from one OCSP responder: a signed answer with a
/// responder certificate chain fits with room to spare.
const MAX_OCSP_BYTES: usize = 64 * 1024;

/// Most bytes read from one CRL distribution point.
const MAX_CRL_BYTES: usize = 1024 * 1024;

/// Most addresses of one kind asked per certificate, so a certificate
/// naming many cannot turn a lookup into a long series of timeouts.
const MAX_ADDRESSES: usize = 3;

/// The media type of an OCSP request (RFC 6960 appendix C.1).
const OCSP_REQUEST_TYPE: &str = "application/ocsp-request";

/// The revocation status of `report`'s signer now, from its
/// responders: what [`super::DocumentReport::with_live_revocation`]
/// takes, as `report.with_live_revocation(|signature|
/// live_revocation(signature, anchors, now))`.
///
/// [`Revocation::Unavailable`] for a signature whose path is not
/// anchored, and whenever no current verified answer arrives.
#[must_use]
pub fn live_revocation(
    report: &SignatureReport,
    anchors: &TrustAnchors,
    now: DateTime,
) -> Revocation {
    live_revocation_from(report, anchors, now, &HttpAnswers)
}

/// Where the bytes of answers come from: one exchange per address,
/// unverified.
pub(super) trait AnswerSource {
    /// The body an OCSP responder at `url` answers `request` with.
    fn ocsp(&self, url: &Uri, request: &[u8]) -> Option<Vec<u8>>;

    /// The body a CRL distribution point at `url` serves.
    fn crl(&self, url: &Uri) -> Option<Vec<u8>>;
}

/// The responders the certificate names, over [`crate::http`].
struct HttpAnswers;

impl AnswerSource for HttpAnswers {
    fn ocsp(&self, url: &Uri, request: &[u8]) -> Option<Vec<u8>> {
        http::post(url, OCSP_REQUEST_TYPE, request, MAX_OCSP_BYTES).ok()
    }

    fn crl(&self, url: &Uri) -> Option<Vec<u8>> {
        http::get(url, MAX_CRL_BYTES).ok()
    }
}

/// The first usable answer about `subject`, issued by `issuer`, at
/// `now`: each OCSP responder in turn, then each CRL distribution
/// point, at most [`MAX_ADDRESSES`] of each. An answer is usable when
/// it holds up as the signing flow holds a timestamp authority's
/// answers ([`check_response`] accepting a pre-produced answer that
/// echoes no nonce but refusing a changed one, [`check_crl`]) and says
/// good or revoked; anything else moves to the next address.
fn first_usable_answer(
    source: &impl AnswerSource,
    subject: &Certificate<'_>,
    issuer: &Certificate<'_>,
    now: DateTime,
) -> ValidationMaterial {
    let mut material = ValidationMaterial::default();
    let name_hash = ocsp::IssuerNameHash::from_name(subject.issuer);
    let key_hash = ocsp::IssuerKeyHash::from_subject_public_key(&issuer.spki);
    for url in subject.ocsp_urls().into_iter().take(MAX_ADDRESSES) {
        let Ok(nonce) = ocsp::OcspNonce::random() else {
            break;
        };
        let request =
            ocsp::build_request_with_nonce(name_hash, key_hash, &subject.serial(), &nonce);
        let Some(response) = source.ocsp(&url, request.as_der()) else {
            continue;
        };
        if usable(check_response(
            NoncePolicy::AllowMissingEcho,
            &response,
            subject,
            issuer,
            &nonce,
            now,
        )) {
            material.ocsp_responses.push(response);
            return material;
        }
    }
    for url in subject
        .crl_distribution_urls()
        .into_iter()
        .take(MAX_ADDRESSES)
    {
        let Some(list) = source.crl(&url) else {
            continue;
        };
        if usable(check_crl(&list, subject, issuer, now)) {
            material.crls.push(list);
            return material;
        }
    }
    material
}

/// Whether a checked answer speaks: good, or revoked.
fn usable(checked: Result<(), MaterialError>) -> bool {
    matches!(checked, Ok(()) | Err(MaterialError::Revoked { .. }))
}

/// [`live_revocation`] with its answers from `source`.
pub(super) fn live_revocation_from(
    report: &SignatureReport,
    anchors: &TrustAnchors,
    now: DateTime,
    source: &impl AnswerSource,
) -> Revocation {
    let CertificationPath::Anchored(path) = report.chain() else {
        return Revocation::Unavailable;
    };
    let signer = report.signer_certificate();
    let mut pool = MaterialPool::new();
    pool.add_anchors(anchors);
    for certificate in path {
        pool.add_certificate(certificate.clone());
    }
    let links: Vec<_> = core::iter::once(signer).chain(path.iter()).collect();
    for pair in links.windows(2) {
        if let [subject, issuer] = pair {
            pool.add_material(&first_usable_answer(
                source,
                &subject.view(),
                &issuer.view(),
                now,
            ));
        }
    }
    let verdict = trust::judge(
        signer,
        &pool,
        anchors,
        AnchorRole::CertificateIssuing,
        // The path is judged where the report judged it, at the proof
        // of existence or the caller's clock (ETSI EN 319 102-1 clause
        // 5.2.4); the answers' freshness at `now`.
        trust::When {
            at: report.validation_time(),
            now,
        },
    );
    if verdict.path.is_anchored() {
        verdict.revocation
    } else {
        Revocation::Unavailable
    }
}
