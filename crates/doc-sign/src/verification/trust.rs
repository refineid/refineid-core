// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! Trust anchors, the validation evidence a document carries, and the
//! offline judgement of a certificate against both.
//!
//! [`TrustAnchors`] holds the certificates a relying party trusts, each
//! for one [`AnchorRole`] during the [`GrantedPeriod`]s its status was
//! granted. [`MaterialPool`] holds the certificates, OCSP responses and
//! CRLs gathered from a document and the anchors, each parsed once.
//! [`judge`] builds a path upward from a certificate through the pool
//! to an anchor of the requested role granted at the validation time,
//! and reads the revocation status of every certificate on that path
//! below the anchor from the pool's verified answers.
//!
//! # Conformance
//!
//! - `ETSI EN 319 102-1` V1.3.1 clause 5.2.6: a certificate is validated
//!   by a path to a trust anchor at the validation time, with the
//!   revocation status of every certificate on it.
//! - RFC 5280 sec.6.1: each step's issuer name equals the subject name
//!   above it, the signature verifies under the issuer key, every
//!   certificate below the anchor is valid at the validation time, and
//!   each issuer below the anchor is a CA (basicConstraints `cA`,
//!   `keyCertSign` when Key Usage is present, `pathLenConstraint`
//!   honoured). Name Constraints are not enforced, so an issuer
//!   carrying them is not used. A trust anchor is the anchor's subject
//!   name and public key (sec.6.1.1 (d)); its own validity and
//!   extensions are not consulted, its granted periods are.
//! - `ETSI EN 319 102-1` V1.3.1 clauses 5.2.5 and 5.6.2: a good answer
//!   counts when its window contains the validation time, or when it
//!   was issued at or after that time while the certificate was still
//!   valid. A verified revoked answer counts whatever its window, and
//!   carries its revocation time so the caller can weigh it against
//!   the proof of existence.
//! - RFC 6960 sec.4.2.2.2: an OCSP answer counts only when its signer
//!   is the issuer or a responder the issuer delegated
//!   ([`VerifiedOcspResponse::verify`]).
//! - RFC 5280 sec.5: a CRL counts only when the issuer signed it
//!   ([`VerifiedCrl::verify`]).

use crate::crl::{OwnedCrl, VerifiedCrl};
use crate::ocsp::{CertStatus, OcspResponseStatus, OwnedOcspResponse, VerifiedOcspResponse};
use crate::revocation::{RevocationStatus, check_against_crl};
use crate::trust::{PINNED_ROOT_DER, PINNED_TSA_ROOT_DER};
use crate::validation::ValidationMaterial;
use refineid_cms::x509::{Certificate, DateTime, OwnedCert, path_extension_profile};

/// Most certificates searched above the signer before a path is
/// abandoned. RFC 5280 sets no bound; a FINEID path is signer,
/// intermediate, root.
const MAX_PATH_DEPTH: usize = 8;

/// What a trust anchor is trusted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorRole {
    /// Issuing the certificates signatures are made under.
    CertificateIssuing,
    /// Issuing, or being, the certificates of time-stamping
    /// authorities.
    TimeStamping,
}

/// Why an anchor or a granted period was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// A period ends before it starts.
    PeriodEndsBeforeStart,
    /// An anchor names no period at all, so it is never trusted.
    NoGrantedPeriod,
}

impl core::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::PeriodEndsBeforeStart => "a granted period ends before it starts",
            Self::NoGrantedPeriod => "a trust anchor names no granted period",
        })
    }
}

impl core::error::Error for AnchorError {}

/// A period during which an anchor's status was granted, both ends
/// inclusive; open-ended when `to` is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantedPeriod {
    /// When the status was granted.
    from: DateTime,
    /// When it was withdrawn, if it was.
    to: Option<DateTime>,
}

impl GrantedPeriod {
    /// The period from `from` until `to`, or open-ended.
    ///
    /// # Errors
    /// [`AnchorError::PeriodEndsBeforeStart`] when `to` precedes `from`.
    pub fn new(from: DateTime, to: Option<DateTime>) -> Result<Self, AnchorError> {
        if to.is_some_and(|to| to < from) {
            return Err(AnchorError::PeriodEndsBeforeStart);
        }
        Ok(Self { from, to })
    }

    /// The period without bounds: from the earliest instant
    /// [`DateTime`] represents, open-ended.
    ///
    /// # Panics
    /// Never: the Unix epoch is the floor of [`DateTime`].
    #[must_use]
    pub fn unbounded() -> Self {
        Self {
            from: DateTime::from_unix_duration(core::time::Duration::ZERO)
                .expect("the Unix epoch is a DateTime"),
            to: None,
        }
    }

    /// When the status was granted.
    #[must_use]
    pub const fn from(&self) -> DateTime {
        self.from
    }

    /// When the status was withdrawn; `None` while it holds.
    #[must_use]
    pub const fn to(&self) -> Option<DateTime> {
        self.to
    }

    /// Whether `at` lies inside the period.
    fn covers(&self, at: DateTime) -> bool {
        self.from <= at && self.to.is_none_or(|to| at <= to)
    }
}

/// One certificate the relying party trusts for one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The anchor certificate; its subject and public key are the
    /// anchor.
    certificate: OwnedCert,
    /// What it is trusted for.
    role: AnchorRole,
    /// When it is trusted; never empty.
    granted: Vec<GrantedPeriod>,
}

impl TrustAnchor {
    /// Trust `certificate` for `role` during `granted`.
    ///
    /// # Errors
    /// [`AnchorError::NoGrantedPeriod`] when `granted` is empty.
    pub fn new(
        certificate: OwnedCert,
        role: AnchorRole,
        granted: Vec<GrantedPeriod>,
    ) -> Result<Self, AnchorError> {
        if granted.is_empty() {
            return Err(AnchorError::NoGrantedPeriod);
        }
        Ok(Self {
            certificate,
            role,
            granted,
        })
    }

    /// The anchor certificate.
    #[must_use]
    pub const fn certificate(&self) -> &OwnedCert {
        &self.certificate
    }

    /// What it is trusted for.
    #[must_use]
    pub const fn role(&self) -> AnchorRole {
        self.role
    }

    /// When it is trusted.
    #[must_use]
    pub fn granted(&self) -> &[GrantedPeriod] {
        &self.granted
    }

    /// Whether `certificate` carries this anchor's subject and key,
    /// and this anchor is trusted for `role` at `at`.
    fn anchors(&self, certificate: Certificate<'_>, role: AnchorRole, at: DateTime) -> bool {
        let anchor = self.certificate.view();
        self.role == role
            && self.granted.iter().any(|period| period.covers(at))
            && anchor.subject == certificate.subject
            && anchor.spki.as_der() == certificate.spki.as_der()
    }
}

/// The trust anchors a verdict is judged under, and when the lists
/// they came from were fetched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchors {
    /// Every anchor.
    anchors: Vec<TrustAnchor>,
    /// When the shell fetched the lists the anchors came from; `None`
    /// for anchors that come from no list.
    fetched_at: Option<DateTime>,
}

impl TrustAnchors {
    /// Exactly these anchors, from no fetched list.
    #[must_use]
    pub const fn new(anchors: Vec<TrustAnchor>) -> Self {
        Self {
            anchors,
            fetched_at: None,
        }
    }

    /// The roots the core pins: the DVV roots for certificate issuing
    /// and the time-stamping root the signing side uses, each granted
    /// without bounds.
    #[must_use]
    pub fn pinned() -> Self {
        let issuing = PINNED_ROOT_DER
            .iter()
            .map(|(_label, der)| (*der, AnchorRole::CertificateIssuing));
        let stamping = PINNED_TSA_ROOT_DER
            .iter()
            .map(|(_label, der)| (*der, AnchorRole::TimeStamping));
        Self::new(
            issuing
                .chain(stamping)
                .filter_map(|(der, role)| {
                    let certificate = OwnedCert::from_der(der).ok()?;
                    TrustAnchor::new(certificate, role, vec![GrantedPeriod::unbounded()]).ok()
                })
                .collect(),
        )
    }

    /// These anchors, taken from lists the shell fetched at
    /// `fetched_at`.
    #[must_use]
    pub const fn fetched(mut self, fetched_at: DateTime) -> Self {
        self.fetched_at = Some(fetched_at);
        self
    }

    /// Every anchor.
    #[must_use]
    pub fn anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    /// When the lists the anchors came from were fetched.
    #[must_use]
    pub const fn fetched_at(&self) -> Option<DateTime> {
        self.fetched_at
    }

    /// Whether `certificate` is an anchor for `role` at `at`.
    #[must_use]
    pub fn is_anchor(&self, certificate: Certificate<'_>, role: AnchorRole, at: DateTime) -> bool {
        self.anchors
            .iter()
            .any(|anchor| anchor.anchors(certificate, role, at))
    }
}

/// Certificates, OCSP responses and CRLs gathered from a document and
/// its anchors, each parsed once and held once.
///
/// Entries that do not parse are left out: the pool is evidence, and
/// an unreadable item proves nothing.
#[derive(Debug, Clone, Default)]
pub struct MaterialPool {
    /// Distinct certificates.
    certificates: Vec<OwnedCert>,
    /// Distinct `OCSPResponse` structures.
    ocsp_responses: Vec<OwnedOcspResponse>,
    /// Distinct CRLs.
    crls: Vec<OwnedCrl>,
}

/// What the pool says about one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerdict {
    /// The certificate that verifiably issued the judged one, when one
    /// in the pool did: the issuer on the anchored path when there is
    /// one.
    pub issuer: Option<OwnedCert>,
    /// Whether a path ends in an anchor of the requested role granted
    /// at the validation time, every certificate below the anchor valid
    /// at that time.
    pub anchored: bool,
    /// The revocation status of the anchored path, or of the judged
    /// certificate alone against its issuer when there is no path.
    pub revocation: Revocation,
}

/// The revocation status the evidence establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// A verified answer says good; `at` is the latest evidence time:
    /// the OCSP `producedAt` or the CRL `thisUpdate`.
    Good {
        /// The evidence time.
        at: DateTime,
    },
    /// A verified answer says revoked; `at` is the revocation time
    /// from the CRL entry or the OCSP `revokedInfo`, the earliest when
    /// several answers or certificates are revoked.
    Revoked {
        /// The revocation time.
        at: DateTime,
    },
    /// No verified answer speaks for the validation time.
    Unavailable,
}

impl Revocation {
    /// Whether a revocation precedes `proof_of_existence`, or any
    /// revocation counts because there is no proof.
    #[must_use]
    pub fn revoked_before(self, proof_of_existence: Option<DateTime>) -> bool {
        match self {
            Self::Revoked { at } => proof_of_existence.is_none_or(|proof| at <= proof),
            Self::Good { .. } | Self::Unavailable => false,
        }
    }
}

/// A verified revocation answer that applies to one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Good, with the evidence time.
    Good(DateTime),
    /// Revoked, at this time.
    Revoked(DateTime),
}

impl MaterialPool {
    /// An empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the certificates, OCSP responses and CRLs of `material`.
    pub fn add_material(&mut self, material: &ValidationMaterial) {
        self.add_certificate_ders(&material.certificates);
        for der in &material.ocsp_responses {
            if self
                .ocsp_responses
                .iter()
                .all(|known| known.as_der() != der.as_slice())
                && let Ok(response) = OwnedOcspResponse::from_der(der)
            {
                self.ocsp_responses.push(response);
            }
        }
        for der in &material.crls {
            if self
                .crls
                .iter()
                .all(|known| known.as_der() != der.as_slice())
                && let Ok(crl) = OwnedCrl::from_der(der)
            {
                self.crls.push(crl);
            }
        }
    }

    /// Add DER certificates.
    pub fn add_certificate_ders(&mut self, ders: &[Vec<u8>]) {
        for der in ders {
            if let Ok(certificate) = OwnedCert::from_der(der) {
                self.add_certificate(certificate);
            }
        }
    }

    /// Add one parsed certificate.
    pub fn add_certificate(&mut self, certificate: OwnedCert) {
        if self
            .certificates
            .iter()
            .all(|known| known.as_der() != certificate.as_der())
        {
            self.certificates.push(certificate);
        }
    }

    /// Add every anchor's certificate, so a document need not carry
    /// the anchor it chains to.
    pub fn add_anchors(&mut self, anchors: &TrustAnchors) {
        for anchor in anchors.anchors() {
            self.add_certificate(anchor.certificate.clone());
        }
    }

    /// The pool certificates that issued `child`: the name chains and
    /// the signature verifies, and the candidate is either an anchor
    /// for `role` at `at` or a CA valid at `at` allowed to issue with
    /// `intermediates_below` CA certificates between it and the end
    /// entity.
    fn issuers_of(&self, child: Certificate<'_>, step: &Step<'_>) -> Vec<&OwnedCert> {
        self.certificates
            .iter()
            .filter(|candidate| {
                let view = candidate.view();
                view.raw_der != child.raw_der
                    && view.subject == child.issuer
                    && (step.anchors.is_anchor(view, step.role, step.at)
                        || (valid_at(view, step.at) && may_issue(view, step.intermediates_below)))
                    && child.verify_signed_by(view).is_ok()
            })
            .collect()
    }

    /// Whether a path from the last certificate of `path` upward ends
    /// in an anchor; on success `path` runs from the judged
    /// certificate to the anchor.
    fn anchored_above(
        &self,
        anchors: &TrustAnchors,
        role: AnchorRole,
        at: DateTime,
        path: &mut Vec<OwnedCert>,
    ) -> bool {
        if path.len() > MAX_PATH_DEPTH {
            return false;
        }
        let Some(top) = path.last().cloned() else {
            return false;
        };
        let step = Step {
            anchors,
            role,
            at,
            intermediates_below: path.len().saturating_sub(1),
        };
        for issuer in self.issuers_of(top.view(), &step) {
            if path.iter().any(|seen| seen.as_der() == issuer.as_der()) {
                continue;
            }
            path.push(issuer.clone());
            if anchors.is_anchor(issuer.view(), role, at)
                || self.anchored_above(anchors, role, at, path)
            {
                return true;
            }
            path.pop();
        }
        false
    }

    /// The revocation status of `certificate` from every verified OCSP
    /// answer and every CRL `issuer` signed, weighed together: revoked
    /// when any says so, else good when any accepted answer says so.
    fn revocation_of(
        &self,
        certificate: Certificate<'_>,
        issuer: Certificate<'_>,
        at: DateTime,
    ) -> Revocation {
        let ocsp = self
            .ocsp_responses
            .iter()
            .filter_map(|response| self.ocsp_answer(response, certificate, issuer, at));
        let crl = self
            .crls
            .iter()
            .filter_map(|crl| crl_answer(crl, certificate, issuer, at));
        strongest(ocsp.chain(crl))
    }

    /// The revocation status of `path`, judged certificate first and
    /// anchor last: every certificate below the anchor is checked
    /// against its issuer (RFC 5280 sec.6.1.3 (a)(3)). Revoked when any
    /// is, at the earliest revocation time; else unavailable when any
    /// is unanswered; else the judged certificate's good answer.
    fn path_revocation(&self, path: &[OwnedCert], at: DateTime) -> Revocation {
        let mut first = None;
        let mut earliest_revocation: Option<DateTime> = None;
        let mut unanswered = false;
        for step in path.windows(2) {
            let [certificate, issuer] = step else {
                continue;
            };
            let revocation = self.revocation_of(certificate.view(), issuer.view(), at);
            match revocation {
                Revocation::Revoked { at: revoked } => {
                    earliest_revocation =
                        Some(earliest_revocation.map_or(revoked, |known| known.min(revoked)));
                }
                Revocation::Unavailable => unanswered = true,
                Revocation::Good { .. } => {}
            }
            first.get_or_insert(revocation);
        }
        match (earliest_revocation, unanswered) {
            (Some(at), _) => Revocation::Revoked { at },
            (None, true) => Revocation::Unavailable,
            (None, false) => first.unwrap_or(Revocation::Unavailable),
        }
    }

    /// What one OCSP response says about `certificate`, when its signer
    /// is `issuer` or a responder `issuer` delegated, and a good answer
    /// was current at `at`.
    fn ocsp_answer(
        &self,
        response: &OwnedOcspResponse,
        certificate: Certificate<'_>,
        issuer: Certificate<'_>,
        at: DateTime,
    ) -> Option<Answer> {
        let view = response.view();
        if view.status != OcspResponseStatus::Successful {
            return None;
        }
        let basic = view.basic.as_ref()?;
        let embedded = basic
            .embedded_cert_ders
            .iter()
            .filter_map(|der| Certificate::from_der(der).ok());
        let pooled = self.certificates.iter().map(OwnedCert::view);
        core::iter::once(issuer)
            .chain(embedded)
            .chain(pooled)
            .filter(|candidate| basic.responder_id.matches_certificate(*candidate))
            .find_map(|candidate| {
                let verified = VerifiedOcspResponse::verify(basic, candidate, issuer).ok()?;
                let single = verified.response_for(certificate)?;
                match single.status {
                    CertStatus::Revoked { revoked_at, .. } => Some(Answer::Revoked(revoked_at)),
                    CertStatus::Good => {
                        accepted_window(certificate, single.this_update, single.next_update, at)
                            .then_some(Answer::Good(basic.produced_at))
                    }
                    CertStatus::Unknown => None,
                }
            })
    }
}

/// What one path-building step consults.
struct Step<'a> {
    /// The anchors.
    anchors: &'a TrustAnchors,
    /// The role the path must end in.
    role: AnchorRole,
    /// The validation time.
    at: DateTime,
    /// CA certificates between the next issuer and the end entity.
    intermediates_below: usize,
}

/// Judge `certificate` against `pool` and `anchors` for `role` at the
/// validation time `at`.
///
/// `issuer` is reported whenever a pool certificate verifiably issued
/// the certificate, anchored or not; `anchored` additionally needs the
/// certificate valid at `at` and a path ending in an anchor for `role`
/// granted at `at`. A certificate that is itself such an anchor is
/// anchored when valid at `at`, with nothing below it to check for
/// revocation. On an anchored path every certificate below the anchor
/// is checked for revocation; without one only the certificate is,
/// against `issuer`. The status is [`Revocation::Unavailable`] without
/// an issuer: no unverified answer is ever reported.
#[must_use]
pub fn judge(
    certificate: &OwnedCert,
    pool: &MaterialPool,
    anchors: &TrustAnchors,
    role: AnchorRole,
    at: DateTime,
) -> ChainVerdict {
    let view = certificate.view();
    let valid = valid_at(view, at);
    if anchors.is_anchor(view, role, at) {
        return ChainVerdict {
            issuer: None,
            anchored: valid,
            revocation: Revocation::Unavailable,
        };
    }
    let step = Step {
        anchors,
        role,
        at,
        intermediates_below: 0,
    };
    let candidates = pool.issuers_of(view, &step);
    let mut path = Vec::new();
    let anchored_issuer = candidates.iter().copied().find(|issuer| {
        path.clear();
        path.push(certificate.clone());
        path.push((*issuer).clone());
        anchors.is_anchor(issuer.view(), role, at)
            || pool.anchored_above(anchors, role, at, &mut path)
    });
    let issuer = anchored_issuer.or_else(|| candidates.first().copied());
    let revocation = match (anchored_issuer, issuer) {
        (Some(_), _) => pool.path_revocation(&path, at),
        (None, Some(issuer)) => pool.revocation_of(view, issuer.view(), at),
        (None, None) => Revocation::Unavailable,
    };
    ChainVerdict {
        issuer: issuer.cloned(),
        anchored: valid && anchored_issuer.is_some(),
        revocation,
    }
}

/// What one CRL says about `certificate`, when `issuer` signed it and a
/// good answer was current at `at`.
fn crl_answer(
    crl: &OwnedCrl,
    certificate: Certificate<'_>,
    issuer: Certificate<'_>,
    at: DateTime,
) -> Option<Answer> {
    let view = crl.view();
    let verified = VerifiedCrl::verify(&view, issuer).ok()?;
    // Read at the CRL's own `thisUpdate`, where it is never stale; the
    // acceptance window is applied below.
    match check_against_crl(certificate, &verified, view.this_update) {
        RevocationStatus::Good => {
            accepted_window(certificate, view.this_update, view.next_update, at)
                .then_some(Answer::Good(view.this_update))
        }
        RevocationStatus::Revoked { at: revoked, .. } => Some(Answer::Revoked(revoked)),
        RevocationStatus::Inapplicable(_)
        | RevocationStatus::Stale
        | RevocationStatus::NotYetValid
        | RevocationStatus::Unknown => None,
    }
}

/// Whether a good answer with this window speaks for `certificate` at
/// `at`: its window `thisUpdate..=nextUpdate` contains `at` (with
/// `nextUpdate` absent the window is `thisUpdate` alone), or it was
/// issued at or after `at` while the certificate was still valid
/// (`thisUpdate <= notAfter`). The second case is evidence gathered
/// after signing, which a level-LT document embeds; it shows the
/// certificate was not revoked when the signature already existed
/// (`ETSI EN 319 102-1` clauses 5.2.5 and 5.6.2).
fn accepted_window(
    certificate: Certificate<'_>,
    this_update: DateTime,
    next_update: Option<DateTime>,
    at: DateTime,
) -> bool {
    let contains_at = this_update <= at && at <= next_update.unwrap_or(this_update);
    let issued_after_at = at <= this_update && this_update <= certificate.not_after;
    contains_at || issued_after_at
}

/// A revoked answer outweighs any good one, the earliest revocation
/// time reported; among good answers the latest evidence time is.
fn strongest(answers: impl Iterator<Item = Answer>) -> Revocation {
    let mut good: Option<DateTime> = None;
    let mut revoked: Option<DateTime> = None;
    for answer in answers {
        match answer {
            Answer::Revoked(at) => revoked = Some(revoked.map_or(at, |known| known.min(at))),
            Answer::Good(at) => good = Some(good.map_or(at, |known| known.max(at))),
        }
    }
    match (revoked, good) {
        (Some(at), _) => Revocation::Revoked { at },
        (None, Some(at)) => Revocation::Good { at },
        (None, None) => Revocation::Unavailable,
    }
}

/// Whether `at` lies inside the certificate's validity window (RFC 5280
/// sec.4.1.2.5, both ends inclusive).
fn valid_at(certificate: Certificate<'_>, at: DateTime) -> bool {
    certificate.not_before <= at && at <= certificate.not_after
}

/// Whether the certificate may issue a certificate with
/// `intermediates_below` CA certificates between it and the end entity
/// (RFC 5280 sec.6.1.4 (k), (l), (n)).
fn may_issue(certificate: Certificate<'_>, intermediates_below: usize) -> bool {
    let Some(extensions) = certificate.extensions else {
        return false;
    };
    let Ok(profile) = path_extension_profile(extensions) else {
        return false;
    };
    let constraints = profile.basic_constraints;
    constraints.present
        && constraints.ca
        && !profile.name_constraints_present
        && profile
            .key_usage
            .is_none_or(|usage| usage.key_usage.key_cert_sign)
        && constraints.path_len.is_none_or(|limit| {
            usize::try_from(limit).is_ok_and(|limit| intermediates_below <= limit)
        })
}

#[cfg(test)]
mod tests {
    use super::{
        AnchorError, AnchorRole, GrantedPeriod, MaterialPool, Revocation, TrustAnchor,
        TrustAnchors, judge,
    };
    use crate::testkit::{
        BOOLEAN, CertificateSpec, DER_TRUE, INTEGER, OcspSpec, ResponderName, SEQUENCE, TestCurve,
        TestKey, ca_extensions, certificate, crl, day, extension, key_usage, ocsp_response, tlv,
    };
    use crate::validation::ValidationMaterial;
    use refineid_cms::oid::known;
    use refineid_cms::testkit::{KEY_USAGE_CA, KEY_USAGE_CA_UNUSED};
    use refineid_cms::x509::OwnedCert;

    /// Root common name.
    const ROOT: &str = "Synthetic Root CA";
    /// Intermediate common name.
    const INTERMEDIATE: &str = "Synthetic Issuing CA";
    /// Second intermediate common name.
    const SUB_INTERMEDIATE: &str = "Synthetic Sub-issuing CA";
    /// Signer common name.
    const SIGNER: &str = "Synthetic Signer";
    /// Root serial.
    const ROOT_SERIAL: u8 = 1;
    /// Intermediate serial.
    const INTERMEDIATE_SERIAL: u8 = 2;
    /// Signer serial.
    const SIGNER_SERIAL: u8 = 3;
    /// Second intermediate serial.
    const SUB_INTERMEDIATE_SERIAL: u8 = 4;
    /// Day every certificate starts.
    const ISSUED: u8 = 1;
    /// Day of a revocation.
    const REVOKED: u8 = 2;
    /// A validation day before [`ENDED_EARLY`].
    const EARLY: u8 = 3;
    /// Day a short-lived certificate or answer ends, before
    /// [`VALIDATED`].
    const ENDED_EARLY: u8 = 5;
    /// Day revocation answers are produced.
    const ANSWERED: u8 = 9;
    /// The validation day.
    const VALIDATED: u8 = 10;
    /// Day long-lived certificates and answers end.
    const ENDS: u8 = 28;
    /// A `pathLenConstraint` admitting no intermediate below.
    const PATH_LEN_ZERO: u8 = 0;

    /// Root, intermediate and signer, each with its key.
    struct Chain {
        /// Root key.
        root_key: TestKey,
        /// Intermediate key.
        intermediate_key: TestKey,
        /// Self-signed root.
        root: Vec<u8>,
        /// Intermediate issued by the root.
        intermediate: Vec<u8>,
        /// Signer issued by the intermediate.
        signer: OwnedCert,
    }

    /// A certificate spec from [`ISSUED`] to `ends`.
    fn spec<'a>(
        serial: u8,
        subject: &'a str,
        issuer: &'a str,
        ends: u8,
        extensions: Vec<Vec<u8>>,
    ) -> CertificateSpec<'a> {
        CertificateSpec {
            serial,
            subject,
            issuer,
            not_before: day(ISSUED),
            not_after: day(ends),
            extensions,
        }
    }

    /// A two-step chain; `intermediate_ends` is the intermediate's last
    /// valid day.
    fn chain(intermediate_ends: u8) -> Chain {
        chain_with(intermediate_ends, ENDS, ca_extensions())
    }

    /// A two-step chain with the intermediate's and the signer's last
    /// valid days and the intermediate's extensions.
    fn chain_with(intermediate_ends: u8, signer_ends: u8, extensions: Vec<Vec<u8>>) -> Chain {
        let root_key = TestKey::derive(TestCurve::P384, b"root");
        let intermediate_key = TestKey::derive(TestCurve::P384, b"intermediate");
        let signer_key = TestKey::derive(TestCurve::P256, b"signer");
        let root = certificate(
            &spec(ROOT_SERIAL, ROOT, ROOT, ENDS, ca_extensions()),
            &root_key,
            &root_key,
        );
        let intermediate = certificate(
            &spec(
                INTERMEDIATE_SERIAL,
                INTERMEDIATE,
                ROOT,
                intermediate_ends,
                extensions,
            ),
            &intermediate_key,
            &root_key,
        );
        let signer = certificate(
            &spec(SIGNER_SERIAL, SIGNER, INTERMEDIATE, signer_ends, Vec::new()),
            &signer_key,
            &intermediate_key,
        );
        Chain {
            root_key,
            intermediate_key,
            root,
            intermediate,
            signer: OwnedCert::from_der(&signer).expect("signer parses"),
        }
    }

    /// `der` trusted for certificate issuing without bounds.
    fn issuing(der: &[u8]) -> TrustAnchors {
        TrustAnchors::new(vec![
            TrustAnchor::new(
                OwnedCert::from_der(der).expect("anchor parses"),
                AnchorRole::CertificateIssuing,
                vec![GrantedPeriod::unbounded()],
            )
            .expect("an anchor"),
        ])
    }

    /// No anchors.
    fn none() -> TrustAnchors {
        TrustAnchors::new(Vec::new())
    }

    impl Chain {
        /// The pool a document carrying the intermediate, plus the
        /// caller's root, gives.
        fn pool(&self) -> MaterialPool {
            let mut pool = MaterialPool::new();
            pool.add_certificate_ders(&[self.intermediate.clone(), self.root.clone()]);
            pool
        }

        /// The chain's pool plus these OCSP answers and CRLs.
        fn pool_with(&self, ocsp_responses: Vec<Vec<u8>>, crls: Vec<Vec<u8>>) -> MaterialPool {
            let mut pool = self.pool();
            pool.add_material(&ValidationMaterial {
                certificates: Vec::new(),
                ocsp_responses,
                crls,
            });
            pool
        }

        /// An OCSP answer about the signer from the intermediate,
        /// produced on `answered`, revoked on [`REVOKED`] when
        /// `revoked`, with `nextUpdate` on `next_update` when given.
        fn ocsp(&self, revoked: bool, answered: u8, next_update: Option<u8>) -> Vec<u8> {
            let issuer = OwnedCert::from_der(&self.intermediate).expect("intermediate parses");
            ocsp_response(&OcspSpec {
                responder_key: &self.intermediate_key,
                responder: ResponderName::ByName(INTERMEDIATE),
                issuer: &issuer,
                serial: SIGNER_SERIAL,
                revoked: revoked.then(|| day(REVOKED)),
                produced_at: day(answered),
                this_update: day(answered),
                next_update: next_update.map(day),
                embedded: Vec::new(),
            })
        }

        /// A good answer about the signer, produced on [`ANSWERED`].
        fn good(&self) -> Vec<u8> {
            self.ocsp(false, ANSWERED, Some(ENDS))
        }

        /// An OCSP answer about the intermediate from the root.
        fn intermediate_ocsp(&self, revoked: bool) -> Vec<u8> {
            let issuer = OwnedCert::from_der(&self.root).expect("root parses");
            ocsp_response(&OcspSpec {
                responder_key: &self.root_key,
                responder: ResponderName::ByName(ROOT),
                issuer: &issuer,
                serial: INTERMEDIATE_SERIAL,
                revoked: revoked.then(|| day(REVOKED)),
                produced_at: day(ANSWERED),
                this_update: day(ANSWERED),
                next_update: Some(day(ENDS)),
                embedded: Vec::new(),
            })
        }

        /// A CRL from the intermediate listing `serials`, revoked on
        /// [`REVOKED`].
        fn crl(&self, serials: &[u8]) -> Vec<u8> {
            crl(
                INTERMEDIATE,
                &self.intermediate_key,
                day(ANSWERED),
                Some(day(ENDS)),
                serials,
                day(REVOKED),
            )
        }
    }

    /// The revocation `judge` reports for `chain.signer` over `pool`
    /// with no anchors at `at`.
    fn signer_revocation(chain: &Chain, pool: &MaterialPool, at: u8) -> Revocation {
        judge(
            &chain.signer,
            pool,
            &none(),
            AnchorRole::CertificateIssuing,
            day(at),
        )
        .revocation
    }

    #[test]
    fn a_two_step_path_to_a_trusted_root_is_anchored() {
        let chain = chain(ENDS);
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            &issuing(&chain.root),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(verdict.anchored);
        assert_eq!(
            verdict.issuer.map(OwnedCert::into_der),
            Some(chain.intermediate.clone())
        );
        assert_eq!(verdict.revocation, Revocation::Unavailable);
    }

    #[test]
    fn an_anchor_counts_only_for_its_role_and_period() {
        let chain = chain(ENDS);
        let root = OwnedCert::from_der(&chain.root).expect("root parses");
        let stamping = TrustAnchors::new(vec![
            TrustAnchor::new(
                root.clone(),
                AnchorRole::TimeStamping,
                vec![GrantedPeriod::unbounded()],
            )
            .expect("an anchor"),
        ]);
        let at = day(VALIDATED);
        let issuing_role = AnchorRole::CertificateIssuing;
        assert!(!judge(&chain.signer, &chain.pool(), &stamping, issuing_role, at).anchored);

        let lapsed = TrustAnchors::new(vec![
            TrustAnchor::new(
                root,
                issuing_role,
                vec![GrantedPeriod::new(day(ISSUED), Some(day(EARLY))).expect("a period")],
            )
            .expect("an anchor"),
        ]);
        assert!(!judge(&chain.signer, &chain.pool(), &lapsed, issuing_role, at).anchored);
        assert!(
            judge(
                &chain.signer,
                &chain.pool(),
                &lapsed,
                issuing_role,
                day(EARLY)
            )
            .anchored
        );
    }

    #[test]
    fn periods_and_anchors_are_checked_at_construction() {
        assert_eq!(
            GrantedPeriod::new(day(VALIDATED), Some(day(ISSUED))),
            Err(AnchorError::PeriodEndsBeforeStart)
        );
        let chain = chain(ENDS);
        assert_eq!(
            TrustAnchor::new(
                OwnedCert::from_der(&chain.root).expect("root parses"),
                AnchorRole::CertificateIssuing,
                Vec::new(),
            ),
            Err(AnchorError::NoGrantedPeriod)
        );
    }

    #[test]
    fn an_intermediate_named_as_anchor_anchors_without_its_root() {
        let chain = chain(ENDS);
        let mut pool = MaterialPool::new();
        let anchors = issuing(&chain.intermediate);
        pool.add_anchors(&anchors);
        let verdict = judge(
            &chain.signer,
            &pool,
            &anchors,
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(verdict.anchored);
    }

    #[test]
    fn the_pinned_anchors_carry_both_roles() {
        let pinned = TrustAnchors::pinned();
        assert!(
            pinned
                .anchors()
                .iter()
                .any(|anchor| anchor.role() == AnchorRole::CertificateIssuing)
        );
        assert!(
            pinned
                .anchors()
                .iter()
                .any(|anchor| anchor.role() == AnchorRole::TimeStamping)
        );
        assert_eq!(
            pinned.anchors().len(),
            crate::trust::PINNED_ROOT_DER.len() + crate::trust::PINNED_TSA_ROOT_DER.len()
        );
        assert_eq!(pinned.fetched_at(), None);
    }

    #[test]
    fn a_root_outside_the_anchors_leaves_the_path_unanchored() {
        let chain = chain(ENDS);
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            &none(),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(!verdict.anchored);
        assert_eq!(
            verdict.issuer.map(OwnedCert::into_der),
            Some(chain.intermediate.clone())
        );
    }

    #[test]
    fn an_issuer_expired_at_the_validation_time_is_no_issuer() {
        let chain = chain(ENDED_EARLY);
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            &issuing(&chain.root),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(!verdict.anchored);
        assert!(verdict.issuer.is_none());
        assert_eq!(verdict.revocation, Revocation::Unavailable);
    }

    #[test]
    fn a_signer_expired_at_the_validation_time_is_not_anchored() {
        let chain = chain_with(ENDS, ENDED_EARLY, ca_extensions());
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            &issuing(&chain.root),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(!verdict.anchored);
        assert!(verdict.issuer.is_some());
    }

    #[test]
    fn an_issuer_with_name_constraints_is_not_used() {
        let mut extensions = ca_extensions();
        extensions.push(extension(
            crate::oids::NAME_CONSTRAINTS,
            true,
            &tlv(SEQUENCE, []),
        ));
        let chain = chain_with(ENDS, ENDS, extensions);
        let verdict = judge(
            &chain.signer,
            &chain.pool(),
            &issuing(&chain.root),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(!verdict.anchored);
        assert!(verdict.issuer.is_none());
    }

    #[test]
    fn a_path_length_constraint_is_honoured() {
        let chain = chain_with(
            ENDS,
            ENDS,
            vec![
                extension(
                    known::BASIC_CONSTRAINTS,
                    true,
                    &tlv(SEQUENCE, {
                        let mut body = tlv(BOOLEAN, [DER_TRUE]);
                        body.extend_from_slice(&tlv(INTEGER, [PATH_LEN_ZERO]));
                        body
                    }),
                ),
                key_usage(KEY_USAGE_CA_UNUSED, KEY_USAGE_CA),
            ],
        );
        let sub_key = TestKey::derive(TestCurve::P256, b"sub-intermediate");
        let sub = certificate(
            &spec(
                SUB_INTERMEDIATE_SERIAL,
                SUB_INTERMEDIATE,
                INTERMEDIATE,
                ENDS,
                ca_extensions(),
            ),
            &sub_key,
            &chain.intermediate_key,
        );
        let deep_signer = certificate(
            &spec(SIGNER_SERIAL, SIGNER, SUB_INTERMEDIATE, ENDS, Vec::new()),
            &TestKey::derive(TestCurve::P256, b"deep signer"),
            &sub_key,
        );
        let mut pool = chain.pool();
        pool.add_certificate_ders(&[sub]);
        let anchors = issuing(&chain.root);
        let at = day(VALIDATED);
        let role = AnchorRole::CertificateIssuing;
        assert!(judge(&chain.signer, &pool, &anchors, role, at).anchored);
        let deep = OwnedCert::from_der(&deep_signer).expect("signer parses");
        assert!(!judge(&deep, &pool, &anchors, role, at).anchored);
    }

    #[test]
    fn a_cycle_of_cross_signed_issuers_ends() {
        let chain = chain(ENDS);
        // The intermediate's key also issues a certificate for the root's
        // name and key, so the root and the intermediate issue each
        // other.
        let cross = certificate(
            &spec(ROOT_SERIAL, ROOT, INTERMEDIATE, ENDS, ca_extensions()),
            &chain.root_key,
            &chain.intermediate_key,
        );
        let mut pool = chain.pool();
        pool.add_certificate_ders(&[cross]);
        let verdict = judge(
            &chain.signer,
            &pool,
            &none(),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(!verdict.anchored);
    }

    #[test]
    fn a_verified_good_ocsp_answer_is_good_as_of_its_production() {
        let chain = chain(ENDS);
        let pool = chain.pool_with(
            vec![chain.good(), chain.intermediate_ocsp(false)],
            Vec::new(),
        );
        let verdict = judge(
            &chain.signer,
            &pool,
            &issuing(&chain.root),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert_eq!(verdict.revocation, Revocation::Good { at: day(ANSWERED) });
    }

    #[test]
    fn a_verified_revoked_answer_carries_its_revocation_time_whatever_its_window() {
        let chain = chain(ENDS);
        let pool = chain.pool_with(
            vec![chain.ocsp(true, ISSUED, Some(ENDED_EARLY))],
            Vec::new(),
        );
        assert_eq!(
            signer_revocation(&chain, &pool, VALIDATED),
            Revocation::Revoked { at: day(REVOKED) }
        );
    }

    #[test]
    fn an_answer_that_expired_before_the_validation_time_is_unavailable() {
        let chain = chain(ENDS);
        let pool = chain.pool_with(
            vec![chain.ocsp(false, ISSUED, Some(ENDED_EARLY))],
            Vec::new(),
        );
        assert_eq!(
            signer_revocation(&chain, &pool, VALIDATED),
            Revocation::Unavailable
        );
    }

    #[test]
    fn an_answer_produced_after_the_validation_time_within_the_signer_validity_is_good() {
        let chain = chain(ENDS);
        let pool = chain.pool_with(vec![chain.good()], Vec::new());
        assert_eq!(
            signer_revocation(&chain, &pool, ENDED_EARLY),
            Revocation::Good { at: day(ANSWERED) }
        );
    }

    #[test]
    fn an_answer_produced_after_the_signer_expired_is_unavailable() {
        let chain = chain_with(ENDS, ENDED_EARLY, ca_extensions());
        let pool = chain.pool_with(vec![chain.good()], Vec::new());
        assert_eq!(
            signer_revocation(&chain, &pool, EARLY),
            Revocation::Unavailable
        );
    }

    #[test]
    fn an_ocsp_answer_signed_by_a_stranger_is_unavailable() {
        let chain = chain(ENDS);
        let issuer = OwnedCert::from_der(&chain.intermediate).expect("intermediate parses");
        let forged = ocsp_response(&OcspSpec {
            responder_key: &chain.root_key,
            responder: ResponderName::ByName(INTERMEDIATE),
            issuer: &issuer,
            serial: SIGNER_SERIAL,
            revoked: Some(day(REVOKED)),
            produced_at: day(ANSWERED),
            this_update: day(ANSWERED),
            next_update: None,
            embedded: Vec::new(),
        });
        let pool = chain.pool_with(vec![forged], Vec::new());
        assert_eq!(
            signer_revocation(&chain, &pool, VALIDATED),
            Revocation::Unavailable
        );
    }

    #[test]
    fn a_verified_crl_listing_the_signer_is_revoked_and_one_without_is_good() {
        let chain = chain(ENDS);
        let pool = chain.pool_with(Vec::new(), vec![chain.crl(&[SIGNER_SERIAL])]);
        assert_eq!(
            signer_revocation(&chain, &pool, VALIDATED),
            Revocation::Revoked { at: day(REVOKED) }
        );
        let pool = chain.pool_with(Vec::new(), vec![chain.crl(&[ROOT_SERIAL])]);
        assert_eq!(
            signer_revocation(&chain, &pool, VALIDATED),
            Revocation::Good { at: day(ANSWERED) }
        );
    }

    #[test]
    fn a_crl_revocation_outweighs_an_ocsp_good() {
        let chain = chain(ENDS);
        let pool = chain.pool_with(
            vec![chain.good(), chain.intermediate_ocsp(false)],
            vec![chain.crl(&[SIGNER_SERIAL])],
        );
        let verdict = judge(
            &chain.signer,
            &pool,
            &issuing(&chain.root),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(verdict.anchored);
        assert_eq!(verdict.revocation, Revocation::Revoked { at: day(REVOKED) });
    }

    #[test]
    fn a_revoked_intermediate_revokes_the_path() {
        let chain = chain(ENDS);
        let pool = chain.pool_with(
            vec![chain.good(), chain.intermediate_ocsp(true)],
            Vec::new(),
        );
        let verdict = judge(
            &chain.signer,
            &pool,
            &issuing(&chain.root),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert_eq!(verdict.revocation, Revocation::Revoked { at: day(REVOKED) });
    }

    #[test]
    fn an_unanswered_intermediate_leaves_the_path_unavailable() {
        let chain = chain(ENDS);
        let pool = chain.pool_with(vec![chain.good()], Vec::new());
        let verdict = judge(
            &chain.signer,
            &pool,
            &issuing(&chain.root),
            AnchorRole::CertificateIssuing,
            day(VALIDATED),
        );
        assert!(verdict.anchored);
        assert_eq!(verdict.revocation, Revocation::Unavailable);
        assert_eq!(
            signer_revocation(&chain, &pool, VALIDATED),
            Revocation::Good { at: day(ANSWERED) }
        );
    }

    #[test]
    fn an_answer_without_next_update_counts_only_when_produced_after_the_validation_time() {
        let chain = chain(ENDS);
        let early = chain.pool_with(vec![chain.ocsp(false, ISSUED, None)], Vec::new());
        assert_eq!(
            signer_revocation(&chain, &early, VALIDATED),
            Revocation::Unavailable
        );
        let later = chain.pool_with(vec![chain.ocsp(false, ANSWERED, None)], Vec::new());
        assert_eq!(
            signer_revocation(&chain, &later, EARLY),
            Revocation::Good { at: day(ANSWERED) }
        );
    }

    #[test]
    fn a_revocation_counts_against_the_proof_of_existence() {
        let revoked = Revocation::Revoked { at: day(REVOKED) };
        assert!(revoked.revoked_before(None));
        assert!(revoked.revoked_before(Some(day(REVOKED))));
        assert!(revoked.revoked_before(Some(day(VALIDATED))));
        assert!(!revoked.revoked_before(Some(day(ISSUED))));
        assert!(!Revocation::Unavailable.revoked_before(None));
        assert!(!Revocation::Good { at: day(ANSWERED) }.revoked_before(None));
    }

    #[test]
    fn the_pool_holds_each_item_once_and_skips_unreadable_ones() {
        let chain = chain(ENDS);
        let mut pool = chain.pool();
        pool.add_certificate_ders(&[chain.root.clone(), b"not a certificate".to_vec()]);
        pool.add_material(&ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: vec![chain.good(), chain.good(), b"not an answer".to_vec()],
            crls: vec![b"not a list".to_vec()],
        });
        assert_eq!(pool.certificates.len(), 2);
        assert_eq!(pool.ocsp_responses.len(), 1);
        assert!(pool.crls.is_empty());
    }

    /// A granted period is inclusive at both ends.
    #[test]
    fn a_granted_period_covers_both_ends() {
        let period = GrantedPeriod::new(day(ISSUED), Some(day(ENDED_EARLY))).expect("a period");
        assert!(period.covers(day(ISSUED)));
        assert!(period.covers(day(ENDED_EARLY)));
        assert!(!period.covers(day(ANSWERED)));
        assert!(GrantedPeriod::unbounded().covers(day(ENDS)));
    }
}
