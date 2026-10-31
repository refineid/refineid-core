// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! End-to-end tests of [`super::verify`]: documents written by the
//! signing side of this crate, or assembled from the testkit, over
//! synthetic keys, certificates and evidence.

use super::{
    AnchorRole, DocumentFailure, DocumentFile, DocumentReport, GrantedPeriod, Revocation,
    SignatureReport, SignatureRow, SignerIdentity, TimestampReport, TrustAnchor, TrustAnchors,
    UnsupportedProfile, UnsupportedSignature, exactly, verify,
};
use crate::asic::DataObject;
use crate::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime};
use crate::cms::CmsError;
use crate::document::{Format, plan};
use crate::pades::{
    DEFAULT_SIGNATURE_CAPACITY, SignatureMetadata, prepare, prepare_document_timestamp,
};
use crate::testkit::{
    CertificateSpec, CmsParts, NULL, OBJECT_IDENTIFIER, OcspSpec, PRINTABLE_STRING, ResponderName,
    SEQUENCE, TestCurve, TestKey, UTF8_STRING, attribute, attribute_set, ca_extensions,
    certificate, certificate_named, cms, content_attributes, day, minimal_pdf, name_of,
    ocsp_response, signing_certificate_v2, timestamp_token, timestamping_extensions, tlv, utc_time,
};
use crate::timestamp::TimestampError;
use crate::validation::ValidationMaterial;
use crate::verification::cades::CadesReadError;
use refineid_cms::oid::known;
use refineid_cms::signed_data::HashAlgorithm;
use refineid_cms::x509::{DateTime, OwnedCert};

/// Root common name.
const ROOT: &str = "Synthetic Root CA";
/// Intermediate common name.
const INTERMEDIATE: &str = "Synthetic Issuing CA";
/// Common name of the signer the root issues.
const DIRECT_SIGNER: &str = "Synthetic Signer";
/// Common name of the signer the intermediate issues.
const ISSUED_SIGNER: &str = "Synthetic Issued Signer";
/// Common name of the RSA signer the root issues.
const RSA_SIGNER: &str = "Synthetic RSA Signer";
/// Time-stamping root common name.
const TSA_ROOT: &str = "Synthetic Time Stamping Root";
/// TSA common name.
const TSA: &str = "Synthetic Time Stamping Unit";
/// Common name of a self-made time-stamping root nobody trusts.
const ROGUE_TSA_ROOT: &str = "Synthetic Self-made Time Stamping Root";
/// Common name of the TSA the self-made root issues.
const ROGUE_TSA: &str = "Synthetic Self-made Time Stamping Unit";
/// Common name of a root nobody trusts.
const STRANGER: &str = "Synthetic Stranger CA";

/// Root serial.
const ROOT_SERIAL: u8 = 1;
/// Intermediate serial.
const INTERMEDIATE_SERIAL: u8 = 2;
/// Direct signer serial.
const DIRECT_SIGNER_SERIAL: u8 = 3;
/// Issued signer serial.
const ISSUED_SIGNER_SERIAL: u8 = 4;
/// TSA serial.
const TSA_SERIAL: u8 = 5;
/// Stranger root serial.
const STRANGER_SERIAL: u8 = 6;
/// Person certificate serial.
const PERSON_SERIAL: u8 = 7;
/// Time-stamping root serial.
const TSA_ROOT_SERIAL: u8 = 8;
/// Self-made TSA serial.
const ROGUE_TSA_SERIAL: u8 = 9;
/// RSA signer serial.
const RSA_SIGNER_SERIAL: u8 = 10;

/// Day every certificate starts.
const ISSUED: u8 = 1;
/// Day of a revocation that precedes the timestamps.
const REVOKED_EARLY: u8 = 5;
/// Day of the timestamps.
const STAMPED: u8 = 10;
/// Day the OCSP answers are produced, after the timestamps.
const ANSWERED: u8 = 11;
/// Day of a revocation after the timestamps and before the validation
/// day.
const REVOKED_LATER: u8 = 15;
/// The validation day.
const NOW: u8 = 20;
/// Day every certificate ends.
const ENDS: u8 = 28;
/// Hour of every fixture instant (`testkit::day`).
const NOON: u8 = 12;

/// A container entry's content.
const NOTE: &[u8] = b"Synthetic note, signed for the verifier tests";
/// A container entry's name.
const NOTE_NAME: &str = "note.txt";
/// A container entry's media type.
const NOTE_TYPE: &str = "text/plain";
/// The PDF's entry name for the router.
const PDF_NAME: &str = "document.pdf";
/// The PDF media type.
const PDF_TYPE: &str = "application/pdf";
/// Text inside the first signed span of every signed fixture PDF.
const MEDIA_BOX: &[u8] = b"/MediaBox [0 0 200 200]";
/// The same text with one byte changed.
const TAMPERED_MEDIA_BOX: &[u8] = b"/MediaBox [0 0 200 201]";
/// The `PAdES` subfilter the writer writes.
const SUBFILTER_PADES: &[u8] = b"/ETSI.CAdES.detached";
/// The PKCS#7 subfilter, the same length.
const SUBFILTER_PKCS7: &[u8] = b"/adbe.pkcs7.detached";
/// A subfilter `ETSI EN 319 142-2` does not name, the same length.
const SUBFILTER_UNKNOWN: &[u8] = b"/ETSI.CAdES.detacheX";
/// Given name of the person certificate.
const GIVEN: &str = "Given Second";
/// Surname of the person certificate.
const SURNAME: &str = "Surname";
/// Common name of the person certificate.
const PERSON: &str = "Surname Given";
/// A synthetic electronic identifier of the right shape.
const IDENTIFIER: &str = "99999999X";
/// Bytes that are not a document.
const GARBAGE_DER: &[u8] = b"0 not a CMS structure";

/// The signing time the writers assert.
const SIGNING_TIME: SigningTime = SigningTime {
    year: 2026,
    month: 6,
    day: STAMPED,
    hour: NOON,
    minute: 0,
    second: 0,
};

/// Which signer signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signer {
    /// The P-256 signer issued by the root.
    Direct,
    /// The P-256 signer issued by the intermediate.
    Issued,
    /// The RSA-2048 signer issued by the root.
    Rsa,
}

/// Which authority timestamps the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stamp {
    /// No timestamp.
    None,
    /// The TSA under the anchored time-stamping root.
    Anchored,
    /// The TSA under the self-made root.
    SelfMade,
}

/// Keys and certificates of one test world.
struct World {
    /// Root key.
    root_key: TestKey,
    /// Root.
    root: Vec<u8>,
    /// Intermediate key.
    intermediate_key: TestKey,
    /// Intermediate, issued by the root.
    intermediate: Vec<u8>,
    /// Key of the P-256 signers.
    signer_key: TestKey,
    /// The RSA signer's key.
    rsa_key: TestKey,
    /// Signer issued by the root.
    direct_signer: Vec<u8>,
    /// Signer issued by the intermediate.
    issued_signer: Vec<u8>,
    /// RSA signer issued by the root.
    rsa_signer: Vec<u8>,
    /// Time-stamping root.
    tsa_root: Vec<u8>,
    /// TSA key.
    tsa_key: TestKey,
    /// TSA, issued by the time-stamping root.
    tsa: Vec<u8>,
    /// The self-made TSA, issued by a root nobody trusts.
    rogue_tsa: Vec<u8>,
    /// A self-signed root nobody trusts.
    stranger: Vec<u8>,
}

/// A certificate valid from [`ISSUED`] to [`ENDS`].
fn spec<'a>(
    serial: u8,
    subject: &'a str,
    issuer: &'a str,
    extensions: Vec<Vec<u8>>,
) -> CertificateSpec<'a> {
    CertificateSpec {
        serial,
        subject,
        issuer,
        not_before: day(ISSUED),
        not_after: day(ENDS),
        extensions,
    }
}

impl World {
    /// The world's keys and certificates.
    fn new() -> Self {
        let root_key = TestKey::derive(TestCurve::P384, b"root");
        let intermediate_key = TestKey::derive(TestCurve::P384, b"intermediate");
        let signer_key = TestKey::derive(TestCurve::P256, b"signer");
        let rsa_key = TestKey::rsa_2048();
        let tsa_root_key = TestKey::derive(TestCurve::P384, b"time-stamping root");
        let tsa_key = TestKey::derive(TestCurve::P256, b"tsa");
        let rogue_root_key = TestKey::derive(TestCurve::P256, b"self-made root");
        let stranger_key = TestKey::derive(TestCurve::P256, b"stranger");
        Self {
            root: certificate(
                &spec(ROOT_SERIAL, ROOT, ROOT, ca_extensions()),
                &root_key,
                &root_key,
            ),
            intermediate: certificate(
                &spec(INTERMEDIATE_SERIAL, INTERMEDIATE, ROOT, ca_extensions()),
                &intermediate_key,
                &root_key,
            ),
            direct_signer: certificate(
                &spec(DIRECT_SIGNER_SERIAL, DIRECT_SIGNER, ROOT, Vec::new()),
                &signer_key,
                &root_key,
            ),
            issued_signer: certificate(
                &spec(
                    ISSUED_SIGNER_SERIAL,
                    ISSUED_SIGNER,
                    INTERMEDIATE,
                    Vec::new(),
                ),
                &signer_key,
                &intermediate_key,
            ),
            rsa_signer: certificate(
                &spec(RSA_SIGNER_SERIAL, RSA_SIGNER, ROOT, Vec::new()),
                &rsa_key,
                &root_key,
            ),
            tsa_root: certificate(
                &spec(TSA_ROOT_SERIAL, TSA_ROOT, TSA_ROOT, ca_extensions()),
                &tsa_root_key,
                &tsa_root_key,
            ),
            tsa: certificate(
                &spec(TSA_SERIAL, TSA, TSA_ROOT, timestamping_extensions()),
                &tsa_key,
                &tsa_root_key,
            ),
            rogue_tsa: certificate(
                &spec(
                    ROGUE_TSA_SERIAL,
                    ROGUE_TSA,
                    ROGUE_TSA_ROOT,
                    timestamping_extensions(),
                ),
                &tsa_key,
                &rogue_root_key,
            ),
            stranger: certificate(
                &spec(STRANGER_SERIAL, STRANGER, STRANGER, ca_extensions()),
                &stranger_key,
                &stranger_key,
            ),
            root_key,
            intermediate_key,
            signer_key,
            rsa_key,
            tsa_key,
        }
    }

    /// The anchors every test trusts: the root for certificate issuing
    /// and the time-stamping root for time-stamping.
    fn anchors(&self) -> TrustAnchors {
        TrustAnchors::new(vec![
            anchor(&self.root, AnchorRole::CertificateIssuing),
            anchor(&self.tsa_root, AnchorRole::TimeStamping),
        ])
    }

    /// The key and certificate of `signer`.
    fn signer(&self, signer: Signer) -> (&TestKey, &[u8]) {
        match signer {
            Signer::Direct => (&self.signer_key, &self.direct_signer),
            Signer::Issued => (&self.signer_key, &self.issued_signer),
            Signer::Rsa => (&self.rsa_key, &self.rsa_signer),
        }
    }

    /// A token from the authority `stamp` names over `imprint`.
    fn token(&self, stamp: Stamp, imprint: &[u8]) -> Option<Vec<u8>> {
        let tsa = match stamp {
            Stamp::None => return None,
            Stamp::Anchored => &self.tsa,
            Stamp::SelfMade => &self.rogue_tsa,
        };
        Some(timestamp_token(
            tsa,
            &self.tsa_key,
            DigestAlgorithm::Sha256,
            imprint,
            day(STAMPED),
        ))
    }

    /// Sign `objects` as `format` through the signing router, with the
    /// timestamp `stamp` names, embedding `material`.
    fn sign(
        &self,
        format: Format,
        objects: Vec<DataObject>,
        signer: Signer,
        stamp: Stamp,
        material: &ValidationMaterial,
    ) -> Vec<u8> {
        let (key, der) = self.signer(signer);
        let owned = OwnedCert::from_der(der).expect("signer parses");
        let certificate = owned.view();
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: match signer {
                Signer::Direct | Signer::Issued => SignatureAlgorithm::EcdsaSha256,
                Signer::Rsa => SignatureAlgorithm::RsaPkcs1Sha256,
            },
            signing_time: Some(SIGNING_TIME),
        };
        let planned =
            plan(format, objects, &parameters, &SignatureMetadata::default()).expect("plans");
        let signature = key.sign_raw(planned.to_be_signed());
        let imprint = planned
            .timestamp_digest(&parameters, &signature, DigestAlgorithm::Sha256)
            .expect("timestamp digest");
        let timestamps: Vec<Vec<u8>> = self.token(stamp, &imprint).into_iter().collect();
        planned
            .finish(&parameters, &signature, &timestamps, material)
            .expect("finishes")
    }

    /// `pdf` signed by `signer`.
    fn sign_pdf(
        &self,
        pdf: Vec<u8>,
        signer: Signer,
        stamp: Stamp,
        material: &ValidationMaterial,
    ) -> Vec<u8> {
        self.sign(
            Format::Pades,
            vec![DataObject {
                name: PDF_NAME.to_owned(),
                mime_type: PDF_TYPE.to_owned(),
                content: pdf,
            }],
            signer,
            stamp,
            material,
        )
    }

    /// The minimal PDF signed by `signer`.
    fn pdf(&self, signer: Signer, stamp: Stamp, material: &ValidationMaterial) -> Vec<u8> {
        self.sign_pdf(minimal_pdf(), signer, stamp, material)
    }

    /// A signed container or CMS over the note.
    fn note(&self, format: Format) -> Vec<u8> {
        self.sign(
            format,
            vec![DataObject {
                name: NOTE_NAME.to_owned(),
                mime_type: NOTE_TYPE.to_owned(),
                content: NOTE.to_vec(),
            }],
            Signer::Direct,
            Stamp::None,
            &ValidationMaterial::default(),
        )
    }

    /// An OCSP answer from `issuer` about `serial`, revoked at
    /// `revoked` when set, produced on `produced`.
    fn ocsp(
        &self,
        issuer: &[u8],
        issuer_name: &str,
        issuer_key: &TestKey,
        serial: u8,
        revoked: Option<DateTime>,
        produced: u8,
    ) -> Vec<u8> {
        let issuer = OwnedCert::from_der(issuer).expect("issuer parses");
        ocsp_response(&OcspSpec {
            responder_key: issuer_key,
            responder: ResponderName::ByName(issuer_name),
            issuer: &issuer,
            serial,
            revoked,
            produced_at: day(produced),
            this_update: day(produced),
            next_update: Some(day(ENDS)),
            embedded: Vec::new(),
        })
    }

    /// The issued signer's chain and OCSP answers about the signer and
    /// the intermediate, produced after the timestamps; the signer is
    /// revoked on `revoked` when set.
    fn lt_material(&self, revoked: Option<u8>) -> ValidationMaterial {
        ValidationMaterial {
            certificates: vec![self.intermediate.clone()],
            ocsp_responses: vec![
                self.ocsp(
                    &self.intermediate,
                    INTERMEDIATE,
                    &self.intermediate_key,
                    ISSUED_SIGNER_SERIAL,
                    revoked.map(day),
                    ANSWERED,
                ),
                self.ocsp(
                    &self.root,
                    ROOT,
                    &self.root_key,
                    INTERMEDIATE_SERIAL,
                    None,
                    ANSWERED,
                ),
            ],
            crls: Vec::new(),
        }
    }

    /// An answer from the root that the direct signer is revoked on
    /// `revoked`, produced the day after.
    fn direct_revoked_on(&self, revoked: u8) -> ValidationMaterial {
        ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: vec![self.ocsp(
                &self.root,
                ROOT,
                &self.root_key,
                DIRECT_SIGNER_SERIAL,
                Some(day(revoked)),
                revoked.saturating_add(1),
            )],
            crls: Vec::new(),
        }
    }

    /// A PDF signature assembled from the testkit by `signer`: an
    /// `ETSI.CAdES.detached` CMS binding the signer with
    /// `signing-certificate-v2`, after `form` adjusts its parts and
    /// `extra` adds signed attributes.
    fn foreign_pdf(
        &self,
        signer: Signer,
        extra: &[Vec<u8>],
        form: impl FnOnce(&mut CmsParts<'_>),
    ) -> Vec<u8> {
        let (key, der) = self.signer(signer);
        let placeholder = prepare(
            &minimal_pdf(),
            &SignatureMetadata::default(),
            DEFAULT_SIGNATURE_CAPACITY,
        )
        .expect("prepares");
        let content = placeholder.signed_octets();
        let mut attributes = content_attributes(known::DATA, key.hash(), &content);
        attributes.push(signing_certificate_v2(der));
        attributes.extend_from_slice(extra);
        let mut parts = CmsParts::detached(key, der, &content);
        parts.signed_attributes = Some(attribute_set(&attributes));
        form(&mut parts);
        placeholder.finish(&cms(&parts)).expect("the CMS fits")
    }

    /// A foreign PDF signature by the direct signer carrying a
    /// signature timestamp over `imprint_of` the signature value, under
    /// the imprint algorithm `algorithm`.
    fn foreign_timestamped_pdf(
        &self,
        algorithm: DigestAlgorithm,
        imprint_of: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Vec<u8> {
        self.foreign_pdf(Signer::Direct, &[], |parts| {
            let signed = parts.signed_attributes.clone().expect("signed attributes");
            let signature = parts.key.sign(&signed);
            let token = timestamp_token(
                &self.tsa,
                &self.tsa_key,
                algorithm,
                &imprint_of(&signature),
                day(STAMPED),
            );
            parts.unsigned_attributes = vec![attribute(known::SIGNATURE_TIME_STAMP_TOKEN, &token)];
            parts.signature = Some(signature);
        })
    }

    /// Verify `bytes` at [`NOW`] under the world's anchors.
    fn verify(&self, bytes: Vec<u8>) -> Result<DocumentReport, DocumentFailure> {
        verify_under(bytes, &self.anchors())
    }
}

/// `der` trusted for `role` without bounds.
fn anchor(der: &[u8], role: AnchorRole) -> TrustAnchor {
    TrustAnchor::new(
        OwnedCert::from_der(der).expect("anchor parses"),
        role,
        vec![GrantedPeriod::unbounded()],
    )
    .expect("an anchor with a period")
}

/// Verify `bytes` at [`NOW`] under `anchors`.
fn verify_under(bytes: Vec<u8>, anchors: &TrustAnchors) -> Result<DocumentReport, DocumentFailure> {
    verify(&DocumentFile::from_file(bytes)?, anchors, day(NOW))
}

/// The one judged signature of a report.
fn only(report: &DocumentReport) -> &SignatureReport {
    let [row] = exactly(report.rows(), "one signature");
    judged(row)
}

/// The report of a judged row.
fn judged(row: &SignatureRow) -> &SignatureReport {
    match row {
        SignatureRow::Judged(report) => Some(report),
        SignatureRow::Unsupported(_) => None,
    }
    .expect("the signature was judged")
}

/// Change one byte inside the first signed span.
fn tamper(mut pdf: Vec<u8>) -> Vec<u8> {
    let at = pdf
        .windows(MEDIA_BOX.len())
        .position(|window| window == MEDIA_BOX)
        .expect("media box present");
    pdf.get_mut(at..at.saturating_add(MEDIA_BOX.len()))
        .expect("in range")
        .copy_from_slice(TAMPERED_MEDIA_BOX);
    pdf
}

/// `pdf` with a document timestamp from the anchored TSA at
/// [`STAMPED`].
fn with_document_timestamp(world: &World, pdf: &[u8]) -> Vec<u8> {
    let placeholder =
        prepare_document_timestamp(pdf, DEFAULT_SIGNATURE_CAPACITY).expect("prepares");
    let token = timestamp_token(
        &world.tsa,
        &world.tsa_key,
        DigestAlgorithm::Sha256,
        &placeholder.digest(DigestAlgorithm::Sha256),
        day(STAMPED),
    );
    placeholder.finish(&token).expect("finishes")
}

#[test]
fn a_level_b_pdf_is_intact_valid_and_anchored_without_proof_of_existence() {
    let world = World::new();
    let report = world
        .verify(world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default()))
        .expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert_eq!(signature.proof_of_existence(), None);
    assert!(signature.timestamps().is_empty());
    assert_eq!(signature.validation_time(), day(NOW));
    assert!(signature.covers_whole_document());
    assert_eq!(signature.revocation(), Revocation::Unavailable);
    assert_eq!(signature.signer().name(), DIRECT_SIGNER);
    assert_eq!(
        signature.issuer_certificate().map(OwnedCert::as_der),
        Some(world.root.as_slice())
    );
    assert!(signature.is_valid());
    assert!(report.document_timestamps().is_empty());
    assert_eq!(report.anchors_fetched_at(), None);
    assert!(report.is_valid());
}

#[test]
fn a_signature_timestamp_proves_existence() {
    let world = World::new();
    let report = world
        .verify(world.pdf(
            Signer::Direct,
            Stamp::Anchored,
            &ValidationMaterial::default(),
        ))
        .expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert_eq!(
        signature.timestamps(),
        [TimestampReport::Verified {
            time: day(STAMPED),
            anchored: true
        }]
    );
    assert_eq!(signature.proof_of_existence(), Some(day(STAMPED)));
    assert_eq!(signature.validation_time(), day(STAMPED));
    assert!(signature.is_valid());
}

#[test]
fn level_lt_chains_through_the_store_and_reads_a_later_ocsp_answer() {
    let world = World::new();
    let pdf = world.pdf(Signer::Issued, Stamp::Anchored, &world.lt_material(None));
    let report = world.verify(pdf).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert!(!signature.covers_whole_document());
    assert_eq!(
        signature.issuer_certificate().map(OwnedCert::as_der),
        Some(world.intermediate.as_slice())
    );
    assert_eq!(
        signature.revocation(),
        Revocation::Good { at: day(ANSWERED) }
    );
    assert!(report.is_valid());
}

#[test]
fn a_signer_revoked_before_the_proof_of_existence_is_not_valid() {
    let world = World::new();
    let pdf = world.pdf(
        Signer::Issued,
        Stamp::Anchored,
        &world.lt_material(Some(REVOKED_EARLY)),
    );
    let report = world.verify(pdf).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert_eq!(
        signature.revocation(),
        Revocation::Revoked {
            at: day(REVOKED_EARLY)
        }
    );
    assert!(!signature.is_valid());
    assert!(!report.is_valid());
}

#[test]
fn a_revocation_after_the_proof_of_existence_leaves_the_signature_valid() {
    let world = World::new();
    let pdf = world.pdf(
        Signer::Issued,
        Stamp::Anchored,
        &world.lt_material(Some(REVOKED_LATER)),
    );
    let report = world.verify(pdf).expect("report");
    let signature = only(&report);
    assert_eq!(signature.proof_of_existence(), Some(day(STAMPED)));
    assert_eq!(
        signature.revocation(),
        Revocation::Revoked {
            at: day(REVOKED_LATER)
        }
    );
    assert!(signature.is_valid());
    assert!(report.is_valid());
}

#[test]
fn an_untrusted_root_leaves_the_chain_unverified_but_names_the_issuer() {
    let world = World::new();
    let mut material = world.lt_material(None);
    material.certificates.push(world.root.clone());
    let pdf = world.pdf(Signer::Issued, Stamp::Anchored, &material);
    let anchors = TrustAnchors::new(vec![
        anchor(&world.stranger, AnchorRole::CertificateIssuing),
        anchor(&world.tsa_root, AnchorRole::TimeStamping),
    ]);
    let report = verify_under(pdf, &anchors).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(!signature.chain_verified());
    assert_eq!(
        signature.issuer_certificate().map(OwnedCert::as_der),
        Some(world.intermediate.as_slice())
    );
    assert!(!report.is_valid());
}

#[test]
fn an_anchor_outside_its_granted_period_does_not_anchor() {
    let world = World::new();
    let pdf = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let lapsed = TrustAnchors::new(vec![
        TrustAnchor::new(
            OwnedCert::from_der(&world.root).expect("root parses"),
            AnchorRole::CertificateIssuing,
            vec![GrantedPeriod::new(day(ISSUED), Some(day(STAMPED))).expect("a period")],
        )
        .expect("an anchor"),
    ])
    .fetched(day(ANSWERED));
    let report = verify_under(pdf.clone(), &lapsed).expect("report");
    assert!(!only(&report).chain_verified());
    assert_eq!(report.anchors_fetched_at(), Some(day(ANSWERED)));

    // The root as a time-stamping anchor issues no signer.
    let wrong_role = TrustAnchors::new(vec![anchor(&world.root, AnchorRole::TimeStamping)]);
    assert!(
        !only(&verify_under(pdf, &wrong_role).expect("report")).chain_verified(),
        "an anchor counts only for its role"
    );
}

#[test]
fn a_document_timestamp_covering_the_signature_proves_existence() {
    let world = World::new();
    let signed = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let stamped = with_document_timestamp(&world, &signed);
    let length = stamped.len();
    let report = world.verify(stamped).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert_eq!(signature.proof_of_existence(), Some(day(STAMPED)));
    assert!(!signature.covers_whole_document());
    let [stamp] = exactly(report.document_timestamps(), "one document timestamp");
    assert_eq!(
        stamp.timestamp(),
        TimestampReport::Verified {
            time: day(STAMPED),
            anchored: true
        }
    );
    assert_eq!(stamp.covers(), length);
    assert!(report.is_valid());
}

#[test]
fn a_document_timestamp_over_other_bytes_is_invalid_and_proves_nothing() {
    let world = World::new();
    let signed = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let placeholder =
        prepare_document_timestamp(&signed, DEFAULT_SIGNATURE_CAPACITY).expect("prepares");
    let token = timestamp_token(
        &world.tsa,
        &world.tsa_key,
        DigestAlgorithm::Sha256,
        &DigestAlgorithm::Sha256.digest(NOTE),
        day(STAMPED),
    );
    let report = world
        .verify(placeholder.finish(&token).expect("finishes"))
        .expect("report");
    assert_eq!(only(&report).proof_of_existence(), None);
    let [stamp] = exactly(report.document_timestamps(), "one document timestamp");
    assert_eq!(
        stamp.timestamp(),
        TimestampReport::Invalid(TimestampError::ImprintMismatch)
    );
    assert!(only(&report).is_valid());
    assert!(!report.is_valid());
}

#[test]
fn a_changed_byte_in_the_signed_span_breaks_only_integrity() {
    let world = World::new();
    let pdf = tamper(world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default()));
    let report = world.verify(pdf).expect("report");
    let signature = only(&report);
    assert!(!signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert!(!report.is_valid());
}

#[test]
fn both_subfilters_verify_and_only_pades_requires_the_ess_binding() {
    let world = World::new();
    // `contentType` and `messageDigest` alone, no ESS attribute, under
    // the subfilter `subfilter` names.
    let unbound = |subfilter: &[u8]| {
        let placeholder = prepare(
            &minimal_pdf(),
            &SignatureMetadata::default(),
            DEFAULT_SIGNATURE_CAPACITY,
        )
        .expect("prepares")
        .respelled(SUBFILTER_PADES, subfilter);
        let content = placeholder.signed_octets();
        let parts = CmsParts::detached(&world.signer_key, &world.direct_signer, &content);
        placeholder.finish(&cms(&parts)).expect("fits")
    };

    let report = world.verify(unbound(SUBFILTER_PKCS7)).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(
        signature.signature_valid(),
        "adbe.pkcs7.detached needs no ESS"
    );
    assert!(report.is_valid());

    let report = world.verify(unbound(SUBFILTER_PADES)).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(
        !signature.signature_valid(),
        "ETSI.CAdES.detached requires the ESS binding"
    );
}

#[test]
fn a_pades_signature_with_a_signing_time_attribute_is_not_valid() {
    let world = World::new();
    let signing_time = attribute(known::SIGNING_TIME, &utc_time(day(STAMPED)));
    let report = world
        .verify(world.foreign_pdf(Signer::Direct, &[signing_time], |_parts| {}))
        .expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(!signature.signature_valid());
    assert!(!report.is_valid());

    let report = world
        .verify(world.foreign_pdf(Signer::Direct, &[], |_parts| {}))
        .expect("report");
    assert!(only(&report).is_valid(), "the same signature without it");
}

#[test]
fn an_rsa_2048_pades_signature_verifies() {
    let world = World::new();
    let report = world
        .verify(world.pdf(Signer::Rsa, Stamp::Anchored, &ValidationMaterial::default()))
        .expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert_eq!(signature.signer().name(), RSA_SIGNER);
    assert!(report.is_valid());
}

#[test]
fn an_asic_e_xades_container_verifies() {
    let world = World::new();
    let report = world
        .verify(world.note(Format::AsicEXades))
        .expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert!(report.is_valid());
}

#[test]
fn an_asic_e_cades_container_verifies() {
    let world = World::new();
    let report = world
        .verify(world.note(Format::AsicECades))
        .expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert!(report.is_valid());
}

#[test]
fn an_attached_cades_file_verifies() {
    let world = World::new();
    let report = world.verify(world.note(Format::Cades)).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(signature.chain_verified());
    assert!(report.is_valid());
}

#[test]
fn files_the_verifier_cannot_judge_are_typed_failures() {
    let world = World::new();
    assert_eq!(
        world.verify(NOTE.to_vec()).map(|_report| ()),
        Err(DocumentFailure::NotASignedDocument)
    );
    assert_eq!(
        world.verify(minimal_pdf()).map(|_report| ()),
        Err(DocumentFailure::NoSignatures)
    );
    assert_eq!(
        world
            .verify(world.note(Format::CadesDetached))
            .map(|_report| ()),
        Err(DocumentFailure::UnsupportedProfile(
            UnsupportedProfile::DetachedCms
        ))
    );
    assert!(matches!(
        world.verify(tlv(SEQUENCE, GARBAGE_DER)).map(|_report| ()),
        Err(DocumentFailure::UnsupportedProfile(
            UnsupportedProfile::Cms(CadesReadError::Cms(_))
        ))
    ));
}

#[test]
fn serial_signatures_are_each_judged_against_their_own_range() {
    let world = World::new();
    let once = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let twice = world.sign_pdf(
        once,
        Signer::Rsa,
        Stamp::None,
        &ValidationMaterial::default(),
    );
    let report = world.verify(twice).expect("report");
    let [first, second] = exactly(report.rows(), "two signatures");
    let (first, second) = (judged(first), judged(second));
    assert_eq!(first.signer().name(), DIRECT_SIGNER);
    assert!(!first.covers_whole_document());
    assert!(first.is_valid());
    assert_eq!(second.signer().name(), RSA_SIGNER);
    assert!(second.covers_whole_document());
    assert!(second.is_valid());
    assert!(report.is_valid());
}

#[test]
fn an_unsupported_signature_is_its_own_row_and_blocks_the_document() {
    let world = World::new();
    let once = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let placeholder = prepare(
        &once,
        &SignatureMetadata::default(),
        DEFAULT_SIGNATURE_CAPACITY,
    )
    .expect("prepares")
    .respelled(SUBFILTER_PADES, SUBFILTER_UNKNOWN);
    let content = placeholder.signed_octets();
    let parts = CmsParts::detached(&world.signer_key, &world.direct_signer, &content);
    let twice = placeholder.finish(&cms(&parts)).expect("fits");
    let report = world.verify(twice).expect("report");
    let [first, second] = exactly(report.rows(), "two signatures");
    assert!(first.is_valid());
    assert!(matches!(
        second,
        SignatureRow::Unsupported(UnsupportedSignature::PdfSubFilter)
    ));
    assert!(!report.is_valid());
}

/// The loss scenario of the design: a self-made timestamp whose time
/// lies inside the signer certificate's validity, over a signer revoked
/// since. The token verifies but is unproven, the signature is judged
/// at now, the revocation is found, and the report says not valid.
#[test]
fn a_self_made_timestamp_is_unproven_and_the_signature_is_judged_at_now() {
    let world = World::new();
    let material = world.direct_revoked_on(REVOKED_LATER);
    let report = world
        .verify(world.pdf(Signer::Direct, Stamp::SelfMade, &material))
        .expect("report");
    let signature = only(&report);
    assert_eq!(
        signature.timestamps(),
        [TimestampReport::Verified {
            time: day(STAMPED),
            anchored: false
        }]
    );
    assert_eq!(signature.proof_of_existence(), None);
    assert_eq!(signature.validation_time(), day(NOW));
    assert!(signature.chain_verified());
    assert_eq!(
        signature.revocation(),
        Revocation::Revoked {
            at: day(REVOKED_LATER)
        }
    );
    assert!(!signature.is_valid());

    // An anchored token at the same time proves the signature existed
    // before the revocation.
    let report = world
        .verify(world.pdf(Signer::Direct, Stamp::Anchored, &material))
        .expect("report");
    let signature = only(&report);
    assert_eq!(signature.proof_of_existence(), Some(day(STAMPED)));
    assert!(signature.is_valid());
}

#[test]
fn a_timestamp_from_a_signing_anchor_is_not_anchored() {
    let world = World::new();
    let pdf = world.pdf(
        Signer::Direct,
        Stamp::Anchored,
        &ValidationMaterial::default(),
    );
    let issuing_only = TrustAnchors::new(vec![
        anchor(&world.root, AnchorRole::CertificateIssuing),
        anchor(&world.tsa_root, AnchorRole::CertificateIssuing),
    ]);
    let report = verify_under(pdf, &issuing_only).expect("report");
    assert_eq!(
        only(&report).timestamps(),
        [TimestampReport::Verified {
            time: day(STAMPED),
            anchored: false
        }]
    );
}

#[test]
fn a_live_answer_fills_only_an_unavailable_status_on_a_verified_chain() {
    let world = World::new();
    let pdf = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let live = Revocation::Revoked { at: day(NOW) };
    let report = world
        .verify(pdf.clone())
        .expect("report")
        .with_live_revocation(|_signature| live);
    assert_eq!(only(&report).revocation(), live);
    assert!(!report.is_valid(), "a revocation without proof counts");

    let anchors = TrustAnchors::new(vec![anchor(
        &world.stranger,
        AnchorRole::CertificateIssuing,
    )]);
    let mut asked = false;
    let report = verify_under(pdf, &anchors)
        .expect("report")
        .with_live_revocation(|_signature| {
            asked = true;
            Revocation::Good { at: day(NOW) }
        });
    assert!(!asked, "an unverified chain is not asked about");
    assert_eq!(only(&report).revocation(), Revocation::Unavailable);
}

#[test]
fn the_signer_identity_prefers_given_names_and_surname() {
    let key = TestKey::derive(TestCurve::P256, b"person");
    let person = certificate_named(
        &spec(PERSON_SERIAL, PERSON, PERSON, Vec::new()),
        &name_of(&[
            (known::COMMON_NAME, UTF8_STRING, PERSON),
            (known::SURNAME, UTF8_STRING, SURNAME),
            (known::GIVEN_NAME, UTF8_STRING, GIVEN),
            (known::SERIAL_NUMBER, PRINTABLE_STRING, IDENTIFIER),
        ]),
        &key,
        &key,
    );
    let identity = SignerIdentity::of(&OwnedCert::from_der(&person).expect("parses"));
    assert_eq!(identity.name(), format!("{GIVEN} {SURNAME}"));
    assert_eq!(
        identity.identifier().map(|peuin| peuin.as_str()),
        Some(IDENTIFIER)
    );

    let plain = certificate(
        &spec(PERSON_SERIAL, DIRECT_SIGNER, DIRECT_SIGNER, Vec::new()),
        &key,
        &key,
    );
    let identity = SignerIdentity::of(&OwnedCert::from_der(&plain).expect("parses"));
    assert_eq!(identity.name(), DIRECT_SIGNER);
    assert!(identity.identifier().is_none());
}

/// An `AlgorithmIdentifier` of `oid`, with NULL parameters when `null`.
fn algorithm(oid: refineid_cms::oid::Oid<'_>, null: bool) -> Vec<u8> {
    let mut body = tlv(OBJECT_IDENTIFIER, oid.as_bytes());
    if null {
        body.extend_from_slice(&tlv(NULL, []));
    }
    tlv(SEQUENCE, body)
}

#[test]
fn rsa_algorithm_parameters_may_be_null_or_absent() {
    let world = World::new();
    for (digest_null, signature_null) in [(true, true), (false, false), (true, false)] {
        let report = world
            .verify(world.foreign_pdf(Signer::Rsa, &[], |parts| {
                parts.digest_algorithm = algorithm(known::SHA256, digest_null);
                parts.signature_algorithm = Some(algorithm(known::SHA256_WITH_RSA, signature_null));
            }))
            .expect("report");
        let signature = only(&report);
        assert!(signature.document_intact());
        assert!(
            signature.signature_valid(),
            "{digest_null} {signature_null}"
        );
    }
}

#[test]
fn the_bare_ec_public_key_identifier_takes_the_digest_algorithm() {
    let world = World::new();
    let report = world
        .verify(world.foreign_pdf(Signer::Direct, &[], |parts| {
            parts.signature_algorithm = Some(algorithm(known::EC_PUBLIC_KEY, false));
        }))
        .expect("report");
    assert!(only(&report).signature_valid());
}

#[test]
fn a_disagreeing_signature_algorithm_is_refused() {
    let world = World::new();
    let report = world
        .verify(world.foreign_pdf(Signer::Direct, &[], |parts| {
            parts.signature_algorithm = Some(algorithm(known::ECDSA_WITH_SHA384, false));
        }))
        .expect("report");
    let [row] = exactly(report.rows(), "one signature");
    assert!(matches!(
        row,
        SignatureRow::Unsupported(UnsupportedSignature::Cms(CadesReadError::Cms(
            CmsError::AlgorithmMismatch
        )))
    ));
    assert!(!report.is_valid());

    // An RSA scheme over an EC key verifies nothing.
    let report = world
        .verify(world.foreign_pdf(Signer::Direct, &[], |parts| {
            parts.signature_algorithm = Some(algorithm(known::SHA256_WITH_RSA, true));
        }))
        .expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(!signature.signature_valid());
}

#[test]
fn an_ecdsa_identifier_with_null_parameters_is_refused() {
    let world = World::new();
    let report = world
        .verify(world.foreign_pdf(Signer::Direct, &[], |parts| {
            parts.signature_algorithm = Some(algorithm(known::ECDSA_WITH_SHA256, true));
        }))
        .expect("report");
    let [row] = exactly(report.rows(), "one signature");
    assert!(matches!(
        row,
        SignatureRow::Unsupported(UnsupportedSignature::Cms(CadesReadError::Cms(
            CmsError::AlgorithmParameters
        )))
    ));
}

#[test]
fn a_signature_timestamp_verifies_under_its_own_imprint_algorithm() {
    let world = World::new();
    for algorithm in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ] {
        let report = world
            .verify(
                world.foreign_timestamped_pdf(algorithm, |signature| algorithm.digest(signature)),
            )
            .expect("report");
        let signature = only(&report);
        assert_eq!(signature.proof_of_existence(), Some(day(STAMPED)));
        assert!(signature.is_valid());
    }
}

#[test]
fn a_sha_512_imprint_verifies_and_a_wrong_length_imprint_is_refused() {
    let world = World::new();
    let sha512 = world.foreign_timestamped_pdf(DigestAlgorithm::Sha512, |signature| {
        DigestAlgorithm::Sha512.digest(signature)
    });
    let report = world.verify(sha512).expect("report");
    let signature = only(&report);
    assert_eq!(
        signature.timestamps(),
        [TimestampReport::Verified {
            time: day(STAMPED),
            anchored: true
        }]
    );
    assert_eq!(signature.proof_of_existence(), Some(day(STAMPED)));
    assert!(signature.is_valid());

    // A SHA-256 imprint of SHA-512 length.
    let wrong_length = world.foreign_timestamped_pdf(DigestAlgorithm::Sha256, |signature| {
        DigestAlgorithm::Sha512.digest(signature)
    });
    let report = world.verify(wrong_length).expect("report");
    let signature = only(&report);
    assert!(signature.signature_valid());
    assert!(matches!(
        signature.timestamps(),
        [TimestampReport::Invalid(TimestampError::Malformed(_))]
    ));
    assert_eq!(signature.proof_of_existence(), None);
    assert!(!signature.is_valid());
}

#[test]
fn a_sha_512_pades_signature_verifies_under_ecdsa_and_rsa() {
    let world = World::new();
    for (signer, scheme) in [
        (Signer::Direct, known::ECDSA_WITH_SHA512),
        (Signer::Rsa, known::SHA512_WITH_RSA),
    ] {
        let (key, der) = world.signer(signer);
        let placeholder = prepare(
            &minimal_pdf(),
            &SignatureMetadata::default(),
            DEFAULT_SIGNATURE_CAPACITY,
        )
        .expect("prepares");
        let content = placeholder.signed_octets();
        let mut attributes = content_attributes(known::DATA, HashAlgorithm::Sha512, &content);
        attributes.push(signing_certificate_v2(der));
        let signed = attribute_set(&attributes);
        let mut parts = CmsParts::detached(key, der, &content);
        parts.digest_algorithm = algorithm(known::SHA512, false);
        parts.signature_algorithm = Some(algorithm(scheme, signer == Signer::Rsa));
        parts.signature = Some(key.sign_with(HashAlgorithm::Sha512, &signed));
        parts.signed_attributes = Some(signed);
        let pdf = placeholder.finish(&cms(&parts)).expect("the CMS fits");
        let report = world.verify(pdf).expect("report");
        let signature = only(&report);
        assert!(signature.document_intact(), "{signer:?}");
        assert!(signature.signature_valid(), "{signer:?}");
        assert!(signature.is_valid(), "{signer:?}");
    }
    assert_eq!(DigestAlgorithm::from_oid(known::SHA1), None);
}

#[test]
fn a_signature_timestamp_over_other_bytes_is_invalid() {
    let world = World::new();
    let report = world
        .verify(
            world.foreign_timestamped_pdf(DigestAlgorithm::Sha256, |_signature| {
                DigestAlgorithm::Sha256.digest(NOTE)
            }),
        )
        .expect("report");
    let signature = only(&report);
    assert_eq!(
        signature.timestamps(),
        [TimestampReport::Invalid(TimestampError::ImprintMismatch)]
    );
    assert!(signature.signature_valid());
    assert!(!signature.is_valid());
}
