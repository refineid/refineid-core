// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
//! End-to-end tests of [`super::verify`]: documents written by the
//! signing side of this crate, or assembled from the testkit, over
//! synthetic keys, certificates and evidence.

use super::{
    AnchorRole, ArchiveForm, CertificationPath, DocumentChange, DocumentFailure, DocumentFile,
    DocumentReport, GrantedPeriod, Revision, Revocation, SignatureOutcome, SignatureReport,
    SignatureRow, SignerIdentity, TimestampReport, TrustAnchor, TrustAnchors, UnsupportedProfile,
    UnsupportedSignature, exactly, verify,
};
use crate::asic::DataObject;
use crate::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime};
use crate::cms::CmsError;
use crate::crl::CrlReason;
use crate::document::{Format, plan};
use crate::pades::{
    DEFAULT_SIGNATURE_CAPACITY, SignatureMetadata, prepare, prepare_document_timestamp,
};
use crate::testkit::{
    CertificateSpec, CmsParts, KEY_USAGE_NON_REPUDIATION, KEY_USAGE_NON_REPUDIATION_UNUSED, NULL,
    OBJECT_IDENTIFIER, OcspSpec, PRINTABLE_STRING, ResponderName, SEQUENCE, TestCurve, TestKey,
    UTF8_STRING, attribute, attribute_set, ca_extensions, certificate, certificate_named, cms,
    content_attributes, day, key_usage, minimal_pdf, name_of, ocsp_response,
    signing_certificate_v2, timestamp_token, timestamping_extensions, tlv, utc_time,
};
use crate::timestamp::TimestampError;
use crate::validation::ValidationMaterial;
use crate::verification::cades::CadesReadError;
use crate::verification::xml::{Algorithm, Canonicalization, Comments, XmlDocument};
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
/// Common name of the person certificate, in the shape a FINEID
/// certificate carries: surname, given names and identifier, the
/// surname in capitals.
const PERSON: &str = "SURNAME Given Second 99999999X";
/// An organisation name holding a character RFC 4514 escapes.
const ORGANISATION: &str = "Synthetic, Ltd";
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

/// The extensions of a document signer: a critical Key Usage asserting
/// `nonRepudiation`, as a qualified signing certificate carries.
/// The OCSP responders and CRL distribution point the signers name.
const OCSP_FIRST: &str = "http://ocsp-one.example/";
const OCSP_SECOND: &str = "http://ocsp-two.example/";
const CRL_POINT: &str = "http://crl.example/root.crl";

fn signer_extensions() -> Vec<Vec<u8>> {
    vec![
        key_usage(KEY_USAGE_NON_REPUDIATION_UNUSED, KEY_USAGE_NON_REPUDIATION),
        crate::testkit::ocsp_access(&[OCSP_FIRST, OCSP_SECOND]),
        crate::testkit::crl_distribution_points(&[CRL_POINT]),
    ]
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
                &spec(
                    DIRECT_SIGNER_SERIAL,
                    DIRECT_SIGNER,
                    ROOT,
                    signer_extensions(),
                ),
                &signer_key,
                &root_key,
            ),
            issued_signer: certificate(
                &spec(
                    ISSUED_SIGNER_SERIAL,
                    ISSUED_SIGNER,
                    INTERMEDIATE,
                    signer_extensions(),
                ),
                &signer_key,
                &intermediate_key,
            ),
            rsa_signer: certificate(
                &spec(RSA_SIGNER_SERIAL, RSA_SIGNER, ROOT, signer_extensions()),
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
            cert_id: crate::testkit::CertIdAlgorithm::Sha1,
            revocation_reason: None,
            response_extensions: Vec::new(),
        })
    }

    /// The issued signer's chain and OCSP answers about the signer and
    /// the intermediate, produced after the timestamps; the signer is
    /// revoked on `revoked` when set, and its answer produced no
    /// earlier than the revocation it reports.
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
                    revoked.map_or(ANSWERED, |revoked| revoked.max(ANSWERED)),
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
    match row.outcome() {
        SignatureOutcome::Judged(report) => Some(report),
        SignatureOutcome::Unsupported { .. } => None,
    }
    .expect("the signature was judged")
}

/// What a timestamp report was found to be, without its authority.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// Anchored at this time.
    Anchored(DateTime),
    /// Claiming this time.
    Claimed(DateTime),
    /// Invalid for this reason.
    Invalid(TimestampError),
    /// Not judged.
    Unsupported,
}

/// The kind of `report`.
fn kind(report: &TimestampReport) -> Kind {
    match report {
        TimestampReport::Anchored { time, .. } => Kind::Anchored(*time),
        TimestampReport::Claimed { time, .. } => Kind::Claimed(*time),
        TimestampReport::Invalid { error, .. } => Kind::Invalid(*error),
        TimestampReport::Unsupported { .. } => Kind::Unsupported,
    }
}

/// The kinds of `reports`.
fn kinds(reports: &[TimestampReport]) -> Vec<Kind> {
    reports.iter().map(kind).collect()
}

/// The DER of each certificate of `path`.
fn ders(path: &CertificationPath) -> Vec<&[u8]> {
    path.certificates().iter().map(OwnedCert::as_der).collect()
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
    assert_eq!(signature.revision(), Revision::WholeDocument);
    assert_eq!(signature.revocation(), Revocation::Unavailable);
    assert_eq!(signature.signer().name(), DIRECT_SIGNER);
    assert_eq!(ders(signature.chain()), [world.root.as_slice()]);
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
        kinds(signature.timestamps()),
        [Kind::Anchored(day(STAMPED))]
    );
    let [stamp] = exactly(signature.timestamps(), "one timestamp");
    let authority = stamp.authority().expect("a verified token");
    assert_eq!(authority.signer().as_der(), world.tsa.as_slice());
    assert_eq!(
        ders(authority.chain()),
        [world.tsa_root.as_slice()],
        "the token signer's path ends in the time-stamping anchor"
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
    assert_eq!(signature.revision(), Revision::LaterRevisionsHarmless);
    assert_eq!(
        ders(signature.chain()),
        [world.intermediate.as_slice(), world.root.as_slice()]
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
            at: day(REVOKED_EARLY),
            reason: None,
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
            at: day(REVOKED_LATER),
            reason: None,
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
        signature
            .chain()
            .certificates()
            .first()
            .map(OwnedCert::as_der),
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
    assert_eq!(signature.revision(), Revision::LaterRevisionsHarmless);
    let [stamp] = exactly(report.document_timestamps(), "one document timestamp");
    assert_eq!(kind(stamp.timestamp()), Kind::Anchored(day(STAMPED)));
    assert_eq!(stamp.covers(), length);
    assert_eq!(
        signature.covering_document_timestamps(),
        report.document_timestamps(),
        "the signature names the document timestamp that covers it"
    );
    assert!(report.is_valid());
}

#[test]
fn a_signature_without_a_document_timestamp_is_covered_by_none() {
    let world = World::new();
    let report = world
        .verify(world.pdf(
            Signer::Direct,
            Stamp::Anchored,
            &ValidationMaterial::default(),
        ))
        .expect("report");
    assert!(only(&report).covering_document_timestamps().is_empty());
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
    assert!(matches!(
        stamp.timestamp(),
        TimestampReport::Invalid {
            error: TimestampError::ImprintMismatch,
            claimed_time: Some(_),
        }
    ));
    assert_eq!(
        stamp.timestamp().claimed_time(),
        Some(day(STAMPED)),
        "the token's claim is reported beside its failure"
    );
    assert_eq!(stamp.timestamp().proven_time(), None);
    assert_eq!(
        only(&report).covering_document_timestamps(),
        report.document_timestamps(),
        "a covering document timestamp is named whatever it was found to be"
    );
    assert!(only(&report).is_valid());
    assert!(
        report.is_valid(),
        "a document timestamp that fails decides nothing"
    );
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
    assert_eq!(first.revision(), Revision::LaterRevisionsHarmless);
    assert!(first.is_valid());
    assert_eq!(second.signer().name(), RSA_SIGNER);
    assert_eq!(second.revision(), Revision::WholeDocument);
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
        second.outcome(),
        SignatureOutcome::Unsupported {
            reason: UnsupportedSignature::PdfSubFilter,
            ..
        }
    ));
    assert_eq!(
        second.signer().map(SignerIdentity::name),
        Some(DIRECT_SIGNER),
        "the unjudged signature still names its signer"
    );
    assert_eq!(
        first.signer().map(SignerIdentity::name),
        Some(DIRECT_SIGNER)
    );
    assert!(!report.is_valid());
}

#[test]
fn every_format_reports_the_signing_time_it_claims() {
    let world = World::new();
    let pdf = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    for (what, file) in [
        ("PAdES, from /M", pdf),
        ("ASiC-E XAdES", world.note(Format::AsicEXades)),
        ("ASiC-E CAdES", world.note(Format::AsicECades)),
        ("attached CAdES", world.note(Format::Cades)),
    ] {
        let report = world.verify(file).expect("report");
        assert_eq!(
            only(&report).claimed_signing_time(),
            Some(day(STAMPED)),
            "{what}"
        );
    }
}

#[test]
fn a_pdf_signing_time_attribute_outranks_its_m_entry() {
    let world = World::new();
    let signing_time = attribute(known::SIGNING_TIME, &utc_time(day(REVOKED_EARLY)));
    let report = world
        .verify(world.foreign_pdf(Signer::Direct, &[signing_time], |_parts| {}))
        .expect("report");
    assert_eq!(
        only(&report).claimed_signing_time(),
        Some(day(REVOKED_EARLY))
    );
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
    assert_eq!(kinds(signature.timestamps()), [Kind::Claimed(day(STAMPED))]);
    let [stamp] = exactly(signature.timestamps(), "one timestamp");
    let authority = stamp.authority().expect("a verified token");
    assert_eq!(authority.signer().as_der(), world.rogue_tsa.as_slice());
    assert!(
        authority.chain().certificates().is_empty(),
        "the self-made root is not in the evidence"
    );
    assert_eq!(signature.proof_of_existence(), None);
    assert_eq!(signature.validation_time(), day(NOW));
    assert!(signature.chain_verified());
    assert_eq!(
        signature.revocation(),
        Revocation::Revoked {
            at: day(REVOKED_LATER),
            reason: None,
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
        kinds(only(&report).timestamps()),
        [Kind::Claimed(day(STAMPED))]
    );
}

#[test]
fn a_live_answer_fills_only_an_unavailable_status_on_a_verified_chain() {
    let world = World::new();
    let pdf = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let live = Revocation::Revoked {
        at: day(NOW),
        reason: None,
    };
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
fn the_signer_name_is_the_common_name_verbatim() {
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
    assert_eq!(
        identity.name(),
        PERSON,
        "neither recomposed nor case-changed"
    );
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

    // Without a commonName, the whole subject as RFC 4514 writes it:
    // the last RDN first, a comma in a short-named value escaped, and a
    // type without a short name as its dotted identifier with `#` and
    // the hexadecimal encoding of its value.
    let unnamed = certificate_named(
        &spec(PERSON_SERIAL, PERSON, PERSON, Vec::new()),
        &name_of(&[
            (known::COUNTRY_NAME, PRINTABLE_STRING, "FI"),
            (ORGANIZATION_NAME, UTF8_STRING, ORGANISATION),
            (known::SURNAME, UTF8_STRING, SURNAME),
            (known::SERIAL_NUMBER, PRINTABLE_STRING, IDENTIFIER),
        ]),
        &key,
        &key,
    );
    let identity = SignerIdentity::of(&OwnedCert::from_der(&unnamed).expect("parses"));
    assert_eq!(
        identity.name(),
        format!(
            "2.5.4.5=#{},2.5.4.4=#{},O=Synthetic\\, Ltd,C=FI",
            crate::hexcodec::Hex::encode(&tlv(PRINTABLE_STRING, IDENTIFIER.as_bytes())),
            crate::hexcodec::Hex::encode(&tlv(UTF8_STRING, SURNAME.as_bytes())),
        )
    );
    assert_eq!(
        identity.identifier().map(|peuin| peuin.as_str()),
        Some(IDENTIFIER)
    );
}

/// The universal tag of `IA5String` (X.680 sec.8.4, Table 1).
const IA5_STRING: u8 = 0x16;

/// `domainComponent` (RFC 4519 sec.2.4), an `IA5String`.
const DOMAIN_COMPONENT: refineid_cms::oid::Oid<'static> = refineid_cms::oid::Oid::const_new(
    ::const_oid::ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25").as_bytes(),
);

/// A subject of `domainComponent` values only renders them as text
/// under their short name `DC` (RFC 4514 sec.3), not as `#` hex.
#[test]
fn domain_components_render_as_text() {
    let key = TestKey::derive(TestCurve::P256, b"person");
    let certificate = certificate_named(
        &spec(PERSON_SERIAL, PERSON, PERSON, Vec::new()),
        &name_of(&[
            (DOMAIN_COMPONENT, IA5_STRING, "org"),
            (DOMAIN_COMPONENT, IA5_STRING, "example"),
        ]),
        &key,
        &key,
    );
    let identity = SignerIdentity::of(&OwnedCert::from_der(&certificate).expect("parses"));
    assert_eq!(identity.name(), "DC=example,DC=org");
}

/// `organizationName` (X.520, RFC 4519 sec.2.19).
const ORGANIZATION_NAME: refineid_cms::oid::Oid<'static> = refineid_cms::oid::Oid::const_new(
    ::const_oid::ObjectIdentifier::new_unwrap("2.5.4.10").as_bytes(),
);

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
        row.outcome(),
        SignatureOutcome::Unsupported {
            reason: UnsupportedSignature::Cms(CadesReadError::Cms(CmsError::AlgorithmMismatch)),
            ..
        }
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
        row.outcome(),
        SignatureOutcome::Unsupported {
            reason: UnsupportedSignature::Cms(CadesReadError::Cms(CmsError::AlgorithmParameters)),
            ..
        }
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
        kinds(signature.timestamps()),
        [Kind::Anchored(day(STAMPED))]
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
        [TimestampReport::Invalid {
            error: TimestampError::Malformed(_),
            ..
        }]
    ));
    assert_eq!(signature.proof_of_existence(), None);
    assert!(
        signature.is_valid(),
        "a timestamp that fails decides nothing"
    );
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
    assert!(matches!(
        signature.timestamps(),
        [TimestampReport::Invalid {
            error: TimestampError::ImprintMismatch,
            claimed_time: Some(_),
        }]
    ));
    assert!(signature.signature_valid());
    assert_eq!(signature.proof_of_existence(), None);
    assert!(
        signature.is_valid(),
        "a timestamp that fails decides nothing"
    );
}

/// A key compromise invalidates the signature whatever the proof of
/// existence; another reason after the proof leaves it valid.
#[test]
fn a_key_compromise_counts_whatever_the_proof_of_existence() {
    let world = World::new();
    for (reason, valid) in [
        (CrlReason::KeyCompromise, false),
        (CrlReason::Superseded, true),
    ] {
        let material = ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: Vec::new(),
            crls: vec![crate::testkit::crl_with_reason(
                ROOT,
                &world.root_key,
                day(REVOKED_LATER),
                Some(day(ENDS)),
                &[DIRECT_SIGNER_SERIAL],
                day(REVOKED_LATER),
                Some(reason),
            )],
        };
        let report = world
            .verify(world.pdf(Signer::Direct, Stamp::Anchored, &material))
            .expect("report");
        let signature = only(&report);
        assert_eq!(signature.proof_of_existence(), Some(day(STAMPED)));
        assert_eq!(
            signature.revocation(),
            Revocation::Revoked {
                at: day(REVOKED_LATER),
                reason: Some(reason)
            }
        );
        assert_eq!(signature.is_valid(), valid, "{reason:?}");
    }
}

/// The content-type signed attribute is mandatory and names `id-data`
/// (RFC 5652 sec.5.3, `ETSI EN 319 122-1` clause 5.1.1): absent, the
/// CMS border refuses the structure; another type is not valid.
#[test]
fn the_content_type_attribute_must_name_data() {
    let world = World::new();
    let pdf = world.foreign_pdf(Signer::Direct, &[], |parts| {
        let attributes = parts.signed_attributes.clone().expect("signed attributes");
        // Re-sign over the attributes with the content type renamed.
        let renamed = attribute_set(&{
            let digest = attribute_from(&attributes, known::MESSAGE_DIGEST);
            vec![
                attribute(
                    known::CONTENT_TYPE,
                    &tlv(OBJECT_IDENTIFIER, known::TST_INFO.as_bytes()),
                ),
                digest,
                signing_certificate_v2(&world.direct_signer),
            ]
        });
        parts.econtent_type = known::TST_INFO;
        parts.signed_attributes = Some(renamed);
    });
    let report = world.verify(pdf).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(!signature.signature_valid());

    let pdf = world.foreign_pdf(Signer::Direct, &[], |parts| {
        let attributes = parts.signed_attributes.clone().expect("signed attributes");
        parts.signed_attributes = Some(attribute_set(&[
            attribute_from(&attributes, known::MESSAGE_DIGEST),
            signing_certificate_v2(&world.direct_signer),
        ]));
    });
    let report = world.verify(pdf).expect("report");
    let [row] = exactly(report.rows(), "one signature");
    assert!(matches!(
        row.outcome(),
        SignatureOutcome::Unsupported {
            reason: UnsupportedSignature::Cms(CadesReadError::Cms(CmsError::UnexpectedStructure(
                _
            ))),
            ..
        }
    ));
}

/// The complete `Attribute` of type `oid` in the DER `SET OF Attribute`
/// `attributes`.
fn attribute_from(attributes: &[u8], oid: refineid_cms::oid::Oid<'_>) -> Vec<u8> {
    let set = crate::ber::BerTlvAny::parse(attributes).expect("a SET");
    let mut rest = set.value();
    while !rest.is_empty() {
        let attribute = crate::ber::BerTlvAny::parse(rest).expect("an Attribute");
        let (der, tail) = rest.split_at(attribute.size());
        let mut fields = crate::ber::BerTlvIter::new(attribute.value());
        let attribute_oid = fields.next().expect("a type").expect("a TLV");
        if attribute_oid.value() == oid.as_bytes() {
            return der.to_vec();
        }
        rest = tail;
    }
    panic!("the attribute is present");
}

/// The evidence a timestamp token carries in its own `SignedData.crls`
/// is judged with the authority's path: an answer that the TSA was
/// revoked before the token's time unanchors the token.
#[test]
fn a_token_s_own_revocation_evidence_is_judged() {
    let world = World::new();
    let tsa_root_key = TestKey::derive(TestCurve::P384, b"time-stamping root");
    let tsa_root = OwnedCert::from_der(&world.tsa_root).expect("root parses");
    let stamped_pdf = |revocation_info: &[Vec<u8>]| {
        world.foreign_pdf(Signer::Direct, &[], |parts| {
            let signed = parts.signed_attributes.clone().expect("signed attributes");
            let signature = parts.key.sign(&signed);
            let token = crate::testkit::timestamp_token_imprinting(
                &world.tsa,
                &world.tsa_key,
                &DigestAlgorithm::Sha256.algorithm_identifier(),
                &DigestAlgorithm::Sha256.digest(&signature),
                day(STAMPED),
                revocation_info,
            );
            parts.unsigned_attributes = vec![attribute(known::SIGNATURE_TIME_STAMP_TOKEN, &token)];
            parts.signature = Some(signature);
        })
    };
    let revoked = ocsp_response(&OcspSpec {
        responder_key: &tsa_root_key,
        responder: ResponderName::ByName(TSA_ROOT),
        issuer: &tsa_root,
        serial: TSA_SERIAL,
        revoked: Some(day(REVOKED_EARLY)),
        revocation_reason: None,
        produced_at: day(REVOKED_EARLY),
        this_update: day(REVOKED_EARLY),
        next_update: Some(day(ENDS)),
        embedded: Vec::new(),
        cert_id: crate::testkit::CertIdAlgorithm::Sha1,
        response_extensions: Vec::new(),
    });

    let report = world.verify(stamped_pdf(&[])).expect("report");
    assert_eq!(
        kinds(only(&report).timestamps()),
        [Kind::Anchored(day(STAMPED))]
    );
    let report = world
        .verify(stamped_pdf(&[crate::testkit::ocsp_revocation_info(
            &revoked,
        )]))
        .expect("report");
    assert_eq!(
        kinds(only(&report).timestamps()),
        [Kind::Claimed(day(STAMPED))]
    );
}

/// The note as the one data object of a container.
fn note_objects() -> Vec<DataObject> {
    vec![DataObject {
        name: NOTE_NAME.to_owned(),
        mime_type: NOTE_TYPE.to_owned(),
        content: NOTE.to_vec(),
    }]
}

/// The ASiC-E container holding the note and `signature_xml`.
fn xades_container_of(signature_xml: &str) -> Vec<u8> {
    crate::asic::xades_container(&note_objects(), signature_xml.as_bytes()).expect("fits")
}

/// The text of `document` from the first `open` through the next
/// `close`.
fn between<'a>(document: &'a str, open: &str, close: &str) -> &'a str {
    let start = document.find(open).expect("element");
    let end = document
        .get(start..)
        .and_then(|rest| rest.find(close))
        .expect("end tag")
        + start
        + close.len();
    document.get(start..end).expect("in range")
}

/// The character data of the first `ds:SignatureValue` of `document`.
fn signature_value_text(document: &str) -> &str {
    let element = between(document, "<ds:SignatureValue", "</ds:SignatureValue>");
    let open_end = element.find('>').expect("start tag ends") + 1;
    element
        .get(open_end..element.len() - "</ds:SignatureValue>".len())
        .expect("in range")
}

/// The element of `document` whose `Id` is `id`, under `method`.
fn canonical_by_id(document: &str, id: &str, method: &Canonicalization) -> Vec<u8> {
    XmlDocument::parse(document.as_bytes().to_vec())
        .expect("parses")
        .elements()
        .find(|element| element.attribute("Id") == Some(id))
        .expect("element with the Id")
        .canonicalize(method)
}

/// The base64 SHA-256 of `octets`, as a `ds:DigestValue` spells it.
fn digest_text(octets: &[u8]) -> String {
    crate::base64::encode(&DigestAlgorithm::Sha256.digest(octets))
}

/// `document` with the `ds:SignatureValue` of its signature `id`
/// replaced by `key`'s signature over that signature's `ds:SignedInfo`
/// under `method`.
fn resigned(document: &str, id: &str, method: &Canonicalization, key: &TestKey) -> String {
    let parsed = XmlDocument::parse(document.as_bytes().to_vec()).expect("parses");
    let signature = parsed
        .elements()
        .find(|element| element.attribute("Id") == Some(id))
        .expect("the signature");
    let signed_info = signature
        .child(crate::xades::NAMESPACE_DSIG, "SignedInfo")
        .expect("SignedInfo")
        .canonicalize(method);
    let value_id = format!("{id}-SIGVAL");
    let value = parsed
        .elements()
        .find(|element| element.attribute("Id") == Some(value_id.as_str()))
        .expect("the SignatureValue")
        .text();
    document.replacen(
        &value,
        &crate::base64::encode(&key.sign_raw(&signed_info)),
        1,
    )
}

/// The identifier of the writer's one signature.
const OUTER_ID: &str = "SIG-1";
/// The identifier of the writer's `SignedProperties`.
const OUTER_PROPERTIES_ID: &str = "SIG-1-SIGNEDPROPS";
/// The identifier of the writer's `SignatureValue`.
const OUTER_VALUE_ID: &str = "SIG-1-SIGVAL";
/// The identifier of the counter-signature.
const COUNTER_ID: &str = "CS-1";
/// Stands where the counter-signature's properties digest goes.
const PROPERTIES_DIGEST_PLACEHOLDER: &str = "properties-digest-placeholder";

impl World {
    /// The writer's `XAdES` signature file over the note, signed by the
    /// direct signer.
    fn xades_note(&self) -> String {
        self.xades_note_with(&ValidationMaterial::default())
    }

    /// As [`Self::xades_note`], carrying `material` in the unsigned
    /// properties.
    fn xades_note_with(&self, material: &ValidationMaterial) -> String {
        let owned = OwnedCert::from_der(&self.direct_signer).expect("signer parses");
        let certificate = owned.view();
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::EcdsaSha256,
            signing_time: Some(SIGNING_TIME),
        };
        let plan = crate::xades::plan(&note_objects(), &parameters).expect("plans");
        let value = self.signer_key.sign_raw(plan.signed_info());
        String::from_utf8(plan.finish(&value, &[], material)).expect("utf-8")
    }

    /// The writer's signature file with `SignedInfo` and the
    /// `SignedProperties` reference under the canonicalisation `uri`
    /// names, as another producer writes them: the properties digest
    /// recomputed and the signature value re-signed under `algorithm`.
    fn recanonicalised(&self, uri: &str, algorithm: Algorithm) -> String {
        let document = self.xades_note();
        let method = Canonicalization {
            algorithm,
            comments: Comments::Omitted,
        };
        let exclusive = Canonicalization::exclusive(Comments::Omitted);
        let renamed = document.replace(
            &format!("Algorithm=\"{}\"", crate::xades::CANONICALIZATION_EXCLUSIVE),
            &format!("Algorithm=\"{uri}\""),
        );
        assert!(renamed != document);
        let redigested = renamed.replacen(
            &digest_text(&canonical_by_id(&document, OUTER_PROPERTIES_ID, &exclusive)),
            &digest_text(&canonical_by_id(&renamed, OUTER_PROPERTIES_ID, &method)),
            1,
        );
        resigned(&redigested, OUTER_ID, &method, &self.signer_key)
    }

    /// `document` with a counter-signature by the RSA signer whose
    /// `CountersignedSignature` reference digests `countersigned`,
    /// carrying a `SigningCertificateV2` when `bound`, placed in the
    /// outer signature's unsigned properties.
    fn counter_signed(&self, document: &str, countersigned: &[u8], bound: bool) -> String {
        let spec = CounterSpec {
            bound,
            ..CounterSpec::over(countersigned.to_vec())
        };
        let placed = place_in_outer(document, &self.counter_signature_xml(&spec));
        self.sign_counter(&placed, &spec)
    }

    /// The `xades:CounterSignature` element `spec` describes, with its
    /// properties digest and value still to be filled in by
    /// [`Self::sign_counter`] once it is placed.
    fn counter_signature_xml(&self, spec: &CounterSpec<'_>) -> String {
        use crate::xades::{
            DIGEST_METHOD_SHA256, NAMESPACE_DSIG, SIGNATURE_METHOD_RSA_SHA256,
            TYPE_SIGNED_PROPERTIES,
        };
        let id = spec.id;
        let uri = spec.canonicalization_uri;
        let binding = if spec.bound {
            format!(
                "<xades:SigningCertificateV2><xades:Cert><xades:CertDigest>\
                 <ds:DigestMethod Algorithm=\"{DIGEST_METHOD_SHA256}\"/>\
                 <ds:DigestValue>{}</ds:DigestValue>\
                 </xades:CertDigest></xades:Cert></xades:SigningCertificateV2>",
                digest_text(&self.rsa_signer)
            )
        } else {
            String::new()
        };
        let key_info = if spec.key_info {
            format!(
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate>\
                 </ds:X509Data></ds:KeyInfo>\n",
                crate::base64::encode(&self.rsa_signer)
            )
        } else {
            String::new()
        };
        let transform = format!(
            "<ds:Transforms><ds:Transform Algorithm=\"{uri}\"/></ds:Transforms>\
             <ds:DigestMethod Algorithm=\"{DIGEST_METHOD_SHA256}\"/>"
        );
        let typed = if spec.typed {
            format!(" Type=\"{}\"", super::xades::TYPE_COUNTERSIGNED_SIGNATURE)
        } else {
            String::new()
        };
        format!(
            "<xades:CounterSignature>\
             <ds:Signature xmlns:ds=\"{NAMESPACE_DSIG}\" Id=\"{id}\">\n\
             <ds:SignedInfo>\n\
             <ds:CanonicalizationMethod Algorithm=\"{uri}\"/>\n\
             <ds:SignatureMethod Algorithm=\"{SIGNATURE_METHOD_RSA_SHA256}\"/>\n\
             <ds:Reference{typed} URI=\"#{target}\">{transform}\
             <ds:DigestValue>{countersigned_digest}</ds:DigestValue></ds:Reference>\n\
             <ds:Reference Type=\"{TYPE_SIGNED_PROPERTIES}\" URI=\"#{id}-SIGNEDPROPS\">{transform}\
             <ds:DigestValue>{PROPERTIES_DIGEST_PLACEHOLDER}-{id}</ds:DigestValue></ds:Reference>\n\
             </ds:SignedInfo>\n\
             <ds:SignatureValue Id=\"{id}-SIGVAL\">unsigned</ds:SignatureValue>\n\
             {key_info}\
             <ds:Object><xades:QualifyingProperties Target=\"#{id}\">\
             <xades:SignedProperties Id=\"{id}-SIGNEDPROPS\">\
             <xades:SignedSignatureProperties>\
             <xades:SigningTime>2026-04-08T12:00:00Z</xades:SigningTime>{binding}\
             </xades:SignedSignatureProperties></xades:SignedProperties>\
             </xades:QualifyingProperties></ds:Object>\n\
             </ds:Signature>\
             </xades:CounterSignature>",
            target = spec.target_value_id,
            countersigned_digest = digest_text(&spec.over),
        )
    }

    /// `document`, holding the counter-signature `spec` describes, with
    /// that counter-signature's properties digested and its value signed
    /// by the RSA signer.
    fn sign_counter(&self, document: &str, spec: &CounterSpec<'_>) -> String {
        let properties_id = format!("{}-SIGNEDPROPS", spec.id);
        let digested = document.replacen(
            &format!("{PROPERTIES_DIGEST_PLACEHOLDER}-{}", spec.id),
            &digest_text(&canonical_by_id(document, &properties_id, &spec.method)),
            1,
        );
        resigned(&digested, spec.id, &spec.method, &self.rsa_key)
    }
}

/// How a test counter-signature is written.
struct CounterSpec<'a> {
    /// Its `Id`, and the stem of its parts' identifiers.
    id: &'a str,
    /// The `Id` its counter-signing reference names.
    target_value_id: &'a str,
    /// The octets that reference's digest is computed over.
    over: Vec<u8>,
    /// Whether it carries `SigningCertificateV2`.
    bound: bool,
    /// Whether the reference carries the `CountersignedSignature` type.
    typed: bool,
    /// Whether it carries its certificate in `ds:KeyInfo`.
    key_info: bool,
    /// The canonicalisation its `SignedInfo` and transforms name.
    canonicalization_uri: &'a str,
    /// That canonicalisation.
    method: Canonicalization,
}

impl CounterSpec<'_> {
    /// An exclusive, bound, typed counter-signature over the writer's
    /// signature value, digesting `over`.
    fn over(over: Vec<u8>) -> Self {
        CounterSpec {
            id: COUNTER_ID,
            target_value_id: OUTER_VALUE_ID,
            over,
            bound: true,
            typed: true,
            key_info: true,
            canonicalization_uri: crate::xades::CANONICALIZATION_EXCLUSIVE,
            method: Canonicalization::exclusive(Comments::Omitted),
        }
    }
}

/// `document` with the counter-signature `counter` added to the
/// writer's outer signature's unsigned properties, after any already
/// there.
fn place_in_outer(document: &str, counter: &str) -> String {
    match document.rfind("</xades:UnsignedSignatureProperties>") {
        Some(at) => {
            let mut placed = document.to_owned();
            placed.insert_str(at, counter);
            placed
        }
        None => document.replacen(
            "</xades:QualifyingProperties>",
            &format!(
                "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{counter}\
                 </xades:UnsignedSignatureProperties></xades:UnsignedProperties>\n\
                 </xades:QualifyingProperties>"
            ),
            1,
        ),
    }
}

/// `document` with the counter-signature `counter` placed inside the
/// counter-signature `id`, which has no unsigned properties yet.
fn place_in_counter(document: &str, id: &str, counter: &str) -> String {
    let marker = format!("Target=\"#{id}\">");
    let start = document.find(&marker).expect("the counter-signature");
    let close = "</xades:QualifyingProperties>";
    let at = start
        + document
            .get(start..)
            .and_then(|rest| rest.find(close))
            .expect("its properties close");
    let mut placed = document.to_owned();
    placed.insert_str(
        at,
        &format!(
            "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{counter}\
             </xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
        ),
    );
    placed
}

/// The two rows of `report`: a signature and its counter-signature.
fn xades_rows(report: &DocumentReport) -> [&SignatureRow; 2] {
    let [outer, counter] = exactly(report.rows(), "a signature and its counter-signature");
    [outer, counter]
}

#[test]
fn inclusive_canonical_xml_signed_info_and_properties_verify() {
    let world = World::new();
    for (uri, algorithm) in [
        (
            super::xades::CANONICALIZATION_INCLUSIVE_10,
            Algorithm::Canonical10,
        ),
        (
            super::xades::CANONICALIZATION_INCLUSIVE_11,
            Algorithm::Canonical11,
        ),
    ] {
        let document = world.recanonicalised(uri, algorithm);
        assert!(document.contains(uri));
        let report = world.verify(xades_container_of(&document)).expect("report");
        let signature = only(&report);
        assert!(signature.document_intact(), "{uri}");
        assert!(signature.signature_valid(), "{uri}");
        assert!(signature.chain_verified(), "{uri}");
        assert!(report.is_valid(), "{uri}");

        // Re-signed under exclusive canonicalisation, the value no
        // longer verifies: the inclusive form differs.
        let exclusive = resigned(
            &document,
            OUTER_ID,
            &Canonicalization::exclusive(Comments::Omitted),
            &world.signer_key,
        );
        let report = world
            .verify(xades_container_of(&exclusive))
            .expect("report");
        assert!(!only(&report).signature_valid(), "{uri}");
    }
}

/// Another producer's spelling of an inclusive `SignedInfo`: the
/// redundant `ds` declaration gone (it is still in scope), empty
/// elements self-closed, single quotes and whitespace inside tags.
#[test]
fn a_respelled_inclusive_signed_info_still_verifies() {
    let world = World::new();
    let document = world.recanonicalised(
        super::xades::CANONICALIZATION_INCLUSIVE_10,
        Algorithm::Canonical10,
    );
    let signed_info = between(&document, "<ds:SignedInfo", "</ds:SignedInfo>");
    let mut respelled = signed_info
        .replacen(
            &format!(" xmlns:ds=\"{}\"", crate::xades::NAMESPACE_DSIG),
            "",
            1,
        )
        .replace("<ds:SignedInfo>", "<ds:SignedInfo >");
    for element in [
        "CanonicalizationMethod",
        "SignatureMethod",
        "DigestMethod",
        "Transform",
    ] {
        respelled = respelled.replace(&format!("></ds:{element}>"), " />");
    }
    respelled = respelled.replace(
        &format!("URI=\"{NOTE_NAME}\""),
        &format!("URI = '{NOTE_NAME}'"),
    );
    assert!(respelled != signed_info);
    let respelled = document.replacen(signed_info, &respelled, 1);
    let report = world
        .verify(xades_container_of(&respelled))
        .expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(report.is_valid());
}

#[test]
fn a_counter_signature_is_its_own_row_over_the_outer_signature_value() {
    let world = World::new();
    let document = world.xades_note();
    let exclusive = Canonicalization::exclusive(Comments::Omitted);
    let over = canonical_by_id(&document, OUTER_VALUE_ID, &exclusive);
    let report = world
        .verify(xades_container_of(
            &world.counter_signed(&document, &over, true),
        ))
        .expect("report");
    let [outer, counter] = xades_rows(&report);
    assert_eq!(outer.counter_signs(), None);
    assert_eq!(counter.counter_signs(), Some(0));
    assert!(outer.is_valid());
    let counter = judged(counter);
    assert_eq!(counter.signer().name(), RSA_SIGNER);
    assert!(counter.document_intact());
    assert!(counter.signature_valid());
    assert!(counter.chain_verified());
    assert!(counter.is_valid());
    assert!(report.is_valid());
}

#[test]
fn a_counter_signature_over_another_signature_value_is_not_valid() {
    let world = World::new();
    let document = world.xades_note();
    let exclusive = Canonicalization::exclusive(Comments::Omitted);
    let real =
        String::from_utf8(canonical_by_id(&document, OUTER_VALUE_ID, &exclusive)).expect("utf-8");
    let value = signature_value_text(&document);
    let mut octets = crate::base64::decode_wrapped(value).expect("base64");
    let last = octets.last_mut().expect("a signature value");
    *last = last.wrapping_add(1);
    let tampered = real.replacen(value, &crate::base64::encode(&octets), 1);
    assert!(tampered != real);
    let report = world
        .verify(xades_container_of(&world.counter_signed(
            &document,
            tampered.as_bytes(),
            true,
        )))
        .expect("report");
    let [outer, counter] = xades_rows(&report);
    assert!(outer.is_valid(), "the outer verdict does not change");
    let counter = judged(counter);
    assert!(!counter.document_intact());
    assert!(counter.signature_valid());
    assert!(!counter.is_valid());
    assert!(report.is_valid(), "a counter-signature decides nothing");
}

#[test]
fn a_counter_signature_without_a_signing_certificate_is_not_valid() {
    let world = World::new();
    let document = world.xades_note();
    let exclusive = Canonicalization::exclusive(Comments::Omitted);
    let over = canonical_by_id(&document, OUTER_VALUE_ID, &exclusive);
    let report = world
        .verify(xades_container_of(
            &world.counter_signed(&document, &over, false),
        ))
        .expect("report");
    let [outer, counter] = xades_rows(&report);
    assert!(outer.is_valid());
    assert_eq!(counter.counter_signs(), Some(0));
    let counter = judged(counter);
    assert!(counter.document_intact());
    assert!(!counter.signature_valid());
    assert!(report.is_valid(), "a counter-signature decides nothing");
}

#[test]
fn an_unreadable_counter_signature_is_an_unsupported_row() {
    let world = World::new();
    let document = world.xades_note().replacen(
        "</xades:QualifyingProperties>",
        "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>\
         <xades:CounterSignature></xades:CounterSignature>\
         </xades:UnsignedSignatureProperties></xades:UnsignedProperties>\n\
         </xades:QualifyingProperties>",
        1,
    );
    let report = world.verify(xades_container_of(&document)).expect("report");
    let [outer, counter] = xades_rows(&report);
    assert!(outer.is_valid());
    assert_eq!(counter.counter_signs(), Some(0));
    assert!(matches!(
        counter.outcome(),
        SignatureOutcome::Unsupported {
            reason: UnsupportedSignature::XadesMalformed(_),
            ..
        }
    ));
    assert!(report.is_valid(), "a counter-signature decides nothing");
}

/// The writer's signature value under `method`, as the counter-signing
/// reference digests it.
fn outer_value(document: &str, method: &Canonicalization) -> Vec<u8> {
    canonical_by_id(document, OUTER_VALUE_ID, method)
}

/// The judged counter-signature row of `report`, after checking it
/// names the first row.
fn counter_report(report: &DocumentReport) -> &SignatureReport {
    let [outer, counter] = xades_rows(report);
    assert!(outer.is_valid());
    assert_eq!(counter.counter_signs(), Some(0));
    judged(counter)
}

/// A reference over the outer value without the
/// `CountersignedSignature` type is an ordinary same-document reference
/// and does not make the counter-signature cover it (EN 319 132-1
/// clause 5.2.7.1).
#[test]
fn a_counter_signing_reference_needs_its_type() {
    let world = World::new();
    let document = world.xades_note();
    let spec = CounterSpec {
        typed: false,
        ..CounterSpec::over(outer_value(
            &document,
            &Canonicalization::exclusive(Comments::Omitted),
        ))
    };
    let signed = world.sign_counter(
        &place_in_outer(&document, &world.counter_signature_xml(&spec)),
        &spec,
    );
    let report = world.verify(xades_container_of(&signed)).expect("report");
    let counter = counter_report(&report);
    assert!(!counter.document_intact());
    assert!(counter.signature_valid());
}

/// A counter-signature counter-signs the signature it is embedded in: a
/// typed reference naming another signature's value, here a sibling
/// counter-signature's, does not count (EN 319 132-1 clause 5.2.7.2).
#[test]
fn a_counter_signature_over_another_signature_s_value_is_not_accepted() {
    let world = World::new();
    let exclusive = Canonicalization::exclusive(Comments::Omitted);
    let document = world.xades_note();
    let first = CounterSpec::over(outer_value(&document, &exclusive));
    let once = world.sign_counter(
        &place_in_outer(&document, &world.counter_signature_xml(&first)),
        &first,
    );
    let sibling_value = format!("{COUNTER_ID}-SIGVAL");
    let second = CounterSpec {
        id: "CS-2",
        target_value_id: &sibling_value,
        ..CounterSpec::over(canonical_by_id(&once, &sibling_value, &exclusive))
    };
    let twice = world.sign_counter(
        &place_in_outer(&once, &world.counter_signature_xml(&second)),
        &second,
    );
    let report = world.verify(xades_container_of(&twice)).expect("report");
    let [outer, first, second] = exactly(report.rows(), "a signature and two counter-signatures");
    assert!(outer.is_valid());
    assert_eq!(first.counter_signs(), Some(0));
    assert_eq!(second.counter_signs(), Some(0));
    assert!(first.is_valid());
    let second = judged(second);
    assert!(
        !second.document_intact(),
        "it names a value it is not embedded under"
    );
    assert!(second.signature_valid());
}

/// A counter-signature under Canonical XML 1.1 throughout verifies.
#[test]
fn a_counter_signature_under_inclusive_canonicalisation_verifies() {
    let world = World::new();
    let method = Canonicalization {
        algorithm: Algorithm::Canonical11,
        comments: Comments::Omitted,
    };
    let document = world.xades_note();
    let spec = CounterSpec {
        canonicalization_uri: super::xades::CANONICALIZATION_INCLUSIVE_11,
        method: method.clone(),
        ..CounterSpec::over(outer_value(&document, &method))
    };
    let signed = world.sign_counter(
        &place_in_outer(&document, &world.counter_signature_xml(&spec)),
        &spec,
    );
    assert!(signed.contains(super::xades::CANONICALIZATION_INCLUSIVE_11));
    let report = world.verify(xades_container_of(&signed)).expect("report");
    assert!(counter_report(&report).is_valid());
}

/// A counter-signature nested in another, carrying no certificate of
/// its own, finds its signer in the outermost signature's
/// `CertificateValues`, and its row names the counter-signature it
/// counter-signs.
#[test]
fn a_nested_counter_signer_is_found_in_an_enclosing_signature() {
    let world = World::new();
    let exclusive = Canonicalization::exclusive(Comments::Omitted);
    let document = world.xades_note_with(&ValidationMaterial {
        certificates: vec![world.rsa_signer.clone()],
        ..ValidationMaterial::default()
    });
    let first = CounterSpec::over(outer_value(&document, &exclusive));
    let once = world.sign_counter(
        &place_in_outer(&document, &world.counter_signature_xml(&first)),
        &first,
    );
    let first_value = format!("{COUNTER_ID}-SIGVAL");
    let nested = CounterSpec {
        id: "CS-2",
        target_value_id: &first_value,
        key_info: false,
        ..CounterSpec::over(canonical_by_id(&once, &first_value, &exclusive))
    };
    let twice = world.sign_counter(
        &place_in_counter(&once, COUNTER_ID, &world.counter_signature_xml(&nested)),
        &nested,
    );
    let report = world.verify(xades_container_of(&twice)).expect("report");
    let [outer, first, nested] = exactly(report.rows(), "a signature and a chain of two");
    assert!(outer.is_valid());
    assert_eq!(first.counter_signs(), Some(0));
    assert!(first.is_valid());
    assert_eq!(nested.counter_signs(), Some(1));
    let nested = judged(nested);
    assert_eq!(nested.signer().name(), RSA_SIGNER);
    assert!(nested.is_valid());

    // Without the certificate in any enclosing signature there is no
    // signer to judge.
    let carried_once = world.xades_note();
    let first = CounterSpec::over(outer_value(&carried_once, &exclusive));
    let once = world.sign_counter(
        &place_in_outer(&carried_once, &world.counter_signature_xml(&first)),
        &first,
    );
    let nested = CounterSpec {
        id: "CS-2",
        target_value_id: &first_value,
        key_info: false,
        ..CounterSpec::over(canonical_by_id(&once, &first_value, &exclusive))
    };
    let twice = world.sign_counter(
        &place_in_counter(&once, COUNTER_ID, &world.counter_signature_xml(&nested)),
        &nested,
    );
    let report = world.verify(xades_container_of(&twice)).expect("report");
    let [_outer, _first, nested] = exactly(report.rows(), "a signature and a chain of two");
    assert!(matches!(
        nested.outcome(),
        SignatureOutcome::Unsupported {
            reason: UnsupportedSignature::XadesSignerNotCarried,
            ..
        }
    ));
}

/// Past [`super::MAX_COUNTER_SIGNATURE_DEPTH`] levels a counter-signature
/// is an unsupported row and nothing below it is read; none of them
/// decides the document.
#[test]
fn counter_signatures_nest_to_a_bounded_depth() {
    use crate::xades::{CANONICALIZATION_EXCLUSIVE, NAMESPACE_DSIG};
    let world = World::new();
    let levels = super::MAX_COUNTER_SIGNATURE_DEPTH + 2;
    let certificate = crate::base64::encode(&world.rsa_signer);
    let mut inner = String::new();
    for level in (1..=levels).rev() {
        let unsigned = if inner.is_empty() {
            String::new()
        } else {
            format!(
                "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{inner}\
                 </xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
            )
        };
        inner = format!(
            "<xades:CounterSignature><ds:Signature xmlns:ds=\"{NAMESPACE_DSIG}\" Id=\"D{level}\">\
             <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/>\
             </ds:SignedInfo><ds:SignatureValue Id=\"D{level}-SIGVAL\">AAAA</ds:SignatureValue>\
             <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate>\
             </ds:X509Data></ds:KeyInfo><ds:Object>\
             <xades:QualifyingProperties Target=\"#D{level}\">{unsigned}</xades:QualifyingProperties>\
             </ds:Object></ds:Signature></xades:CounterSignature>"
        );
    }
    let document = place_in_outer(&world.xades_note(), &inner);
    let report = world.verify(xades_container_of(&document)).expect("report");
    let rows = report.rows();
    assert_eq!(
        rows.len(),
        super::MAX_COUNTER_SIGNATURE_DEPTH + 2,
        "the outer row, the bounded levels and the refused one"
    );
    for (index, row) in rows.iter().enumerate().skip(1) {
        assert_eq!(row.counter_signs(), Some(index - 1));
    }
    assert!(matches!(
        rows.last().map(SignatureRow::outcome),
        Some(SignatureOutcome::Unsupported {
            reason: UnsupportedSignature::CounterSignatureTooDeep,
            ..
        })
    ));
    assert!(report.is_valid());
}

/// A same-document reference without a transform is canonicalised by
/// Canonical XML 1.0 (XML Signature 1.1 clause 4.4.3.2).
#[test]
fn a_reference_without_a_transform_digests_canonical_xml_1_0() {
    let world = World::new();
    let document = world.xades_note();
    let transforms = format!(
        "<ds:Transforms>\n<ds:Transform Algorithm=\"{}\"></ds:Transform>\n</ds:Transforms>\n",
        crate::xades::CANONICALIZATION_EXCLUSIVE
    );
    assert!(document.contains(&transforms));
    let bare = document.replacen(&transforms, "", 1);
    let inclusive = Canonicalization {
        algorithm: Algorithm::Canonical10,
        comments: Comments::Omitted,
    };
    let exclusive = Canonicalization::exclusive(Comments::Omitted);
    let redigested = bare.replacen(
        &digest_text(&canonical_by_id(&document, OUTER_PROPERTIES_ID, &exclusive)),
        &digest_text(&canonical_by_id(&bare, OUTER_PROPERTIES_ID, &inclusive)),
        1,
    );
    let signed = resigned(&redigested, OUTER_ID, &exclusive, &world.signer_key);
    let report = world.verify(xades_container_of(&signed)).expect("report");
    let signature = only(&report);
    assert!(signature.document_intact());
    assert!(signature.signature_valid());
    assert!(report.is_valid());
}

/// Common name of the time-stamping root the archive timestamps chain
/// to.
const ARCHIVE_TSA_ROOT: &str = "Synthetic Archive Time Stamping Root";
/// Common name of the TSA that issues the archive timestamps.
const ARCHIVE_TSA: &str = "Synthetic Archive Time Stamping Unit";
/// Archive time-stamping root serial.
const ARCHIVE_TSA_ROOT_SERIAL: u8 = 11;
/// Archive TSA serial.
const ARCHIVE_TSA_SERIAL: u8 = 12;
/// Common name of the issuing CA under the archive root.
const ARCHIVE_CA: &str = "Synthetic Archive Issuing CA";
/// Common name of the TSA that issuing CA certifies.
const CHAINED_ARCHIVE_TSA: &str = "Synthetic Chained Archive Time Stamping Unit";
/// Archive issuing CA serial.
const ARCHIVE_CA_SERIAL: u8 = 13;
/// Chained archive TSA serial.
const CHAINED_ARCHIVE_TSA_SERIAL: u8 = 14;
/// Day of the archive timestamps, after the signature timestamps.
const ARCHIVED: u8 = 16;
/// A validation day after every fixture certificate has expired.
const EXPIRED: u8 = 29;
/// The `XAdES` 1.4.1 namespace of `ArchiveTimeStamp` and
/// `TimeStampValidationData` (`ETSI EN 319 132-1` clause 4.2).
const NAMESPACE_XADES_141: &str = "http://uri.etsi.org/01903/v1.4.1#";

/// The authority archive timestamps come from, under a root of its own.
struct ArchiveAuthority {
    /// The time-stamping root.
    root: Vec<u8>,
    /// The TSA key.
    key: TestKey,
    /// The TSA.
    tsa: Vec<u8>,
    /// An issuing CA under the root.
    ca: Vec<u8>,
    /// A TSA that CA certifies, with the same key, whose token carries
    /// only its own certificate.
    chained_tsa: Vec<u8>,
}

impl ArchiveAuthority {
    /// The archive authority's keys and certificates.
    fn new() -> Self {
        let root_key = TestKey::derive(TestCurve::P384, b"archive time-stamping root");
        let key = TestKey::derive(TestCurve::P256, b"archive tsa");
        let ca_key = TestKey::derive(TestCurve::P384, b"archive issuing ca");
        Self {
            root: certificate(
                &spec(
                    ARCHIVE_TSA_ROOT_SERIAL,
                    ARCHIVE_TSA_ROOT,
                    ARCHIVE_TSA_ROOT,
                    ca_extensions(),
                ),
                &root_key,
                &root_key,
            ),
            tsa: certificate(
                &spec(
                    ARCHIVE_TSA_SERIAL,
                    ARCHIVE_TSA,
                    ARCHIVE_TSA_ROOT,
                    timestamping_extensions(),
                ),
                &key,
                &root_key,
            ),
            ca: certificate(
                &spec(
                    ARCHIVE_CA_SERIAL,
                    ARCHIVE_CA,
                    ARCHIVE_TSA_ROOT,
                    ca_extensions(),
                ),
                &ca_key,
                &root_key,
            ),
            chained_tsa: certificate(
                &spec(
                    CHAINED_ARCHIVE_TSA_SERIAL,
                    CHAINED_ARCHIVE_TSA,
                    ARCHIVE_CA,
                    timestamping_extensions(),
                ),
                &key,
                &ca_key,
            ),
            key,
        }
    }

    /// The anchors of a relying party years later: the signer's root,
    /// and the archive authority's root, while the authority of the
    /// signature timestamps is no longer listed.
    fn anchors(&self, world: &World) -> TrustAnchors {
        TrustAnchors::new(vec![
            anchor(&world.root, AnchorRole::CertificateIssuing),
            anchor(&self.root, AnchorRole::TimeStamping),
        ])
    }

    /// A token from this authority at [`ARCHIVED`] over `input`.
    fn token(&self, input: &[u8]) -> Vec<u8> {
        self.token_from(&self.tsa, input)
    }

    /// A token from `tsa`, one of this authority's TSAs, at
    /// [`ARCHIVED`] over `input`.
    fn token_from(&self, tsa: &[u8], input: &[u8]) -> Vec<u8> {
        timestamp_token(
            tsa,
            &self.key,
            DigestAlgorithm::Sha256,
            &DigestAlgorithm::Sha256.digest(input),
            day(ARCHIVED),
        )
    }
}

/// How an archive-time-stamp-v3 fixture departs from a sound one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveFault {
    /// None.
    Sound,
    /// The hash index also names a certificate the signature does not
    /// carry.
    AbsentValue,
    /// The signature timestamp the index names is replaced afterwards.
    TamperedValue,
    /// The archive attribute holds the token twice.
    TwoValues,
    /// The issued signer signs, its intermediate among the certificates
    /// the index lists.
    IntermediateCovered,
    /// The issued signer signs, its intermediate added to the
    /// certificates after the archive timestamp.
    IntermediateAfter,
    /// Another unsigned attribute is added after the archive timestamp.
    AttributeAfter,
    /// The index is under SHA-384 while the token imprints SHA-256.
    IndexAlgorithm,
    /// The token carries no index.
    NoIndex,
    /// The token carries the index twice.
    TwoIndexes,
}

/// `der` by `world`'s TSA at `on` over the signature value `signature`.
fn signature_time_stamp(world: &World, signature: &[u8], on: u8) -> Vec<u8> {
    attribute(
        known::SIGNATURE_TIME_STAMP_TOKEN,
        &timestamp_token(
            &world.tsa,
            &world.tsa_key,
            DigestAlgorithm::Sha256,
            &DigestAlgorithm::Sha256.digest(signature),
            day(on),
        ),
    )
}

/// The minimal PDF signed by the direct signer at level LTA in the
/// `CAdES` way: a signature timestamp from the world's TSA at
/// [`STAMPED`], then an `archive-time-stamp-v3` from `archive` at
/// [`ARCHIVED`] whose input is computed as `ETSI EN 319 122-1` clause
/// 5.5.3 lists it, departing as `fault` says.
fn archived_pdf(world: &World, archive: &ArchiveAuthority, fault: ArchiveFault) -> Vec<u8> {
    let issued = matches!(
        fault,
        ArchiveFault::IntermediateCovered | ArchiveFault::IntermediateAfter
    );
    let (key, der) = world.signer(if issued {
        Signer::Issued
    } else {
        Signer::Direct
    });
    let placeholder = prepare(
        &minimal_pdf(),
        &SignatureMetadata::default(),
        DEFAULT_SIGNATURE_CAPACITY,
    )
    .expect("prepares");
    let content = placeholder.signed_octets();
    let mut attributes = content_attributes(known::DATA, key.hash(), &content);
    attributes.push(signing_certificate_v2(der));
    let mut parts = CmsParts::detached(key, der, &content);
    let signed_attributes = attribute_set(&attributes);
    let signature = key.sign(&signed_attributes);
    parts.signed_attributes = Some(signed_attributes);
    parts.signature = Some(signature.clone());
    parts.unsigned_attributes = vec![signature_time_stamp(world, &signature, STAMPED)];
    if fault == ArchiveFault::IntermediateCovered {
        parts.certificates.push(world.intermediate.clone());
    }

    let unarchived = cms(&parts);
    let signed = crate::cms::SignedData::parse(&unarchived).expect("the CMS parses");
    let attribute_values: Vec<Vec<u8>> = signed
        .signer()
        .unsigned_attributes()
        .iter()
        .map(|attribute| [attribute.type_der.as_bytes(), attribute.values_der].concat())
        .collect();
    let mut certificates: Vec<&[u8]> = signed.certificates().to_vec();
    if fault == ArchiveFault::AbsentValue {
        certificates.push(&world.stranger);
    }
    let revocation: Vec<&[u8]> = signed
        .revocation_info()
        .iter()
        .map(|entry| entry.encoded().as_bytes())
        .collect();
    let index_algorithm = if fault == ArchiveFault::IndexAlgorithm {
        DigestAlgorithm::Sha384
    } else {
        DigestAlgorithm::Sha256
    };
    let index = crate::testkit::ats_hash_index_v3(
        index_algorithm,
        &certificates,
        &revocation,
        &attribute_values,
    );
    let mut input = signed.econtent_type_der().as_bytes().to_vec();
    input.extend_from_slice(&index_algorithm.digest(&content));
    input.extend_from_slice(signed.signer().archive_fields().as_bytes());
    input.extend_from_slice(&index);
    let indexes = match fault {
        ArchiveFault::NoIndex => Vec::new(),
        ArchiveFault::TwoIndexes => vec![index.clone(), index.clone()],
        _ => vec![index],
    };
    let token = crate::testkit::archive_timestamp_token_indexed(
        &archive.tsa,
        &archive.key,
        DigestAlgorithm::Sha256,
        &DigestAlgorithm::Sha256.digest(&input),
        day(ARCHIVED),
        &indexes,
    );
    match fault {
        ArchiveFault::TamperedValue => {
            parts.unsigned_attributes = vec![signature_time_stamp(world, &signature, ANSWERED)];
        }
        ArchiveFault::IntermediateAfter => parts.certificates.push(world.intermediate.clone()),
        _ => {}
    }
    let archive_attribute = if fault == ArchiveFault::TwoValues {
        let mut body = tlv(OBJECT_IDENTIFIER, known::ARCHIVE_TIME_STAMP_V3.as_bytes());
        body.extend_from_slice(&tlv(crate::testkit::SET, [token.clone(), token].concat()));
        tlv(SEQUENCE, body)
    } else {
        attribute(known::ARCHIVE_TIME_STAMP_V3, &token)
    };
    parts.unsigned_attributes.push(archive_attribute);
    if fault == ArchiveFault::AttributeAfter {
        parts
            .unsigned_attributes
            .push(signature_time_stamp(world, &signature, ANSWERED));
    }
    placeholder.finish(&cms(&parts)).expect("the CMS fits")
}

/// The archive timestamps of `signature` as kinds, each with its form.
fn archive_kinds(signature: &SignatureReport) -> Vec<(ArchiveForm, Kind)> {
    signature
        .archive_timestamps()
        .iter()
        .map(|archive| (archive.form(), kind(archive.timestamp())))
        .collect()
}

/// Verify `bytes` on [`EXPIRED`] under `anchors`.
fn verify_expired(bytes: Vec<u8>, anchors: &TrustAnchors) -> DocumentReport {
    verify(
        &DocumentFile::from_file(bytes).expect("a known shape"),
        anchors,
        day(EXPIRED),
    )
    .expect("report")
}

#[test]
fn an_lta_pdf_whose_signature_timestamp_authority_expired_stands_on_its_archive_timestamp() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let pdf = archived_pdf(&world, &archive, ArchiveFault::Sound);
    let report = verify_expired(pdf.clone(), &archive.anchors(&world));
    let signature = only(&report);
    assert_eq!(kinds(signature.timestamps()), [Kind::Claimed(day(STAMPED))]);
    assert_eq!(
        archive_kinds(signature),
        [(ArchiveForm::CadesV3, Kind::Anchored(day(ARCHIVED)))]
    );
    let [archived] = exactly(signature.archive_timestamps(), "one archive timestamp");
    let authority = archived.timestamp().authority().expect("a verified token");
    assert_eq!(ders(authority.chain()), [archive.root.as_slice()]);
    assert_eq!(signature.proof_of_existence(), Some(day(ARCHIVED)));
    assert_eq!(signature.validation_time(), day(ARCHIVED));
    assert!(signature.chain_verified());
    assert!(report.is_valid());

    // Without the archive authority nothing proves existence, and the
    // signer, expired by now, is judged now.
    let unarchived = TrustAnchors::new(vec![anchor(&world.root, AnchorRole::CertificateIssuing)]);
    let report = verify_expired(pdf, &unarchived);
    assert_eq!(only(&report).proof_of_existence(), None);
    assert!(!report.is_valid());
}

#[test]
fn an_archive_index_naming_a_value_that_is_not_present_is_invalid() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let report = verify_expired(
        archived_pdf(&world, &archive, ArchiveFault::AbsentValue),
        &archive.anchors(&world),
    );
    let signature = only(&report);
    assert_eq!(
        archive_kinds(signature),
        [(
            ArchiveForm::CadesV3,
            Kind::Invalid(TimestampError::ImprintMismatch)
        )]
    );
    assert_eq!(signature.proof_of_existence(), None);
    assert!(!report.is_valid());
}

#[test]
fn a_tampered_indexed_value_makes_the_archive_timestamp_invalid() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let report = verify_expired(
        archived_pdf(&world, &archive, ArchiveFault::TamperedValue),
        &archive.anchors(&world),
    );
    let signature = only(&report);
    assert_eq!(
        archive_kinds(signature),
        [(
            ArchiveForm::CadesV3,
            Kind::Invalid(TimestampError::ImprintMismatch)
        )]
    );
    assert!(!report.is_valid());
}

#[test]
fn a_v2_archive_timestamp_is_counted_and_not_judged() {
    let world = World::new();
    let pdf = world.foreign_pdf(Signer::Direct, &[], |parts| {
        let token = timestamp_token(
            &world.tsa,
            &world.tsa_key,
            DigestAlgorithm::Sha256,
            &DigestAlgorithm::Sha256.digest(b"archive v2 input"),
            day(ARCHIVED),
        );
        parts.unsigned_attributes = vec![attribute(known::ARCHIVE_TIME_STAMP_V2, &token)];
    });
    let report = world.verify(pdf).expect("report");
    let signature = only(&report);
    assert_eq!(
        archive_kinds(signature),
        [(ArchiveForm::CadesV2, Kind::Unsupported)]
    );
    assert_eq!(signature.proof_of_existence(), None);
    assert!(report.is_valid());
}

/// How an `XAdES` archive fixture departs from a sound one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XadesArchiveFault {
    /// None.
    Sound,
    /// The validation data is changed after the archive timestamp.
    Tampered,
    /// The issued signer signs, its intermediate in `CertificateValues`
    /// before the archive timestamp.
    IntermediateBefore,
    /// The issued signer signs, its intermediate in `CertificateValues`
    /// after the archive timestamp.
    IntermediateAfter,
    /// The issued signer signs; the archive token comes from the chained
    /// TSA, and a `TimeStampValidationData` after it carries the
    /// archive issuing CA and the signer's intermediate.
    AuthorityDataAfter,
    /// As [`Self::AuthorityDataAfter`] without that validation data.
    AuthorityDataMissing,
}

/// The writer's `XAdES` signature over the note by the direct signer
/// with a signature timestamp from the world's TSA at [`STAMPED`], a
/// `TimeStampValidationData` carrying the time-stamping root, and an
/// `ArchiveTimeStamp` from `archive` whose input is computed as `ETSI
/// EN 319 132-1` clause 5.5.2.3 lists it; when `tamper` is set, the
/// validation data is changed after the archive timestamp is made.
fn archived_xades(world: &World, archive: &ArchiveAuthority, fault: XadesArchiveFault) -> Vec<u8> {
    use crate::xades::{CANONICALIZATION_EXCLUSIVE, NAMESPACE_DSIG, NAMESPACE_XADES};
    let issued = matches!(
        fault,
        XadesArchiveFault::IntermediateBefore
            | XadesArchiveFault::IntermediateAfter
            | XadesArchiveFault::AuthorityDataAfter
            | XadesArchiveFault::AuthorityDataMissing
    );
    let chained = matches!(
        fault,
        XadesArchiveFault::AuthorityDataAfter | XadesArchiveFault::AuthorityDataMissing
    );
    let owned = OwnedCert::from_der(if issued {
        &world.issued_signer
    } else {
        &world.direct_signer
    })
    .expect("signer parses");
    let certificate = owned.view();
    let parameters = SignerParameters {
        certificate: &certificate,
        digest_algorithm: DigestAlgorithm::Sha256,
        signature_algorithm: SignatureAlgorithm::EcdsaSha256,
        signing_time: Some(SIGNING_TIME),
    };
    let plan = crate::xades::plan(&note_objects(), &parameters).expect("plans");
    let value = world.signer_key.sign_raw(plan.signed_info());
    let stamp = timestamp_token(
        &world.tsa,
        &world.tsa_key,
        DigestAlgorithm::Sha256,
        &crate::xades::SignaturePlan::timestamp_digest(&value, DigestAlgorithm::Sha256),
        day(STAMPED),
    );
    let document = String::from_utf8(plan.finish(&value, &[stamp], &ValidationMaterial::default()))
        .expect("utf-8");
    let close = "</xades:UnsignedSignatureProperties>";
    let validation_data = format!(
        "<xades141:TimeStampValidationData xmlns:xades141=\"{NAMESPACE_XADES_141}\">\
         <xades:CertificateValues><xades:EncapsulatedX509Certificate>{}\
         </xades:EncapsulatedX509Certificate></xades:CertificateValues>\
         </xades141:TimeStampValidationData>",
        crate::base64::encode(&world.tsa_root)
    );
    let intermediate = format!(
        "<xades:CertificateValues><xades:EncapsulatedX509Certificate>{}\
         </xades:EncapsulatedX509Certificate></xades:CertificateValues>",
        crate::base64::encode(&world.intermediate)
    );
    let before = if fault == XadesArchiveFault::IntermediateBefore {
        intermediate.as_str()
    } else {
        ""
    };
    let document = document.replace(close, &format!("{validation_data}{before}{close}"));

    let method = Canonicalization::exclusive(Comments::Omitted);
    let parsed = XmlDocument::parse(document.as_bytes().to_vec()).expect("parses");
    let signature = parsed
        .root()
        .child(NAMESPACE_DSIG, "Signature")
        .expect("signature");
    let signed_info = signature
        .child(NAMESPACE_DSIG, "SignedInfo")
        .expect("SignedInfo");
    let mut input = Vec::new();
    for reference in signed_info.children_named(NAMESPACE_DSIG, "Reference") {
        match reference
            .attribute("URI")
            .and_then(|uri| uri.strip_prefix('#'))
        {
            Some(id) => input.extend_from_slice(&canonical_by_id(&document, id, &method)),
            None => input.extend_from_slice(NOTE),
        }
    }
    input.extend_from_slice(&signed_info.canonicalize(&method));
    for name in ["SignatureValue", "KeyInfo"] {
        input.extend_from_slice(
            &signature
                .child(NAMESPACE_DSIG, name)
                .expect("element")
                .canonicalize(&method),
        );
    }
    let unsigned = signature
        .descendants()
        .find(|element| element.is(NAMESPACE_XADES, "UnsignedSignatureProperties"))
        .expect("unsigned properties");
    for property in unsigned.children() {
        input.extend_from_slice(&property.canonicalize(&method));
    }
    for object in signature.children_named(NAMESPACE_DSIG, "Object") {
        if object
            .child(NAMESPACE_XADES, "QualifyingProperties")
            .is_none()
        {
            input.extend_from_slice(&object.canonicalize(&method));
        }
    }
    let archive_xml = format!(
        "<xades141:ArchiveTimeStamp xmlns:xades141=\"{NAMESPACE_XADES_141}\">\
         <ds:CanonicalizationMethod Algorithm=\"{CANONICALIZATION_EXCLUSIVE}\"/>\
         <xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp>\
         </xades141:ArchiveTimeStamp>",
        crate::base64::encode(&if chained {
            archive.token_from(&archive.chained_tsa, &input)
        } else {
            archive.token(&input)
        })
    );
    let mut archived = document.replace(close, &format!("{archive_xml}{close}"));
    if fault == XadesArchiveFault::IntermediateAfter {
        archived = archived.replace(close, &format!("{intermediate}{close}"));
    }
    if fault == XadesArchiveFault::AuthorityDataAfter {
        let authority_data = format!(
            "<xades141:TimeStampValidationData xmlns:xades141=\"{NAMESPACE_XADES_141}\">\
             <xades:CertificateValues><xades:EncapsulatedX509Certificate>{}\
             </xades:EncapsulatedX509Certificate><xades:EncapsulatedX509Certificate>{}\
             </xades:EncapsulatedX509Certificate></xades:CertificateValues>\
             </xades141:TimeStampValidationData>",
            crate::base64::encode(&archive.ca),
            crate::base64::encode(&world.intermediate)
        );
        archived = archived.replace(close, &format!("{authority_data}{close}"));
    }
    if fault == XadesArchiveFault::Tampered {
        archived = archived.replacen(
            &crate::base64::encode(&world.tsa_root),
            &crate::base64::encode(&world.root),
            1,
        );
    }
    xades_container_of(&archived)
}

#[test]
fn an_lta_xades_container_whose_signature_timestamp_authority_expired_stands_on_its_archive_timestamp()
 {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let report = verify_expired(
        archived_xades(&world, &archive, XadesArchiveFault::Sound),
        &archive.anchors(&world),
    );
    let signature = only(&report);
    assert_eq!(kinds(signature.timestamps()), [Kind::Claimed(day(STAMPED))]);
    assert_eq!(
        archive_kinds(signature),
        [(ArchiveForm::Xades, Kind::Anchored(day(ARCHIVED)))]
    );
    assert_eq!(signature.proof_of_existence(), Some(day(ARCHIVED)));
    assert_eq!(signature.validation_time(), day(ARCHIVED));
    assert!(report.is_valid());
}

#[test]
fn changed_xades_validation_data_makes_the_archive_timestamp_invalid() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let report = verify_expired(
        archived_xades(&world, &archive, XadesArchiveFault::Tampered),
        &archive.anchors(&world),
    );
    let signature = only(&report);
    assert_eq!(
        archive_kinds(signature),
        [(
            ArchiveForm::Xades,
            Kind::Invalid(TimestampError::ImprintMismatch)
        )]
    );
    assert!(!report.is_valid());
}

/// The object number of the content stream, form field or page a
/// revision test adds to the minimal PDF, one past its last object.
const ADDED_OBJECT: u32 = 4;
/// The minimal PDF's catalog.
const CATALOG_OBJECT: u32 = 1;
/// The minimal PDF's page tree root.
const PAGES_OBJECT: u32 = 2;
/// The minimal PDF's one page.
const PAGE_OBJECT: u32 = 3;
/// The pages of the minimal PDF once one is added.
const PAGES_AFTER_ADDING: u32 = 2;

/// The newest body of object `number` of `pdf`.
fn newest_body(pdf: &[u8], number: u32) -> Vec<u8> {
    crate::pades::index::PdfIndex::parse(pdf)
        .expect("indexes")
        .object_body(number)
        .expect("the object")
}

/// One past the highest object number of `pdf`, from its trailer.
fn next_object(pdf: &[u8]) -> u32 {
    let index = crate::pades::index::PdfIndex::parse(pdf).expect("indexes");
    crate::pades::index::dictionary_integer(index.trailer(), b"/Size").expect("a /Size")
}

/// `body` with `old` replaced by `new` once.
fn edited(body: &[u8], old: &str, new: &str) -> Vec<u8> {
    let text = String::from_utf8(body.to_vec()).expect("ASCII");
    assert!(text.contains(old), "{old} in the body");
    text.replacen(old, new, 1).into_bytes()
}

/// The facts of the first signature of `pdf`, judged at [`NOW`].
fn first_signature(world: &World, pdf: Vec<u8>) -> SignatureReport {
    let report = world.verify(pdf).expect("report");
    judged(report.rows().first().expect("a signature")).clone()
}

#[test]
fn a_document_timestamp_and_validation_store_after_signing_change_nothing() {
    let world = World::new();
    let signed = world.pdf(Signer::Issued, Stamp::Anchored, &world.lt_material(None));
    let report = world
        .verify(with_document_timestamp(&world, &signed))
        .expect("report");
    let signature = only(&report);
    assert_eq!(signature.revision(), Revision::LaterRevisionsHarmless);
    assert!(signature.document_intact());
    assert!(signature.is_valid());
    assert!(report.is_valid());
}

#[test]
fn a_second_signature_after_signing_changes_nothing() {
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
    assert_eq!(judged(first).revision(), Revision::LaterRevisionsHarmless);
    assert!(judged(first).document_intact());
    assert_eq!(judged(second).revision(), Revision::WholeDocument);
    assert!(report.is_valid());
}

#[test]
fn a_changed_page_content_stream_is_a_change_after_signing() {
    let world = World::new();
    let stream = |text: &str| format!("<< /Length {} >>\nstream\n{text}\nendstream", text.len());
    let page = edited(
        &newest_body(&minimal_pdf(), PAGE_OBJECT),
        " >>",
        &format!(" /Contents {ADDED_OBJECT} 0 R >>"),
    );
    let drawn = crate::testkit::incremental_update(
        &minimal_pdf(),
        &[
            (ADDED_OBJECT, stream("0 0 m 10 10 l S").as_bytes()),
            (PAGE_OBJECT, &page),
        ],
    );
    let signed = world.sign_pdf(
        drawn,
        Signer::Direct,
        Stamp::None,
        &ValidationMaterial::default(),
    );
    let redrawn = crate::testkit::incremental_update(
        &signed,
        &[(ADDED_OBJECT, stream("0 0 m 20 20 l S").as_bytes())],
    );
    let signature = first_signature(&world, redrawn);
    assert_eq!(
        signature.revision(),
        Revision::ChangedAfterSigning(DocumentChange::Content)
    );
    assert!(!signature.document_intact());
    assert!(!signature.is_valid());
}

#[test]
fn an_added_page_is_a_change_after_signing() {
    let world = World::new();
    let signed = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let added = next_object(&signed);
    let page = format!(
        "<< /Type /Page /Parent {PAGES_OBJECT} 0 R {} >>",
        core::str::from_utf8(MEDIA_BOX).expect("ASCII")
    );
    let pages = format!(
        "<< /Type /Pages /Kids [{PAGE_OBJECT} 0 R {added} 0 R] /Count {PAGES_AFTER_ADDING} >>"
    );
    let extended = crate::testkit::incremental_update(
        &signed,
        &[(added, page.as_bytes()), (PAGES_OBJECT, pages.as_bytes())],
    );
    let signature = first_signature(&world, extended);
    assert_eq!(
        signature.revision(),
        Revision::ChangedAfterSigning(DocumentChange::Pages)
    );
    assert!(!signature.document_intact());
}

#[test]
fn a_changed_form_field_value_is_a_change_after_signing() {
    let world = World::new();
    let field = |value: &str| format!("<< /FT /Tx /T (Name) /V ({value}) >>");
    let catalog = edited(
        &newest_body(&minimal_pdf(), CATALOG_OBJECT),
        " >>",
        &format!(" /AcroForm << /Fields [{ADDED_OBJECT} 0 R] >> >>"),
    );
    let form = crate::testkit::incremental_update(
        &minimal_pdf(),
        &[
            (ADDED_OBJECT, field("Before").as_bytes()),
            (CATALOG_OBJECT, &catalog),
        ],
    );
    let signed = world.sign_pdf(
        form,
        Signer::Direct,
        Stamp::None,
        &ValidationMaterial::default(),
    );
    let filled =
        crate::testkit::incremental_update(&signed, &[(ADDED_OBJECT, field("After").as_bytes())]);
    let signature = first_signature(&world, filled);
    assert_eq!(
        signature.revision(),
        Revision::ChangedAfterSigning(DocumentChange::FormField)
    );
    assert!(!signature.document_intact());
}

#[test]
fn an_added_annotation_is_a_change_after_signing() {
    let world = World::new();
    let signed = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let added = next_object(&signed);
    let note = "<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (Added) >>";
    let page = edited(
        &newest_body(&signed, PAGE_OBJECT),
        "/Annots [",
        &format!("/Annots [{added} 0 R "),
    );
    let annotated = crate::testkit::incremental_update(
        &signed,
        &[(added, note.as_bytes()), (PAGE_OBJECT, &page)],
    );
    let signature = first_signature(&world, annotated);
    assert_eq!(
        signature.revision(),
        Revision::ChangedAfterSigning(DocumentChange::Annotation)
    );
    assert!(!signature.document_intact());
}

#[test]
fn an_archive_attribute_holding_two_values_is_invalid() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let report = verify_expired(
        archived_pdf(&world, &archive, ArchiveFault::TwoValues),
        &archive.anchors(&world),
    );
    let signature = only(&report);
    assert_eq!(
        archive_kinds(signature),
        [(
            ArchiveForm::CadesV3,
            Kind::Invalid(TimestampError::Malformed(
                "archive-time-stamp-v3 holds more than one value"
            ))
        )]
    );
    assert_eq!(signature.proof_of_existence(), None);
    assert!(!report.is_valid());
}

#[test]
fn updated_document_information_and_metadata_change_nothing() {
    let world = World::new();
    let signed = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let metadata = next_object(&signed);
    let info = metadata.saturating_add(1);
    let stream = |text: &str| {
        format!(
            "<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n{text}\nendstream",
            text.len()
        )
    };
    let information = |producer: &str| format!("<< /Producer ({producer}) >>");
    let catalog = edited(
        &newest_body(&signed, CATALOG_OBJECT),
        "/Type /Catalog",
        &format!("/Type /Catalog /Metadata {metadata} 0 R"),
    );
    let described = crate::testkit::incremental_update_with_info(
        &signed,
        &[
            (metadata, stream("<x:xmpmeta/>").as_bytes()),
            (info, information("Synthetic first").as_bytes()),
            (CATALOG_OBJECT, &catalog),
        ],
        info,
    );
    let redescribed = crate::testkit::incremental_update_with_info(
        &described,
        &[
            (metadata, stream("<x:xmpmeta></x:xmpmeta>").as_bytes()),
            (info, information("Synthetic second").as_bytes()),
        ],
        info,
    );
    let report = world.verify(redescribed).expect("report");
    let signature = only(&report);
    assert_eq!(signature.revision(), Revision::LaterRevisionsHarmless);
    assert!(signature.document_intact());
    assert!(report.is_valid());
}

/// The archive kinds and chain verdict of `pdf`'s one signature on
/// [`EXPIRED`] under the archive authority's anchors.
fn judged_on_expiry(
    world: &World,
    archive: &ArchiveAuthority,
    bytes: Vec<u8>,
) -> (Vec<(ArchiveForm, Kind)>, bool, bool) {
    let report = verify_expired(bytes, &archive.anchors(world));
    let signature = only(&report);
    (
        archive_kinds(signature),
        signature.chain_verified(),
        report.is_valid(),
    )
}

#[test]
fn material_the_archive_index_covers_is_used_at_the_archive_time() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let (kinds, chain, valid) = judged_on_expiry(
        &world,
        &archive,
        archived_pdf(&world, &archive, ArchiveFault::IntermediateCovered),
    );
    assert_eq!(
        kinds,
        [(ArchiveForm::CadesV3, Kind::Anchored(day(ARCHIVED)))]
    );
    assert!(chain);
    assert!(valid);
}

#[test]
fn a_certificate_added_after_the_archive_timestamp_is_not_used_at_the_archive_time() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let (kinds, chain, valid) = judged_on_expiry(
        &world,
        &archive,
        archived_pdf(&world, &archive, ArchiveFault::IntermediateAfter),
    );
    assert_eq!(
        kinds,
        [(ArchiveForm::CadesV3, Kind::Anchored(day(ARCHIVED)))]
    );
    assert!(
        !chain,
        "the intermediate is not covered by the archive index"
    );
    assert!(!valid);
}

#[test]
fn an_unsigned_attribute_after_the_archive_timestamp_is_not_demanded() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let (kinds, _chain, valid) = judged_on_expiry(
        &world,
        &archive,
        archived_pdf(&world, &archive, ArchiveFault::AttributeAfter),
    );
    assert_eq!(
        kinds,
        [(ArchiveForm::CadesV3, Kind::Anchored(day(ARCHIVED)))]
    );
    assert!(valid);
}

#[test]
fn an_index_under_another_algorithm_than_the_token_is_invalid() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let (kinds, _chain, _valid) = judged_on_expiry(
        &world,
        &archive,
        archived_pdf(&world, &archive, ArchiveFault::IndexAlgorithm),
    );
    assert_eq!(
        kinds,
        [(
            ArchiveForm::CadesV3,
            Kind::Invalid(TimestampError::ImprintMismatch)
        )]
    );
}

#[test]
fn a_token_with_no_index_or_two_is_invalid() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    for (fault, reason) in [
        (ArchiveFault::NoIndex, "ats-hash-index-v3 absent"),
        (ArchiveFault::TwoIndexes, "ats-hash-index-v3 repeated"),
    ] {
        let (kinds, _chain, valid) =
            judged_on_expiry(&world, &archive, archived_pdf(&world, &archive, fault));
        assert_eq!(
            kinds,
            [(
                ArchiveForm::CadesV3,
                Kind::Invalid(TimestampError::Malformed(reason))
            )]
        );
        assert!(!valid);
    }
}

#[test]
fn xades_material_after_the_archive_timestamp_is_not_used_at_the_archive_time() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let (kinds, chain, valid) = judged_on_expiry(
        &world,
        &archive,
        archived_xades(&world, &archive, XadesArchiveFault::IntermediateBefore),
    );
    assert_eq!(kinds, [(ArchiveForm::Xades, Kind::Anchored(day(ARCHIVED)))]);
    assert!(chain);
    assert!(valid);
    let (kinds, chain, valid) = judged_on_expiry(
        &world,
        &archive,
        archived_xades(&world, &archive, XadesArchiveFault::IntermediateAfter),
    );
    assert_eq!(kinds, [(ArchiveForm::Xades, Kind::Anchored(day(ARCHIVED)))]);
    assert!(!chain, "the intermediate follows the archive timestamp");
    assert!(!valid);
}

/// The object number `key` references in `body`, as `/Key N 0 R` or
/// the first entry of `/Key [N 0 R ...]`.
fn referenced(body: &[u8], key: &str) -> u32 {
    let text = String::from_utf8(body.to_vec()).expect("ASCII");
    let after = text
        .split_once(&format!("/{key}"))
        .expect("the key")
        .1
        .trim_start()
        .trim_start_matches('[');
    after
        .split_whitespace()
        .next()
        .and_then(|number| number.parse().ok())
        .expect("an object number")
}

/// The revision fact of the first signature of `pdf`, judged at
/// [`NOW`].
fn revision_of(world: &World, pdf: Vec<u8>) -> Revision {
    first_signature(world, pdf).revision()
}

/// The minimal PDF signed by the direct signer, no timestamp.
fn plainly_signed(world: &World, pdf: Vec<u8>) -> Vec<u8> {
    world.sign_pdf(
        pdf,
        Signer::Direct,
        Stamp::None,
        &ValidationMaterial::default(),
    )
}

#[test]
fn a_rewritten_signed_widget_is_a_change() {
    let world = World::new();
    let signed = plainly_signed(&world, minimal_pdf());
    let widget = referenced(&newest_body(&signed, PAGE_OBJECT), "Annots");
    let body = newest_body(&signed, widget);
    let appearance = next_object(&signed);
    for rewritten in [
        edited(&body, "/Rect [0 0 0 0]", "/Rect [0 0 10 10]"),
        edited(&body, " >>", &format!(" /AP << /N {appearance} 0 R >> >>")),
    ] {
        let updated = crate::testkit::incremental_update(
            &signed,
            &[
                (widget, &rewritten),
                (appearance, b"<< /Length 0 >>\nstream\n\nendstream"),
            ],
        );
        assert_eq!(
            revision_of(&world, updated),
            Revision::ChangedAfterSigning(DocumentChange::FormField)
        );
    }
}

#[test]
fn a_replaced_validation_store_object_is_a_change() {
    let world = World::new();
    let stored = world.pdf(Signer::Issued, Stamp::None, &world.lt_material(None));
    let twice = plainly_signed(&world, stored);
    let store = referenced(&newest_body(&twice, CATALOG_OBJECT), "DSS");
    let certificate = referenced(&newest_body(&twice, store), "Certs");
    let replaced = crate::testkit::incremental_update(
        &twice,
        &[(certificate, b"<< /Length 5 >>\nstream\nother\nendstream")],
    );
    let report = world.verify(replaced).expect("report");
    let [_first, second] = exactly(report.rows(), "two signatures");
    assert_eq!(
        judged(second).revision(),
        Revision::ChangedAfterSigning(DocumentChange::Content),
        "the store the second signer saw is rewritten"
    );
}

#[test]
fn a_new_trailer_root_is_a_change() {
    let world = World::new();
    let signed = plainly_signed(&world, minimal_pdf());
    let catalog = newest_body(&signed, CATALOG_OBJECT);
    let root = next_object(&signed);
    let rerooted = crate::testkit::incremental_update_with_root(&signed, &[(root, &catalog)], root);
    assert_eq!(
        revision_of(&world, rerooted),
        Revision::ChangedAfterSigning(DocumentChange::Catalog),
        "a new catalog, named by a new /Root"
    );
}

/// The object number of a text annotation the base PDF of a list test
/// carries before signing.
const NOTE_OBJECT: u32 = 4;
/// The object number of the indirect `/Annots` array of that PDF.
const ANNOTS_OBJECT: u32 = 5;
/// The object number of its text field.
const TEXT_FIELD_OBJECT: u32 = 6;
/// The object number of its indirect `/Fields` array.
const FIELDS_OBJECT: u32 = 7;

/// The minimal PDF with a text annotation in an indirect `/Annots`
/// array and a text field in an indirect `/Fields` array, signed.
fn signed_with_lists(world: &World) -> Vec<u8> {
    let page = edited(
        &newest_body(&minimal_pdf(), PAGE_OBJECT),
        " >>",
        &format!(" /Annots {ANNOTS_OBJECT} 0 R >>"),
    );
    let catalog = edited(
        &newest_body(&minimal_pdf(), CATALOG_OBJECT),
        " >>",
        &format!(" /AcroForm << /Fields {FIELDS_OBJECT} 0 R >> >>"),
    );
    let note = "<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (Note) >>";
    let annots = format!("[{NOTE_OBJECT} 0 R]");
    let field = "<< /FT /Tx /T (Name) /V (Value) >>";
    let fields = format!("[{TEXT_FIELD_OBJECT} 0 R]");
    let base = crate::testkit::incremental_update(
        &minimal_pdf(),
        &[
            (NOTE_OBJECT, note.as_bytes()),
            (ANNOTS_OBJECT, annots.as_bytes()),
            (TEXT_FIELD_OBJECT, field.as_bytes()),
            (FIELDS_OBJECT, fields.as_bytes()),
            (PAGE_OBJECT, &page),
            (CATALOG_OBJECT, &catalog),
        ],
    );
    plainly_signed(world, base)
}

/// `array` with its two entries swapped.
fn swapped(array: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(array.to_vec()).expect("ASCII");
    let inner = text.trim().trim_start_matches('[').trim_end_matches(']');
    let entries: Vec<&str> = inner
        .split(" R")
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    let [first, second] = exactly(&entries, "two entries");
    format!("[{second} R {first} R]").into_bytes()
}

#[test]
fn indirect_lists_are_judged_through_their_arrays() {
    let world = World::new();
    let signed = signed_with_lists(&world);
    assert_eq!(revision_of(&world, signed.clone()), Revision::WholeDocument);
    let annots = newest_body(&signed, ANNOTS_OBJECT);
    let fields = newest_body(&signed, FIELDS_OBJECT);

    let stamped = with_document_timestamp(&world, &signed);
    assert_eq!(
        revision_of(&world, stamped),
        Revision::LaterRevisionsHarmless,
        "a document timestamp's widget is appended to both arrays"
    );

    let reordered_fields =
        crate::testkit::incremental_update(&signed, &[(FIELDS_OBJECT, &swapped(&fields))]);
    assert_eq!(
        revision_of(&world, reordered_fields),
        Revision::LaterRevisionsHarmless
    );

    let reordered_annots =
        crate::testkit::incremental_update(&signed, &[(ANNOTS_OBJECT, &swapped(&annots))]);
    assert_eq!(
        revision_of(&world, reordered_annots),
        Revision::ChangedAfterSigning(DocumentChange::Annotation)
    );
}

#[test]
fn an_annotation_whose_parent_is_a_signature_field_is_a_change() {
    let world = World::new();
    let signed = plainly_signed(&world, minimal_pdf());
    let page_body = newest_body(&signed, PAGE_OBJECT);
    let widget = referenced(&page_body, "Annots");
    let added = next_object(&signed);
    let note = format!("<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Parent {widget} 0 R >>");
    let page = edited(&page_body, "/Annots [", &format!("/Annots [{added} 0 R "));
    let updated = crate::testkit::incremental_update(
        &signed,
        &[(added, note.as_bytes()), (PAGE_OBJECT, &page)],
    );
    assert!(matches!(
        revision_of(&world, updated),
        Revision::ChangedAfterSigning(_)
    ));
}

#[test]
fn a_new_object_that_is_none_of_the_harmless_kinds_is_a_change() {
    let world = World::new();
    let signed = plainly_signed(&world, minimal_pdf());
    let added = next_object(&signed);
    for (body, kind) in [
        (
            b"<< /Length 9 >>\nstream\n0 0 m S Q\nendstream".as_slice(),
            DocumentChange::Content,
        ),
        (
            b"<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] >>".as_slice(),
            DocumentChange::Annotation,
        ),
        (
            b"<< /Unread /Value >> not a stream".as_slice(),
            DocumentChange::Content,
        ),
    ] {
        let updated = crate::testkit::incremental_update(&signed, &[(added, body)]);
        assert_eq!(
            revision_of(&world, updated),
            Revision::ChangedAfterSigning(kind)
        );
    }
}

#[test]
fn a_stream_linked_only_from_a_dummy_store_entry_or_an_unattached_field_is_a_change() {
    let world = World::new();
    let signed = world.pdf(Signer::Issued, Stamp::None, &world.lt_material(None));
    let store = referenced(&newest_body(&signed, CATALOG_OBJECT), "DSS");
    let stream = next_object(&signed);
    let content = b"<< /Length 5 >>\nstream\n0 0 m\nendstream";
    let dummy = edited(
        &newest_body(&signed, store),
        " >>",
        &format!(" /Dummy [{stream} 0 R] >>"),
    );
    let linked = crate::testkit::incremental_update(
        &signed,
        &[(stream, content.as_slice()), (store, &dummy)],
    );
    assert_eq!(
        revision_of(&world, linked),
        Revision::ChangedAfterSigning(DocumentChange::Content)
    );

    let field = stream.saturating_add(1);
    let unattached = format!("<< /FT /Sig /T (Loose) /V {store} 0 R /AP << /N {stream} 0 R >> >>");
    let loose = crate::testkit::incremental_update(
        &signed,
        &[(stream, content.as_slice()), (field, unattached.as_bytes())],
    );
    assert!(matches!(
        revision_of(&world, loose),
        Revision::ChangedAfterSigning(_)
    ));
}

/// The generation an object takes when its number is reused.
const RAISED_GENERATION: u16 = 1;

#[test]
fn a_raised_generation_is_a_replacement_and_a_change() {
    let world = World::new();
    let stream = |text: &str| format!("<< /Length {} >>\nstream\n{text}\nendstream", text.len());
    let page = edited(
        &newest_body(&minimal_pdf(), PAGE_OBJECT),
        " >>",
        &format!(" /Contents {ADDED_OBJECT} 0 R >>"),
    );
    let drawn = crate::testkit::incremental_update(
        &minimal_pdf(),
        &[
            (ADDED_OBJECT, stream("0 0 m 10 10 l S").as_bytes()),
            (PAGE_OBJECT, &page),
        ],
    );
    let signed = plainly_signed(&world, drawn);
    let bumped = crate::testkit::incremental_update_at_generation(
        &signed,
        &[(
            ADDED_OBJECT,
            RAISED_GENERATION,
            stream("0 0 m 10 10 l S").as_bytes(),
        )],
    );
    assert_eq!(
        revision_of(&world, bumped),
        Revision::ChangedAfterSigning(DocumentChange::Content),
        "the signed page's reference no longer resolves"
    );
}

#[test]
fn reference_cycles_end_and_are_changes() {
    let world = World::new();
    let signed = plainly_signed(&world, minimal_pdf());
    let page_body = newest_body(&signed, PAGE_OBJECT);
    let looped = next_object(&signed);
    let note = format!("<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Parent {looped} 0 R >>");
    let page = edited(&page_body, "/Annots [", &format!("/Annots [{looped} 0 R "));
    let parent_cycle = crate::testkit::incremental_update(
        &signed,
        &[(looped, note.as_bytes()), (PAGE_OBJECT, &page)],
    );
    assert_eq!(
        revision_of(&world, parent_cycle),
        Revision::ChangedAfterSigning(DocumentChange::Annotation)
    );

    let other = looped.saturating_add(1);
    let first = format!("<< /FT /Tx /T (First) /Kids [{other} 0 R] >>");
    let second = format!("<< /FT /Tx /T (Second) /Kids [{looped} 0 R] >>");
    let catalog = edited(
        &newest_body(&signed, CATALOG_OBJECT),
        "/Fields [",
        &format!("/Fields [{looped} 0 R "),
    );
    let kids_cycle = crate::testkit::incremental_update(
        &signed,
        &[
            (looped, first.as_bytes()),
            (other, second.as_bytes()),
            (CATALOG_OBJECT, &catalog),
        ],
    );
    assert_eq!(
        revision_of(&world, kids_cycle),
        Revision::ChangedAfterSigning(DocumentChange::FormField)
    );
}

#[test]
fn validation_data_after_an_archive_timestamp_serves_that_timestamp_alone() {
    let world = World::new();
    let archive = ArchiveAuthority::new();
    let (kinds, chain, valid) = judged_on_expiry(
        &world,
        &archive,
        archived_xades(&world, &archive, XadesArchiveFault::AuthorityDataAfter),
    );
    assert_eq!(kinds, [(ArchiveForm::Xades, Kind::Anchored(day(ARCHIVED)))]);
    assert!(
        !chain,
        "the signer's intermediate in that validation data is not used for the signer"
    );
    assert!(!valid);

    let (kinds, _chain, valid) = judged_on_expiry(
        &world,
        &archive,
        archived_xades(&world, &archive, XadesArchiveFault::AuthorityDataMissing),
    );
    assert_eq!(kinds, [(ArchiveForm::Xades, Kind::Claimed(day(ARCHIVED)))]);
    assert!(!valid);
}

/// What a scripted OCSP responder answers, in turn.
#[derive(Debug, Clone, Copy)]
enum Responder {
    /// Bytes that are no OCSP response.
    Garbage,
    /// A good answer echoing the request's nonce, produced on the day.
    Good(u8),
    /// A revoked answer echoing the request's nonce.
    Revoked(u8),
    /// A good answer whose nonce is not the request's.
    ChangedNonce,
    /// A good pre-produced answer that echoes no nonce.
    NoNonce,
}

/// Bytes a responder returns that are no OCSP response.
const NOT_AN_ANSWER: &[u8] = b"not an answer";
/// A nonce no request carried.
const OTHER_NONCE: &[u8] = b"another request's nonce";

/// The value of the nonce extension `request` carries: the content of
/// its `extnValue` (RFC 8954 sec.2.1).
fn request_nonce(request: &[u8]) -> Vec<u8> {
    let oid = crate::ocsp::OID_OCSP_NONCE.as_bytes();
    let at = request
        .windows(oid.len())
        .position(|window| window == oid)
        .expect("the request carries a nonce")
        .saturating_add(oid.len());
    refineid_ber::BerTlvAny::parse(&request[at..])
        .expect("extnValue")
        .value()
        .to_vec()
}

/// Answers from scripted responders, counting the exchanges.
struct ScriptedAnswers<'w> {
    world: &'w World,
    ocsp: Vec<Responder>,
    crls: Vec<Vec<u8>>,
    ocsp_asked: core::cell::Cell<usize>,
    crl_asked: core::cell::Cell<usize>,
}

impl<'w> ScriptedAnswers<'w> {
    fn new(world: &'w World, ocsp: Vec<Responder>, crls: Vec<Vec<u8>>) -> Self {
        Self {
            world,
            ocsp,
            crls,
            ocsp_asked: core::cell::Cell::new(0),
            crl_asked: core::cell::Cell::new(0),
        }
    }

    /// The root's answer about the direct signer, echoing `nonce`.
    fn root_answer(&self, nonce: Option<&[u8]>, revoked: Option<u8>, produced: u8) -> Vec<u8> {
        let nonce_oid = crate::ocsp::OID_OCSP_NONCE;
        let issuer = OwnedCert::from_der(&self.world.root).expect("issuer parses");
        ocsp_response(&OcspSpec {
            responder_key: &self.world.root_key,
            responder: ResponderName::ByName(ROOT),
            issuer: &issuer,
            serial: DIRECT_SIGNER_SERIAL,
            revoked: revoked.map(day),
            produced_at: day(produced),
            this_update: day(produced),
            next_update: None,
            embedded: Vec::new(),
            cert_id: crate::testkit::CertIdAlgorithm::Sha1,
            revocation_reason: None,
            response_extensions: nonce
                .map(|nonce| {
                    crate::testkit::extension(
                        refineid_cms::oid::Oid::const_new(nonce_oid.as_bytes()),
                        false,
                        nonce,
                    )
                })
                .into_iter()
                .collect(),
        })
    }
}

impl super::live::AnswerSource for ScriptedAnswers<'_> {
    fn ocsp(&self, _url: &crate::uri::Uri, request: &[u8]) -> Option<Vec<u8>> {
        let turn = self.ocsp_asked.get();
        self.ocsp_asked.set(turn.saturating_add(1));
        let echoed = request_nonce(request);
        Some(match *self.ocsp.get(turn)? {
            Responder::Garbage => NOT_AN_ANSWER.to_vec(),
            Responder::Good(produced) => self.root_answer(Some(&echoed), None, produced),
            Responder::Revoked(on) => self.root_answer(Some(&echoed), Some(on), NOW),
            Responder::ChangedNonce => self.root_answer(
                Some(&tlv(crate::testkit::OCTET_STRING, OTHER_NONCE)),
                None,
                NOW,
            ),
            Responder::NoNonce => self.root_answer(None, None, NOW),
        })
    }

    fn crl(&self, _url: &crate::uri::Uri) -> Option<Vec<u8>> {
        let turn = self.crl_asked.get();
        self.crl_asked.set(turn.saturating_add(1));
        self.crls.get(turn).cloned()
    }
}

/// The direct signer's PDF, unstamped, judged at [`NOW`].
fn unstamped_direct(world: &World) -> DocumentReport {
    let pdf = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    world.verify(pdf).expect("report")
}

#[test]
fn a_live_lookup_judges_what_the_responders_answer() {
    let world = World::new();
    let anchors = world.anchors();
    let report = unstamped_direct(&world);
    let signature = only(&report);
    assert_eq!(signature.revocation(), Revocation::Unavailable);
    for (what, ocsp, expected) in [
        (
            "good",
            vec![Responder::Good(NOW)],
            Revocation::Good { at: day(NOW) },
        ),
        (
            "revoked",
            vec![Responder::Revoked(REVOKED_LATER)],
            Revocation::Revoked {
                at: day(REVOKED_LATER),
                reason: None,
            },
        ),
        ("silent", Vec::new(), Revocation::Unavailable),
    ] {
        let source = ScriptedAnswers::new(&world, ocsp, Vec::new());
        let live = super::live::live_revocation_from(signature, &anchors, day(NOW), &source);
        assert_eq!(live, expected, "{what}");
    }
}

#[test]
fn a_live_lookup_asks_the_next_responder_after_one_that_does_not_hold_up() {
    let world = World::new();
    let anchors = world.anchors();
    let report = unstamped_direct(&world);
    let source = ScriptedAnswers::new(
        &world,
        vec![Responder::Garbage, Responder::Good(NOW)],
        Vec::new(),
    );
    let live = super::live::live_revocation_from(only(&report), &anchors, day(NOW), &source);
    assert_eq!(live, Revocation::Good { at: day(NOW) });
    assert_eq!(source.ocsp_asked.get(), 2, "both responders were asked");
    assert_eq!(source.crl_asked.get(), 0, "no list once OCSP answered");
}

#[test]
fn a_live_lookup_falls_back_to_the_crl_when_no_responder_holds_up() {
    let world = World::new();
    let anchors = world.anchors();
    let report = unstamped_direct(&world);
    let list = crate::testkit::crl(
        ROOT,
        &world.root_key,
        day(NOW),
        Some(day(ENDS)),
        &[DIRECT_SIGNER_SERIAL],
        day(REVOKED_LATER),
    );
    let source = ScriptedAnswers::new(
        &world,
        vec![Responder::Garbage, Responder::Garbage],
        vec![list],
    );
    let live = super::live::live_revocation_from(only(&report), &anchors, day(NOW), &source);
    assert_eq!(
        live,
        Revocation::Revoked {
            at: day(REVOKED_LATER),
            reason: None,
        }
    );
    assert_eq!(source.ocsp_asked.get(), 2);
    assert_eq!(source.crl_asked.get(), 1);
}

#[test]
fn a_live_answer_whose_nonce_changed_is_no_answer() {
    let world = World::new();
    let anchors = world.anchors();
    let report = unstamped_direct(&world);
    let source = ScriptedAnswers::new(&world, vec![Responder::ChangedNonce], Vec::new());
    let live = super::live::live_revocation_from(only(&report), &anchors, day(NOW), &source);
    assert_eq!(live, Revocation::Unavailable);
}

#[test]
fn a_live_answer_that_echoes_no_nonce_is_an_answer() {
    let world = World::new();
    let anchors = world.anchors();
    let report = unstamped_direct(&world);
    let source = ScriptedAnswers::new(&world, vec![Responder::NoNonce], Vec::new());
    let live = super::live::live_revocation_from(only(&report), &anchors, day(NOW), &source);
    assert_eq!(live, Revocation::Good { at: day(NOW) });
}

#[test]
fn a_live_lookup_judges_the_path_at_the_proof_of_existence() {
    let world = World::new();
    let anchors = world.anchors();
    let pdf = world.pdf(
        Signer::Direct,
        Stamp::Anchored,
        &ValidationMaterial::default(),
    );
    let report = verify_expired(pdf, &anchors);
    let signature = only(&report);
    assert_eq!(signature.validation_time(), day(STAMPED));
    assert!(signature.chain_verified());
    // Answered on the signer's last valid day, asked a day later.
    let source = ScriptedAnswers::new(&world, vec![Responder::Good(ENDS)], Vec::new());
    let live = super::live::live_revocation_from(signature, &anchors, day(EXPIRED), &source);
    assert_eq!(
        live,
        Revocation::Good { at: day(ENDS) },
        "the signer expired before now and was valid at the proven time"
    );
}

#[test]
fn a_live_lookup_asks_nothing_for_an_unanchored_chain() {
    let world = World::new();
    let pdf = world.pdf(Signer::Direct, Stamp::None, &ValidationMaterial::default());
    let strangers = TrustAnchors::new(vec![anchor(
        &world.stranger,
        AnchorRole::CertificateIssuing,
    )]);
    let report = verify_under(pdf, &strangers).expect("report");
    let source = ScriptedAnswers::new(&world, vec![Responder::Revoked(REVOKED_LATER)], Vec::new());
    let live = super::live::live_revocation_from(only(&report), &strangers, day(NOW), &source);
    assert_eq!(live, Revocation::Unavailable);
    assert_eq!(source.ocsp_asked.get(), 0);
}
