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

//! Document signing through the paired phone's card.
//!
//! The requester -- the computer's app -- drives RAPP itself and
//! implements [`RemoteSigner`] over it: [`RemoteSigner::signature_certificate`]
//! is `read_certificate` with kind `signature`, and
//! [`RemoteSigner::sign`] is one `sign_document` for a batch of one or
//! one `batch_sign_documents` for several (RAPP v26.10.29 section 9.3).
//! The phone shows the document names, asks for PIN 2 once on its own
//! screen, and its card signs each digest; no PIN reaches this
//! computer, and no document byte reaches the phone.
//!
//! [`sign_on_phone`] does everything else, sharing the local card
//! path's finish: it plans every document around the phone's
//! certificate, sends every digest in one call, verifies every
//! returned signature against that certificate before finishing any
//! document, and then finishes each with the same timestamp, long-term
//! material and output steps as a signature made in this computer's
//! reader.
//!
//! What the requester passes on the wire is read off the batch:
//! [`PhoneSigningBatch::key_profile`] and [`PhoneSigningBatch::algorithm`]
//! map name for name onto RAPP's `key_profile` and `algorithm`
//! (`rsa_2048`, `rsa_3072` or `ecdsa_p384`; `rsa_pkcs1_sha256` or
//! `ecdsa_sha384`), and each [`PhoneDocument::digest`] is sent as is.

use core::fmt;
use core::ops::RangeInclusive;
use std::path::PathBuf;

use refineid_cms::x509::{
    EcCurve, MessageSignatureAlgorithm, OwnedCert, PublicKeyAlgorithm, extract_key_usage,
};
use refineid_remote::{RemoteKeyProfile, RemoteSignatureAlgorithm, SignatureRequest};

use crate::cades::SignatureAlgorithm;
use crate::digest::Sha256;
use crate::document::{self, DocumentPlan};
use crate::service::{
    DocumentRequest, LocalVerifyOutcome, SignErrorKind, SignOutput, SignReport, SignSlot,
    SigningDevice, document_signer, ensure_visible_signature_format, finish_document,
    load_data_objects, verify_against_certificate,
};
use crate::x509_ext::NameExt as _;

/// The UTF-8 byte length of one document name the phone shows: RAPP
/// v26.10.29 section 9.3, `document_name` and each of
/// `document_names`, `tstr .size (1..256)`.
const DOCUMENT_NAME_BYTES: RangeInclusive<usize> = 1..=MAX_DOCUMENT_NAME_BYTES;
/// The upper bound of [`DOCUMENT_NAME_BYTES`].
const MAX_DOCUMENT_NAME_BYTES: usize = 256;
/// Between the file names of a container's files in its one document
/// name.
const CONTAINER_NAME_SEPARATOR: &str = ", ";
/// Modulus width of the RAPP key profile `rsa_2048` (section 9.2).
const RSA_2048_MODULUS_BITS: usize = 2048;
/// Modulus width of the RAPP key profile `rsa_3072` (section 9.2).
const RSA_3072_MODULUS_BITS: usize = 3072;

/// The certificate DER the paired phone returned for its card's
/// qualified-signature key, not yet checked.
///
/// Transit: it is consumed by [`sign_on_phone`], which parses it and
/// refuses anything but a qualified-signature certificate.
pub struct UnvalidatedPhoneCertificate(Vec<u8>);

impl UnvalidatedPhoneCertificate {
    /// The `certificate` of the phone's `read_certificate` result.
    #[must_use]
    pub const fn from_der(der: Vec<u8>) -> Self {
        Self(der)
    }
}

impl fmt::Debug for UnvalidatedPhoneCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnvalidatedPhoneCertificate")
            .field("len", &self.0.len())
            .finish()
    }
}

/// One signature the paired phone returned, not yet checked.
///
/// Transit: [`sign_on_phone`] verifies it against the phone's
/// certificate over the signed octets of the document at its position
/// before anything is finished.
pub struct UnvalidatedPhoneSignature(Vec<u8>);

impl UnvalidatedPhoneSignature {
    /// One entry of the phone's `signature` or `signatures` result, in
    /// the RAPP section 9.2 wire format.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for UnvalidatedPhoneSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnvalidatedPhoneSignature")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Why the paired phone produced no certificate or no signatures.
///
/// The requester maps its own protocol's outcomes onto this closed
/// set: RAPP v26.10.29 section 10.3 names the `operation.result` errors,
/// and a session or link that ends before the result arrives is
/// [`Self::Unreachable`] (section 9.3: an interrupted batch delivers no
/// signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneRefusal {
    /// The holder declined on the phone (`user_cancelled`).
    Declined,
    /// The operation's deadline passed (`operation_expired`), or no
    /// answer arrived within the requester's own deadline.
    Expired,
    /// The phone's card did not answer: no card within the wait, the
    /// field lost, a transmission fault (`card_error`).
    CardUnavailable,
    /// The card reports fewer than three PIN 2 tries left, so the phone
    /// sent no verification (`retry_floor`).
    RetryFloor,
    /// The pairing is not granted document signing (`unauthorized`).
    NotGranted,
    /// The phone refused the key profile, algorithm or a parameter
    /// value (`unsupported_parameter`).
    Unsupported,
    /// The phone could not carry the operation out for a reason of its
    /// own (`operation_failed`).
    PhoneFailed,
    /// No session to the phone could be opened or kept until the
    /// result arrived.
    Unreachable,
}

impl fmt::Display for PhoneRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Declined => "the signing was declined on the phone",
            Self::Expired => "the phone did not answer in time",
            Self::CardUnavailable => "the phone's card did not answer",
            Self::RetryFloor => {
                "the card's remaining PIN 2 tries are reserved for the card issuer's software"
            }
            Self::NotGranted => "the pairing is not granted document signing",
            Self::Unsupported => "the phone refused the request's parameters",
            Self::PhoneFailed => "the phone could not carry out the signing",
            Self::Unreachable => "the phone could not be reached",
        })
    }
}

/// Why the certificate the paired phone returned was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneCertificateError {
    /// The bytes are not a certificate.
    Unparseable(String),
    /// The certificate's key usage does not assert nonRepudiation, so
    /// it does not certify the card's qualified-signature key (FINEID
    /// S2: the signature certificate's key usage is nonRepudiation;
    /// RFC 5280 section 4.2.1.3).
    NotQualifiedSignature,
    /// The certificate's key has no RAPP key profile a document
    /// signature can be made with: RSA of 2048 or 3072 bits, or ECDSA
    /// on P-384.
    UnsupportedKey,
}

impl fmt::Display for PhoneCertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unparseable(detail) => write!(f, "not a certificate: {detail}"),
            Self::NotQualifiedSignature => {
                f.write_str("not the card's qualified-signature certificate")
            }
            Self::UnsupportedKey => f.write_str("its key cannot make a document signature"),
        }
    }
}

impl core::error::Error for PhoneCertificateError {}

/// The name the phone shows the holder for one document: the file's
/// name, or for a container the names of the files it carries, joined
/// in the order they are signed. Its UTF-8 length is within RAPP
/// v26.10.29 section 9.3's bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentName(String);

impl DocumentName {
    /// The name from the files' names, refused outside the bound.
    fn of_files<'a>(names: impl Iterator<Item = &'a str>) -> Result<Self, SignErrorKind> {
        let joined = names.collect::<Vec<_>>().join(CONTAINER_NAME_SEPARATOR);
        if DOCUMENT_NAME_BYTES.contains(&joined.len()) {
            Ok(Self(joined))
        } else {
            Err(SignErrorKind::DocumentNameLength)
        }
    }

    /// The name, as the phone shows it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One document the phone is asked to sign: the name it shows and the
/// digest its card signs.
#[derive(Debug, Clone)]
pub struct PhoneDocument {
    /// The name shown to the holder.
    name: DocumentName,
    /// The digest, with the batch's key profile and algorithm.
    request: SignatureRequest,
}

impl PhoneDocument {
    /// The name the phone shows the holder for this document.
    #[must_use]
    pub const fn name(&self) -> &DocumentName {
        &self.name
    }

    /// The digest the card signs: exactly what the document's format
    /// signs, hashed as [`PhoneSigningBatch::algorithm`] names, sent as
    /// RAPP's `digest` (or one entry of `digests`) unchanged. The card
    /// applies the scheme: the DigestInfo and PKCS#1 padding for RSA, the
    /// ECDSA computation for an elliptic-curve key.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        self.request.digest()
    }
}

/// Every document of one signing, in signing order, under one key
/// profile and one algorithm read off the phone's certificate. The
/// phone answers with one signature per document, in the same order.
/// Never empty.
#[derive(Debug, Clone)]
pub struct PhoneSigningBatch {
    /// The certificate key's RAPP profile.
    key_profile: RemoteKeyProfile,
    /// The RAPP algorithm the documents' formats name.
    algorithm: RemoteSignatureAlgorithm,
    /// The documents, in signing order.
    documents: Vec<PhoneDocument>,
}

impl PhoneSigningBatch {
    /// RAPP's `key_profile`: the profile of the phone certificate's key.
    #[must_use]
    pub const fn key_profile(&self) -> RemoteKeyProfile {
        self.key_profile
    }

    /// RAPP's `algorithm`: the signature algorithm every document's
    /// format names for that key.
    #[must_use]
    pub const fn algorithm(&self) -> RemoteSignatureAlgorithm {
        self.algorithm
    }

    /// The documents, in signing order; one or more.
    #[must_use]
    pub fn documents(&self) -> &[PhoneDocument] {
        &self.documents
    }
}

/// The paired phone, as the document signing flow drives it.
///
/// Implemented by the requester over its own RAPP transport; this crate
/// holds no transport. Each method is one RAPP operation and is called
/// at most once per [`sign_on_phone`].
pub trait RemoteSigner {
    /// The certificate of the phone's card's qualified-signature key:
    /// `read_certificate` with kind `signature` (RAPP v26.10.29
    /// section 9.3).
    ///
    /// # Errors
    /// The phone's refusal.
    fn signature_certificate(&mut self) -> Result<UnvalidatedPhoneCertificate, PhoneRefusal>;

    /// Ask the phone to sign every document of `batch` under one
    /// consent and one PIN 2 entry on the phone: `sign_document` for a
    /// batch of one, `batch_sign_documents` for several, carrying the
    /// batch's names, key profile, algorithm and digests in order.
    /// Returns the phone's signatures in the order it gave them.
    ///
    /// # Errors
    /// The phone's refusal; no signature of a refused batch is used.
    fn sign(
        &mut self,
        batch: &PhoneSigningBatch,
    ) -> Result<Vec<UnvalidatedPhoneSignature>, PhoneRefusal>;
}

/// One document to sign through the phone: the file, where the signed
/// document goes, and how it is signed.
#[derive(Debug)]
pub struct PhoneSignOptions {
    /// The file to sign; the first file of a container.
    pub input: PathBuf,
    /// Where the signed document is written.
    pub output: SignOutput,
    /// The format and level. The phone's card is bound by the
    /// certificate the phone returns, which the batch is built on.
    pub document: DocumentRequest,
}

/// The outcome of one document once the phone's signatures verified.
pub type PhoneDocumentOutcome = Result<SignReport, SignErrorKind>;

/// The paired phone's certificate, checked: a qualified-signature
/// certificate whose key has a RAPP key profile.
struct PhoneSignatureCertificate {
    /// The certificate.
    cert: OwnedCert,
    /// Its key's RAPP profile.
    key_profile: RemoteKeyProfile,
}

impl PhoneSignatureCertificate {
    /// Parse and check the phone's answer.
    fn from_phone(unvalidated: UnvalidatedPhoneCertificate) -> Result<Self, SignErrorKind> {
        let cert = OwnedCert::from_der(&unvalidated.0).map_err(|e| {
            SignErrorKind::PhoneCertificate(PhoneCertificateError::Unparseable(e.to_string()))
        })?;
        let view = cert.view();
        let non_repudiation = view
            .extensions
            .and_then(extract_key_usage)
            .is_some_and(|usage| usage.non_repudiation);
        if !non_repudiation {
            return Err(SignErrorKind::PhoneCertificate(
                PhoneCertificateError::NotQualifiedSignature,
            ));
        }
        let key_profile = match view.spki.algorithm() {
            PublicKeyAlgorithm::Rsa {
                modulus_bits: RSA_2048_MODULUS_BITS,
            } => RemoteKeyProfile::Rsa2048,
            PublicKeyAlgorithm::Rsa {
                modulus_bits: RSA_3072_MODULUS_BITS,
            } => RemoteKeyProfile::Rsa3072,
            PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => RemoteKeyProfile::EcdsaP384,
            PublicKeyAlgorithm::Rsa { .. }
            | PublicKeyAlgorithm::Ec(_)
            | PublicKeyAlgorithm::Other => {
                return Err(SignErrorKind::PhoneCertificate(
                    PhoneCertificateError::UnsupportedKey,
                ));
            }
        };
        Ok(Self { cert, key_profile })
    }
}

/// The RAPP algorithm the card computes for a format's signature
/// algorithm, and the verifier that checks the card's answer in the
/// RAPP section 9.2 wire format.
const fn phone_algorithm(
    algorithm: SignatureAlgorithm,
) -> (RemoteSignatureAlgorithm, MessageSignatureAlgorithm) {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1Sha256 => (
            RemoteSignatureAlgorithm::RsaPkcs1Sha256,
            MessageSignatureAlgorithm::RsaPkcs1Sha256,
        ),
        SignatureAlgorithm::RsaPkcs1Sha384 => (
            RemoteSignatureAlgorithm::RsaPkcs1Sha384,
            MessageSignatureAlgorithm::RsaPkcs1Sha384,
        ),
        SignatureAlgorithm::EcdsaSha256 => (
            RemoteSignatureAlgorithm::EcdsaSha256,
            MessageSignatureAlgorithm::EcdsaSha256Raw,
        ),
        SignatureAlgorithm::EcdsaSha384 => (
            RemoteSignatureAlgorithm::EcdsaSha384,
            MessageSignatureAlgorithm::EcdsaSha384Raw,
        ),
    }
}

/// One document planned around the phone's certificate, before the
/// phone signs.
struct PreparedDocument {
    /// The options it was asked with.
    options: PhoneSignOptions,
    /// Length of the input file.
    input_len: u64,
    /// SHA-256 of the input file.
    input_sha256: Sha256,
    /// The half-built document the signature completes.
    plan: DocumentPlan,
    /// What the phone is asked to sign for it.
    phone_document: PhoneDocument,
    /// The verifier for the phone's answer.
    verifier: MessageSignatureAlgorithm,
}

/// Sign one or several documents with the paired phone's card.
///
/// Steps:
///
///   1. Check every document's request, as the local path does before
///      it opens a reader.
///   2. Read the phone's certificate ([`RemoteSigner::signature_certificate`])
///      and refuse it unless it is a qualified-signature certificate
///      with a key a document signature can be made with.
///   3. Plan every document around that certificate and take the
///      digest of exactly what its format signs.
///   4. Send every digest in one [`RemoteSigner::sign`]: one consent and
///      one PIN 2 entry on the phone.
///   5. Refuse the whole answer unless it has one signature per
///      document and each verifies against the certificate's key over
///      its own document's signed octets, in order; nothing is written
///      then.
///   6. Finish each document on the local path's finish -- timestamps,
///      long-term material, output -- and report each.
///
/// # Errors
/// The outer error means no document was written: a request refused,
/// a phone refusal, a certificate refused, or an answer that does not
/// verify. Once every signature has verified, each document finishes on
/// its own, and its outcome is the inner result at its position: a
/// timestamp authority that refuses one document leaves the others
/// written.
pub fn sign_on_phone(
    signer: &mut dyn RemoteSigner,
    documents: Vec<PhoneSignOptions>,
) -> Result<Vec<PhoneDocumentOutcome>, SignErrorKind> {
    if documents.is_empty() {
        return Err(SignErrorKind::NoDocuments);
    }
    for options in &documents {
        options.document.validate_signing_policy()?;
        ensure_visible_signature_format(&options.document)?;
    }
    let certificate = PhoneSignatureCertificate::from_phone(
        signer
            .signature_certificate()
            .map_err(SignErrorKind::Phone)?,
    )?;
    let prepared = documents
        .into_iter()
        .map(|options| prepare_document(options, &certificate))
        .collect::<Result<Vec<_>, _>>()?;
    let batch = batch_of(&certificate, &prepared)?;
    let returned = signer.sign(&batch).map_err(SignErrorKind::Phone)?;
    let signatures = verify_returned(&certificate, &prepared, returned)?;
    Ok(prepared
        .into_iter()
        .zip(signatures)
        .map(|(document, signature)| finish_phone_document(document, &certificate, &signature))
        .collect())
}

/// Read one document and plan it around the phone's certificate.
fn prepare_document(
    options: PhoneSignOptions,
    certificate: &PhoneSignatureCertificate,
) -> Result<PreparedDocument, SignErrorKind> {
    let input_bytes = std::fs::read(&options.input).map_err(|source| SignErrorKind::InputRead {
        path: options.input.clone(),
        source,
    })?;
    let input_len: u64 = u64::try_from(input_bytes.len()).unwrap_or(u64::MAX);
    let input_sha256 = Sha256::of(&input_bytes);
    let view = certificate.cert.view();
    let parameters = document_signer(
        &view,
        view.spki.algorithm(),
        SignSlot::Qualified,
        options.document.signing_time,
    )?;
    let objects = load_data_objects(&options.input, &options.document, &input_bytes)?;
    let name = DocumentName::of_files(objects.iter().map(|object| object.name.as_str()))?;
    let plan = document::plan(
        options.document.format,
        objects,
        &parameters,
        &options.document.metadata,
    )
    .map_err(SignErrorKind::Document)?;
    let (algorithm, verifier) = phone_algorithm(parameters.signature_algorithm);
    let digest = parameters.digest_algorithm.digest(plan.to_be_signed());
    let request = SignatureRequest::new(certificate.key_profile, algorithm, digest).map_err(
        |_incompatible| SignErrorKind::PhoneCertificate(PhoneCertificateError::UnsupportedKey),
    )?;
    Ok(PreparedDocument {
        options,
        input_len,
        input_sha256,
        plan,
        phone_document: PhoneDocument { name, request },
        verifier,
    })
}

/// The batch the phone is asked to sign: every prepared document, in
/// order, under the certificate's key profile and the one algorithm the
/// documents share.
fn batch_of(
    certificate: &PhoneSignatureCertificate,
    prepared: &[PreparedDocument],
) -> Result<PhoneSigningBatch, SignErrorKind> {
    // The algorithm is a function of the certificate's key alone
    // (`document_signer`), so every document of the batch names the
    // first one's.
    let Some(first) = prepared.first() else {
        return Err(SignErrorKind::NoDocuments);
    };
    let algorithm = first.phone_document.request.algorithm();
    Ok(PhoneSigningBatch {
        key_profile: certificate.key_profile,
        algorithm,
        documents: prepared
            .iter()
            .map(|document| document.phone_document.clone())
            .collect(),
    })
}

/// The phone's signatures, each verified against the certificate's key
/// over the signed octets of the document at its position.
fn verify_returned(
    certificate: &PhoneSignatureCertificate,
    prepared: &[PreparedDocument],
    returned: Vec<UnvalidatedPhoneSignature>,
) -> Result<Vec<Vec<u8>>, SignErrorKind> {
    if returned.len() != prepared.len() {
        return Err(SignErrorKind::PhoneSignatureCount {
            expected: prepared.len(),
            got: returned.len(),
        });
    }
    let view = certificate.cert.view();
    prepared
        .iter()
        .zip(returned)
        .map(|(document, UnvalidatedPhoneSignature(signature))| {
            verify_against_certificate(
                &view,
                document.verifier,
                document.plan.to_be_signed(),
                &signature,
            )
            .map(|()| signature)
            .map_err(|detail| SignErrorKind::PhoneSignatureInvalid {
                document: document.phone_document.name.clone(),
                detail,
            })
        })
        .collect()
}

/// Finish one document on the shared finish and report it.
fn finish_phone_document(
    document: PreparedDocument,
    certificate: &PhoneSignatureCertificate,
    signature: &[u8],
) -> PhoneDocumentOutcome {
    let PreparedDocument {
        options,
        input_len,
        input_sha256,
        plan,
        ..
    } = document;
    let assembled = finish_document(
        &options.document,
        plan,
        &certificate.cert,
        SignSlot::Qualified,
        signature,
    )?;
    let signature_path = options
        .output
        .write(assembled.best_signature_time, &assembled.bytes)?;
    Ok(SignReport {
        device: SigningDevice::PairedPhone,
        slot: SignSlot::Qualified,
        input_len,
        input_sha256,
        signature_path,
        cert_path: None,
        signature_len: signature.len(),
        timestamps: assembled.timestamps,
        best_signature_time: assembled.best_signature_time,
        output_len: assembled.bytes.len(),
        cert_subject_cn: certificate.cert.view().subject.common_name(),
        pin_retries_after: None,
        local_verify: LocalVerifyOutcome::Ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cades::SigningTime;
    use crate::document::Format;
    use crate::pades::SignatureMetadata;
    use crate::test_util::{TempDir, TestResult, check, check_true};
    use crate::testkit::{
        CertificateSpec, KEY_USAGE_DIGITAL_SIGNATURE, KEY_USAGE_DIGITAL_SIGNATURE_UNUSED,
        KEY_USAGE_NON_REPUDIATION, KEY_USAGE_NON_REPUDIATION_UNUSED, TestCurve, TestKey,
        certificate, day, key_usage, minimal_pdf,
    };
    use crate::verification::{DocumentFile, SignatureOutcome, TrustAnchors, verify};
    use refineid_digest::{SHA256_LEN, SHA384_LEN};

    /// First day of the fixture certificates' validity.
    const NOT_BEFORE: u8 = 1;
    /// Last day of the fixture certificates' validity.
    const NOT_AFTER: u8 = 28;
    /// The day the finished documents are verified.
    const VERIFIED_ON: u8 = 15;
    /// Serial of the phone's signature certificate.
    const SIGNER_SERIAL: u8 = 7;
    /// The claimed signing time's year, inside the validity month.
    const SIGNING_YEAR: u16 = 2026;
    /// Its month.
    const SIGNING_MONTH: u8 = 6;
    /// Its hour.
    const SIGNING_HOUR: u8 = 12;
    /// Documents in the PDF batch.
    const BATCH_SIZE: usize = 3;

    /// The claimed signing time of the `index`th document: one second
    /// apart, so no two documents of a batch sign the same octets.
    fn signing_time(index: usize) -> SigningTime {
        SigningTime {
            year: SIGNING_YEAR,
            month: SIGNING_MONTH,
            day: VERIFIED_ON,
            hour: SIGNING_HOUR,
            minute: 0,
            second: u8::try_from(index).unwrap_or(u8::MAX),
        }
    }

    /// A level-B request for `format`.
    fn request(format: Format, index: usize) -> DocumentRequest {
        DocumentRequest {
            format,
            additional_inputs: Vec::new(),
            signing_time: signing_time(index),
            metadata: SignatureMetadata::default(),
            archive: false,
            long_term: false,
            timestamp_authorities: Vec::new(),
            timestamp_credentials: None,
        }
    }

    /// What the scripted phone answers to `sign`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Answer {
        /// Signs every digest, in order.
        Sign,
        /// Signs every digest and returns them in reverse order.
        Reverse,
        /// Signs every digest and drops the last signature.
        DropLast,
        /// Signs a digest of other octets for every document.
        OtherDigest,
        /// Refuses with this.
        Refuse(PhoneRefusal),
    }

    /// One batch the phone was asked to sign, as the phone saw it.
    struct SeenBatch {
        key_profile: RemoteKeyProfile,
        algorithm: RemoteSignatureAlgorithm,
        names: Vec<String>,
        digests: Vec<Vec<u8>>,
    }

    /// A paired phone whose card holds `key`, certified by
    /// `certificate`, answering as `answer` says.
    struct ScriptedPhone {
        key: TestKey,
        certificate: Vec<u8>,
        answer: Answer,
        batches: Vec<SeenBatch>,
    }

    impl ScriptedPhone {
        /// A phone whose certificate carries `usage` with `unused` bits.
        fn with_usage(key: TestKey, unused: u8, usage: u8, answer: Answer) -> Self {
            let issuer = TestKey::derive(TestCurve::P384, b"phone-signature-issuer");
            let spec = CertificateSpec {
                serial: SIGNER_SERIAL,
                subject: "Test Holder",
                issuer: "Test Signature CA",
                not_before: day(NOT_BEFORE),
                not_after: day(NOT_AFTER),
                extensions: vec![key_usage(unused, usage)],
            };
            let certificate = certificate(&spec, &key, &issuer);
            Self {
                key,
                certificate,
                answer,
                batches: Vec::new(),
            }
        }

        /// A phone with a qualified-signature certificate.
        fn qualified(key: TestKey, answer: Answer) -> Self {
            Self::with_usage(
                key,
                KEY_USAGE_NON_REPUDIATION_UNUSED,
                KEY_USAGE_NON_REPUDIATION,
                answer,
            )
        }

        /// An ECDSA P-384 phone, the newer card's qualified key.
        fn p384(answer: Answer) -> Self {
            Self::qualified(TestKey::derive(TestCurve::P384, b"phone-signature"), answer)
        }
    }

    impl RemoteSigner for ScriptedPhone {
        fn signature_certificate(&mut self) -> Result<UnvalidatedPhoneCertificate, PhoneRefusal> {
            Ok(UnvalidatedPhoneCertificate::from_der(
                self.certificate.clone(),
            ))
        }

        fn sign(
            &mut self,
            batch: &PhoneSigningBatch,
        ) -> Result<Vec<UnvalidatedPhoneSignature>, PhoneRefusal> {
            self.batches.push(SeenBatch {
                key_profile: batch.key_profile(),
                algorithm: batch.algorithm(),
                names: batch
                    .documents()
                    .iter()
                    .map(|document| document.name().as_str().to_owned())
                    .collect(),
                digests: batch
                    .documents()
                    .iter()
                    .map(|document| document.digest().to_vec())
                    .collect(),
            });
            let other = self.key.hash().digest(b"a document the holder never named");
            let mut signatures: Vec<UnvalidatedPhoneSignature> = batch
                .documents()
                .iter()
                .map(|document| {
                    let digest = match self.answer {
                        Answer::OtherDigest => other.as_slice(),
                        Answer::Sign | Answer::Reverse | Answer::DropLast | Answer::Refuse(_) => {
                            document.digest()
                        }
                    };
                    UnvalidatedPhoneSignature::from_bytes(self.key.sign_digest_raw(digest))
                })
                .collect();
            match self.answer {
                Answer::Refuse(refusal) => return Err(refusal),
                Answer::Reverse => signatures.reverse(),
                Answer::DropLast => {
                    signatures.pop();
                }
                Answer::Sign | Answer::OtherDigest => {}
            }
            Ok(signatures)
        }
    }

    /// Verify `path` with the crate's verifier and require one judged
    /// signature, intact and valid.
    fn require_verified(path: &std::path::Path) -> TestResult {
        let bytes = std::fs::read(path)?;
        let report = verify(
            &DocumentFile::from_file(bytes)?,
            &TrustAnchors::new(Vec::new()),
            day(VERIFIED_ON),
        )?;
        check(&report.rows().len(), &1, "one signature")?;
        let Some(row) = report.rows().first() else {
            return Err("no row".into());
        };
        let SignatureOutcome::Judged(judged) = row.outcome() else {
            return Err(format!("{}: signature not judged", path.display()).into());
        };
        check_true(judged.signature_valid(), "signature verifies")?;
        check_true(judged.document_intact(), "document intact")
    }

    /// One document of `format` from `name` holding `content`.
    fn one(
        dir: &TempDir,
        format: Format,
        name: &str,
        content: &[u8],
        index: usize,
    ) -> Result<PhoneSignOptions, Box<dyn core::error::Error>> {
        let input = dir.write(name, content)?;
        Ok(PhoneSignOptions {
            output: SignOutput::At(dir.path().join(format!("signed-{name}"))),
            input,
            document: request(format, index),
        })
    }

    /// The outputs `documents` name.
    fn outputs(documents: &[PhoneSignOptions]) -> Vec<PathBuf> {
        documents
            .iter()
            .map(|document| document.output.path(None))
            .collect()
    }

    #[test]
    fn each_format_is_signed_by_the_phone_and_verifies() -> TestResult {
        let dir = TempDir::new("phone-formats")?;
        for (index, format) in [
            Format::Pades,
            Format::Cades,
            Format::CadesDetached,
            Format::AsicECades,
            Format::AsicEXades,
        ]
        .into_iter()
        .enumerate()
        {
            let (name, content) = if format == Format::Pades {
                (format!("document-{index}.pdf"), minimal_pdf())
            } else {
                (format!("document-{index}.txt"), b"agreed terms".to_vec())
            };
            let mut phone = ScriptedPhone::p384(Answer::Sign);
            let document = one(&dir, format, &name, &content, index)?;
            let output = document.output.path(None);
            let reports = sign_on_phone(&mut phone, vec![document])?;
            check(&phone.batches.len(), &1, "one call to the phone")?;
            let Some(batch) = phone.batches.first() else {
                return Err("no batch".into());
            };
            check(
                &batch.names,
                &vec![name.clone()],
                "the phone shows the file",
            )?;
            check(&batch.key_profile, &RemoteKeyProfile::EcdsaP384, "profile")?;
            check(
                &batch.algorithm,
                &RemoteSignatureAlgorithm::EcdsaSha384,
                "algorithm",
            )?;
            check(
                &batch.digests.iter().map(Vec::len).collect::<Vec<_>>(),
                &vec![SHA384_LEN],
                "a SHA-384 digest",
            )?;
            let [Ok(report)] = reports.as_slice() else {
                return Err(format!("{format:?}: one finished document expected").into());
            };
            check(&report.device, &SigningDevice::PairedPhone, "device")?;
            check(&report.signature_path, &output, "written where asked")?;
            check_true(report.local_verify.is_ok(), "verified before finishing")?;
            if format != Format::CadesDetached {
                require_verified(&output)?;
            }
        }
        Ok(())
    }

    #[test]
    fn an_rsa_phone_is_asked_for_pkcs1_over_sha256() -> TestResult {
        let dir = TempDir::new("phone-rsa")?;
        let mut phone = ScriptedPhone::qualified(TestKey::rsa_2048(), Answer::Sign);
        let document = one(&dir, Format::Pades, "contract.pdf", &minimal_pdf(), 0)?;
        let output = document.output.path(None);
        sign_on_phone(&mut phone, vec![document])?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let Some(batch) = phone.batches.first() else {
            return Err("no batch".into());
        };
        check(&batch.key_profile, &RemoteKeyProfile::Rsa2048, "profile")?;
        check(
            &batch.algorithm,
            &RemoteSignatureAlgorithm::RsaPkcs1Sha256,
            "algorithm",
        )?;
        check(
            &batch.digests.iter().map(Vec::len).collect::<Vec<_>>(),
            &vec![SHA256_LEN],
            "a SHA-256 digest; the card adds the DigestInfo",
        )?;
        require_verified(&output)
    }

    /// `BATCH_SIZE` PDFs, each distinct.
    fn pdf_batch(dir: &TempDir) -> Result<Vec<PhoneSignOptions>, Box<dyn core::error::Error>> {
        (0..BATCH_SIZE)
            .map(|index| {
                one(
                    dir,
                    Format::Pades,
                    &format!("invoice-{index}.pdf"),
                    &minimal_pdf(),
                    index,
                )
            })
            .collect()
    }

    #[test]
    fn a_batch_of_pdfs_is_one_call_in_order() -> TestResult {
        let dir = TempDir::new("phone-batch")?;
        let documents = pdf_batch(&dir)?;
        let expected = outputs(&documents);
        let mut phone = ScriptedPhone::p384(Answer::Sign);
        let reports = sign_on_phone(&mut phone, documents)?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        check(&phone.batches.len(), &1, "one call: one consent, one PIN 2")?;
        let Some(batch) = phone.batches.first() else {
            return Err("no batch".into());
        };
        let names: Vec<String> = (0..BATCH_SIZE)
            .map(|index| format!("invoice-{index}.pdf"))
            .collect();
        check(&batch.names, &names, "names in signing order")?;
        check(
            &reports
                .iter()
                .map(|report| report.signature_path.clone())
                .collect::<Vec<_>>(),
            &expected,
            "reports in signing order",
        )?;
        for output in &expected {
            require_verified(output)?;
        }
        Ok(())
    }

    #[test]
    fn a_container_of_several_files_is_one_document() -> TestResult {
        let dir = TempDir::new("phone-container")?;
        let second = dir.write("annex.txt", b"annex")?;
        let mut document = one(&dir, Format::AsicEXades, "letter.txt", b"letter", 0)?;
        document.document.additional_inputs.push(second);
        let output = document.output.path(None);
        let mut phone = ScriptedPhone::p384(Answer::Sign);
        sign_on_phone(&mut phone, vec![document])?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let Some(batch) = phone.batches.first() else {
            return Err("no batch".into());
        };
        check(
            &batch.names,
            &vec!["letter.txt, annex.txt".to_owned()],
            "one name for the container",
        )?;
        check(&batch.digests.len(), &1, "one digest for the container")?;
        require_verified(&output)
    }

    /// Require that none of `paths` exists.
    fn require_nothing_written(paths: &[PathBuf]) -> TestResult {
        check_true(
            paths.iter().all(|path| !path.exists()),
            "nothing is written",
        )
    }

    #[test]
    fn a_declined_batch_writes_nothing() -> TestResult {
        let dir = TempDir::new("phone-declined")?;
        let documents = pdf_batch(&dir)?;
        let expected = outputs(&documents);
        let mut phone = ScriptedPhone::p384(Answer::Refuse(PhoneRefusal::Declined));
        check_true(
            matches!(
                sign_on_phone(&mut phone, documents),
                Err(SignErrorKind::Phone(PhoneRefusal::Declined))
            ),
            "the refusal is reported as the phone's",
        )?;
        require_nothing_written(&expected)
    }

    #[test]
    fn a_certificate_without_non_repudiation_is_refused_before_signing() -> TestResult {
        let dir = TempDir::new("phone-auth-cert")?;
        let documents = pdf_batch(&dir)?;
        let expected = outputs(&documents);
        let mut phone = ScriptedPhone::with_usage(
            TestKey::derive(TestCurve::P384, b"phone-authentication"),
            KEY_USAGE_DIGITAL_SIGNATURE_UNUSED,
            KEY_USAGE_DIGITAL_SIGNATURE,
            Answer::Sign,
        );
        check_true(
            matches!(
                sign_on_phone(&mut phone, documents),
                Err(SignErrorKind::PhoneCertificate(
                    PhoneCertificateError::NotQualifiedSignature
                ))
            ),
            "the authentication certificate is refused",
        )?;
        check_true(phone.batches.is_empty(), "no digest went to the phone")?;
        require_nothing_written(&expected)
    }

    #[test]
    fn a_signature_over_another_digest_writes_nothing() -> TestResult {
        let dir = TempDir::new("phone-other-digest")?;
        let documents = pdf_batch(&dir)?;
        let expected = outputs(&documents);
        let mut phone = ScriptedPhone::p384(Answer::OtherDigest);
        check_true(
            matches!(
                sign_on_phone(&mut phone, documents),
                Err(SignErrorKind::PhoneSignatureInvalid { .. })
            ),
            "a signature over other octets is refused",
        )?;
        require_nothing_written(&expected)
    }

    #[test]
    fn a_signature_by_another_key_writes_nothing() -> TestResult {
        let dir = TempDir::new("phone-other-key")?;
        let documents = pdf_batch(&dir)?;
        let expected = outputs(&documents);
        let mut phone = ScriptedPhone::p384(Answer::Sign);
        phone.key = TestKey::derive(TestCurve::P384, b"a key the certificate does not name");
        check_true(
            matches!(
                sign_on_phone(&mut phone, documents),
                Err(SignErrorKind::PhoneSignatureInvalid { .. })
            ),
            "a signature by a key the certificate does not certify is refused",
        )?;
        require_nothing_written(&expected)
    }

    #[test]
    fn a_reordered_batch_writes_nothing() -> TestResult {
        let dir = TempDir::new("phone-reordered")?;
        let documents = pdf_batch(&dir)?;
        let expected = outputs(&documents);
        let mut phone = ScriptedPhone::p384(Answer::Reverse);
        check_true(
            matches!(
                sign_on_phone(&mut phone, documents),
                Err(SignErrorKind::PhoneSignatureInvalid { .. })
            ),
            "a signature at another document's position is refused",
        )?;
        require_nothing_written(&expected)
    }

    #[test]
    fn a_short_answer_writes_nothing() -> TestResult {
        let dir = TempDir::new("phone-short")?;
        let documents = pdf_batch(&dir)?;
        let expected = outputs(&documents);
        let mut phone = ScriptedPhone::p384(Answer::DropLast);
        let result = sign_on_phone(&mut phone, documents);
        let Err(SignErrorKind::PhoneSignatureCount {
            expected: asked,
            got,
        }) = result
        else {
            return Err("a count mismatch is refused".into());
        };
        check(&asked, &BATCH_SIZE, "documents asked")?;
        check(&got, &BATCH_SIZE.saturating_sub(1), "signatures returned")?;
        require_nothing_written(&expected)
    }

    #[test]
    fn an_empty_batch_is_refused() -> TestResult {
        let mut phone = ScriptedPhone::p384(Answer::Sign);
        check_true(
            matches!(
                sign_on_phone(&mut phone, Vec::new()),
                Err(SignErrorKind::NoDocuments)
            ),
            "nothing to sign",
        )?;
        check_true(phone.batches.is_empty(), "no digest went to the phone")
    }

    #[test]
    fn document_names_follow_the_rapp_bound() -> TestResult {
        let at_bound = "n".repeat(MAX_DOCUMENT_NAME_BYTES);
        check(
            &DocumentName::of_files([at_bound.as_str()].into_iter())?.as_str(),
            &at_bound.as_str(),
            "a name at the bound",
        )?;
        let over = "n".repeat(MAX_DOCUMENT_NAME_BYTES.saturating_add(1));
        check_true(
            matches!(
                DocumentName::of_files([over.as_str()].into_iter()),
                Err(SignErrorKind::DocumentNameLength)
            ),
            "a name over the bound",
        )?;
        check_true(
            matches!(
                DocumentName::of_files(core::iter::empty()),
                Err(SignErrorKind::DocumentNameLength)
            ),
            "an empty name",
        )
    }
}
