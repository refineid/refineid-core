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

//! The independent validation gate: every format this crate writes is
//! signed the way a release build signs it, at the long-term level the
//! owner's rule requires, and then judged by the EU DSS library, which
//! is not this crate's code and does not share its mistakes.
//!
//! A signature passes only when DSS reports the format's `B-LTA` level
//! with indication `TOTAL_PASSED`, and this crate's own verifier agrees:
//! valid, with an anchored signature timestamp and an anchored archive
//! timestamp over it.
//!
//! Everything runs offline. The signer is a scripted phone holding a
//! synthetic card key; a synthetic PKI (root, issuing CA, timestamp
//! authority, OCSP responder, CRL) answers through an in-memory HTTP
//! transport; DSS trusts only the synthetic root. `scripts/dss-gate.sh`
//! fetches and checks the pinned DSS release once, then runs this file
//! with `REFINEID_DSS_JAVA` and `REFINEID_DSS_CLASSPATH` set; without
//! them every test here fails rather than passes unexamined.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use refineid_cms::oid::known;
use refineid_cms::x509::{DateTime, OwnedCert};
use refineid_doc_sign::cades::SigningTime;
use refineid_doc_sign::digest::Sha1;
use refineid_doc_sign::document::Format;
use refineid_doc_sign::http::{HttpError, HttpTransport, set_http_transport};
use refineid_doc_sign::now_date_time;
use refineid_doc_sign::oids::{AUTHORITY_KEY_IDENTIFIER, SUBJECT_KEY_IDENTIFIER};
use refineid_doc_sign::pades::SignatureMetadata;
use refineid_doc_sign::remote::{
    PhoneRefusal, PhoneSignOptions, PhoneSigningBatch, RemoteSigner, UnvalidatedPhoneCertificate,
    UnvalidatedPhoneSignature, sign_on_phone,
};
use refineid_doc_sign::service::{DocumentRequest, SignOutput, SigningBuild};
use refineid_doc_sign::testkit::{
    CONTEXT_0_PRIMITIVE, CertIdAlgorithm, CertificateSpec, CmsParts, INTEGER,
    KEY_USAGE_NON_REPUDIATION, KEY_USAGE_NON_REPUDIATION_UNUSED, OBJECT_IDENTIFIER, OCTET_STRING,
    OcspSpec, ResponderName, SEQUENCE, TEST_POLICY, TST_INFO_VERSION, TestCurve, TestKey,
    attribute_set, ca_extensions, certificate, cms, content_attributes, crl,
    crl_distribution_points, extension, generalized_time, key_usage, minimal_pdf, ocsp_response,
    positive_integer, signing_certificate_v2, timestamping_extensions, tlv,
};
use refineid_doc_sign::uri::Uri;
use refineid_doc_sign::verification::{
    AnchorRole, DocumentFile, GrantedPeriod, SignatureOutcome, TimestampReport, TrustAnchor,
    TrustAnchors, verify,
};

type TestResult = Result<(), Box<dyn core::error::Error>>;

/// Where the synthetic PKI publishes. The name is under `.test`
/// (RFC 6761 sec.6.2), so no resolver anywhere answers for it.
const PKI_HOST: &str = "pki.dss-gate.test";
/// The issuing CA's certificate, named by the signer's CA Issuers.
const ISSUER_URL: &str = "http://pki.dss-gate.test/issuing-ca.der";
/// The issuing CA's OCSP responder, named by the signer's AIA.
const OCSP_URL: &str = "http://pki.dss-gate.test/ocsp";
/// The root's CRL, named by every certificate the root issues.
const ROOT_CRL_URL: &str = "http://pki.dss-gate.test/root.crl";
/// The synthetic timestamp authority, configured as a request's TSA.
const TSA_URL: &str = "http://pki.dss-gate.test/tsa";

/// The address [`PKI_HOST`] resolves to. Never contacted: the
/// transport answers in memory. It must be a public unicast address,
/// because the destination guard refuses every other kind for a URL a
/// certificate published.
const UNCONTACTED_PUBLIC_ADDRESS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// Common names of the synthetic PKI.
const ROOT_NAME: &str = "DSS Gate Test Root CA";
const ISSUING_NAME: &str = "DSS Gate Test Signature CA";
const TSA_NAME: &str = "DSS Gate Test Timestamp Authority";
const HOLDER_NAME: &str = "DSS Gate Test Holder";

/// Certificate serials, each unique under its issuer.
const ROOT_SERIAL: u8 = 1;
const ISSUING_SERIAL: u8 = 2;
const TSA_SERIAL: u8 = 3;
const HOLDER_SERIAL: u8 = 4;

/// How far certificate validity reaches either side of now.
const VALIDITY_MARGIN: Duration = Duration::from_hours(24 * 365);
/// How long a CRL or an OCSP answer stays current.
const STATUS_LIFETIME: Duration = Duration::from_hours(24);
/// How long before a fetch the root issued its current CRL: a CRL is
/// published on a schedule, not minted per request.
const CRL_AGE: Duration = Duration::from_hours(1);

/// `PKIStatus` granted (RFC 3161 sec.2.4.2).
const PKI_STATUS_GRANTED: u8 = 0;
/// `id-pkix-ocsp-nonce` (RFC 6960 sec.4.4.1).
const OCSP_NONCE_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
/// `requestExtensions [2] EXPLICIT` of a `TBSRequest` (RFC 6960
/// sec.4.1.1).
const REQUEST_EXTENSIONS: u8 = 0xA2;
/// The DER `TLV` short-form length bound and the long-form marker
/// (X.690 sec.8.1.3).
const LONG_FORM: u8 = 0x80;

/// Content of the non-PDF documents.
const TEXT: &[u8] = b"terms agreed under the DSS gate";

/// Environment variable naming the `java` launcher.
const JAVA_VARIABLE: &str = "REFINEID_DSS_JAVA";
/// Environment variable naming the DSS class path, validator included.
const CLASSPATH_VARIABLE: &str = "REFINEID_DSS_CLASSPATH";
/// The validator's main class (`tools/dss-gate/DssGate.java`).
const VALIDATOR_CLASS: &str = "DssGate";

/// DSS's indication for a signature that passed every check
/// (ETSI EN 319 102-1 clause 5.1.3).
const TOTAL_PASSED: &str = "TOTAL_PASSED";
/// DSS's container type for an `ASiC-E` (ETSI EN 319 162-1).
const ASIC_E: &str = "ASiC-E";

/// The synthetic PKI: one root over an issuing CA and a timestamp
/// authority; the holder's certificate under the issuing CA.
struct Pki {
    root_key: TestKey,
    root: Vec<u8>,
    issuing_key: TestKey,
    issuing: Vec<u8>,
    tsa_key: TestKey,
    tsa: Vec<u8>,
    holder_key: TestKey,
    holder: Vec<u8>,
    token_serial: AtomicU8,
}

/// `now` moved by `offset`, forward or back.
fn shifted(now: DateTime, offset: Duration, forward: bool) -> DateTime {
    let base = now.unix_duration();
    let moved = if forward {
        base.saturating_add(offset)
    } else {
        base.saturating_sub(offset)
    };
    DateTime::from_unix_duration(moved).unwrap_or(now)
}

/// An `authorityInfoAccess` naming `ocsp` as the OCSP responder and
/// `issuer` as the CA Issuers location (RFC 5280 sec.4.2.2.1).
fn authority_info_access(ocsp: &str, issuer: &str) -> Vec<u8> {
    /// `uniformResourceIdentifier [6] IA5String`, implicitly tagged.
    const GENERAL_NAME_URI: u8 = 0x86;
    let mut descriptions = Vec::new();
    for (method, url) in [(known::AD_OCSP, ocsp), (known::AD_CA_ISSUERS, issuer)] {
        let mut description = tlv(OBJECT_IDENTIFIER, method.as_bytes());
        description.extend_from_slice(&tlv(GENERAL_NAME_URI, url.as_bytes()));
        descriptions.extend_from_slice(&tlv(SEQUENCE, description));
    }
    extension(
        known::AUTHORITY_INFO_ACCESS,
        false,
        &tlv(SEQUENCE, descriptions),
    )
}

/// The key identifier of `key`: the SHA-1 of its subject public key
/// bits (RFC 5280 sec.4.2.1.2, method 1).
fn key_identifier(key: &TestKey) -> Vec<u8> {
    let spki = key.spki();
    refineid_cms::x509::SpkiDer::try_from(spki.as_slice()).map_or_else(
        |_| Vec::new(),
        |typed| {
            Sha1::of(typed.subject_public_key_bits())
                .as_bytes()
                .to_vec()
        },
    )
}

/// The `subjectKeyIdentifier` of `subject` and, when it has an issuer
/// above it, the `authorityKeyIdentifier` naming `issuer` (RFC 5280
/// sec.4.2.1.1, sec.4.2.1.2), which every CA certificate carries.
fn key_identifiers(subject: &TestKey, issuer: Option<&TestKey>) -> Vec<Vec<u8>> {
    let mut extensions = vec![extension(
        SUBJECT_KEY_IDENTIFIER,
        false,
        &tlv(OCTET_STRING, key_identifier(subject)),
    )];
    if let Some(issuer) = issuer {
        extensions.push(extension(
            AUTHORITY_KEY_IDENTIFIER,
            false,
            &tlv(SEQUENCE, tlv(CONTEXT_0_PRIMITIVE, key_identifier(issuer))),
        ));
    }
    extensions
}

impl Pki {
    fn new() -> Self {
        let now = now_date_time();
        let not_before = shifted(now, VALIDITY_MARGIN, false);
        let not_after = shifted(now, VALIDITY_MARGIN, true);
        let root_key = TestKey::derive(TestCurve::P384, b"dss-gate-root");
        let issuing_key = TestKey::derive(TestCurve::P384, b"dss-gate-issuing");
        let tsa_key = TestKey::derive(TestCurve::P256, b"dss-gate-tsa");
        let holder_key = TestKey::derive(TestCurve::P384, b"dss-gate-holder");
        let spec = |serial, subject, issuer, extensions| CertificateSpec {
            serial,
            subject,
            issuer,
            not_before,
            not_after,
            extensions,
        };
        let mut root_extensions = ca_extensions();
        root_extensions.extend(key_identifiers(&root_key, None));
        let root = certificate(
            &spec(ROOT_SERIAL, ROOT_NAME, ROOT_NAME, root_extensions),
            &root_key,
            &root_key,
        );
        let mut issuing_extensions = ca_extensions();
        issuing_extensions.extend(key_identifiers(&issuing_key, Some(&root_key)));
        issuing_extensions.push(crl_distribution_points(&[ROOT_CRL_URL]));
        let issuing = certificate(
            &spec(ISSUING_SERIAL, ISSUING_NAME, ROOT_NAME, issuing_extensions),
            &issuing_key,
            &root_key,
        );
        let mut tsa_extensions = timestamping_extensions();
        tsa_extensions.extend(key_identifiers(&tsa_key, Some(&root_key)));
        tsa_extensions.push(crl_distribution_points(&[ROOT_CRL_URL]));
        let tsa = certificate(
            &spec(TSA_SERIAL, TSA_NAME, ROOT_NAME, tsa_extensions),
            &tsa_key,
            &root_key,
        );
        let mut holder_extensions = vec![
            key_usage(KEY_USAGE_NON_REPUDIATION_UNUSED, KEY_USAGE_NON_REPUDIATION),
            authority_info_access(OCSP_URL, ISSUER_URL),
        ];
        holder_extensions.extend(key_identifiers(&holder_key, Some(&issuing_key)));
        let holder = certificate(
            &spec(HOLDER_SERIAL, HOLDER_NAME, ISSUING_NAME, holder_extensions),
            &holder_key,
            &issuing_key,
        );
        Self {
            root_key,
            root,
            issuing_key,
            issuing,
            tsa_key,
            tsa,
            holder_key,
            holder,
            token_serial: AtomicU8::new(1),
        }
    }

    /// The root's current CRL, issued [`CRL_AGE`] ago, revoking
    /// nothing.
    fn root_crl(&self) -> Vec<u8> {
        let now = now_date_time();
        let issued = shifted(now, CRL_AGE, false);
        crl(
            ROOT_NAME,
            &self.root_key,
            issued,
            Some(shifted(now, STATUS_LIFETIME, true)),
            &[],
            issued,
        )
    }

    /// The issuing CA's answer to `request`: the holder is good, the
    /// request's nonce echoed.
    fn ocsp(&self, request: &[u8]) -> Result<Vec<u8>, HttpError> {
        let issuer = OwnedCert::from_der(&self.issuing).map_err(refused)?;
        let now = now_date_time();
        let nonce = ocsp_nonce_extension(request).ok_or_else(|| refused("no nonce"))?;
        Ok(ocsp_response(&OcspSpec {
            responder_key: &self.issuing_key,
            responder: ResponderName::ByName(ISSUING_NAME),
            issuer: &issuer,
            serial: HOLDER_SERIAL,
            revoked: None,
            revocation_reason: None,
            produced_at: now,
            this_update: now,
            next_update: Some(shifted(now, STATUS_LIFETIME, true)),
            embedded: Vec::new(),
            cert_id: CertIdAlgorithm::Sha1,
            response_extensions: vec![nonce],
        }))
    }

    /// The timestamp authority's granted answer to `request`: a token
    /// over the request's imprint, echoing its nonce, carrying the
    /// authority's certificate and the root above it.
    fn timestamp(&self, request: &[u8]) -> Result<Vec<u8>, HttpError> {
        let fields = children(content(request).ok_or_else(|| refused("request"))?)
            .ok_or_else(|| refused("request fields"))?;
        let [_version, imprint, rest @ ..] = fields.as_slice() else {
            return Err(refused("request shape"));
        };
        let mut tst_info = tlv(INTEGER, [TST_INFO_VERSION]);
        tst_info.extend_from_slice(&tlv(OBJECT_IDENTIFIER, TEST_POLICY.as_bytes()));
        tst_info.extend_from_slice(imprint);
        let serial = self.token_serial.fetch_add(1, Ordering::Relaxed);
        tst_info.extend_from_slice(&positive_integer(&[serial]));
        tst_info.extend_from_slice(&generalized_time(now_date_time()));
        if let Some(nonce) = rest.iter().find(|field| field.first() == Some(&INTEGER)) {
            tst_info.extend_from_slice(nonce);
        }
        let tst_info = tlv(SEQUENCE, tst_info);
        let mut attributes = content_attributes(known::TST_INFO, self.tsa_key.hash(), &tst_info);
        attributes.push(signing_certificate_v2(&self.tsa));
        let mut parts = CmsParts::attached(&self.tsa_key, &self.tsa, &tst_info);
        parts.econtent_type = known::TST_INFO;
        parts.signed_attributes = Some(attribute_set(&attributes));
        parts.certificates.push(self.root.clone());
        let token = cms(&parts);
        let mut response = tlv(SEQUENCE, tlv(INTEGER, [PKI_STATUS_GRANTED]));
        response.extend_from_slice(&token);
        Ok(tlv(SEQUENCE, response))
    }
}

/// An answer the synthetic PKI cannot give.
fn refused(why: impl core::fmt::Display) -> HttpError {
    HttpError::Io(io::Error::other(format!("synthetic PKI: {why}")))
}

/// The value of the DER TLV `der` starts with.
fn content(der: &[u8]) -> Option<&[u8]> {
    let (header, length) = header(der)?;
    der.get(header..header.checked_add(length)?)
}

/// The header length and value length of the TLV `der` starts with.
fn header(der: &[u8]) -> Option<(usize, usize)> {
    let first = *der.get(1)?;
    if first < LONG_FORM {
        return Some((2, usize::from(first)));
    }
    let count = usize::from(first & !LONG_FORM);
    let bytes = der.get(2..2_usize.checked_add(count)?)?;
    let length = bytes.iter().try_fold(0_usize, |length, byte| {
        length.checked_mul(256)?.checked_add(usize::from(*byte))
    })?;
    Some((2_usize.checked_add(count)?, length))
}

/// The complete TLVs inside `value`, in order.
fn children(mut value: &[u8]) -> Option<Vec<&[u8]>> {
    let mut found = Vec::new();
    while !value.is_empty() {
        let (header, length) = header(value)?;
        let end = header.checked_add(length)?;
        found.push(value.get(..end)?);
        value = value.get(end..)?;
    }
    Some(found)
}

/// The nonce `Extension` of an `OCSPRequest`, whole, for the response
/// to echo (RFC 6960 sec.4.4.1).
fn ocsp_nonce_extension(request: &[u8]) -> Option<Vec<u8>> {
    let tbs = children(content(request)?)?.into_iter().next()?;
    let extensions = children(content(tbs)?)?
        .into_iter()
        .find(|field| field.first() == Some(&REQUEST_EXTENSIONS))?;
    let list = content(content(extensions)?)?;
    let nonce_oid = tlv(OBJECT_IDENTIFIER, OCSP_NONCE_OID.as_bytes());
    children(list)?
        .into_iter()
        .find(|extension| content(extension).is_some_and(|body| body.starts_with(&nonce_oid)))
        .map(<[u8]>::to_vec)
}

/// The synthetic PKI, built once for every test of this binary, and
/// the in-memory transport registered for it.
fn pki() -> &'static Pki {
    static PKI: OnceLock<&'static Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let pki: &'static Pki = Box::leak(Box::new(Pki::new()));
        set_http_transport(Box::new(SyntheticNetwork(pki)));
        pki
    })
}

/// Every URL of the synthetic PKI, answered in memory.
struct SyntheticNetwork(&'static Pki);

impl HttpTransport for SyntheticNetwork {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, HttpError> {
        if host == PKI_HOST {
            Ok(vec![SocketAddr::new(
                IpAddr::V4(UNCONTACTED_PUBLIC_ADDRESS),
                port,
            )])
        } else {
            Err(refused(format!("unknown host {host}")))
        }
    }

    fn get(
        &self,
        url: &Uri,
        _addresses: &[SocketAddr],
        _max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        match url.to_string().as_str() {
            ISSUER_URL => Ok(self.0.issuing.clone()),
            ROOT_CRL_URL => Ok(self.0.root_crl()),
            other => Err(refused(format!("GET {other}"))),
        }
    }

    fn post(
        &self,
        url: &Uri,
        _addresses: &[SocketAddr],
        _content_type: &str,
        body: &[u8],
        _max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        match url.to_string().as_str() {
            OCSP_URL => self.0.ocsp(body),
            other => Err(refused(format!("POST {other}"))),
        }
    }

    fn post_authority(
        &self,
        url: &Uri,
        _content_type: &str,
        body: &[u8],
        _max_bytes: usize,
        _auth_header: Option<&str>,
    ) -> Result<Vec<u8>, HttpError> {
        match url.to_string().as_str() {
            TSA_URL => self.0.timestamp(body),
            other => Err(refused(format!("POST {other}"))),
        }
    }
}

/// A paired phone whose card holds the synthetic holder's key.
struct SyntheticPhone(&'static Pki);

impl RemoteSigner for SyntheticPhone {
    fn signature_certificate(&mut self) -> Result<UnvalidatedPhoneCertificate, PhoneRefusal> {
        Ok(UnvalidatedPhoneCertificate::from_der(self.0.holder.clone()))
    }

    fn sign(
        &mut self,
        batch: &PhoneSigningBatch,
    ) -> Result<Vec<UnvalidatedPhoneSignature>, PhoneRefusal> {
        Ok(batch
            .documents()
            .iter()
            .map(|document| {
                UnvalidatedPhoneSignature::from_bytes(
                    self.0.holder_key.sign_digest_raw(document.digest()),
                )
            })
            .collect())
    }
}

/// A scratch directory for one format, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> io::Result<Self> {
        let path =
            std::env::temp_dir().join(format!("refineid-dss-gate-{label}-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let path = self.0.join(name);
        std::fs::write(&path, bytes)?;
        Ok(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.0);
    }
}

/// What DSS concluded about the one signature of a document.
#[derive(Debug)]
struct DssVerdict {
    format: String,
    indication: String,
    subindication: String,
    container: String,
    transcript: String,
}

/// Run the DSS validator over `signed`, `detached` being the original
/// a detached signature covers.
fn dss(signed: &Path, detached: Option<&Path>, root: &Path) -> Result<DssVerdict, String> {
    let java = std::env::var(JAVA_VARIABLE).map_err(|_| {
        format!("{JAVA_VARIABLE} is not set: run the gate through scripts/dss-gate.sh")
    })?;
    let classpath = std::env::var(CLASSPATH_VARIABLE).map_err(|_| {
        format!("{CLASSPATH_VARIABLE} is not set: run the gate through scripts/dss-gate.sh")
    })?;
    let mut command = Command::new(java);
    command
        .arg("-cp")
        .arg(classpath)
        .arg(VALIDATOR_CLASS)
        .arg("--anchor")
        .arg(root);
    if let Some(original) = detached {
        command.arg("--detached").arg(original);
    }
    let output = command
        .arg(signed)
        .output()
        .map_err(|error| format!("cannot run DSS: {error}"))?;
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() {
        return Err(format!("DSS failed ({}):\n{transcript}", output.status));
    }
    let signatures: Vec<&str> = transcript
        .lines()
        .filter(|line| line.starts_with("signature "))
        .collect();
    let [line] = signatures.as_slice() else {
        return Err(format!("DSS found no single signature:\n{transcript}"));
    };
    let field = |name: &str| {
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(name))
            .unwrap_or_default()
            .to_owned()
    };
    let container = transcript
        .lines()
        .find_map(|line| line.strip_prefix("container="))
        .unwrap_or_default()
        .to_owned();
    Ok(DssVerdict {
        format: field("format="),
        indication: field("indication="),
        subindication: field("subindication="),
        container,
        transcript,
    })
}

/// The synthetic root as this crate's verifier trusts it: for issuing
/// signers' certificates and timestamp authorities' alike.
fn anchors(pki: &Pki) -> Result<TrustAnchors, Box<dyn core::error::Error>> {
    let root = || OwnedCert::from_der(&pki.root);
    Ok(TrustAnchors::new(vec![
        TrustAnchor::new(
            root()?,
            AnchorRole::CertificateIssuing,
            vec![GrantedPeriod::unbounded()],
        )
        .map_err(|error| format!("{error:?}"))?,
        TrustAnchor::new(
            root()?,
            AnchorRole::TimeStamping,
            vec![GrantedPeriod::unbounded()],
        )
        .map_err(|error| format!("{error:?}"))?,
    ]))
}

/// Whether `report` proves a time from an anchored authority.
const fn anchored(report: &TimestampReport) -> bool {
    matches!(report, TimestampReport::Anchored { .. })
}

/// This crate's verifier on `signed`: one valid signature, its own
/// timestamp anchored, and an anchored archive timestamp over it (a
/// `PAdES` document timestamp covering it, or the `CAdES` or `XAdES`
/// archive timestamp).
fn own_verifier_agrees(pki: &Pki, signed: &[u8]) -> Result<(), String> {
    let anchors = anchors(pki).map_err(|error| error.to_string())?;
    let file = DocumentFile::from_file(signed.to_vec()).map_err(|error| error.to_string())?;
    let report = verify(&file, &anchors, now_date_time()).map_err(|error| error.to_string())?;
    let [row] = report.rows() else {
        return Err(format!("{} signatures, one expected", report.rows().len()));
    };
    let SignatureOutcome::Judged(judged) = row.outcome() else {
        return Err("signature not judged".to_owned());
    };
    if !judged.is_valid() {
        return Err(format!("verdict {:?}", judged.verdict()));
    }
    if !judged.timestamps().iter().any(anchored) {
        return Err("no anchored signature timestamp".to_owned());
    }
    let archived = judged
        .archive_timestamps()
        .iter()
        .any(|archive| anchored(archive.timestamp()))
        || judged
            .covering_document_timestamps()
            .iter()
            .any(|document| anchored(document.timestamp()));
    if archived {
        Ok(())
    } else {
        Err(
            "no anchored archive timestamp: it judges CAdES and XAdES archive \
             timestamps and PDF document timestamps, and passes over an ASiC archive \
             manifest and its token unjudged"
                .to_owned(),
        )
    }
}

/// Sign one document of `format` as a release build does, asking for
/// the long-term archive level, judge it with DSS, and require
/// `expected` with `TOTAL_PASSED`; then require this crate's verifier
/// to agree.
fn gate(format: Format, label: &str, expected: &str, container: Option<&str>) -> TestResult {
    let pki = pki();
    let scratch = Scratch::new(label)?;
    let (name, content) = if format == Format::Pades {
        ("document.pdf", minimal_pdf())
    } else {
        ("document.txt", TEXT.to_vec())
    };
    let input = scratch.write(name, &content)?;
    let output = scratch.0.join(format!("signed-{label}"));
    let root = scratch.write("root.der", &pki.root)?;
    let document = PhoneSignOptions {
        input: input.clone(),
        output: SignOutput::At(output.clone()),
        document: DocumentRequest {
            format,
            additional_inputs: Vec::new(),
            signing_time: SigningTime::now(),
            metadata: SignatureMetadata::default(),
            archive: true,
            long_term: true,
            signer_anchors: vec![pki.root.clone()],
            timestamp_authorities: vec![TSA_URL.to_owned()],
            timestamp_credentials: None,
            build: SigningBuild::Release,
        },
    };
    let outcomes = sign_on_phone(&mut SyntheticPhone(pki), vec![document])
        .map_err(|error| format!("{label}: release build refused the B-LTA request: {error}"))?;
    let [outcome] = outcomes.as_slice() else {
        return Err(format!("{label}: {} outcomes, one expected", outcomes.len()).into());
    };
    if let Err(error) = outcome {
        return Err(format!("{label}: release build refused the B-LTA request: {error}").into());
    }

    let detached = (format == Format::CadesDetached).then_some(input.as_path());
    let verdict = dss(&output, detached, &root).map_err(|error| format!("{label}: {error}"))?;
    let reached = verdict.format == expected
        && verdict.indication == TOTAL_PASSED
        && container.is_none_or(|kind| verdict.container == kind);
    if !reached {
        return Err(format!(
            "{label}: DSS reports {} {} {} in container {}, required {expected} {TOTAL_PASSED}{}\n{}",
            verdict.format,
            verdict.indication,
            verdict.subindication,
            verdict.container,
            container.map_or_else(String::new, |kind| format!(" in {kind}")),
            verdict.transcript
        )
        .into());
    }

    if format != Format::CadesDetached {
        let signed = std::fs::read(&output)?;
        own_verifier_agrees(pki, &signed)
            .map_err(|error| format!("{label}: DSS passed it, but our verifier: {error}"))?;
    }
    Ok(())
}

#[test]
fn pades_reaches_b_lta_in_dss() -> TestResult {
    gate(Format::Pades, "pades.pdf", "PAdES-BASELINE-LTA", None)
}

#[test]
fn asic_e_with_xades_reaches_b_lta_in_dss() -> TestResult {
    gate(
        Format::AsicEXades,
        "asic-e-xades.asice",
        "XAdES-BASELINE-LTA",
        Some(ASIC_E),
    )
}

#[test]
fn asic_e_with_cades_reaches_b_lta_in_dss() -> TestResult {
    gate(
        Format::AsicECades,
        "asic-e-cades.asice",
        "CAdES-BASELINE-LTA",
        Some(ASIC_E),
    )
}

#[test]
fn cades_attached_reaches_b_lta_in_dss() -> TestResult {
    gate(Format::Cades, "cades.p7m", "CAdES-BASELINE-LTA", None)
}

#[test]
fn cades_detached_reaches_b_lta_in_dss() -> TestResult {
    gate(
        Format::CadesDetached,
        "cades.p7s",
        "CAdES-BASELINE-LTA",
        None,
    )
}
