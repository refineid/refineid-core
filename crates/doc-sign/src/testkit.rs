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

//! Synthetic keys, certificates, CRLs, OCSP responses, timestamp
//! tokens and PDFs for the document verifier's tests.
//!
//! Compiled for this crate's tests and behind the `testkit` feature.
//! The keys, certificates and CMS assembly come from
//! [`refineid_cms::testkit`], re-exported here; this module adds the
//! revocation, timestamp and PDF structures on top. Every byte is
//! assembled from named tag and field constants, every instant comes
//! from [`day`], and nothing here is a real identity.

pub use refineid_cms::testkit::{
    BIT_STRING, BOOLEAN, CONTEXT_0, CONTEXT_0_PRIMITIVE, CONTEXT_1, CONTEXT_2, CONTEXT_3,
    CertificateSpec, CmsParts, DER_TRUE, ENUMERATED, GENERALIZED_TIME, INTEGER, INTEGER_SIGN_BIT,
    INTEGER_SIGN_PAD, KEY_USAGE_CA, KEY_USAGE_CA_UNUSED, KEY_USAGE_CERT_SIGN,
    KEY_USAGE_CERT_SIGN_UNUSED, KEY_USAGE_DIGITAL_SIGNATURE, KEY_USAGE_DIGITAL_SIGNATURE_UNUSED,
    KEY_USAGE_NON_REPUDIATION, KEY_USAGE_NON_REPUDIATION_UNUSED, NO_UNUSED_BITS, NULL,
    OBJECT_IDENTIFIER, OCTET_STRING, PRINTABLE_STRING, PSS_SALT_LEN, SEQUENCE, SET,
    SIGNED_DATA_VERSION, SIGNER_INFO_VERSION, TestCurve, TestKey, TestKeyKind, UTC_TIME,
    UTF8_STRING, X509_VERSION_3, attribute, attribute_set, bit_string, ca_basic_constraints,
    ca_extensions, certificate, certificate_named, cms, content_attributes, day,
    digest_algorithm_identifier, extended_key_usage, extension, generalized_time, key_usage, name,
    name_of, positive_integer, signed, signed_body, tbs_certificate, tbs_certificate_named,
    timestamping_extensions, tlv, utc_time,
};

use crate::cades::{DigestAlgorithm, SignatureAlgorithm};
use crate::crl::CrlReason;
use crate::ocsp::{IssuerKeyHash, IssuerNameHash};
use refineid_cms::oid::{Oid, known};
use refineid_cms::x509::{DateTime, OwnedCert};

/// CRL `Version` v2, encoded as INTEGER 1 (RFC 5280 sec.5.1).
pub const CRL_VERSION_2: u8 = 0x01;
/// `OCSPResponseStatus` successful (RFC 6960 sec.4.2.1).
pub const OCSP_SUCCESSFUL: u8 = 0x00;
/// `TSTInfo` version 1 (RFC 3161 sec.2.4.2).
pub const TST_INFO_VERSION: u8 = 0x01;
/// `TSTInfo.serialNumber` of every fixture token.
pub const TOKEN_SERIAL: u8 = 0x01;
/// The last day of the fixture month, for validity that outlasts every
/// fixture instant.
pub const FIXTURE_LAST_DAY: u8 = 30;
/// A TSA policy under the documentation enterprise number 32473
/// (RFC 5612).
pub const TEST_POLICY: Oid<'static> =
    Oid::const_new(const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1").as_bytes());

/// The `CAdES` writer's name for `key`'s signatures.
#[must_use]
pub const fn cades_algorithm(key: &TestKey) -> SignatureAlgorithm {
    match key.kind() {
        TestKeyKind::Ecdsa(TestCurve::P256) => SignatureAlgorithm::EcdsaSha256,
        TestKeyKind::Ecdsa(TestCurve::P384) => SignatureAlgorithm::EcdsaSha384,
        TestKeyKind::Rsa => SignatureAlgorithm::RsaPkcs1Sha256,
    }
}

/// The digest `key`'s signatures are computed over.
#[must_use]
pub const fn digest_algorithm(key: &TestKey) -> DigestAlgorithm {
    match key.kind() {
        TestKeyKind::Ecdsa(TestCurve::P256) | TestKeyKind::Rsa => DigestAlgorithm::Sha256,
        TestKeyKind::Ecdsa(TestCurve::P384) => DigestAlgorithm::Sha384,
    }
}

/// The extensions of a delegated OCSP responder (RFC 6960
/// sec.4.2.2.2): critical EKU `id-kp-OCSPSigning`, and the
/// non-critical `id-pkix-ocsp-nocheck` holding DER NULL when
/// `no_check` is set (sec.4.2.2.2.1).
#[must_use]
pub fn ocsp_responder_extensions(no_check: bool) -> Vec<Vec<u8>> {
    let mut extensions = vec![extended_key_usage(known::KP_OCSP_SIGNING)];
    if no_check {
        extensions.push(extension(known::OCSP_NO_CHECK, false, &tlv(NULL, [])));
    }
    extensions
}

/// A CRL from `issuer`, listing `revoked` serials as revoked on
/// `revoked_on`, carrying `cRLNumber` and `authorityKeyIdentifier`
/// (RFC 5280 sec.5.2.1, sec.5.2.3).
#[must_use]
pub fn crl(
    issuer: &str,
    issuer_key: &TestKey,
    this_update: DateTime,
    next_update: Option<DateTime>,
    revoked: &[u8],
    revoked_on: DateTime,
) -> Vec<u8> {
    crl_with_reason(
        issuer,
        issuer_key,
        this_update,
        next_update,
        revoked,
        revoked_on,
        None,
    )
}

/// As [`crl`], each entry carrying the `reasonCode` `reason` when given
/// (RFC 5280 sec.5.3.1).
#[must_use]
pub fn crl_with_reason(
    issuer: &str,
    issuer_key: &TestKey,
    this_update: DateTime,
    next_update: Option<DateTime>,
    revoked: &[u8],
    revoked_on: DateTime,
    reason: Option<CrlReason>,
) -> Vec<u8> {
    signed(
        &tbs_cert_list_with_reason(
            issuer,
            issuer_key,
            this_update,
            next_update,
            revoked,
            revoked_on,
            reason,
        ),
        issuer_key,
    )
}

/// The `TBSCertList` of [`crl`].
#[must_use]
pub fn tbs_cert_list(
    issuer: &str,
    issuer_key: &TestKey,
    this_update: DateTime,
    next_update: Option<DateTime>,
    revoked: &[u8],
    revoked_on: DateTime,
) -> Vec<u8> {
    tbs_cert_list_with_reason(
        issuer,
        issuer_key,
        this_update,
        next_update,
        revoked,
        revoked_on,
        None,
    )
}

/// The `TBSCertList` of [`crl_with_reason`].
#[must_use]
pub fn tbs_cert_list_with_reason(
    issuer: &str,
    issuer_key: &TestKey,
    this_update: DateTime,
    next_update: Option<DateTime>,
    revoked: &[u8],
    revoked_on: DateTime,
    reason: Option<CrlReason>,
) -> Vec<u8> {
    let mut tbs = tlv(INTEGER, [CRL_VERSION_2]);
    tbs.extend_from_slice(&issuer_key.algorithm_identifier());
    tbs.extend_from_slice(&name(issuer));
    tbs.extend_from_slice(&utc_time(this_update));
    if let Some(next_update) = next_update {
        tbs.extend_from_slice(&utc_time(next_update));
    }
    if !revoked.is_empty() {
        let mut entries = Vec::new();
        for serial in revoked {
            let mut entry = positive_integer(&[*serial]);
            entry.extend_from_slice(&utc_time(revoked_on));
            if let Some(reason) = reason {
                entry.extend_from_slice(&tlv(
                    SEQUENCE,
                    extension(known::CRL_REASON, false, &tlv(ENUMERATED, [reason.code()])),
                ));
            }
            entries.extend_from_slice(&tlv(SEQUENCE, entry));
        }
        tbs.extend_from_slice(&tlv(SEQUENCE, entries));
    }
    let spki = issuer_key.spki();
    let key = refineid_cms::x509::SpkiDer::try_from(spki.as_slice()).expect("kit SPKI parses");
    let key_identifier = tlv(
        CONTEXT_0_PRIMITIVE,
        crate::digest::Sha1::of(key.subject_public_key_bits()).into_bytes(),
    );
    let mut extensions = extension(
        crate::oids::CRL_NUMBER,
        false,
        &positive_integer(&[TOKEN_SERIAL]),
    );
    extensions.extend_from_slice(&extension(
        crate::oids::AUTHORITY_KEY_IDENTIFIER,
        false,
        &tlv(SEQUENCE, key_identifier),
    ));
    tbs.extend_from_slice(&tlv(CONTEXT_0, tlv(SEQUENCE, extensions)));
    tlv(SEQUENCE, tbs)
}

/// How a fixture OCSP response names its signer (RFC 6960 sec.4.2.1).
#[derive(Debug, Clone, Copy)]
pub enum ResponderName<'a> {
    /// `byName`: the responder's subject common name.
    ByName(&'a str),
    /// `byKey`: the SHA-1 of this key's subject public key.
    ByKey(&'a TestKey),
}

/// What one OCSP response says.
#[derive(Debug, Clone)]
pub struct OcspSpec<'a> {
    /// The key that signs the response.
    pub responder_key: &'a TestKey,
    /// The responder identity the response carries.
    pub responder: ResponderName<'a>,
    /// The issuer of the certificate asked about.
    pub issuer: &'a OwnedCert,
    /// Serial of the certificate asked about.
    pub serial: u8,
    /// `Some(revocation time)` for a revoked answer, `None` for good.
    pub revoked: Option<DateTime>,
    /// The `revocationReason` of a revoked answer, when it gives one.
    pub revocation_reason: Option<CrlReason>,
    /// `producedAt`.
    pub produced_at: DateTime,
    /// `thisUpdate`.
    pub this_update: DateTime,
    /// `nextUpdate`.
    pub next_update: Option<DateTime>,
    /// Certificates carried in `BasicOCSPResponse.certs`.
    pub embedded: Vec<Vec<u8>>,
    /// The `CertID.hashAlgorithm` the response names its certificate
    /// under.
    pub cert_id: CertIdAlgorithm,
    /// Complete `Extension` encodings of `responseExtensions`; none
    /// writes no field.
    pub response_extensions: Vec<Vec<u8>>,
}

/// A `CertID.hashAlgorithm` a fixture response uses (RFC 6960
/// sec.4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertIdAlgorithm {
    /// SHA-1, written with NULL parameters as requests write it.
    Sha1,
    /// SHA-256, parameters absent.
    Sha256,
}

/// A successful `OCSPResponse` (RFC 6960 sec.4.2.1).
#[must_use]
pub fn ocsp_response(spec: &OcspSpec<'_>) -> Vec<u8> {
    let issuer = spec.issuer.view();
    let mut cert_id = match spec.cert_id {
        CertIdAlgorithm::Sha1 => {
            let mut hash_algorithm = tlv(OBJECT_IDENTIFIER, known::SHA1.as_bytes());
            hash_algorithm.extend_from_slice(&tlv(NULL, []));
            let mut cert_id = tlv(SEQUENCE, hash_algorithm);
            cert_id.extend_from_slice(&tlv(
                OCTET_STRING,
                IssuerNameHash::from_name(issuer.subject).as_bytes(),
            ));
            cert_id.extend_from_slice(&tlv(
                OCTET_STRING,
                IssuerKeyHash::from_subject_public_key(&issuer.spki).as_bytes(),
            ));
            cert_id
        }
        CertIdAlgorithm::Sha256 => {
            let mut cert_id = DigestAlgorithm::Sha256.algorithm_identifier();
            cert_id.extend_from_slice(&tlv(
                OCTET_STRING,
                DigestAlgorithm::Sha256.digest(issuer.subject.as_der()),
            ));
            cert_id.extend_from_slice(&tlv(
                OCTET_STRING,
                DigestAlgorithm::Sha256.digest(issuer.spki.subject_public_key_bits()),
            ));
            cert_id
        }
    };
    cert_id.extend_from_slice(&positive_integer(&[spec.serial]));

    let mut single = tlv(SEQUENCE, cert_id);
    match spec.revoked {
        None => single.extend_from_slice(&tlv(CONTEXT_0_PRIMITIVE, [])),
        Some(at) => {
            let mut revoked_info = generalized_time(at);
            if let Some(reason) = spec.revocation_reason {
                revoked_info.extend_from_slice(&tlv(CONTEXT_0, tlv(ENUMERATED, [reason.code()])));
            }
            single.extend_from_slice(&tlv(CONTEXT_1, revoked_info));
        }
    }
    single.extend_from_slice(&generalized_time(spec.this_update));
    if let Some(next_update) = spec.next_update {
        single.extend_from_slice(&tlv(CONTEXT_0, generalized_time(next_update)));
    }

    let mut response_data = match spec.responder {
        ResponderName::ByName(common_name) => tlv(CONTEXT_1, name(common_name)),
        ResponderName::ByKey(key) => {
            let spki = key.spki();
            let typed =
                refineid_cms::x509::SpkiDer::try_from(spki.as_slice()).expect("kit SPKI parses");
            tlv(
                CONTEXT_2,
                tlv(
                    OCTET_STRING,
                    IssuerKeyHash::from_subject_public_key(&typed).as_bytes(),
                ),
            )
        }
    };
    response_data.extend_from_slice(&generalized_time(spec.produced_at));
    response_data.extend_from_slice(&tlv(SEQUENCE, tlv(SEQUENCE, single)));
    if !spec.response_extensions.is_empty() {
        response_data.extend_from_slice(&tlv(
            CONTEXT_1,
            tlv(SEQUENCE, spec.response_extensions.concat()),
        ));
    }
    let mut basic = signed_body(&tlv(SEQUENCE, response_data), spec.responder_key);
    if !spec.embedded.is_empty() {
        basic.extend_from_slice(&tlv(CONTEXT_0, tlv(SEQUENCE, spec.embedded.concat())));
    }

    let mut response_bytes = tlv(OBJECT_IDENTIFIER, known::BASIC_OCSP_RESPONSE.as_bytes());
    response_bytes.extend_from_slice(&tlv(OCTET_STRING, tlv(SEQUENCE, basic)));
    let mut response = tlv(ENUMERATED, [OCSP_SUCCESSFUL]);
    response.extend_from_slice(&tlv(CONTEXT_0, tlv(SEQUENCE, response_bytes)));
    tlv(SEQUENCE, response)
}

/// An RFC 3161 token from the TSA certificate `tsa`, generated at
/// `generated`, whose `messageImprint` is `imprint` under `algorithm`.
/// The imprint is written as given, so a test can make its length
/// disagree with its algorithm.
#[must_use]
pub fn timestamp_token(
    tsa: &[u8],
    tsa_key: &TestKey,
    algorithm: DigestAlgorithm,
    imprint: &[u8],
    generated: DateTime,
) -> Vec<u8> {
    timestamp_token_imprinting(
        tsa,
        tsa_key,
        &algorithm.algorithm_identifier(),
        imprint,
        generated,
        &[],
    )
}

/// As [`timestamp_token`], with the imprint's `AlgorithmIdentifier`
/// written as given, so a test can name an algorithm the verifier
/// refuses, and `revocation_info` (encoded `RevocationInfoChoice`s, see
/// [`ocsp_revocation_info`]) in the token's `SignedData.crls`.
#[must_use]
pub fn timestamp_token_imprinting(
    tsa: &[u8],
    tsa_key: &TestKey,
    imprint_algorithm: &[u8],
    imprint: &[u8],
    generated: DateTime,
    revocation_info: &[Vec<u8>],
) -> Vec<u8> {
    let mut message_imprint = imprint_algorithm.to_vec();
    message_imprint.extend_from_slice(&tlv(OCTET_STRING, imprint));
    let mut tst_info = tlv(INTEGER, [TST_INFO_VERSION]);
    tst_info.extend_from_slice(&tlv(OBJECT_IDENTIFIER, TEST_POLICY.as_bytes()));
    tst_info.extend_from_slice(&tlv(SEQUENCE, message_imprint));
    tst_info.extend_from_slice(&positive_integer(&[TOKEN_SERIAL]));
    tst_info.extend_from_slice(&generalized_time(generated));
    let tst_info = tlv(SEQUENCE, tst_info);
    let hash = tsa_key.hash();
    let mut attributes = content_attributes(known::TST_INFO, hash, &tst_info);
    attributes.push(signing_certificate_v2(tsa));
    let mut parts = CmsParts::attached(tsa_key, tsa, &tst_info);
    parts.econtent_type = known::TST_INFO;
    parts.signed_attributes = Some(attribute_set(&attributes));
    parts.revocation_info = revocation_info.to_vec();
    cms(&parts)
}

/// The `RevocationInfoChoice` carrying the `OCSPResponse` `response`
/// (RFC 5940 sec.4.1): `other` with `id-ri-ocsp-response`.
#[must_use]
pub fn ocsp_revocation_info(response: &[u8]) -> Vec<u8> {
    let mut other = tlv(
        OBJECT_IDENTIFIER,
        known::OCSP_RESPONSE_REVOCATION_INFO.as_bytes(),
    );
    other.extend_from_slice(response);
    tlv(CONTEXT_1, other)
}

/// The ESS `signing-certificate-v2` attribute binding `certificate`:
/// one `ESSCertIDv2` with the DEFAULT SHA-256 hash algorithm left out
/// (RFC 5035 sec.4).
#[must_use]
pub fn signing_certificate_v2(certificate: &[u8]) -> Vec<u8> {
    let ess = tlv(
        SEQUENCE,
        tlv(
            SEQUENCE,
            tlv(
                SEQUENCE,
                tlv(OCTET_STRING, DigestAlgorithm::Sha256.digest(certificate)),
            ),
        ),
    );
    attribute(known::SIGNING_CERTIFICATE_V2, &ess)
}

/// A minimal PDF: catalog, page tree, one page, a classic
/// cross-reference table and a trailer, with offsets computed from
/// the bytes (ISO 32000-1 sec.7.5).
#[must_use]
pub fn minimal_pdf() -> Vec<u8> {
    let bodies = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
    ];
    let mut pdf = Vec::from("%PDF-1.7\n");
    let mut offsets = Vec::new();
    for (index, body) in bodies.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(
            format!("{} 0 obj\n{body}\nendobj\n", index.saturating_add(1)).as_bytes(),
        );
    }
    let xref_at = pdf.len();
    let size = bodies.len().saturating_add(1);
    pdf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n")
            .as_bytes(),
    );
    pdf
}
