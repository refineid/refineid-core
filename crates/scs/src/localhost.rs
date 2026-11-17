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

//! The two-tier localhost PKI the SCS presents at
//! `https://127.0.0.1:53952` (DVV SCS specification v1.3 sec.2.3).
//!
//! Issuance creates an ephemeral P-256 root authority key in memory,
//! signs one name-constrained root certificate and one short-lived
//! non-CA server leaf around the caller's server key, and discards
//! the root private key on return.
//!
//! Only the loopback server leaf and offline root certificate are retained
//! in the resulting [`IssuedChain`].

use refineid_cms::oid::known;

use crate::der;
use crate::time;
use crate::values;

/// The server leaf's common name, fixed by the specification at the
/// loopback address (v1.3 sec.2.3).
pub const COMMON_NAME: &str = "127.0.0.1";

/// The offline root authority's common name, distinct from the
/// server leaf so the chain is never self-issued at the leaf.
pub const ROOT_COMMON_NAME: &str = "RefineID SCS Localhost Root CA";

/// The DNS name carried beside the loopback address.
const LOCALHOST_NAME: &str = "localhost";

/// X.509 version 3, zero-based.
const VERSION_THREE: u8 = 2;

/// Maximum attempts to draw a valid ephemeral P-256 scalar from OS random.
const MAX_KEYGEN_ATTEMPTS: usize = 16;

/// One freshly minted localhost certificate chain (DVV SCS v1.3 sec.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedChain {
    /// The DER-encoded non-CA server leaf (`CN=127.0.0.1`).
    pub leaf_der: Vec<u8>,
    /// The DER-encoded offline root CA certificate (`CN=RefineID SCS Localhost Root CA`).
    pub root_der: Vec<u8>,
}

impl IssuedChain {
    /// Return the concatenated certificate chain DER bytes (leaf followed by root).
    #[must_use]
    pub fn chain_der(&self) -> Vec<u8> {
        let mut chain = Vec::with_capacity(self.leaf_der.len() + self.root_der.len());
        chain.extend_from_slice(&self.leaf_der);
        chain.extend_from_slice(&self.root_der);
        chain
    }
}

/// Why the certificate or chain cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalhostError {
    /// The signing operation failed.
    SigningFailed,
    /// The validity window cannot be represented.
    UnrepresentableTime,
    /// Secure random byte generation failed.
    RandomFailed,
    /// The provided public key is invalid or not P-256.
    InvalidKey,
}

impl core::fmt::Display for LocalhostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SigningFailed => f.write_str("localhost certificate signing failed"),
            Self::UnrepresentableTime => f.write_str("localhost certificate time out of range"),
            Self::RandomFailed => f.write_str("localhost certificate random generation failed"),
            Self::InvalidKey => f.write_str("localhost certificate public key invalid"),
        }
    }
}

impl core::error::Error for LocalhostError {}

/// Wrap a P-256 public key's SEC1 representation as a DER
/// SubjectPublicKeyInfo.
pub fn subject_public_key_info(representation: &[u8]) -> Result<Vec<u8>, LocalhostError> {
    let algorithm = der::sequence(&[
        &der::oid(known::EC_PUBLIC_KEY.as_bytes()).map_err(|()| LocalhostError::SigningFailed)?,
        &der::oid(known::SECP256R1.as_bytes()).map_err(|()| LocalhostError::SigningFailed)?,
    ])
    .map_err(|()| LocalhostError::SigningFailed)?;
    let bits = der::bit_string(representation).map_err(|()| LocalhostError::SigningFailed)?;
    der::sequence(&[&algorithm, &bits]).map_err(|()| LocalhostError::SigningFailed)
}

/// Resolve either a DER SubjectPublicKeyInfo or raw SEC1 point into
/// canonical SPKI DER bytes and uncompressed SEC1 point bytes.
fn resolve_spki_and_raw(representation: &[u8]) -> Result<(Vec<u8>, Vec<u8>), LocalhostError> {
    if let Ok(spki_obj) = refineid_cms::x509::SpkiDer::try_from(representation) {
        if spki_obj.algorithm()
            != refineid_cms::x509::PublicKeyAlgorithm::Ec(refineid_cms::x509::EcCurve::Secp256r1)
        {
            return Err(LocalhostError::InvalidKey);
        }
        let raw = spki_obj.subject_public_key_bits();
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(raw)
            .map_err(|_| LocalhostError::InvalidKey)?;
        let point = vk.to_sec1_point(false);
        let uncompressed = point.as_bytes().to_vec();
        let canonical_spki = subject_public_key_info(&uncompressed)?;
        Ok((canonical_spki, uncompressed))
    } else {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(representation)
            .map_err(|_| LocalhostError::InvalidKey)?;
        let point = vk.to_sec1_point(false);
        let uncompressed = point.as_bytes().to_vec();
        let spki = subject_public_key_info(&uncompressed)?;
        Ok((spki, uncompressed))
    }
}

/// Compute the 160-bit SHA-1 SubjectKeyIdentifier from the uncompressed
/// SEC1 public key point bytes (RFC 5280 sec.4.2.1.2).
fn key_identifier(uncompressed_sec1: &[u8]) -> [u8; refineid_digest::SHA1_LEN] {
    refineid_digest::Sha1::of(uncompressed_sec1).into_bytes()
}

/// Draw a fresh ephemeral P-256 key pair from OS entropy, zeroizing the secret buffer.
fn draw_ephemeral_root_key(
    buffer: &mut zeroize::Zeroizing<[u8; values::TRANSACTION_KEY_LENGTH]>,
) -> Result<p256::ecdsa::SigningKey, LocalhostError> {
    for _ in 0..MAX_KEYGEN_ATTEMPTS {
        getrandom::fill(&mut buffer[..]).map_err(|_| LocalhostError::RandomFailed)?;
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&buffer[..]) {
            return Ok(key);
        }
    }
    Err(LocalhostError::RandomFailed)
}

/// Draw a random 128-bit positive certificate serial number.
fn random_serial() -> Result<[u8; values::SERIAL_OCTET_COUNT], LocalhostError> {
    let mut bytes = [0_u8; values::SERIAL_OCTET_COUNT];
    getrandom::fill(&mut bytes).map_err(|_| LocalhostError::RandomFailed)?;
    bytes[0] &= values::SERIAL_POSITIVE_MASK;
    if bytes.iter().all(|&b| b == 0) {
        bytes[values::SERIAL_OCTET_COUNT - 1] = values::SERIAL_NON_ZERO_BIT;
    }
    Ok(bytes)
}

/// Encode a single commonName RDN sequence.
fn distinguished_name(cn: &str) -> Result<Vec<u8>, LocalhostError> {
    let attribute = der::sequence(&[
        &der::oid(known::COMMON_NAME.as_bytes()).map_err(|()| LocalhostError::SigningFailed)?,
        &der::utf8_string(cn.as_bytes()).map_err(|()| LocalhostError::SigningFailed)?,
    ])
    .map_err(|()| LocalhostError::SigningFailed)?;
    let set = der::set(&[&attribute]).map_err(|()| LocalhostError::SigningFailed)?;
    der::sequence(&[&set]).map_err(|()| LocalhostError::SigningFailed)
}

/// Encode the certificate validity window per RFC 5280 sec.4.1.2.5.
fn validity(not_before_unix: i64, not_after_unix: i64) -> Result<Vec<u8>, LocalhostError> {
    let (before_tag, before_bytes) = time::format_rfc5280_time(not_before_unix)
        .map_err(|_| LocalhostError::UnrepresentableTime)?;
    let (after_tag, after_bytes) = time::format_rfc5280_time(not_after_unix)
        .map_err(|_| LocalhostError::UnrepresentableTime)?;
    let before_tlv =
        der::tagged(before_tag, &before_bytes).map_err(|()| LocalhostError::SigningFailed)?;
    let after_tlv =
        der::tagged(after_tag, &after_bytes).map_err(|()| LocalhostError::SigningFailed)?;
    der::sequence(&[&before_tlv, &after_tlv]).map_err(|()| LocalhostError::SigningFailed)
}

/// One Extension record: identifier, criticality, wrapped value.
fn extension_record(oid: &[u8], critical: bool, value: &[u8]) -> Result<Vec<u8>, LocalhostError> {
    let oid = der::oid(oid).map_err(|()| LocalhostError::SigningFailed)?;
    let wrapped = der::octet_string(value).map_err(|()| LocalhostError::SigningFailed)?;
    if critical {
        let flag = der::boolean_true().map_err(|()| LocalhostError::SigningFailed)?;
        der::sequence(&[&oid, &flag, &wrapped]).map_err(|()| LocalhostError::SigningFailed)
    } else {
        der::sequence(&[&oid, &wrapped]).map_err(|()| LocalhostError::SigningFailed)
    }
}

/// Root CA extensions: cA=TRUE, pathLenConstraint=0, keyCertSign, cRLSign, SKI,
/// and NameConstraints permitted to localhost, 127.0.0.1/32, ::1/128 (RFC 5280).
fn root_extensions(subject_key_id: &[u8]) -> Result<Vec<u8>, LocalhostError> {
    let basic_constraints = extension_record(
        known::BASIC_CONSTRAINTS.as_bytes(),
        true,
        &der::sequence(&[
            &der::boolean_true().map_err(|()| LocalhostError::SigningFailed)?,
            &der::integer(values::ROOT_PATH_LENGTH).map_err(|()| LocalhostError::SigningFailed)?,
        ])
        .map_err(|()| LocalhostError::SigningFailed)?,
    )?;
    let key_usage = extension_record(
        known::KEY_USAGE.as_bytes(),
        true,
        &der::bit_string_raw(&[
            values::ROOT_KEY_USAGE_UNUSED_BITS,
            values::ROOT_KEY_USAGE_BITS,
        ])
        .map_err(|()| LocalhostError::SigningFailed)?,
    )?;
    let ski = extension_record(
        known::SUBJECT_KEY_IDENTIFIER.as_bytes(),
        false,
        &der::octet_string(subject_key_id).map_err(|()| LocalhostError::SigningFailed)?,
    )?;

    // NameConstraints: permittedSubtrees [0] GeneralSubtrees
    let dns_subtree =
        der::sequence(&[
            &der::tagged(der::TAG_CONTEXT_TWO, LOCALHOST_NAME.as_bytes())
                .map_err(|()| LocalhostError::SigningFailed)?,
        ])
        .map_err(|()| LocalhostError::SigningFailed)?;
    let ipv4_subtree = der::sequence(&[&der::tagged(
        der::TAG_CONTEXT_SEVEN,
        &values::LOOPBACK_NAME_CONSTRAINT_IPV4,
    )
    .map_err(|()| LocalhostError::SigningFailed)?])
    .map_err(|()| LocalhostError::SigningFailed)?;
    let ipv6_subtree = der::sequence(&[&der::tagged(
        der::TAG_CONTEXT_SEVEN,
        &values::LOOPBACK_NAME_CONSTRAINT_IPV6,
    )
    .map_err(|()| LocalhostError::SigningFailed)?])
    .map_err(|()| LocalhostError::SigningFailed)?;

    let mut subtrees_payload = Vec::new();
    subtrees_payload.extend_from_slice(&dns_subtree);
    subtrees_payload.extend_from_slice(&ipv4_subtree);
    subtrees_payload.extend_from_slice(&ipv6_subtree);

    let permitted = der::tagged(der::TAG_CONTEXT_ZERO, &subtrees_payload)
        .map_err(|()| LocalhostError::SigningFailed)?;
    let nc_value = der::sequence(&[&permitted]).map_err(|()| LocalhostError::SigningFailed)?;
    let name_constraints = extension_record(known::NAME_CONSTRAINTS.as_bytes(), true, &nc_value)?;

    der::sequence(&[&basic_constraints, &key_usage, &ski, &name_constraints])
        .map_err(|()| LocalhostError::SigningFailed)
}

/// Server Leaf extensions: cA=FALSE, digitalSignature, keyEncipherment,
/// serverAuth, SKI, AKI, and SAN (localhost, 127.0.0.1, ::1) (DVV SCS v1.3 sec.2.3).
fn leaf_extensions(
    subject_key_id: &[u8],
    authority_key_id: &[u8],
) -> Result<Vec<u8>, LocalhostError> {
    let basic_constraints = extension_record(
        known::BASIC_CONSTRAINTS.as_bytes(),
        true,
        &der::sequence(&[]).map_err(|()| LocalhostError::SigningFailed)?,
    )?;
    let key_usage = extension_record(
        known::KEY_USAGE.as_bytes(),
        true,
        &der::bit_string_raw(&[
            values::SERVER_KEY_USAGE_UNUSED_BITS,
            values::SERVER_KEY_USAGE_BITS,
        ])
        .map_err(|()| LocalhostError::SigningFailed)?,
    )?;
    let extended_key_usage = extension_record(
        known::EXT_KEY_USAGE.as_bytes(),
        false,
        &der::sequence(&[&der::oid(known::KP_SERVER_AUTH.as_bytes())
            .map_err(|()| LocalhostError::SigningFailed)?])
        .map_err(|()| LocalhostError::SigningFailed)?,
    )?;
    let ski = extension_record(
        known::SUBJECT_KEY_IDENTIFIER.as_bytes(),
        false,
        &der::octet_string(subject_key_id).map_err(|()| LocalhostError::SigningFailed)?,
    )?;
    let aki_key_id = der::tagged(der::TAG_CONTEXT_ZERO_PRIMITIVE, authority_key_id)
        .map_err(|()| LocalhostError::SigningFailed)?;
    let aki_value = der::sequence(&[&aki_key_id]).map_err(|()| LocalhostError::SigningFailed)?;
    let aki = extension_record(
        known::AUTHORITY_KEY_IDENTIFIER.as_bytes(),
        false,
        &aki_value,
    )?;
    let alternative_names = extension_record(
        known::SUBJECT_ALT_NAME.as_bytes(),
        false,
        &der::sequence(&[
            &der::tagged(der::TAG_CONTEXT_TWO, LOCALHOST_NAME.as_bytes())
                .map_err(|()| LocalhostError::SigningFailed)?,
            &der::tagged(der::TAG_CONTEXT_SEVEN, &values::LOOPBACK_ADDRESS)
                .map_err(|()| LocalhostError::SigningFailed)?,
            &der::tagged(der::TAG_CONTEXT_SEVEN, &values::LOOPBACK_IPV6_ADDRESS)
                .map_err(|()| LocalhostError::SigningFailed)?,
        ])
        .map_err(|()| LocalhostError::SigningFailed)?,
    )?;
    der::sequence(&[
        &basic_constraints,
        &key_usage,
        &extended_key_usage,
        &ski,
        &aki,
        &alternative_names,
    ])
    .map_err(|()| LocalhostError::SigningFailed)
}

/// ecdsa-with-SHA256, the signature algorithm for localhost certificates.
fn signature_algorithm() -> Result<Vec<u8>, LocalhostError> {
    der::sequence(&[&der::oid(known::ECDSA_WITH_SHA256.as_bytes())
        .map_err(|()| LocalhostError::SigningFailed)?])
    .map_err(|()| LocalhostError::SigningFailed)
}

/// Fields assembled into one X.509 v3 TBSCertificate.
struct TbsFields<'a> {
    serial_number: &'a [u8],
    issuer: &'a [u8],
    not_before_unix: i64,
    not_after_unix: i64,
    subject: &'a [u8],
    subject_public_key_info: &'a [u8],
    extensions: &'a [u8],
}

/// Assemble a TBSCertificate SEQUENCE.
fn tbs_certificate(fields: &TbsFields<'_>) -> Result<Vec<u8>, LocalhostError> {
    let validity = validity(fields.not_before_unix, fields.not_after_unix)?;
    let version = der::tagged(
        der::TAG_CONTEXT_ZERO,
        &der::integer(VERSION_THREE).map_err(|()| LocalhostError::SigningFailed)?,
    )
    .map_err(|()| LocalhostError::SigningFailed)?;
    let serial =
        der::unsigned_integer(fields.serial_number).map_err(|()| LocalhostError::SigningFailed)?;
    let extensions = der::tagged(der::TAG_CONTEXT_THREE, fields.extensions)
        .map_err(|()| LocalhostError::SigningFailed)?;
    der::sequence(&[
        &version,
        &serial,
        &signature_algorithm()?,
        fields.issuer,
        &validity,
        fields.subject,
        fields.subject_public_key_info,
        &extensions,
    ])
    .map_err(|()| LocalhostError::SigningFailed)
}

/// Wrap a TBSCertificate and ECDSA signature into a signed Certificate SEQUENCE.
fn signed_certificate(tbs: &[u8], signature_der: &[u8]) -> Result<Vec<u8>, LocalhostError> {
    let bits = der::bit_string(signature_der).map_err(|()| LocalhostError::SigningFailed)?;
    der::sequence(&[tbs, &signature_algorithm()?, &bits])
        .map_err(|()| LocalhostError::SigningFailed)
}

/// Issue a fresh localhost certificate chain (Root CA and Server Leaf)
/// conforming to DVV SCS v1.3 sec.2.3.
///
/// An ephemeral Root CA key pair is generated in memory, signs both the
/// self-signed Root CA certificate and the loopback Server Leaf, and is
/// zeroized and dropped on return.
pub fn issue_chain(
    server_public_key: &[u8],
    not_before_unix: i64,
) -> Result<IssuedChain, LocalhostError> {
    let mut root_key_bytes = zeroize::Zeroizing::new([0_u8; values::TRANSACTION_KEY_LENGTH]);
    let root_key = draw_ephemeral_root_key(&mut root_key_bytes)?;
    let root_serial = random_serial()?;
    let leaf_serial = random_serial()?;
    let chain = issue_chain_with(
        server_public_key,
        &root_key,
        &root_serial,
        &leaf_serial,
        not_before_unix,
    )?;
    drop(root_key);
    drop(root_key_bytes);
    Ok(chain)
}

/// Deterministic variant of [`issue_chain`] for testing and reproducible issuance.
///
/// Production listeners MUST call [`issue_chain`] so an ephemeral Root CA key pair
/// is generated on the fly, used strictly for this issuance, and destroyed immediately.
pub fn issue_chain_with(
    server_public_key: &[u8],
    root_signing_key: &p256::ecdsa::SigningKey,
    root_serial: &[u8],
    leaf_serial: &[u8],
    not_before_unix: i64,
) -> Result<IssuedChain, LocalhostError> {
    use p256::ecdsa::signature::Signer as _;

    let (leaf_spki, leaf_sec1) = resolve_spki_and_raw(server_public_key)?;
    let root_point = root_signing_key.verifying_key().to_sec1_point(false);
    let root_sec1 = root_point.as_bytes();
    let root_spki = subject_public_key_info(root_sec1)?;

    let root_key_id = key_identifier(root_sec1);
    let leaf_key_id = key_identifier(&leaf_sec1);

    let not_before = time::sub_seconds(not_before_unix, values::NOT_BEFORE_CLOCK_SKEW_SECONDS)
        .map_err(|_| LocalhostError::UnrepresentableTime)?;
    let root_not_after = time::add_years(not_before_unix, values::ROOT_CERTIFICATE_VALIDITY_YEARS)
        .map_err(|_| LocalhostError::UnrepresentableTime)?;
    let leaf_not_after = time::add_days(not_before_unix, values::LEAF_CERTIFICATE_VALIDITY_DAYS)
        .map_err(|_| LocalhostError::UnrepresentableTime)?;

    let root_dn = distinguished_name(ROOT_COMMON_NAME)?;
    let leaf_dn = distinguished_name(COMMON_NAME)?;

    let root_exts = root_extensions(&root_key_id)?;
    let leaf_exts = leaf_extensions(&leaf_key_id, &root_key_id)?;

    let root_tbs = tbs_certificate(&TbsFields {
        serial_number: root_serial,
        issuer: &root_dn,
        not_before_unix: not_before,
        not_after_unix: root_not_after,
        subject: &root_dn,
        subject_public_key_info: &root_spki,
        extensions: &root_exts,
    })?;

    let leaf_tbs = tbs_certificate(&TbsFields {
        serial_number: leaf_serial,
        issuer: &root_dn,
        not_before_unix: not_before,
        not_after_unix: leaf_not_after,
        subject: &leaf_dn,
        subject_public_key_info: &leaf_spki,
        extensions: &leaf_exts,
    })?;

    let root_sig: p256::ecdsa::Signature = root_signing_key.sign(&root_tbs);
    let leaf_sig: p256::ecdsa::Signature = root_signing_key.sign(&leaf_tbs);

    let root_der = signed_certificate(&root_tbs, root_sig.to_der().as_bytes())?;
    let leaf_der = signed_certificate(&leaf_tbs, leaf_sig.to_der().as_bytes())?;

    Ok(IssuedChain { leaf_der, root_der })
}

/// Build and issue a localhost certificate chain.
///
/// Convenience alias for [`issue_chain`].
pub fn make(server_public_key: &[u8], not_before_unix: i64) -> Result<IssuedChain, LocalhostError> {
    issue_chain(server_public_key, not_before_unix)
}

#[cfg(test)]
mod tests {
    use super::{
        COMMON_NAME, IssuedChain, LocalhostError, ROOT_COMMON_NAME, issue_chain, issue_chain_with,
        make, subject_public_key_info,
    };
    use crate::values;

    /// Length of a P-256 private key secret, in bytes.
    const SECRET_LENGTH: usize = 32;

    /// Byte value used to initialize test server key.
    const SERVER_SECRET_FILL: u8 = 1;

    /// Byte value used to initialize test root key.
    const ROOT_SECRET_FILL: u8 = 2;

    /// Serial number for root test certificate.
    const TEST_ROOT_SERIAL: &[u8] = &[10];

    /// Serial number for leaf test certificate.
    const TEST_LEAF_SERIAL: &[u8] = &[20];

    /// Unix seconds of 2023-11-14T22:13:20Z.
    const NOT_BEFORE: i64 = 1_700_000_000;

    #[test]
    fn issues_verifiable_chain_and_destroys_root_key() {
        let leaf_key = p256::ecdsa::SigningKey::from_slice(&[SERVER_SECRET_FILL; SECRET_LENGTH])
            .expect("leaf key parses");
        let leaf_point = leaf_key.verifying_key().to_sec1_point(false);

        let chain = issue_chain(leaf_point.as_bytes(), NOT_BEFORE).expect("issues chain");

        assert!(!chain.leaf_der.is_empty());
        assert!(!chain.root_der.is_empty());
        assert_eq!(
            chain.chain_der().len(),
            chain.leaf_der.len() + chain.root_der.len()
        );

        let leaf_cert = refineid_cms::x509::Certificate::from_der(&chain.leaf_der)
            .expect("leaf parses as RFC 5280 X.509");
        let root_cert = refineid_cms::x509::Certificate::from_der(&chain.root_der)
            .expect("root parses as RFC 5280 X.509");

        // Root CA is self-signed and verifies itself.
        root_cert
            .verify_signed_by(root_cert)
            .expect("root CA self-signature verifies");

        // Server leaf is signed by Root CA.
        leaf_cert
            .verify_signed_by(root_cert)
            .expect("server leaf verifies against root CA");

        // Leaf is not signed by itself.
        assert!(leaf_cert.verify_signed_by(leaf_cert).is_err());

        // Validate Root CA facts.
        let root_exts = root_cert.extensions.expect("root extensions present");
        let root_bc = refineid_cms::x509::extract_basic_constraints(root_exts);
        assert!(root_bc.ca);
        assert_eq!(root_bc.path_len, Some(values::ROOT_PATH_LENGTH.into()));
        assert!(root_bc.critical);

        let root_ku = refineid_cms::x509::extract_key_usage(root_exts).expect("root key usage");
        assert!(root_ku.key_cert_sign);
        assert!(root_ku.crl_sign);
        assert!(!root_ku.digital_signature);

        // Root extensions.
        assert!(
            root_exts
                .windows(refineid_cms::oid::known::NAME_CONSTRAINTS.as_bytes().len())
                .any(|w| w == refineid_cms::oid::known::NAME_CONSTRAINTS.as_bytes())
        );
        assert!(
            !root_exts
                .windows(refineid_cms::oid::known::EXT_KEY_USAGE.as_bytes().len())
                .any(|w| w == refineid_cms::oid::known::EXT_KEY_USAGE.as_bytes())
        );

        // Root names.
        assert!(
            chain
                .root_der
                .windows(ROOT_COMMON_NAME.len())
                .any(|window| window == ROOT_COMMON_NAME.as_bytes())
        );

        // Validate Leaf facts.
        let leaf_exts = leaf_cert.extensions.expect("leaf extensions present");
        let leaf_bc = refineid_cms::x509::extract_basic_constraints(leaf_exts);
        assert!(!leaf_bc.ca);
        assert!(leaf_bc.critical);

        let leaf_ku = refineid_cms::x509::extract_key_usage(leaf_exts).expect("leaf key usage");
        assert!(leaf_ku.digital_signature);
        assert!(leaf_ku.key_encipherment);
        assert!(!leaf_ku.key_cert_sign);

        let leaf_eku = refineid_cms::x509::extract_extended_key_usage(leaf_exts);
        assert!(
            leaf_eku
                .iter()
                .any(|oid| oid == "1.3.6.1.5.5.7.3.1" || oid.contains("serverAuth"))
        );

        assert!(
            leaf_exts
                .windows(
                    refineid_cms::oid::known::AUTHORITY_KEY_IDENTIFIER
                        .as_bytes()
                        .len()
                )
                .any(|w| w == refineid_cms::oid::known::AUTHORITY_KEY_IDENTIFIER.as_bytes())
        );
        assert!(
            !leaf_exts
                .windows(refineid_cms::oid::known::NAME_CONSTRAINTS.as_bytes().len())
                .any(|w| w == refineid_cms::oid::known::NAME_CONSTRAINTS.as_bytes())
        );

        // Validity windows.
        assert!(leaf_cert.not_after > leaf_cert.not_before);
        assert!(root_cert.not_after > root_cert.not_before);
        assert!(root_cert.not_after > leaf_cert.not_after);

        // Leaf names.
        assert!(
            chain
                .leaf_der
                .windows(COMMON_NAME.len())
                .any(|window| window == COMMON_NAME.as_bytes())
        );
        assert!(
            chain
                .leaf_der
                .windows(b"localhost".len())
                .any(|window| window == b"localhost")
        );
        assert!(
            chain
                .leaf_der
                .windows(values::LOOPBACK_ADDRESS.len())
                .any(|window| window == values::LOOPBACK_ADDRESS)
        );
        assert!(
            chain
                .leaf_der
                .windows(values::LOOPBACK_IPV6_ADDRESS.len())
                .any(|window| window == values::LOOPBACK_IPV6_ADDRESS)
        );
    }

    #[test]
    fn deterministic_issuance_and_alias() {
        let server_key = p256::ecdsa::SigningKey::from_slice(&[SERVER_SECRET_FILL; SECRET_LENGTH])
            .expect("server key parses");
        let root_key = p256::ecdsa::SigningKey::from_slice(&[ROOT_SECRET_FILL; SECRET_LENGTH])
            .expect("root key parses");
        let server_point = server_key.verifying_key().to_sec1_point(false);

        let chain1 = issue_chain_with(
            server_point.as_bytes(),
            &root_key,
            TEST_ROOT_SERIAL,
            TEST_LEAF_SERIAL,
            NOT_BEFORE,
        )
        .expect("deterministic chain 1");

        let chain2 = issue_chain_with(
            server_point.as_bytes(),
            &root_key,
            TEST_ROOT_SERIAL,
            TEST_LEAF_SERIAL,
            NOT_BEFORE,
        )
        .expect("deterministic chain 2");

        assert_eq!(chain1, chain2);

        // Convenience make alias works.
        let chain_make: Result<IssuedChain, LocalhostError> =
            make(server_point.as_bytes(), NOT_BEFORE);
        assert!(chain_make.is_ok());
    }

    #[test]
    fn accepts_spki_and_compressed_sec1() {
        let server_key = p256::ecdsa::SigningKey::from_slice(&[SERVER_SECRET_FILL; SECRET_LENGTH])
            .expect("server key parses");
        let uncompressed = server_key.verifying_key().to_sec1_point(false);
        let compressed = server_key.verifying_key().to_sec1_point(true);
        let spki = subject_public_key_info(uncompressed.as_bytes()).expect("spki");

        let chain_from_spki = issue_chain(&spki, NOT_BEFORE).expect("issues from SPKI");
        let chain_from_comp =
            issue_chain(compressed.as_bytes(), NOT_BEFORE).expect("issues from compressed SEC1");

        assert!(!chain_from_spki.leaf_der.is_empty());
        assert!(!chain_from_comp.leaf_der.is_empty());
    }

    #[test]
    fn rejects_invalid_public_key() {
        assert_eq!(
            issue_chain(&[], NOT_BEFORE),
            Err(LocalhostError::InvalidKey)
        );
        assert_eq!(
            issue_chain(&[0_u8; SECRET_LENGTH], NOT_BEFORE),
            Err(LocalhostError::InvalidKey)
        );
    }

    #[test]
    fn unrepresentable_window_refuses() {
        let key = p256::ecdsa::SigningKey::from_slice(&[SERVER_SECRET_FILL; SECRET_LENGTH])
            .expect("key parses");
        let point = key.verifying_key().to_sec1_point(false);
        let outcome = issue_chain(point.as_bytes(), i64::MIN);
        assert_eq!(outcome, Err(LocalhostError::UnrepresentableTime));
    }
}
