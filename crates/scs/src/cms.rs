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

//! Minimal detached CMS SignedData for the SCS `cms-pades` form.
//!
//! The caller supplies the document digest; the card signs the DER SET
//! of signed attributes (content-type, message-digest, signing-time,
//! and signing-certificate-v2 per v1.3 sec.4.4 and the ETSI PAdES
//! profile), and the finished SignedData carries the certificate chain
//! and the signature with the content itself detached -- the PAdES
//! shape a signing service embeds into the document (DVV SCS
//! specification v1.3 sec.2.6.2).

use refineid_ber::BerTlvAny;
use refineid_cms::oid::known;
use refineid_digest::HashAlg;

use crate::der;
use crate::error::TransactionError;
use crate::purpose::KeyAlgorithm;

/// DER tag: SEQUENCE, as the parser reports it.
const TAG_SEQUENCE: u16 = der::TAG_SEQUENCE as u16;

/// DER tag: INTEGER, as the parser reports it.
const TAG_INTEGER: u16 = der::TAG_INTEGER as u16;

/// DER tag: explicit [0], as the parser reports it.
const TAG_EXPLICIT_ZERO: u16 = der::TAG_CONTEXT_ZERO as u16;

/// SignedData and SignerInfo version.
const CMS_VERSION: u8 = 1;

/// Minimal detached CMS SignedData under construction.
///
/// The issuer name and serial number travel through unconsulted: they
/// are validated TLV fragments the finished SignedData re-emits, and
/// this value is short-lived -- prepared, signed, assembled.
pub struct DetachedCms {
    certificates: Vec<Vec<u8>>,
    digest_oid: &'static [u8],
    ecdsa: bool,
    issuer_name: Vec<u8>,
    serial_number: Vec<u8>,
    signature_algorithm: Vec<u8>,
    signed_attributes: Vec<u8>,
}

impl DetachedCms {
    /// The DER SET of signed attributes: the exact bytes the card
    /// signs.
    #[must_use]
    pub fn signed_attributes(&self) -> &[u8] {
        &self.signed_attributes
    }

    /// Assemble the finished SignedData around the card's signature
    /// over [`signed_attributes`](Self::signed_attributes).
    pub fn signed_data(&self, signature: &[u8]) -> Result<Vec<u8>, TransactionError> {
        let fail = || TransactionError::internal_error("assemble CMS SignedData");
        let signature = if self.ecdsa {
            crate::codec::ecdsa_signature_der(signature).map_err(|()| fail())?
        } else {
            signature.to_vec()
        };
        let signer_identifier = der::sequence(&[
            &self.issuer_name,
            &der::unsigned_integer(&self.serial_number).map_err(|()| fail())?,
        ])
        .map_err(|()| fail())?;
        let signer_info = der::sequence(&[
            &der::integer(CMS_VERSION).map_err(|()| fail())?,
            &signer_identifier,
            &der::sequence(&[&der::oid(self.digest_oid).map_err(|()| fail())?])
                .map_err(|()| fail())?,
            &der::retag(der::TAG_CONTEXT_ZERO, &self.signed_attributes).map_err(|()| fail())?,
            &self.signature_algorithm,
            &der::octet_string(&signature).map_err(|()| fail())?,
        ])
        .map_err(|()| fail())?;
        let mut chain = Vec::new();
        for certificate in &self.certificates {
            chain.extend_from_slice(certificate);
        }
        let content = der::sequence(&[
            &der::integer(CMS_VERSION).map_err(|()| fail())?,
            &der::set(&[
                &der::sequence(&[&der::oid(self.digest_oid).map_err(|()| fail())?])
                    .map_err(|()| fail())?,
            ])
            .map_err(|()| fail())?,
            &der::sequence(&[&der::oid(known::DATA.as_bytes()).map_err(|()| fail())?])
                .map_err(|()| fail())?,
            &der::tagged(der::TAG_CONTEXT_ZERO, &chain).map_err(|()| fail())?,
            &der::set(&[&signer_info]).map_err(|()| fail())?,
        ])
        .map_err(|()| fail())?;
        der::sequence(&[
            &der::oid(known::SIGNED_DATA.as_bytes()).map_err(|()| fail())?,
            &der::tagged(der::TAG_CONTEXT_ZERO, &content).map_err(|()| fail())?,
        ])
        .map_err(|()| fail())
    }
}

/// Prepare the attribute set for `digest` under `hash`, signed at
/// `signed_at_unix`.
///
/// Refuses a digest whose length does not match the named hash, and
/// an empty chain -- the leaf supplies the signer identifier and the
/// signing-certificate hash.
pub fn prepare(
    digest: &[u8],
    certificates: &[Vec<u8>],
    hash: HashAlg,
    key_algorithm: KeyAlgorithm,
    signed_at_unix: i64,
) -> Result<DetachedCms, TransactionError> {
    if digest.len() != hash.digest_len() {
        return Err(TransactionError::bad_request(format!(
            "{} digest must be {} bytes, got {}",
            crate::hash::scs_name(hash),
            hash.digest_len(),
            digest.len()
        )));
    }
    let leaf = certificates
        .first()
        .ok_or_else(|| TransactionError::bad_request("leaf certificate is not DER X.509"))?;
    let (issuer_name, serial_number) = signer_identifier(leaf)
        .ok_or_else(|| TransactionError::bad_request("leaf certificate is not DER X.509"))?;
    let digest_oid = match hash {
        HashAlg::Sha1 => known::SHA1.as_bytes(),
        HashAlg::Sha256 => known::SHA256.as_bytes(),
        HashAlg::Sha384 => known::SHA384.as_bytes(),
        HashAlg::Sha512 => known::SHA512.as_bytes(),
    };
    let signature_algorithm = signature_algorithm(hash, key_algorithm)?;
    let signed_time = crate::time::format_utc_time(signed_at_unix)
        .map_err(|_| TransactionError::internal_error("assemble CMS attributes"))?;
    let attributes = der::set(&[
        &attribute(
            known::CONTENT_TYPE.as_bytes(),
            &der::oid(known::DATA.as_bytes()).map_err(|()| attributes_failure())?,
        )
        .map_err(|()| attributes_failure())?,
        &attribute(
            known::MESSAGE_DIGEST.as_bytes(),
            &der::octet_string(digest).map_err(|()| attributes_failure())?,
        )
        .map_err(|()| attributes_failure())?,
        &attribute(
            known::SIGNING_TIME.as_bytes(),
            &der::tagged(crate::time::UTC_TIME_TAG, &signed_time)
                .map_err(|()| attributes_failure())?,
        )
        .map_err(|()| attributes_failure())?,
        &attribute(
            known::SIGNING_CERTIFICATE_V2.as_bytes(),
            &signing_certificate_v2(leaf, hash).map_err(|()| attributes_failure())?,
        )
        .map_err(|()| attributes_failure())?,
    ])
    .map_err(|()| attributes_failure())?;
    Ok(DetachedCms {
        certificates: certificates.to_vec(),
        digest_oid,
        ecdsa: key_algorithm == KeyAlgorithm::Ecdsa,
        issuer_name,
        serial_number,
        signature_algorithm,
        signed_attributes: attributes,
    })
}

/// The attribute assembly failed.
fn attributes_failure() -> TransactionError {
    TransactionError::internal_error("assemble CMS attributes")
}

/// One `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF }`.
fn attribute(oid: &[u8], value_der: &[u8]) -> Result<Vec<u8>, ()> {
    let oid = der::oid(oid)?;
    let values = der::set(&[value_der])?;
    der::sequence(&[&oid, &values])
}

/// `SigningCertificateV2` (RFC 5035 sec.3), binding the signature to
/// the exact leaf that made it.
///
/// `issuerSerial` is omitted: it is OPTIONAL, and the certificate
/// hash already pins the leaf uniquely. The hash-algorithm default
/// (SHA-256) is omitted when it is the value, per DER.
fn signing_certificate_v2(leaf: &[u8], hash: HashAlg) -> Result<Vec<u8>, ()> {
    let cert_hash = match hash {
        HashAlg::Sha1 => refineid_digest::Sha1::of(leaf).as_bytes().to_vec(),
        HashAlg::Sha256 => refineid_digest::Sha256::of(leaf).as_bytes().to_vec(),
        HashAlg::Sha384 => refineid_digest::Sha384::of(leaf).as_bytes().to_vec(),
        HashAlg::Sha512 => refineid_digest::Sha512::of(leaf).as_bytes().to_vec(),
    };
    let mut cert_id = Vec::new();
    if hash != HashAlg::Sha256 {
        let oid = match hash {
            HashAlg::Sha1 => known::SHA1.as_bytes(),
            HashAlg::Sha256 => known::SHA256.as_bytes(),
            HashAlg::Sha384 => known::SHA384.as_bytes(),
            HashAlg::Sha512 => known::SHA512.as_bytes(),
        };
        cert_id.extend_from_slice(&der::sequence(&[&der::oid(oid)?])?);
    }
    cert_id.extend_from_slice(&der::octet_string(&cert_hash)?);
    let cert_id = der::sequence(&[cert_id.as_slice()])?;
    der::sequence(&[&der::sequence(&[&cert_id])?])
}

/// The `SignerInfo.signatureAlgorithm` for `hash` under `key`: PKCS#1
/// `rsaEncryption` for RSA, `ecdsa-with-SHA*` without parameters for
/// ECDSA (v1.3 sec.4.4, RFC 5758 sec.3.2).
fn signature_algorithm(
    hash: HashAlg,
    key_algorithm: KeyAlgorithm,
) -> Result<Vec<u8>, TransactionError> {
    if key_algorithm == KeyAlgorithm::Rsa {
        let oid = der::oid(known::RSA_ENCRYPTION.as_bytes())
            .map_err(|()| TransactionError::internal_error("assemble CMS attributes"))?;
        let null = der::null()
            .map_err(|()| TransactionError::internal_error("assemble CMS attributes"))?;
        return der::sequence(&[&oid, &null])
            .map_err(|()| TransactionError::internal_error("assemble CMS attributes"));
    }
    let oid = match hash {
        HashAlg::Sha256 => known::ECDSA_WITH_SHA256.as_bytes(),
        HashAlg::Sha384 => known::ECDSA_WITH_SHA384.as_bytes(),
        HashAlg::Sha512 => known::ECDSA_WITH_SHA512.as_bytes(),
        HashAlg::Sha1 => {
            return Err(TransactionError::internal_error(
                "refused hash algorithm reached signing",
            ));
        }
    };
    der::sequence(&[
        &der::oid(oid).map_err(|()| TransactionError::internal_error("assemble CMS attributes"))?
    ])
    .map_err(|()| TransactionError::internal_error("assemble CMS attributes"))
}

/// The leaf's issuer name TLV and serial content bytes.
fn signer_identifier(leaf: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let certificate = BerTlvAny::parse(leaf).ok()?;
    if certificate.tag() != TAG_SEQUENCE {
        return None;
    }
    let outer = child_values(certificate.value())?;
    let tbs = outer.first()?;
    let mut rest = tbs.value();
    if let Ok(first) = BerTlvAny::parse(rest) {
        if first.tag() == TAG_EXPLICIT_ZERO {
            rest = rest.get(first.size()..)?;
        }
    } else {
        return None;
    }
    let serial = BerTlvAny::parse(rest).ok()?;
    if serial.tag() != TAG_INTEGER {
        return None;
    }
    rest = rest.get(serial.size()..)?;
    let signature_algorithm = BerTlvAny::parse(rest).ok()?;
    rest = rest.get(signature_algorithm.size()..)?;
    let issuer = BerTlvAny::parse(rest).ok()?;
    // The full issuer Name TLV: tag and length octets plus the value.
    let issuer_tlv = rest.get(..issuer.size())?.to_vec();
    let serial_value = serial.value().strip_prefix(&[0]).unwrap_or(serial.value());
    if serial_value.is_empty() {
        return None;
    }
    Some((issuer_tlv, serial_value.to_vec()))
}

/// The children of a constructed value, or `None` when the value is
/// not a clean child sequence.
fn child_values(value: &[u8]) -> Option<Vec<BerTlvAny<'_>>> {
    let mut children = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let child = BerTlvAny::parse(rest).ok()?;
        children.push(child);
        rest = rest.get(child.size()..)?;
    }
    Some(children)
}

#[cfg(test)]
mod tests {
    use super::prepare;
    use crate::purpose::KeyAlgorithm;
    use crate::test_support::mint_certificate;
    use refineid_digest::{HashAlg, SHA256_LEN};

    /// Unix seconds of 2023-11-14T22:13:20Z.
    const SIGNED_AT: i64 = 1_700_000_000;

    /// A SHA-256 digest over the minted leaf builds attributes and a
    /// SignedData carrying the signature.
    #[test]
    fn happy_path_builds_signed_data() {
        let minted = mint_certificate();
        let digest = refineid_digest::Sha256::of(b"document").into_bytes();
        assert_eq!(digest.len(), SHA256_LEN);
        let prepared = prepare(
            &digest,
            &[minted.der],
            HashAlg::Sha256,
            KeyAlgorithm::Rsa,
            SIGNED_AT,
        )
        .expect("prepares");
        assert!(!prepared.signed_attributes().is_empty());
        let signed = prepared.signed_data(b"card-signature").expect("assembles");
        // The finished value parses as CMS SignedData.
        refineid_cms::signed_data::SignedData::parse(&signed).expect("parses as SignedData");
        assert!(
            signed
                .windows(b"card-signature".len())
                .any(|window| window == b"card-signature")
        );
    }

    /// The ECDSA form converts the raw pair and keeps the RSA form
    /// byte-identical.
    #[test]
    fn ecdsa_signs_der_rsa_signs_raw() {
        use p256::ecdsa::signature::Signer as _;
        let minted = mint_certificate();
        let digest = refineid_digest::Sha256::of(b"document").into_bytes();
        let chain = [minted.der];
        let prepared = prepare(
            &digest,
            &chain,
            HashAlg::Sha256,
            KeyAlgorithm::Ecdsa,
            SIGNED_AT,
        )
        .expect("prepares");
        let signature: p256::ecdsa::Signature = minted.key.sign(prepared.signed_attributes());
        let signed = prepared
            .signed_data(signature.to_bytes().as_slice())
            .expect("assembles");
        refineid_cms::signed_data::SignedData::parse(&signed).expect("parses as SignedData");
        let prepared = prepare(
            &digest,
            &chain,
            HashAlg::Sha256,
            KeyAlgorithm::Rsa,
            SIGNED_AT,
        )
        .expect("prepares");
        let signed = prepared.signed_data(b"card-signature").expect("assembles");
        assert!(
            signed
                .windows(b"card-signature".len())
                .any(|window| window == b"card-signature")
        );
    }

    /// Wrong digests, unknown hashes, and missing leaves are refused.
    #[test]
    fn deviations_are_refused() {
        let minted = mint_certificate();
        assert!(
            prepare(
                b"short",
                std::slice::from_ref(&minted.der),
                HashAlg::Sha256,
                KeyAlgorithm::Rsa,
                SIGNED_AT
            )
            .is_err()
        );
        let digest = refineid_digest::Sha256::of(b"document").into_bytes();
        assert!(prepare(&digest, &[], HashAlg::Sha256, KeyAlgorithm::Rsa, SIGNED_AT).is_err());
        assert!(
            prepare(
                &digest,
                &[b"not-a-cert".to_vec()],
                HashAlg::Sha256,
                KeyAlgorithm::Rsa,
                SIGNED_AT
            )
            .is_err()
        );
    }
}
