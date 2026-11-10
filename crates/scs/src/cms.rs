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
//! of signed attributes (content-type and message-digest, RFC 5652
//! sec.5.4), and the finished SignedData carries the certificate chain
//! and the signature with the content itself detached -- the PAdES
//! shape a signing service embeds into the document (DVV SCS
//! specification v1.3 sec.2.6.2).

use refineid_ber::BerTlvAny;
use refineid_cms::oid::known;
use refineid_digest::HashAlg;

use crate::der;
use crate::error::TransactionError;
use crate::hash;

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
    issuer_name: Vec<u8>,
    serial_number: Vec<u8>,
    digest_oid: &'static [u8],
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
    ///
    /// The builders below fail only on lengths no SCS document
    /// reaches; an encoding failure answers an empty encoding, which
    /// no consumer accepts silently.
    #[must_use]
    pub fn signed_data(&self, signature: &[u8]) -> Vec<u8> {
        let digest_algorithm = der::sequence(&[
            &der::oid(self.digest_oid).unwrap_or_default(),
            &der::null().unwrap_or_default(),
        ])
        .unwrap_or_default();
        let signer_identifier = der::sequence(&[
            &self.issuer_name,
            &der::unsigned_integer(&self.serial_number).unwrap_or_default(),
        ])
        .unwrap_or_default();
        let signer_info = der::sequence(&[
            &der::integer(CMS_VERSION).unwrap_or_default(),
            &signer_identifier,
            &digest_algorithm,
            &der::tagged(der::TAG_CONTEXT_ZERO, &self.signed_attributes).unwrap_or_default(),
            &digest_algorithm,
            &der::octet_string(signature).unwrap_or_default(),
        ])
        .unwrap_or_default();
        let mut chain = Vec::new();
        for certificate in &self.certificates {
            chain.extend_from_slice(certificate);
        }
        let content = der::sequence(&[
            &der::integer(CMS_VERSION).unwrap_or_default(),
            &der::set(&[&digest_algorithm]).unwrap_or_default(),
            &der::sequence(&[&der::oid(known::DATA.as_bytes()).unwrap_or_default()])
                .unwrap_or_default(),
            &der::tagged(der::TAG_CONTEXT_ZERO, &chain).unwrap_or_default(),
            &der::set(&[&signer_info]).unwrap_or_default(),
        ])
        .unwrap_or_default();
        der::sequence(&[
            &der::oid(known::SIGNED_DATA.as_bytes()).unwrap_or_default(),
            &der::tagged(der::TAG_CONTEXT_ZERO, &content).unwrap_or_default(),
        ])
        .unwrap_or_default()
    }
}

/// Prepare the attribute set for `digest` under `hash_name`.
///
/// Refuses a digest whose length does not match the named hash, and
/// an empty chain -- the leaf supplies the signer identifier.
pub fn prepare(
    digest: &[u8],
    certificates: &[Vec<u8>],
    hash_name: &str,
) -> Result<DetachedCms, TransactionError> {
    let hash = hash::hash_named(hash_name).ok_or_else(|| {
        TransactionError::bad_request(format!("unsupported CMS digest algorithm {hash_name}"))
    })?;
    if digest.len() != hash.digest_len() {
        return Err(TransactionError::bad_request(format!(
            "{hash_name} digest must be {} bytes, got {}",
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
    let attributes = der::set(&[
        &der::sequence(&[
            &der::oid(known::CONTENT_TYPE.as_bytes()).unwrap_or_default(),
            &der::set(&[&der::oid(known::DATA.as_bytes()).unwrap_or_default()]).unwrap_or_default(),
        ])
        .unwrap_or_default(),
        &der::sequence(&[
            &der::oid(known::MESSAGE_DIGEST.as_bytes()).unwrap_or_default(),
            &der::set(&[&der::octet_string(digest).unwrap_or_default()]).unwrap_or_default(),
        ])
        .unwrap_or_default(),
    ])
    .map_err(|()| TransactionError::internal_error("assemble CMS attributes"))?;
    Ok(DetachedCms {
        certificates: certificates.to_vec(),
        issuer_name,
        serial_number,
        digest_oid,
        signed_attributes: attributes,
    })
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
    use crate::test_support::mint_certificate;
    use refineid_digest::SHA256_LEN;

    /// A SHA-256 digest over the minted leaf builds attributes and a
    /// SignedData carrying the signature.
    #[test]
    fn happy_path_builds_signed_data() {
        let minted = mint_certificate();
        let digest = refineid_digest::Sha256::of(b"document").into_bytes();
        assert_eq!(digest.len(), SHA256_LEN);
        let prepared = prepare(&digest, &[minted.der], "SHA256").expect("prepares");
        assert!(!prepared.signed_attributes().is_empty());
        let signed = prepared.signed_data(b"card-signature");
        // The finished value is a ContentInfo wrapping SignedData.
        let outer = refineid_ber::BerTlvAny::parse(&signed).expect("parses");
        assert_eq!(outer.tag(), super::TAG_SEQUENCE);
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
        assert!(prepare(b"short", std::slice::from_ref(&minted.der), "SHA256").is_err());
        let digest = refineid_digest::Sha256::of(b"document").into_bytes();
        assert!(prepare(&digest, std::slice::from_ref(&minted.der), "SHA224").is_err());
        assert!(prepare(&digest, &[], "SHA256").is_err());
        assert!(prepare(&digest, &[b"not-a-cert".to_vec()], "SHA256").is_err());
    }
}
