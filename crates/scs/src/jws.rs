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

//! Verification of the `begin` transaction's compact JWS against the
//! relying service's certificate (DVV SCS specification v1.3; RFC
//! 7515).
//!
//! The certificate rides in the payload itself; what verification
//! establishes is that the party who published the server key also
//! authorised this transaction, and that its certificate is inside
//! its validity window. Chain building is deliberately not attempted
//! here -- the origin-bound challenge, not the certificate chain, is
//! what protects the holder.

use std::time::SystemTime;

use elliptic_curve::sec1::ToSec1Point as _;
use refineid_ber::BerTlvAny;
use signature::Verifier as _;

use crate::der;
use crate::error::TransactionError;
use crate::time;

/// DER tag: SEQUENCE, as the parser reports it.
const TAG_SEQUENCE: u16 = der::TAG_SEQUENCE as u16;

/// DER tag: INTEGER, as the parser reports it.
const TAG_INTEGER: u16 = der::TAG_INTEGER as u16;

/// DER tag: explicit [0] (certificate version), as reported.
const TAG_EXPLICIT_ZERO: u16 = der::TAG_CONTEXT_ZERO as u16;

/// Raw ES256 JWS signatures are r||s at 64 bytes (RFC 7518 sec.3.4).
const ES256_SIGNATURE_LENGTH: usize = 64;

/// Why the JWS is refused, or `None` when it verifies at `now`.
pub fn refusal(
    algorithm: &str,
    certificate_der: &[u8],
    signing_input: &[u8],
    signature: &[u8],
    now: SystemTime,
) -> Option<TransactionError> {
    if let Some(refusal) = validity_refusal(certificate_der, now) {
        return Some(refusal);
    }
    match algorithm {
        "RS256" => rsa_refusal(certificate_der, signing_input, signature),
        "ES256" => ec_refusal(certificate_der, signing_input, signature),
        other => Some(TransactionError::bad_request(format!(
            "unsupported JWS algorithm {other}"
        ))),
    }
}

/// Why the validity window cannot be read.
enum WindowFailure {
    /// The bytes are not a certificate reaching a validity.
    Malformed,
    /// The window's times do not parse.
    Unreadable,
}

/// Why the certificate's validity window refuses `now`, or `None`.
///
/// The window is the two Time fields of TBSCertificate (RFC 5280
/// sec.4.1.2.5), located positionally: optional version, serial,
/// signature algorithm, issuer, then validity.
fn validity_refusal(certificate_der: &[u8], now: SystemTime) -> Option<TransactionError> {
    let (start, end) = match validity_window(certificate_der) {
        Ok(window) => window,
        Err(WindowFailure::Malformed) => {
            return Some(TransactionError::bad_request("serverCert is not DER X.509"));
        }
        Err(WindowFailure::Unreadable) => {
            return Some(TransactionError::bad_request(
                "serverCert has no readable validity window",
            ));
        }
    };
    let now = match time::system_unix(now) {
        Ok(now) => now,
        Err(_) => return Some(TransactionError::internal_error("read the system clock")),
    };
    if now < start || now > end {
        return Some(TransactionError::forbidden(
            "serverCert is not currently valid",
        ));
    }
    None
}

/// The validity window as unix seconds.
fn validity_window(certificate_der: &[u8]) -> Result<(i64, i64), WindowFailure> {
    let certificate = BerTlvAny::parse(certificate_der).map_err(|_| WindowFailure::Malformed)?;
    if certificate.tag() != TAG_SEQUENCE {
        return Err(WindowFailure::Malformed);
    }
    let outer = child_values(certificate.value()).ok_or(WindowFailure::Malformed)?;
    let tbs = outer.first().ok_or(WindowFailure::Malformed)?;
    let children = child_values(tbs.value()).ok_or(WindowFailure::Malformed)?;
    let mut cursor = children.as_slice();
    if matches!(cursor.first(), Some(first) if first.tag() == TAG_EXPLICIT_ZERO) {
        cursor = cursor.get(1..).ok_or(WindowFailure::Malformed)?;
    }
    let [_serial, _signature_algorithm, _issuer, validity, ..] = cursor else {
        return Err(WindowFailure::Malformed);
    };
    let window = child_values(validity.value()).ok_or(WindowFailure::Malformed)?;
    let [not_before, not_after] = window.as_slice() else {
        return Err(WindowFailure::Malformed);
    };
    let start = time::parse_time(not_before.tag(), not_before.value())
        .map_err(|_| WindowFailure::Unreadable)?;
    let end = time::parse_time(not_after.tag(), not_after.value())
        .map_err(|_| WindowFailure::Unreadable)?;
    Ok((start, end))
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

/// TBSCertificate children before the subjectPublicKeyInfo:
/// serial, signature algorithm, issuer, validity, subject.
const TBS_CHILDREN_BEFORE_SPKI: usize = 5;

/// The certificate's DER SPKI, located positionally after the
/// version, serial, signature algorithm, issuer, validity, and
/// subject.
fn spki_der(certificate_der: &[u8]) -> Option<Vec<u8>> {
    let certificate = BerTlvAny::parse(certificate_der).ok()?;
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
    for _ in 0..TBS_CHILDREN_BEFORE_SPKI {
        let child = BerTlvAny::parse(rest).ok()?;
        rest = rest.get(child.size()..)?;
    }
    let spki = BerTlvAny::parse(rest).ok()?;
    rest.get(..spki.size()).map(<[u8]>::to_vec)
}

/// Verify an RS256 JWS against the certificate's RSA key.
fn rsa_refusal(
    certificate_der: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Option<TransactionError> {
    let spki = match spki_der(certificate_der) {
        Some(spki) => spki,
        None => return Some(TransactionError::bad_request("serverCert is not DER X.509")),
    };
    match rsa_verify(&spki, signing_input, signature) {
        None => Some(TransactionError::bad_request("serverCert is not DER X.509")),
        Some(false) => Some(TransactionError::forbidden(
            "begin transaction JWS signature is invalid",
        )),
        Some(true) => None,
    }
}

/// The RSA key of an SPKI, or `None` when the SPKI does not carry
/// one.
fn rsa_key(spki_der: &[u8]) -> Option<refineid_cms::rsa::RsaPublicKey> {
    use spki::der::Decode as _;
    let info = spki::SubjectPublicKeyInfoRef::from_der(spki_der).ok()?;
    if info.algorithm.oid.as_bytes() != refineid_cms::oid::known::RSA_ENCRYPTION.as_bytes() {
        return None;
    }
    let bits = info.subject_public_key.as_bytes()?;
    let sequence = BerTlvAny::parse(bits).ok()?;
    if sequence.tag() != TAG_SEQUENCE {
        return None;
    }
    let children = child_values(sequence.value())?;
    let [modulus, exponent] = children.as_slice() else {
        return None;
    };
    if modulus.tag() != TAG_INTEGER || exponent.tag() != TAG_INTEGER {
        return None;
    }
    let key = refineid_cms::rsa::RsaPublicKey {
        modulus: refineid_cms::rsa::RsaModulus::try_from_pkcs1(strip_sign_byte(modulus.value()))
            .ok()?,
        exponent: refineid_cms::rsa::RsaPublicExponent::try_from_pkcs1(strip_sign_byte(
            exponent.value(),
        ))
        .ok()?,
    };
    Some(key)
}

/// Verify the RS256 signature; `None` when the key does not parse.
fn rsa_verify(spki_der: &[u8], signing_input: &[u8], signature: &[u8]) -> Option<bool> {
    let key = rsa_key(spki_der)?;
    let signature = refineid_cms::container::Signature::new(signature.to_vec());
    Some(
        key.verify_pkcs1v15_sha256(signing_input, &signature)
            .is_ok(),
    )
}

/// Strip the DER INTEGER sign byte, when present.
fn strip_sign_byte(content: &[u8]) -> &[u8] {
    content.strip_prefix(&[0]).unwrap_or(content)
}

/// Verify an ES256 JWS against the certificate's P-256 key.
fn ec_refusal(
    certificate_der: &[u8],
    signing_input: &[u8],
    signature: &[u8],
) -> Option<TransactionError> {
    if signature.len() != ES256_SIGNATURE_LENGTH {
        return Some(TransactionError::bad_request(
            "ES256 signature is not raw r||s",
        ));
    }
    let spki = match spki_der(certificate_der) {
        Some(spki) => spki,
        None => return Some(TransactionError::bad_request("serverCert is not DER X.509")),
    };
    let key = match crate::codec::p256_spki_key(&spki) {
        Ok(key) => key,
        Err(()) => return Some(TransactionError::bad_request("serverCert is not DER X.509")),
    };
    let verifying =
        match p256::ecdsa::VerifyingKey::from_sec1_bytes(key.to_sec1_point(false).as_bytes()) {
            Ok(verifying) => verifying,
            Err(_) => return Some(TransactionError::bad_request("serverCert is not DER X.509")),
        };
    let signature = match p256::ecdsa::Signature::from_slice(signature) {
        Ok(signature) => signature,
        Err(_) => {
            return Some(TransactionError::bad_request(
                "ES256 signature is not raw r||s",
            ));
        }
    };
    match verifying.verify(signing_input, &signature) {
        Ok(()) => None,
        Err(_) => Some(TransactionError::forbidden(
            "begin transaction JWS signature is invalid",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::refusal;
    use crate::error::TransactionError;
    use crate::test_support;
    use std::time::{Duration, UNIX_EPOCH};

    /// Unix seconds of 2023-11-14T22:13:20Z, inside every test window.
    const TEST_NOW_SECONDS: u64 = 1_700_000_000;

    /// A moment inside the test windows.
    fn test_now() -> std::time::SystemTime {
        UNIX_EPOCH + Duration::from_secs(TEST_NOW_SECONDS)
    }

    /// A valid ES256 JWS over the test certificate verifies.
    #[test]
    fn valid_jws_verifies() {
        use p256::ecdsa::signature::Signer as _;
        let minted = test_support::mint_certificate();
        let signing_input = b"header.payload";
        let signature: p256::ecdsa::Signature = minted.key.sign(signing_input);
        assert_eq!(
            refusal(
                "ES256",
                &minted.der,
                signing_input,
                signature.to_bytes().as_slice(),
                test_now()
            ),
            None
        );
    }

    /// A signature over other bytes is forbidden, not malformed.
    #[test]
    fn wrong_signature_is_forbidden() {
        use p256::ecdsa::signature::Signer as _;
        let minted = test_support::mint_certificate();
        let signature: p256::ecdsa::Signature = minted.key.sign(b"other.payload");
        assert_eq!(
            refusal(
                "ES256",
                &minted.der,
                b"header.payload",
                signature.to_bytes().as_slice(),
                test_now()
            ),
            Some(TransactionError::forbidden(
                "begin transaction JWS signature is invalid"
            ))
        );
    }

    /// An expired certificate is forbidden before any cryptography.
    #[test]
    fn expired_certificate_is_forbidden() {
        let minted = test_support::mint_certificate_window("200101000000Z", "200201000000Z");
        assert_eq!(
            refusal(
                "ES256",
                &minted.der,
                b"in",
                &[0_u8; super::ES256_SIGNATURE_LENGTH],
                test_now()
            ),
            Some(TransactionError::forbidden(
                "serverCert is not currently valid"
            ))
        );
    }

    /// Unknown algorithms and malformed certificates are refused as
    /// bad requests.
    #[test]
    fn unknown_algorithm_and_malformed_cert_are_refused() {
        let minted = test_support::mint_certificate();
        assert_eq!(
            refusal(
                "HS256",
                &minted.der,
                b"in",
                &[0_u8; super::ES256_SIGNATURE_LENGTH],
                test_now()
            ),
            Some(TransactionError::bad_request(
                "unsupported JWS algorithm HS256"
            ))
        );
        assert_eq!(
            refusal(
                "ES256",
                b"not-a-certificate",
                b"in",
                &[0_u8; super::ES256_SIGNATURE_LENGTH],
                test_now()
            ),
            Some(TransactionError::bad_request("serverCert is not DER X.509"))
        );
        assert_eq!(
            refusal("ES256", &minted.der, b"in", b"short", test_now()),
            Some(TransactionError::bad_request(
                "ES256 signature is not raw r||s"
            ))
        );
    }
}
