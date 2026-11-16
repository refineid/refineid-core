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

use refineid_cms::ecdsa::EcdsaError;
use refineid_cms::x509::{
    Certificate, EcCurve, MessageSignatureAlgorithm, PublicKeyAlgorithm, SpkiDer, VerifyError,
    X509Error,
};

use crate::error::TransactionError;
use crate::time;

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
    let certificate = match Certificate::from_der(certificate_der) {
        Ok(certificate) => certificate,
        Err(X509Error::InvalidTime) => {
            return Some(TransactionError::bad_request(
                "serverCert has no readable validity window",
            ));
        }
        Err(_) => {
            return Some(TransactionError::bad_request("serverCert is not DER X.509"));
        }
    };
    let Ok(now) = time::system_date_time(now) else {
        return Some(TransactionError::internal_error("read the system clock"));
    };
    if now < certificate.not_before || now > certificate.not_after {
        return Some(TransactionError::forbidden(
            "serverCert is not currently valid",
        ));
    }
    match algorithm {
        "RS256" => rsa_refusal(certificate.spki, signing_input, signature),
        "ES256" => ec_refusal(certificate.spki, signing_input, signature),
        other => Some(TransactionError::bad_request(format!(
            "unsupported JWS algorithm {other}"
        ))),
    }
}

/// Verify an RS256 JWS against the certificate's RSA key.
fn rsa_refusal(
    spki: SpkiDer<'_>,
    signing_input: &[u8],
    signature: &[u8],
) -> Option<TransactionError> {
    match spki.verify_message_signature(
        MessageSignatureAlgorithm::RsaPkcs1Sha256,
        signing_input,
        signature,
    ) {
        Ok(()) => None,
        Err(VerifyError::BadIssuerKey) => {
            Some(TransactionError::bad_request("serverCert is not DER X.509"))
        }
        Err(VerifyError::Rsa(_) | VerifyError::Ecdsa(_) | VerifyError::Unsupported(_)) => Some(
            TransactionError::forbidden("begin transaction JWS signature is invalid"),
        ),
    }
}

/// Verify an ES256 JWS against the certificate's P-256 key.
fn ec_refusal(
    spki: SpkiDer<'_>,
    signing_input: &[u8],
    signature: &[u8],
) -> Option<TransactionError> {
    if signature.len() != ES256_SIGNATURE_LENGTH {
        return Some(TransactionError::bad_request(
            "ES256 signature is not raw r||s",
        ));
    }
    if spki.algorithm() != PublicKeyAlgorithm::Ec(EcCurve::Secp256r1) {
        return Some(TransactionError::bad_request("serverCert is not DER X.509"));
    }
    match spki.verify_message_signature(
        MessageSignatureAlgorithm::EcdsaSha256Raw,
        signing_input,
        signature,
    ) {
        Ok(()) => None,
        Err(
            VerifyError::BadIssuerKey
            | VerifyError::Ecdsa(EcdsaError::BadModulus | EcdsaError::BadPublicKey),
        ) => Some(TransactionError::bad_request("serverCert is not DER X.509")),
        Err(VerifyError::Ecdsa(
            EcdsaError::BadSignature | EcdsaError::SigOutOfRange | EcdsaError::NotInvertible,
        )) => Some(TransactionError::bad_request(
            "ES256 signature is not raw r||s",
        )),
        Err(
            VerifyError::Ecdsa(EcdsaError::VerifyFailed)
            | VerifyError::Rsa(_)
            | VerifyError::Unsupported(_),
        ) => Some(TransactionError::forbidden(
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

    /// Byte value exceeding the P-256 curve order when repeated across a scalar.
    const ALL_ONES_BYTE: u8 = u8::MAX;

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

    /// Unknown algorithms, malformed or trailing-byte certificates, key-type
    /// mismatches, and out-of-range raw scalars are refused cleanly.
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
        let mut trailing = minted.der.clone();
        trailing.push(0);
        assert_eq!(
            refusal(
                "ES256",
                &trailing,
                b"in",
                &[0_u8; super::ES256_SIGNATURE_LENGTH],
                test_now()
            ),
            Some(TransactionError::bad_request("serverCert is not DER X.509"))
        );
        // RS256 against a P-256 certificate is rejected as a key mismatch.
        assert_eq!(
            refusal(
                "RS256",
                &minted.der,
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
        assert_eq!(
            refusal(
                "ES256",
                &minted.der,
                b"in",
                &[0_u8; super::ES256_SIGNATURE_LENGTH],
                test_now()
            ),
            Some(TransactionError::bad_request(
                "ES256 signature is not raw r||s"
            ))
        );
        assert_eq!(
            refusal(
                "ES256",
                &minted.der,
                b"in",
                &[ALL_ONES_BYTE; super::ES256_SIGNATURE_LENGTH],
                test_now()
            ),
            Some(TransactionError::bad_request(
                "ES256 signature is not raw r||s"
            ))
        );
    }

    /// Invalid validity windows and pre-epoch clocks return their distinct refusals.
    #[test]
    fn unreadable_validity_and_pre_epoch_clock_are_refused() {
        let malformed_time =
            test_support::mint_certificate_window("230229000000Z", "400101000000Z");
        assert_eq!(
            refusal(
                "ES256",
                &malformed_time.der,
                b"in",
                &[0_u8; super::ES256_SIGNATURE_LENGTH],
                test_now()
            ),
            Some(TransactionError::bad_request(
                "serverCert has no readable validity window"
            ))
        );
        let minted = test_support::mint_certificate();
        assert_eq!(
            refusal(
                "ES256",
                &minted.der,
                b"in",
                &[0_u8; super::ES256_SIGNATURE_LENGTH],
                UNIX_EPOCH - Duration::from_secs(1)
            ),
            Some(TransactionError::internal_error("read the system clock"))
        );
    }

    /// RS256 verifies over a valid RSA certificate, rejects wrong RSA
    /// signatures as 403, and ES256 rejects non-P-256 certificates as 400.
    #[test]
    fn rs256_and_curve_mismatch_paths() {
        use refineid_cms::testkit::{self, CertificateSpec, TestCurve, TestKey};

        /// First day of the testkit month (2026-06-01T12:00:00Z).
        const FIRST_DAY: u8 = 1;
        /// Last day of the testkit window (2026-06-20T12:00:00Z).
        const LAST_DAY: u8 = 20;
        /// Unix seconds of 2026-06-10T12:00:00Z, inside the testkit window.
        const KIT_NOW_SECONDS: u64 = 1_781_092_800;

        let now = UNIX_EPOCH + Duration::from_secs(KIT_NOW_SECONDS);
        let spec = CertificateSpec {
            serial: 1,
            subject: "scs-rsa-test",
            issuer: "scs-rsa-test",
            not_before: testkit::day(FIRST_DAY),
            not_after: testkit::day(LAST_DAY),
            extensions: Vec::new(),
        };

        let rsa_key = TestKey::rsa_2048();
        let rsa_cert = testkit::certificate(&spec, &rsa_key, &rsa_key);
        let signing_input = b"header.payload";
        let valid_rsa_sig = rsa_key.sign(signing_input);
        assert_eq!(
            refusal("RS256", &rsa_cert, signing_input, &valid_rsa_sig, now),
            None
        );

        let wrong_rsa_sig = rsa_key.sign(b"other.payload");
        assert_eq!(
            refusal("RS256", &rsa_cert, signing_input, &wrong_rsa_sig, now),
            Some(TransactionError::forbidden(
                "begin transaction JWS signature is invalid"
            ))
        );
        assert_eq!(
            refusal(
                "ES256",
                &rsa_cert,
                signing_input,
                &[1_u8; super::ES256_SIGNATURE_LENGTH],
                now
            ),
            Some(TransactionError::bad_request("serverCert is not DER X.509"))
        );

        let p384_key = TestKey::derive(TestCurve::P384, b"scs-p384-mismatch");
        let p384_cert = testkit::certificate(&spec, &p384_key, &p384_key);
        assert_eq!(
            refusal(
                "ES256",
                &p384_cert,
                signing_input,
                &[1_u8; super::ES256_SIGNATURE_LENGTH],
                now
            ),
            Some(TransactionError::bad_request("serverCert is not DER X.509"))
        );
    }
}
