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

//! The self-signed localhost server certificate the SCS presents at
//! `https://127.0.0.1:53952` (DVV SCS specification v1.3 sec.2.3).
//!
//! The specification names the attributes the browser checks before it
//! will talk to the local service: CN `127.0.0.1`, subjectAltName with
//! both the loopback address and `localhost`, KeyUsage digitalSignature
//! and keyEncipherment, and extended key usage serverAuth. Signing
//! stays a caller-supplied closure so the key can live wherever the
//! platform keeps it.

use refineid_cms::oid::known;

use crate::der;
use crate::time;
use crate::values;

/// The certificate's common name, which the specification fixes at
/// the loopback address (v1.3 sec.2.3).
pub const COMMON_NAME: &str = "127.0.0.1";

/// The DNS name carried beside the loopback address.
const LOCALHOST_NAME: &str = "localhost";

/// X.509 version 3, zero-based.
const VERSION_THREE: u8 = 2;

/// Basic-constraints path length of the self-signed leaf.
const PATH_LENGTH: u8 = 0;

/// Why the certificate cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalhostError {
    /// The signing closure refused the TBSCertificate.
    SigningFailed,
    /// The validity window cannot be represented.
    UnrepresentableTime,
}

impl core::fmt::Display for LocalhostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SigningFailed => f.write_str("localhost certificate signing failed"),
            Self::UnrepresentableTime => f.write_str("localhost certificate time out of range"),
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

/// Build and sign the certificate.
///
/// `sign` receives the DER TBSCertificate and must answer an
/// ecdsa-with-SHA256 signature in X9.62 DER form.
pub fn make(
    subject_public_key_info: &[u8],
    serial_number: &[u8],
    not_before_unix: i64,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, LocalhostError>,
) -> Result<Vec<u8>, LocalhostError> {
    let tbs = tbs_certificate(subject_public_key_info, serial_number, not_before_unix)?;
    let signature = sign(&tbs)?;
    let bits = der::bit_string(&signature).map_err(|()| LocalhostError::SigningFailed)?;
    der::sequence(&[&tbs, &signature_algorithm()?, &bits])
        .map_err(|()| LocalhostError::SigningFailed)
}

/// ecdsa-with-SHA256, the signature this builder expects from its
/// signing closure.
fn signature_algorithm() -> Result<Vec<u8>, LocalhostError> {
    der::sequence(&[&der::oid(known::ECDSA_WITH_SHA256.as_bytes())
        .map_err(|()| LocalhostError::SigningFailed)?])
    .map_err(|()| LocalhostError::SigningFailed)
}

/// The certificate's one subject and issuer name.
fn name() -> Result<Vec<u8>, LocalhostError> {
    let attribute = der::sequence(&[
        &der::oid(known::COMMON_NAME.as_bytes()).map_err(|()| LocalhostError::SigningFailed)?,
        &der::utf8_string(COMMON_NAME.as_bytes()).map_err(|()| LocalhostError::SigningFailed)?,
    ])
    .map_err(|()| LocalhostError::SigningFailed)?;
    let set = der::set(&[&attribute]).map_err(|()| LocalhostError::SigningFailed)?;
    der::sequence(&[&set]).map_err(|()| LocalhostError::SigningFailed)
}

/// The to-be-signed body: version 3, the fixed names, the sec.2.3
/// extension set.
fn tbs_certificate(
    subject_public_key_info: &[u8],
    serial_number: &[u8],
    not_before_unix: i64,
) -> Result<Vec<u8>, LocalhostError> {
    let not_after_unix = time::add_years(not_before_unix, values::CERTIFICATE_VALIDITY_YEARS)
        .map_err(|_| LocalhostError::UnrepresentableTime)?;
    let not_before =
        time::format_utc_time(not_before_unix).map_err(|_| LocalhostError::UnrepresentableTime)?;
    let not_after =
        time::format_utc_time(not_after_unix).map_err(|_| LocalhostError::UnrepresentableTime)?;
    let validity = der::sequence(&[
        &der::tagged(time::UTC_TIME_TAG, &not_before)
            .map_err(|()| LocalhostError::SigningFailed)?,
        &der::tagged(time::UTC_TIME_TAG, &not_after).map_err(|()| LocalhostError::SigningFailed)?,
    ])
    .map_err(|()| LocalhostError::SigningFailed)?;
    let version = der::tagged(
        der::TAG_CONTEXT_ZERO,
        &der::integer(VERSION_THREE).map_err(|()| LocalhostError::SigningFailed)?,
    )
    .map_err(|()| LocalhostError::SigningFailed)?;
    let serial =
        der::unsigned_integer(serial_number).map_err(|()| LocalhostError::SigningFailed)?;
    let name = name()?;
    let extensions = der::tagged(der::TAG_CONTEXT_THREE, &extensions()?)
        .map_err(|()| LocalhostError::SigningFailed)?;
    der::sequence(&[
        &version,
        &serial,
        &signature_algorithm()?,
        &name,
        &validity,
        &name,
        subject_public_key_info,
        &extensions,
    ])
    .map_err(|()| LocalhostError::SigningFailed)
}

/// The sec.2.3 extension set: CA basic constraints (so a browser can
/// trust the self-signed leaf as its own root), the key usages,
/// serverAuth, and the loopback subject names.
fn extensions() -> Result<Vec<u8>, LocalhostError> {
    let basic_constraints = extension_record(
        known::BASIC_CONSTRAINTS.as_bytes(),
        true,
        &der::sequence(&[
            &der::boolean_true().map_err(|()| LocalhostError::SigningFailed)?,
            &der::integer(PATH_LENGTH).map_err(|()| LocalhostError::SigningFailed)?,
        ])
        .map_err(|()| LocalhostError::SigningFailed)?,
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
    let alternative_names = extension_record(
        known::SUBJECT_ALT_NAME.as_bytes(),
        false,
        &der::sequence(&[
            &der::tagged(der::TAG_CONTEXT_TWO, LOCALHOST_NAME.as_bytes())
                .map_err(|()| LocalhostError::SigningFailed)?,
            &der::tagged(der::TAG_CONTEXT_SEVEN, &values::LOOPBACK_ADDRESS)
                .map_err(|()| LocalhostError::SigningFailed)?,
        ])
        .map_err(|()| LocalhostError::SigningFailed)?,
    )?;
    der::sequence(&[
        &basic_constraints,
        &key_usage,
        &extended_key_usage,
        &alternative_names,
    ])
    .map_err(|()| LocalhostError::SigningFailed)
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

#[cfg(test)]
mod tests {
    use super::{COMMON_NAME, LocalhostError, make, subject_public_key_info};
    use crate::time;
    use crate::values;

    /// Serial bytes of the test certificate.
    const SERIAL: &[u8] = &[1];

    /// Length of a P-256 secret, in bytes.
    const SECRET_LENGTH: usize = 32;

    /// Unix seconds of 2023-11-14T22:13:20Z.
    const NOT_BEFORE: i64 = 1_700_000_000;

    /// The built certificate parses, names the loopback service, and
    /// carries a signature over its TBSCertificate.
    #[test]
    fn builds_a_verifiable_server_certificate() {
        use p256::ecdsa::signature::{Signer as _, Verifier as _};
        let key = p256::ecdsa::SigningKey::from_slice(&[1_u8; SECRET_LENGTH]).expect("key parses");
        let point = key.verifying_key().to_sec1_point(false);
        let spki = subject_public_key_info(point.as_bytes()).expect("SPKI encodes");
        let signed_tbs = std::sync::Mutex::new(Vec::new());
        let der = make(&spki, SERIAL, NOT_BEFORE, |tbs| {
            *signed_tbs.lock().expect("record") = tbs.to_vec();
            let signature: p256::ecdsa::Signature = key.sign(tbs);
            Ok(signature.to_der().as_bytes().to_vec())
        })
        .expect("builds");
        // The common name, the DNS name, and the loopback address are
        // all present.
        assert!(
            der.windows(COMMON_NAME.len())
                .any(|window| window == COMMON_NAME.as_bytes())
        );
        assert!(
            der.windows(b"localhost".len())
                .any(|window| window == b"localhost")
        );
        assert!(
            der.windows(values::LOOPBACK_ADDRESS.len())
                .any(|window| window == values::LOOPBACK_ADDRESS)
        );
        // The validity window spans the configured years.
        let tbs = signed_tbs.lock().expect("recorded");
        let not_after =
            time::add_years(NOT_BEFORE, values::CERTIFICATE_VALIDITY_YEARS).expect("adds");
        let before = time::format_utc_time(NOT_BEFORE).expect("formats");
        let after = time::format_utc_time(not_after).expect("formats");
        assert!(
            tbs.windows(before.len())
                .any(|window| window == before.as_slice())
        );
        assert!(
            tbs.windows(after.len())
                .any(|window| window == after.as_slice())
        );
        // The signature verifies over the TBSCertificate.
        let certificate = refineid_ber::BerTlvAny::parse(&der).expect("parses");
        let signature_bits = {
            let mut rest = certificate.value();
            let mut last = Vec::new();
            while !rest.is_empty() {
                let child = refineid_ber::BerTlvAny::parse(rest).expect("child");
                last = child.value().to_vec();
                rest = rest.get(child.size()..).expect("advance");
            }
            last
        };
        let signature_der = signature_bits
            .strip_prefix(&[0])
            .expect("unused-bits octet");
        let signature = p256::ecdsa::Signature::from_der(signature_der).expect("DER signature");
        key.verifying_key()
            .verify(&tbs, &signature)
            .expect("verifies");
    }

    /// An unrepresentable window refuses the build.
    #[test]
    fn unrepresentable_window_refuses() {
        let outcome: Result<Vec<u8>, LocalhostError> =
            make(&[], SERIAL, i64::MIN, |_| Ok(Vec::new()));
        assert_eq!(outcome, Err(LocalhostError::UnrepresentableTime));
    }
}
