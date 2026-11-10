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

//! The stateless helpers under the SCS transaction flow: origin and
//! selector gates, JOSE segment coding, and the response key
//! identifier (DVV SCS specification v1.3 sec.2.7).

use refineid_digest::Sha1;

use crate::base64;
use crate::document::{BeginDocument, BeginSelector};
use crate::error::TransactionError;
use crate::purpose::{KeyAlgorithm, SignPurpose};
use crate::values;

/// Characters in the hexadecimal alphabet.
const HEX_LENGTH: usize = 16;

/// Upper-case hexadecimal digits.
const HEX_UPPER: &[u8; HEX_LENGTH] = b"0123456789ABCDEF";

/// Bits carried by one hexadecimal digit.
const BITS_PER_HEX_DIGIT: usize = 4;

/// Mask selecting one hexadecimal digit's worth of bits.
const HEX_DIGIT_MASK: u8 = 0x0F;

/// The transaction Origin gate: present and HTTPS (v1.3 sec.2.7).
pub fn validated_origin(origin: Option<&str>) -> Result<String, TransactionError> {
    let Some(origin) = origin else {
        return Err(TransactionError::forbidden("missing Origin header"));
    };
    if !origin.starts_with("https://") {
        return Err(TransactionError::forbidden(
            "transaction Origin must use HTTPS",
        ));
    }
    Ok(origin.to_owned())
}

/// The card key the selector names; mixing both usages is refused.
pub fn purpose_of_selector(
    selector: Option<&BeginSelector>,
) -> Result<SignPurpose, TransactionError> {
    let qualified = selector.is_some_and(|selector| {
        selector
            .keyusages
            .iter()
            .any(|usage| usage.eq_ignore_ascii_case("nonRepudiation"))
    });
    let authentication = selector.is_some_and(|selector| {
        selector
            .keyusages
            .iter()
            .any(|usage| usage.eq_ignore_ascii_case("digitalSignature"))
    });
    if qualified && authentication {
        return Err(TransactionError::bad_request(
            "selector mixes authentication and signing key usages",
        ));
    }
    Ok(if qualified {
        SignPurpose::Qualified
    } else {
        SignPurpose::Authentication
    })
}

/// The strict key-algorithm selector gate (v1.3 sec.2.7.2).
#[must_use]
pub fn selector_refusal(
    payload: &BeginDocument,
    key_algorithm: KeyAlgorithm,
) -> Option<TransactionError> {
    if !payload.strict_key_policy {
        return None;
    }
    let algorithms = payload
        .selector
        .as_ref()
        .map(|selector| &selector.keyalgorithms)?;
    if algorithms.is_empty() {
        return None;
    }
    let name = match key_algorithm {
        KeyAlgorithm::Ecdsa => "ec",
        KeyAlgorithm::Rsa => "rsa",
    };
    let accepted = algorithms
        .iter()
        .any(|algorithm| algorithm.eq_ignore_ascii_case(name));
    if accepted {
        None
    } else {
        Some(TransactionError::bad_request(
            "strict key policy excludes the available card key",
        ))
    }
}

/// Decode one base64url JSON segment through `decode`.
pub fn decode_segment<T>(
    encoded: &str,
    label: &str,
    decode: fn(&serde_json::Value) -> Result<T, ()>,
) -> Result<T, TransactionError> {
    let data = base64::decode_url(encoded)
        .map_err(|_| TransactionError::bad_request(format!("{label} is not base64url")))?;
    let value: serde_json::Value = serde_json::from_slice(&data)
        .map_err(|_| TransactionError::bad_request(format!("{label} is not valid JSON")))?;
    decode(&value).map_err(|()| TransactionError::bad_request(format!("{label} is not valid JSON")))
}

/// Encode one JSON value as a base64url segment.
pub fn encode_segment(value: &serde_json::Value) -> Result<String, TransactionError> {
    let data = serde_json::to_vec(value)
        .map_err(|_| TransactionError::internal_error("serialize transaction response"))?;
    Ok(base64::encode_url(&data))
}

/// The response JWT's key identifier: the leaf certificate's SHA-1,
/// upper-case hex, as the specification prints it.
#[must_use]
pub fn key_identifier(chain: &[String]) -> String {
    let leaf = chain
        .first()
        .and_then(|encoded| base64::decode(encoded).ok())
        .unwrap_or_default();
    let digest = Sha1::of(&leaf);
    let mut out = String::with_capacity(values::SHA1_HEX_LENGTH);
    for byte in digest.as_bytes() {
        out.push(char::from(
            HEX_UPPER[usize::from(byte >> BITS_PER_HEX_DIGIT)],
        ));
        out.push(char::from(HEX_UPPER[usize::from(byte & HEX_DIGIT_MASK)]));
    }
    out
}

/// Length of an uncompressed P-256 SEC1 point, tag included.
const UNCOMPRESSED_POINT_LENGTH: usize = 65;

/// The uncompressed-point tag.
const UNCOMPRESSED_TAG: u8 = 0x04;

/// A raw ECDSA signature's two halves.
const ECDSA_SIGNATURE_HALVES: usize = 2;

/// A raw ECDSA signature as X9.62 DER `SEQUENCE { r, s }`.
/// Cards return `r || s`; the `signature` form and CMS carry DER
/// (v1.3 sec.2.6.1, RFC 5753 sec.2.1.1).
pub(crate) fn ecdsa_signature_der(raw: &[u8]) -> Result<Vec<u8>, ()> {
    if raw.is_empty() || !raw.len().is_multiple_of(ECDSA_SIGNATURE_HALVES) {
        return Err(());
    }
    let (r, s) = raw.split_at(raw.len() / ECDSA_SIGNATURE_HALVES);
    let r = der_integer(r)?;
    let s = der_integer(s)?;
    crate::der::sequence(&[&r, &s])
}

/// One signature integer in minimal DER form.
fn der_integer(magnitude: &[u8]) -> Result<Vec<u8>, ()> {
    crate::der::unsigned_integer(magnitude)
}

/// Parse a DER SPKI as a P-256 agreement key.
pub(crate) fn p256_spki_key(spki_der: &[u8]) -> Result<p256::PublicKey, ()> {
    use spki::der::Decode as _;
    use spki::der::asn1::ObjectIdentifier;
    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|_| ())?;
    if spki.algorithm.oid.as_bytes() != refineid_cms::oid::known::EC_PUBLIC_KEY.as_bytes() {
        return Err(());
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
        .filter(|oid| oid.as_bytes() == refineid_cms::oid::known::SECP256R1.as_bytes());
    if curve.is_none() {
        return Err(());
    }
    let point = spki
        .subject_public_key
        .as_bytes()
        .filter(|point| point.len() == UNCOMPRESSED_POINT_LENGTH && point[0] == UNCOMPRESSED_TAG);
    let Some(point) = point else {
        return Err(());
    };
    p256::PublicKey::from_sec1_bytes(point).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{key_identifier, purpose_of_selector, validated_origin};
    use crate::document::BeginSelector;
    use crate::error::TransactionError;
    use crate::purpose::SignPurpose;
    use crate::values;

    /// The transaction Origin is present and HTTPS.
    #[test]
    fn origin_gate() {
        assert_eq!(
            validated_origin(Some("https://example.com")),
            Ok("https://example.com".to_owned())
        );
        assert_eq!(
            validated_origin(None),
            Err(TransactionError::forbidden("missing Origin header"))
        );
        assert_eq!(
            validated_origin(Some("http://example.com")),
            Err(TransactionError::forbidden(
                "transaction Origin must use HTTPS"
            ))
        );
    }

    /// The selector picks one key; mixing usages is refused.
    #[test]
    fn purpose_gate() {
        assert_eq!(purpose_of_selector(None), Ok(SignPurpose::Authentication));
        let signing = BeginSelector {
            keyalgorithms: Vec::new(),
            keyusages: ["nonRepudiation".to_owned()].into(),
        };
        assert_eq!(
            purpose_of_selector(Some(&signing)),
            Ok(SignPurpose::Qualified)
        );
        let mixed = BeginSelector {
            keyalgorithms: Vec::new(),
            keyusages: ["digitalSignature".to_owned(), "nonRepudiation".to_owned()].into(),
        };
        assert_eq!(
            purpose_of_selector(Some(&mixed)),
            Err(TransactionError::bad_request(
                "selector mixes authentication and signing key usages"
            ))
        );
    }

    /// The key identifier is the upper-case SHA-1 of the leaf.
    #[test]
    fn key_identifier_is_upper_hex() {
        // SHA-1 of "abc" (FIPS 180-4 known-answer test).
        assert_eq!(
            key_identifier(&["YWJj".to_owned()]),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
        // An empty chain hashes the empty leaf, like the reference.
        assert_eq!(key_identifier(&[]).len(), values::SHA1_HEX_LENGTH);
    }
}
