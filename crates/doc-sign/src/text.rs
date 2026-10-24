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

//! Tiny text-codec helpers shared across CLI modules.
//!
//! base64 decode + PEM auto-detect. Both are minimal
//! RFC 4648 / RFC 7468 implementations -- enough for cert
//! loading without reaching for the `base64` / `pem`
//! crates.

/// DER SEQUENCE tag byte (universal class, constructed, tag 16).
/// A DER-encoded `Certificate`, `SubjectPublicKeyInfo`, etc. all
/// start with this byte.
const DER_SEQUENCE_TAG: u8 = 0x30;

/// Auto-detect a certificate blob's wire form.
///
/// Accepts either raw DER (starts with `0x30` SEQUENCE tag) or a
/// PEM `CERTIFICATE` block (RFC 7468), and returns the decoded DER
/// body. Whitespace inside the base64 body is stripped before
/// decode. Every caller loads certificates, so the PEM label is
/// fixed rather than a parameter.
///
/// Returns `None` for input that's neither.
#[must_use]
pub(crate) fn decode_cert_pem_or_der(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.first() == Some(&DER_SEQUENCE_TAG) {
        return Some(bytes.to_vec());
    }
    let s = core::str::from_utf8(bytes).ok()?;
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let begin = s.find(begin_marker)?;
    let body_start = begin.checked_add(begin_marker.len())?;
    let tail = s.get(begin..)?;
    let end_offset = tail.find(end_marker)?;
    let body_end = begin.checked_add(end_offset)?;
    if body_end < body_start {
        return None;
    }
    let body = s.get(body_start..body_end)?;
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    crate::base64::decode(&cleaned).ok()
}

/// Render a [`DateTime`](refineid_cms::x509::DateTime) as
/// RFC 3339 `YYYY-MM-DDTHH:MM:SSZ` for the `card`/`cert` reports.
///
/// The trailing `Z` is fixed: `der::DateTime` is always UTC (RFC
/// 5280 sec.4.1.2.5 -- certs encode `UTCTime` / `GeneralizedTime`
/// in UTC). Zero-padding keeps report columns aligned.
#[must_use]
#[expect(
    dead_code,
    reason = "timestamp rendering for the GUI Verify/Documents report lands with the Documents tab; the unfulfilled expectation will flag this for removal at wiring"
)]
pub(crate) fn fmt_rfc3339(t: refineid_cms::x509::DateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minutes(),
        t.seconds()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_with_matching_label_decodes() {
        let pem = b"-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n";
        assert_eq!(decode_cert_pem_or_der(pem), Some(b"foobar".to_vec()));
    }

    #[test]
    fn pem_with_wrong_label_rejected() {
        let pem = b"-----BEGIN PUBLIC KEY-----\nZm9vYmFy\n-----END PUBLIC KEY-----\n";
        assert!(decode_cert_pem_or_der(pem).is_none());
    }

    #[test]
    fn raw_der_passes_through() {
        let der: Vec<u8> = vec![
            0x30_u8, 0x05_u8, 0xAA_u8, 0xBB_u8, 0xCC_u8, 0xDD_u8, 0xEE_u8,
        ];
        assert_eq!(decode_cert_pem_or_der(&der), Some(der));
    }
}
