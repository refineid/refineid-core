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

//! X.509 extension URL and metadata extractors.

use crate::identity::{CertSerial, CommonName, Peuin, SplitGivenNames, Surname};
use crate::uri::Uri;
use refineid_ber::{BerTlv, BerTlvAny, BerTlvIter, Sequence};
use refineid_cms::oid::Oid;
use refineid_cms::x509::{Certificate, Name};
use spki::der::asn1::AnyRef;
use spki::der::{Decode as _, Reader as _, SliceReader, Tag, Tagged as _};

/// `id-pe-authorityInfoAccess` (RFC 5280 sec.4.2.2.1).
const OID_AUTHORITY_INFO_ACCESS: Oid<'static> =
    Oid::const_new(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]);

/// `id-ad-ocsp` (RFC 5280 sec.4.2.2.1 / RFC 6960).
const OID_AD_OCSP: Oid<'static> = Oid::const_new(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]);

/// `id-ad-caIssuers` (RFC 5280 sec.4.2.2.1).
const OID_AD_CA_ISSUERS: Oid<'static> =
    Oid::const_new(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]);

/// `id-ce-cRLDistributionPoints` (RFC 5280 sec.4.2.1.13).
const OID_CRL_DISTRIBUTION_POINTS: Oid<'static> = Oid::const_new(&[0x55, 0x1D, 0x1F]);

/// `[0] EXPLICIT` wrapper for `DistributionPointName`.
const TAG_DP_DISTRIBUTION_POINT_NAME: u16 = 0xA0;
/// `[0] IMPLICIT` choice `fullName` in `DistributionPointName`.
const TAG_DP_FULL_NAME: u16 = 0xA0;
/// `[6] IMPLICIT` `uniformResourceIdentifier` in `GeneralName`.
const TAG_GN_URI: u16 = 0x86;
/// DER-encoded `BOOLEAN FALSE` content octet (X.690 sec.11.1).
const DER_BOOLEAN_FALSE: u8 = 0x00;
/// DER-encoded `BOOLEAN TRUE` content octet (X.690 sec.11.1).
const DER_BOOLEAN_TRUE: u8 = 0xFF;
const GN_URI: Tag = Tag::ContextSpecific {
    constructed: false,
    number: spki::der::TagNumber(6),
};

/// Return the `extnValue` octets for the first `Extension` whose OID matches
/// `oid_value`. Non-matching or malformed sibling entries are skipped; a
/// matched entry with any structural defect fails closed (`None`) rather than
/// falling through to a later duplicate extension.
fn find_extension<'a>(extensions: &'a [u8], oid_value: Oid<'_>) -> Option<&'a [u8]> {
    let mut reader = SliceReader::new(extensions).ok()?;
    while !reader.is_finished() {
        let Ok(ext_bytes) = reader.tlv_bytes() else {
            break;
        };
        let Ok(ext) = AnyRef::from_der(ext_bytes) else {
            continue;
        };
        if ext.tag() != Tag::Sequence {
            continue;
        }
        let Ok(mut fields) = SliceReader::new(ext.value()) else {
            continue;
        };
        let Ok(oid_bytes) = fields.tlv_bytes() else {
            continue;
        };
        let Ok(oid) = AnyRef::from_der(oid_bytes) else {
            continue;
        };
        if oid.tag() != Tag::ObjectIdentifier || oid.value() != oid_value.as_bytes() {
            continue;
        }
        let Ok(mut next) = fields.tlv_bytes().and_then(AnyRef::from_der) else {
            return None;
        };
        if next.tag() == Tag::Boolean {
            if next.value() != [DER_BOOLEAN_FALSE] && next.value() != [DER_BOOLEAN_TRUE] {
                return None;
            }
            let Ok(val) = fields.tlv_bytes().and_then(AnyRef::from_der) else {
                return None;
            };
            next = val;
        }
        if next.tag() != Tag::OctetString || !fields.is_finished() {
            return None;
        }
        return Some(next.value());
    }
    None
}

fn aia_urls_for(extensions: &[u8], access_method: Oid<'_>) -> Vec<Uri> {
    let mut urls = Vec::new();
    let Some(extn_value) = find_extension(extensions, OID_AUTHORITY_INFO_ACCESS) else {
        return urls;
    };
    let Ok(outer) = AnyRef::from_der(extn_value) else {
        return urls;
    };
    if outer.tag() != Tag::Sequence {
        return urls;
    }
    let Ok(mut reader) = SliceReader::new(outer.value()) else {
        return urls;
    };
    while !reader.is_finished() {
        let Ok(ad_bytes) = reader.tlv_bytes() else {
            break;
        };
        let Ok(ad) = AnyRef::from_der(ad_bytes) else {
            continue;
        };
        if ad.tag() != Tag::Sequence {
            continue;
        }
        let Ok(mut fields) = SliceReader::new(ad.value()) else {
            continue;
        };
        let Ok(oid) = fields.tlv_bytes().and_then(AnyRef::from_der) else {
            continue;
        };
        if oid.tag() != Tag::ObjectIdentifier || oid.value() != access_method.as_bytes() {
            continue;
        }
        let Ok(loc) = fields.tlv_bytes().and_then(AnyRef::from_der) else {
            continue;
        };
        if !fields.is_finished() {
            continue;
        }
        if loc.tag() == GN_URI
            && let Ok(s) = core::str::from_utf8(loc.value())
            && let Ok(url) = Uri::parse(s.to_owned())
        {
            urls.push(url);
        }
    }
    urls
}

/// Extract CRL distribution-point URLs from a certificate extensions block.
#[must_use]
pub fn extract_crl_distribution_urls(extensions: &[u8]) -> Vec<Uri> {
    let Some(extn_value) = find_extension(extensions, OID_CRL_DISTRIBUTION_POINTS) else {
        return Vec::new();
    };
    let Ok(outer) = BerTlv::<Sequence>::parse(extn_value) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for dp in BerTlvIter::new(outer.value()) {
        let Ok(dp) = dp.and_then(BerTlvAny::expect::<Sequence>) else {
            continue;
        };
        for field in BerTlvIter::new(dp.value()) {
            let Ok(field) = field else { continue };
            if field.tag() != TAG_DP_DISTRIBUTION_POINT_NAME {
                continue;
            }
            for gn_wrap in BerTlvIter::new(field.value()) {
                let Ok(gn_wrap) = gn_wrap else { continue };
                if gn_wrap.tag() != TAG_DP_FULL_NAME {
                    continue;
                }
                for gn in BerTlvIter::new(gn_wrap.value()) {
                    let Ok(gn) = gn else { continue };
                    if gn.tag() == TAG_GN_URI
                        && let Ok(s) = core::str::from_utf8(gn.value())
                        && let Ok(url) = Uri::parse(s.to_owned())
                    {
                        urls.push(url);
                    }
                }
            }
        }
    }
    urls
}

/// Extract OCSP responder URLs from the Authority Information Access extension.
#[must_use]
pub fn extract_ocsp_urls(extensions: &[u8]) -> Vec<Uri> {
    aia_urls_for(extensions, OID_AD_OCSP)
}

/// Extract `caIssuers` URLs from the Authority Information Access extension.
#[must_use]
pub fn extract_ca_issuers_urls(extensions: &[u8]) -> Vec<Uri> {
    aia_urls_for(extensions, OID_AD_CA_ISSUERS)
}

fn decode_directory_string(value: AnyRef<'_>) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "der::Tag has ~25 variants; only the DirectoryString string types decode to text"
    )]
    match value.tag() {
        Tag::Utf8String => core::str::from_utf8(value.value()).ok().map(String::from),
        Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => value
            .value()
            .iter()
            .all(u8::is_ascii)
            .then(|| String::from_utf8_lossy(value.value()).into_owned()),
        Tag::BmpString => {
            if !value.value().len().is_multiple_of(2) {
                return None;
            }
            let cap = value.value().len() / 2;
            let mut out = String::with_capacity(cap);
            for &[hi, lo] in value.value().as_chunks::<2>().0 {
                let code = u32::from(u16::from_be_bytes([hi, lo]));
                out.push(char::from_u32(code)?);
            }
            Some(out)
        }
        _ => None,
    }
}

/// The attribute types RFC 4514 sec.3 names by a short string, with
/// that string; any other type is written as its dotted object
/// identifier.
const RFC4514_SHORT_NAMES: [(&str, &str); 9] = [
    ("2.5.4.3", "CN"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.6", "C"),
    ("2.5.4.9", "STREET"),
    ("0.9.2342.19200300.100.1.25", "DC"),
    ("0.9.2342.19200300.100.1.1", "UID"),
];

/// Characters RFC 4514 sec.2.4 escapes with a backslash anywhere in a
/// value.
const RFC4514_ESCAPED: [char; 7] = ['"', '+', ',', ';', '<', '>', '\\'];

/// The NUL character, which RFC 4514 sec.2.4 escapes as a hex pair.
const NUL: char = '\0';

/// The escaped spelling of [`NUL`].
const ESCAPED_NUL: &str = "\\00";

/// `value` escaped as RFC 4514 sec.2.4 writes an attribute value.
fn rfc4514_escape(value: &str, out: &mut String) {
    let last = value.chars().count().saturating_sub(1);
    for (position, character) in value.chars().enumerate() {
        let leading = position == 0 && (character == '#' || character == ' ');
        let trailing = position == last && character == ' ';
        if leading || trailing || RFC4514_ESCAPED.contains(&character) {
            out.push('\\');
            out.push(character);
        } else if character == NUL {
            out.push_str(ESCAPED_NUL);
        } else {
            out.push(character);
        }
    }
}

/// `dn_der` as RFC 4514 sec.2 writes a distinguished name: the RDNs in
/// reverse order separated by commas, the attributes of one RDN by
/// plus signs, each `type=value`: a short-named type with its string
/// value escaped, a type written as its dotted identifier (or a value
/// that is not a directory string) with `#` and the hexadecimal BER
/// encoding of the value.
fn rfc4514_name(dn_der: &[u8]) -> Option<String> {
    let name = AnyRef::from_der(dn_der).ok()?;
    if name.tag() != Tag::Sequence {
        return None;
    }
    let mut rdns = SliceReader::new(name.value()).ok()?;
    let mut rendered: Vec<String> = Vec::new();
    while !rdns.is_finished() {
        let rdn = AnyRef::from_der(rdns.tlv_bytes().ok()?).ok()?;
        if rdn.tag() != Tag::Set {
            return None;
        }
        let mut atvs = SliceReader::new(rdn.value()).ok()?;
        let mut parts: Vec<String> = Vec::new();
        while !atvs.is_finished() {
            let atv = AnyRef::from_der(atvs.tlv_bytes().ok()?).ok()?;
            if atv.tag() != Tag::Sequence {
                return None;
            }
            let mut fields = SliceReader::new(atv.value()).ok()?;
            let oid = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
            let value_der = fields.tlv_bytes().ok()?;
            let value = AnyRef::from_der(value_der).ok()?;
            if !fields.is_finished() || oid.tag() != Tag::ObjectIdentifier {
                return None;
            }
            let dotted = ::const_oid::ObjectIdentifier::from_bytes(oid.value())
                .ok()?
                .to_string();
            let short = RFC4514_SHORT_NAMES
                .iter()
                .find(|(number, _)| *number == dotted)
                .map(|(_, short)| *short);
            let mut part = short.map_or_else(|| dotted.clone(), str::to_owned);
            part.push('=');
            // A type written as its dotted identifier takes its value as
            // `#` and the hexadecimal BER encoding (sec.2.4); so does a
            // short-named one whose value is not a directory string.
            match short.and(decode_directory_string(value)) {
                Some(text) => rfc4514_escape(&text, &mut part),
                None => {
                    part.push('#');
                    part.push_str(&crate::hexcodec::Hex::encode(value_der));
                }
            }
            parts.push(part);
        }
        rendered.push(parts.join("+"));
    }
    rendered.reverse();
    Some(rendered.join(","))
}

/// Extension methods for [`Name`] to extract identity attributes.
pub trait NameExt {
    /// `commonName` (X.520 `cn`, OID 2.5.4.3).
    fn common_name(&self) -> Option<CommonName>;

    /// `surname` (X.520 `sn`, OID 2.5.4.4).
    fn surname(&self) -> Option<Surname>;

    /// `givenName` (X.520 `gn`, OID 2.5.4.42), split into typed slots.
    fn given_names(&self) -> SplitGivenNames;

    /// PEUIN / SATU from the `serialNumber` DN attribute (OID 2.5.4.5).
    fn peuin(&self) -> Option<Peuin>;
    /// The name as RFC 4514 sec.2 writes it; `None` when the encoding
    /// is not a `Name`.
    fn rfc4514(&self) -> Option<String>;
}

impl NameExt for Name<'_> {
    fn common_name(&self) -> Option<CommonName> {
        Name::common_name(self)
    }

    fn surname(&self) -> Option<Surname> {
        Name::surname(self)
    }

    fn given_names(&self) -> SplitGivenNames {
        Name::given_names(self)
    }

    fn peuin(&self) -> Option<Peuin> {
        Name::peuin(self)
    }

    fn rfc4514(&self) -> Option<String> {
        rfc4514_name(self.as_der())
    }
}

/// Extension methods for [`Certificate`].
pub trait CertificateExt {
    /// Certificate serial number.
    fn serial(&self) -> CertSerial;

    /// Extract CRL distribution-point URLs from the certificate's extensions.
    fn crl_distribution_urls(&self) -> Vec<Uri>;

    /// Extract OCSP responder URLs from the Authority Information Access extension.
    fn ocsp_urls(&self) -> Vec<Uri>;

    /// Extract `caIssuers` URLs from the Authority Information Access extension.
    fn ca_issuers_urls(&self) -> Vec<Uri>;
}

impl CertificateExt for Certificate<'_> {
    fn serial(&self) -> CertSerial {
        CertSerial::from_bytes(self.serial_der.as_bytes().to_vec())
    }

    fn crl_distribution_urls(&self) -> Vec<Uri> {
        self.extensions
            .map_or_else(Vec::new, extract_crl_distribution_urls)
    }

    fn ocsp_urls(&self) -> Vec<Uri> {
        self.extensions.map_or_else(Vec::new, extract_ocsp_urls)
    }

    fn ca_issuers_urls(&self) -> Vec<Uri> {
        self.extensions
            .map_or_else(Vec::new, extract_ca_issuers_urls)
    }
}

impl CertificateExt for &Certificate<'_> {
    fn serial(&self) -> CertSerial {
        (*self).serial()
    }

    fn crl_distribution_urls(&self) -> Vec<Uri> {
        (*self).crl_distribution_urls()
    }

    fn ocsp_urls(&self) -> Vec<Uri> {
        (*self).ocsp_urls()
    }

    fn ca_issuers_urls(&self) -> Vec<Uri> {
        (*self).ca_issuers_urls()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DER_BOOLEAN_TRUE, OID_AD_CA_ISSUERS, OID_AD_OCSP, OID_AUTHORITY_INFO_ACCESS,
        OID_CRL_DISTRIBUTION_POINTS, TAG_DP_DISTRIBUTION_POINT_NAME, TAG_DP_FULL_NAME, TAG_GN_URI,
        extract_ca_issuers_urls, extract_crl_distribution_urls, extract_ocsp_urls, rfc4514_name,
    };
    use crate::ber::tlv;
    use crate::test_util::{TestResult, check};
    use refineid_cms::oid::{Oid, known};

    const DER_TAG_BOOLEAN: u8 = 0x01;
    const DER_TAG_OCTET_STRING: u8 = 0x04;
    const DER_TAG_NULL: u8 = 0x05;
    const DER_TAG_OID: u8 = 0x06;
    const DER_TAG_UTF8_STRING: u8 = 0x0C;
    const DER_TAG_SEQUENCE: u8 = 0x30;
    const DER_TAG_SET: u8 = 0x31;
    const NON_DER_BOOLEAN_VALUE: [u8; 1] = [0x01];
    const OVERLONG_BOOLEAN_VALUE: [u8; 2] = [0x00, 0x00];
    const TRUNCATED_OID_LEN: u8 = 5;
    const TRUNCATED_INNER_TLV: [u8; 2] = [DER_TAG_OID, TRUNCATED_OID_LEN];

    const TEST_OCSP_URL: &str = "http://ocsp.example.com/";
    const TEST_CA_ISSUERS_URL: &str = "http://ca.example.com/issuer.crt";
    const TEST_CRL_URL: &str = "http://crl.example.com/example.crl";

    fn tag_byte(tag: u16) -> Result<u8, String> {
        u8::try_from(tag).map_err(|err| format!("tag fits u8: {err}"))
    }

    fn extension(
        oid: Oid<'_>,
        critical: bool,
        inner_der: &[u8],
        trailing: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut body = tlv(DER_TAG_OID, oid.as_bytes());
        if critical {
            body.extend_from_slice(&tlv(DER_TAG_BOOLEAN, &[DER_BOOLEAN_TRUE]));
        }
        body.extend_from_slice(&tlv(DER_TAG_OCTET_STRING, inner_der));
        if let Some(extra) = trailing {
            body.extend_from_slice(extra);
        }
        tlv(DER_TAG_SEQUENCE, &body)
    }

    fn access_description(
        method: Oid<'_>,
        uri: &str,
        trailing: Option<&[u8]>,
    ) -> Result<Vec<u8>, String> {
        let gn_uri_tag = tag_byte(TAG_GN_URI)?;
        let mut body = tlv(DER_TAG_OID, method.as_bytes());
        body.extend_from_slice(&tlv(gn_uri_tag, uri.as_bytes()));
        if let Some(extra) = trailing {
            body.extend_from_slice(extra);
        }
        Ok(tlv(DER_TAG_SEQUENCE, &body))
    }

    fn cdp_value(uri: &str) -> Result<Vec<u8>, String> {
        let gn = tlv(tag_byte(TAG_GN_URI)?, uri.as_bytes());
        let dp_full = tlv(tag_byte(TAG_DP_FULL_NAME)?, &gn);
        let dp_name = tlv(tag_byte(TAG_DP_DISTRIBUTION_POINT_NAME)?, &dp_full);
        let dp = tlv(DER_TAG_SEQUENCE, &dp_name);
        Ok(tlv(DER_TAG_SEQUENCE, &dp))
    }

    #[test]
    fn find_extension_skips_empty_and_malformed_sibling_extensions() -> TestResult {
        let empty_sibling = tlv(DER_TAG_SEQUENCE, &[]);
        let malformed_sibling = tlv(DER_TAG_SEQUENCE, &TRUNCATED_INNER_TLV);
        let aia_seq = tlv(
            DER_TAG_SEQUENCE,
            &access_description(OID_AD_OCSP, TEST_OCSP_URL, None)?,
        );
        let aia_ext = extension(OID_AUTHORITY_INFO_ACCESS, false, &aia_seq, None);
        let cdp_ext = extension(
            OID_CRL_DISTRIBUTION_POINTS,
            false,
            &cdp_value(TEST_CRL_URL)?,
            None,
        );

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&empty_sibling);
        extensions.extend_from_slice(&malformed_sibling);
        extensions.extend_from_slice(&aia_ext);
        extensions.extend_from_slice(&cdp_ext);

        let ocsp: Vec<String> = extract_ocsp_urls(&extensions)
            .iter()
            .map(ToString::to_string)
            .collect();
        let crls: Vec<String> = extract_crl_distribution_urls(&extensions)
            .iter()
            .map(ToString::to_string)
            .collect();
        check(
            &ocsp,
            &vec![TEST_OCSP_URL.to_owned()],
            "OCSP URL extracted after malformed siblings",
        )?;
        check(
            &crls,
            &vec![TEST_CRL_URL.to_owned()],
            "CRL URL extracted after malformed siblings",
        )
    }

    #[test]
    fn find_extension_rejects_trailing_fields_in_extension_sequence() -> TestResult {
        let trailing_null = tlv(DER_TAG_NULL, &[]);
        let aia_seq = tlv(
            DER_TAG_SEQUENCE,
            &access_description(OID_AD_OCSP, TEST_OCSP_URL, None)?,
        );
        let non_critical_trailing = extension(
            OID_AUTHORITY_INFO_ACCESS,
            false,
            &aia_seq,
            Some(&trailing_null),
        );
        let critical_trailing = extension(
            OID_AUTHORITY_INFO_ACCESS,
            true,
            &aia_seq,
            Some(&trailing_null),
        );

        check(
            &extract_ocsp_urls(&non_critical_trailing),
            &Vec::new(),
            "non-critical Extension with trailing TLV is rejected",
        )?;
        check(
            &extract_ocsp_urls(&critical_trailing),
            &Vec::new(),
            "critical Extension with trailing TLV is rejected",
        )
    }

    #[test]
    fn aia_skips_access_description_with_trailing_fields() -> TestResult {
        let trailing_null = tlv(DER_TAG_NULL, &[]);
        let bad_ocsp = access_description(OID_AD_OCSP, TEST_OCSP_URL, Some(&trailing_null))?;
        let good_ca_issuers = access_description(OID_AD_CA_ISSUERS, TEST_CA_ISSUERS_URL, None)?;

        let mut aia_body = Vec::new();
        aia_body.extend_from_slice(&bad_ocsp);
        aia_body.extend_from_slice(&good_ca_issuers);
        let aia_ext = extension(
            OID_AUTHORITY_INFO_ACCESS,
            false,
            &tlv(DER_TAG_SEQUENCE, &aia_body),
            None,
        );

        check(
            &extract_ocsp_urls(&aia_ext),
            &Vec::new(),
            "AccessDescription with trailing TLV is skipped",
        )?;
        let issuers: Vec<String> = extract_ca_issuers_urls(&aia_ext)
            .iter()
            .map(ToString::to_string)
            .collect();
        check(
            &issuers,
            &vec![TEST_CA_ISSUERS_URL.to_owned()],
            "valid sibling AccessDescription still extracts",
        )
    }

    #[test]
    fn find_extension_rejects_malformed_boolean_and_duplicate_fallthrough() -> TestResult {
        let aia_seq = tlv(
            DER_TAG_SEQUENCE,
            &access_description(OID_AD_OCSP, TEST_OCSP_URL, None)?,
        );
        for bad_bool in [
            &NON_DER_BOOLEAN_VALUE[..],
            &OVERLONG_BOOLEAN_VALUE[..],
            &[][..],
        ] {
            let mut body = tlv(DER_TAG_OID, OID_AUTHORITY_INFO_ACCESS.as_bytes());
            body.extend_from_slice(&tlv(DER_TAG_BOOLEAN, bad_bool));
            body.extend_from_slice(&tlv(DER_TAG_OCTET_STRING, &aia_seq));
            let malformed = tlv(DER_TAG_SEQUENCE, &body);
            check(
                &extract_ocsp_urls(&malformed),
                &Vec::new(),
                "non-DER critical BOOLEAN is rejected",
            )?;
        }

        // Double BOOLEAN fails closed even if a valid duplicate extension follows.
        let mut double_bool = tlv(DER_TAG_OID, OID_AUTHORITY_INFO_ACCESS.as_bytes());
        double_bool.extend_from_slice(&tlv(DER_TAG_BOOLEAN, &[DER_BOOLEAN_TRUE]));
        double_bool.extend_from_slice(&tlv(DER_TAG_BOOLEAN, &[DER_BOOLEAN_TRUE]));
        double_bool.extend_from_slice(&tlv(DER_TAG_OCTET_STRING, &aia_seq));
        let mut duplicate_stream = tlv(DER_TAG_SEQUENCE, &double_bool);
        duplicate_stream.extend_from_slice(&extension(
            OID_AUTHORITY_INFO_ACCESS,
            false,
            &aia_seq,
            None,
        ));
        check(
            &extract_ocsp_urls(&duplicate_stream),
            &Vec::new(),
            "malformed matched extension fails closed without falling through to duplicate",
        )
    }

    #[test]
    fn rfc4514_name_rejects_trailing_fields_in_attribute_type_and_value() -> TestResult {
        let mut valid_atv = tlv(DER_TAG_OID, known::COMMON_NAME.as_bytes());
        valid_atv.extend_from_slice(&tlv(DER_TAG_UTF8_STRING, b"Alice"));
        let valid_dn = tlv(
            DER_TAG_SEQUENCE,
            &tlv(DER_TAG_SET, &tlv(DER_TAG_SEQUENCE, &valid_atv)),
        );

        let mut trailing_atv = valid_atv;
        trailing_atv.extend_from_slice(&tlv(DER_TAG_NULL, &[]));
        let trailing_dn = tlv(
            DER_TAG_SEQUENCE,
            &tlv(DER_TAG_SET, &tlv(DER_TAG_SEQUENCE, &trailing_atv)),
        );

        check(
            &rfc4514_name(&valid_dn),
            &Some("CN=Alice".to_owned()),
            "valid DN formats cleanly",
        )?;
        check(
            &rfc4514_name(&trailing_dn),
            &None,
            "ATV with trailing TLV is rejected",
        )
    }
}
