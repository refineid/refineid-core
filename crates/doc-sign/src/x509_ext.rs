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

use crate::identity::{CertSerial, CommonName, GivenNamesText, Peuin, SplitGivenNames, Surname};
use crate::uri::Uri;
use refineid_ber::{BerTlv, BerTlvAny, BerTlvIter, Sequence};
use refineid_cms::oid::{Oid, known};
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
const GN_URI: Tag = Tag::ContextSpecific {
    constructed: false,
    number: spki::der::TagNumber(6),
};

fn find_extension<'a>(extensions: &'a [u8], oid_value: Oid<'_>) -> Option<&'a [u8]> {
    let mut reader = SliceReader::new(extensions).ok()?;
    while !reader.is_finished() {
        let ext = AnyRef::from_der(reader.tlv_bytes().ok()?).ok()?;
        if ext.tag() != Tag::Sequence {
            continue;
        }
        let mut fields = SliceReader::new(ext.value()).ok()?;
        let oid = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
        if oid.tag() != Tag::ObjectIdentifier || oid.value() != oid_value.as_bytes() {
            continue;
        }
        let mut next = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
        if next.tag() == Tag::Boolean {
            next = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
        }
        if next.tag() != Tag::OctetString {
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
        let Ok(oid) = fields.tlv_bytes().map(AnyRef::from_der) else {
            continue;
        };
        let Ok(oid) = oid else { continue };
        if oid.tag() != Tag::ObjectIdentifier || oid.value() != access_method.as_bytes() {
            continue;
        }
        let Ok(loc) = fields.tlv_bytes().map(AnyRef::from_der) else {
            continue;
        };
        let Ok(loc) = loc else { continue };
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

fn name_dn_attribute(dn_der: &[u8], oid_body: Oid<'_>) -> Option<String> {
    let name = AnyRef::from_der(dn_der).ok()?;
    if name.tag() != Tag::Sequence {
        return None;
    }
    let mut rdns = SliceReader::new(name.value()).ok()?;
    let mut found: Option<String> = None;
    while !rdns.is_finished() {
        let rdn = AnyRef::from_der(rdns.tlv_bytes().ok()?).ok()?;
        if rdn.tag() != Tag::Set {
            continue;
        }
        let mut atvs = SliceReader::new(rdn.value()).ok()?;
        while !atvs.is_finished() {
            let atv = AnyRef::from_der(atvs.tlv_bytes().ok()?).ok()?;
            if atv.tag() != Tag::Sequence {
                continue;
            }
            let mut fields = SliceReader::new(atv.value()).ok()?;
            let oid = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
            let val = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
            if oid.tag() == Tag::ObjectIdentifier
                && oid.value() == oid_body.as_bytes()
                && let Some(s) = decode_directory_string(val)
            {
                found = Some(s);
            }
        }
    }
    found
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
}

impl NameExt for Name<'_> {
    fn common_name(&self) -> Option<CommonName> {
        Some(CommonName::new(name_dn_attribute(
            self.as_der(),
            known::COMMON_NAME,
        )?))
    }

    fn surname(&self) -> Option<Surname> {
        Surname::new(name_dn_attribute(self.as_der(), known::SURNAME)?).ok()
    }

    fn given_names(&self) -> SplitGivenNames {
        name_dn_attribute(self.as_der(), known::GIVEN_NAME).map_or_else(
            SplitGivenNames::default,
            |raw| {
                GivenNamesText::new(raw)
                    .map_or_else(|_err| SplitGivenNames::default(), |text| text.split())
            },
        )
    }

    fn peuin(&self) -> Option<Peuin> {
        Peuin::new(&name_dn_attribute(self.as_der(), known::SERIAL_NUMBER)?).ok()
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
        CertSerial::from_bytes(self.serial_der.to_vec())
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
