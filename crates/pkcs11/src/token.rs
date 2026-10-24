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

//! Slot / token / object model over PC/SC.
//!
//! A FINEID token exposes the authentication certificate
//! ([`ObjectKind::Certificate`], handle [`OBJ_CERTIFICATE`]), its
//! public key ([`ObjectKind::PublicKey`], handle [`OBJ_PUBLIC_KEY`],
//! for consumers such as p11tool / libp11 that enumerate public
//! keys), its auth private key ([`ObjectKind::PrivateKey`], handle
//! [`OBJ_PRIVATE_KEY`]), and dynamic CA certificates read from card silicon
//! and persisted cache ([`ObjectKind::Ca`], handles starting at [`OBJ_CA_BASE`]).
//! All authentication objects carry the same [`crate::ck::CKA_ID`] so NSS
//! pairs them.
//!
//! The card is opened only for the moment it takes to read the
//! certificate or run a signature, then dropped -- this module never
//! holds a PC/SC handle across PKCS#11 calls, so the desktop CLI
//! shares the reader.

use alloc::collections::BTreeMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use refineid_apdu::CardTransport;
#[cfg(feature = "pin-change")]
use refineid_auth::PinManageOps as _;
use refineid_auth::{
    PinOps as _, PinRetryRisk, PinSlot, PinStatus, VerifyOutcome,
    pin1_status_permits_reusable_cache,
};
use refineid_cms::container::{EcdsaP384, RsaPkcs1Sha256, Signature};
use refineid_cms::x509::{
    EcCurve, Name, OwnedCert, PublicKeyAlgorithm, SpkiDer, extract_rsa_public_key,
};
use refineid_digest::{SHA256_LEN, SHA384_LEN, SHA512_LEN, Sha1, Sha224, Sha256, Sha384, Sha512};
use refineid_pcsc::{PcscBackend, PcscCard, ReaderAccessCap, ReaderBackend as _, ReaderId};
use refineid_pkcs15::{
    CertSlot, Pkcs15Ops as _, TokenSerial, derive_printed_serial, render_token_serial,
};

use refineid_remote::{
    DisplayText, RemoteKeyProfile, RemoteOperationError, RemoteSignatureAlgorithm, SignatureRequest,
};

use crate::pin::PinBytes;
use crate::pin_cache::PinSafetyCache;
use crate::remote::{REMOTE_SIGN_DEADLINE, RemoteSignError, RemoteTokenSource, SessionCertificate};
use crate::slot_kind::{RemoteSlotId, SlotKind};

#[cfg(feature = "pin-change")]
use crate::ck::CKR_PIN_LEN_RANGE;
use crate::ck::{
    CK_CERTIFICATE_CATEGORY_AUTHORITY, CK_CERTIFICATE_CATEGORY_TOKEN_USER, CK_FALSE, CK_TRUE,
    CKA_ALWAYS_AUTHENTICATE, CKA_ALWAYS_SENSITIVE, CKA_CERTIFICATE_CATEGORY, CKA_CERTIFICATE_TYPE,
    CKA_CLASS, CKA_DERIVE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_ID,
    CKA_ISSUER, CKA_KEY_TYPE, CKA_LABEL, CKA_LOCAL, CKA_MODULUS, CKA_MODULUS_BITS,
    CKA_NEVER_EXTRACTABLE, CKA_PRIVATE, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SERIAL_NUMBER,
    CKA_SIGN, CKA_SIGN_RECOVER, CKA_SUBJECT, CKA_TOKEN, CKA_TRUSTED, CKA_UNWRAP, CKA_VALUE,
    CKA_VERIFY, CKA_WRAP, CKC_X_509, CKK_EC, CKK_RSA, CKO_CERTIFICATE, CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_MECHANISM_INVALID,
    CKR_OK, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
    CKR_USER_NOT_LOGGED_IN, CkAttributeType, CkBbool, CkObjectHandle, CkRv, CkUlong,
};
use crate::sign::{
    CardSignInput, DigestInfoHash, ECDSA_P384_SIGNATURE_BYTES, Mechanism, RSA3072_MODULUS_BITS,
    RSA3072_SIGNATURE_BYTES, parse_digest_info, reject_degenerate_digest, sign_with_card,
};

/// Object handle for the authentication certificate. Fixed for the
/// process; the session's slot disambiguates which card it belongs
/// to. Non-zero (0 is [`crate::ck::CK_INVALID_HANDLE`]).
pub const OBJ_CERTIFICATE: CkObjectHandle = 1;
/// Object handle for the authentication private key. Fixed for the
/// process; shares [`CKA_ID`] with the certificate so NSS pairs them.
pub const OBJ_PRIVATE_KEY: CkObjectHandle = 2;
/// Object handle for the authentication public key, derived from the
/// certificate SPKI. Shares [`CKA_ID`] with the other two objects.
pub const OBJ_PUBLIC_KEY: CkObjectHandle = 3;
/// Base object handle for on-card and persisted CA certificates.
/// Subsequent CA certificates receive sequential handles: `OBJ_CA_BASE + index`.
pub const OBJ_CA_BASE: CkObjectHandle = 4;
/// The handle range one raised token occupies. Each token the module
/// raises takes the next range, so a handle of a withdrawn token
/// names no object of the token that replaced it.
const TOKEN_HANDLE_SPACE: CkObjectHandle = 1 << 16;

/// Fixed human-readable token / object label used when the card's
/// certificate carries no usable common name. NSS shows it in the
/// certificate-selection UI.
const DEFAULT_LABEL: &str = "FINEID";

/// ASN.1 DER tag for `INTEGER` (X.690 s8.3; universal 2). Used to
/// rebuild the [`CKA_SERIAL_NUMBER`] TLV from the parsed value bytes.
const DER_TAG_INTEGER: u8 = 0x02;
/// ASN.1 DER tag for `OCTET STRING` (X.690 s8.7; universal 4). Wraps
/// the SEC1 point for [`CKA_EC_POINT`].
const DER_TAG_OCTET_STRING: u8 = 0x04;
/// X.690 s8.1.3.5 long-form length marker: a length octet with bit 8
/// set introduces long-form length. Values below it are short-form
/// (the length is the octet itself).
const DER_SHORT_FORM_LIMIT: usize = 0x80;
/// X.690 s8.1.3.5 long-form prefix for a length encoded in one
/// subsequent octet (`0x80 | 1`).
const DER_LONG_FORM_ONE_OCTET: u8 = 0x81;
/// X.690 s8.1.3.5 long-form prefix for a length encoded in two
/// subsequent octets (`0x80 | 2`).
const DER_LONG_FORM_TWO_OCTETS: u8 = 0x82;

/// ASN.1 `DigestInfo` prefix for SHA-256 (RFC 8017 s9.2 note 1):
/// `SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL },
/// OCTET STRING (32) }` minus the hash bytes. `CKM_RSA_PKCS`
/// callers pass `DigestInfo || hash` -- the same input shape the
/// sign path takes to the card.
const DIGEST_INFO_SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// DER encoding of the ANSI X9.62 named-curve OID for secp384r1 /
/// NIST P-384 (`1.3.132.0.34`): `OBJECT IDENTIFIER` TLV. This is the
/// value NSS expects for [`CKA_EC_PARAMS`] on the ECC FINEID card
/// (RFC 5480 s2.1.1; SEC2 v2 s2.6.1).
const EC_PARAMS_SECP384R1: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

/// Which of the token's three objects an attribute query refers to.
///
/// HARD LIMIT: never add a `CKO_PROFILE` object (or any object
/// answering `CKA_PROFILE_ID` = `CKP_AUTHENTICATION_TOKEN`). NSS
/// reads that profile as permission to log in proactively and
/// prompts for PIN1 at Firefox startup, before the user asked for
/// anything -- a blocker-severity regression when it was tried
/// (eager PIN1 from `CKP_AUTHENTICATION_TOKEN`). PIN prompts must
/// appear only when a TLS handshake actually needs the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// The X.509 authentication certificate ([`CKO_CERTIFICATE`]).
    Certificate,
    /// The authentication public key ([`CKO_PUBLIC_KEY`]), from the
    /// certificate SPKI.
    PublicKey,
    /// The authentication private key ([`CKO_PRIVATE_KEY`]).
    PrivateKey,
    /// Dynamic CA certificate object at index `usize`.
    Ca(usize),
}

impl ObjectKind {
    /// Resolve an object handle to its kind, or `None` when the
    /// handle names no valid object range this token exposes.
    #[must_use]
    pub(crate) fn from_handle(handle: CkObjectHandle) -> Option<Self> {
        match handle {
            OBJ_CERTIFICATE => Some(Self::Certificate),
            OBJ_PRIVATE_KEY => Some(Self::PrivateKey),
            OBJ_PUBLIC_KEY => Some(Self::PublicKey),
            h if h >= OBJ_CA_BASE => {
                let idx = usize::try_from(h - OBJ_CA_BASE).ok()?;
                Some(Self::Ca(idx))
            }
            _ => None,
        }
    }

    /// The object handle for this kind.
    #[must_use]
    pub(crate) fn handle(self) -> CkObjectHandle {
        match self {
            Self::Certificate => OBJ_CERTIFICATE,
            Self::PrivateKey => OBJ_PRIVATE_KEY,
            Self::PublicKey => OBJ_PUBLIC_KEY,
            Self::Ca(idx) => OBJ_CA_BASE
                .saturating_add(CkObjectHandle::try_from(idx).unwrap_or(CkObjectHandle::MAX)),
        }
    }
}

/// Result of an attribute lookup: either a borrowed slice from certificate
/// or token metadata, an inlined scalar byte buffer, or a marker that the
/// attribute exists but is sensitive (the private key's [`CKA_VALUE`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrValue<'a> {
    /// Borrowed slice from certificate / key DER or token metadata.
    Borrowed(&'a [u8]),
    /// Inlined scalar bytes (for [`CkUlong`], [`CkBbool`]) with zero heap allocations.
    Inline([u8; 8], usize),
    /// The attribute exists but its value is sensitive and withheld.
    Sensitive,
}

impl AttrValue<'_> {
    /// Borrow the underlying attribute bytes if available.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Borrowed(slice) => Some(slice),
            Self::Inline(buf, len) => Some(&buf[..*len]),
            Self::Sensitive => None,
        }
    }
}

/// A parsed and verified CA certificate object on the token.
#[derive(Debug, Clone)]
pub struct CaObject {
    cert: OwnedCert,
    id: Sha1,
    label: String,
    serial_der: Vec<u8>,
}

fn extract_common_name(name: &Name<'_>) -> Option<String> {
    const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    use spki::der::asn1::AnyRef;
    use spki::der::{Decode as _, Reader as _, SliceReader, Tag, Tagged as _};

    let name = AnyRef::from_der(name.as_der()).ok()?;
    if name.tag() != Tag::Sequence {
        return None;
    }
    let mut rdns = SliceReader::new(name.value()).ok()?;
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
            if oid.tag() == Tag::ObjectIdentifier && oid.value() == OID_COMMON_NAME {
                match val.tag() {
                    Tag::Utf8String => {
                        return core::str::from_utf8(val.value()).ok().map(String::from);
                    }
                    Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => {
                        return val
                            .value()
                            .iter()
                            .all(u8::is_ascii)
                            .then(|| String::from_utf8_lossy(val.value()).into_owned());
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

impl CaObject {
    pub(crate) fn new(cert: OwnedCert) -> Self {
        let view = cert.view();
        let label =
            extract_common_name(&view.subject).unwrap_or_else(|| "CA Certificate".to_owned());
        let id = Sha1::of(view.spki.as_der());
        let serial_der = der_integer(view.serial_der);
        Self {
            cert,
            id,
            label,
            serial_der,
        }
    }

    #[must_use]
    pub(crate) fn id_bytes(&self) -> &[u8] {
        self.id.as_bytes()
    }

    #[must_use]
    pub(crate) fn label_bytes(&self) -> &[u8] {
        self.label.as_bytes()
    }

    #[must_use]
    pub(crate) fn serial_der(&self) -> &[u8] {
        &self.serial_der
    }
}

/// An invariant-preserving trust store that guarantees:
/// 1. Zero duplicate certificates (enforced at insertion by DER comparison).
/// 2. Stable discovery order and sequential handle indexing (`OBJ_CA_BASE + index`).
/// 3. Total operations — no indexing panics, no out-of-bounds states.
#[derive(Debug, Default, Clone)]
pub struct RefinedTrustStore {
    distinct_anchors: Vec<CaObject>,
}

impl RefinedTrustStore {
    /// Construct a store from an initial set of distinct CA objects.
    #[expect(
        dead_code,
        reason = "constructor for distinct CA sets used in tests and custom initialization"
    )]
    #[must_use]
    pub fn new(initial: impl IntoIterator<Item = CaObject>) -> Self {
        let mut store = Self {
            distinct_anchors: Vec::new(),
        };
        for obj in initial {
            store.push_anchor(obj);
        }
        store
    }

    /// Total, infallible prepending that preserves uniqueness by construction.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "prepends anchors for tests and dynamic updates")
    )]
    pub fn prepend_anchor(&mut self, anchor: CaObject) {
        if self.contains(&anchor.cert) {
            return;
        }
        let mut updated = Vec::with_capacity(self.distinct_anchors.len().saturating_add(1));
        updated.push(anchor);
        updated.extend(core::mem::take(&mut self.distinct_anchors));
        self.distinct_anchors = updated;
    }

    /// Append an anchor if not already present.
    pub fn push_anchor(&mut self, anchor: CaObject) {
        if self.contains(&anchor.cert) {
            return;
        }
        self.distinct_anchors.push(anchor);
    }

    /// Check if a certificate is present in the store.
    #[must_use]
    pub fn contains(&self, cert: &OwnedCert) -> bool {
        self.distinct_anchors
            .iter()
            .any(|existing| existing.cert.as_der() == cert.as_der())
    }

    /// Number of distinct CA certificates in the store.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn len(&self) -> usize {
        self.distinct_anchors.len()
    }

    /// Whether the store is empty.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.distinct_anchors.is_empty()
    }

    /// Safe, total lookup by index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&CaObject> {
        self.distinct_anchors.get(index)
    }

    /// Iterate over distinct CA certificates.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn iter(&self) -> core::slice::Iter<'_, CaObject> {
        self.distinct_anchors.iter()
    }
}

/// Strongly typed key material parsed from the card profile certificate SPKI.
#[derive(Debug, Clone)]
pub enum TokenKeyMaterial {
    Rsa {
        modulus: Vec<u8>,
        modulus_bits: CkUlong,
        public_exponent: Vec<u8>,
    },
    Ec {
        params: &'static [u8],
        point: Vec<u8>,
    },
}

impl TokenKeyMaterial {
    fn extract(spki: &SpkiDer<'_>) -> Result<Self, CkRv> {
        match spki.algorithm() {
            PublicKeyAlgorithm::Rsa { modulus_bits } => {
                let public = extract_rsa_public_key(spki.as_der()).ok_or(CKR_DEVICE_ERROR)?;
                let bits = CkUlong::try_from(modulus_bits).map_err(|_| CKR_DEVICE_ERROR)?;
                Ok(Self::Rsa {
                    modulus: public.modulus.as_bytes().to_vec(),
                    modulus_bits: bits,
                    public_exponent: public.exponent.as_bytes().to_vec(),
                })
            }
            PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
                let point = spki.ec_public_key_point().ok_or(CKR_DEVICE_ERROR)?;
                Ok(Self::Ec {
                    params: &EC_PARAMS_SECP384R1,
                    point: der_octet_string(point.as_bytes()),
                })
            }
            PublicKeyAlgorithm::Ec(_)
            | PublicKeyAlgorithm::EcExplicit { .. }
            | PublicKeyAlgorithm::Other => Err(CKR_DEVICE_ERROR),
        }
    }

    #[must_use]
    pub(crate) const fn key_type(&self) -> CkUlong {
        match self {
            Self::Rsa { .. } => CKK_RSA,
            Self::Ec { .. } => CKK_EC,
        }
    }

    #[must_use]
    pub(crate) const fn mechanism(&self) -> Mechanism {
        match self {
            Self::Rsa { .. } => Mechanism::RsaPkcs,
            Self::Ec { .. } => Mechanism::Ecdsa,
        }
    }
}

/// The token objects, parsed from the card's authentication
/// certificate and cached per slot while the same card stays present.
#[derive(Debug, Clone)]
pub struct TokenObjects {
    /// The parsed leaf authentication certificate.
    auth_cert: OwnedCert,
    /// [`CKA_ID`]: SHA-1 of the SPKI DER, shared by cert and key.
    auth_cert_id: Sha1,
    /// Human-readable label for [`CKA_LABEL`] (common name, else [`DEFAULT_LABEL`]).
    auth_cert_label: String,
    /// Pre-encoded serial number DER INTEGER for the authentication certificate.
    auth_cert_serial_der: Vec<u8>,
    /// Chip serial from PKCS#15 EF.TokenInfo: the plastic-printed
    /// card identifier when [`derive_printed_serial`] recognises
    /// the chip generation (the form a citizen can check against
    /// the card body), else the full rendered serial via
    /// [`render_token_serial`]; empty when the card reports none.
    /// Reported in `CK_TOKEN_INFO.serialNumber`.
    token_serial: String,
    /// Key-type specific material extracted and validated from the SPKI.
    key_material: TokenKeyMaterial,
    /// Intermediate and root CA certificate store.
    ca_store: RefinedTrustStore,
    /// Which raised token these objects belong to; its handles are
    /// offset by this many [`TOKEN_HANDLE_SPACE`]s.
    generation: CkObjectHandle,
}

/// Encode a [`CkUlong`] attribute value into an inline zero-allocation buffer.
#[expect(
    clippy::host_endian_bytes,
    reason = "PKCS#11 CK_ULONG attribute values live in caller memory as a native-endian machine word; NSS reads them back as CK_ULONG, so the on-wire bytes must match the host byte order, not a fixed endianness"
)]
fn ulong_attr(value: CkUlong) -> AttrValue<'static> {
    let bytes = value.to_ne_bytes();
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(&bytes);
    AttrValue::Inline(buf, bytes.len())
}

/// Encode a [`CkBbool`] attribute value into an inline zero-allocation buffer.
fn bool_attr(value: CkBbool) -> AttrValue<'static> {
    let mut buf = [0u8; 8];
    buf[0] = value;
    AttrValue::Inline(buf, 1)
}

/// Number of bits per byte used for length shifts.
const BITS_PER_BYTE: u32 = 8;
/// Mask to extract a single low byte from an integer.
const BYTE_MASK: usize = 0xFF;

/// Append a DER length for `len` to `out` (X.690 s8.1.3). Handles the
/// short form and one/two-octet long forms; every value this module
/// encodes is far below 65536 bytes.
fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < DER_SHORT_FORM_LIMIT {
        if let Ok(short) = u8::try_from(len) {
            out.push(short);
        }
    } else if let Ok(one) = u8::try_from(len) {
        out.push(DER_LONG_FORM_ONE_OCTET);
        out.push(one);
    } else {
        let high =
            u8::try_from((len.checked_shr(BITS_PER_BYTE).unwrap_or(0)) & BYTE_MASK).unwrap_or(0);
        let low = u8::try_from(len & BYTE_MASK).unwrap_or(0);
        out.push(DER_LONG_FORM_TWO_OCTETS);
        out.push(high);
        out.push(low);
    }
}

/// Rebuild a DER `INTEGER` TLV from the certificate's serial value
/// bytes (`Certificate::serial_der` yields the INTEGER contents only,
/// no tag/length). NSS matches [`CKA_SERIAL_NUMBER`] against the full
/// TLV.
fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_add(2));
    out.push(DER_TAG_INTEGER);
    push_der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Wrap a SEC1 EC point in a DER `OCTET STRING` TLV for [`CKA_EC_POINT`]
/// per PKCS#11 v2.40 s2.3.4.
fn der_octet_string(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_add(2));
    out.push(DER_TAG_OCTET_STRING);
    push_der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Reject empty byte slices by mapping them to `None`.
fn non_empty(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() { None } else { Some(bytes) }
}

impl TokenObjects {
    /// Build token objects from the card's leaf authentication certificate
    /// DER bytes. Initializes an empty trust store populated dynamically from
    /// persisted cache and on-card CA slots.
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] if the DER does not parse or the key
    /// algorithm is neither RSA nor secp384r1 EC (the only two FINEID
    /// auth profiles).
    pub(crate) fn from_cert_der(cert_der: Vec<u8>) -> Result<Self, CkRv> {
        let auth_cert = OwnedCert::from_der(&cert_der).map_err(|_parse_err| CKR_DEVICE_ERROR)?;
        let view = auth_cert.view();
        let key_material = TokenKeyMaterial::extract(&view.spki)?;
        let auth_cert_id = Sha1::of(view.spki.as_der());
        let auth_cert_label =
            extract_common_name(&view.subject).unwrap_or_else(|| DEFAULT_LABEL.to_owned());
        let auth_cert_serial_der = der_integer(view.serial_der);
        let ca_store = RefinedTrustStore::default();
        Ok(Self {
            auth_cert,
            auth_cert_id,
            auth_cert_label,
            auth_cert_serial_der,
            token_serial: String::new(),
            key_material,
            ca_store,
            generation: 0,
        })
    }

    /// Place the objects in the handle range of the token being
    /// raised.
    pub(crate) const fn set_generation(&mut self, generation: CkObjectHandle) {
        self.generation = generation;
    }

    /// The handle of one of this token's objects.
    #[must_use]
    pub(crate) fn handle(&self, kind: ObjectKind) -> CkObjectHandle {
        self.generation
            .saturating_mul(TOKEN_HANDLE_SPACE)
            .saturating_add(kind.handle())
    }

    /// The object a handle names on this token, or `None` for a
    /// handle of another token or of no object.
    #[must_use]
    pub(crate) fn kind_of(&self, handle: CkObjectHandle) -> Option<ObjectKind> {
        if handle / TOKEN_HANDLE_SPACE != self.generation {
            return None;
        }
        let kind = ObjectKind::from_handle(handle % TOKEN_HANDLE_SPACE)?;
        self.object_exists(kind).then_some(kind)
    }

    /// The sign mechanism for this card profile.
    #[must_use]
    pub(crate) const fn mechanism(&self) -> Mechanism {
        self.key_material.mechanism()
    }

    /// The rendered chip serial from EF.TokenInfo; empty when the
    /// card did not report one.
    #[must_use]
    pub(crate) fn token_serial(&self) -> &str {
        &self.token_serial
    }

    /// Name the token by the pairing it is served through.
    pub(crate) fn set_token_serial(&mut self, serial: String) {
        self.token_serial = serial;
    }

    /// The authentication certificate's DER, as the token carries it.
    #[must_use]
    pub(crate) fn auth_cert_der(&self) -> &[u8] {
        self.auth_cert.as_der()
    }

    /// The key a phone-served token signs with, decided from the
    /// certificate's public key.
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] when the key is neither RSA-3072 nor
    /// P-384, the two profiles a FINEID authentication key has.
    pub(crate) fn remote_key(&self) -> Result<RemoteKey, CkRv> {
        match &self.key_material {
            TokenKeyMaterial::Rsa { modulus_bits, .. } if *modulus_bits == RSA3072_MODULUS_BITS => {
                Ok(RemoteKey::Rsa3072)
            }
            TokenKeyMaterial::Ec { params, .. } if *params == EC_PARAMS_SECP384R1 => {
                Ok(RemoteKey::EcdsaP384)
            }
            TokenKeyMaterial::Rsa { .. } | TokenKeyMaterial::Ec { .. } => Err(CKR_DEVICE_ERROR),
        }
    }

    /// Look up one attribute of one object.
    ///
    /// Returns `None` when the attribute type does not apply to the
    /// object (the caller maps that to
    /// [`crate::ck::CKR_ATTRIBUTE_TYPE_INVALID`]); returns
    /// [`AttrValue::Sensitive`] for the private key's [`CKA_VALUE`].
    #[must_use]
    pub(crate) fn attribute(
        &self,
        kind: ObjectKind,
        attr: CkAttributeType,
    ) -> Option<AttrValue<'_>> {
        match kind {
            ObjectKind::Certificate => self.certificate_attribute(attr),
            ObjectKind::PublicKey => self.public_key_attribute(attr),
            ObjectKind::PrivateKey => self.private_key_attribute(attr),
            ObjectKind::Ca(_) => self.ca_attribute(kind, attr),
        }
    }

    /// Look up the CA certificate object matching `kind` by dynamic index.
    pub(crate) fn ca_object_for_kind(&self, kind: ObjectKind) -> Option<&CaObject> {
        match kind {
            ObjectKind::Ca(idx) => self.ca_store.get(idx),
            ObjectKind::Certificate | ObjectKind::PrivateKey | ObjectKind::PublicKey => None,
        }
    }

    /// Attribute lookup for an on-card CA certificate object matching `kind`.
    fn ca_attribute(&self, kind: ObjectKind, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        let ca = self.ca_object_for_kind(kind)?;
        let view = ca.cert.view();
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_CERTIFICATE)),
            CKA_CERTIFICATE_TYPE => Some(ulong_attr(CKC_X_509)),
            CKA_CERTIFICATE_CATEGORY => Some(ulong_attr(CK_CERTIFICATE_CATEGORY_AUTHORITY)),
            CKA_TOKEN => Some(bool_attr(CK_TRUE)),
            // Token CA certificates are intermediate path-building candidates for NSS
            // client-certificate TLS authentication, not ambient trust anchors for
            // server verification (PKCS#11 v2.40 §4.4: CKA_TRUSTED; NSS lib/pk11wrap/pk11cert.c
            // imports token certificates into its session cache without requiring CKA_TRUSTED).
            CKA_PRIVATE | CKA_TRUSTED => Some(bool_attr(CK_FALSE)),
            CKA_LABEL => Some(AttrValue::Borrowed(ca.label_bytes())),
            CKA_ID => Some(AttrValue::Borrowed(ca.id_bytes())),
            CKA_VALUE => Some(AttrValue::Borrowed(ca.cert.as_der())),
            CKA_ISSUER => non_empty(view.issuer.as_der()).map(AttrValue::Borrowed),
            CKA_SUBJECT => non_empty(view.subject.as_der()).map(AttrValue::Borrowed),
            CKA_SERIAL_NUMBER => non_empty(ca.serial_der()).map(AttrValue::Borrowed),
            _ => None,
        }
    }

    /// Attribute lookup for the certificate object.
    ///
    /// [`CKA_TRUSTED`] and [`CKA_LOCAL`] are answered `CK_FALSE`
    /// rather than left absent: both are honest (an end-entity
    /// credential is not a trust anchor; the certificate was
    /// personalised by DVV, not generated through this module) and a
    /// concrete answer keeps `pkcs11-tool --list-objects` free of
    /// attribute-read failure noise.
    fn certificate_attribute(&self, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        let view = self.auth_cert.view();
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_CERTIFICATE)),
            CKA_CERTIFICATE_TYPE => Some(ulong_attr(CKC_X_509)),
            CKA_CERTIFICATE_CATEGORY => Some(ulong_attr(CK_CERTIFICATE_CATEGORY_TOKEN_USER)),
            CKA_KEY_TYPE => Some(ulong_attr(self.key_material.key_type())),
            CKA_TOKEN => Some(bool_attr(CK_TRUE)),
            CKA_PRIVATE | CKA_TRUSTED | CKA_LOCAL => Some(bool_attr(CK_FALSE)),
            CKA_LABEL => Some(AttrValue::Borrowed(self.auth_cert_label.as_bytes())),
            CKA_ID => Some(AttrValue::Borrowed(self.auth_cert_id.as_bytes())),
            CKA_VALUE => Some(AttrValue::Borrowed(self.auth_cert.as_der())),
            CKA_ISSUER => non_empty(view.issuer.as_der()).map(AttrValue::Borrowed),
            CKA_SUBJECT => non_empty(view.subject.as_der()).map(AttrValue::Borrowed),
            CKA_SERIAL_NUMBER => non_empty(&self.auth_cert_serial_der).map(AttrValue::Borrowed),
            _ => None,
        }
    }

    /// Attribute lookup for the public key object, served from the
    /// certificate SPKI. [`CKA_VERIFY`] is `CK_TRUE` (the key's
    /// purpose per the certificate); the other usage flags are
    /// `CK_FALSE` because this token performs none of those
    /// operations.
    fn public_key_attribute(&self, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_PUBLIC_KEY)),
            CKA_KEY_TYPE => Some(ulong_attr(self.key_material.key_type())),
            CKA_TOKEN | CKA_VERIFY => Some(bool_attr(CK_TRUE)),
            CKA_PRIVATE | CKA_ENCRYPT | CKA_WRAP | CKA_DERIVE => Some(bool_attr(CK_FALSE)),
            CKA_LABEL => Some(AttrValue::Borrowed(self.auth_cert_label.as_bytes())),
            CKA_ID => Some(AttrValue::Borrowed(self.auth_cert_id.as_bytes())),
            CKA_SUBJECT => {
                non_empty(self.auth_cert.view().subject.as_der()).map(AttrValue::Borrowed)
            }
            CKA_MODULUS => match &self.key_material {
                TokenKeyMaterial::Rsa { modulus, .. } => Some(AttrValue::Borrowed(modulus)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_MODULUS_BITS => match &self.key_material {
                TokenKeyMaterial::Rsa { modulus_bits, .. } => Some(ulong_attr(*modulus_bits)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_PUBLIC_EXPONENT => match &self.key_material {
                TokenKeyMaterial::Rsa {
                    public_exponent, ..
                } => Some(AttrValue::Borrowed(public_exponent)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_EC_PARAMS => match &self.key_material {
                TokenKeyMaterial::Ec { params, .. } => Some(AttrValue::Borrowed(params)),
                TokenKeyMaterial::Rsa { .. } => None,
            },
            CKA_EC_POINT => match &self.key_material {
                TokenKeyMaterial::Ec { point, .. } => Some(AttrValue::Borrowed(point)),
                TokenKeyMaterial::Rsa { .. } => None,
            },
            _ => None,
        }
    }

    /// Attribute lookup for the private key object.
    ///
    /// The extractability triple ([`CKA_EXTRACTABLE`] false,
    /// [`CKA_NEVER_EXTRACTABLE`] / [`CKA_ALWAYS_SENSITIVE`] true)
    /// states the FINEID guarantee that the private key never leaves
    /// the card -- it is what a security review greps for, and an
    /// absent attribute never matches a find template asking for
    /// `CKA_EXTRACTABLE = FALSE`.
    fn private_key_attribute(&self, attr: CkAttributeType) -> Option<AttrValue<'_>> {
        match attr {
            CKA_CLASS => Some(ulong_attr(CKO_PRIVATE_KEY)),
            CKA_KEY_TYPE => Some(ulong_attr(self.key_material.key_type())),
            CKA_TOKEN
            | CKA_PRIVATE
            | CKA_SIGN
            | CKA_SENSITIVE
            | CKA_NEVER_EXTRACTABLE
            | CKA_ALWAYS_SENSITIVE => Some(bool_attr(CK_TRUE)),
            CKA_ALWAYS_AUTHENTICATE
            | CKA_EXTRACTABLE
            | CKA_SIGN_RECOVER
            | CKA_UNWRAP
            | CKA_DERIVE => Some(bool_attr(CK_FALSE)),
            CKA_LABEL => Some(AttrValue::Borrowed(self.auth_cert_label.as_bytes())),
            CKA_ID => Some(AttrValue::Borrowed(self.auth_cert_id.as_bytes())),
            CKA_SUBJECT => {
                non_empty(self.auth_cert.view().subject.as_der()).map(AttrValue::Borrowed)
            }
            CKA_VALUE => Some(AttrValue::Sensitive),
            CKA_MODULUS => match &self.key_material {
                TokenKeyMaterial::Rsa { modulus, .. } => Some(AttrValue::Borrowed(modulus)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_MODULUS_BITS => match &self.key_material {
                TokenKeyMaterial::Rsa { modulus_bits, .. } => Some(ulong_attr(*modulus_bits)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_PUBLIC_EXPONENT => match &self.key_material {
                TokenKeyMaterial::Rsa {
                    public_exponent, ..
                } => Some(AttrValue::Borrowed(public_exponent)),
                TokenKeyMaterial::Ec { .. } => None,
            },
            CKA_EC_PARAMS => match &self.key_material {
                TokenKeyMaterial::Ec { params, .. } => Some(AttrValue::Borrowed(params)),
                TokenKeyMaterial::Rsa { .. } => None,
            },
            CKA_EC_POINT => match &self.key_material {
                TokenKeyMaterial::Ec { point, .. } => Some(AttrValue::Borrowed(point)),
                TokenKeyMaterial::Rsa { .. } => None,
            },
            _ => None,
        }
    }

    /// Add an on-card CA certificate to the end of the token cache.
    pub(crate) fn push_ca_cert(&mut self, cert: OwnedCert) {
        self.ca_store.push_anchor(CaObject::new(cert));
    }

    /// Software signature verification against the cached
    /// certificate public key -- pure host-side computation, no
    /// card IO, no PIN. Serves `C_Verify` so `pkcs11-tool
    /// --verify` and libp11-style consumers work without the
    /// caller re-extracting the public key.
    ///
    /// Input shapes mirror the sign path exactly:
    /// `CKM_RSA_PKCS` takes `DigestInfo || SHA-256 hash`;
    /// `CKM_ECDSA` takes a raw digest (SHA-1/224/256/384/512
    /// lengths accepted) with raw `r || s` signatures.
    pub(crate) fn verify_signature(
        &self,
        mechanism: Mechanism,
        data: &[u8],
        signature: &[u8],
    ) -> CkRv {
        if signature.len() != mechanism.signature_len() {
            return CKR_SIGNATURE_LEN_RANGE;
        }
        match mechanism {
            Mechanism::RsaPkcs => self.verify_rsa_pkcs(data, signature),
            Mechanism::Ecdsa => self.verify_ecdsa(data, signature),
        }
    }

    /// `CKM_RSA_PKCS` software verify: strict `DigestInfo`
    /// (SHA-256) input, PKCS#1 v1.5 padding check in lib-core.
    fn verify_rsa_pkcs(&self, data: &[u8], signature: &[u8]) -> CkRv {
        let Some(hash) = data.strip_prefix(&DIGEST_INFO_SHA256_PREFIX) else {
            return CKR_DATA_INVALID;
        };
        let Ok(digest) = <[u8; 32]>::try_from(hash) else {
            return CKR_DATA_INVALID;
        };
        let Some(key) = extract_rsa_public_key(self.auth_cert.view().spki.as_der()) else {
            return CKR_DEVICE_ERROR;
        };
        let sig = Signature::<RsaPkcs1Sha256>::new(signature.to_vec());
        match key.verify_pkcs1v15_sha256_digest(&digest, &sig) {
            Ok(()) => CKR_OK,
            Err(_mismatch) => CKR_SIGNATURE_INVALID,
        }
    }

    /// `CKM_ECDSA` software verify: the digest length selects the
    /// hash family (PKCS#11 attaches no hash to `CKM_ECDSA`; the
    /// caller already hashed), the signature is card-native raw
    /// `r || s`.
    fn verify_ecdsa(&self, data: &[u8], signature: &[u8]) -> CkRv {
        let Some(point) = self.auth_cert.view().spki.ec_public_key_point() else {
            return CKR_DEVICE_ERROR;
        };
        let sig = Signature::<EcdsaP384>::new(signature.to_vec());
        let outcome = if let Ok(digest) = <[u8; 20]>::try_from(data) {
            point.verify_p384_sha1_raw(sig, Sha1::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 28]>::try_from(data) {
            point.verify_p384_sha224_raw(sig, Sha224::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 32]>::try_from(data) {
            point.verify_p384_sha256_raw(sig, Sha256::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 48]>::try_from(data) {
            point.verify_p384_sha384_raw(sig, Sha384::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 64]>::try_from(data) {
            point.verify_p384_sha512_raw(sig, Sha512::from_bytes(digest))
        } else {
            return CKR_DATA_LEN_RANGE;
        };
        match outcome {
            Ok(()) => CKR_OK,
            Err(_mismatch) => CKR_SIGNATURE_INVALID,
        }
    }

    /// Check whether this object exists in the token.
    #[must_use]
    pub(crate) fn object_exists(&self, kind: ObjectKind) -> bool {
        match kind {
            ObjectKind::Certificate | ObjectKind::PublicKey | ObjectKind::PrivateKey => true,
            ObjectKind::Ca(idx) => self.ca_store.get(idx).is_some(),
        }
    }

    /// Return all active object kinds present on this token.
    #[must_use]
    pub(crate) fn all_object_kinds(&self) -> Vec<ObjectKind> {
        let mut kinds = vec![
            ObjectKind::Certificate,
            ObjectKind::PublicKey,
            ObjectKind::PrivateKey,
        ];
        for idx in 0..self.ca_store.len() {
            kinds.push(ObjectKind::Ca(idx));
        }
        kinds
    }

    /// Test whether an object matches every `(type, value)` pair in a
    /// `C_FindObjects` template. A template entry matches only when
    /// the attribute is present, concrete, and byte-equal; a
    /// sensitive or absent attribute never matches.
    #[must_use]
    pub(crate) fn matches(
        &self,
        kind: ObjectKind,
        template: &[(CkAttributeType, Vec<u8>)],
    ) -> bool {
        if !self.object_exists(kind) {
            return false;
        }
        template.iter().all(|(attr, wanted)| {
            self.attribute(kind, *attr)
                .is_some_and(|val| val.as_bytes() == Some(wanted.as_slice()))
        })
    }
}

/// Resolve the filesystem directory used for caching on-card CA certificates.
///
/// Cache-directory integrity relies on the OS user profile's access control
/// lists (ACLs) to prevent unauthorized modification of cached CA certificates
/// by other users. Local attackers possessing access to the user profile are
/// out of scope.
///
/// The cache is shared across all identity cards inserted for this user profile
/// and seeded across sessions. Cached certificates are untrusted intermediates
/// (served with `CKA_TRUSTED = CK_FALSE`), never ambient trust anchors.
fn persistent_ca_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("REFINEID_CA_CACHE_DIR")
        && !dir.is_empty()
    {
        return Some(std::path::PathBuf::from(dir));
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA")
            && !local_app_data.is_empty()
        {
            return Some(
                std::path::PathBuf::from(local_app_data)
                    .join("refineid")
                    .join("ca-certificates"),
            );
        }
        if let Ok(app_data) = std::env::var("APPDATA")
            && !app_data.is_empty()
        {
            return Some(
                std::path::PathBuf::from(app_data)
                    .join("refineid")
                    .join("ca-certificates"),
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME")
            && !home.is_empty()
        {
            return Some(
                std::path::PathBuf::from(home).join("Library/Caches/fi.refineid/ca-certificates"),
            );
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(xdg_cache) = std::env::var("XDG_CACHE_HOME")
            && !xdg_cache.is_empty()
        {
            return Some(
                std::path::PathBuf::from(xdg_cache)
                    .join("refineid")
                    .join("ca-certificates"),
            );
        }
        if let Ok(home) = std::env::var("HOME")
            && !home.is_empty()
        {
            return Some(std::path::PathBuf::from(home).join(".cache/refineid/ca-certificates"));
        }
    }
    None
}

const MAX_CA_CERTS: usize = 16;
const MAX_CA_CERT_BYTES: u64 = 65536;

/// Check if an X.509 certificate's validity window includes `now` (fail closed).
///
/// Citing RFC 5280 §4.1.2.5: "The validity period for a certificate is the period
/// of time from notBefore through notAfter, inclusive."
fn is_cert_valid_at(cert: &OwnedCert, now: std::time::Duration) -> bool {
    let view = cert.view();
    view.not_before.unix_duration() <= now && now <= view.not_after.unix_duration()
}

/// Check if an X.509 certificate's validity window is currently valid (fail closed).
fn is_cert_valid(cert: &OwnedCert) -> bool {
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    is_cert_valid_at(cert, now)
}

/// Check if an X.509 certificate asserts certificate authority status via `BasicConstraints` CA:TRUE.
///
/// Citing RFC 5280 §4.2.1.9: "The cA boolean indicates whether the certified public key
/// may be used to verify certificate signatures. ... If the basic constraints extension
/// is not present in a version 3 certificate, or the extension is present but the cA
/// boolean is not asserted, then the certified public key MUST NOT be used to verify
/// certificate signatures."
fn is_ca_cert(cert: &OwnedCert) -> bool {
    let view = cert.view();
    view.extensions
        .is_some_and(|exts| refineid_cms::x509::extract_basic_constraints(exts).ca)
}

/// Check if a certificate meets the persistence policy: unexpired and asserts CA status.
fn meets_ca_persistence_policy(cert: &OwnedCert) -> bool {
    is_cert_valid(cert) && is_ca_cert(cert)
}

/// Load persisted CA certificates from a directory, purging any expired, oversized, or non-CA ones.
fn load_persisted_ca_certs_from(dir: &std::path::Path) -> Vec<OwnedCert> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries.flatten() {
        if paths.len() >= MAX_CA_CERTS * 4 {
            break;
        }
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("der"))
        {
            paths.push(path);
        }
    }
    paths.sort();

    let mut certs = Vec::new();
    for path in paths {
        if certs.len() >= MAX_CA_CERTS {
            break;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || metadata.len() > MAX_CA_CERT_BYTES {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > usize::try_from(MAX_CA_CERT_BYTES).unwrap_or(usize::MAX) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(cert) = OwnedCert::from_der(&bytes) else {
            let _ = std::fs::remove_file(&path);
            continue;
        };
        if !meets_ca_persistence_policy(&cert) {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        certs.push(cert);
    }
    certs
}

/// Load persisted CA certificates from disk, purging any expired ones.
fn load_persisted_ca_certs() -> Vec<OwnedCert> {
    persistent_ca_dir().map_or_else(Vec::new, |dir| load_persisted_ca_certs_from(&dir))
}

/// Persist a policy-conformant CA certificate to a specific directory.
fn persist_ca_cert_to(dir: &std::path::Path, cert: &OwnedCert) {
    if !meets_ca_persistence_policy(cert) {
        return;
    }
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let der = cert.as_der();
    let fingerprint = Sha256::of(der);
    let hex_name = hex::encode(fingerprint.as_bytes());
    let final_path = dir.join(format!("{hex_name}.der"));
    if final_path.exists() {
        return;
    }
    let temp_name = format!(".{hex_name}.tmp.{}", std::process::id());
    let temp_path = dir.join(temp_name);
    let write_res = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .and_then(|mut f| {
            f.write_all(der)?;
            f.flush()
        });
    if write_res.is_ok() {
        if std::fs::rename(&temp_path, &final_path).is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
    } else {
        let _ = std::fs::remove_file(&temp_path);
    }
}

/// Persist a policy-conformant CA certificate to disk.
fn persist_ca_cert(cert: &OwnedCert) {
    if let Some(dir) = persistent_ca_dir() {
        persist_ca_cert_to(&dir, cert);
    }
}

/// Attempt to read and parse an optional CA certificate from a card slot.
///
/// Returns `Some(OwnedCert)` when the slot is populated on the card profile
/// and contains a valid DER X.509 certificate; returns `None` when the slot
/// is absent on older card generations or unreadable.
fn read_optional_ca_cert(card: &mut PcscCard, slot: CertSlot) -> Option<OwnedCert> {
    let raw = match card.read_certificate(slot) {
        Ok(raw) => raw,
        Err(_read_err) => return None,
    };
    OwnedCert::from_der(raw.as_bytes()).ok()
}

/// Build the token objects for `reader_name`: open the card once,
/// read EF.TokenInfo (chip serial, card label) and the
/// authentication certificate via the PKCS#15 chain, drop the
/// card, and parse.
///
/// A missing or unreadable EF.TokenInfo is tolerated (empty
/// serial / label); the certificate read is mandatory.
///
/// # Errors
/// [`CKR_DEVICE_ERROR`] if the reader cannot be opened or the
/// certificate cannot be read or parsed.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling state module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn build_token_objects(reader: &ReaderId) -> Result<TokenObjects, CkRv> {
    let backend = PcscBackend;
    let mut card = backend
        .open_session(reader, ReaderAccessCap::Read)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    let token_info = card.read_token_info().ok();
    let serial = token_info
        .as_ref()
        .and_then(|info| info.serial_number_hex())
        .cloned()
        .map(render_token_serial)
        .map(|full| {
            derive_printed_serial(&full).map_or_else(
                || full.as_str().to_owned(),
                |printed| printed.as_str().to_owned(),
            )
        });
    let cert = card
        .read_certificate(CertSlot::Authentication)
        .or_else(|_| card.read_certificate(CertSlot::AuthenticationAlt))
        .map_err(|_read_err| CKR_DEVICE_ERROR)?;

    let mut cas = load_persisted_ca_certs();
    let mut objects = TokenObjects::from_cert_der(cert.as_bytes().to_vec())?;
    if let Some(serial) = serial {
        objects.token_serial = serial;
    }

    let leaf_issuer = objects.auth_cert.view().issuer;
    // Skip on-card CA reads when a cached CA already matches the leaf certificate's
    // issuer DN. This rests on two assumptions:
    // (a) Matching issuer DN identifies the necessary issuing CA chain element.
    //     (A re-issued CA with the same DN but a different key would serve the cached
    //     intermediate until its expiration).
    // (b) Presence of the issuing intermediate implies the root CA is also cached,
    //     as both slots are persisted as a pair and roots outlive intermediates.
    let has_leaf_issuer = cas
        .iter()
        .any(|ca| ca.view().subject.as_der() == leaf_issuer.as_der());
    if !has_leaf_issuer {
        let on_card_cas: Vec<OwnedCert> = [CertSlot::IssuingCaEcc, CertSlot::RootCa]
            .into_iter()
            .filter_map(|slot| read_optional_ca_cert(&mut card, slot))
            .filter(meets_ca_persistence_policy)
            .collect();
        for ca in &on_card_cas {
            persist_ca_cert(ca);
        }
        for ca in on_card_cas {
            if !cas.iter().any(|c| c.as_der() == ca.as_der()) {
                cas.push(ca);
            }
        }
    }
    drop(card);

    for ca in cas {
        objects.push_ca_cert(ca);
    }
    Ok(objects)
}

/// Probe the live PIN1 retry state without consuming a retry.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_pin1_status(kind: &SlotKind) -> Result<PinStatus, CkRv> {
    // A remote reader reports its own PIN1 state over an authenticated
    // pairing, and this computer has no card to ask. Reaching this arm
    // requires a host-admitted pairing, not a reader name.
    let Some(reader) = kind.local_reader() else {
        return Ok(PinStatus::Verified);
    };
    let backend = PcscBackend;
    let mut card = backend
        .open_session(reader, ReaderAccessCap::Read)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    card.pin_status(PinSlot::Pin1)
        .map_err(|_status_err| CKR_DEVICE_ERROR)
}

/// Run a signature on the card of a local reader.
///
/// Mirrors the proven FINEID chain: open the card, select the
/// PKCS#15 application, VERIFY PIN1 in that application context (the
/// card refuses VERIFY from MF context with `SW=6985`), then run the
/// pre-hashed PSO chain via [`sign_with_card`]. The whole sequence
/// runs inside one PC/SC transaction ([`PcscCard::pin_sequence`])
/// that ends with a card reset, so no other PC/SC client can slip a
/// command between the VERIFY and the signature or use the verified
/// state afterwards.
///
/// PIN1 is presented for every signature: the card drops its PIN1
/// verification after each signature with the authentication key
/// (FINEID S4-1 v4.2 section 8.1.7). The held PIN1 is checked out for
/// the card's token serial under the retry state the card reports in
/// the same card session, settled by the card's answer to the VERIFY
/// ([`crate::pin_cache::CheckedOutPin1::settle_verify`]), and an
/// accepted value settled again by what became of the card in the
/// signature ([`crate::pin_cache::AcceptedPin1::settle_operation`]).
/// The reader's card lane is held from before the checkout until the
/// value is settled.
///
/// # Errors
/// [`CKR_DATA_INVALID`] / [`CKR_DATA_LEN_RANGE`] on bad input, before
/// the card is opened; [`CKR_USER_NOT_LOGGED_IN`] when no usable PIN1
/// is held; [`CKR_PIN_INCORRECT`] / [`CKR_PIN_LOCKED`] on PIN failure;
/// [`CKR_DEVICE_ERROR`] on any other card / transport failure.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_sign(
    kind: &SlotKind,
    pin_cache: &Arc<Mutex<PinSafetyCache>>,
    mechanism: Mechanism,
    input: &[u8],
) -> Result<Vec<u8>, CkRv> {
    let request = CardSignInput::parse(mechanism, input)?;
    let backend = PcscBackend;
    // A remote slot has no local reader; its signatures go through
    // `remote_card_sign`.
    let reader = kind.local_reader().ok_or(CKR_DEVICE_ERROR)?;
    // The lane keeps this process's other PIN-bearing operations on
    // this reader waiting until the held PIN1 is settled. The PIN is
    // already in the cache -- no prompt or non-card wait happens while
    // the card is open.
    let lane = card_lane(reader)?;
    let _turn = lane.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
    let card = backend
        .open_session(reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.pin_sequence(|mut card| -> Result<Vec<u8>, CkRv> {
        card.select_pkcs15_application()
            .map_err(|_select_err| CKR_DEVICE_ERROR)?;
        let serial = match live_token_serial(&mut card) {
            Ok(serial) => serial,
            Err(error) => {
                clear_positive(pin_cache);
                return Err(error);
            }
        };
        let pin1_status = match card.pin_status(PinSlot::Pin1) {
            Ok(status) => status,
            Err(_status_err) => {
                clear_positive(pin_cache);
                return Err(CKR_DEVICE_ERROR);
            }
        };
        if let Err(error) = pin1_verify_guard(pin1_status) {
            clear_positive(pin_cache);
            return Err(error);
        }
        let checkout = pin_cache
            .lock()
            .map_err(|_poisoned| CKR_DEVICE_ERROR)?
            .checkout_pin1(&serial, pin1_status)
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;
        let secret =
            refineid_auth::UnvalidatedSecret::from_owned_bytes(checkout.pin().as_bytes().to_vec());
        let Ok(pin1) = refineid_auth::Pin1::reconstruct(secret) else {
            return Err(CKR_DEVICE_ERROR);
        };
        let answer = card.verify_pin1(pin1);
        let accepted = checkout.settle_verify(
            &mut *pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?,
            &answer,
        );
        let accepted = match (answer, accepted) {
            (Ok(VerifyOutcome::Ok), Some(accepted)) => accepted,
            (Ok(VerifyOutcome::WrongPin { .. }), _) => return Err(CKR_PIN_INCORRECT),
            (Ok(VerifyOutcome::Locked), _) => return Err(CKR_PIN_LOCKED),
            _ => return Err(CKR_DEVICE_ERROR),
        };
        let signed = sign_with_card(&mut card, request);
        accepted.settle_operation(
            &mut *pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?,
            signed.as_ref().err(),
        );
        signed.map_err(|_card_err| CKR_DEVICE_ERROR)
    })
    .map_err(|_transaction_err| CKR_DEVICE_ERROR)?
}

/// The card lane of each local reader this process has signed or
/// logged in on, by reader name.
static CARD_LANES: Mutex<BTreeMap<String, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());

/// The card lane of `reader`: held by one PIN-bearing card operation at
/// a time, from before its PIN1 is checked out or verified until the
/// PIN1 is settled, so a concurrent operation on the same card waits
/// instead of finding the PIN1 out or interleaving its commands.
fn card_lane(reader: &ReaderId) -> Result<Arc<Mutex<()>>, CkRv> {
    let mut lanes = CARD_LANES.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
    Ok(Arc::clone(
        lanes.entry(reader.as_str().to_owned()).or_default(),
    ))
}

/// Ask the paired phone of `pair_id` for the signature of `input`
/// under `mechanism`.
///
/// The request is built once at this border: for `CKM_RSA_PKCS` the
/// caller's `DigestInfo` names the hash and carries the digest; for
/// `CKM_ECDSA` the caller's raw digest names the hash by its length
/// and travels at that length. The phone verifies PIN 1 on the
/// device, so no credential leaves this computer. One call per
/// `C_Sign`; an answer that misses [`REMOTE_SIGN_DEADLINE`], a
/// signature of the wrong length, or an unclassifiable outcome is
/// reported and never retried.
///
/// # Errors
/// [`CKR_DATA_INVALID`] / [`CKR_DATA_LEN_RANGE`] on bad input, the
/// [`RemoteSignError::ck_rv`] of the source's answer, or
/// [`CKR_DEVICE_ERROR`] when the signature is not the length the
/// key produces.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn remote_card_sign(
    source: &dyn RemoteTokenSource,
    pair_id: &RemoteSlotId,
    key: RemoteKey,
    context: &DisplayText,
    mechanism: Mechanism,
    input: &[u8],
) -> Result<Vec<u8>, CkRv> {
    let request = remote_signature_request(key, mechanism, input)?;
    let started = Instant::now();
    let signature = source
        .sign(pair_id, &request, context, REMOTE_SIGN_DEADLINE)
        .map_err(RemoteSignError::ck_rv)?;
    if started.elapsed() > REMOTE_SIGN_DEADLINE {
        crate::diag::diag!("remote_card_sign: the answer missed the deadline");
        return Err(RemoteSignError::Expired.ck_rv());
    }
    if signature.len() != key.signature_len() {
        crate::diag::diag!("remote_card_sign: signature length is not the key's");
        return Err(CKR_DEVICE_ERROR);
    }
    Ok(signature)
}

/// Build the typed request a phone signs, from the caller's PKCS#11
/// input shape.
///
/// # Errors
/// [`CKR_DATA_INVALID`] on a malformed or degenerate digest,
/// [`CKR_DATA_LEN_RANGE`] on an ECDSA digest of no SHA-2 length,
/// [`CKR_MECHANISM_INVALID`] when the mechanism does not fit the key.
fn remote_signature_request(
    key: RemoteKey,
    mechanism: Mechanism,
    input: &[u8],
) -> Result<SignatureRequest, CkRv> {
    let (algorithm, digest) = match mechanism {
        Mechanism::RsaPkcs => {
            let (hash, digest) = parse_digest_info(input)?;
            let algorithm = match hash {
                DigestInfoHash::Sha256 => RemoteSignatureAlgorithm::RsaPkcs1Sha256,
                DigestInfoHash::Sha384 => RemoteSignatureAlgorithm::RsaPkcs1Sha384,
                DigestInfoHash::Sha512 => RemoteSignatureAlgorithm::RsaPkcs1Sha512,
            };
            (algorithm, digest)
        }
        Mechanism::Ecdsa => {
            let algorithm = match input.len() {
                SHA256_LEN => RemoteSignatureAlgorithm::EcdsaSha256,
                SHA384_LEN => RemoteSignatureAlgorithm::EcdsaSha384,
                SHA512_LEN => RemoteSignatureAlgorithm::EcdsaSha512,
                _ => return Err(CKR_DATA_LEN_RANGE),
            };
            reject_degenerate_digest(input)?;
            (algorithm, input)
        }
    };
    SignatureRequest::new(key.profile(), algorithm, digest.to_vec()).map_err(|error| match error {
        RemoteOperationError::IncompatibleAlgorithm => CKR_MECHANISM_INVALID,
        RemoteOperationError::DigestLength { .. } => CKR_DATA_LEN_RANGE,
        RemoteOperationError::UnknownName
        | RemoteOperationError::EmptyDisplayText
        | RemoteOperationError::DisplayTextTooLong => CKR_DEVICE_ERROR,
    })
}

/// The key a remote token serves: one of the two authentication key
/// profiles a FINEID card carries, decided from the certificate's
/// public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteKey {
    /// RSA-3072 (FINEID S4-1 v3.1).
    Rsa3072,
    /// ECDSA over P-384 (FINEID S4-1 v4.0).
    EcdsaP384,
}

impl RemoteKey {
    /// The registered key profile the request asserts.
    #[must_use]
    pub(crate) const fn profile(self) -> RemoteKeyProfile {
        match self {
            Self::Rsa3072 => RemoteKeyProfile::Rsa3072,
            Self::EcdsaP384 => RemoteKeyProfile::EcdsaP384,
        }
    }

    /// The length of every signature the key produces: the PKCS#1
    /// block for RSA, the fixed-width `r || s` for ECDSA.
    #[must_use]
    pub(crate) const fn signature_len(self) -> usize {
        match self {
            Self::Rsa3072 => RSA3072_SIGNATURE_BYTES,
            Self::EcdsaP384 => ECDSA_P384_SIGNATURE_BYTES,
        }
    }
}

/// Token objects for a phone-served card, from the certificate the
/// source checked on its session; the serial names the pairing and
/// the persisted CA certificates complete the chain.
///
/// # Errors
/// [`CKR_DEVICE_ERROR`] if the certificate does not parse or carries
/// a key outside the two FINEID authentication profiles.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling state module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn remote_token_objects(
    pair_id: &RemoteSlotId,
    certificate: &SessionCertificate,
) -> Result<TokenObjects, CkRv> {
    let mut objects = TokenObjects::from_cert_der(certificate.as_der().to_vec())?;
    objects.remote_key()?;
    objects.set_token_serial(pair_id.token_serial());
    for ca in load_persisted_ca_certs() {
        objects.push_ca_cert(ca);
    }
    Ok(objects)
}

/// Verify a `C_Login` PIN on the live card and keep it only once the
/// card accepts it: held when the retry counter read before the VERIFY
/// was pristine ([`PinSafetyCache::store_pin1`]), otherwise staged for
/// the one operation that follows ([`PinSafetyCache::stage_pin1_once`]).
///
/// The VERIFY runs inside one PC/SC transaction that ends with a card
/// reset ([`PcscCard::pin_sequence`]): the login proves the PIN to this
/// module and leaves no verified state on the card for another PC/SC
/// client to use. Each signature presents PIN1 again.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_login(
    kind: &SlotKind,
    pin_cache: &Arc<Mutex<PinSafetyCache>>,
    pin1: PinBytes,
) -> Result<(), CkRv> {
    // Protected authentication path: the paired device verifies PIN1 in
    // its own protected storage, so there is no secret for this
    // computer to accept or check. Reaching this arm requires a
    // host-admitted pairing, not a reader name.
    if kind.is_remote() {
        return Ok(());
    }
    let backend = PcscBackend;
    let reader = kind.local_reader().ok_or(CKR_DEVICE_ERROR)?;
    // The reader to open is this one; a remote slot has no local
    // reader and never reaches here. The lane keeps this process's
    // other PIN-bearing operations on this reader waiting until the
    // VERIFY is settled; the PIN arrived with the call, so nothing
    // non-card happens while the card is open.
    let lane = card_lane(reader)?;
    let _turn = lane.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
    let card = backend
        .open_session(reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.pin_sequence(|mut card| -> Result<(), CkRv> {
        card.select_pkcs15_application()
            .map_err(|_select_err| CKR_DEVICE_ERROR)?;
        let serial = match live_token_serial(&mut card) {
            Ok(serial) => serial,
            Err(error) => {
                clear_positive(pin_cache);
                return Err(error);
            }
        };
        let pin1_status = match card.pin_status(PinSlot::Pin1) {
            Ok(status) => status,
            Err(_status_err) => {
                clear_positive(pin_cache);
                return Err(CKR_DEVICE_ERROR);
            }
        };
        if let Err(error) = pin1_verify_guard(pin1_status) {
            clear_positive(pin_cache);
            return Err(error);
        }
        // The cache mutex is bookkeeping and is never held across a card
        // exchange: rejection memory is consulted and released before
        // the VERIFY, and the answer is settled under a second lock. The
        // reader's lane, held above, serialises PIN-bearing operations.
        let rejected = pin_cache
            .lock()
            .map_err(|_poisoned| CKR_DEVICE_ERROR)?
            .is_rejected(&serial, &pin1);
        if rejected {
            return Err(CKR_PIN_INCORRECT);
        }
        let secret = refineid_auth::UnvalidatedSecret::from_owned_bytes(pin1.as_bytes().to_vec());
        let Ok(pin1_val) = refineid_auth::Pin1::reconstruct(secret) else {
            return Err(CKR_PIN_INCORRECT);
        };
        let outcome = card
            .verify_pin1(pin1_val)
            .map_err(|_verify_err| CKR_DEVICE_ERROR)?;
        let mut cache = pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
        settle_login(&mut cache, serial, pin1, pin1_status, outcome)
    })
    .map_err(|_transaction_err| CKR_DEVICE_ERROR)?
}

/// Settle a `C_Login` VERIFY by the card's answer: hold an accepted
/// value when `pin1_status`, read before the VERIFY, was pristine,
/// stage it for one operation otherwise; remember a refused value as
/// rejected; keep nothing for a blocked PIN or any other status word.
fn settle_login(
    cache: &mut PinSafetyCache,
    serial: TokenSerial,
    pin1: PinBytes,
    pin1_status: PinStatus,
    outcome: VerifyOutcome,
) -> Result<(), CkRv> {
    match outcome {
        VerifyOutcome::Ok => {
            let stored = if pin1_status_permits_reusable_cache(pin1_status) {
                cache.store_pin1(serial, pin1)
            } else {
                cache.stage_pin1_once(serial, pin1)
            };
            stored.map_err(|_rejected| CKR_PIN_INCORRECT)
        }
        VerifyOutcome::WrongPin { .. } => {
            cache.record_rejected(&serial, &pin1);
            Err(CKR_PIN_INCORRECT)
        }
        VerifyOutcome::Locked => Err(CKR_PIN_LOCKED),
        VerifyOutcome::Other(_sw) => Err(CKR_DEVICE_ERROR),
    }
}

/// Refuse every PIN-bearing APDU once fewer than three attempts remain.
/// Firefox does not surface retry warnings, so the module may consume
/// attempts down to two remaining and no further: a near-last attempt is
/// never `RefineID`'s to spend, and only another middleware locks the card.
/// Mirrors the `CryptoTokenKit` adapter's retry floor of three.
const fn pin1_verify_guard(status: PinStatus) -> Result<(), CkRv> {
    match status {
        PinStatus::Remaining(retries) => match PinRetryRisk::from_retries(retries) {
            Some(risk) if risk.permits_compatibility_module() => Ok(()),
            Some(_) => Err(CKR_PIN_LOCKED),
            None => Err(CKR_DEVICE_ERROR),
        },
        PinStatus::Locked => Err(CKR_PIN_LOCKED),
        PinStatus::Verified => Ok(()),
        PinStatus::NoInfo | PinStatus::Other(_) => Err(CKR_DEVICE_ERROR),
    }
}

fn live_token_serial<T: CardTransport>(card: &mut T) -> Result<TokenSerial, CkRv> {
    card.read_token_info()
        .map_err(|_read_err| CKR_DEVICE_ERROR)?
        .serial_number_hex()
        .cloned()
        .map(render_token_serial)
        .filter(|serial| !serial.as_str().is_empty())
        .ok_or(CKR_DEVICE_ERROR)
}

fn clear_positive(pin_cache: &Arc<Mutex<PinSafetyCache>>) {
    if let Ok(mut cache) = pin_cache.lock() {
        cache.clear_positive();
    }
}

/// Change PIN1 on the card at `reader_name`.
///
/// Only compiled into the `pin-change` build; the default
/// (login-only) beta stubs `C_SetPIN`, so this has no caller there.
///
/// Mirrors [`card_sign`]'s proven chain: open the card, select the
/// PKCS#15 application (reference-data commands are refused from MF
/// context the same way VERIFY is), then run `CHANGE REFERENCE
/// DATA` with the current + new PIN pair in one command -- no prior
/// VERIFY is needed. The card is dropped before returning. On `Ok`
/// the card has reset the retry counter and cleared its PIN
/// presentation, so the caller must refresh any cached PIN1.
///
/// Typed inputs cross the boundary owned: [`ReaderId`] names the
/// reader and both PINs are consumed (their buffers zeroize on
/// drop), matching [`refineid_lib_core::auth::PinOps::change_pin`].
///
/// # Errors
/// [`CKR_PIN_INCORRECT`] when the current PIN is wrong,
/// [`CKR_PIN_LOCKED`] when the slot is blocked,
/// [`CKR_PIN_LEN_RANGE`] on a length rejection (local policy or
/// card-side), [`CKR_DEVICE_ERROR`] on any card / transport failure.
#[cfg(feature = "pin-change")]
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is called from sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_change_pin1(
    reader: &ReaderId,
    current_pin1: PinBytes,
    new_pin1: PinBytes,
) -> Result<(), CkRv> {
    let backend = PcscBackend;
    // SELECT -> probe -> CHANGE REFERENCE DATA is one held
    // transaction, ended with a card reset; both PINs arrived with
    // the call.
    let card = backend
        .open_session(reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.pin_sequence(|mut card| -> Result<(), CkRv> {
        card.select_pkcs15_application()
            .map_err(|_select_err| CKR_DEVICE_ERROR)?;
        // The empty-body VERIFY probe consumes no retry. Apply the same
        // consumer floor as login and signing before CHANGE REFERENCE DATA.
        let status = card
            .pin_status(PinSlot::Pin1)
            .map_err(|_probe_err| CKR_DEVICE_ERROR)?;
        pin1_verify_guard(status)?;
        let curr_secret =
            refineid_auth::UnvalidatedSecret::from_owned_bytes(current_pin1.as_bytes().to_vec());
        let Ok(curr_pin) = refineid_auth::Pin1::reconstruct(curr_secret) else {
            return Err(CKR_PIN_INCORRECT);
        };
        let new_secret =
            refineid_auth::UnvalidatedSecret::from_owned_bytes(new_pin1.as_bytes().to_vec());
        let Ok(new_pin) = refineid_auth::Pin1::reconstruct(new_secret) else {
            return Err(CKR_PIN_LEN_RANGE);
        };
        let outcome = card
            .change_pin1(curr_pin, new_pin)
            .map_err(|_change_err| CKR_DEVICE_ERROR)?;
        match outcome {
            refineid_auth::ManageOutcome::Ok => Ok(()),
            refineid_auth::ManageOutcome::WrongCredential { .. } => Err(CKR_PIN_INCORRECT),
            refineid_auth::ManageOutcome::Locked => Err(CKR_PIN_LOCKED),
            refineid_auth::ManageOutcome::Other(_sw) => Err(CKR_DEVICE_ERROR),
        }
    })
    .map_err(|_transaction_err| CKR_DEVICE_ERROR)?
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "unit tests assert on fixed offsets of compile-time-known byte fixtures; production code stays panic-free."
)]
mod tests {
    use refineid_apdu::{PinRetries, StatusWord};
    use refineid_auth::PinStatus;

    use super::{
        DER_LONG_FORM_ONE_OCTET, DER_TAG_INTEGER, DER_TAG_OCTET_STRING, OBJ_CERTIFICATE,
        OBJ_PRIVATE_KEY, OBJ_PUBLIC_KEY, ObjectKind, OwnedCert, der_integer, der_octet_string,
        pin1_verify_guard,
    };
    use crate::ck::{CKR_DEVICE_ERROR, CKR_PIN_LOCKED};

    #[test]
    fn pin1_verify_guard_blocks_only_one_and_two_attempts() {
        let retries = |count| {
            PinRetries::from_nibble(count).expect("test retry count fits the status-word nibble")
        };

        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(5))), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(4))), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(3))), Ok(()));
        assert_eq!(
            pin1_verify_guard(PinStatus::Remaining(retries(2))),
            Err(CKR_PIN_LOCKED)
        );
        assert_eq!(
            pin1_verify_guard(PinStatus::Remaining(retries(1))),
            Err(CKR_PIN_LOCKED)
        );
        // Zero attempts passes the floor; the card itself then reports locked.
        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(0))), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Locked), Err(CKR_PIN_LOCKED));
        assert_eq!(pin1_verify_guard(PinStatus::NoInfo), Err(CKR_DEVICE_ERROR));
        assert_eq!(
            pin1_verify_guard(PinStatus::Other(StatusWord::from_bytes(0x6F, 0x00))),
            Err(CKR_DEVICE_ERROR)
        );
    }

    #[test]
    fn object_kind_handle_round_trip() {
        assert_eq!(
            ObjectKind::from_handle(OBJ_CERTIFICATE),
            Some(ObjectKind::Certificate)
        );
        assert_eq!(
            ObjectKind::from_handle(OBJ_PRIVATE_KEY),
            Some(ObjectKind::PrivateKey)
        );
        assert_eq!(
            ObjectKind::from_handle(OBJ_PUBLIC_KEY),
            Some(ObjectKind::PublicKey)
        );
        assert_eq!(ObjectKind::from_handle(0), None);
        assert_eq!(ObjectKind::Certificate.handle(), OBJ_CERTIFICATE);
        assert_eq!(ObjectKind::PrivateKey.handle(), OBJ_PRIVATE_KEY);
        assert_eq!(ObjectKind::PublicKey.handle(), OBJ_PUBLIC_KEY);
    }

    #[test]
    fn empty_der_span_is_an_absent_attribute() {
        const EMPTY_SPAN: &[u8] = &[];
        const NON_EMPTY_SPAN: &[u8] = b"non-empty";
        assert_eq!(super::non_empty(EMPTY_SPAN), None);
        assert_eq!(super::non_empty(NON_EMPTY_SPAN), Some(NON_EMPTY_SPAN));
    }

    #[test]
    fn der_integer_short_form() {
        const TEST_SERIAL_BYTES: [u8; 3] = [1, 2, 3];
        let tlv = der_integer(&TEST_SERIAL_BYTES);
        let mut expected = Vec::with_capacity(TEST_SERIAL_BYTES.len().saturating_add(2));
        expected.push(DER_TAG_INTEGER);
        expected.push(u8::try_from(TEST_SERIAL_BYTES.len()).expect("test serial len fits in u8"));
        expected.extend_from_slice(&TEST_SERIAL_BYTES);
        assert_eq!(tlv, expected);
    }

    #[test]
    fn der_octet_string_short_form() {
        const TEST_OCTETS: &[u8] = b"sample-point-bytes";
        let tlv = der_octet_string(TEST_OCTETS);
        let mut expected = Vec::with_capacity(TEST_OCTETS.len().saturating_add(2));
        expected.push(DER_TAG_OCTET_STRING);
        expected.push(u8::try_from(TEST_OCTETS.len()).expect("test octet len fits in u8"));
        expected.extend_from_slice(TEST_OCTETS);
        assert_eq!(tlv, expected);
    }

    #[test]
    fn der_length_long_form_one_octet() {
        const TEST_PAYLOAD_LEN: usize = 200;
        const ZERO_BYTE: u8 = 0;
        const TAG_OVERHEAD_BYTES: usize = 1;
        const LENGTH_FLAG_BYTES: usize = 1;
        const LENGTH_VALUE_BYTES: usize = 1;
        const TOTAL_HEADER_BYTES: usize =
            TAG_OVERHEAD_BYTES + LENGTH_FLAG_BYTES + LENGTH_VALUE_BYTES;

        let body = vec![ZERO_BYTE; TEST_PAYLOAD_LEN];
        let tlv = der_octet_string(&body);
        assert_eq!(tlv[0], DER_TAG_OCTET_STRING);
        assert_eq!(tlv[1], DER_LONG_FORM_ONE_OCTET);
        assert_eq!(
            tlv[2],
            u8::try_from(TEST_PAYLOAD_LEN).expect("200 fits in u8")
        );
        assert_eq!(tlv.len(), TEST_PAYLOAD_LEN + TOTAL_HEADER_BYTES);
    }

    #[test]
    fn refined_trust_store_invariants() {
        const INITIAL_COUNT: usize = 2;
        const OUT_OF_BOUNDS_INDEX: usize = 99;

        const TEST_CA_1_DER: &[u8] =
            include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");
        const TEST_CA_2_DER: &[u8] =
            include_bytes!("../ca-certs/fineid-intermediate-02-citizen-g4r.der");

        let cert1 = OwnedCert::from_der(TEST_CA_1_DER).expect("valid cert1");
        let cert2 = OwnedCert::from_der(TEST_CA_2_DER).expect("valid cert2");

        let mut store = super::RefinedTrustStore::default();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store.push_anchor(super::CaObject::new(cert1.clone()));
        store.push_anchor(super::CaObject::new(cert2.clone()));
        assert_eq!(store.len(), INITIAL_COUNT);
        assert!(!store.is_empty());

        // Invariant 1: Zero duplicate certificates on push or prepend
        store.push_anchor(super::CaObject::new(cert1.clone()));
        assert_eq!(store.len(), INITIAL_COUNT);
        store.prepend_anchor(super::CaObject::new(cert2.clone()));
        assert_eq!(store.len(), INITIAL_COUNT);

        // Invariant 2: Total lookup without panicking
        assert!(store.get(0).is_some());
        assert!(store.get(1).is_some());
        assert!(store.get(OUT_OF_BOUNDS_INDEX).is_none());

        // Invariant 3: Iteration
        let count = store.iter().count();
        assert_eq!(count, INITIAL_COUNT);
    }

    #[test]
    fn persistent_ca_roundtrip_and_pruning() {
        const TEST_CA_1_DER: &[u8] =
            include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");

        let unique_name = format!("refineid-test-ca-cache-pkcs11-{}", std::process::id());
        let temp_dir = std::env::temp_dir().join(unique_name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);

        let cert1 = OwnedCert::from_der(TEST_CA_1_DER).expect("valid cert1");
        super::persist_ca_cert_to(&temp_dir, &cert1);

        // Plant an unparseable / corrupted file to verify purging
        let corrupt_path = temp_dir.join("corrupt.der");
        let _ = std::fs::write(&corrupt_path, b"not-a-valid-der-certificate");

        // Plant an oversized file (> 64 KB) to verify purging
        let oversized_path = temp_dir.join("oversized.der");
        let oversized_len = usize::try_from(super::MAX_CA_CERT_BYTES).unwrap_or(usize::MAX) + 1;
        let _ = std::fs::write(&oversized_path, vec![0u8; oversized_len]);

        let loaded = super::load_persisted_ca_certs_from(&temp_dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].as_der(), cert1.as_der());

        // Corrupt and oversized files should have been purged
        assert!(!corrupt_path.exists());
        assert!(!oversized_path.exists());

        // Test object_exists and ca_object_for_kind
        let mut objects = super::TokenObjects::from_cert_der(TEST_CA_1_DER.to_vec())
            .expect("token objects from cert der");
        assert!(!objects.object_exists(ObjectKind::Ca(0)));

        objects.push_ca_cert(cert1);
        assert!(objects.object_exists(ObjectKind::Ca(0)));
        assert!(!objects.object_exists(ObjectKind::Ca(1)));
        assert_eq!(objects.all_object_kinds().len(), 4);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn leaf_cert_rejected_by_ca_policy() {
        // BasicConstraints extension OID (2.5.29.19) DER OBJECT IDENTIFIER TLV
        const BASIC_CONSTRAINTS_OID_DER: &[u8] = b"\x06\x03\x55\x1d\x13";
        // Non-CA extension OID (2.5.29.20: CRL Number) DER OBJECT IDENTIFIER TLV
        const NON_CA_EXTENSION_OID_DER: &[u8] = b"\x06\x03\x55\x1d\x14";

        const CA_DER: &[u8] = include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");
        let mut leaf_der = CA_DER.to_vec();
        let pos = leaf_der
            .windows(BASIC_CONSTRAINTS_OID_DER.len())
            .position(|w| w == BASIC_CONSTRAINTS_OID_DER)
            .expect("BasicConstraints found");
        let rpos = leaf_der
            .windows(BASIC_CONSTRAINTS_OID_DER.len())
            .rposition(|w| w == BASIC_CONSTRAINTS_OID_DER)
            .expect("BasicConstraints found");
        assert_eq!(
            pos, rpos,
            "BasicConstraints OID must appear uniquely in fixture"
        );
        leaf_der[pos..pos + BASIC_CONSTRAINTS_OID_DER.len()]
            .copy_from_slice(NON_CA_EXTENSION_OID_DER);

        let leaf = OwnedCert::from_der(&leaf_der).expect("valid leaf cert DER");
        assert!(!super::is_ca_cert(&leaf));
        assert!(!super::meets_ca_persistence_policy(&leaf));

        let unique_name = format!("refineid-test-leaf-rejection-{}", std::process::id());
        let temp_dir = std::env::temp_dir().join(unique_name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);

        // Directly plant the leaf certificate DER in cache dir
        let leaf_path = temp_dir.join("leaf.der");
        std::fs::write(&leaf_path, &leaf_der).expect("write leaf");

        let loaded = super::load_persisted_ca_certs_from(&temp_dir);
        assert!(loaded.is_empty());
        assert!(
            !leaf_path.exists(),
            "leaf certificate must be purged from cache"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn expired_ca_cert_purged_from_cache() {
        use spki::der::Encode as _;
        use spki::der::asn1::UtcTime;

        const CA_DER: &[u8] = include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");
        let parsed_fixture = OwnedCert::from_der(CA_DER).expect("valid fixture DER");

        // Dynamically encode the fixture's actual parsed notAfter as ASN.1 UTCTime TLV
        let original_not_after_tlv = UtcTime::from_date_time(parsed_fixture.view().not_after)
            .expect("valid fixture notAfter in UTCTime window")
            .to_der()
            .expect("UTCTime encodes");

        // Construct an expired timestamp in the past (year 2020)
        const EXPIRED_YEAR: u16 = 2020;
        const EXPIRED_MONTH: u8 = 1;
        const EXPIRED_DAY: u8 = 1;
        let expired_dt =
            spki::der::DateTime::new(EXPIRED_YEAR, EXPIRED_MONTH, EXPIRED_DAY, 0, 0, 0)
                .expect("valid expired DateTime");
        let expired_not_after_tlv = UtcTime::from_date_time(expired_dt)
            .expect("valid expired notAfter in UTCTime window")
            .to_der()
            .expect("UTCTime encodes");
        assert_eq!(original_not_after_tlv.len(), expired_not_after_tlv.len());

        let mut expired_der = CA_DER.to_vec();
        let tlv_len = original_not_after_tlv.len();
        let pos = expired_der
            .windows(tlv_len)
            .position(|w| w == original_not_after_tlv)
            .expect("notAfter TLV found in CA");
        let rpos = expired_der
            .windows(tlv_len)
            .rposition(|w| w == original_not_after_tlv)
            .expect("notAfter TLV found in CA");
        assert_eq!(pos, rpos, "notAfter TLV must appear uniquely in fixture");
        expired_der[pos..pos + tlv_len].copy_from_slice(&expired_not_after_tlv);

        let expired_cert = OwnedCert::from_der(&expired_der).expect("valid DER structure");
        assert!(super::is_ca_cert(&expired_cert));
        assert!(!super::is_cert_valid(&expired_cert));
        assert!(!super::meets_ca_persistence_policy(&expired_cert));

        let unique_name = format!("refineid-test-expired-purge-{}", std::process::id());
        let temp_dir = std::env::temp_dir().join(unique_name);
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir_all(&temp_dir);

        let expired_path = temp_dir.join("expired.der");
        std::fs::write(&expired_path, &expired_der).expect("write expired CA");

        let loaded = super::load_persisted_ca_certs_from(&temp_dir);
        assert!(loaded.is_empty());
        assert!(
            !expired_path.exists(),
            "expired CA certificate must be purged from cache"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn all_published_ca_fixtures_assert_ca_basic_constraints() {
        let fixtures: [&[u8]; 6] = [
            include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der"),
            include_bytes!("../ca-certs/fineid-intermediate-02-citizen-g4r.der"),
            include_bytes!("../ca-certs/fineid-intermediate-00-citizen-g3.der"),
            include_bytes!("../ca-certs/fineid-intermediate-03-organisation-g4r.der"),
            include_bytes!("../ca-certs/dvv-gov-root-ca-g3-ecc.der"),
            include_bytes!("../ca-certs/dvv-gov-root-ca-g3-rsa.der"),
        ];

        for der in fixtures {
            let cert = OwnedCert::from_der(der).expect("valid cert");
            assert!(super::is_ca_cert(&cert));
        }
    }

    #[test]
    fn ca_handle_round_trip_and_bounds() {
        assert_eq!(
            ObjectKind::from_handle(super::OBJ_CA_BASE),
            Some(ObjectKind::Ca(0))
        );
        assert_eq!(
            ObjectKind::from_handle(super::OBJ_CA_BASE + 1),
            Some(ObjectKind::Ca(1))
        );
        assert_eq!(ObjectKind::from_handle(crate::ck::CK_INVALID_HANDLE), None);
        assert_eq!(ObjectKind::Ca(0).handle(), super::OBJ_CA_BASE);
        assert_eq!(ObjectKind::Ca(1).handle(), super::OBJ_CA_BASE + 1);

        const TEST_CA_1_DER: &[u8] =
            include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");
        let objects = super::TokenObjects::from_cert_der(TEST_CA_1_DER.to_vec())
            .expect("token objects from cert der");
        assert!(!objects.object_exists(ObjectKind::Ca(0)));
        const HIGH_OUT_OF_BOUNDS_INDEX: usize = 9999;
        assert!(!objects.object_exists(ObjectKind::Ca(HIGH_OUT_OF_BOUNDS_INDEX)));
    }

    #[test]
    fn not_after_boundary_inclusivity() {
        const TEST_CA_1_DER: &[u8] =
            include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");
        let cert = OwnedCert::from_der(TEST_CA_1_DER).expect("valid cert");
        let view = cert.view();
        let not_before = view.not_before.unix_duration();
        let not_after = view.not_after.unix_duration();

        // Boundary assertions per RFC 5280 §4.1.2.5:
        // "The validity period for a certificate is the period of time
        // from notBefore through notAfter, inclusive."
        assert!(super::is_cert_valid_at(&cert, not_before));
        assert!(super::is_cert_valid_at(&cert, not_after));

        let before_not_before = not_before
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("before notBefore");
        assert!(!super::is_cert_valid_at(&cert, before_not_before));

        let past_not_after = not_after + std::time::Duration::from_secs(1);
        assert!(!super::is_cert_valid_at(&cert, past_not_after));
    }

    /// A reader that names itself after a pairing: local, and so never
    /// routed to the remote sign path.
    fn impersonating_local_kind() -> super::SlotKind {
        super::SlotKind::Local {
            reader: refineid_pcsc::ReaderId::new("rapp:0123456789abcdef".to_owned()),
        }
    }

    /// A local reader that cannot be opened fails on the card, never
    /// on a phone.
    #[test]
    fn a_local_reader_naming_itself_a_pairing_never_takes_the_remote_path() {
        let pin_cache = std::sync::Arc::new(std::sync::Mutex::new(
            super::PinSafetyCache::new().expect("pin safety cache"),
        ));
        let digest = refineid_digest::Sha256::of(b"a signature the card is asked for");
        let res = super::card_sign(
            &impersonating_local_kind(),
            &pin_cache,
            crate::sign::Mechanism::Ecdsa,
            digest.as_bytes(),
        );
        assert_eq!(res, Err(crate::ck::CKR_DEVICE_ERROR));
    }

    /// PIN1 state for a local reader is whatever the card says; only a
    /// host-admitted pairing reports a state this computer did not read.
    #[test]
    fn a_local_reader_naming_itself_a_pairing_has_no_remote_pin_state() {
        let res = super::card_pin1_status(&impersonating_local_kind());
        assert_ne!(res, Ok(super::PinStatus::Verified));
    }

    /// `C_Login` succeeds without a card only for a host-admitted
    /// pairing, whose PIN1 the device verified itself.
    #[test]
    fn a_local_reader_naming_itself_a_pairing_does_not_skip_login() {
        let pin_cache = std::sync::Arc::new(std::sync::Mutex::new(
            super::PinSafetyCache::new().expect("pin safety cache"),
        ));
        let pin = crate::pin::PinBytes::try_from(*b"1234").expect("valid PIN1");
        let res = super::card_login(&impersonating_local_kind(), &pin_cache, pin);
        assert_eq!(res, Err(crate::ck::CKR_DEVICE_ERROR));
    }

    /// A source that answers every request with a fixed outcome and
    /// records the request it was handed.
    struct AnsweringSource {
        answer: Result<Vec<u8>, crate::remote::RemoteSignError>,
        seen: std::sync::Mutex<Option<(refineid_remote::SignatureRequest, String)>>,
    }

    impl AnsweringSource {
        fn answering(answer: Result<Vec<u8>, crate::remote::RemoteSignError>) -> Self {
            Self {
                answer,
                seen: std::sync::Mutex::new(None),
            }
        }

        fn seen(&self) -> Option<(refineid_remote::SignatureRequest, String)> {
            self.seen.lock().expect("seen lock").clone()
        }
    }

    impl crate::remote::RemoteTokenSource for AnsweringSource {
        fn offered(&self) -> Option<crate::remote::RemoteOffer> {
            None
        }

        fn sign(
            &self,
            _pair_id: &super::RemoteSlotId,
            request: &refineid_remote::SignatureRequest,
            context: &refineid_remote::DisplayText,
            deadline: core::time::Duration,
        ) -> Result<Vec<u8>, crate::remote::RemoteSignError> {
            assert_eq!(deadline, crate::remote::REMOTE_SIGN_DEADLINE);
            *self.seen.lock().expect("seen lock") =
                Some((request.clone(), context.as_str().to_owned()));
            self.answer.clone()
        }

        fn stop(&self) {}
    }

    fn pair_id() -> super::RemoteSlotId {
        super::RemoteSlotId::parse(&"a5".repeat(crate::slot_kind::PAIR_ID_SIZE))
            .expect("valid pair id")
    }

    fn context() -> refineid_remote::DisplayText {
        refineid_remote::DisplayText::new("alpha-desk".to_owned()).expect("bounded text")
    }

    /// A SHA-384 digest that is not a degenerate sentinel.
    fn sha384_digest() -> Vec<u8> {
        (1_u8..=48_u8).collect()
    }

    #[test]
    fn an_ecdsa_digest_names_its_hash_by_length_and_travels_whole() {
        let signature = vec![7_u8; super::ECDSA_P384_SIGNATURE_BYTES];
        let source = AnsweringSource::answering(Ok(signature.clone()));
        let res = super::remote_card_sign(
            &source,
            &pair_id(),
            super::RemoteKey::EcdsaP384,
            &context(),
            crate::sign::Mechanism::Ecdsa,
            &sha384_digest(),
        );
        assert_eq!(res, Ok(signature));
        let (request, shown) = source.seen().expect("the source was asked");
        assert_eq!(
            request.algorithm(),
            refineid_remote::RemoteSignatureAlgorithm::EcdsaSha384
        );
        assert_eq!(
            request.key_profile(),
            refineid_remote::RemoteKeyProfile::EcdsaP384
        );
        assert_eq!(request.digest(), sha384_digest().as_slice());
        assert_eq!(shown, "alpha-desk");
    }

    #[test]
    fn each_sha2_length_selects_its_ecdsa_algorithm() {
        for (len, algorithm) in [
            (32, refineid_remote::RemoteSignatureAlgorithm::EcdsaSha256),
            (48, refineid_remote::RemoteSignatureAlgorithm::EcdsaSha384),
            (64, refineid_remote::RemoteSignatureAlgorithm::EcdsaSha512),
        ] {
            let digest: Vec<u8> = (1..=len).map(|byte| byte as u8).collect();
            let request = super::remote_signature_request(
                super::RemoteKey::EcdsaP384,
                crate::sign::Mechanism::Ecdsa,
                &digest,
            )
            .expect("a SHA-2 length");
            assert_eq!(request.algorithm(), algorithm);
        }
        let odd: Vec<u8> = (1_u8..=20_u8).collect();
        assert_eq!(
            super::remote_signature_request(
                super::RemoteKey::EcdsaP384,
                crate::sign::Mechanism::Ecdsa,
                &odd,
            ),
            Err(crate::ck::CKR_DATA_LEN_RANGE)
        );
        assert_eq!(
            super::remote_signature_request(
                super::RemoteKey::EcdsaP384,
                crate::sign::Mechanism::Ecdsa,
                &[0_u8; 48],
            ),
            Err(crate::ck::CKR_DATA_INVALID)
        );
    }

    #[test]
    fn each_digest_info_hash_selects_its_rsa_algorithm() {
        for (info, algorithm) in [
            (
                crate::sign::tests::digest_info_sha256_with_null(),
                refineid_remote::RemoteSignatureAlgorithm::RsaPkcs1Sha256,
            ),
            (
                crate::sign::tests::digest_info_sha384_with_null(),
                refineid_remote::RemoteSignatureAlgorithm::RsaPkcs1Sha384,
            ),
            (
                crate::sign::tests::digest_info_sha512_with_null(),
                refineid_remote::RemoteSignatureAlgorithm::RsaPkcs1Sha512,
            ),
        ] {
            let request = super::remote_signature_request(
                super::RemoteKey::Rsa3072,
                crate::sign::Mechanism::RsaPkcs,
                &info,
            )
            .expect("a SHA-2 DigestInfo");
            assert_eq!(request.algorithm(), algorithm);
            assert_eq!(
                request.key_profile(),
                refineid_remote::RemoteKeyProfile::Rsa3072
            );
            assert_eq!(request.digest().len(), algorithm.digest_len());
        }
    }

    /// A `DigestInfo` handed to an ECDSA key, or a raw digest to an
    /// RSA key, is a mechanism that does not fit the key.
    #[test]
    fn a_mechanism_that_does_not_fit_the_key_is_refused() {
        assert_eq!(
            super::remote_signature_request(
                super::RemoteKey::EcdsaP384,
                crate::sign::Mechanism::RsaPkcs,
                &crate::sign::tests::digest_info_sha256_with_null(),
            ),
            Err(crate::ck::CKR_MECHANISM_INVALID)
        );
        assert_eq!(
            super::remote_signature_request(
                super::RemoteKey::Rsa3072,
                crate::sign::Mechanism::Ecdsa,
                &sha384_digest(),
            ),
            Err(crate::ck::CKR_MECHANISM_INVALID)
        );
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused() {
        let source = AnsweringSource::answering(Ok(vec![7_u8; 10]));
        let res = super::remote_card_sign(
            &source,
            &pair_id(),
            super::RemoteKey::EcdsaP384,
            &context(),
            crate::sign::Mechanism::Ecdsa,
            &sha384_digest(),
        );
        assert_eq!(res, Err(crate::ck::CKR_DEVICE_ERROR));
    }

    #[test]
    fn the_sources_errors_reach_the_caller_as_the_table_says() {
        for error in crate::remote::RemoteSignError::ALL {
            let source = AnsweringSource::answering(Err(error));
            let res = super::remote_card_sign(
                &source,
                &pair_id(),
                super::RemoteKey::EcdsaP384,
                &context(),
                crate::sign::Mechanism::Ecdsa,
                &sha384_digest(),
            );
            assert_eq!(res, Err(error.ck_rv()), "{error}");
        }
    }

    /// A bad digest never reaches the source.
    #[test]
    fn a_bad_digest_is_refused_before_the_phone_is_asked() {
        let source = AnsweringSource::answering(Ok(vec![7_u8; super::ECDSA_P384_SIGNATURE_BYTES]));
        let res = super::remote_card_sign(
            &source,
            &pair_id(),
            super::RemoteKey::EcdsaP384,
            &context(),
            crate::sign::Mechanism::Ecdsa,
            &[],
        );
        assert_eq!(res, Err(crate::ck::CKR_DATA_LEN_RANGE));
        assert!(source.seen().is_none());
    }

    /// The key a phone-served token signs with follows the
    /// certificate's public key: P-384 is served; RSA-4096 and P-256
    /// are not FINEID authentication keys and are refused at token
    /// discovery.
    #[test]
    fn the_remote_key_follows_the_certificate() {
        const EC_DER: &[u8] = include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");
        const RSA_4096_DER: &[u8] =
            include_bytes!("../ca-certs/fineid-intermediate-02-citizen-g4r.der");
        const P256_DER: &[u8] = include_bytes!("../test-certs/p256-alpha.der");
        let ec = super::TokenObjects::from_cert_der(EC_DER.to_vec()).expect("parses");
        assert_eq!(ec.remote_key(), Ok(super::RemoteKey::EcdsaP384));
        let rsa = super::TokenObjects::from_cert_der(RSA_4096_DER.to_vec()).expect("parses");
        assert_eq!(rsa.remote_key(), Err(crate::ck::CKR_DEVICE_ERROR));
        assert_eq!(
            super::TokenObjects::from_cert_der(P256_DER.to_vec()).map(|_| ()),
            Err(crate::ck::CKR_DEVICE_ERROR)
        );
        for refused in [RSA_4096_DER, P256_DER] {
            let certificate = crate::remote::SessionCertificate::new(refused.to_vec());
            assert_eq!(
                super::remote_token_objects(&pair_id(), &certificate).map(|_| ()),
                Err(crate::ck::CKR_DEVICE_ERROR)
            );
        }
        let certificate = crate::remote::SessionCertificate::new(EC_DER.to_vec());
        let objects = super::remote_token_objects(&pair_id(), &certificate).expect("served");
        assert_eq!(objects.token_serial(), "REMOTE-a5a5a5a5");
    }

    /// Retry count of a pristine FINEID PIN.
    const RETRIES_PRISTINE: u8 = 5;
    /// Retry count after one refused presentation.
    const RETRIES_ONE_SPENT: u8 = 4;
    const DECIMAL_DIGIT_RADIX: u8 = 10;
    /// A synthetic card serial for the login settlement tests.
    const LOGIN_CARD_SERIAL: &str = "CARD-LOGIN-FULL-SERIAL";

    fn login_cache() -> super::PinSafetyCache {
        super::PinSafetyCache::new().expect("operating system random source is available")
    }

    fn login_serial() -> super::TokenSerial {
        super::TokenSerial::new(LOGIN_CARD_SERIAL.to_owned())
    }

    fn random_pin() -> crate::pin::PinBytes {
        let mut digits = vec![0_u8; crate::pin::PinBytes::MAX_LENGTH];
        getrandom::fill(&mut digits).expect("operating system random source is available");
        for digit in &mut digits {
            *digit = b'0' + (*digit % DECIMAL_DIGIT_RADIX);
        }
        crate::pin::PinBytes::new(digits).expect("random digits satisfy the PIN policy")
    }

    fn retries(count: u8) -> PinRetries {
        PinRetries::from_nibble(count).expect("test retry count fits the status-word nibble")
    }

    fn remaining(count: u8) -> PinStatus {
        PinStatus::Remaining(retries(count))
    }

    /// Take the settled value out for one accepted VERIFY and one
    /// completed operation, as a signature does.
    fn use_once(cache: &mut super::PinSafetyCache) {
        let checkout = cache
            .checkout_pin1(&login_serial(), remaining(RETRIES_PRISTINE))
            .expect("the settled value is checked out");
        let accepted: Result<super::VerifyOutcome, refineid_auth::AuthError<String>> =
            Ok(super::VerifyOutcome::Ok);
        let accepted = checkout
            .settle_verify(cache, &accepted)
            .expect("an accepted VERIFY leads to the operation");
        accepted.settle_operation::<String>(cache, None);
    }

    #[test]
    fn settle_login_holds_an_accepted_pin1_under_a_pristine_counter() {
        let mut cache = login_cache();
        let res = super::settle_login(
            &mut cache,
            login_serial(),
            random_pin(),
            remaining(RETRIES_PRISTINE),
            super::VerifyOutcome::Ok,
        );
        assert_eq!(res, Ok(()));
        assert!(cache.holds_pin1());
        use_once(&mut cache);
        assert!(cache.holds_pin1());
        assert!(
            cache
                .checkout_pin1(&login_serial(), remaining(RETRIES_PRISTINE))
                .is_some()
        );
    }

    #[test]
    fn settle_login_stages_an_accepted_pin1_under_a_spent_counter() {
        let mut cache = login_cache();
        let res = super::settle_login(
            &mut cache,
            login_serial(),
            random_pin(),
            remaining(RETRIES_ONE_SPENT),
            super::VerifyOutcome::Ok,
        );
        assert_eq!(res, Ok(()));
        assert!(cache.holds_pin1());
        use_once(&mut cache);
        assert!(!cache.holds_pin1());
        assert!(
            cache
                .checkout_pin1(&login_serial(), remaining(RETRIES_PRISTINE))
                .is_none()
        );
    }

    #[test]
    fn settle_login_remembers_a_refused_pin1() {
        let mut cache = login_cache();
        let pin = random_pin();
        let res = super::settle_login(
            &mut cache,
            login_serial(),
            pin.clone(),
            remaining(RETRIES_PRISTINE),
            super::VerifyOutcome::WrongPin {
                retries_left: retries(RETRIES_ONE_SPENT),
            },
        );
        assert_eq!(res, Err(crate::ck::CKR_PIN_INCORRECT));
        assert!(cache.is_rejected(&login_serial(), &pin));
        assert!(!cache.holds_pin1());
    }

    #[test]
    fn settle_login_maps_locked_and_other() {
        for (outcome, expected) in [
            (super::VerifyOutcome::Locked, CKR_PIN_LOCKED),
            (
                super::VerifyOutcome::Other(StatusWord::SecurityNotSatisfied),
                CKR_DEVICE_ERROR,
            ),
        ] {
            let mut cache = login_cache();
            let res = super::settle_login(
                &mut cache,
                login_serial(),
                random_pin(),
                remaining(RETRIES_PRISTINE),
                outcome,
            );
            assert_eq!(res, Err(expected));
            assert!(!cache.holds_pin1());
        }
    }
}
