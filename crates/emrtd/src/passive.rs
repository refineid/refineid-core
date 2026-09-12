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

//! ICAO 9303 passive authentication.
//!
//! Proves that the data groups a card handed over are the ones its
//! issuing state signed: the EF.SOD security object's CMS signature is
//! verified with the Document Signer Certificate embedded in the SOD
//! itself, the DG1 and DG2 hashes inside the verified content are
//! compared against the raw files read from the card, and the DSC is
//! chained to a caller-supplied CSCA trust anchor.
//!
//! Trust topology: the card is trusted to deliver its own certificates
//! -- the DSC always comes from the SOD, so a DSC rotation needs no
//! software update -- but never to vouch for itself. The CSCA anchor is
//! the one input that must come from the verifier, because a forged
//! document can always embed a self-consistent chain. Anchors are
//! matched by subject name against the DSC issuer, so one anchor set
//! serves any number of issuing states.
//!
//! Verification is offline and deliberately clock-free, matching the
//! reference implementation: certificate validity windows describe the
//! signing era, not the reading moment, and expiry alone does not
//! un-sign a document.

use core::error::Error as CoreError;
use core::fmt;

use refineid_cms::signed_data::{CmsError, OwnedSignedData, VerifiedSignedData};
use refineid_cms::x509::{OwnedCert, X509Error};

/// ICAO 9303-10 data group number carrying the TD1 MRZ.
const DATA_GROUP_NUMBER_MRZ: u32 = 1;
/// ICAO 9303-10 data group number carrying the encoded face.
const DATA_GROUP_NUMBER_FACE: u32 = 2;

/// Raw EF.DG1 bytes exactly as read from the card. Explicitly
/// unvalidated boundary input to [`authenticate_document`].
pub struct EfDg1Bytes(Vec<u8>);

/// Raw EF.DG2 bytes exactly as read from the card. Explicitly
/// unvalidated boundary input to [`authenticate_document`].
pub struct EfDg2Bytes(Vec<u8>);

/// Raw EF.SOD bytes exactly as read from the card. Explicitly
/// unvalidated boundary input to [`authenticate_document`].
pub struct EfSodBytes(Vec<u8>);

/// The three raw files passive authentication consumes, read inside
/// one selected eMRTD application session.
pub struct PassiveAuthenticationFiles {
    /// Raw EF.DG1 (TD1 MRZ) bytes.
    pub mrz: EfDg1Bytes,
    /// Raw EF.DG2 (encoded face) bytes.
    pub face: EfDg2Bytes,
    /// Raw EF.SOD (security object) bytes.
    pub security_object: EfSodBytes,
}

impl EfDg1Bytes {
    /// Wrap raw card-read bytes; no validation happens here.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw file bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl EfDg2Bytes {
    /// Wrap raw card-read bytes; no validation happens here.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw file bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl EfSodBytes {
    /// Wrap raw card-read bytes; no validation happens here.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw file bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// The data groups carry personal data (MRZ identity, facial image), so
// their Debug forms render only the length -- a value formatted into a
// trace or an assertion message must not leak card contents.
impl fmt::Debug for EfDg1Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EfDg1Bytes([redacted; {}])", self.0.len())
    }
}

impl fmt::Debug for EfDg2Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EfDg2Bytes([redacted; {}])", self.0.len())
    }
}

impl fmt::Debug for EfSodBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EfSodBytes([redacted; {}])", self.0.len())
    }
}

/// One trusted CSCA certificate. Parse-validated at construction, so
/// an anchor set can only hold structurally sound certificates.
pub struct CscaAnchor {
    certificate: OwnedCert,
}

impl CscaAnchor {
    /// Parse one trusted CSCA certificate from its DER bytes.
    ///
    /// # Errors
    ///
    /// [`PassiveAuthenticationError::AnchorMalformed`] when the bytes
    /// are not a well-formed X.509 certificate.
    pub fn from_der(der: &[u8]) -> Result<Self, PassiveAuthenticationError> {
        let certificate =
            OwnedCert::from_der(der).map_err(PassiveAuthenticationError::AnchorMalformed)?;
        Ok(Self { certificate })
    }
}

impl fmt::Debug for CscaAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CscaAnchor({} DER bytes)",
            self.certificate.as_der().len()
        )
    }
}

/// The verifier-owned CSCA trust anchor set.
#[derive(Debug)]
pub struct CscaAnchors(Vec<CscaAnchor>);

impl CscaAnchors {
    /// Wrap an already-parsed anchor collection.
    #[must_use]
    pub fn new(anchors: Vec<CscaAnchor>) -> Self {
        Self(anchors)
    }

    /// Whether the set holds no anchors at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Why passive authentication rejected a document.
#[derive(Debug)]
pub enum PassiveAuthenticationError {
    /// A supplied trust anchor was not a well-formed certificate.
    AnchorMalformed(X509Error),
    /// EF.SOD did not parse as a CMS `SignedData`.
    MalformedSecurityObject(CmsError),
    /// The SOD carries no embedded Document Signer Certificate.
    DocumentSignerMissing,
    /// The embedded Document Signer Certificate did not parse.
    DocumentSignerMalformed(X509Error),
    /// The SOD's CMS signature failed against the embedded DSC.
    SecurityObjectSignature(CmsError),
    /// The verified content is not a well-formed `LDSSecurityObject`.
    SecurityObjectContent(CmsError),
    /// The SOD attests no hash for DG1 (the MRZ).
    MrzHashMissing,
    /// The card's DG1 bytes do not hash to the attested value.
    MrzHashMismatch,
    /// The SOD attests no hash for DG2 (the face).
    FaceHashMissing,
    /// The card's DG2 bytes do not hash to the attested value.
    FaceHashMismatch,
    /// The verifier supplied an empty anchor set.
    NoTrustedAnchors,
    /// No supplied anchor with a subject matching the DSC issuer
    /// verified the DSC signature.
    AnchorChainFailed,
}

impl fmt::Display for PassiveAuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnchorMalformed(error) => write!(f, "trust anchor did not parse: {error}"),
            Self::MalformedSecurityObject(error) => {
                write!(f, "EF.SOD did not parse as CMS SignedData: {error}")
            }
            Self::DocumentSignerMissing => {
                f.write_str("EF.SOD embeds no Document Signer Certificate")
            }
            Self::DocumentSignerMalformed(error) => {
                write!(
                    f,
                    "embedded Document Signer Certificate did not parse: {error}"
                )
            }
            Self::SecurityObjectSignature(error) => {
                write!(
                    f,
                    "EF.SOD signature failed against the embedded DSC: {error}"
                )
            }
            Self::SecurityObjectContent(error) => {
                write!(f, "verified content is not an LDSSecurityObject: {error}")
            }
            Self::MrzHashMissing => f.write_str("EF.SOD attests no hash for DG1"),
            Self::MrzHashMismatch => f.write_str("DG1 bytes do not match the attested hash"),
            Self::FaceHashMissing => f.write_str("EF.SOD attests no hash for DG2"),
            Self::FaceHashMismatch => f.write_str("DG2 bytes do not match the attested hash"),
            Self::NoTrustedAnchors => f.write_str("no CSCA trust anchors supplied"),
            Self::AnchorChainFailed => {
                f.write_str("no supplied CSCA anchor verified the Document Signer Certificate")
            }
        }
    }
}

impl CoreError for PassiveAuthenticationError {}

/// Proof that one document passed passive authentication. Exists only
/// through [`authenticate_document`], so holding a value is holding the
/// verification result.
pub struct AuthenticatedDocument {
    document_signer_der: Vec<u8>,
}

impl AuthenticatedDocument {
    /// DER of the Document Signer Certificate that verified, for
    /// display or fingerprinting by the caller.
    #[must_use]
    pub fn document_signer_der(&self) -> &[u8] {
        &self.document_signer_der
    }
}

impl fmt::Debug for AuthenticatedDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthenticatedDocument(dsc: {} DER bytes)",
            self.document_signer_der.len()
        )
    }
}

/// Run passive authentication over one card read.
///
/// The steps, in trust order: parse EF.SOD as CMS `SignedData`; verify
/// its signature with the embedded DSC (the verified wrapper is the
/// only door to the signed content); compare the attested DG1 and DG2
/// hashes against the raw card files; then close the `DSC -> CSCA` hop
/// against the supplied anchors by subject-name match plus signature
/// verification.
///
/// # Errors
///
/// A [`PassiveAuthenticationError`] naming the first failed step; see
/// the variant docs.
pub fn authenticate_document(
    security_object: &EfSodBytes,
    mrz: &EfDg1Bytes,
    face: &EfDg2Bytes,
    anchors: &CscaAnchors,
) -> Result<AuthenticatedDocument, PassiveAuthenticationError> {
    if anchors.is_empty() {
        return Err(PassiveAuthenticationError::NoTrustedAnchors);
    }

    let owned = OwnedSignedData::from_der(security_object.as_bytes())
        .map_err(PassiveAuthenticationError::MalformedSecurityObject)?;
    let signed_data = owned.view();

    let document_signer_der = signed_data
        .certificates_der
        .first()
        .copied()
        .ok_or(PassiveAuthenticationError::DocumentSignerMissing)?;
    let document_signer = OwnedCert::from_der(document_signer_der)
        .map_err(PassiveAuthenticationError::DocumentSignerMalformed)?;

    // Signature first: the DG-hash table is readable only through the
    // verified wrapper, so a hash comparison can never run over an
    // attacker-controlled, unverified SOD.
    let verified = VerifiedSignedData::verify(&signed_data, &document_signer.view().spki)
        .map_err(PassiveAuthenticationError::SecurityObjectSignature)?;
    let lds = verified
        .lds_security_object()
        .map_err(PassiveAuthenticationError::SecurityObjectContent)?;

    let mut mrz_hash: Option<&[u8]> = None;
    let mut face_hash: Option<&[u8]> = None;
    for (data_group_number, attested) in &lds.data_group_hashes {
        match *data_group_number {
            DATA_GROUP_NUMBER_MRZ => mrz_hash = Some(attested),
            DATA_GROUP_NUMBER_FACE => face_hash = Some(attested),
            _ => {}
        }
    }
    let mrz_hash = mrz_hash.ok_or(PassiveAuthenticationError::MrzHashMissing)?;
    if lds.hash_algorithm.digest(mrz.as_bytes()) != mrz_hash {
        return Err(PassiveAuthenticationError::MrzHashMismatch);
    }
    let face_hash = face_hash.ok_or(PassiveAuthenticationError::FaceHashMissing)?;
    if lds.hash_algorithm.digest(face.as_bytes()) != face_hash {
        return Err(PassiveAuthenticationError::FaceHashMismatch);
    }

    // DSC -> CSCA: subject-name match selects candidates, signature
    // verification decides. Matching by name keeps the anchor set
    // country-neutral -- Finnish and Estonian anchors coexist and the
    // right one is chosen by the DSC's own issuer name.
    let dsc_view = document_signer.view();
    let mut chained = false;
    for anchor in &anchors.0 {
        let candidate = anchor.certificate.view();
        if candidate.subject != dsc_view.issuer {
            continue;
        }
        if dsc_view.verify_signed_by(candidate).is_ok() {
            chained = true;
            break;
        }
    }
    if !chained {
        return Err(PassiveAuthenticationError::AnchorChainFailed);
    }

    Ok(AuthenticatedDocument {
        document_signer_der: document_signer_der.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticatedDocument, CscaAnchor, CscaAnchors, EfDg1Bytes, EfDg2Bytes, EfSodBytes,
        PassiveAuthenticationError, authenticate_document,
    };
    use refineid_cms::signed_data::OwnedSignedData;

    /// The exact DG1 payload the committed fixture's SOD attests to.
    const FIXTURE_DG1: &[u8] = b"refineid-test-DG1";
    /// The exact DG2 payload the committed fixture's SOD attests to.
    const FIXTURE_DG2: &[u8] = b"refineid-test-DG2";

    // The same committed RSA-2048/SHA-256 CMS fixture the cms crate's
    // tests verify: eContent is a minimal LDSSecurityObject attesting
    // SHA-256 hashes of `FIXTURE_DG1` / `FIXTURE_DG2`, signed by an
    // embedded self-signed "RefineID Test DSC RSA" certificate. The
    // self-signed signer doubles as its own anchor here, exercising the
    // full chain: signature, both DG hashes, and the anchor hop.
    const FIXTURE_SOD_HEX: &str = "\
        3082060906092a864886f70d010702a08205fa308205f6020103310d300b0609\
        60864801650304020130700606678108010101a06604643062020100300d0609\
        6086480165030402010500304e3025020101042040d486fedd456ab92c4d02b2\
        704362570c096df55f421fee53945e70c6831bfd3025020102042072fc7341e3\
        f5f8935e96be104329ea083e88d8f009bcb46a340be9968902c008a082032530\
        82032130820209a00302010202141abbaecfaf492906d7fc069b27857f73ee21\
        0b4b300d06092a864886f70d01010b05003020311e301c06035504030c155265\
        46696e65494420546573742044534320525341301e170d323630363238313532\
        3834385a170d3336303632353135323834385a3020311e301c06035504030c15\
        526546696e6549442054657374204453432052534130820122300d06092a8648\
        86f70d01010105000382010f003082010a0282010100ed28349290c82f3dd487\
        1eff7b2ec12d057a9d2dc9ba566cd8ce23a0b5fc559ce4456738e2b69b57fd56\
        f84d0f6a5ca91f22d36a3a64864c0c3c50f0d96af2a18ecd5a7c1f934c2f3638\
        5264d867982f70487004cd5105d16cd47a7ec61c204a37d947c5d997ebf8e1ef\
        f6581823b15d753123991b308669ec5633214e7d75b35fbbdb937c6782f6e406\
        aed8edca9b5a028297891acad926fecb3adaa806daaf0bf886bb16c667762269\
        c9ecf3f6edd3398d151cbbe8f1b50ba6b4f4365451ad21fbc4804ff2bc406d61\
        db7041239b7bf53c4bfc5724302c2b392530e9b56c57c4d6072528fa2b3f95ed\
        90d6144869d5c5e9f48f74da2b1babed1d9d2bb2ef130203010001a353305130\
        1d0603551d0e04160414e5c676464f2bbed52b1298910619a21cde4f372a301f\
        0603551d23041830168014e5c676464f2bbed52b1298910619a21cde4f372a30\
        0f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003\
        82010100773ea57116db9ed8a192ce9c79faa1f6628b1d948f8d98aebb1a14fe\
        c50c931d89afbf74fd8f7890461231d1c29dfae7b4abfe71e7414a6b09191f69\
        608d940b9735fb3064152349f793ef0acc89a30bdf41383762cba983f0d4248a\
        67867cb7fce688a0a34454a2653648eeedd9b20b03bc73cd19df061cf3e045e1\
        26c3eb25aa529c872134bfa1c4057f3fd4177983ea2a7608d8ea413846d3c9f0\
        c0bb2f304246bbaaeb99c77fb761a711d630dea9dd37b8619a3030b47cdcc948\
        15f4baa7bf471fe4c5371ebe77e7e99d161eb5bf3a16802622899c8a3c07f45c\
        e1f9bded56c3e3b14e9201be3d585573af6a3441c0dbe94378e6fd9a984cbc3d\
        f865f8f1318202453082024102010130383020311e301c06035504030c155265\
        46696e6549442054657374204453432052534102141abbaecfaf492906d7fc06\
        9b27857f73ee210b4b300b0609608648016503040201a081e1301506092a8648\
        86f70d01090331080606678108010101301c06092a864886f70d010905310f17\
        0d3236303632383135323834385a302f06092a864886f70d01090431220420b4\
        f0af7f043f5d2153918add8d1aeee3214894d7d086ddec9332a3a6524989d230\
        7906092a864886f70d01090f316c306a300b060960864801650304012a300b06\
        09608648016503040116300b0609608648016503040102300a06082a864886f7\
        0d0307300e06082a864886f70d030202020080300d06082a864886f70d030202\
        0140300706052b0e030207300d06082a864886f70d0302020128300d06092a86\
        4886f70d010101050004820100515a1e751b91741f1c30ee975c3c7c84b94a2d\
        6b7f44bbd7edacaba05e39f7a116905c4d0c097ca694119542f43b3e9c28e84a\
        c4ded455743185b90122ad8b9e802b2cdf80f6c4f8be4dc9eeefcd72a679688d\
        9a6e0de0c0401d4a71f2b36edb763ab42b7cc8738b52f92a3b2f8f69b318d44e\
        0a53df2a5afead31394a89419a535a3656e0b4dfdbf585d0bceb04fdc258987a\
        afa1d3e2f49273c257dcb638b78c106ed077554742a2450a04a610f0e9104510\
        bec7224c82b5d65442376ff4a746ccd879056ee3347e02ceadf2f89cecc7d2b2\
        6613fd61ac2e60db8d4039844238e15e5e76de70305e2624d429ecf66c193b99\
        dda4b5a213bde6bd9e531be4d8";

    fn unhex(hex_fixture: &str) -> Vec<u8> {
        hex::decode(hex_fixture.replace([' ', '\n'], "")).expect("fixture hex decodes")
    }

    fn fixture_sod() -> EfSodBytes {
        EfSodBytes::new(unhex(FIXTURE_SOD_HEX))
    }

    fn fixture_anchor() -> CscaAnchors {
        let sod = OwnedSignedData::from_der(&unhex(FIXTURE_SOD_HEX)).expect("fixture SOD parses");
        let view = sod.view();
        let dsc_der = view
            .certificates_der
            .first()
            .copied()
            .expect("fixture SOD embeds its DSC");
        CscaAnchors::new(vec![
            CscaAnchor::from_der(dsc_der).expect("fixture DSC parses as anchor"),
        ])
    }

    #[test]
    fn authenticates_the_committed_fixture_end_to_end() {
        let result: AuthenticatedDocument = authenticate_document(
            &fixture_sod(),
            &EfDg1Bytes::new(FIXTURE_DG1.to_vec()),
            &EfDg2Bytes::new(FIXTURE_DG2.to_vec()),
            &fixture_anchor(),
        )
        .expect("fixture document authenticates");
        assert!(!result.document_signer_der().is_empty());
    }

    #[test]
    fn rejects_wrong_mrz_bytes() {
        let outcome = authenticate_document(
            &fixture_sod(),
            &EfDg1Bytes::new(b"tampered".to_vec()),
            &EfDg2Bytes::new(FIXTURE_DG2.to_vec()),
            &fixture_anchor(),
        );
        assert!(matches!(
            outcome,
            Err(PassiveAuthenticationError::MrzHashMismatch)
        ));
    }

    #[test]
    fn rejects_wrong_face_bytes() {
        let outcome = authenticate_document(
            &fixture_sod(),
            &EfDg1Bytes::new(FIXTURE_DG1.to_vec()),
            &EfDg2Bytes::new(b"tampered".to_vec()),
            &fixture_anchor(),
        );
        assert!(matches!(
            outcome,
            Err(PassiveAuthenticationError::FaceHashMismatch)
        ));
    }

    #[test]
    fn rejects_empty_anchor_set() {
        let outcome = authenticate_document(
            &fixture_sod(),
            &EfDg1Bytes::new(FIXTURE_DG1.to_vec()),
            &EfDg2Bytes::new(FIXTURE_DG2.to_vec()),
            &CscaAnchors::new(Vec::new()),
        );
        assert!(matches!(
            outcome,
            Err(PassiveAuthenticationError::NoTrustedAnchors)
        ));
    }

    /// Keep the leading half of the fixture: enough to carry the outer
    /// header, short enough that the DER structure cannot complete.
    const TRUNCATION_KEEP_DIVISOR: usize = 2;

    #[test]
    fn rejects_truncated_security_object() {
        let mut bytes = unhex(FIXTURE_SOD_HEX);
        bytes.truncate(bytes.len().div_euclid(TRUNCATION_KEEP_DIVISOR));
        let outcome = authenticate_document(
            &EfSodBytes::new(bytes),
            &EfDg1Bytes::new(FIXTURE_DG1.to_vec()),
            &EfDg2Bytes::new(FIXTURE_DG2.to_vec()),
            &fixture_anchor(),
        );
        assert!(matches!(
            outcome,
            Err(PassiveAuthenticationError::MalformedSecurityObject(_))
        ));
    }

    #[test]
    fn rejects_tampered_signature_byte() {
        let mut bytes = unhex(FIXTURE_SOD_HEX);
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
        let outcome = authenticate_document(
            &EfSodBytes::new(bytes),
            &EfDg1Bytes::new(FIXTURE_DG1.to_vec()),
            &EfDg2Bytes::new(FIXTURE_DG2.to_vec()),
            &fixture_anchor(),
        );
        assert!(outcome.is_err());
    }

    #[test]
    fn debug_forms_redact_card_bytes() {
        let dg1 = EfDg1Bytes::new(FIXTURE_DG1.to_vec());
        let rendered = format!("{dg1:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("refineid-test"));
    }
}
