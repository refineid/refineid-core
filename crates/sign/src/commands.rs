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

//! Typed commands for the FINEID signing chain.
//!
//! Signing is a two- or three-command choreography (FINEID S1 v4.2
//! sections 3.6 through 3.8). MANAGE SECURITY ENVIRONMENT: SET pins the
//! key and algorithm in the digital-signature template, and PERFORM
//! SECURITY OPERATION: COMPUTE DIGITAL SIGNATURE returns the signature.
//! The citizen card loads the host-computed digest with an intervening
//! PERFORM SECURITY OPERATION: HASH and signs an empty PSO:CDS; the
//! organizational card carries the digest inline in PSO:CDS and issues no
//! PSO:HASH. The card holds the private key and never reveals it; these
//! commands carry no credential material.

use refineid_apdu::{ApduClass, CommandApdu, CommandDataError, CommandHeader};

use crate::container::RsaCryptogram;

/// MANAGE SECURITY ENVIRONMENT instruction.
const MSE_INS: u8 = 0x22;
/// MSE P1 selecting SET for computation and decipherment.
const MSE_P1_SET: u8 = 0x41;
/// MSE P2 for the digital-signature template (DST). It is the only
/// template FINEID sets ahead of PERFORM SECURITY OPERATION: COMPUTE
/// DIGITAL SIGNATURE, for the authentication key and the
/// qualified-signature key alike: S1 v4.2 section 3.6.2 defines a
/// hash (AAh), a digital-signature (B6h), and a confidentiality (B8h)
/// template, and PSO:CDS runs under the digital-signature one.
const MSE_P2_DST: u8 = 0xB6;

/// Control-reference-object tag for the algorithm reference.
const CRDO_ALG_REF: u8 = 0x80;
/// Control-reference-object tag for the key reference.
const CRDO_KEY_REF: u8 = 0x84;
/// Control-reference-object value length: the references are one byte.
const CRDO_VALUE_LEN: u8 = 0x01;

/// PERFORM SECURITY OPERATION instruction, shared by HASH and COMPUTE
/// DIGITAL SIGNATURE.
const PSO_INS: u8 = 0x2A;
/// PSO:HASH P1.
const PSO_HASH_P1: u8 = 0x90;
/// PSO:HASH P2 for the external / final hash form.
const PSO_HASH_P2_EXTERNAL: u8 = 0xA0;
/// The hash-value object tag inside PSO:HASH.
const PSO_HASH_TAG_VALUE: u8 = 0x90;
/// Bytes preceding the digest in the hash-value object: the tag and the
/// length byte.
const HASH_VALUE_HEADER_LEN: usize = 2;

/// PSO:COMPUTE DIGITAL SIGNATURE P1.
const PSO_CDS_P1: u8 = 0x9E;
/// PSO:COMPUTE DIGITAL SIGNATURE P2.
const PSO_CDS_P2: u8 = 0x9A;
/// Expected-length byte requesting every available byte of the
/// signature; the adapter chains any 61xx response.
const PSO_CDS_LE_ANY: u8 = 0x00;

/// MSE P2 for the confidentiality template (CT), which holds the decipher
/// key (FINEID S1 v4.2 section 3.6.2).
const MSE_P2_CT: u8 = 0xB8;
/// PSO:DECIPHER P1: the decrypted value is returned in the response
/// (FINEID S1 v4.2 section 3.9).
const PSO_DECIPHER_P1: u8 = 0x80;
/// PSO:DECIPHER P2: the cryptogram is in the data field.
const PSO_DECIPHER_P2: u8 = 0x86;
/// Padding-content indicator prefixing the cryptogram (FINEID S1 v4.2
/// section 3.9): the data field is this byte followed by the encrypted
/// message.
const DECIPHER_PADDING_INDICATOR: u8 = 0x81;
/// Bytes the padding-content indicator occupies ahead of the cryptogram.
const DECIPHER_INDICATOR_LEN: usize = 1;

/// SHA-1 digest length in bytes.
pub const SHA1_LEN: usize = 20;
/// SHA-224 digest length in bytes.
pub const SHA224_LEN: usize = 28;
/// SHA-256 digest length in bytes.
pub const SHA256_LEN: usize = 32;
/// SHA-384 digest length in bytes.
pub const SHA384_LEN: usize = 48;
/// SHA-512 digest length in bytes.
pub const SHA512_LEN: usize = 64;

/// Algorithm-reference byte for the digital-signature template, per
/// FINEID S1 v4.2 section 3.6.3 Table 6. The byte packs the hash
/// function in its high nibble and the signature scheme in its low
/// nibble; the named values are the ones FINEID cards accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureAlgRef {
    byte: u8,
}

impl SignatureAlgRef {
    /// SHA-256 (high nibble 4) with RSASSA-PKCS1-v1_5 (low nibble 2):
    /// the RSA FINEID signing key's reference.
    pub const SHA256_RSA_PKCS1: Self = Self { byte: 0x42 };
    /// SHA-384 (high nibble 5) with RSASSA-PKCS1-v1_5 (low nibble 2):
    /// the RSA signature reference over SHA-384.
    pub const SHA384_RSA_PKCS1: Self = Self { byte: 0x52 };
    /// SHA-512 (high nibble 6) with RSASSA-PKCS1-v1_5 (low nibble 2):
    /// the RSA signature reference over SHA-512.
    pub const SHA512_RSA_PKCS1: Self = Self { byte: 0x62 };
    /// SHA-384 (high nibble 5) with ECDSA (low nibble 4): the newer
    /// P-384 key's reference (FINEID S4-1 v4.2 section 4.2).
    pub const SHA384_ECDSA: Self = Self { byte: 0x54 };
    /// SHA-256 (high nibble 4) with ECDSA (low nibble 4): the P-384 key
    /// signing a SHA-256 digest, required by some relying parties.
    pub const SHA256_ECDSA: Self = Self { byte: 0x44 };
    /// SHA-256 (high nibble 4) with RSASSA-PSS (low nibble 5): the RSA
    /// key producing a PSS signature. FINEID cards apply the PSS padding
    /// themselves, so the choreography matches the pre-hashed RSA chain
    /// (FINEID S1 v4.2 section 3.6.3 Table 6).
    pub const SHA256_RSA_PSS: Self = Self { byte: 0x45 };
    /// SHA-384 (high nibble 5) with RSASSA-PSS (low nibble 5), using
    /// SHA-384 for MGF1 and a 48-byte salt as published in CIAInfo
    /// (FINEID S4-1 v4.2 section 8.1.3).
    pub const SHA384_RSA_PSS: Self = Self { byte: 0x55 };
    /// SHA-512 (high nibble 6) with RSASSA-PSS (low nibble 5), using
    /// SHA-512 for MGF1 and a 64-byte salt as published in CIAInfo
    /// (FINEID S4-1 v4.2 section 8.1.3).
    pub const SHA512_RSA_PSS: Self = Self { byte: 0x65 };

    /// The wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.byte
    }
}

/// Algorithm-reference byte for the confidentiality template, per FINEID
/// S1 v4.2 section 3.6.3 Table 7: the padding a PSO:DECIPHER expects the
/// cryptogram to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecipherAlgRef {
    byte: u8,
}

impl DecipherAlgRef {
    /// RSASSA PKCS#1 v1.5 (block type 2) padding.
    pub const RSA_PKCS1: Self = Self { byte: 0x1A };
    /// RSAES-OAEP with SHA-256.
    pub const RSAES_OAEP_SHA256: Self = Self { byte: 0x4D };

    /// The wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.byte
    }
}

/// Assemble an MSE:SET control-reference body -- the algorithm and key
/// control-reference objects -- into a case-3 command under `template_p2`.
fn mse_set_apdu(template_p2: u8, alg: u8, key_ref: u8) -> Result<CommandApdu, CommandDataError> {
    let data = [
        CRDO_ALG_REF,
        CRDO_VALUE_LEN,
        alg,
        CRDO_KEY_REF,
        CRDO_VALUE_LEN,
        key_ref,
    ];
    CommandApdu::case_3(
        CommandHeader {
            class: ApduClass::Plain,
            instruction: MSE_INS,
            p1: MSE_P1_SET,
            p2: template_p2,
        },
        &data,
    )
}

/// MANAGE SECURITY ENVIRONMENT: SET for a signing key, in the
/// digital-signature template.
#[derive(Debug, Clone, Copy)]
pub struct MseSet {
    /// Algorithm reference.
    pub alg_ref: SignatureAlgRef,
    /// Private-key reference byte, already resolved for the card's
    /// numbering: a citizen reference from [`crate::KeyRef::as_byte`], or
    /// the organizational qualified key's local reference from
    /// [`crate::KeyRef::reference`].
    pub key_ref: u8,
}

impl MseSet {
    /// Serialise into a case-3 command APDU.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] never triggers here: the fixed six-byte
    /// control-reference body is always within the short form. The
    /// result is fallible so the caller stays fail-closed.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        mse_set_apdu(MSE_P2_DST, self.alg_ref.as_byte(), self.key_ref)
    }
}

/// MANAGE SECURITY ENVIRONMENT: SET for a decipher key, in the
/// confidentiality template.
#[derive(Debug, Clone, Copy)]
pub struct MseSetCt {
    /// Algorithm (padding) reference.
    pub alg_ref: DecipherAlgRef,
    /// Private-key reference byte, already resolved for the card's
    /// numbering.
    pub key_ref: u8,
}

impl MseSetCt {
    /// Serialise into a case-3 command APDU.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] never triggers here: the fixed six-byte
    /// control-reference body is always within the short form. The result
    /// is fallible so the caller stays fail-closed.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        mse_set_apdu(MSE_P2_CT, self.alg_ref.as_byte(), self.key_ref)
    }
}

/// A host-computed digest shipped to the card for signing. Each variant
/// pins its wire length (FINEID S1 v4.2 section 3.7.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalHashValue {
    /// A SHA-1 digest.
    Sha1([u8; SHA1_LEN]),
    /// A SHA-224 digest.
    Sha224([u8; SHA224_LEN]),
    /// A SHA-256 digest.
    Sha256([u8; SHA256_LEN]),
    /// A SHA-384 digest.
    Sha384([u8; SHA384_LEN]),
    /// A SHA-512 digest.
    Sha512([u8; SHA512_LEN]),
}

impl ExternalHashValue {
    /// The digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha1(bytes) => bytes,
            Self::Sha224(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
            Self::Sha384(bytes) => bytes,
            Self::Sha512(bytes) => bytes,
        }
    }

    /// The length byte for the hash-value object; within `u8` by
    /// construction.
    #[must_use]
    pub const fn len_byte(&self) -> u8 {
        match self {
            Self::Sha1(_) => SHA1_LEN as u8,
            Self::Sha224(_) => SHA224_LEN as u8,
            Self::Sha256(_) => SHA256_LEN as u8,
            Self::Sha384(_) => SHA384_LEN as u8,
            Self::Sha512(_) => SHA512_LEN as u8,
        }
    }
}

/// PSO:HASH shipping a host-computed digest in the external-hash form.
#[derive(Debug, Clone, Copy)]
pub struct PsoHashExternal {
    /// The host-computed digest.
    pub hash: ExternalHashValue,
}

impl PsoHashExternal {
    /// Serialise into a case-3 command APDU carrying the hash-value
    /// object.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] never triggers: the largest digest object is
    /// well within the short form. Fallible so the caller stays
    /// fail-closed.
    pub fn into_apdu(self) -> Result<CommandApdu, CommandDataError> {
        let bytes = self.hash.as_bytes();
        let mut data = Vec::with_capacity(HASH_VALUE_HEADER_LEN.saturating_add(bytes.len()));
        data.push(PSO_HASH_TAG_VALUE);
        data.push(self.hash.len_byte());
        data.extend_from_slice(bytes);
        CommandApdu::case_3(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: PSO_INS,
                p1: PSO_HASH_P1,
                p2: PSO_HASH_P2_EXTERNAL,
            },
            &data,
        )
    }
}

/// PSO:COMPUTE DIGITAL SIGNATURE. The empty-bodied form signs a hash the
/// card already holds; the inline form carries the digest itself.
#[derive(Debug, Clone, Copy)]
pub struct PsoComputeDigitalSignature;

/// The Le byte requesting a signature of `sig_bytes`.
///
/// A signature that fits the short form asks for its exact length, which a
/// T=0 card requires and answers directly; the ECDSA signatures take this
/// path. A signature wider than the short form -- RSA-3072 -- cannot, so it
/// uses the maximum-length encoding and the adapter chains the 61xx
/// response.
#[must_use]
pub fn expected_length_le(sig_bytes: usize) -> u8 {
    u8::try_from(sig_bytes).unwrap_or(PSO_CDS_LE_ANY)
}

impl PsoComputeDigitalSignature {
    /// Serialise the empty-bodied form into a case-2 command APDU: the
    /// card signs the hash previously loaded by [`PsoHashExternal`] and
    /// returns the signature. This ends the citizen chain (FINEID S1 v4.2
    /// section 3.8). `le` is the expected-length byte (see
    /// [`expected_length_le`]); the adapter chains any 61xx response.
    #[must_use]
    pub fn into_apdu(self, le: u8) -> CommandApdu {
        CommandApdu::case_2(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: PSO_INS,
                p1: PSO_CDS_P1,
                p2: PSO_CDS_P2,
            },
            le,
        )
    }

    /// Serialise the inline-digest form into a case-4 command APDU
    /// (`00 2A 9E 9A <Lc> <digest> <Le>`): the organizational card has no
    /// external-hash PSO:HASH step, so the digest rides inline and the
    /// card signs it directly. The citizen card rejects this shape and the
    /// organizational card rejects the empty form, which is why the
    /// resolved numbering picks the chain. The digest is an
    /// [`ExternalHashValue`], so its wire length is the one its hash
    /// function fixes; `le` is the expected-length byte (see
    /// [`expected_length_le`]).
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] never triggers: the largest digest is well
    /// within the short form. Fallible so the caller stays fail-closed.
    pub fn into_apdu_with_digest(
        self,
        hash: ExternalHashValue,
        le: u8,
    ) -> Result<CommandApdu, CommandDataError> {
        CommandApdu::case_4(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: PSO_INS,
                p1: PSO_CDS_P1,
                p2: PSO_CDS_P2,
            },
            hash.as_bytes(),
            le,
        )
    }
}

/// PERFORM SECURITY OPERATION: DECIPHER over an RSA cryptogram.
///
/// The data field is the padding-content indicator followed by the
/// encrypted message, which is modulus-wide and so exceeds the short
/// form; the cryptogram is shipped by command chaining (FINEID S1 v4.2
/// section 3.9). The card strips the padding and returns the plaintext.
#[derive(Debug, Clone, Copy)]
pub struct PsoDecipher<'a> {
    /// The RSA cryptogram, modulus-wide by construction.
    pub cryptogram: &'a RsaCryptogram,
}

impl PsoDecipher<'_> {
    /// Serialise into a command-chained sequence: the caller transmits
    /// each in order, and the last returns the deciphered plaintext.
    ///
    /// # Errors
    ///
    /// [`CommandDataError`] never triggers: the data field is the
    /// padding-content indicator and a modulus-wide block. Fallible so
    /// the caller stays fail-closed.
    pub fn into_chain(self) -> Result<Vec<CommandApdu>, CommandDataError> {
        let ciphertext = self.cryptogram.as_bytes();
        let mut data = Vec::with_capacity(DECIPHER_INDICATOR_LEN + ciphertext.len());
        data.push(DECIPHER_PADDING_INDICATOR);
        data.extend_from_slice(ciphertext);
        CommandApdu::command_chain(
            CommandHeader {
                class: ApduClass::Plain,
                instruction: PSO_INS,
                p1: PSO_DECIPHER_P1,
                p2: PSO_DECIPHER_P2,
            },
            &data,
            PSO_CDS_LE_ANY,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CRDO_ALG_REF, CRDO_KEY_REF, CRDO_VALUE_LEN, DECIPHER_PADDING_INDICATOR, DecipherAlgRef,
        ExternalHashValue, HASH_VALUE_HEADER_LEN, MSE_INS, MSE_P1_SET, MSE_P2_CT, MSE_P2_DST,
        MseSet, MseSetCt, PSO_CDS_LE_ANY, PSO_CDS_P1, PSO_CDS_P2, PSO_DECIPHER_P1, PSO_DECIPHER_P2,
        PSO_HASH_P1, PSO_HASH_P2_EXTERNAL, PSO_HASH_TAG_VALUE, PSO_INS, PsoComputeDigitalSignature,
        PsoDecipher, PsoHashExternal, SHA256_LEN, SHA384_LEN, SHA512_LEN, SignatureAlgRef,
    };
    use crate::{
        KEY_REF_AUTH, KEY_REF_SIGN, ORG_QUALIFIED_KEY_REF, RSA_3072_MODULUS_BYTES, RsaCryptogram,
    };
    use refineid_apdu::ApduClass;

    /// A digest filler byte.
    const FILL: u8 = 0xAB;
    /// The documented SHA-256 + RSA-PKCS1 algorithm-reference byte.
    const ALG_SHA256_RSA: u8 = 0x42;
    /// The documented SHA-384 + RSA-PKCS1 algorithm-reference byte.
    const ALG_SHA384_RSA: u8 = 0x52;
    /// The documented SHA-512 + RSA-PKCS1 algorithm-reference byte.
    const ALG_SHA512_RSA: u8 = 0x62;
    /// The documented SHA-384 + ECDSA algorithm-reference byte.
    const ALG_SHA384_ECDSA: u8 = 0x54;
    /// The documented SHA-256 + ECDSA algorithm-reference byte.
    const ALG_SHA256_ECDSA: u8 = 0x44;
    /// The documented SHA-256 + RSASSA-PSS algorithm-reference byte.
    const ALG_SHA256_RSA_PSS: u8 = 0x45;
    /// The documented SHA-384 + RSASSA-PSS algorithm-reference byte.
    const ALG_SHA384_RSA_PSS: u8 = 0x55;
    /// The documented SHA-512 + RSASSA-PSS algorithm-reference byte.
    const ALG_SHA512_RSA_PSS: u8 = 0x65;
    /// The documented RSA PKCS#1 v1.5 decipher algorithm-reference byte.
    const ALG_DECIPHER_PKCS1: u8 = 0x1A;
    /// Commands a modulus-wide cryptogram chains into.
    const TWO_DECIPHER_COMMANDS: usize = 2;
    /// Wire index of the instruction byte.
    const INS_INDEX: usize = 1;
    /// Wire index of the P1 byte.
    const P1_INDEX: usize = 2;
    /// Wire index of the P2 byte.
    const P2_INDEX: usize = 3;
    /// Wire offset of the data field: past the header and the Lc byte.
    const DATA_OFFSET: usize = 5;

    /// The expected MSE:Set wire for `template_p2`, `alg`, and `key_ref`,
    /// assembled from the named framing constants: header, Lc, then the
    /// algorithm and key control-reference objects.
    fn mse_set_wire(template_p2: u8, alg: u8, key_ref: u8) -> Vec<u8> {
        let body = [
            CRDO_ALG_REF,
            CRDO_VALUE_LEN,
            alg,
            CRDO_KEY_REF,
            CRDO_VALUE_LEN,
            key_ref,
        ];
        let mut wire = vec![ApduClass::Plain.as_byte(), MSE_INS, MSE_P1_SET, template_p2];
        wire.push(body.len() as u8);
        wire.extend_from_slice(&body);
        wire
    }

    /// The expected PSO:HASH prefix for a digest of `digest_len`: header,
    /// Lc, then the hash-value tag and length, before the digest bytes.
    fn pso_hash_prefix(digest_len: usize) -> Vec<u8> {
        let object_len = HASH_VALUE_HEADER_LEN + digest_len;
        vec![
            ApduClass::Plain.as_byte(),
            PSO_INS,
            PSO_HASH_P1,
            PSO_HASH_P2_EXTERNAL,
            object_len as u8,
            PSO_HASH_TAG_VALUE,
            digest_len as u8,
        ]
    }

    /// The expected empty-bodied PSO:CDS wire: header and the expected-
    /// length byte `le`, no data.
    fn pso_cds_empty_wire(le: u8) -> Vec<u8> {
        vec![
            ApduClass::Plain.as_byte(),
            PSO_INS,
            PSO_CDS_P1,
            PSO_CDS_P2,
            le,
        ]
    }

    /// The expected inline-digest PSO:CDS wire: header, Lc, the digest,
    /// then the expected-length byte `le`.
    fn pso_cds_inline_wire(digest: &[u8], le: u8) -> Vec<u8> {
        let mut wire = vec![ApduClass::Plain.as_byte(), PSO_INS, PSO_CDS_P1, PSO_CDS_P2];
        wire.push(digest.len() as u8);
        wire.extend_from_slice(digest);
        wire.push(le);
        wire
    }

    #[test]
    fn algorithm_references_pack_the_documented_bytes() {
        assert_eq!(SignatureAlgRef::SHA256_RSA_PKCS1.as_byte(), ALG_SHA256_RSA);
        assert_eq!(SignatureAlgRef::SHA384_RSA_PKCS1.as_byte(), ALG_SHA384_RSA);
        assert_eq!(SignatureAlgRef::SHA512_RSA_PKCS1.as_byte(), ALG_SHA512_RSA);
        assert_eq!(SignatureAlgRef::SHA384_ECDSA.as_byte(), ALG_SHA384_ECDSA);
        assert_eq!(SignatureAlgRef::SHA256_ECDSA.as_byte(), ALG_SHA256_ECDSA);
        assert_eq!(
            SignatureAlgRef::SHA256_RSA_PSS.as_byte(),
            ALG_SHA256_RSA_PSS
        );
        assert_eq!(
            SignatureAlgRef::SHA384_RSA_PSS.as_byte(),
            ALG_SHA384_RSA_PSS
        );
        assert_eq!(
            SignatureAlgRef::SHA512_RSA_PSS.as_byte(),
            ALG_SHA512_RSA_PSS
        );
    }

    #[test]
    fn mse_set_for_the_signature_key_matches_the_specified_wire() {
        let apdu = MseSet {
            alg_ref: SignatureAlgRef::SHA256_RSA_PKCS1,
            key_ref: KEY_REF_SIGN,
        }
        .into_apdu()
        .expect("fixed body encodes");
        assert_eq!(
            apdu.as_bytes(),
            mse_set_wire(MSE_P2_DST, ALG_SHA256_RSA, KEY_REF_SIGN)
        );
    }

    #[test]
    fn mse_set_names_the_authentication_key_in_the_signature_template() {
        // The authentication key signs under the digital-signature
        // template too: FINEID defines no authentication template for
        // PSO:CDS.
        let apdu = MseSet {
            alg_ref: SignatureAlgRef::SHA384_ECDSA,
            key_ref: KEY_REF_AUTH,
        }
        .into_apdu()
        .expect("fixed body encodes");
        assert_eq!(
            apdu.as_bytes(),
            mse_set_wire(MSE_P2_DST, ALG_SHA384_ECDSA, KEY_REF_AUTH)
        );
    }

    #[test]
    fn organizational_mse_set_names_the_local_qualified_key() {
        let apdu = MseSet {
            alg_ref: SignatureAlgRef::SHA256_ECDSA,
            key_ref: ORG_QUALIFIED_KEY_REF,
        }
        .into_apdu()
        .expect("fixed body encodes");
        assert_eq!(
            apdu.as_bytes(),
            mse_set_wire(MSE_P2_DST, ALG_SHA256_ECDSA, ORG_QUALIFIED_KEY_REF)
        );
    }

    #[test]
    fn pso_hash_sha256_matches_the_specified_wire() {
        let apdu = PsoHashExternal {
            hash: ExternalHashValue::Sha256([FILL; SHA256_LEN]),
        }
        .into_apdu()
        .expect("digest object encodes");
        let wire = apdu.as_bytes();
        let prefix = pso_hash_prefix(SHA256_LEN);
        assert_eq!(&wire[..prefix.len()], prefix.as_slice());
        assert_eq!(wire.len(), prefix.len() + SHA256_LEN);
    }

    #[test]
    fn pso_hash_length_byte_tracks_the_digest() {
        assert_eq!(
            ExternalHashValue::Sha256([FILL; SHA256_LEN]).len_byte(),
            SHA256_LEN as u8
        );
        assert_eq!(
            ExternalHashValue::Sha384([FILL; SHA384_LEN]).len_byte(),
            SHA384_LEN as u8
        );
        assert_eq!(
            ExternalHashValue::Sha512([FILL; SHA512_LEN]).len_byte(),
            SHA512_LEN as u8
        );
    }

    #[test]
    fn pso_cds_empty_matches_the_specified_wire() {
        assert_eq!(
            PsoComputeDigitalSignature
                .into_apdu(PSO_CDS_LE_ANY)
                .as_bytes(),
            pso_cds_empty_wire(PSO_CDS_LE_ANY)
        );
    }

    #[test]
    fn pso_cds_inline_carries_the_digest_between_lc_and_le() {
        let digest = [FILL; SHA384_LEN];
        let apdu = PsoComputeDigitalSignature
            .into_apdu_with_digest(ExternalHashValue::Sha384(digest), PSO_CDS_LE_ANY)
            .expect("digest fits the short form");
        assert_eq!(
            apdu.as_bytes(),
            pso_cds_inline_wire(&digest, PSO_CDS_LE_ANY)
        );
    }

    #[test]
    fn expected_length_le_is_exact_when_it_fits_and_maximal_otherwise() {
        assert_eq!(
            super::expected_length_le(crate::ECDSA_P384_SIG_BYTES),
            crate::ECDSA_P384_SIG_BYTES as u8
        );
        assert_eq!(
            super::expected_length_le(crate::RSA_3072_SIG_BYTES),
            PSO_CDS_LE_ANY
        );
    }

    #[test]
    fn decipher_references_pack_the_documented_bytes() {
        assert_eq!(DecipherAlgRef::RSA_PKCS1.as_byte(), ALG_DECIPHER_PKCS1);
    }

    #[test]
    fn mse_set_ct_names_the_confidentiality_template() {
        let apdu = MseSetCt {
            alg_ref: DecipherAlgRef::RSA_PKCS1,
            key_ref: KEY_REF_AUTH,
        }
        .into_apdu()
        .expect("fixed body encodes");
        assert_eq!(
            apdu.as_bytes(),
            mse_set_wire(MSE_P2_CT, ALG_DECIPHER_PKCS1, KEY_REF_AUTH)
        );
    }

    #[test]
    fn pso_decipher_chains_the_padding_indicator_and_cryptogram() {
        let cryptogram =
            RsaCryptogram::from_bytes(vec![FILL; RSA_3072_MODULUS_BYTES]).expect("modulus-wide");
        let chain = PsoDecipher {
            cryptogram: &cryptogram,
        }
        .into_chain()
        .expect("cryptogram chains");
        assert_eq!(chain.len(), TWO_DECIPHER_COMMANDS);

        // First command: chaining class, the DECIPHER header, and a data
        // field that opens with the padding-content indicator.
        let first = chain[0].as_bytes();
        assert_eq!(first[0], ApduClass::ChainedFirst.as_byte());
        assert_eq!(first[INS_INDEX], PSO_INS);
        assert_eq!(first[P1_INDEX], PSO_DECIPHER_P1);
        assert_eq!(first[P2_INDEX], PSO_DECIPHER_P2);
        assert_eq!(first[DATA_OFFSET], DECIPHER_PADDING_INDICATOR);

        // Last command: plain class, ending in the expected-length byte.
        let last = chain[1].as_bytes();
        assert_eq!(last[0], ApduClass::Plain.as_byte());
        assert_eq!(last.last().copied(), Some(PSO_CDS_LE_ANY));
    }
}
