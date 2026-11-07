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

//! Certificate public-key border: arbitrary bytes as an unvalidated
//! certificate yield a typed key or a typed error; an accepted key
//! re-serialises as a SubjectPublicKeyInfo, and that SubjectPublicKeyInfo
//! in a certificate shell reconstructs the same key.

#![no_main]

use refineid_ber::{BerTag, Integer, Sequence, tlv};
use refineid_x509::{PublicKey, UnvalidatedCertificate};

/// The RFC 5280 section 4.1 TBSCertificate SEQUENCE fields between
/// serialNumber and subjectPublicKeyInfo when the explicit version is
/// absent: signature, issuer, validity and subject.
const TBS_SEQUENCES_BEFORE_SPKI: usize = 4;

/// The shell's serialNumber: a positive INTEGER of one octet (RFC 5280
/// section 4.1.2.2).
const SHELL_SERIAL_NUMBER: u8 = 1;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let certificate = UnvalidatedCertificate::new(bytes.to_vec());
    let Ok(key) = PublicKey::from_certificate(certificate) else {
        return;
    };
    if let PublicKey::Rsa(rsa) = &key {
        assert!(rsa.modulus().bit_length() > 0);
    }
    let spki = key.to_spki_der().expect("an accepted key re-serialises");
    let shell = certificate_around(&spki);
    assert_eq!(
        PublicKey::from_certificate(UnvalidatedCertificate::new(shell)),
        Ok(key)
    );
});

/// A certificate SEQUENCE whose TBSCertificate carries a one-octet
/// serialNumber, empty SEQUENCEs for signature, issuer, validity and
/// subject, then `spki`.
fn certificate_around(spki: &[u8]) -> Vec<u8> {
    let sequence_tag = u8::try_from(<Sequence as BerTag>::TAG).expect("a universal tag");
    let integer_tag = u8::try_from(<Integer as BerTag>::TAG).expect("a universal tag");
    let mut tbs_value = tlv(integer_tag, [SHELL_SERIAL_NUMBER]).expect("a serial encodes");
    for _ in 0..TBS_SEQUENCES_BEFORE_SPKI {
        let empty = tlv(sequence_tag, []).expect("an empty SEQUENCE encodes");
        tbs_value.extend_from_slice(&empty);
    }
    tbs_value.extend_from_slice(spki);
    let tbs = tlv(sequence_tag, tbs_value).expect("a TBSCertificate encodes");
    tlv(sequence_tag, tbs).expect("a certificate encodes")
}
