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

//! CMS and X.509 borders: arbitrary bytes as a certificate, a
//! SubjectPublicKeyInfo, an extensions block, a SignedData, or a raw
//! ECDSA signature parse or refuse with a typed error; an owned wrapper
//! that accepted its bytes hands out its borrowed view.

#![no_main]

use refineid_cms::container::{EcdsaDer, Signature};
use refineid_cms::signed_data::{OwnedSignedData, SignedData};
use refineid_cms::x509::{
    Certificate, OwnedCert, extract_basic_constraints, extract_extended_key_usage,
    extract_extended_key_usage_meta, extract_key_usage, extract_key_usage_meta,
    extract_rsa_public_key, parse_subject_public_key_info,
};

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(certificate) = Certificate::from_der(bytes) {
        let _ = parse_subject_public_key_info(certificate.spki.as_der());
        let _ = extract_rsa_public_key(certificate.spki.as_der());
        if let Some(extensions) = certificate.extensions {
            check_extensions(extensions);
        }
        let _ = certificate.verify_signed_by(certificate);
        let owned = OwnedCert::from_der(bytes).expect("an accepted certificate is accepted again");
        assert_eq!(owned.view().raw_der, certificate.raw_der);
    } else {
        assert!(OwnedCert::from_der(bytes).is_err());
    }
    let _ = parse_subject_public_key_info(bytes);
    let _ = extract_rsa_public_key(bytes);
    check_extensions(bytes);

    if let Ok(signed_data) = SignedData::parse(bytes) {
        let signer = signed_data.signer();
        let _ = (
            signed_data.certificates().len(),
            signed_data.revocation_info().len(),
            signer.signer_identifier(),
            signer.signed_attributes().len(),
            signer.unsigned_attributes().len(),
            signer.signed_attributes_der(),
        );
        let owned =
            OwnedSignedData::from_der(bytes).expect("an accepted SignedData is accepted again");
        let _ = owned.view();
    } else {
        assert!(OwnedSignedData::from_der(bytes).is_err());
    }

    let _ = Signature::<EcdsaDer>::from_raw_concatenation(bytes);
});

fn check_extensions(extensions: &[u8]) {
    let _ = extract_key_usage(extensions);
    let _ = extract_key_usage_meta(extensions);
    let _ = extract_extended_key_usage(extensions);
    let _ = extract_extended_key_usage_meta(extensions);
    let _ = extract_basic_constraints(extensions);
}
