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

//! Document-verification borders: an arbitrary file as a PDF, an ASiC
//! container, a CAdES signature, an XML document, a CRL, an OCSP
//! response or a time-stamp token parses or refuses with a typed error,
//! and verifying it under no trust anchors returns a report or a typed
//! failure without touching the network.

#![no_main]

use core::time::Duration;

use refineid_doc_sign::crl::OwnedCrl;
use refineid_doc_sign::ocsp::OwnedOcspResponse;
use refineid_doc_sign::timestamp::claimed_generation_time;
use refineid_doc_sign::verification::asic::AsicContainer;
use refineid_doc_sign::verification::cades::CadesSignature;
use refineid_doc_sign::verification::pdf::PdfDocument;
use refineid_doc_sign::verification::xml::XmlDocument;
use refineid_doc_sign::verification::{DocumentFile, TrustAnchors, verify};
use refineid_doc_sign::x509::DateTime;
use refineid_doc_sign::x509_ext::{
    extract_ca_issuers_urls, extract_crl_distribution_urls, extract_ocsp_urls,
};

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(document) = PdfDocument::parse(bytes) {
        for signature in document.signatures() {
            let _ = signature.cms();
        }
    }
    if let Ok(container) = AsicContainer::parse(bytes) {
        for entry in container.data_files() {
            let _ = (entry.name(), entry.content().len());
        }
        for entry in container.cades_signatures() {
            let _ = container.manifest_intact(entry);
        }
    }
    let _ = CadesSignature::parse(bytes);
    let _ = XmlDocument::parse(bytes.to_vec());
    let _ = OwnedCrl::from_der(bytes);
    let _ = OwnedOcspResponse::from_der(bytes);
    let _ = claimed_generation_time(bytes);
    let _ = extract_crl_distribution_urls(bytes);
    let _ = extract_ocsp_urls(bytes);
    let _ = extract_ca_issuers_urls(bytes);

    let now = DateTime::from_unix_duration(Duration::ZERO).expect("the epoch is a date");
    if let Ok(file) = DocumentFile::from_file(bytes.to_vec()) {
        let _ = verify(&file, &TrustAnchors::new(Vec::new()), now);
    }
});
