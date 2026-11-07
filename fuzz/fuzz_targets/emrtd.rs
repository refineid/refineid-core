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

//! eMRTD borders: EF.COM, DG1 and DG2 contents and the outer-length
//! header decoder accept arbitrary bytes without panicking, and the
//! header decoder agrees with the BER decoder wherever both accept.

#![no_main]

use refineid_ber::BerTlvAny;
use refineid_emrtd::reader::MAX_EMRTD_FILE_BYTES;
use refineid_emrtd::{
    DataGroupInventory, ParsedMrzTd1, decode_outer_total_length, parse_card_face_image,
};

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let _ = DataGroupInventory::parse(bytes);
    let _ = ParsedMrzTd1::parse(bytes);
    if let Some(image) = parse_card_face_image(bytes) {
        assert!(image.image_bytes().len() <= bytes.len());
    }
    let total = decode_outer_total_length(bytes);
    if let Some(total) = total {
        assert!(total <= MAX_EMRTD_FILE_BYTES);
    }
    if let (Some(total), Ok(record)) = (total, BerTlvAny::parse(bytes)) {
        assert_eq!(total, record.size());
    }
});
