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

//! PKCS#15 borders: EF.TokenInfo and EF.AOD contents of arbitrary bytes
//! parse or refuse with a typed error, and every password object an
//! accepted EF.AOD yields satisfies its length-range predicate.

#![no_main]

use refineid_pkcs15::{
    AuthenticationObjects, TokenInfo, derive_printed_serial, render_token_serial,
};

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    if let Ok(token_info) = TokenInfo::parse(bytes) {
        let _ = (
            token_info.version(),
            token_info.manufacturer_id(),
            token_info.label(),
        );
        if let Some(serial) = token_info.serial_number_hex() {
            let rendered = render_token_serial(serial.clone());
            let _ = derive_printed_serial(serial);
            let _ = derive_printed_serial(&rendered);
        }
    }
    if let Ok(objects) = AuthenticationObjects::parse(bytes) {
        for password in objects.passwords() {
            let lengths = password.lengths();
            assert!(lengths.min() >= 1);
            assert!(lengths.min() <= lengths.max());
            assert!(lengths.contains(lengths.min()));
            assert!(lengths.contains(lengths.max()));
            assert_eq!(lengths.intersection(lengths), Some(lengths));
        }
    }
});
