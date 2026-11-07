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

//! ATR parsing of arbitrary bytes: every parse returns, an accepted ATR
//! re-emits exactly the bytes it was parsed from, and the re-emitted
//! bytes parse to the same value.

#![no_main]

use refineid_atr::Atr;

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let Ok(atr) = Atr::new(bytes) else {
        return;
    };
    let wire = atr.to_wire_bytes();
    assert_eq!(wire, bytes);
    assert_eq!(Atr::new(&wire).as_ref(), Ok(&atr));
    assert_eq!(atr.tck().is_some(), atr.supports_non_t0_protocol());
    let historical = atr.historical_bytes();
    assert_eq!(
        historical.len(),
        usize::from(atr.t0().historical_byte_count())
    );
    for object in historical.data_objects() {
        let _ = format!("{object:?}");
    }
    for group in atr.interface_groups() {
        let _ = format!("{group:?}");
    }
    let _ = format!("{atr}");
});
