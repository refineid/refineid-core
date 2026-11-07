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

//! EF.CardAccess border: arbitrary bytes parse to the PACE suites the
//! crate implements or to a typed error, and the suite the handshake
//! would run is one of those listed.

#![no_main]

use refineid_pace::{CardAccess, UnvalidatedCardAccess};

libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    let Ok(card_access) = CardAccess::parse(UnvalidatedCardAccess::from_card_bytes(bytes.to_vec()))
    else {
        return;
    };
    for info in card_access.pace_infos() {
        let _ = (info.mapping(), info.domain(), info.domain().parameter_id());
    }
    if let Some(suite) = card_access.generic_mapping_suite() {
        assert!(card_access.pace_infos().contains(&suite));
    }
});
