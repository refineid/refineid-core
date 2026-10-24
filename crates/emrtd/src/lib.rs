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

//! ICAO 9303 eMRTD application file reading and data parsing for FINEID cards.
//!
//! The operations layer on any [`refineid_apdu::CardTransport`], typically
//! a secure-messaging transport after establishing a PACE secure channel with
//! the Card Access Number (CAN).

pub mod applet;
pub mod error;
pub mod inventory;
pub mod mrz;
pub mod ops;
pub mod portrait;
pub mod reader;
pub mod sfi;

pub use applet::{EMRTD_AID_LEN, EMRTD_APPLET_AID, select_emrtd_application};
pub use error::EmrtdError;
pub use inventory::DataGroupInventory;
pub use mrz::ParsedMrzTd1;
pub use ops::{EmrtdCardProfile, EmrtdOps};
pub use portrait::{CardFaceImage, ImageFormat, parse_card_face_image};
pub use reader::{decode_outer_total_length, read_emrtd_file};
pub use sfi::{SFI_EF_COM, SFI_EF_DG1, SFI_EF_DG2, SFI_EF_DG7, Sfi};
