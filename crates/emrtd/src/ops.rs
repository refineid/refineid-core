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

//! Extension trait providing high-level eMRTD operations on any [`CardTransport`].

use refineid_apdu::CardTransport;

use crate::applet::select_emrtd_application;
use crate::error::EmrtdError;
use crate::inventory::DataGroupInventory;
use crate::mrz::ParsedMrzTd1;
use crate::portrait::{CardFaceImage, parse_card_face_image};
use crate::reader::read_emrtd_file;
use crate::sfi::{SFI_EF_COM, SFI_EF_DG1, SFI_EF_DG2};

/// High-level operations for reading ICAO 9303 eMRTD applications.
pub trait EmrtdOps: CardTransport {
    /// Selects the eMRTD application (`A0 00 00 02 47 10 01`).
    ///
    /// # Errors
    ///
    /// Returns [`EmrtdError`] if the transport fails or selection is refused.
    fn select_emrtd_application(&mut self) -> Result<(), EmrtdError<Self::Error>> {
        select_emrtd_application(self)
    }

    /// Reads EF.COM and returns the data group inventory.
    ///
    /// # Errors
    ///
    /// Returns [`EmrtdError`] if file reading fails.
    fn read_data_group_inventory(&mut self) -> Result<DataGroupInventory, EmrtdError<Self::Error>> {
        let bytes = read_emrtd_file(self, SFI_EF_COM)?;
        DataGroupInventory::parse(&bytes).ok_or(EmrtdError::MalformedData)
    }

    /// Reads EF.DG2 and parses the validated cardholder facial portrait.
    ///
    /// # Errors
    ///
    /// Returns [`EmrtdError`] if file reading fails.
    fn read_face_image(&mut self) -> Result<Option<CardFaceImage>, EmrtdError<Self::Error>> {
        let bytes = read_emrtd_file(self, SFI_EF_DG2)?;
        Ok(parse_card_face_image(&bytes))
    }

    /// Reads EF.DG1 and parses TD1 MRZ information.
    ///
    /// # Errors
    ///
    /// Returns [`EmrtdError`] if file reading fails.
    fn read_mrz_td1(&mut self) -> Result<Option<ParsedMrzTd1>, EmrtdError<Self::Error>> {
        let bytes = read_emrtd_file(self, SFI_EF_DG1)?;
        Ok(ParsedMrzTd1::parse(&bytes))
    }

    /// Selects the eMRTD application, reads the identification and biometric files
    /// (EF.DG1 and EF.DG2), and returns an [`EmrtdCardProfile`]. A file that fails
    /// to read or parse leaves its field `None`.
    ///
    /// # Errors
    ///
    /// Returns [`EmrtdError`] if the transport fails or application selection is refused.
    fn read_card_emrtd_profile(&mut self) -> Result<EmrtdCardProfile, EmrtdError<Self::Error>> {
        self.select_emrtd_application()?;
        let document_number = self
            .read_mrz_td1()
            .ok()
            .flatten()
            .map(|mrz| mrz.document_number);
        let face_image = self.read_face_image().ok().flatten();
        Ok(EmrtdCardProfile {
            document_number,
            face_image,
        })
    }
}

/// A high-level summary of the travel document files read from the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmrtdCardProfile {
    /// Document number parsed from EF.DG1.
    pub document_number: Option<String>,
    /// Parsed cardholder facial image from EF.DG2.
    pub face_image: Option<CardFaceImage>,
}

impl<T: CardTransport + ?Sized> EmrtdOps for T {}
