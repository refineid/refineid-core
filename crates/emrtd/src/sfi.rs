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

//! Short File Identifier (SFI) definitions for ICAO 9303 elementary files.

const SFI_BIT_MASK: u8 = 0x1F;
const SFI_READ_P1_FLAG: u8 = 0x80;

const RAW_SFI_COM: u8 = 0x1E;
const RAW_SFI_DG1: u8 = 0x01;
const RAW_SFI_DG2: u8 = 0x02;
const RAW_SFI_DG7: u8 = 0x07;

/// Short File Identifier (5-bit value, ISO 7816-4 section 7.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sfi(u8);

impl Sfi {
    /// Creates a new `Sfi` from a 5-bit raw value.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value & SFI_BIT_MASK)
    }

    /// The 5-bit numeric value.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The P1 parameter byte for an ISO 7816-4 `READ BINARY` command by SFI.
    #[must_use]
    pub const fn p1_for_read_binary(self) -> u8 {
        SFI_READ_P1_FLAG | self.0
    }
}

/// EF.COM: Common data and list of available data groups.
pub const SFI_EF_COM: Sfi = Sfi::new(RAW_SFI_COM);

/// EF.DG1: Machine Readable Zone (MRZ) data.
pub const SFI_EF_DG1: Sfi = Sfi::new(RAW_SFI_DG1);

/// EF.DG2: Biometric template for facial photograph.
pub const SFI_EF_DG2: Sfi = Sfi::new(RAW_SFI_DG2);

/// EF.DG7: Displayed signature or usual mark.
pub const SFI_EF_DG7: Sfi = Sfi::new(RAW_SFI_DG7);

#[cfg(test)]
mod tests {
    use super::{SFI_EF_COM, SFI_EF_DG1, SFI_EF_DG2, SFI_EF_DG7, Sfi};

    const FULL_MASK_INPUT: u8 = 0xFF;
    const FULL_MASK_EXPECTED: u8 = 0x1F;
    const DG2_RAW: u8 = 0x02;

    const EXPECTED_P1_DG1: u8 = 0x81;
    const EXPECTED_P1_DG2: u8 = 0x82;
    const EXPECTED_P1_DG7: u8 = 0x87;
    const EXPECTED_P1_COM: u8 = 0x9E;

    #[test]
    fn sfi_masks_to_five_bits() {
        assert_eq!(Sfi::new(FULL_MASK_INPUT).raw(), FULL_MASK_EXPECTED);
        assert_eq!(Sfi::new(DG2_RAW).raw(), DG2_RAW);
    }

    #[test]
    fn sfi_p1_sets_highest_bit() {
        assert_eq!(SFI_EF_DG1.p1_for_read_binary(), EXPECTED_P1_DG1);
        assert_eq!(SFI_EF_DG2.p1_for_read_binary(), EXPECTED_P1_DG2);
        assert_eq!(SFI_EF_DG7.p1_for_read_binary(), EXPECTED_P1_DG7);
        assert_eq!(SFI_EF_COM.p1_for_read_binary(), EXPECTED_P1_COM);
    }
}
