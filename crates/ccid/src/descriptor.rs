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

//! USB CCID Class Functional Descriptor parsing.
//!
//! Defined by USB-IF Smart Card CCID Specification Revision 1.1 §5.1.
//! Every CCID interface exposes a 54-byte functional descriptor specifying
//! its supported exchange level, message size limits, protocols, and feature flags.

use crate::error::CcidError;

/// USB descriptor header length (bLength, bDescriptorType).
pub const USB_DESCRIPTOR_HEADER_LENGTH: usize = 2;
/// Descriptor type offset in USB descriptor header.
pub const DESCRIPTOR_TYPE_OFFSET: usize = 1;

/// Standard USB Interface Descriptor Type (0x04).
pub const USB_INTERFACE_DESCRIPTOR_TYPE: u8 = 0x04;
/// Standard USB Interface Descriptor Length (9 bytes).
pub const USB_INTERFACE_DESCRIPTOR_LENGTH: usize = 9;
/// Interface number offset within interface descriptor.
pub const INTERFACE_NUMBER_OFFSET: usize = 2;
/// Alternate setting offset within interface descriptor.
pub const ALTERNATE_SETTING_OFFSET: usize = 3;
/// Interface class offset within interface descriptor.
pub const INTERFACE_CLASS_OFFSET: usize = 5;
/// USB Smart Card (CCID) Interface Class (0x0B).
pub const CCID_INTERFACE_CLASS: u8 = 0x0B;

/// CCID Functional Descriptor Type (0x21).
pub const CCID_FUNCTIONAL_DESCRIPTOR_TYPE: u8 = 0x21;
/// CCID Functional Descriptor Length (54 bytes).
pub const CCID_FUNCTIONAL_DESCRIPTOR_LENGTH: usize = 54;

/// Byte offset of `dwProtocols` in CCID functional descriptor.
pub const PROTOCOLS_OFFSET: usize = 6;
/// Byte offset of `dwFeatures` in CCID functional descriptor.
pub const FEATURES_OFFSET: usize = 40;
/// Byte offset of `dwMaxCCIDMessageLength` in CCID functional descriptor.
pub const MAXIMUM_MESSAGE_LENGTH_OFFSET: usize = 44;
/// Byte offset of `bMaxSlotIndex` in CCID functional descriptor.
pub const MAX_SLOT_INDEX_OFFSET: usize = 4;

/// Feature flag: Automatic parameter configuration based on ATR.
pub const AUTOMATIC_PARAMETER_CONFIGURATION: u32 = 0x0000_0002;
/// Feature flag: Automatic activation of ICC on connect.
pub const AUTOMATIC_ACTIVATION: u32 = 0x0000_0004;
/// Feature flag: Automatic voltage selection.
pub const AUTOMATIC_VOLTAGE_SELECTION: u32 = 0x0000_0008;
/// Feature flag: Automatic parameter negotiation (PPS).
pub const AUTOMATIC_PARAMETER_NEGOTIATION: u32 = 0x0000_0040;
/// Feature flag: Automatic PPS performed by reader.
pub const AUTOMATIC_PPS: u32 = 0x0000_0080;

/// Mask for CCID exchange level bits in `dwFeatures`.
pub const EXCHANGE_LEVEL_MASK: u32 = 0x0007_0000;
/// Character level exchange (unsupported).
pub const CHARACTER_EXCHANGE: u32 = 0x0000_0000;
/// TPDU level exchange.
pub const TPDU_EXCHANGE: u32 = 0x0001_0000;
/// Short APDU level exchange.
pub const SHORT_APDU_EXCHANGE: u32 = 0x0002_0000;
/// Short and extended APDU level exchange.
pub const SHORT_AND_EXTENDED_APDU_EXCHANGE: u32 = 0x0004_0000;

/// Maximum ISO 7816-3 T=0 TPDU command payload length.
pub const MAXIMUM_T0_TPDU_LENGTH: usize = 260;
/// Minimum message length for T=0 TPDU exchange (10-byte header + 260 bytes).
pub const MINIMUM_T0_TPDU_MESSAGE_LENGTH: usize = 10 + MAXIMUM_T0_TPDU_LENGTH;
/// Maximum ISO 7816-4 short APDU command payload length.
pub const MAXIMUM_SHORT_APDU_LENGTH: usize = 261;
/// Minimum message length for Short APDU exchange (10-byte header + 261 bytes).
pub const MINIMUM_SHORT_APDU_MESSAGE_LENGTH: usize = 10 + MAXIMUM_SHORT_APDU_LENGTH;
/// Maximum ISO 7816-4 extended APDU command payload length (65544 bytes).
pub const MAXIMUM_CCID_COMMAND_PAYLOAD_LENGTH: usize = 65_544;
/// Absolute maximum CCID message length including 10-byte header (65554 bytes).
pub const MAXIMUM_CCID_MESSAGE_LENGTH: usize = 10 + MAXIMUM_CCID_COMMAND_PAYLOAD_LENGTH;

/// CCID command / exchange level supported by the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcidExchangeLevel {
    /// TPDU level: reader expects raw T=0/T=1 TPDUs.
    Tpdu,
    /// Short APDU level: reader accepts APDUs up to 261 bytes and handles TPDU framing.
    ShortApdu,
    /// Short and Extended APDU level: reader accepts APDUs up to 65,544 bytes.
    ShortAndExtendedApdu,
}

/// Parsed, validated USB CCID functional descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcidFunctionalDescriptor {
    /// Supported APDU/TPDU exchange level.
    pub exchange_level: CcidExchangeLevel,
    /// Maximum CCID message length in bytes declared by reader.
    pub maximum_message_length: usize,
    /// Maximum slot index supported (slot count = max_slot_index + 1).
    pub max_slot_index: u8,
    /// Feature flags bitmask (`dwFeatures`).
    pub features: u32,
    /// Supported protocols bitmask (`dwProtocols`). Bit 0: T=0, Bit 1: T=1.
    pub protocols: u32,
}

impl CcidFunctionalDescriptor {
    /// Returns the maximum allowed payload length in bytes (excluding 10-byte CCID header).
    #[must_use]
    pub const fn maximum_payload_length(&self) -> usize {
        self.maximum_message_length.saturating_sub(10)
    }

    /// Returns the maximum transfer block length supported for APDU/TPDU packets.
    #[must_use]
    pub fn maximum_transfer_block_length(&self) -> usize {
        let max_payload = self.maximum_payload_length();
        match self.exchange_level {
            CcidExchangeLevel::Tpdu => max_payload.min(MAXIMUM_T0_TPDU_LENGTH),
            CcidExchangeLevel::ShortApdu => max_payload.min(MAXIMUM_SHORT_APDU_LENGTH),
            CcidExchangeLevel::ShortAndExtendedApdu => max_payload,
        }
    }

    /// Whether reader advertises T=0 support in `dwProtocols`.
    #[must_use]
    pub const fn supports_t0(&self) -> bool {
        (self.protocols & 0x01) != 0
    }

    /// Whether reader advertises T=1 support in `dwProtocols`.
    #[must_use]
    pub const fn supports_t1(&self) -> bool {
        (self.protocols & 0x02) != 0
    }

    /// Whether automatic parameter configuration is enabled in `dwFeatures`.
    #[must_use]
    pub const fn automatic_parameter_configuration(&self) -> bool {
        (self.features & AUTOMATIC_PARAMETER_CONFIGURATION) != 0
    }

    /// Parse a 54-byte CCID functional descriptor directly.
    ///
    /// # Errors
    pub fn parse_functional_descriptor(bytes: &[u8]) -> Result<Self, CcidError> {
        if bytes.len() < CCID_FUNCTIONAL_DESCRIPTOR_LENGTH {
            return Err(CcidError::CcidDescriptorTooShort);
        }
        if bytes[DESCRIPTOR_TYPE_OFFSET] != CCID_FUNCTIONAL_DESCRIPTOR_TYPE {
            return Err(CcidError::InvalidCcidDescriptor(
                "invalid CCID functional descriptor type".into(),
            ));
        }

        let max_slot_index = bytes[MAX_SLOT_INDEX_OFFSET];

        let protocols = u32::from_le_bytes([
            bytes[PROTOCOLS_OFFSET],
            bytes[PROTOCOLS_OFFSET + 1],
            bytes[PROTOCOLS_OFFSET + 2],
            bytes[PROTOCOLS_OFFSET + 3],
        ]);

        let features = u32::from_le_bytes([
            bytes[FEATURES_OFFSET],
            bytes[FEATURES_OFFSET + 1],
            bytes[FEATURES_OFFSET + 2],
            bytes[FEATURES_OFFSET + 3],
        ]);

        let exchange_level = match features & EXCHANGE_LEVEL_MASK {
            TPDU_EXCHANGE => CcidExchangeLevel::Tpdu,
            SHORT_APDU_EXCHANGE => CcidExchangeLevel::ShortApdu,
            SHORT_AND_EXTENDED_APDU_EXCHANGE => CcidExchangeLevel::ShortAndExtendedApdu,
            CHARACTER_EXCHANGE => return Err(CcidError::UnsupportedExchangeLevel),
            _ => return Err(CcidError::InvalidExchangeLevel),
        };

        let automatic_negotiation = (features & AUTOMATIC_PARAMETER_NEGOTIATION) != 0;
        let automatic_pps = (features & AUTOMATIC_PPS) != 0;
        if automatic_negotiation && automatic_pps {
            return Err(CcidError::InvalidApduConfiguration);
        }

        let declared_message_length = u32::from_le_bytes([
            bytes[MAXIMUM_MESSAGE_LENGTH_OFFSET],
            bytes[MAXIMUM_MESSAGE_LENGTH_OFFSET + 1],
            bytes[MAXIMUM_MESSAGE_LENGTH_OFFSET + 2],
            bytes[MAXIMUM_MESSAGE_LENGTH_OFFSET + 3],
        ]) as usize;

        if declared_message_length > MAXIMUM_CCID_MESSAGE_LENGTH {
            return Err(CcidError::MessageLengthOutOfRange);
        }

        let minimum_message_length = match exchange_level {
            CcidExchangeLevel::Tpdu => MINIMUM_T0_TPDU_MESSAGE_LENGTH,
            CcidExchangeLevel::ShortApdu | CcidExchangeLevel::ShortAndExtendedApdu => {
                MINIMUM_SHORT_APDU_MESSAGE_LENGTH
            }
        };

        if declared_message_length < minimum_message_length {
            return Err(CcidError::TransferMessageBoundTooSmall);
        }

        Ok(Self {
            exchange_level,
            maximum_message_length: declared_message_length,
            max_slot_index,
            features,
            protocols,
        })
    }

    /// Parse USB configuration descriptors to find the CCID functional descriptor
    /// matching the given target interface number and alternate setting.
    ///
    /// # Errors
    /// Returns `CcidError` if the descriptors are truncated or no matching CCID interface is found.
    pub fn parse_from_usb_descriptors(
        raw_descriptors: &[u8],
        interface_number: u8,
        alternate_setting: u8,
    ) -> Result<Self, CcidError> {
        let mut offset = 0;
        let mut is_target_interface = false;

        while offset < raw_descriptors.len() {
            let remaining = &raw_descriptors[offset..];
            if remaining.len() < USB_DESCRIPTOR_HEADER_LENGTH {
                return Err(CcidError::TruncatedDescriptorHeader);
            }

            let descriptor_length = remaining[0] as usize;
            if descriptor_length < USB_DESCRIPTOR_HEADER_LENGTH {
                return Err(CcidError::InvalidDescriptorLength);
            }
            if descriptor_length > remaining.len() {
                return Err(CcidError::TruncatedDescriptor);
            }

            let descriptor_type = remaining[DESCRIPTOR_TYPE_OFFSET];
            match descriptor_type {
                USB_INTERFACE_DESCRIPTOR_TYPE => {
                    if descriptor_length < USB_INTERFACE_DESCRIPTOR_LENGTH {
                        return Err(CcidError::InvalidInterfaceDescriptor);
                    }
                    let iface_num = remaining[INTERFACE_NUMBER_OFFSET];
                    let alt_setting = remaining[ALTERNATE_SETTING_OFFSET];
                    let iface_class = remaining[INTERFACE_CLASS_OFFSET];

                    is_target_interface = iface_num == interface_number
                        && alt_setting == alternate_setting
                        && iface_class == CCID_INTERFACE_CLASS;
                }
                CCID_FUNCTIONAL_DESCRIPTOR_TYPE if is_target_interface => {
                    return Self::parse_functional_descriptor(&remaining[..descriptor_length]);
                }
                _ => {}
            }

            offset += descriptor_length;
        }

        Err(CcidError::MissingCcidDescriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_ccid_descriptor(
        exchange_level_bits: u32,
        max_message_len: u32,
        protocols: u32,
        features_extra: u32,
        max_slot: u8,
    ) -> [u8; 54] {
        let mut d = [0_u8; 54];
        d[0] = 54; // bLength
        d[1] = CCID_FUNCTIONAL_DESCRIPTOR_TYPE; // 0x21
        d[2] = 0x10; // bcdCCID = 1.10
        d[3] = 0x01;
        d[4] = max_slot; // bMaxSlotIndex
        d[5] = 0x07; // bVoltageSupport (5V, 3V, 1.8V)
        d[6..10].copy_from_slice(&protocols.to_le_bytes()); // dwProtocols
        d[10..14].copy_from_slice(&4800_u32.to_le_bytes()); // dwDefaultClock
        d[14..18].copy_from_slice(&4800_u32.to_le_bytes()); // dwMaximumClock
        d[18] = 0; // bNumClockSupported
        d[19..23].copy_from_slice(&10752_u32.to_le_bytes()); // dwDataRate
        d[23..27].copy_from_slice(&344064_u32.to_le_bytes()); // dwMaxDataRate
        d[27] = 0; // bNumDataRatesSupported
        d[28..32].copy_from_slice(&254_u32.to_le_bytes()); // dwMaxIFSD
        d[32..36].copy_from_slice(&0_u32.to_le_bytes()); // dwSynchProtocols
        d[36..40].copy_from_slice(&0_u32.to_le_bytes()); // dwMechanical
        let features = exchange_level_bits | features_extra;
        d[40..44].copy_from_slice(&features.to_le_bytes()); // dwFeatures
        d[44..48].copy_from_slice(&max_message_len.to_le_bytes()); // dwMaxCCIDMessageLength
        d[48] = 0; // bClassGetResponse
        d[49] = 0; // bClassEnvelope
        d[50..52].copy_from_slice(&0_u16.to_le_bytes()); // wLcdLayout
        d[52] = 0; // bPINSupport
        d[53] = 1; // bMaxCCIDBusySlots
        d
    }

    #[test]
    fn parse_short_apdu_descriptor_acr39u() {
        // Short APDU level (0x00020000), max message 271 bytes, T=0 and T=1
        let bytes = build_test_ccid_descriptor(
            SHORT_APDU_EXCHANGE,
            271,
            0x0000_0003,
            AUTOMATIC_ACTIVATION | AUTOMATIC_VOLTAGE_SELECTION | AUTOMATIC_PPS,
            0,
        );
        let desc = CcidFunctionalDescriptor::parse_functional_descriptor(&bytes)
            .expect("valid short APDU descriptor");

        assert_eq!(desc.exchange_level, CcidExchangeLevel::ShortApdu);
        assert_eq!(desc.maximum_message_length, 271);
        assert_eq!(desc.maximum_payload_length(), 261);
        assert_eq!(desc.maximum_transfer_block_length(), 261);
        assert_eq!(desc.max_slot_index, 0);
        assert!(desc.supports_t0());
        assert!(desc.supports_t1());
    }

    #[test]
    fn parse_extended_apdu_descriptor_trust_reader() {
        // Extended APDU level (0x00040000), max message 65544 bytes
        let bytes = build_test_ccid_descriptor(
            SHORT_AND_EXTENDED_APDU_EXCHANGE,
            65544,
            0x0000_0003,
            AUTOMATIC_PARAMETER_CONFIGURATION | AUTOMATIC_ACTIVATION,
            0,
        );
        let desc = CcidFunctionalDescriptor::parse_functional_descriptor(&bytes)
            .expect("valid extended APDU descriptor");

        assert_eq!(desc.exchange_level, CcidExchangeLevel::ShortAndExtendedApdu);
        assert_eq!(desc.maximum_message_length, 65544);
        assert_eq!(desc.maximum_payload_length(), 65534);
        assert_eq!(desc.maximum_transfer_block_length(), 65534);
        assert!(desc.automatic_parameter_configuration());
    }

    #[test]
    fn parse_tpdu_descriptor() {
        let bytes = build_test_ccid_descriptor(TPDU_EXCHANGE, 270, 0x0000_0001, 0, 0);
        let desc = CcidFunctionalDescriptor::parse_functional_descriptor(&bytes)
            .expect("valid TPDU descriptor");

        assert_eq!(desc.exchange_level, CcidExchangeLevel::Tpdu);
        assert_eq!(desc.maximum_message_length, 270);
        assert_eq!(desc.maximum_payload_length(), 260);
        assert_eq!(desc.maximum_transfer_block_length(), 260);
        assert!(desc.supports_t0());
        assert!(!desc.supports_t1());
    }

    #[test]
    fn reject_too_short_descriptor() {
        let short = [0_u8; 53];
        assert_eq!(
            CcidFunctionalDescriptor::parse_functional_descriptor(&short),
            Err(CcidError::CcidDescriptorTooShort)
        );
    }

    #[test]
    fn reject_character_exchange_level() {
        let bytes = build_test_ccid_descriptor(CHARACTER_EXCHANGE, 300, 1, 0, 0);
        assert_eq!(
            CcidFunctionalDescriptor::parse_functional_descriptor(&bytes),
            Err(CcidError::UnsupportedExchangeLevel)
        );
    }

    #[test]
    fn reject_invalid_exchange_level_multiple_bits() {
        let invalid = TPDU_EXCHANGE | SHORT_APDU_EXCHANGE;
        let bytes = build_test_ccid_descriptor(invalid, 300, 1, 0, 0);
        assert_eq!(
            CcidFunctionalDescriptor::parse_functional_descriptor(&bytes),
            Err(CcidError::InvalidExchangeLevel)
        );
    }

    #[test]
    fn reject_conflicting_automatic_parameter_negotiation() {
        let conflict = AUTOMATIC_PARAMETER_NEGOTIATION | AUTOMATIC_PPS;
        let bytes = build_test_ccid_descriptor(SHORT_APDU_EXCHANGE, 300, 1, conflict, 0);
        assert_eq!(
            CcidFunctionalDescriptor::parse_functional_descriptor(&bytes),
            Err(CcidError::InvalidApduConfiguration)
        );
    }

    #[test]
    fn reject_excessive_message_length() {
        let bytes = build_test_ccid_descriptor(
            SHORT_AND_EXTENDED_APDU_EXCHANGE,
            MAXIMUM_CCID_MESSAGE_LENGTH as u32 + 1,
            1,
            0,
            0,
        );
        assert_eq!(
            CcidFunctionalDescriptor::parse_functional_descriptor(&bytes),
            Err(CcidError::MessageLengthOutOfRange)
        );
    }

    #[test]
    fn reject_message_length_too_small_for_exchange_level() {
        let bytes = build_test_ccid_descriptor(SHORT_APDU_EXCHANGE, 270, 1, 0, 0);
        assert_eq!(
            CcidFunctionalDescriptor::parse_functional_descriptor(&bytes),
            Err(CcidError::TransferMessageBoundTooSmall)
        );
    }

    #[test]
    fn parse_acr1581u_composite_multi_interface_descriptors() {
        // ACR1581U-CF layout:
        // Interface 0: Contactless PICC (bSlot = 0)
        // Interface 1: Contact ICC (bSlot = 0)
        // Interface 2: SAM (bSlot = 0)
        let mut usb_config = Vec::new();

        // 9-byte Configuration Descriptor
        usb_config.extend_from_slice(&[9, 0x02, 0x00, 0x00, 3, 1, 0, 0x80, 50]);

        // Interface 0: PICC
        usb_config.extend_from_slice(&[
            9,
            0x04,
            0x00,
            0x00,
            3,
            CCID_INTERFACE_CLASS,
            0x00,
            0x00,
            0x00,
        ]);
        let ccid0 = build_test_ccid_descriptor(SHORT_APDU_EXCHANGE, 271, 0x02, 0, 0);
        usb_config.extend_from_slice(&ccid0);

        // Interface 1: Contact ICC
        usb_config.extend_from_slice(&[
            9,
            0x04,
            0x01,
            0x00,
            3,
            CCID_INTERFACE_CLASS,
            0x00,
            0x00,
            0x00,
        ]);
        let ccid1 = build_test_ccid_descriptor(SHORT_AND_EXTENDED_APDU_EXCHANGE, 65544, 0x03, 0, 0);
        usb_config.extend_from_slice(&ccid1);

        // Interface 2: SAM
        usb_config.extend_from_slice(&[
            9,
            0x04,
            0x02,
            0x00,
            3,
            CCID_INTERFACE_CLASS,
            0x00,
            0x00,
            0x00,
        ]);
        let ccid2 = build_test_ccid_descriptor(TPDU_EXCHANGE, 270, 0x01, 0, 0);
        usb_config.extend_from_slice(&ccid2);

        // Parse target interface 1 (Contact slot)
        let iface1 = CcidFunctionalDescriptor::parse_from_usb_descriptors(&usb_config, 1, 0)
            .expect("found interface 1 descriptor");
        assert_eq!(
            iface1.exchange_level,
            CcidExchangeLevel::ShortAndExtendedApdu
        );
        assert_eq!(iface1.maximum_message_length, 65544);

        // Parse target interface 0 (Contactless PICC)
        let iface0 = CcidFunctionalDescriptor::parse_from_usb_descriptors(&usb_config, 0, 0)
            .expect("found interface 0 descriptor");
        assert_eq!(iface0.exchange_level, CcidExchangeLevel::ShortApdu);

        // Parse target interface 2 (SAM)
        let iface2 = CcidFunctionalDescriptor::parse_from_usb_descriptors(&usb_config, 2, 0)
            .expect("found interface 2 descriptor");
        assert_eq!(iface2.exchange_level, CcidExchangeLevel::Tpdu);

        // Non-existent interface 3
        assert_eq!(
            CcidFunctionalDescriptor::parse_from_usb_descriptors(&usb_config, 3, 0),
            Err(CcidError::MissingCcidDescriptor)
        );
    }
}
