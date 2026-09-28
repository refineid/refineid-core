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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! What kind of device a slot is, decided where that fact is known.
//!
//! A slot is either a physical PC/SC reader this computer drives over
//! USB, or a paired mobile RAPP reader whose credential is verified on
//! the device. The distinction governs PIN1 handling, login, and sign
//! routing, so it is carried as a type rather than recovered from a
//! reader name: a reader name is a string the reader's own driver
//! reports, and the driver is a USB device that chose it.
//!
//! Two trust origins, two constructors. A [`SlotKind::Local`] is
//! admitted at the PC/SC enumeration border and can only ever be a
//! reader this computer drives, whatever it calls itself. A
//! [`SlotKind::Remote`] is admitted at the vault border from a paired
//! RAPP record and carries a validated [`RemoteSlotId`], so holding one
//! is proof the pairing was established rather than claimed.

use alloc::string::{String, ToString};

use refineid_pcsc::ReaderId;

/// Byte length of the pair identifier that names a remote reader.
///
/// RAPP v26.9.28 section 13.1 derives `pair_id` as the first 16 bytes
/// of `SHA-512("RAPP-pair-id-v1" || h)`. This crate states the length
/// locally rather than depending on `refineid-rapp`: the PKCS#11 module
/// needs the pair identifier only as a vault key, and taking a
/// dependency on the RAPP protocol crate to read its own key length
/// would couple the module to a wire format it never parses.
pub const PAIR_ID_SIZE: usize = 16;

/// Hex-encoded characters a [`RemoteSlotId`] renders as: two per byte.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "read by RemoteSlotId::parse, which only the vault producer can reach"
    )
)]
const PAIR_ID_HEX_SIZE: usize = PAIR_ID_SIZE * 2;

/// Prefix a remote reader's display name carries, so a paired phone is
/// distinguishable from a USB reader in a slot list.
const REMOTE_DISPLAY_PREFIX: &str = "RefineID Remote ";

/// Why a candidate pair identifier is not a [`RemoteSlotId`].
///
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reported by RemoteSlotId::parse, which only the vault producer can reach"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSlotIdError {
    /// The candidate is not a whole number of hex-encoded bytes.
    NotHex,
    /// The candidate decodes to a different number of bytes than a
    /// RAPP pair identifier.
    WrongLength,
}

impl core::fmt::Display for RemoteSlotIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotHex => f.write_str("pair identifier is not hex"),
            Self::WrongLength => f.write_str("pair identifier is not a RAPP pair id length"),
        }
    }
}

/// The pair identifier of one paired remote RAPP reader.
///
/// The predicate -- a hex encoding of exactly [`PAIR_ID_SIZE`] bytes --
/// is checked once, here, so that every later holder of the value may
/// read it, use it as a vault key, and render it back to hex without
/// re-checking. The hex form is regenerated from the bytes rather than
/// kept beside them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSlotId {
    bytes: [u8; PAIR_ID_SIZE],
}

impl RemoteSlotId {
    /// Validates a hex-encoded pair identifier from the pairing record.
    ///
    /// # Errors
    ///
    /// [`RemoteSlotIdError::NotHex`] when a character outside `[0-9a-f]`
    /// appears, [`RemoteSlotIdError::WrongLength`] when the decoded
    /// length is not [`PAIR_ID_SIZE`].
    ///
    /// [`RemoteSlotIdError`]: crate::slot_kind::RemoteSlotIdError
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the vault producer is the only caller that may admit a pairing"
        )
    )]
    pub fn parse(hex: &str) -> Result<Self, RemoteSlotIdError> {
        if hex.len() != PAIR_ID_HEX_SIZE || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(if hex.len() != PAIR_ID_HEX_SIZE {
                RemoteSlotIdError::WrongLength
            } else {
                RemoteSlotIdError::NotHex
            });
        }
        let decoded = hex::decode(hex).map_err(|_| RemoteSlotIdError::NotHex)?;
        let mut bytes = [0_u8; PAIR_ID_SIZE];
        bytes.copy_from_slice(&decoded);
        Ok(Self { bytes })
    }

    /// The pair identifier's bytes.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the vault producer is the only reader of the pair id bytes"
        )
    )]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PAIR_ID_SIZE] {
        &self.bytes
    }

    /// The pair identifier re-encoded as lower-case hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.bytes)
    }
}

/// The device a slot is bound to, as decided at its border.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotKind {
    /// A physical PC/SC reader, named by the reader's own driver.
    Local {
        /// The PC/SC reader name used to open the card.
        reader: ReaderId,
    },
    /// A paired mobile RAPP reader; the credential is verified on the
    /// device, so this computer never holds a PIN1.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the vault producer may mint a Remote slot, so no reader name can impersonate one"
        )
    )]
    Remote {
        /// The vault key naming the pairing this reader is trusted through.
        pair_id: RemoteSlotId,
    },
}

impl SlotKind {
    /// Whether this slot is a paired remote reader rather than a USB one.
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        matches!(self, Self::Remote { .. })
    }

    /// The PC/SC reader to open, when this slot is a local reader.
    #[must_use]
    pub const fn local_reader(&self) -> Option<&ReaderId> {
        match self {
            Self::Local { reader } => Some(reader),
            Self::Remote { .. } => None,
        }
    }

    /// The pairing a remote slot is trusted through, when it is remote.
    #[must_use]
    pub const fn remote_pair_id(&self) -> Option<&RemoteSlotId> {
        match self {
            Self::Local { .. } => None,
            Self::Remote { pair_id } => Some(pair_id),
        }
    }

    /// A stable key for process-lifetime state that must not outlive
    /// the device it describes, so a local reader and a paired phone
    /// can never share an entry.
    #[must_use]
    pub fn cache_key(&self) -> String {
        match self {
            Self::Local { reader } => reader.as_str().to_string(),
            Self::Remote { pair_id } => pair_id.to_hex(),
        }
    }

    /// The text a caller sees for this slot.
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::Local { reader } => reader.as_str().to_string(),
            Self::Remote { pair_id } => {
                let mut name = String::from(REMOTE_DISPLAY_PREFIX);
                name.push_str(&pair_id.to_hex());
                name
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PAIR_ID_SIZE, RemoteSlotId, RemoteSlotIdError, SlotKind};
    use alloc::string::ToString;
    use refineid_pcsc::ReaderId;

    /// A valid pair identifier as the hex a pairing record carries.
    fn valid_hex() -> String {
        hex::encode([0xA5_u8; PAIR_ID_SIZE])
    }

    #[test]
    fn valid_pair_id_round_trips() {
        let hex = valid_hex();
        let id = RemoteSlotId::parse(&hex).expect("valid pair id");
        assert_eq!(id.to_hex(), hex);
        assert_eq!(id.as_bytes().len(), PAIR_ID_SIZE);
    }

    #[test]
    fn wrong_length_is_refused() {
        let short = hex::encode([0xA5_u8; PAIR_ID_SIZE - 1]);
        assert_eq!(
            RemoteSlotId::parse(&short),
            Err(RemoteSlotIdError::WrongLength)
        );
        let long = hex::encode([0xA5_u8; PAIR_ID_SIZE + 1]);
        assert_eq!(
            RemoteSlotId::parse(&long),
            Err(RemoteSlotIdError::WrongLength)
        );
    }

    #[test]
    fn non_hex_is_refused() {
        let mut hex = valid_hex();
        hex.replace_range(0..1, "z");
        assert_eq!(RemoteSlotId::parse(&hex), Err(RemoteSlotIdError::NotHex));
    }

    #[test]
    fn a_local_reader_claiming_a_remote_name_stays_local() {
        // A USB device chooses the string its driver reports, so a
        // reader naming itself after a pairing proves nothing about
        // how its credential is verified.
        let kind = SlotKind::Local {
            reader: ReaderId::new("rapp:0123456789abcdef".to_string()),
        };
        assert!(!kind.is_remote());
        assert!(kind.remote_pair_id().is_none());
        assert!(kind.local_reader().is_some());
    }

    #[test]
    fn a_local_and_a_remote_slot_never_share_a_cache_key() {
        let pair_id = RemoteSlotId::parse(&valid_hex()).expect("valid pair id");
        let local = SlotKind::Local {
            reader: ReaderId::new("Generic USB Reader".to_string()),
        };
        let remote = SlotKind::Remote { pair_id };
        assert_ne!(local.cache_key(), remote.cache_key());
        assert_ne!(local.display_name(), remote.display_name());
    }

    #[test]
    fn remote_display_name_carries_the_pair_id() {
        let hex = valid_hex();
        let kind = SlotKind::Remote {
            pair_id: RemoteSlotId::parse(&hex).expect("valid pair id"),
        };
        assert!(kind.display_name().ends_with(&hex));
        assert!(!kind.display_name().starts_with("rapp:"));
    }

    #[test]
    fn error_display_names_the_fault() {
        assert_eq!(
            RemoteSlotIdError::NotHex.to_string(),
            "pair identifier is not hex"
        );
        assert_eq!(
            RemoteSlotIdError::WrongLength.to_string(),
            "pair identifier is not a RAPP pair id length"
        );
    }

    #[test]
    fn parse_accepts_only_the_specified_shape() {
        assert!(RemoteSlotId::parse("").is_err());
        // Either hex case may arrive from a pairing record; the value
        // renders back as lower-case, so the two spellings cannot
        // become two different pairings.
        let upper = RemoteSlotId::parse(&"A5".repeat(PAIR_ID_SIZE)).expect("upper-case hex");
        let lower = RemoteSlotId::parse(&"a5".repeat(PAIR_ID_SIZE)).expect("lower-case hex");
        assert_eq!(upper, lower);
        assert_eq!(upper.to_hex(), "a5".repeat(PAIR_ID_SIZE));
        assert!(RemoteSlotId::parse(&"a5".repeat(PAIR_ID_SIZE)).is_ok());
        assert!(RemoteSlotId::parse("zz").is_err());
    }
}
