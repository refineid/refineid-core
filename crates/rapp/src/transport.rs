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

use std::collections::BTreeMap;

use super::{MAX_FRAME_SIZE, WireValue};

/// Invalid bounded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// A transport attempted to allocate or deliver an oversized frame.
    Oversized {
        /// Received byte count.
        got: usize,
        /// Protocol maximum.
        maximum: usize,
    },
}

/// One bounded RAPP transport frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFrame(Vec<u8>);

impl BinaryFrame {
    /// Validate and take ownership of frame bytes.
    ///
    /// # Errors
    /// [`FrameError::Oversized`] when the bytes exceed the frame limit.
    pub fn reconstruct(bytes: Vec<u8>) -> Result<Self, FrameError> {
        if bytes.len() > MAX_FRAME_SIZE {
            return Err(FrameError::Oversized {
                got: bytes.len(),
                maximum: MAX_FRAME_SIZE,
            });
        }
        Ok(Self(bytes))
    }

    /// Borrow frame bytes for one transport or cryptographic operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the frame into its allocation.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Registered transport profile name of the BLE direct proximity profile.
pub const BLE_PROFILE: &str = "fi.refineid.rapp.ble.v1";
/// Registered candidate identifier of the BLE profile.
pub const BLE_CANDIDATE_ID: &str = "ble-direct-1";
/// Domain string opening every BLE routing preamble.
const BLE_PREAMBLE_DOMAIN: &str = "RAPP-ble-v1";
/// Domain string opening every stream routing preamble.
const STREAM_PREAMBLE_DOMAIN: &str = "RAPP-stream-v1";
/// 128-bit RAPP service UUID the BLE offer entry carries.
pub const BLE_SERVICE_UUID: &str = "7E39FD01-A6B5-4D78-9E11-37E28E9545F1";
/// Offer-entry parameter key naming the BLE service UUID.
const BLE_SERVICE_UUID_PARAMETER: &str = "service_uuid";
/// Registered candidate identifier of the stream profile.
pub const STREAM_CANDIDATE_ID: &str = "stream-1";

/// A registered transport profile (RAPP v26.10.10 §2.2).
///
/// Each profile fixes its candidate identifier and the exact offer-entry
/// parameters, so a valid offer entry is fully determined by its profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportProfile {
    /// `fi.refineid.rapp.ble.v1`.
    Ble,
    /// `fi.refineid.stream.v1`.
    Stream,
}

impl TransportProfile {
    /// Registered profile name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ble => BLE_PROFILE,
            Self::Stream => super::STREAM_PROFILE,
        }
    }

    /// Domain string opening this profile's routing preamble (§2.2).
    #[must_use]
    pub const fn preamble_domain(self) -> &'static str {
        match self {
            Self::Ble => BLE_PREAMBLE_DOMAIN,
            Self::Stream => STREAM_PREAMBLE_DOMAIN,
        }
    }

    /// Registered candidate identifier.
    #[must_use]
    pub const fn candidate_id(self) -> &'static str {
        match self {
            Self::Ble => BLE_CANDIDATE_ID,
            Self::Stream => STREAM_CANDIDATE_ID,
        }
    }

    /// Parse a registered profile name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            BLE_PROFILE => Some(Self::Ble),
            super::STREAM_PROFILE => Some(Self::Stream),
            _ => None,
        }
    }

    /// The exact offer entry this profile contributes to `pairing-offer`.
    #[must_use]
    pub fn offer_entry(self) -> TransportCandidate {
        let mut parameters = BTreeMap::new();
        if self == Self::Ble {
            parameters.insert(
                BLE_SERVICE_UUID_PARAMETER.to_owned(),
                WireValue::Text(BLE_SERVICE_UUID.to_owned()),
            );
        }
        TransportCandidate {
            profile: self.name().to_owned(),
            candidate_id: self.candidate_id().to_owned(),
            parameters,
        }
    }
}

/// Transport candidate advertised in a pairing offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportCandidate {
    /// Registered transport profile.
    pub profile: String,
    /// Candidate identifier echoed after authentication.
    pub candidate_id: String,
    /// Profile-specific public parameters included in deterministic CBOR.
    pub parameters: BTreeMap<String, WireValue>,
}

/// Reliable ordered binary-frame channel required by RAPP Core.
///
/// Transport authentication is never treated as RAPP identity. Every
/// implementation still runs the required Noise handshake over this channel.
pub trait FrameTransport {
    /// Adapter-specific failure type. It must not contain credential values.
    type Error;

    /// Candidate identifier known to both endpoints after establishment.
    fn candidate_id(&self) -> &str;

    /// Send exactly one bounded frame.
    ///
    /// # Errors
    /// The adapter-specific transport failure.
    fn send(&mut self, frame: BinaryFrame) -> Result<(), Self::Error>;

    /// Receive exactly one bounded frame, or `None` for EOF.
    ///
    /// # Errors
    /// The adapter-specific transport failure.
    fn receive(&mut self) -> Result<Option<BinaryFrame>, Self::Error>;

    /// Close and cancel pending transport work.
    ///
    /// # Errors
    /// The adapter-specific transport failure.
    fn close(&mut self) -> Result<(), Self::Error>;
}
