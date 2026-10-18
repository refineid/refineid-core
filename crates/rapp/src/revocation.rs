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

//! Announced pairing revocation (RAPP v26.10.18 §4.6).
//!
//! An endpoint that forgets a pairing keeps, in place of the destroyed
//! private key, the pairing's revocation key `K_rev` and the time of the
//! revocation. For thirty days a custodian carries the revocation hint of
//! each pairing it revoked in the `revoked` attribute of its `mode=session`
//! record, padded to eight entries with random fillers, so that a requester
//! still holding the pairing learns that the phone forgot it. The hint is
//! keyed by the pairing's static agreement, which never crosses the wire,
//! and is bound to the advertised service instance name and the 15-minute
//! discovery epoch.

use core::fmt;
use std::collections::BTreeMap;

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use super::txt::{AnnouncementCandidate, most_recently_used};
use super::wire::{decode_deterministic_cbor, encode_deterministic_cbor};
use super::{
    DiscoveryRecord, InstanceName, PAIR_KEY_SIZE, PairId, PairRecord, WireValue, X25519_KEY_SIZE,
};

/// Byte length of one revocation hint.
pub const REVOCATION_HINT_SIZE: usize = super::txt::HINT_SIZE;

/// Entries in every `revoked=` value, hints and fillers together.
pub const REVOKED_ANNOUNCEMENT_ENTRIES: usize = 8;

/// Milliseconds per day.
const MILLISECONDS_PER_DAY: u64 = 86_400_000;

/// Days a revocation is announced after it happened.
const REVOCATION_ANNOUNCEMENT_DAYS: u64 = 30;

/// How long after a revocation the custodian announces it, in
/// milliseconds (RAPP v26.10.18 §4.6 item 4).
pub const REVOCATION_ANNOUNCEMENT_MS: u64 = REVOCATION_ANNOUNCEMENT_DAYS * MILLISECONDS_PER_DAY;

/// Format version of an encoded [`RevocationRetention`].
pub const REVOCATION_RETENTION_FORMAT_VERSION: u64 = 1;

/// HKDF-Expand info naming the revocation key.
const REVOCATION_KEY_INFO: &[u8] = b"RAPP-revocation-v1";

/// Why a revocation value could not be formed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationError {
    /// The static agreement is the identity point.
    DegenerateAgreement,
    /// The platform random source failed.
    RandomUnavailable,
}

impl fmt::Display for RevocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DegenerateAgreement => "static agreement is the identity point",
            Self::RandomUnavailable => "random source unavailable",
        })
    }
}

impl core::error::Error for RevocationError {}

/// One pairing's revocation key `K_rev`, equal on both endpoints.
pub struct RevocationKey(Zeroizing<[u8; PAIR_KEY_SIZE]>);

impl fmt::Debug for RevocationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RevocationKey([redacted])")
    }
}

impl RevocationKey {
    /// Derives the key of a stored pairing.
    ///
    /// # Errors
    /// [`RevocationError::DegenerateAgreement`] when the static agreement is
    /// the identity point.
    pub fn derive(record: &PairRecord) -> Result<Self, RevocationError> {
        Self::from_parts(
            record.pair_id(),
            record.local_static_private(),
            record.remote_static_public(),
        )
    }

    /// Derives `K_rev = HKDF-SHA-256(salt = pair_id, IKM = X25519(local
    /// static private, peer static public), info = "RAPP-revocation-v1",
    /// L = 32)`.
    ///
    /// # Errors
    /// [`RevocationError::DegenerateAgreement`] when the agreement is the
    /// identity point.
    pub fn from_parts(
        pair_id: PairId,
        local_static_private: &[u8; X25519_KEY_SIZE],
        remote_static_public: &[u8; X25519_KEY_SIZE],
    ) -> Result<Self, RevocationError> {
        let key = super::derive_pair_key(
            pair_id,
            local_static_private,
            remote_static_public,
            REVOCATION_KEY_INFO,
        )
        .map_err(|_| RevocationError::DegenerateAgreement)?;
        Ok(Self(key))
    }

    /// First 8 bytes of `HMAC-SHA-256(K_rev, len(instance) || instance ||
    /// epoch_be64)`, `len` one octet and `epoch` the discovery epoch.
    #[must_use]
    pub fn hint(&self, instance: &InstanceName, epoch: u64) -> [u8; REVOCATION_HINT_SIZE] {
        let name = instance.as_bytes();
        let length = u8::try_from(name.len()).expect("an instance portion is at most 63 octets");
        let digest = super::pair_key_mac(&self.0, &[&[length], name, &epoch.to_be_bytes()]);
        let mut hint = [0_u8; REVOCATION_HINT_SIZE];
        hint.copy_from_slice(&digest[..REVOCATION_HINT_SIZE]);
        hint
    }

    /// Whether the `revoked` entries of `record`, published on `instance`,
    /// carry this pairing's hint for `epoch` or an adjacent epoch, compared
    /// in constant time. A record without `revoked` matches nothing.
    #[must_use]
    pub fn matches(&self, record: &DiscoveryRecord, instance: &InstanceName, epoch: u64) -> bool {
        let Some(entries) = record.revoked() else {
            return false;
        };
        let mut matched = Choice::from(0);
        for candidate in [epoch.checked_sub(1), Some(epoch), epoch.checked_add(1)]
            .into_iter()
            .flatten()
        {
            let expected = self.hint(instance, candidate);
            for entry in entries {
                matched |= expected.ct_eq(entry);
            }
        }
        bool::from(matched)
    }
}

/// What an endpoint keeps of a pairing it revoked: the revocation key,
/// which names the pairing only to its former peer, and when the private
/// key was destroyed, in milliseconds since the Unix epoch.
pub struct RevocationRetention {
    pair_id: PairId,
    key: RevocationKey,
    revoked_at_ms: u64,
}

impl fmt::Debug for RevocationRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevocationRetention")
            .field("pair_id", &self.pair_id)
            .field("revoked_at_ms", &self.revoked_at_ms)
            .finish_non_exhaustive()
    }
}

impl RevocationRetention {
    /// Derives what to keep of `record` before its private key is
    /// destroyed at `revoked_at_ms`.
    ///
    /// # Errors
    /// [`RevocationError::DegenerateAgreement`] when the static agreement is
    /// the identity point; such a pairing is never announced.
    pub fn derive(record: &PairRecord, revoked_at_ms: u64) -> Result<Self, RevocationError> {
        Ok(Self {
            pair_id: record.pair_id(),
            key: RevocationKey::derive(record)?,
            revoked_at_ms,
        })
    }

    /// The revoked pair identifier.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.pair_id
    }

    /// Milliseconds since the Unix epoch at which the private key was
    /// destroyed.
    #[must_use]
    pub const fn revoked_at_ms(&self) -> u64 {
        self.revoked_at_ms
    }

    /// Whether the revocation is still announced at `now_ms`: thirty days
    /// have not passed since it, and it is not in the future.
    #[must_use]
    pub const fn announces_at(&self, now_ms: u64) -> bool {
        match now_ms.checked_sub(self.revoked_at_ms) {
            Some(age_ms) => age_ms < REVOCATION_ANNOUNCEMENT_MS,
            None => false,
        }
    }

    /// Whether the announcement window has run out at `now_ms`, so the
    /// retention can be destroyed (section 4.6 item 4). A `now_ms` before
    /// the revocation is not an expiry: the clock has merely not reached
    /// the revocation's own millisecond.
    #[must_use]
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        match now_ms.checked_sub(self.revoked_at_ms) {
            Some(age_ms) => age_ms >= REVOCATION_ANNOUNCEMENT_MS,
            None => false,
        }
    }

    /// The revocation hint for `instance` at `epoch`.
    #[must_use]
    pub fn hint(&self, instance: &InstanceName, epoch: u64) -> [u8; REVOCATION_HINT_SIZE] {
        self.key.hint(instance, epoch)
    }

    /// What the custodian could announce at `now_ms` for `instance` at
    /// `epoch`: the hint and revocation time of each retention still within
    /// its announcement window.
    #[must_use]
    pub fn candidates(
        retentions: &[Self],
        instance: &InstanceName,
        epoch: u64,
        now_ms: u64,
    ) -> Vec<AnnouncementCandidate> {
        retentions
            .iter()
            .filter(|retention| retention.announces_at(now_ms))
            .map(|retention| AnnouncementCandidate {
                hint: retention.hint(instance, epoch),
                last_used_ms: retention.revoked_at_ms,
            })
            .collect()
    }
}

/// Why a retention could not be decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationRetentionCodecError {
    /// The input is not deterministic CBOR of the expected shape.
    InvalidInput,
    /// Serialization failed.
    ProtocolFailure,
    /// The format version is unsupported.
    UnsupportedVersion,
}

impl fmt::Display for RevocationRetentionCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid revocation retention input",
            Self::ProtocolFailure => "failed to encode revocation retention",
            Self::UnsupportedVersion => "unsupported revocation retention format version",
        })
    }
}

impl core::error::Error for RevocationRetentionCodecError {}

/// Serializes a [`RevocationRetention`] to deterministic CBOR for the
/// platform's device-only storage; the key travels inside it.
///
/// # Errors
/// [`RevocationRetentionCodecError::ProtocolFailure`] if serialization
/// fails.
pub fn encode_revocation_retention(
    retention: &RevocationRetention,
) -> Result<Zeroizing<Vec<u8>>, RevocationRetentionCodecError> {
    let mut value = WireValue::Map(BTreeMap::from([
        (
            "format_version".to_owned(),
            WireValue::Unsigned(REVOCATION_RETENTION_FORMAT_VERSION),
        ),
        (
            "pair_id".to_owned(),
            WireValue::Bytes(retention.pair_id.as_bytes().to_vec()),
        ),
        (
            "revocation_key".to_owned(),
            WireValue::Bytes(retention.key.0.to_vec()),
        ),
        (
            "revoked_at_ms".to_owned(),
            WireValue::Unsigned(retention.revoked_at_ms),
        ),
    ]));
    let encoded = encode_deterministic_cbor(&value)
        .map(Zeroizing::new)
        .map_err(|_| RevocationRetentionCodecError::ProtocolFailure);
    // The wire value held the only unprotected copy of the key; it is
    // erased before the value is dropped.
    if let WireValue::Map(map) = &mut value
        && let Some(WireValue::Bytes(key)) = map.get_mut("revocation_key")
    {
        key.zeroize();
    }
    encoded
}

/// Deserializes a [`RevocationRetention`] from deterministic CBOR.
///
/// # Errors
/// [`RevocationRetentionCodecError`] on malformed CBOR, unexpected keys, or
/// an unsupported format version.
pub fn decode_revocation_retention(
    bytes: &[u8],
) -> Result<RevocationRetention, RevocationRetentionCodecError> {
    let WireValue::Map(mut map) = decode_deterministic_cbor(bytes)
        .map_err(|_| RevocationRetentionCodecError::InvalidInput)?
    else {
        return Err(RevocationRetentionCodecError::InvalidInput);
    };
    let version = match map.remove("format_version") {
        Some(WireValue::Unsigned(version)) => version,
        _ => return Err(RevocationRetentionCodecError::InvalidInput),
    };
    if version != REVOCATION_RETENTION_FORMAT_VERSION {
        return Err(RevocationRetentionCodecError::UnsupportedVersion);
    }
    let pair_id = match map.remove("pair_id") {
        Some(WireValue::Bytes(bytes)) => {
            PairId::reconstruct(&bytes).map_err(|_| RevocationRetentionCodecError::InvalidInput)?
        }
        _ => return Err(RevocationRetentionCodecError::InvalidInput),
    };
    let key = match map.remove("revocation_key") {
        Some(WireValue::Bytes(bytes)) => {
            let bytes = Zeroizing::new(bytes);
            let mut key = Zeroizing::new([0_u8; PAIR_KEY_SIZE]);
            if bytes.len() != PAIR_KEY_SIZE {
                return Err(RevocationRetentionCodecError::InvalidInput);
            }
            key.copy_from_slice(&bytes);
            RevocationKey(key)
        }
        _ => return Err(RevocationRetentionCodecError::InvalidInput),
    };
    let revoked_at_ms = match map.remove("revoked_at_ms") {
        Some(WireValue::Unsigned(value)) => value,
        _ => return Err(RevocationRetentionCodecError::InvalidInput),
    };
    if !map.is_empty() {
        return Err(RevocationRetentionCodecError::InvalidInput);
    }
    Ok(RevocationRetention {
        pair_id,
        key,
        revoked_at_ms,
    })
}

/// The `revoked` attribute of a `mode=session` record: exactly eight
/// entries, the hints of the up to eight most recent announced revocations
/// and random fillers, in random order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokedAnnouncement {
    entries: [[u8; REVOCATION_HINT_SIZE]; REVOKED_ANNOUNCEMENT_ENTRIES],
}

impl RevokedAnnouncement {
    /// Assembles the attribute from `candidates` (hints with their
    /// revocation times), taking the eight most recent, filling the
    /// remaining entries with random values and shuffling all eight with
    /// `random`. Revocations beyond the eighth are not announced.
    ///
    /// # Errors
    /// [`RevocationError::RandomUnavailable`] when `random` fails.
    pub fn assemble(
        candidates: &[AnnouncementCandidate],
        mut random: impl FnMut(&mut [u8]) -> Result<(), RevocationError>,
    ) -> Result<Self, RevocationError> {
        let hints = most_recently_used(candidates, REVOKED_ANNOUNCEMENT_ENTRIES);
        let mut keyed = [([0_u8; REVOCATION_HINT_SIZE], [0_u8; REVOCATION_HINT_SIZE]);
            REVOKED_ANNOUNCEMENT_ENTRIES];
        for (index, (order, entry)) in keyed.iter_mut().enumerate() {
            random(order)?;
            match hints.get(index) {
                Some(hint) => *entry = *hint,
                None => random(entry)?,
            }
        }
        keyed.sort_unstable_by_key(|(order, _)| *order);
        Ok(Self {
            entries: keyed.map(|(_, entry)| entry),
        })
    }

    /// The eight entries in publication order.
    #[must_use]
    pub const fn entries(&self) -> &[[u8; REVOCATION_HINT_SIZE]; REVOKED_ANNOUNCEMENT_ENTRIES] {
        &self.entries
    }

    /// Exactly eight parsed entries, in publication order.
    pub(crate) const fn from_entries(
        entries: [[u8; REVOCATION_HINT_SIZE]; REVOKED_ANNOUNCEMENT_ENTRIES],
    ) -> Self {
        Self { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        REVOCATION_ANNOUNCEMENT_MS, REVOCATION_HINT_SIZE, REVOKED_ANNOUNCEMENT_ENTRIES,
        RevocationKey, RevocationRetention, RevocationRetentionCodecError, RevokedAnnouncement,
        decode_revocation_retention, encode_revocation_retention,
    };
    use crate::{
        DiscoveryRecord, DiscoveryRecordError, EndpointRole, GrantsHash, InstanceName,
        PAIR_ID_SIZE, PairId, PairRecord, ProfileName, X25519_KEY_SIZE, noise::x25519_public_key,
        txt::AnnouncementCandidate,
    };

    /// Synthetic static private keys and pair identifier bytes.
    const CUSTODIAN_PRIVATE_BYTE: u8 = 0x11;
    const REQUESTER_PRIVATE_BYTE: u8 = 0x22;
    const PAIR_ID_BYTE: u8 = 0x33;
    const FILLER_BYTE: u8 = 0x44;
    const GRANTS_HASH_BYTE: u8 = 0x55;
    const INSTANCE: &str = "refineid-7f2a1c84";
    const OTHER_INSTANCE: &str = "refineid-b3d90e15";
    const EPOCH: u64 = 1_990_656;
    const REVOKED_AT_MS: u64 = 1_000;
    const CREATED_AT_MS: u64 = 1;

    fn pair_id() -> PairId {
        PairId::reconstruct(&[PAIR_ID_BYTE; PAIR_ID_SIZE]).expect("pair id")
    }

    fn keys() -> (RevocationKey, RevocationKey) {
        let custodian = [CUSTODIAN_PRIVATE_BYTE; X25519_KEY_SIZE];
        let requester = [REQUESTER_PRIVATE_BYTE; X25519_KEY_SIZE];
        (
            RevocationKey::from_parts(pair_id(), &custodian, &x25519_public_key(&requester))
                .expect("custodian key"),
            RevocationKey::from_parts(pair_id(), &requester, &x25519_public_key(&custodian))
                .expect("requester key"),
        )
    }

    fn custodian_record() -> PairRecord {
        let custodian = [CUSTODIAN_PRIVATE_BYTE; X25519_KEY_SIZE];
        let requester = [REQUESTER_PRIVATE_BYTE; X25519_KEY_SIZE];
        PairRecord::new(
            pair_id(),
            EndpointRole::Proxy,
            custodian,
            x25519_public_key(&custodian),
            x25519_public_key(&requester),
            GrantsHash::from_array([GRANTS_HASH_BYTE; crate::GRANTS_HASH_SIZE]),
            vec![ProfileName::CardStatus],
            CREATED_AT_MS,
        )
        .expect("record")
    }

    fn instance(name: &str) -> InstanceName {
        InstanceName::new(name).expect("instance")
    }

    fn fill(bytes: &mut [u8]) -> Result<(), super::RevocationError> {
        bytes.fill(FILLER_BYTE);
        Ok(())
    }

    fn record_with(hint: [u8; REVOCATION_HINT_SIZE]) -> DiscoveryRecord {
        let candidate = AnnouncementCandidate {
            hint,
            last_used_ms: REVOKED_AT_MS,
        };
        let announcement = RevokedAnnouncement::assemble(&[candidate], fill).expect("announcement");
        DiscoveryRecord::assemble(&[], Some(announcement))
    }

    #[test]
    fn both_endpoints_derive_one_key() {
        let (custodian, requester) = keys();
        let name = instance(INSTANCE);
        assert_eq!(custodian.hint(&name, EPOCH), requester.hint(&name, EPOCH));
    }

    #[test]
    fn a_hint_matches_its_epoch_and_both_neighbours_only() {
        let (custodian, requester) = keys();
        let name = instance(INSTANCE);
        let record = record_with(custodian.hint(&name, EPOCH));
        for epoch in [EPOCH - 1, EPOCH, EPOCH + 1] {
            assert!(requester.matches(&record, &name, epoch));
        }
        assert!(!requester.matches(&record, &name, EPOCH + 2));
        assert!(!requester.matches(&record, &name, EPOCH - 2));
    }

    #[test]
    fn a_hint_is_bound_to_its_instance() {
        let (custodian, requester) = keys();
        let record = record_with(custodian.hint(&instance(INSTANCE), EPOCH));
        assert!(!requester.matches(&record, &instance(OTHER_INSTANCE), EPOCH));
    }

    #[test]
    fn a_record_without_revocations_matches_nothing() {
        let (_, requester) = keys();
        let record = DiscoveryRecord::parse(&[("v", "1"), ("mode", "session")]).expect("record");
        assert!(!requester.matches(&record, &instance(INSTANCE), EPOCH));
    }

    #[test]
    fn a_record_round_trips_through_txt() {
        let (custodian, requester) = keys();
        let name = instance(INSTANCE);
        let record = record_with(custodian.hint(&name, EPOCH));
        let entries = record.txt_entries();
        let pairs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let parsed = DiscoveryRecord::parse(&pairs).expect("parse");
        assert_eq!(parsed, record);
        assert!(requester.matches(&parsed, &name, EPOCH));
    }

    #[test]
    fn malformed_revocations_are_refused() {
        let entry = "0123456789abcdef";
        let eight = [entry; REVOKED_ANNOUNCEMENT_ENTRIES].join(",");
        let seven = [entry; REVOKED_ANNOUNCEMENT_ENTRIES - 1].join(",");
        let nine = [entry; REVOKED_ANNOUNCEMENT_ENTRIES + 1].join(",");
        let upper = eight.to_uppercase();
        let with = |list: &str| {
            DiscoveryRecord::parse(&[("v", "1"), ("mode", "session"), ("revoked", list)])
        };
        assert!(with(&eight).is_ok());
        for malformed in [seven.as_str(), nine.as_str(), upper.as_str(), ""] {
            assert_eq!(
                with(malformed),
                Err(DiscoveryRecordError::MalformedRevocations)
            );
        }
        assert_eq!(
            DiscoveryRecord::parse(&[
                ("v", "1"),
                ("mode", "session"),
                ("revoked", &eight),
                ("REVOKED", &eight)
            ]),
            Err(DiscoveryRecordError::UnexpectedKey)
        );
    }

    #[test]
    fn revocations_beyond_the_eighth_are_not_announced() {
        let candidates = (0..=REVOKED_ANNOUNCEMENT_ENTRIES)
            .map(|index| AnnouncementCandidate {
                hint: [u8::try_from(index).expect("small"); REVOCATION_HINT_SIZE],
                last_used_ms: u64::try_from(index).expect("small"),
            })
            .collect::<Vec<_>>();
        let announcement = RevokedAnnouncement::assemble(&candidates, fill).expect("announcement");
        let least_recent = [0_u8; REVOCATION_HINT_SIZE];
        assert!(!announcement.entries().contains(&least_recent));
        for candidate in &candidates[1..] {
            assert!(announcement.entries().contains(&candidate.hint));
        }
    }

    #[test]
    fn a_retention_announces_for_thirty_days() {
        let retention =
            RevocationRetention::derive(&custodian_record(), REVOKED_AT_MS).expect("retention");
        assert!(retention.announces_at(REVOKED_AT_MS));
        assert!(retention.announces_at(REVOKED_AT_MS + REVOCATION_ANNOUNCEMENT_MS - 1));
        assert!(!retention.announces_at(REVOKED_AT_MS + REVOCATION_ANNOUNCEMENT_MS));
        assert!(!retention.announces_at(REVOKED_AT_MS - 1));
        assert!(!retention.is_expired(REVOKED_AT_MS - 1));
        assert!(!retention.is_expired(REVOKED_AT_MS));
        assert!(!retention.is_expired(REVOKED_AT_MS + REVOCATION_ANNOUNCEMENT_MS - 1));
        assert!(retention.is_expired(REVOKED_AT_MS + REVOCATION_ANNOUNCEMENT_MS));
        let name = instance(INSTANCE);
        let expired = RevocationRetention::candidates(
            &[retention],
            &name,
            EPOCH,
            REVOKED_AT_MS + REVOCATION_ANNOUNCEMENT_MS,
        );
        assert!(expired.is_empty());
    }

    #[test]
    fn a_retention_round_trips_and_keeps_the_hint() {
        let (custodian, _) = keys();
        let retention =
            RevocationRetention::derive(&custodian_record(), REVOKED_AT_MS).expect("retention");
        let encoded = encode_revocation_retention(&retention).expect("encode");
        let decoded = decode_revocation_retention(&encoded).expect("decode");
        assert_eq!(decoded.pair_id(), pair_id());
        assert_eq!(decoded.revoked_at_ms(), REVOKED_AT_MS);
        let name = instance(INSTANCE);
        assert_eq!(decoded.hint(&name, EPOCH), custodian.hint(&name, EPOCH));
        assert!(matches!(
            decode_revocation_retention(&encoded[..encoded.len() - 1]),
            Err(RevocationRetentionCodecError::InvalidInput)
        ));
    }
}
