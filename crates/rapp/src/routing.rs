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

//! How a stored pairing finds its peer without naming itself on the wire:
//! rotating discovery hints (hierarchy specification §4.3) and per-dial
//! session routing tags (RAPP v26.10.10 §2.2.1).
//!
//! Both are keyed by the pairing's static X25519 agreement, which only the
//! two endpoints know. A discovery hint changes every 15 minutes and a
//! routing tag on every dial, so an observer of advertisements or preambles
//! cannot tell one pairing's values from another's.

use std::collections::VecDeque;

use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use super::txt::{
    AnnouncementCandidate, MODE_KEY, VERSION, VERSION_KEY, decode_list, encode_list,
    most_recently_used, values,
};
use super::{
    DegenerateAgreement, PAIR_KEY_SIZE, PairId, PairRecord, TransportProfile, X25519_KEY_SIZE,
};

/// Byte length of one published discovery hint.
pub const DISCOVERY_HINT_SIZE: usize = super::txt::HINT_SIZE;

/// Most discovery hints one `mode=session` record carries.
pub const MAX_DISCOVERY_HINTS: usize = 4;

/// TXT value naming the session mode.
const TXT_MODE_SESSION: &str = "session";

/// TXT key carrying the discovery hint list.
const TXT_HINTS_KEY: &str = "hints";

/// Length in seconds of one discovery-hint epoch.
pub const DISCOVERY_HINT_EPOCH_SECONDS: u64 = 900;

/// Byte length of the requester's fresh routing nonce.
pub const ROUTING_NONCE_SIZE: usize = 16;

/// Byte length of a routing tag.
pub const ROUTING_TAG_SIZE: usize = 16;

/// Byte length of the session preamble's routing value: nonce then tag.
pub const SESSION_ROUTING_SIZE: usize = ROUTING_NONCE_SIZE + ROUTING_TAG_SIZE;

/// Accepted nonces a custodian remembers to refuse a replayed preamble.
pub const ROUTING_REPLAY_WINDOW: usize = 256;

/// HKDF info naming the discovery-hint key.
const DISCOVERY_KEY_INFO: &[u8] = b"RAPP-discovery-hint-v2";

/// HKDF info naming the routing key.
const ROUTING_KEY_INFO: &[u8] = b"RAPP-routing-v1";

/// The discovery epoch of a Unix time: `floor(unix_time / 900)`.
#[must_use]
pub const fn discovery_epoch(unix_time_seconds: u64) -> u64 {
    unix_time_seconds / DISCOVERY_HINT_EPOCH_SECONDS
}

/// One pairing's discovery-hint key `K_disc`, equal on both endpoints.
pub struct DiscoveryKey(Zeroizing<[u8; PAIR_KEY_SIZE]>);

impl core::fmt::Debug for DiscoveryKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DiscoveryKey([redacted])")
    }
}

impl DiscoveryKey {
    /// Derives the key of a stored pairing.
    ///
    /// # Errors
    /// [`DegenerateAgreement`] when the static agreement is the identity
    /// point.
    pub fn derive(record: &PairRecord) -> Result<Self, DegenerateAgreement> {
        Self::from_parts(
            record.pair_id(),
            record.local_static_private(),
            record.remote_static_public(),
        )
    }

    /// Derives `K_disc = HKDF-SHA-256(salt = pair_id, IKM = X25519(local
    /// static private, peer static public), info = "RAPP-discovery-hint-v2",
    /// L = 32)`.
    ///
    /// # Errors
    /// [`DegenerateAgreement`] when the agreement is the identity point.
    pub fn from_parts(
        pair_id: PairId,
        local_static_private: &[u8; X25519_KEY_SIZE],
        remote_static_public: &[u8; X25519_KEY_SIZE],
    ) -> Result<Self, DegenerateAgreement> {
        super::derive_pair_key(
            pair_id,
            local_static_private,
            remote_static_public,
            DISCOVERY_KEY_INFO,
        )
        .map(Self)
    }

    /// First 8 bytes of `HMAC-SHA-256(K_disc, epoch_be64)`.
    #[must_use]
    pub fn hint(&self, epoch: u64) -> [u8; DISCOVERY_HINT_SIZE] {
        let digest = super::pair_key_mac(&self.0, &[&epoch.to_be_bytes()]);
        let mut hint = [0_u8; DISCOVERY_HINT_SIZE];
        hint.copy_from_slice(&digest[..DISCOVERY_HINT_SIZE]);
        hint
    }

    /// Whether `hint` is this pairing's hint for `epoch` or an adjacent
    /// epoch, compared in constant time.
    #[must_use]
    pub fn matches(&self, hint: &[u8; DISCOVERY_HINT_SIZE], epoch: u64) -> bool {
        let mut matched = subtle::Choice::from(0);
        for candidate in [epoch.checked_sub(1), Some(epoch), epoch.checked_add(1)]
            .into_iter()
            .flatten()
        {
            matched |= self.hint(candidate).ct_eq(hint);
        }
        bool::from(matched)
    }

    /// Whether `record` carries this pairing's hint for `epoch` or an
    /// adjacent epoch.
    #[must_use]
    pub fn matches_record(&self, record: &DiscoveryRecord, epoch: u64) -> bool {
        record
            .hints
            .iter()
            .fold(false, |found, hint| found | self.matches(hint, epoch))
    }
}

/// A well-formed `mode=session` record and the discovery hints it carries,
/// possibly none (hierarchy specification §4.3).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryRecord {
    hints: Vec<[u8; DISCOVERY_HINT_SIZE]>,
}

/// Why a TXT record is not a well-formed `mode=session` record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryRecordError {
    /// A key other than `v`, `mode` and `hints`, or a repeated key; keys
    /// compare case-insensitively.
    UnexpectedKey,
    /// `v` or `mode` is missing or has another value.
    WrongHeader,
    /// The hint list is not one to four lowercase 16-digit hexadecimal
    /// entries.
    MalformedHints,
}

impl DiscoveryRecord {
    /// A record announcing the hints of the four most recently used
    /// pairings among `candidates`; pairings beyond the fourth are not
    /// announced.
    #[must_use]
    pub fn assemble(candidates: &[AnnouncementCandidate]) -> Self {
        Self {
            hints: most_recently_used(candidates, MAX_DISCOVERY_HINTS),
        }
    }

    /// Parses the TXT key/value pairs of a discovered record.
    ///
    /// # Errors
    /// [`DiscoveryRecordError`] for anything but `v=1`, `mode=session` and an
    /// optional `hints=` of one to four lowercase entries.
    pub fn parse(entries: &[(&str, &str)]) -> Result<Self, DiscoveryRecordError> {
        let [version, mode, hints] = values(entries, [VERSION_KEY, MODE_KEY, TXT_HINTS_KEY])
            .ok_or(DiscoveryRecordError::UnexpectedKey)?;
        if version != Some(VERSION) || mode != Some(TXT_MODE_SESSION) {
            return Err(DiscoveryRecordError::WrongHeader);
        }
        let hints = match hints {
            None => Vec::new(),
            Some(list) => decode_list(list, MAX_DISCOVERY_HINTS)
                .ok_or(DiscoveryRecordError::MalformedHints)?,
        };
        Ok(Self { hints })
    }

    /// The record's TXT key/value pairs, in publication order; `hints` only
    /// when there are hints.
    #[must_use]
    pub fn txt_entries(&self) -> Vec<(&'static str, String)> {
        let mut entries = vec![
            (VERSION_KEY, VERSION.to_owned()),
            (MODE_KEY, TXT_MODE_SESSION.to_owned()),
        ];
        if !self.hints.is_empty() {
            entries.push((TXT_HINTS_KEY, encode_list(&self.hints)));
        }
        entries
    }

    /// The announced hints in publication order.
    #[must_use]
    pub fn hints(&self) -> &[[u8; DISCOVERY_HINT_SIZE]] {
        &self.hints
    }
}

/// One pairing's routing key `K_route`, equal on both endpoints.
pub struct RoutingKey(Zeroizing<[u8; PAIR_KEY_SIZE]>);

impl core::fmt::Debug for RoutingKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RoutingKey([redacted])")
    }
}

impl RoutingKey {
    /// Derives the key of a stored pairing.
    ///
    /// # Errors
    /// [`DegenerateAgreement`] when the static agreement is the identity
    /// point.
    pub fn derive(record: &PairRecord) -> Result<Self, DegenerateAgreement> {
        Self::from_parts(
            record.pair_id(),
            record.local_static_private(),
            record.remote_static_public(),
        )
    }

    /// Derives `K_route = HKDF-SHA-256(salt = pair_id, IKM = X25519(local
    /// static private, peer static public), info = "RAPP-routing-v1",
    /// L = 32)`.
    ///
    /// # Errors
    /// [`DegenerateAgreement`] when the agreement is the identity point.
    pub fn from_parts(
        pair_id: PairId,
        local_static_private: &[u8; X25519_KEY_SIZE],
        remote_static_public: &[u8; X25519_KEY_SIZE],
    ) -> Result<Self, DegenerateAgreement> {
        super::derive_pair_key(
            pair_id,
            local_static_private,
            remote_static_public,
            ROUTING_KEY_INFO,
        )
        .map(Self)
    }

    /// First 16 bytes of `HMAC-SHA-256(K_route, len(domain) || domain ||
    /// nonce)`, `len` one octet and `domain` the profile's preamble domain.
    #[must_use]
    pub fn tag(
        &self,
        profile: TransportProfile,
        nonce: &[u8; ROUTING_NONCE_SIZE],
    ) -> [u8; ROUTING_TAG_SIZE] {
        let domain = profile.preamble_domain().as_bytes();
        let length = u8::try_from(domain.len()).expect("a preamble domain is short");
        let digest = super::pair_key_mac(&self.0, &[&[length], domain, nonce]);
        let mut tag = [0_u8; ROUTING_TAG_SIZE];
        tag.copy_from_slice(&digest[..ROUTING_TAG_SIZE]);
        tag
    }

    /// A fresh routing value for one dial on `profile`.
    ///
    /// # Errors
    /// [`RandomUnavailable`] when `random` fails.
    pub fn route(
        &self,
        profile: TransportProfile,
        random: impl FnOnce(&mut [u8]) -> Result<(), RandomUnavailable>,
    ) -> Result<SessionRouting, RandomUnavailable> {
        let mut nonce = [0_u8; ROUTING_NONCE_SIZE];
        random(&mut nonce)?;
        Ok(SessionRouting {
            nonce,
            tag: self.tag(profile, &nonce),
        })
    }

    fn admits(&self, profile: TransportProfile, routing: &SessionRouting) -> subtle::Choice {
        self.tag(profile, &routing.nonce).ct_eq(&routing.tag)
    }
}

/// The platform random source failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RandomUnavailable;

/// The routing value of a `"session"` preamble: a fresh nonce and the tag
/// it keys. Public bytes; only the two endpoints can tell whose it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionRouting {
    nonce: [u8; ROUTING_NONCE_SIZE],
    tag: [u8; ROUTING_TAG_SIZE],
}

impl SessionRouting {
    /// Splits a received 32-byte routing value; any other length is `None`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (nonce, tag) = bytes.split_first_chunk::<ROUTING_NONCE_SIZE>()?;
        Some(Self {
            nonce: *nonce,
            tag: <[u8; ROUTING_TAG_SIZE]>::try_from(tag).ok()?,
        })
    }

    /// The wire bytes, nonce then tag.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SESSION_ROUTING_SIZE] {
        let mut bytes = [0_u8; SESSION_ROUTING_SIZE];
        let (nonce, tag) = bytes.split_at_mut(ROUTING_NONCE_SIZE);
        nonce.copy_from_slice(&self.nonce);
        tag.copy_from_slice(&self.tag);
        bytes
    }

    /// The requester's nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; ROUTING_NONCE_SIZE] {
        &self.nonce
    }
}

/// The position in `keys` of the one pairing that keyed `routing` on
/// `profile`, or `None`.
///
/// Every key is evaluated and the comparison is constant time, so the time
/// taken does not depend on which pairing matched or whether any did.
#[must_use]
pub fn route_session(
    keys: &[RoutingKey],
    profile: TransportProfile,
    routing: &SessionRouting,
) -> Option<usize> {
    let mut found = subtle::Choice::from(0);
    let mut position = 0_u64;
    for (index, key) in keys.iter().enumerate() {
        let admitted = key.admits(profile, routing);
        let candidate = u64::try_from(index).expect("a pairing count fits in u64");
        position.conditional_assign(&candidate, admitted & !found);
        found |= admitted;
    }
    bool::from(found).then(|| usize::try_from(position).expect("index came from a usize"))
}

/// The nonces of the custodian's most recently routed sessions.
///
/// A preamble whose nonce is already here is a replay and is refused before
/// any session work starts.
#[derive(Debug, Default)]
pub struct RoutingReplayCache {
    seen: VecDeque<[u8; ROUTING_NONCE_SIZE]>,
}

impl RoutingReplayCache {
    /// Records `nonce` and reports whether it was new. The oldest of more
    /// than [`ROUTING_REPLAY_WINDOW`] nonces is forgotten.
    pub fn admit(&mut self, nonce: &[u8; ROUTING_NONCE_SIZE]) -> bool {
        if self.seen.contains(nonce) {
            return false;
        }
        if self.seen.len() == ROUTING_REPLAY_WINDOW {
            self.seen.pop_front();
        }
        self.seen.push_back(*nonce);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::super::txt::AnnouncementCandidate;
    use super::*;

    const FIRST_PRIVATE: u8 = 0x11;
    const SECOND_PRIVATE: u8 = 0x22;
    const PAIR_BYTE: u8 = 0x33;
    const NONCE_BYTE: u8 = 0x44;
    const OTHER_PAIR_BYTE: u8 = 0x55;
    const EPOCH: u64 = 1_990_560;
    const EPOCH_STEP: u64 = 1;
    const FAR_EPOCH_STEP: u64 = 2;

    fn public(private: u8) -> [u8; X25519_KEY_SIZE] {
        curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped([private; X25519_KEY_SIZE])
            .to_bytes()
    }

    fn keys(pair: u8) -> (RoutingKey, RoutingKey) {
        let pair_id = PairId::from_array([pair; super::super::PAIR_ID_SIZE]);
        (
            RoutingKey::from_parts(
                pair_id,
                &[FIRST_PRIVATE; X25519_KEY_SIZE],
                &public(SECOND_PRIVATE),
            )
            .expect("key"),
            RoutingKey::from_parts(
                pair_id,
                &[SECOND_PRIVATE; X25519_KEY_SIZE],
                &public(FIRST_PRIVATE),
            )
            .expect("key"),
        )
    }

    fn fixed_nonce(bytes: &mut [u8]) -> Result<(), RandomUnavailable> {
        bytes.fill(NONCE_BYTE);
        Ok(())
    }

    #[test]
    fn both_endpoints_key_the_same_tag() {
        let (requester, custodian) = keys(PAIR_BYTE);
        let routing = requester
            .route(TransportProfile::Stream, fixed_nonce)
            .expect("route");
        assert_eq!(
            route_session(&[custodian], TransportProfile::Stream, &routing),
            Some(0)
        );
    }

    #[test]
    fn the_tag_is_bound_to_the_profile() {
        let (requester, custodian) = keys(PAIR_BYTE);
        let routing = requester
            .route(TransportProfile::Stream, fixed_nonce)
            .expect("route");
        assert_eq!(
            route_session(&[custodian], TransportProfile::Ble, &routing),
            None
        );
    }

    #[test]
    fn routing_finds_the_right_pairing_among_several() {
        let (requester, custodian) = keys(PAIR_BYTE);
        let (_, other) = keys(OTHER_PAIR_BYTE);
        let routing = requester
            .route(TransportProfile::Ble, fixed_nonce)
            .expect("route");
        assert_eq!(
            route_session(&[other, custodian], TransportProfile::Ble, &routing),
            Some(1)
        );
    }

    #[test]
    fn routing_value_round_trips_and_rejects_other_lengths() {
        let (requester, _) = keys(PAIR_BYTE);
        let routing = requester
            .route(TransportProfile::Stream, fixed_nonce)
            .expect("route");
        let bytes = routing.to_bytes();
        assert_eq!(SessionRouting::from_bytes(&bytes), Some(routing));
        assert_eq!(SessionRouting::from_bytes(&bytes[1..]), None);
    }

    #[test]
    fn a_replayed_nonce_is_refused() {
        let mut cache = RoutingReplayCache::default();
        let nonce = [NONCE_BYTE; ROUTING_NONCE_SIZE];
        assert!(cache.admit(&nonce));
        assert!(!cache.admit(&nonce));
    }

    #[test]
    fn the_replay_window_forgets_its_oldest_nonce() {
        let mut cache = RoutingReplayCache::default();
        let first = [0_u8; ROUTING_NONCE_SIZE];
        assert!(cache.admit(&first));
        for value in 1..=ROUTING_REPLAY_WINDOW {
            let mut nonce = [0_u8; ROUTING_NONCE_SIZE];
            nonce[..size_of::<u64>()]
                .copy_from_slice(&u64::try_from(value).expect("small").to_be_bytes());
            assert!(cache.admit(&nonce));
        }
        assert!(cache.admit(&first));
    }

    #[test]
    fn a_session_record_round_trips_and_matches() {
        let pair_id = PairId::from_array([PAIR_BYTE; super::super::PAIR_ID_SIZE]);
        let custodian = DiscoveryKey::from_parts(
            pair_id,
            &[FIRST_PRIVATE; X25519_KEY_SIZE],
            &public(SECOND_PRIVATE),
        )
        .expect("key");
        let requester = DiscoveryKey::from_parts(
            pair_id,
            &[SECOND_PRIVATE; X25519_KEY_SIZE],
            &public(FIRST_PRIVATE),
        )
        .expect("key");
        let record = DiscoveryRecord::assemble(&[AnnouncementCandidate {
            hint: custodian.hint(EPOCH),
            last_used_ms: EPOCH,
        }]);
        let entries: Vec<(String, String)> = record
            .txt_entries()
            .into_iter()
            .map(|(key, value)| (key.to_uppercase(), value))
            .collect();
        let pairs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let parsed = DiscoveryRecord::parse(&pairs).expect("parse");
        assert!(requester.matches_record(&parsed, EPOCH));
        assert_eq!(
            DiscoveryRecord::parse(&[("v", "1"), ("mode", "session")]),
            Ok(DiscoveryRecord::default())
        );
        assert_eq!(
            DiscoveryRecord::parse(&[("v", "1"), ("mode", "pairing")]),
            Err(DiscoveryRecordError::WrongHeader)
        );
    }

    #[test]
    fn discovery_hints_match_on_both_endpoints_within_one_epoch() {
        let pair_id = PairId::from_array([PAIR_BYTE; super::super::PAIR_ID_SIZE]);
        let custodian = DiscoveryKey::from_parts(
            pair_id,
            &[FIRST_PRIVATE; X25519_KEY_SIZE],
            &public(SECOND_PRIVATE),
        )
        .expect("key");
        let requester = DiscoveryKey::from_parts(
            pair_id,
            &[SECOND_PRIVATE; X25519_KEY_SIZE],
            &public(FIRST_PRIVATE),
        )
        .expect("key");
        let hint = custodian.hint(EPOCH);
        assert!(requester.matches(&hint, EPOCH));
        assert!(requester.matches(&hint, EPOCH + EPOCH_STEP));
        assert!(!requester.matches(&hint, EPOCH + FAR_EPOCH_STEP));
    }
}
