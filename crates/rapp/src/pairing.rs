//! Durable pairing records and the device-only persistence boundary.
//!
//! RAPP deliberately does not provide an in-memory default store. Platform
//! integrations must place the private key in device-only, non-backup secret
//! storage and make insertion/revocation atomic.

use core::fmt;
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::{
    EndpointRole, GrantsHash, PairId, ProfileName, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor,
};

const X25519_KEY_SIZE: usize = 32;

/// Format version for encoded pairing records.
pub const PAIR_RECORD_FORMAT_VERSION: u64 = 6;

/// Active long-term pairing material.
///
/// This type is intentionally neither `Clone` nor serializable. Persistence
/// adapters must explicitly extract the secret inside their protected storage
/// implementation instead of accidentally copying it through application
/// models, logs, backups, or diagnostics.
pub struct PairRecord {
    pair_id: PairId,
    role: EndpointRole,
    local_static_private: Zeroizing<[u8; X25519_KEY_SIZE]>,
    local_static_public: [u8; X25519_KEY_SIZE],
    remote_static_public: [u8; X25519_KEY_SIZE],
    grants_hash: GrantsHash,
    profiles: Vec<ProfileName>,
    created_at_ms: u64,
    storage_confirmed: bool,
    forgotten_at_ms: Option<u64>,
}

/// Days a forgotten pairing keeps its key to deliver the `pairing_revoked`
/// close on a later session (RAPP v26.10.21 section 4.6 item 3).
const REVOCATION_NOTICE_DAYS: u64 = 30;
const MILLISECONDS_PER_DAY: u64 = 86_400_000;
/// How long a forgotten pairing keeps its key for the close.
pub const REVOCATION_NOTICE_MS: u64 = REVOCATION_NOTICE_DAYS * MILLISECONDS_PER_DAY;

impl PairRecord {
    /// Constructs a validated pairing record whose storage the peer has
    /// confirmed. The pairing flow builds its record unconfirmed and
    /// confirms it only through an [`ActivePairing`](crate::ActivePairing)
    /// (RAPP v26.10.21 section 4.3 item 4).
    ///
    /// # Errors
    /// [`PairRecordError`] on an all-zero static key or an empty profile set.
    #[allow(
        clippy::too_many_arguments,
        reason = "one atomic constructor takes every field of the record"
    )]
    pub fn new(
        pair_id: PairId,
        role: EndpointRole,
        local_static_private: [u8; X25519_KEY_SIZE],
        local_static_public: [u8; X25519_KEY_SIZE],
        remote_static_public: [u8; X25519_KEY_SIZE],
        grants_hash: GrantsHash,
        profiles: Vec<ProfileName>,
        created_at_ms: u64,
    ) -> Result<Self, PairRecordError> {
        if local_static_private.iter().all(|byte| *byte == 0)
            || local_static_public.iter().all(|byte| *byte == 0)
            || remote_static_public.iter().all(|byte| *byte == 0)
        {
            return Err(PairRecordError::InvalidStaticKey);
        }
        if profiles.is_empty() {
            return Err(PairRecordError::NoNegotiatedProfiles);
        }

        Ok(Self {
            pair_id,
            role,
            local_static_private: Zeroizing::new(local_static_private),
            local_static_public,
            remote_static_public,
            grants_hash,
            profiles,
            created_at_ms,
            storage_confirmed: true,
            forgotten_at_ms: None,
        })
    }

    /// Stable identifier of the pairing.
    #[must_use]
    pub const fn pair_id(&self) -> PairId {
        self.pair_id
    }

    /// Local endpoint role fixed during pairing.
    #[must_use]
    pub const fn role(&self) -> EndpointRole {
        self.role
    }

    /// Remote static Noise public key pinned by the pairing handshake.
    #[must_use]
    pub const fn remote_static_public(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.remote_static_public
    }

    /// Local static Noise public key corresponding to protected private bytes.
    #[must_use]
    pub const fn local_static_public(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.local_static_public
    }

    /// Hash of the negotiated authorization grants.
    #[must_use]
    pub const fn grants_hash(&self) -> GrantsHash {
        self.grants_hash
    }

    /// Profiles permitted by this pairing.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileName] {
        &self.profiles
    }

    /// Pair creation time supplied by the platform wall clock.
    #[must_use]
    pub const fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// Whether the peer confirmed that it stored its record (section 4.3
    /// item 4). Only a confirmed record opens sessions, routes, or is
    /// announced; an unconfirmed one found in storage was written inside a
    /// confirmation window the endpoint did not complete, and is revoked.
    #[must_use]
    pub const fn is_storage_confirmed(&self) -> bool {
        self.storage_confirmed
    }

    /// The record as the pairing flow stores it before the peer's
    /// `pairing.stored` arrives.
    pub(crate) const fn awaiting_storage_confirmation(mut self) -> Self {
        self.storage_confirmed = false;
        self
    }

    /// The record once both storage confirmations have been exchanged.
    pub(crate) const fn storage_confirmed(mut self) -> Self {
        self.storage_confirmed = true;
        self
    }

    /// When its user forgot the pairing while no session was open: the
    /// record serves nothing from then on and keeps its key only to deliver
    /// the `pairing_revoked` close on the next session (section 4.6 item 2).
    #[must_use]
    pub const fn forgotten_at_ms(&self) -> Option<u64> {
        self.forgotten_at_ms
    }

    /// The record its user forgot at `at_ms`, kept for the close.
    #[must_use]
    pub const fn forgotten(mut self, at_ms: u64) -> Self {
        self.forgotten_at_ms = Some(at_ms);
        self
    }

    /// Whether a forgotten record has kept its key for
    /// [`REVOCATION_NOTICE_MS`]; it is then destroyed untold.
    #[must_use]
    pub const fn revocation_notice_expired(&self, now_ms: u64) -> bool {
        match self.forgotten_at_ms {
            Some(at_ms) => now_ms.saturating_sub(at_ms) >= REVOCATION_NOTICE_MS,
            None => false,
        }
    }

    /// The profiles a session of this record serves: the granted ones, or
    /// none once the record is forgotten.
    #[must_use]
    pub fn serving_profiles(&self) -> &[ProfileName] {
        if self.forgotten_at_ms.is_some() {
            &[]
        } else {
            &self.profiles
        }
    }

    /// Exposes the private key only to sibling protocol machinery and stores.
    #[must_use]
    pub fn local_static_private(&self) -> &[u8; X25519_KEY_SIZE] {
        &self.local_static_private
    }
}

impl fmt::Debug for PairRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairRecord")
            .field("pair_id", &self.pair_id)
            .field("role", &self.role)
            .field("local_static_private", &"[redacted]")
            .field("local_static_public", &"[public key]")
            .field("remote_static_public", &"[public key]")
            .field("grants_hash", &self.grants_hash)
            .field("profiles", &self.profiles)
            .field("created_at_ms", &self.created_at_ms)
            .field("storage_confirmed", &self.storage_confirmed)
            .field("forgotten_at_ms", &self.forgotten_at_ms)
            .finish()
    }
}

/// Non-secret marker retained after an irreversible revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairTombstone {
    /// Revoked pair identifier.
    pub pair_id: PairId,
    /// Local time at which the secret was destroyed.
    pub revoked_at_ms: u64,
}

/// Platform persistence boundary for long-term pair keys.
///
/// Implementations MUST use device-only, non-migrating, non-backup secret
/// storage. `insert` and `revoke` MUST be atomic. `revoke` MUST destroy the
/// private key before reporting success and retain only a non-secret tombstone.
pub trait PairStore {
    /// Platform storage error.
    type Error;

    /// Loads an active pair into zeroizing process memory.
    ///
    /// # Errors
    /// The platform storage failure.
    fn load(&mut self, pair_id: PairId) -> Result<Option<PairRecord>, Self::Error>;

    /// Atomically inserts a newly authenticated pair.
    ///
    /// # Errors
    /// [`PairStoreError`] on a reused identifier or a backend failure.
    fn insert(&mut self, record: PairRecord) -> Result<(), PairStoreError<Self::Error>>;

    /// Atomically destroys active secret material and stores a tombstone.
    ///
    /// # Errors
    /// [`PairStoreError`] when the pair does not exist or the backend fails.
    fn revoke(&mut self, tombstone: PairTombstone) -> Result<(), PairStoreError<Self::Error>>;

    /// Reports whether an identifier has been permanently revoked locally.
    ///
    /// # Errors
    /// The platform storage failure.
    fn is_revoked(&mut self, pair_id: PairId) -> Result<bool, Self::Error>;
}

/// Pair-record validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairRecordError {
    /// A Noise static key was the all-zero invalid value.
    InvalidStaticKey,
    /// Pairing completed without any negotiated profile.
    NoNegotiatedProfiles,
}

impl fmt::Display for PairRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for PairRecordError {}

/// Atomic pair-store operation failure.
#[derive(Debug)]
pub enum PairStoreError<E> {
    /// The identifier already has an active record or tombstone.
    IdentifierAlreadyUsed,
    /// The requested active pair does not exist.
    PairNotFound,
    /// Platform-provided storage failed.
    Backend(E),
}

/// Failure during pair record serialization or deserialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairRecordCodecError {
    /// The input bytes were not valid deterministic CBOR or contained unexpected keys/types.
    InvalidInput,
    /// Serialization failed.
    ProtocolFailure,
    /// The format version is unsupported.
    UnsupportedVersion,
    /// Record invariants failed.
    InvalidRecord(PairRecordError),
}

impl fmt::Display for PairRecordCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("invalid pairing record input"),
            Self::ProtocolFailure => formatter.write_str("failed to encode pairing record"),
            Self::UnsupportedVersion => {
                formatter.write_str("unsupported pairing record format version")
            }
            Self::InvalidRecord(err) => write!(formatter, "invalid record contents: {err}"),
        }
    }
}

impl core::error::Error for PairRecordCodecError {}

/// Serializes a [`PairRecord`] to deterministic CBOR.
///
/// # Errors
/// [`PairRecordCodecError::ProtocolFailure`] if serialization fails.
pub fn encode_pair_record(record: &PairRecord) -> Result<Vec<u8>, PairRecordCodecError> {
    let role = match record.role() {
        EndpointRole::Requester => "requester",
        EndpointRole::Proxy => "proxy",
    };
    let value = WireValue::Map(BTreeMap::from([
        (
            "format_version".to_owned(),
            WireValue::Unsigned(PAIR_RECORD_FORMAT_VERSION),
        ),
        (
            "pair_id".to_owned(),
            WireValue::Bytes(record.pair_id().as_bytes().to_vec()),
        ),
        ("role".to_owned(), WireValue::Text(role.to_owned())),
        (
            "local_static_private".to_owned(),
            WireValue::Bytes(record.local_static_private().to_vec()),
        ),
        (
            "local_static_public".to_owned(),
            WireValue::Bytes(record.local_static_public().to_vec()),
        ),
        (
            "remote_static_public".to_owned(),
            WireValue::Bytes(record.remote_static_public().to_vec()),
        ),
        (
            "grants_hash".to_owned(),
            WireValue::Bytes(record.grants_hash().as_bytes().to_vec()),
        ),
        (
            "profiles".to_owned(),
            WireValue::Array(
                record
                    .profiles()
                    .iter()
                    .map(|profile| WireValue::Text(profile.as_str().to_owned()))
                    .collect(),
            ),
        ),
        (
            "created_at_ms".to_owned(),
            WireValue::Unsigned(record.created_at_ms()),
        ),
        (
            "storage_confirmed".to_owned(),
            WireValue::Bool(record.is_storage_confirmed()),
        ),
        (
            "forgotten_at_ms".to_owned(),
            record
                .forgotten_at_ms()
                .map_or(WireValue::Null, WireValue::Unsigned),
        ),
    ]));
    encode_deterministic_cbor(&value).map_err(|_| PairRecordCodecError::ProtocolFailure)
}

/// Deserializes a [`PairRecord`] from deterministic CBOR.
///
/// # Errors
/// [`PairRecordCodecError`] on malformed CBOR, invalid keys, unsupported format version,
/// or invariant failure.
pub fn decode_pair_record(bytes: &[u8]) -> Result<PairRecord, PairRecordCodecError> {
    let WireValue::Map(mut map) =
        decode_deterministic_cbor(bytes).map_err(|_| PairRecordCodecError::InvalidInput)?
    else {
        return Err(PairRecordCodecError::InvalidInput);
    };
    let expected = [
        "format_version",
        "pair_id",
        "role",
        "local_static_private",
        "local_static_public",
        "remote_static_public",
        "grants_hash",
        "profiles",
        "created_at_ms",
        "storage_confirmed",
        "forgotten_at_ms",
    ];
    if map.keys().any(|key| !expected.contains(&key.as_str())) {
        return Err(PairRecordCodecError::InvalidInput);
    }
    if take_unsigned(&mut map, "format_version")? != PAIR_RECORD_FORMAT_VERSION {
        return Err(PairRecordCodecError::UnsupportedVersion);
    }
    let pair_id = PairId::reconstruct(&take_bytes(&mut map, "pair_id")?)
        .map_err(|_| PairRecordCodecError::InvalidInput)?;
    let role = match take_text(&mut map, "role")?.as_str() {
        "requester" => EndpointRole::Requester,
        "proxy" => EndpointRole::Proxy,
        _ => return Err(PairRecordCodecError::InvalidInput),
    };
    let local_static_private = take_array::<X25519_KEY_SIZE>(&mut map, "local_static_private")?;
    let local_static_public = take_array::<X25519_KEY_SIZE>(&mut map, "local_static_public")?;
    let remote_static_public = take_array::<X25519_KEY_SIZE>(&mut map, "remote_static_public")?;
    let grants_hash = GrantsHash::reconstruct(&take_bytes(&mut map, "grants_hash")?)
        .map_err(|_| PairRecordCodecError::InvalidInput)?;
    let profiles = take_text_array(&mut map, "profiles")?
        .into_iter()
        .map(|name| ProfileName::parse(&name).ok_or(PairRecordCodecError::InvalidInput))
        .collect::<Result<Vec<_>, _>>()?;
    let created_at_ms = take_unsigned(&mut map, "created_at_ms")?;
    let storage_confirmed = take_bool(&mut map, "storage_confirmed")?;
    let forgotten_at_ms = match map.remove("forgotten_at_ms") {
        Some(WireValue::Null) => None,
        Some(WireValue::Unsigned(at_ms)) => Some(at_ms),
        _ => return Err(PairRecordCodecError::InvalidInput),
    };
    if !map.is_empty() {
        return Err(PairRecordCodecError::InvalidInput);
    }
    let record = PairRecord::new(
        pair_id,
        role,
        local_static_private,
        local_static_public,
        remote_static_public,
        grants_hash,
        profiles,
        created_at_ms,
    )
    .map_err(PairRecordCodecError::InvalidRecord)?;
    let record = if storage_confirmed {
        record
    } else {
        record.awaiting_storage_confirmation()
    };
    Ok(match forgotten_at_ms {
        Some(at_ms) => record.forgotten(at_ms),
        None => record,
    })
}

/// Serializes multiple [`PairRecord`]s to deterministic CBOR.
///
/// # Errors
/// [`PairRecordCodecError::ProtocolFailure`] if serialization fails.
pub fn encode_pair_records(records: &[PairRecord]) -> Result<Vec<u8>, PairRecordCodecError> {
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        entries.push(WireValue::Bytes(encode_pair_record(record)?));
    }
    encode_deterministic_cbor(&WireValue::Array(entries))
        .map_err(|_| PairRecordCodecError::ProtocolFailure)
}

/// Deserializes multiple [`PairRecord`]s from deterministic CBOR.
///
/// # Errors
/// [`PairRecordCodecError`] on malformed CBOR or invalid record entries.
pub fn decode_pair_records(bytes: &[u8]) -> Result<Vec<PairRecord>, PairRecordCodecError> {
    let WireValue::Array(entries) =
        decode_deterministic_cbor(bytes).map_err(|_| PairRecordCodecError::InvalidInput)?
    else {
        return Err(PairRecordCodecError::InvalidInput);
    };
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let WireValue::Bytes(record_bytes) = entry else {
            return Err(PairRecordCodecError::InvalidInput);
        };
        records.push(decode_pair_record(&record_bytes)?);
    }
    Ok(records)
}

fn take_value(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<WireValue, PairRecordCodecError> {
    map.remove(key).ok_or(PairRecordCodecError::InvalidInput)
}

fn take_bytes(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<Vec<u8>, PairRecordCodecError> {
    match take_value(map, key)? {
        WireValue::Bytes(value) => Ok(value),
        _ => Err(PairRecordCodecError::InvalidInput),
    }
}

fn take_array<const SIZE: usize>(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<[u8; SIZE], PairRecordCodecError> {
    take_bytes(map, key)?
        .try_into()
        .map_err(|_| PairRecordCodecError::InvalidInput)
}

fn take_text(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<String, PairRecordCodecError> {
    match take_value(map, key)? {
        WireValue::Text(value) => Ok(value),
        _ => Err(PairRecordCodecError::InvalidInput),
    }
}

fn take_unsigned(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<u64, PairRecordCodecError> {
    match take_value(map, key)? {
        WireValue::Unsigned(value) => Ok(value),
        _ => Err(PairRecordCodecError::InvalidInput),
    }
}

fn take_bool(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<bool, PairRecordCodecError> {
    match take_value(map, key)? {
        WireValue::Bool(value) => Ok(value),
        _ => Err(PairRecordCodecError::InvalidInput),
    }
}

fn take_text_array(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<Vec<String>, PairRecordCodecError> {
    let WireValue::Array(values) = take_value(map, key)? else {
        return Err(PairRecordCodecError::InvalidInput);
    };
    values
        .into_iter()
        .map(|value| match value {
            WireValue::Text(value) => Ok(value),
            _ => Err(PairRecordCodecError::InvalidInput),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        EndpointRole, GrantsHash, PairId, PairRecord, ProfileName, REVOCATION_NOTICE_MS,
        decode_pair_record, decode_pair_records, encode_pair_record, encode_pair_records,
    };

    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;

    #[test]
    fn a_forgotten_record_round_trips_and_serves_nothing() {
        let forgotten = test_record(0x42).forgotten(FORGOTTEN_AT_MS);
        let decoded =
            decode_pair_record(&encode_pair_record(&forgotten).expect("encode")).expect("decode");
        assert_eq!(decoded.forgotten_at_ms(), Some(FORGOTTEN_AT_MS));
        assert!(decoded.serving_profiles().is_empty());
        assert!(!test_record(0x42).serving_profiles().is_empty());
    }

    #[test]
    fn a_forgotten_record_keeps_its_key_for_the_notice_window() {
        let forgotten = test_record(0x42).forgotten(FORGOTTEN_AT_MS);
        assert!(!forgotten.revocation_notice_expired(FORGOTTEN_AT_MS + REVOCATION_NOTICE_MS - 1));
        assert!(forgotten.revocation_notice_expired(FORGOTTEN_AT_MS + REVOCATION_NOTICE_MS));
        assert!(!test_record(0x42).revocation_notice_expired(u64::MAX));
    }

    fn test_record(id_byte: u8) -> PairRecord {
        PairRecord::new(
            PairId::from_array([id_byte; 16]),
            EndpointRole::Requester,
            [id_byte.wrapping_add(2); 32],
            [id_byte.wrapping_add(3); 32],
            [id_byte.wrapping_add(4); 32],
            GrantsHash::from_array([id_byte.wrapping_add(5); 32]),
            vec![ProfileName::Authentication, ProfileName::CardStatus],
            1_700_000_000_000,
        )
        .expect("valid pair record")
    }

    #[test]
    fn single_pair_record_round_trips() {
        let original = test_record(0x42);
        let encoded = encode_pair_record(&original).expect("encode succeeds");
        let decoded = decode_pair_record(&encoded).expect("decode succeeds");

        assert_eq!(original.pair_id(), decoded.pair_id());
        assert_eq!(original.role(), decoded.role());
        assert_eq!(
            original.local_static_private(),
            decoded.local_static_private()
        );
        assert_eq!(
            original.local_static_public(),
            decoded.local_static_public()
        );
        assert_eq!(
            original.remote_static_public(),
            decoded.remote_static_public()
        );
        assert_eq!(original.grants_hash(), decoded.grants_hash());
        assert_eq!(original.profiles(), decoded.profiles());
        assert_eq!(original.created_at_ms(), decoded.created_at_ms());
        assert!(decoded.is_storage_confirmed());
    }

    #[test]
    fn an_unconfirmed_record_round_trips_unconfirmed() {
        let original = test_record(0x42).awaiting_storage_confirmation();
        assert!(!original.is_storage_confirmed());
        let encoded = encode_pair_record(&original).expect("encode succeeds");
        let decoded = decode_pair_record(&encoded).expect("decode succeeds");
        assert!(!decoded.is_storage_confirmed());
        assert!(decoded.storage_confirmed().is_storage_confirmed());
    }

    #[test]
    fn multiple_pair_records_round_trip() {
        let records = vec![test_record(0x11), test_record(0x22), test_record(0x33)];
        let encoded = encode_pair_records(&records).expect("encode records succeeds");
        let decoded = decode_pair_records(&encoded).expect("decode records succeeds");

        assert_eq!(records.len(), decoded.len());
        for (orig, dec) in records.iter().zip(decoded.iter()) {
            assert_eq!(orig.pair_id(), dec.pair_id());
            assert_eq!(orig.local_static_private(), dec.local_static_private());
        }
    }
}
