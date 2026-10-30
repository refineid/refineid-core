//! Durable pairing records and the device-only persistence boundary.
//!
//! RAPP deliberately does not provide an in-memory default store. Platform
//! integrations must place the private key in device-only, non-backup secret
//! storage and make insertion/revocation atomic.

use core::fmt;
use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::wire::encode_deterministic_cbor_into;
use super::{
    EndpointRole, GrantsHash, PairId, ProfileName, WireValue, decode_deterministic_cbor,
    encode_deterministic_cbor,
};

const X25519_KEY_SIZE: usize = 32;

/// Format version for encoded pairing records.
pub const PAIR_RECORD_FORMAT_VERSION: u64 = 7;

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
    last_session_at_ms: Option<u64>,
}

/// Days a forgotten pairing keeps its key to deliver the `pairing_revoked`
/// close on a later session (RAPP v26.10.29 section 4.6 item 3).
pub const REVOCATION_NOTICE_DAYS: u64 = 30;
/// Days a pairing lives without an established session before it expires
/// (RAPP v26.10.29 section 4.6 item 5).
pub const PAIRING_IDLE_EXPIRY_DAYS: u64 = 30;
const MILLISECONDS_PER_DAY: u64 = 86_400_000;
/// How long a forgotten pairing keeps its key for the close.
pub const REVOCATION_NOTICE_MS: u64 = REVOCATION_NOTICE_DAYS * MILLISECONDS_PER_DAY;
/// How long a pairing lives without an established session.
pub const PAIRING_IDLE_EXPIRY_MS: u64 = PAIRING_IDLE_EXPIRY_DAYS * MILLISECONDS_PER_DAY;

/// What an idle-expiry sweep did with one pairing (RAPP v26.10.29 section
/// 4.6 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepOutcome {
    /// A session to the pairing is established: the sweep recorded its time
    /// and the pairing stays.
    Recorded,
    /// Nothing changed: no session is established and the pairing is short
    /// of the idle limit, or the record is not active.
    Kept,
    /// The pairing had no established session for
    /// [`PAIRING_IDLE_EXPIRY_DAYS`]: the record is forgotten at the sweep's
    /// time and keeps its key only for the close (section 4.6 items 2 to
    /// 4). Nothing is sent and no user is told.
    Expired,
}

/// Why a sweep changed nothing although its pairing needed a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepError<E> {
    /// The changed record could not be encoded; nothing was handed to the
    /// store.
    Encoding(PairRecordCodecError),
    /// The store refused the changed record. The record is as it was, and
    /// the next sweep repeats the whole step.
    Store(E),
}

impl<E: fmt::Display> fmt::Display for SweepError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "the swept record did not encode: {error}"),
            Self::Store(error) => write!(formatter, "the store refused the swept record: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> core::error::Error for SweepError<E> {}

/// A pair record in its stored form, on its way to or from the
/// device-only store. It carries the static private key, so it is zeroized
/// on drop, cannot be cloned, and formats without its bytes. Only
/// [`encode_pair_record`] builds one from a record, and only
/// [`decode_pair_record`] reads one back.
pub struct EncodedPairRecord(Zeroizing<Vec<u8>>);

impl EncodedPairRecord {
    /// Take custody of bytes read back from the device-only store. They
    /// are zeroized when this value drops; [`decode_pair_record`] checks
    /// them.
    #[must_use]
    pub fn from_stored(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The bytes the device-only store writes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for EncodedPairRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedPairRecord([redacted])")
    }
}

/// The times a sweep leaves in one record and what it did, decided before
/// anything changes so that the store commits first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SweepPlan {
    outcome: SweepOutcome,
    last_session_at_ms: Option<u64>,
    forgotten_at_ms: Option<u64>,
}

/// The later of a recorded session time and a new reading.
const fn later_session(recorded_ms: Option<u64>, at_ms: u64) -> u64 {
    match recorded_ms {
        Some(recorded_ms) if recorded_ms >= at_ms => recorded_ms,
        _ => at_ms,
    }
}

impl PairRecord {
    /// Constructs a validated pairing record whose storage the peer has
    /// confirmed. The pairing flow builds its record unconfirmed and
    /// confirms it only through an [`ActivePairing`](crate::ActivePairing)
    /// (RAPP v26.10.29 section 4.3 item 4).
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
            last_session_at_ms: None,
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

    /// When its user forgot the pairing, or it expired (section 4.6 item 5),
    /// while no session was open: the record serves nothing from then on
    /// and keeps its key only to deliver the `pairing_revoked` close on the
    /// next session (section 4.6 item 2).
    #[must_use]
    pub const fn forgotten_at_ms(&self) -> Option<u64> {
        self.forgotten_at_ms
    }

    /// The record its user forgot, or that expired, at `at_ms`, kept for the
    /// close. A record already forgotten keeps its first time, so the notice
    /// window of section 4.6 item 3 runs from the revocation.
    #[must_use]
    pub const fn forgotten(mut self, at_ms: u64) -> Self {
        if self.forgotten_at_ms.is_none() {
            self.forgotten_at_ms = Some(at_ms);
        }
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

    /// The latest wall-clock time, in milliseconds since the Unix epoch, at
    /// which the pairing had an established session, or `None` while it has
    /// had none (section 4.6 item 5).
    #[must_use]
    pub const fn last_session_at_ms(&self) -> Option<u64> {
        self.last_session_at_ms
    }

    /// The record whose pairing had an established session at `at_ms`,
    /// milliseconds since the Unix epoch, as stored. The recorded time only
    /// moves forward: a time before the one already recorded, as a clock set
    /// back reads, leaves it as it is. The idle time of section 4.6 item 5
    /// runs from the latest time recorded; [`Self::sweep`] is the only way
    /// to record a session.
    #[must_use]
    const fn with_session_at(mut self, at_ms: u64) -> Self {
        self.last_session_at_ms = Some(later_session(self.last_session_at_ms, at_ms));
        self
    }

    /// One pairing's idle-expiry check at `now_ms`, milliseconds since the
    /// Unix epoch (section 4.6 item 5). `session_established` says whether
    /// a session to the pairing is established now. With one, the sweep
    /// records `now_ms` and keeps the pairing, whatever time was recorded
    /// before, so no order of calls expires a pairing in session. Without
    /// one, the pairing expires once [`PAIRING_IDLE_EXPIRY_MS`] have passed
    /// since its latest recorded session, or since its creation while it
    /// has had none. A record that is not active, one the peer never
    /// confirmed or one already forgotten, is kept as it is: section 4.3
    /// item 4 and section 4.6 item 3 govern it.
    ///
    /// A change is stored before it is made: the sweep hands the changed
    /// record, encoded, to `store`, which writes it to the device-only
    /// store, and changes this record only when `store` returned `Ok`. With
    /// nothing to change ([`SweepOutcome::Kept`]) it calls nothing. A
    /// refused store leaves the record as it was, so the next sweep repeats
    /// the whole step.
    ///
    /// The endpoint sweeps every pairing when it starts and at least once a
    /// day, and sweeps a pairing with `session_established` true when a
    /// session to it is established and when that session ends.
    ///
    /// # Errors
    /// [`SweepError::Store`] with the store's error, and
    /// [`SweepError::Encoding`] when the changed record does not encode; the
    /// record is unchanged in both.
    pub fn sweep<E>(
        &mut self,
        now_ms: u64,
        session_established: bool,
        store: impl FnOnce(&EncodedPairRecord) -> Result<(), E>,
    ) -> Result<SweepOutcome, SweepError<E>> {
        let plan = self.plan_sweep(now_ms, session_established);
        if plan.outcome == SweepOutcome::Kept {
            return Ok(plan.outcome);
        }
        let encoded = encode_with_times(self, plan.forgotten_at_ms, plan.last_session_at_ms)
            .map_err(SweepError::Encoding)?;
        store(&encoded).map_err(SweepError::Store)?;
        self.last_session_at_ms = plan.last_session_at_ms;
        self.forgotten_at_ms = plan.forgotten_at_ms;
        Ok(plan.outcome)
    }

    /// What [`Self::sweep`] would leave in this record, without changing it.
    const fn plan_sweep(&self, now_ms: u64, session_established: bool) -> SweepPlan {
        let unchanged = SweepPlan {
            outcome: SweepOutcome::Kept,
            last_session_at_ms: self.last_session_at_ms,
            forgotten_at_ms: self.forgotten_at_ms,
        };
        if !self.storage_confirmed || self.forgotten_at_ms.is_some() {
            return unchanged;
        }
        if session_established {
            return SweepPlan {
                outcome: SweepOutcome::Recorded,
                last_session_at_ms: Some(later_session(self.last_session_at_ms, now_ms)),
                ..unchanged
            };
        }
        if self.idle_limit_reached(now_ms) {
            return SweepPlan {
                outcome: SweepOutcome::Expired,
                forgotten_at_ms: Some(now_ms),
                ..unchanged
            };
        }
        unchanged
    }

    /// Whether [`PAIRING_IDLE_EXPIRY_MS`] have passed at `now_ms` since the
    /// later of the pairing's creation and its latest recorded session.
    const fn idle_limit_reached(&self, now_ms: u64) -> bool {
        let since_ms = match self.last_session_at_ms {
            Some(at_ms) if at_ms > self.created_at_ms => at_ms,
            _ => self.created_at_ms,
        };
        now_ms.saturating_sub(since_ms) >= PAIRING_IDLE_EXPIRY_MS
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

    /// Exposes the private key only to sibling protocol machinery.
    #[must_use]
    pub(crate) fn local_static_private(&self) -> &[u8; X25519_KEY_SIZE] {
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
            .field("last_session_at_ms", &self.last_session_at_ms)
            .finish()
    }
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

/// Serializes a [`PairRecord`] to deterministic CBOR in its stored form.
///
/// # Errors
/// [`PairRecordCodecError::ProtocolFailure`] if serialization fails.
pub fn encode_pair_record(record: &PairRecord) -> Result<EncodedPairRecord, PairRecordCodecError> {
    encode_with_times(
        record,
        record.forgotten_at_ms(),
        record.last_session_at_ms(),
    )
}

/// Map key of the static private key in the stored form.
const LOCAL_STATIC_PRIVATE_KEY: &str = "local_static_private";

/// Encodes `record` with the given times. Every buffer that holds the
/// private key is zeroized: the key's map entry once the encoding is
/// written, and the encoding itself, which is reserved at its final
/// length so that it is never reallocated.
fn encode_with_times(
    record: &PairRecord,
    forgotten_at_ms: Option<u64>,
    last_session_at_ms: Option<u64>,
) -> Result<EncodedPairRecord, PairRecordCodecError> {
    let role = match record.role() {
        EndpointRole::Requester => "requester",
        EndpointRole::Proxy => "proxy",
    };
    let mut value = Zeroizing::new(WireValue::Map(BTreeMap::from([
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
            LOCAL_STATIC_PRIVATE_KEY.to_owned(),
            WireValue::Bytes(vec![0; X25519_KEY_SIZE]),
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
            forgotten_at_ms.map_or(WireValue::Null, WireValue::Unsigned),
        ),
        (
            "last_session_at_ms".to_owned(),
            last_session_at_ms.map_or(WireValue::Null, WireValue::Unsigned),
        ),
    ])));
    // The key is a fixed-size byte string, so the encoding with its
    // placeholder has the final length.
    let length = encode_deterministic_cbor(&value)
        .map_err(|_| PairRecordCodecError::ProtocolFailure)?
        .len();
    if let WireValue::Map(map) = &mut *value
        && let Some(WireValue::Bytes(key)) = map.get_mut(LOCAL_STATIC_PRIVATE_KEY)
    {
        key.copy_from_slice(record.local_static_private());
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(length));
    encode_deterministic_cbor_into(&value, &mut encoded)
        .map_err(|_| PairRecordCodecError::ProtocolFailure)?;
    Ok(EncodedPairRecord(encoded))
}

/// Deserializes a [`PairRecord`] from its stored form. The decoded
/// values are zeroized on every path, the private key included.
///
/// # Errors
/// [`PairRecordCodecError`] on malformed CBOR, invalid keys, unsupported format version,
/// or invariant failure.
pub fn decode_pair_record(encoded: &EncodedPairRecord) -> Result<PairRecord, PairRecordCodecError> {
    let mut value = Zeroizing::new(
        decode_deterministic_cbor(encoded.as_bytes())
            .map_err(|_| PairRecordCodecError::InvalidInput)?,
    );
    let WireValue::Map(map) = &mut *value else {
        return Err(PairRecordCodecError::InvalidInput);
    };
    let expected = [
        "format_version",
        "pair_id",
        "role",
        LOCAL_STATIC_PRIVATE_KEY,
        "local_static_public",
        "remote_static_public",
        "grants_hash",
        "profiles",
        "created_at_ms",
        "storage_confirmed",
        "forgotten_at_ms",
        "last_session_at_ms",
    ];
    if map.keys().any(|key| !expected.contains(&key.as_str())) {
        return Err(PairRecordCodecError::InvalidInput);
    }
    if take_unsigned(map, "format_version")? != PAIR_RECORD_FORMAT_VERSION {
        return Err(PairRecordCodecError::UnsupportedVersion);
    }
    let pair_id = PairId::reconstruct(&take_bytes(map, "pair_id")?)
        .map_err(|_| PairRecordCodecError::InvalidInput)?;
    let role = match take_text(map, "role")?.as_str() {
        "requester" => EndpointRole::Requester,
        "proxy" => EndpointRole::Proxy,
        _ => return Err(PairRecordCodecError::InvalidInput),
    };
    let local_static_private = take_private_key(map)?;
    let local_static_public = take_array::<X25519_KEY_SIZE>(map, "local_static_public")?;
    let remote_static_public = take_array::<X25519_KEY_SIZE>(map, "remote_static_public")?;
    let grants_hash = GrantsHash::reconstruct(&take_bytes(map, "grants_hash")?)
        .map_err(|_| PairRecordCodecError::InvalidInput)?;
    let profiles = take_text_array(map, "profiles")?
        .into_iter()
        .map(|name| ProfileName::parse(&name).ok_or(PairRecordCodecError::InvalidInput))
        .collect::<Result<Vec<_>, _>>()?;
    let created_at_ms = take_unsigned(map, "created_at_ms")?;
    let storage_confirmed = take_bool(map, "storage_confirmed")?;
    let forgotten_at_ms = take_optional_unsigned(map, "forgotten_at_ms")?;
    let last_session_at_ms = take_optional_unsigned(map, "last_session_at_ms")?;
    if !map.is_empty() {
        return Err(PairRecordCodecError::InvalidInput);
    }
    let record = PairRecord::new(
        pair_id,
        role,
        *local_static_private,
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
    let record = match last_session_at_ms {
        Some(at_ms) => record.with_session_at(at_ms),
        None => record,
    };
    Ok(match forgotten_at_ms {
        Some(at_ms) => record.forgotten(at_ms),
        None => record,
    })
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

/// Takes the static private key out of the decoded map. The decoded
/// byte string is zeroized when this returns, whatever its length.
fn take_private_key(
    map: &mut BTreeMap<String, WireValue>,
) -> Result<Zeroizing<[u8; X25519_KEY_SIZE]>, PairRecordCodecError> {
    let decoded = Zeroizing::new(take_bytes(map, LOCAL_STATIC_PRIVATE_KEY)?);
    let mut key = Zeroizing::new([0_u8; X25519_KEY_SIZE]);
    if decoded.len() != X25519_KEY_SIZE {
        return Err(PairRecordCodecError::InvalidInput);
    }
    key.copy_from_slice(&decoded);
    Ok(key)
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

fn take_optional_unsigned(
    map: &mut BTreeMap<String, WireValue>,
    key: &str,
) -> Result<Option<u64>, PairRecordCodecError> {
    match take_value(map, key)? {
        WireValue::Null => Ok(None),
        WireValue::Unsigned(value) => Ok(Some(value)),
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
        EncodedPairRecord, EndpointRole, GrantsHash, MILLISECONDS_PER_DAY,
        PAIRING_IDLE_EXPIRY_DAYS, PAIRING_IDLE_EXPIRY_MS, PairId, PairRecord, ProfileName,
        REVOCATION_NOTICE_MS, SweepError, SweepOutcome, decode_pair_record, encode_pair_record,
    };
    use core::convert::Infallible;

    const CREATED_AT_MS: u64 = 1_700_000_000_000;
    const FORGOTTEN_AT_MS: u64 = 1_800_000_000_000;
    const SESSION_AT_MS: u64 = 1_750_000_000_000;

    /// Sweeps `record` into a store that accepts every write.
    fn swept(record: &mut PairRecord, now_ms: u64, session_established: bool) -> SweepOutcome {
        record
            .sweep(now_ms, session_established, |_| Ok::<(), Infallible>(()))
            .expect("the store accepts")
    }

    #[test]
    fn a_pairing_without_sessions_expires_from_its_creation() {
        let mut record = test_record(0x42);
        assert_eq!(record.last_session_at_ms(), None);
        assert_eq!(
            swept(
                &mut record,
                CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS - 1,
                false
            ),
            SweepOutcome::Kept
        );
        assert_eq!(
            swept(&mut record, CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS, false),
            SweepOutcome::Expired
        );
        assert_eq!(
            record.forgotten_at_ms(),
            Some(CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS)
        );
        assert!(record.serving_profiles().is_empty());
    }

    #[test]
    fn a_recorded_session_renews_the_idle_time() {
        let record = || test_record(0x42).with_session_at(SESSION_AT_MS);
        assert_eq!(
            swept(&mut record(), CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS, false),
            SweepOutcome::Kept
        );
        assert_eq!(
            swept(
                &mut record(),
                SESSION_AT_MS + PAIRING_IDLE_EXPIRY_MS - 1,
                false
            ),
            SweepOutcome::Kept
        );
        assert_eq!(
            swept(&mut record(), SESSION_AT_MS + PAIRING_IDLE_EXPIRY_MS, false),
            SweepOutcome::Expired
        );
    }

    #[test]
    fn the_recorded_session_time_never_moves_back() {
        let mut record = test_record(0x42)
            .with_session_at(SESSION_AT_MS)
            .with_session_at(SESSION_AT_MS - MILLISECONDS_PER_DAY);
        assert_eq!(record.last_session_at_ms(), Some(SESSION_AT_MS));
        assert_eq!(
            swept(&mut record, CREATED_AT_MS, true),
            SweepOutcome::Recorded
        );
        assert_eq!(record.last_session_at_ms(), Some(SESSION_AT_MS));
    }

    #[test]
    fn a_clock_behind_the_last_session_expires_nothing() {
        let mut record = test_record(0x42).with_session_at(SESSION_AT_MS);
        assert_eq!(swept(&mut record, CREATED_AT_MS, false), SweepOutcome::Kept);
    }

    #[test]
    fn a_session_held_open_past_the_idle_limit_never_expires() {
        let mut record = test_record(0x42);
        let mut now_ms = CREATED_AT_MS;
        for _ in 0..PAIRING_IDLE_EXPIRY_DAYS * 2 {
            now_ms += MILLISECONDS_PER_DAY;
            assert_eq!(swept(&mut record, now_ms, true), SweepOutcome::Recorded);
        }
        assert_eq!(record.last_session_at_ms(), Some(now_ms));
        assert_eq!(
            swept(&mut record, now_ms + PAIRING_IDLE_EXPIRY_MS - 1, false),
            SweepOutcome::Kept
        );
        assert_eq!(
            swept(&mut record, now_ms + PAIRING_IDLE_EXPIRY_MS, false),
            SweepOutcome::Expired
        );
    }

    #[test]
    fn a_long_idle_pairing_with_a_session_established_is_recorded_not_expired() {
        let now_ms = CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS * 2;
        let mut record = test_record(0x42);
        assert_eq!(swept(&mut record, now_ms, true), SweepOutcome::Recorded);
        assert_eq!(record.forgotten_at_ms(), None);
        assert_eq!(record.last_session_at_ms(), Some(now_ms));
    }

    #[test]
    fn the_store_receives_the_record_the_sweep_leaves() {
        let now_ms = CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS;
        for session_established in [true, false] {
            let mut record = test_record(0x42);
            let before = encode_pair_record(&record)
                .expect("encode record")
                .as_bytes()
                .to_vec();
            let mut stored = None;
            record
                .sweep(now_ms, session_established, |encoded| {
                    stored = Some(encoded.as_bytes().to_vec());
                    Ok::<(), Infallible>(())
                })
                .expect("the store accepts");
            let stored = stored.expect("a change is stored");
            assert_ne!(stored, before, "the sweep changes the stored times");
            assert_eq!(
                encode_pair_record(&record)
                    .expect("encode swept")
                    .as_bytes(),
                stored
            );
        }
    }

    #[test]
    fn a_sweep_whose_store_failed_is_repeated_whole() {
        let expired_at_ms = CREATED_AT_MS + PAIRING_IDLE_EXPIRY_MS;
        let mut record = test_record(0x42);
        assert_eq!(
            record.sweep(expired_at_ms, false, |_| Err("store unavailable")),
            Err(SweepError::Store("store unavailable"))
        );
        assert_eq!(
            record.forgotten_at_ms(),
            None,
            "a refused store leaves the record as it was"
        );
        let mut stored = None;
        assert_eq!(
            record.sweep(expired_at_ms, false, |encoded| {
                stored = Some(encoded.as_bytes().to_vec());
                Ok::<(), Infallible>(())
            }),
            Ok(SweepOutcome::Expired)
        );
        let stored = decode_pair_record(&EncodedPairRecord::from_stored(
            stored.expect("the retry stores"),
        ))
        .expect("decode");
        assert_eq!(stored.forgotten_at_ms(), Some(expired_at_ms));
        assert_eq!(record.forgotten_at_ms(), Some(expired_at_ms));

        let mut record = test_record(0x42);
        assert!(
            record
                .sweep(SESSION_AT_MS, true, |_| Err("store unavailable"))
                .is_err()
        );
        assert_eq!(record.last_session_at_ms(), None);
        assert_eq!(
            swept(&mut record, SESSION_AT_MS, true),
            SweepOutcome::Recorded
        );
        assert_eq!(record.last_session_at_ms(), Some(SESSION_AT_MS));
    }

    #[test]
    fn a_sweep_that_changes_nothing_stores_nothing() {
        let mut record = test_record(0x42);
        assert_eq!(
            record.sweep(CREATED_AT_MS, false, |_| -> Result<(), Infallible> {
                unreachable!("nothing changed, so nothing is stored")
            }),
            Ok(SweepOutcome::Kept)
        );
    }

    #[test]
    fn a_record_that_is_not_active_is_kept_as_it_is() {
        let mut forgotten = test_record(0x42).forgotten(FORGOTTEN_AT_MS);
        assert_eq!(swept(&mut forgotten, u64::MAX, false), SweepOutcome::Kept);
        assert_eq!(forgotten.forgotten_at_ms(), Some(FORGOTTEN_AT_MS));
        let mut unconfirmed = test_record(0x42).awaiting_storage_confirmation();
        assert_eq!(
            swept(&mut unconfirmed, SESSION_AT_MS, true),
            SweepOutcome::Kept
        );
        assert_eq!(unconfirmed.last_session_at_ms(), None);
    }

    #[test]
    fn the_last_session_round_trips() {
        let original = test_record(0x42).with_session_at(SESSION_AT_MS);
        let decoded =
            decode_pair_record(&encode_pair_record(&original).expect("encode")).expect("decode");
        assert_eq!(decoded.last_session_at_ms(), Some(SESSION_AT_MS));
        let fresh = decode_pair_record(&encode_pair_record(&test_record(0x42)).expect("encode"))
            .expect("decode");
        assert_eq!(fresh.last_session_at_ms(), None);
    }

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

    #[test]
    fn forgetting_again_keeps_the_first_time() {
        let later = FORGOTTEN_AT_MS + REVOCATION_NOTICE_MS / 2;
        let forgotten = test_record(0x42)
            .forgotten(FORGOTTEN_AT_MS)
            .forgotten(later);
        assert_eq!(forgotten.forgotten_at_ms(), Some(FORGOTTEN_AT_MS));
        assert!(!forgotten.revocation_notice_expired(FORGOTTEN_AT_MS + REVOCATION_NOTICE_MS - 1));
        assert!(forgotten.revocation_notice_expired(FORGOTTEN_AT_MS + REVOCATION_NOTICE_MS));
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
            CREATED_AT_MS,
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
    fn the_codec_keeps_the_stored_form_in_custody() {
        let encoded: EncodedPairRecord =
            encode_pair_record(&test_record(0x42)).expect("encode succeeds");
        assert_eq!(format!("{encoded:?}"), "EncodedPairRecord([redacted])");
        let reread = EncodedPairRecord::from_stored(encoded.as_bytes().to_vec());
        let decoded = decode_pair_record(&reread).expect("decode succeeds");
        assert_eq!(decoded.pair_id(), test_record(0x42).pair_id());
    }

    #[test]
    fn a_private_key_of_the_wrong_length_is_refused() {
        let encoded = encode_pair_record(&test_record(0x42)).expect("encode succeeds");
        let crate::WireValue::Map(mut map) =
            crate::decode_deterministic_cbor(encoded.as_bytes()).expect("decodes")
        else {
            panic!("a pair record is a map");
        };
        map.insert(
            super::LOCAL_STATIC_PRIVATE_KEY.to_owned(),
            crate::WireValue::Bytes(vec![0x42; super::X25519_KEY_SIZE - 1]),
        );
        let short = crate::encode_deterministic_cbor(&crate::WireValue::Map(map)).expect("encodes");
        assert_eq!(
            decode_pair_record(&EncodedPairRecord::from_stored(short)).err(),
            Some(super::PairRecordCodecError::InvalidInput)
        );
    }
}
