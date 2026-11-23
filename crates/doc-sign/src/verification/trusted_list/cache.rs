// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

//! The EU trusted lists the trust anchors come from, fetched and kept in
//! a cache directory the shell names.
//!
//! [`super`] reads and verifies the lists and writes no file; this module
//! fetches them, stores what was fetched and hands it back. The cache is
//! one directory holding one file per list: its record as `key: value`
//! lines (`location`, `fetched-at`, `next-update`), one blank line, then
//! the list's bytes as fetched. Each file is written atomically
//! (temporary file, `fsync`, rename); on Unix the directory is `0700`
//! and the files `0600`, elsewhere the directory's inherited access
//! applies. The lists are public and every signature is verified again
//! on each read.
//!
//! On each run the cached lists are read back, every signature verified
//! again, and used as they are while none is due: the lists are fetched
//! afresh when there is no cache, a cached list no longer reads, the
//! Finnish list is missing, one is past its `NextUpdate`, the cache is
//! older than [`REFRESH_AFTER`], or the caller asks ([`Refresh::Now`]).
//! A fetch that leaves them due is not tried again for [`RETRY_AFTER`],
//! recorded in an `attempted-at` file. A national list that fails in a
//! refresh keeps its last cached copy; a list of the lists that fails
//! leaves every cached list in use and the report says how old they are.
//! With no list at all there is no anchor, and
//! [`AnchorSource::Unavailable`] says why: the software ships no root.
//!
//! The shell brings two things this module has no platform for: the
//! cache directory ([`ListCache::at`], resolved from the platform's
//! variables at the shell's edge) and the network, as the `get` closure
//! [`run_anchors`] fetches through (over the crate's HTTP transport,
//! which the shell installs) and the progress sink [`prefetching_get`]
//! counts into. Diagnostics go to the shell's log through the `report`
//! closure as [`CacheEvent`]s.

use core::time::Duration;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use super::super::{AnchorRole, TrustAnchors};
use super::{
    CachedList, LOTL_LOCATION, ListFailure, ListPointer, NationalList, TrustedList,
    TrustedListError, TrustedLists,
};
use crate::uri::Uri;
use refineid_cms::x509::{DateTime, OwnedCert};
use sha2::{Digest as _, Sha256};

/// Seconds in a day.
const SECONDS_PER_DAY: u64 = 86_400;
/// Days a cache is used before it is fetched again although no list
/// is past its `NextUpdate`.
const REFRESH_AFTER_DAYS: u64 = 30;
/// How old the cache may grow before a run fetches the lists again
/// although no list is past its `NextUpdate`. `ETSI TS 119 612` clause
/// 5.3.15 lets an operator set the next update up to six months ahead,
/// and operators reissue a list whenever a service's status changes,
/// often monthly; a month-old cache therefore misses a withdrawal the
/// list's own schedule would announce only later.
pub const REFRESH_AFTER: Duration = Duration::from_secs(REFRESH_AFTER_DAYS * SECONDS_PER_DAY);
/// Seconds in an hour.
const SECONDS_PER_HOUR: u64 = 3_600;
/// How long after a fetch a run that finds the lists still due uses
/// them as they are instead of fetching again. A fetch can leave them
/// due through no fault of this computer: an operator late with its
/// next list keeps a list past its `NextUpdate`, and a list that does
/// not arrive keeps its old copy. Without this pause every run would
/// download every list again, some 30 MB, until the operator or the
/// network recovered; an hour bounds that to one download an hour,
/// far inside the [`REFRESH_AFTER`] a fresh cache is trusted for.
pub const RETRY_AFTER: Duration = Duration::from_secs(SECONDS_PER_HOUR);

/// File extension of one stored list.
const LIST_EXTENSION: &str = "list";
/// File extension of a list being written.
const TEMPORARY_EXTENSION: &str = "tmp";
/// Random bytes appended to each staging file name so writers do not collide
/// on a predictable path.
const TEMP_SUFFIX_BYTES: usize = 8;
/// Maximum exclusive-create attempts before failing closed on staging-path
/// collisions.
const MAX_TEMP_ATTEMPTS: usize = 8;
/// Zero fill byte used when initializing the random staging-suffix buffer.
const ZERO_BYTE: u8 = 0;
/// Win32 `FILE_FLAG_OPEN_REPARSE_POINT` (`CreateFileW`): prevents following a
/// symlink or reparse point (including a dangling symlink) when opening a
/// staging file exclusively on Windows.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// How many national lists are downloaded at once. One after another
/// the thirty-odd EU lists, some 30 MB, take as long as their sum,
/// tens of seconds; eight at a time bring that near the slowest
/// server's time without opening a connection to every operator at
/// once.
const PARALLEL_FETCHES: usize = 8;
/// The file holding when the lists were last fetched or tried.
const ATTEMPT_FILE: &str = "attempted-at";
/// Owner-only directory permissions, on Unix.
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o700;
/// Owner-only file permissions, on Unix.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// The record key of the list's location.
const KEY_LOCATION: &str = "location";
/// The record key of the fetch time.
const KEY_FETCHED_AT: &str = "fetched-at";
/// The record key of the list's next update.
const KEY_NEXT_UPDATE: &str = "next-update";
/// The separator of a record key and its value.
const KEY_SEPARATOR: &str = ": ";
/// The value of `next-update` for a closed list.
const NO_NEXT_UPDATE: &str = "-";
/// How many lists of the lists one set holds.
const LISTS_OF_THE_LISTS: usize = 1;
/// What ends the record, its last line and one blank line, and starts
/// the list's bytes.
const RECORD_END: &[u8] = b"\n\n";

/// The `SchemeTerritory` of Finland's national list: the ISO 3166-1
/// alpha-2 code `ETSI TS 119 612` clause 5.3.10 names a member
/// state's list by. FINEID cards chain to the services it lists.
pub const FINNISH_TERRITORY: &str = "FI";

/// Why the Finnish national list gave no anchors while other lists
/// did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinnishListGap {
    /// The list of the lists points at no Finnish list.
    NotPointedAt,
    /// The list it points at did not arrive or read.
    Failed(ListFailure),
}

impl core::fmt::Display for FinnishListGap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotPointedAt => f.write_str("the list of the lists points at none"),
            Self::Failed(failure) => write!(f, "{failure}"),
        }
    }
}

/// Why the Finnish list in `lists` gave no anchors, or `None` when it
/// read.
fn finnish_gap(lists: &TrustedLists) -> Option<FinnishListGap> {
    let mut gap = Some(FinnishListGap::NotPointedAt);
    for list in lists
        .national()
        .iter()
        .filter(|list| list.territory() == FINNISH_TERRITORY)
    {
        match list.outcome() {
            Ok(_) => return None,
            Err(failure) => {
                if gap == Some(FinnishListGap::NotPointedAt) {
                    gap = Some(FinnishListGap::Failed(failure));
                }
            }
        }
    }
    gap
}

/// When a run fetches the lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    /// When the cache is missing, unreadable, past a list's
    /// `NextUpdate` or older than [`REFRESH_AFTER`].
    WhenDue,
    /// Before judging anything, whatever the cache holds.
    Now,
    /// Never: the cached lists as they are, stale or not, and no
    /// anchor when there are none. `--offline`.
    CacheOnly,
}

/// Where the anchors of one run came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorSource {
    /// The trusted lists fetched at `fetched_at`.
    Lists {
        /// When the lists were fetched; the oldest list's time when
        /// a refresh kept a cached national list.
        fetched_at: DateTime,
        /// Whether a list is past its `NextUpdate`.
        stale: bool,
    },
    /// No list is at hand: none was ever fetched, or the cache no
    /// longer reads and the fetch failed as the error says. Nothing
    /// anchors anything.
    Unavailable(TrustedListError),
}

impl core::fmt::Display for AnchorSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lists { fetched_at, stale } => {
                write!(f, "trusted lists fetched {fetched_at}")?;
                if *stale {
                    f.write_str(", past their next update")?;
                }
                Ok(())
            }
            Self::Unavailable(error) => {
                write!(
                    f,
                    "trusted lists not fetched yet, nothing can be anchored: {error}"
                )
            }
        }
    }
}

/// The anchors of one run and where they came from.
#[derive(Debug)]
pub struct RunAnchors {
    /// The anchors.
    pub anchors: TrustAnchors,
    /// Where they came from.
    pub source: AnchorSource,
    /// Why the Finnish list gave no anchors when other lists are at
    /// hand; `None` when it read or when no list is at hand at all.
    pub finnish_gap: Option<FinnishListGap>,
}

/// What happened fetching or caching the lists, for the shell's log.
/// The run carries on; these name what it carried on past.
#[derive(Debug, Clone, Copy)]
pub enum CacheEvent {
    /// The cached records did not read; a fetch was tried instead.
    CachedListsUnreadable {
        /// Why.
        error: TrustedListError,
    },
    /// Freshly fetched lists could not be stored; they anchor this
    /// run and the cache keeps its old records.
    ListsNotCached {
        /// The I/O failure's kind.
        error: std::io::ErrorKind,
    },
    /// The fetch failed; the cached lists, if any, are in use.
    ListsNotFetched {
        /// Why.
        error: TrustedListError,
    },
    /// The fetch time could not be recorded; the next run tries again
    /// at once.
    AttemptNotRecorded {
        /// The I/O failure's kind.
        error: std::io::ErrorKind,
    },
}

/// The lists' cache directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCache {
    /// The directory.
    directory: PathBuf,
}

impl ListCache {
    /// The cache in `directory`.
    #[must_use]
    pub const fn at(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Every stored record that reads; files that do not are skipped.
    #[must_use]
    pub fn load(&self) -> Vec<CachedList> {
        let Ok(entries) = fs::read_dir(&self.directory) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == LIST_EXTENSION))
            .filter_map(|path| fs::read(path).ok())
            .filter_map(|bytes| decode(&bytes))
            .collect()
    }

    /// Replace the stored lists by `records`: each written atomically,
    /// then every stored list not among them removed.
    ///
    /// # Errors
    /// The I/O error of the first file that could not be written.
    pub fn store(&self, records: &[CachedList]) -> std::io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(DIRECTORY_MODE);
        builder.create(&self.directory)?;
        let mut kept = Vec::new();
        for record in records {
            let path = self.path_for(record.location());
            write_atomically(&path, &encode(record))?;
            kept.push(path);
        }
        for entry in fs::read_dir(&self.directory)?.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == LIST_EXTENSION) && !kept.contains(&path) {
                let _removed = fs::remove_file(path);
            }
        }
        Ok(())
    }

    /// Whether the cache holds no list file: a fetch into it is the
    /// first download.
    #[must_use]
    pub fn holds_no_list(&self) -> bool {
        fs::read_dir(&self.directory).map_or(true, |entries| {
            !entries.filter_map(Result::ok).any(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == LIST_EXTENSION)
            })
        })
    }

    /// When a fetch was last tried into this cache, if one was and
    /// its record reads.
    fn attempted_at(&self) -> Option<DateTime> {
        let bytes = fs::read(self.directory.join(ATTEMPT_FILE)).ok()?;
        core::str::from_utf8(&bytes).ok()?.trim().parse().ok()
    }

    /// Record that a fetch was tried at `now`.
    ///
    /// # Errors
    /// The I/O error of the write.
    fn mark_attempt(&self, now: DateTime) -> std::io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(DIRECTORY_MODE);
        builder.create(&self.directory)?;
        write_atomically(
            &self.directory.join(ATTEMPT_FILE),
            now.to_string().as_bytes(),
        )
    }

    /// The file of the list at `location`: the SHA-256 of the location
    /// in lowercase hex.
    fn path_for(&self, location: &Uri) -> PathBuf {
        let name = hex::encode(Sha256::digest(location.to_string().as_bytes()));
        self.directory.join(name).with_extension(LIST_EXTENSION)
    }
}

/// The anchors of a run at `now`.
///
/// The lists in `cache` are read under `signers`, every signature
/// verified again, and used as they are unless a fetch is due:
/// `refresh` is [`Refresh::Now`], there are no lists, or, unless a
/// fetch was tried within [`RETRY_AFTER`], one no longer reads, the
/// Finnish list is missing, one is past its `NextUpdate`, or the cache
/// is older than [`REFRESH_AFTER`]. A due fetch reads the lists again
/// with `get` and the cache takes the result; a list of the lists that
/// does not arrive or read leaves the cached lists in use. Under
/// [`Refresh::CacheOnly`] nothing is fetched and `get` is never
/// called. Without lists there is no anchor.
///
/// What the run carries on past is reported through `report` as
/// [`CacheEvent`]s, for the shell's log.
pub fn run_anchors(
    cache: Option<&ListCache>,
    now: DateTime,
    refresh: Refresh,
    signers: &[OwnedCert],
    get: impl FnMut(&Uri) -> Option<Vec<u8>>,
    report: &mut dyn FnMut(CacheEvent),
) -> RunAnchors {
    let records = cache.map(ListCache::load).unwrap_or_default();
    let cached = (!records.is_empty())
        .then(|| match TrustedLists::from_cache(&records, signers) {
            Ok(lists) => Some(lists),
            Err(error) => {
                report(CacheEvent::CachedListsUnreadable { error });
                None
            }
        })
        .flatten();
    let due = |lists: &TrustedLists| match refresh {
        Refresh::Now => true,
        Refresh::CacheOnly => false,
        Refresh::WhenDue => {
            let recently_tried = cache
                .and_then(ListCache::attempted_at)
                .is_some_and(|at| at <= now && age(at, now) < RETRY_AFTER);
            !recently_tried
                && (lists.is_stale(now)
                    || records.iter().any(|record| record.fetched_at() > now)
                    || age(lists.fetched_at(), now) > REFRESH_AFTER
                    || read_count(lists) != records.len()
                    || finnish_gap(lists).is_some())
        }
    };
    let lists = match cached {
        Some(lists) if !due(&lists) => Ok(lists),
        None if refresh == Refresh::CacheOnly => Err(TrustedListError::NotFetched),
        cached => match fetch_and_mark(cache, get, now, signers, &records, report) {
            Ok((lists, fetched)) => {
                if let Some(cache) = cache
                    && let Err(error) = cache.store(&fetched)
                {
                    report(CacheEvent::ListsNotCached {
                        error: error.kind(),
                    });
                }
                Ok(lists)
            }
            Err(error) => {
                report(CacheEvent::ListsNotFetched { error });
                cached.ok_or(error)
            }
        },
    };
    match lists {
        Ok(lists) => RunAnchors {
            anchors: TrustAnchors::from_trusted_lists(&lists),
            source: AnchorSource::Lists {
                fetched_at: lists.fetched_at(),
                stale: lists.is_stale(now),
            },
            finnish_gap: finnish_gap(&lists),
        },
        Err(error) => RunAnchors {
            anchors: without_lists(),
            source: AnchorSource::Unavailable(error),
            finnish_gap: None,
        },
    }
}

/// The anchors a run has with no list at hand: none. The software
/// ships no root a chain could end at.
fn without_lists() -> TrustAnchors {
    TrustAnchors::default()
}

/// The DER of every anchor in `anchors` trusted for
/// [`AnchorRole::CertificateIssuing`] at `now`: what a signing
/// request's `signer_anchors` takes from the lists.
#[must_use]
pub fn certificate_issuing_ders(anchors: &TrustAnchors, now: DateTime) -> Vec<Vec<u8>> {
    anchors
        .anchors()
        .iter()
        .filter(|anchor| anchor.role() == AnchorRole::CertificateIssuing)
        .filter(|anchor| anchors.is_anchor(anchor.certificate().view(), anchor.role(), now))
        .map(|anchor| anchor.certificate().as_der().to_vec())
        .collect()
}

/// How long ago `then` was at `now`; nothing when `then` is later.
fn age(then: DateTime, now: DateTime) -> Duration {
    now.unix_duration().saturating_sub(then.unix_duration())
}

/// [`fetch`], then record in `cache` that a fetch was tried at `now`,
/// whatever came of it, when the cache holds lists to fall back on:
/// with none, every run tries again.
fn fetch_and_mark(
    cache: Option<&ListCache>,
    get: impl FnMut(&Uri) -> Option<Vec<u8>>,
    now: DateTime,
    signers: &[OwnedCert],
    previous: &[CachedList],
    report: &mut dyn FnMut(CacheEvent),
) -> Result<(TrustedLists, Vec<CachedList>), TrustedListError> {
    let fetched = fetch(get, now, signers, previous);
    if let Some(cache) = cache
        && (fetched.is_ok() || !previous.is_empty())
        && let Err(error) = cache.mark_attempt(now)
    {
        report(CacheEvent::AttemptNotRecorded {
            error: error.kind(),
        });
    }
    fetched
}

/// Fetch the lists afresh with `get` at `now`: the list of the lists
/// from [`LOTL_LOCATION`], read under `signers`, then each national
/// list it points at. A national list that does not arrive or read
/// keeps its record among `previous`, when there is one, and every
/// list is then read again from the records. A list the new list of
/// the lists no longer points at is not among the records returned.
///
/// # Errors
/// [`TrustedListError`] when the list of the lists does not arrive or
/// does not read.
fn fetch(
    mut get: impl FnMut(&Uri) -> Option<Vec<u8>>,
    now: DateTime,
    signers: &[OwnedCert],
    previous: &[CachedList],
) -> Result<(TrustedLists, Vec<CachedList>), TrustedListError> {
    let lotl_location =
        Uri::parse(LOTL_LOCATION.to_owned()).map_err(|_| TrustedListError::NotFetched)?;
    let lotl = get(&lotl_location).ok_or(TrustedListError::NotFetched)?;
    let (fresh, fetched) = TrustedLists::read(lotl, signers, &mut get, now)?;
    let kept: Vec<CachedList> = fresh
        .national()
        .iter()
        .filter(|list| list.outcome().is_err())
        .filter_map(NationalList::location)
        .filter_map(|location| previous.iter().find(|record| record.location() == location))
        .cloned()
        .collect();
    if kept.is_empty() {
        return Ok((fresh, fetched));
    }
    let mut records = fetched.clone();
    records.extend(kept);
    let Ok(lists) = TrustedLists::from_cache(&records, signers) else {
        return Ok((fresh, fetched));
    };
    records.retain(|record| {
        *record.location() == lotl_location
            || lists
                .national()
                .iter()
                .any(|list| list.location() == Some(record.location()) && list.outcome().is_ok())
    });
    Ok((lists, records))
}

/// `get`, except that fetching the list of the lists also downloads
/// every national list it points at, eight at a time, for the
/// requests that follow to take, each arrival counted into `progress`
/// as `(fetched, total)`. Only a list of the lists that verifies
/// under `signers` is followed.
pub fn prefetching_get<'a>(
    signers: &'a [OwnedCert],
    get: impl Fn(&Uri) -> Option<Vec<u8>> + Sync + 'a,
    progress: &'a (dyn Fn(usize, usize) + Sync),
) -> impl FnMut(&Uri) -> Option<Vec<u8>> + 'a {
    let mut prefetched: Vec<(Uri, Option<Vec<u8>>)> = Vec::new();
    move |location| {
        if location.to_string() == LOTL_LOCATION {
            let lotl = get(location)?;
            prefetched = TrustedList::read(lotl.clone(), signers)
                .map(|list| {
                    prefetch(&national_locations(&list), &get, &|fetched, total| {
                        progress(fetched, total);
                    })
                })
                .unwrap_or_default();
            return Some(lotl);
        }
        match prefetched.iter().position(|(at, _)| at == location) {
            Some(index) => prefetched.swap_remove(index).1,
            None => get(location),
        }
    }
}

/// The locations of the national lists `lotl` points at, as
/// [`TrustedLists::read`] follows them.
fn national_locations(lotl: &TrustedList) -> Vec<Uri> {
    lotl.pointers()
        .iter()
        .filter(|pointer| pointer.names_national_list())
        .filter_map(ListPointer::location)
        .cloned()
        .collect()
}

/// Each of `locations` with what `get` returned for it, fetched by
/// [`PARALLEL_FETCHES`] threads at once; `fetched` hears how many of
/// them have arrived after each one.
fn prefetch(
    locations: &[Uri],
    get: impl Fn(&Uri) -> Option<Vec<u8>> + Sync,
    fetched: &(dyn Fn(usize, usize) + Sync),
) -> Vec<(Uri, Option<Vec<u8>>)> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(Uri, Option<Vec<u8>>)>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..PARALLEL_FETCHES.min(locations.len()) {
            scope.spawn(|| {
                while let Some(location) = locations.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let bytes = get(location);
                    let mut results = results.lock().unwrap_or_else(PoisonError::into_inner);
                    results.push((location.clone(), bytes));
                    fetched(results.len(), locations.len());
                }
            });
        }
    });
    results.into_inner().unwrap_or_else(PoisonError::into_inner)
}

/// How many of `lists` read: the list of the lists and every national
/// list that did. Only lists that read are stored, so a cache that
/// yields fewer than it holds has a list that no longer reads.
fn read_count(lists: &TrustedLists) -> usize {
    LISTS_OF_THE_LISTS
        + lists
            .national()
            .iter()
            .filter(|list| list.outcome().is_ok())
            .count()
}

/// The stored form of `record`.
fn encode(record: &CachedList) -> Vec<u8> {
    let next_update = record
        .next_update()
        .map_or_else(|| NO_NEXT_UPDATE.to_owned(), |due| due.to_string());
    let mut out = String::new();
    for (key, value) in [
        (KEY_LOCATION, record.location().to_string()),
        (KEY_FETCHED_AT, record.fetched_at().to_string()),
        (KEY_NEXT_UPDATE, next_update),
    ] {
        out.push_str(key);
        out.push_str(KEY_SEPARATOR);
        out.push_str(&value);
        out.push('\n');
    }
    out.push('\n');
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(record.bytes());
    bytes
}

/// The record `bytes` store, if they read.
fn decode(bytes: &[u8]) -> Option<CachedList> {
    let end = bytes
        .windows(RECORD_END.len())
        .position(|window| window == RECORD_END)?;
    let (head, rest) = bytes.split_at(end);
    let list = rest.get(RECORD_END.len()..)?.to_vec();
    let head = core::str::from_utf8(head).ok()?;
    let mut lines = head.lines().map(|line| line.split_once(KEY_SEPARATOR));
    let mut value = |key: &str| match lines.next() {
        Some(Some((found, value))) if found == key => Some(value),
        _ => None,
    };
    let location = Uri::parse(value(KEY_LOCATION)?.to_owned()).ok()?;
    let fetched_at = value(KEY_FETCHED_AT)?.parse().ok()?;
    let next_update = match value(KEY_NEXT_UPDATE)? {
        NO_NEXT_UPDATE => None,
        due => Some(due.parse().ok()?),
    };
    if lines.next().is_some() {
        return None;
    }
    Some(CachedList::new(location, fetched_at, next_update, list))
}

/// Build the sibling staging path for `path` with `suffix`.
fn temporary_path(path: &Path, suffix: &str) -> PathBuf {
    path.with_extension(format!("{TEMPORARY_EXTENSION}.{suffix}"))
}

/// Generate a random hex suffix for an exclusive staging file.
fn random_temp_suffix() -> std::io::Result<String> {
    let mut random = [ZERO_BYTE; TEMP_SUFFIX_BYTES];
    getrandom::fill(&mut random)
        .map_err(|error| std::io::Error::other(format!("staging-file entropy failed: {error}")))?;
    Ok(hex::encode(random))
}

/// Return the Unix `O_NOFOLLOW` open flag, failing closed if it cannot be
/// represented as `i32`.
#[cfg(unix)]
fn no_follow_flag() -> std::io::Result<i32> {
    i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
        .map_err(|_| std::io::Error::other("O_NOFOLLOW flag does not fit in i32"))
}

/// Return whether an exclusive staging-file open error indicates a path
/// collision (existing file or symlink) that should retry with a fresh name.
fn is_retryable_temp_open_error(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        return true;
    }
    #[cfg(unix)]
    if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
        return true;
    }
    false
}

/// Write `bytes` to `path` atomically, owner-only on Unix.
///
/// # Errors
/// The I/O error of the write; any newly created temporary file is removed on
/// failure.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomically_with_suffix(path, bytes, random_temp_suffix)
}

/// Write `bytes` to `path` atomically using exclusive staging-file creation
/// (`create_new(true)` and `O_NOFOLLOW` on Unix) with bounded retries over
/// `next_suffix`.
fn write_atomically_with_suffix<F>(
    path: &Path,
    bytes: &[u8],
    mut next_suffix: F,
) -> std::io::Result<()>
where
    F: FnMut() -> std::io::Result<String>,
{
    #[cfg(unix)]
    let no_follow = no_follow_flag()?;

    for _ in 0..MAX_TEMP_ATTEMPTS {
        let suffix = next_suffix()?;
        let temporary = temporary_path(path, &suffix);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(FILE_MODE);
            options.custom_flags(no_follow);
        }
        #[cfg(windows)]
        {
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file: File = match options.open(&temporary) {
            Ok(file) => file,
            Err(error) if is_retryable_temp_open_error(&error) => continue,
            Err(error) => return Err(error),
        };
        let written = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, path)
        })();
        if written.is_err() {
            let _removed = fs::remove_file(&temporary);
        }
        return written;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate unique temporary file",
    ))
}

#[cfg(test)]
mod tests;
