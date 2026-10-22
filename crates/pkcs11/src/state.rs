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

//! Module and session state.
//!
//! One process-global [`MODULE`] holds the live [`ModuleState`]
//! between `C_Initialize` and `C_Finalize`: the stable slot table,
//! open sessions, the per-token PIN1 login state, and the cached
//! token objects. All access is serialised by a [`Mutex`]; the module
//! advertises Rust-side locking, so it accepts both a NULL
//! `C_Initialize` arg and `CKF_OS_LOCKING_OK`.
//!
//! PIN1 secrecy: the login secret lives only in [`PinSafetyCache`] here,
//! is never logged or rendered, and has no idle window. Besides the
//! invalidation rules the cache enforces itself, it is dropped
//! (zeroized by `PinBytes`) on `C_Logout`, `C_CloseSession` of the last
//! session, card removal, and `C_Finalize`.

use alloc::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use refineid_pcsc::{
    PcscBackend, ReaderAccessCap, ReaderBackend as _, ReaderId, ReaderIdentity, ReaderInfo,
    read_reader_identity,
};
use refineid_pkcs15::{Pkcs15Error, Pkcs15Ops as _};

use crate::pin_cache::PinSafetyCache;
use crate::remote::{RemoteOffer, RemoteTokenSource};
use crate::slot_kind::SlotKind;

use crate::ck::{
    CKF_RW_SESSION, CKR_DEVICE_ERROR, CKR_TOKEN_NOT_PRESENT, CKS_RO_PUBLIC_SESSION,
    CKS_RO_USER_FUNCTIONS, CKS_RW_PUBLIC_SESSION, CKS_RW_USER_FUNCTIONS, CkFlags, CkObjectHandle,
    CkRv, CkSessionHandle, CkSlotId, CkState,
};
use crate::sign::Mechanism;
use crate::token::{TokenObjects, build_token_objects, remote_token_objects};

/// First slot id handed out. Slot ids are stable per reader name for
/// the process lifetime; starting at 1 keeps 0 (a common "invalid"
/// sentinel in caller code) out of the slot-id space.
const SLOT_ID_BASE: CkSlotId = 1;
/// First session handle handed out. 0 is
/// [`crate::ck::CK_INVALID_HANDLE`] and must never be a live handle.
const SESSION_HANDLE_BASE: CkSessionHandle = 1;
/// The handle range of the first token raised; the range below it
/// holds objects of no raised token.
const FIRST_TOKEN_GENERATION: CkObjectHandle = 1;
/// The vendor a remote slot reports for its reader: this software,
/// which is what drives the phone.
const REMOTE_READER_VENDOR: &str = "RefineID";
/// PIN1 minimum length in ASCII digits accepted by `C_Login`
/// (DVV FINEID PIN1 policy).
pub const PIN1_MIN_DIGITS: usize = 4;
/// PIN1 maximum length in ASCII digits accepted by `C_Login`
/// (DVV FINEID PIN1 policy).
pub const PIN1_MAX_DIGITS: usize = 12;

/// The process-global module state, `Some` between `C_Initialize` and
/// `C_Finalize`. [`Mutex::new`] is `const`, so this needs no lazy
/// initialiser.
pub static MODULE: Mutex<Option<ModuleState>> = Mutex::new(None);

/// Per-device rejection memory survives PKCS#11 finalize/reinitialize
/// for the lifetime of the hosting process. Keyed by
/// [`SlotKind::cache_key`], so a local reader and a paired phone can
/// never share an entry. Finalize clears positive secrets.
static PROCESS_PIN_CACHES: Mutex<BTreeMap<String, Arc<Mutex<PinSafetyCache>>>> =
    Mutex::new(BTreeMap::new());

/// One PKCS#11 slot, bound to a device.
#[derive(Debug, Clone)]
pub struct SlotRecord {
    /// Stable slot id for this device for the process lifetime.
    id: CkSlotId,
    /// What kind of device backs the slot, decided at the border that
    /// admitted it. Nothing downstream re-derives this from a name: a
    /// reader's driver-chosen name is not evidence of anything.
    kind: SlotKind,
    /// Whether a validated FINEID card was present at the last
    /// slot-table refresh.
    card_present: bool,
    /// The reader's own vendor / IFD-version attributes, read once
    /// when the slot is first seen (direct-mode, card-less).
    /// Reported in `CK_SLOT_INFO`: the slot describes the physical
    /// reader, not this module.
    reader_identity: ReaderIdentity,
}

impl SlotRecord {
    /// The device this slot is bound to.
    pub(crate) const fn kind(&self) -> &SlotKind {
        &self.kind
    }

    /// The text a caller sees for this slot.
    pub(crate) fn display_name(&self) -> String {
        self.kind.display_name()
    }

    /// Whether a card was present at the last slot-table refresh.
    pub(crate) const fn card_present(&self) -> bool {
        self.card_present
    }

    /// The reader's driver-reported identity attributes.
    pub(crate) const fn reader_identity(&self) -> &ReaderIdentity {
        &self.reader_identity
    }

    /// A remote slot, for tests that need one without a source.
    #[cfg(test)]
    pub(crate) fn remote_for_test(
        id: CkSlotId,
        pair_id: crate::slot_kind::RemoteSlotId,
        label: &str,
        context: &str,
        card_present: bool,
    ) -> Self {
        Self {
            id,
            kind: SlotKind::Remote {
                pair_id,
                label: label.to_owned(),
                context: refineid_remote::DisplayText::new(context.to_owned())
                    .expect("bounded text"),
            },
            card_present,
            reader_identity: ReaderIdentity::default(),
        }
    }
}

/// An in-progress `C_FindObjects` operation on a session: the object
/// handles still to be returned.
#[derive(Debug, Clone, Default)]
pub struct FindState {
    /// Handles matching the active template not yet returned to the
    /// caller.
    remaining: Vec<CkObjectHandle>,
}

/// An in-progress `C_Sign` operation on a session.
#[derive(Debug, Clone, Copy)]
pub struct SignState {
    /// The mechanism selected at `C_SignInit`.
    mechanism: Mechanism,
}

impl SignState {
    /// The mechanism selected at `C_SignInit`.
    pub(crate) const fn mechanism(self) -> Mechanism {
        self.mechanism
    }
}

/// One open session on a slot.
#[derive(Debug, Clone, Default)]
pub struct Session {
    /// The slot this session belongs to.
    slot_id: CkSlotId,
    /// Session flags as passed to `C_OpenSession`.
    flags: CkFlags,
    /// Active find operation, if `C_FindObjectsInit` has run.
    find: Option<FindState>,
    /// Active sign operation, if `C_SignInit` has run.
    sign: Option<SignState>,
    /// Active software verify operation, if `C_VerifyInit` has
    /// run. Independent of `sign` per v2.40 (one active
    /// operation per category).
    verify: Option<SignState>,
}

impl Session {
    /// The slot this session belongs to.
    pub(crate) const fn slot_id(&self) -> CkSlotId {
        self.slot_id
    }

    /// The session flags passed to `C_OpenSession`.
    pub(crate) const fn flags(&self) -> CkFlags {
        self.flags
    }

    /// The active sign operation, if any.
    pub(crate) const fn sign_state(&self) -> Option<SignState> {
        self.sign
    }

    /// Whether a sign operation is already active on this session.
    pub(crate) const fn has_active_sign(&self) -> bool {
        self.sign.is_some()
    }

    /// Begin a find operation with the given matching handles.
    pub(crate) fn begin_find(&mut self, handles: Vec<CkObjectHandle>) {
        self.find = Some(FindState { remaining: handles });
    }

    /// Return the next batch of up to `max` find handles, or `None`
    /// when no find operation is active.
    pub(crate) fn next_find_batch(&mut self, max: usize) -> Option<Vec<CkObjectHandle>> {
        let find = self.find.as_mut()?;
        let wanted = max.min(find.remaining.len());
        Some(find.remaining.drain(..wanted).collect())
    }

    /// End the active find operation, reporting whether one was
    /// active.
    pub(crate) fn take_find(&mut self) -> bool {
        self.find.take().is_some()
    }

    /// Begin a sign operation with the given mechanism.
    pub(crate) fn begin_sign(&mut self, mechanism: Mechanism) {
        self.sign = Some(SignState { mechanism });
    }

    /// Clear any active sign operation.
    pub(crate) fn clear_sign(&mut self) {
        self.sign = None;
    }

    /// The active verify operation, if any.
    pub(crate) const fn verify_state(&self) -> Option<SignState> {
        self.verify
    }

    /// Whether a verify operation is already active on this session.
    pub(crate) const fn has_active_verify(&self) -> bool {
        self.verify.is_some()
    }

    /// Begin a verify operation with the given mechanism.
    pub(crate) fn begin_verify(&mut self, mechanism: Mechanism) {
        self.verify = Some(SignState { mechanism });
    }

    /// Clear any active verify operation.
    pub(crate) fn clear_verify(&mut self) {
        self.verify = None;
    }
}

/// Live module state between `C_Initialize` and `C_Finalize`.
#[derive(Debug)]
pub struct ModuleState {
    /// Stable slot table; entries are appended, never removed, so
    /// slot ids stay stable per reader for the process lifetime.
    slots: Vec<SlotRecord>,
    /// Next slot id to assign to a newly-seen reader.
    next_slot_id: CkSlotId,
    /// Open sessions keyed by handle.
    sessions: BTreeMap<CkSessionHandle, Session>,
    /// Next session handle to assign.
    next_session_handle: CkSessionHandle,
    /// Per-slot held PIN1 plus process-lifetime rejection memory.
    /// Entries survive logout/removal so rejection fingerprints cannot
    /// be bypassed without restarting the process.
    pin_caches: BTreeMap<CkSlotId, Arc<Mutex<PinSafetyCache>>>,
    /// Cached token objects per slot while the same card stays
    /// present.
    token_cache: BTreeMap<CkSlotId, TokenObjects>,
    /// Per-slot card presence as last reported through
    /// `C_WaitForSlotEvent`. Absent entry = never reported, so a
    /// slot's first sighting counts as an event (the caller has
    /// not seen it yet).
    event_reported: BTreeMap<CkSlotId, bool>,
    /// Active login state for remote RAPP readers (authenticated via on-device protected path).
    remote_logged_in: BTreeSet<CkSlotId>,
    /// The handle range the next raised token takes.
    next_token_generation: CkObjectHandle,
}

impl ModuleState {
    /// Build empty module state with an initial slot-table refresh.
    #[must_use]
    pub(crate) fn new() -> Self {
        let mut state = Self {
            slots: Vec::new(),
            next_slot_id: SLOT_ID_BASE,
            sessions: BTreeMap::new(),
            next_session_handle: SESSION_HANDLE_BASE,
            pin_caches: BTreeMap::new(),
            token_cache: BTreeMap::new(),
            event_reported: BTreeMap::new(),
            remote_logged_in: BTreeSet::new(),
            next_token_generation: FIRST_TOKEN_GENERATION,
        };
        state.refresh_slots();
        state
    }

    /// Raise a token: place its objects in the next handle range and
    /// cache them for the slot. Returns the objects as cached.
    fn cache_token(&mut self, slot_id: CkSlotId, mut objects: TokenObjects) -> TokenObjects {
        objects.set_generation(self.next_token_generation);
        self.next_token_generation = self.next_token_generation.saturating_add(1);
        self.token_cache.insert(slot_id, objects.clone());
        objects
    }

    /// Re-enumerate readers, appending readers only after their
    /// inserted card proves that it is FINEID and updating FINEID-card
    /// presence. When a card leaves a slot, its cached objects and
    /// login state are dropped.
    ///
    /// Proof of FINEID has two stages. Answering the PKCS#15 AID
    /// SELECT ([`probe_fineid_card`]) is the cheap steady-state
    /// check, but it is not sufficient: an unrelated token could
    /// answer that SELECT and still surface as a slot to NSS. A card
    /// TRANSITIONING into presence must additionally yield a
    /// parseable authentication certificate
    /// ([`build_token_objects`]) -- the same bar the CLI reader
    /// picker sets -- and the parsed objects are cached for the new
    /// slot, so the stronger proof costs nothing extra
    /// ([`Self::ensure_token`] needed them anyway). A transient read
    /// failure on a genuine card self-heals on the next refresh
    /// (the transition re-runs until the proof succeeds).
    pub(crate) fn refresh_slots(&mut self) {
        let _ = self.refresh_slots_with(&PcscProber);
        self.refresh_remote_slots();
    }

    /// [`Self::refresh_slots`] over an injected [`SlotProber`], so
    /// the admission logic (AID probe + cert-proven transition) is
    /// testable without PC/SC hardware.
    fn refresh_slots_with(&mut self, prober: &impl SlotProber) -> Result<(), CkRv> {
        let readers = match prober.enumerate() {
            Ok(readers) => readers,
            Err(error) => {
                self.clear_all_positive_pins();
                return Err(error);
            }
        };
        for reader in readers {
            let observation = if reader.card_present {
                prober.probe(&reader.id)
            } else {
                FineidCardObservation::Absent
            };
            if observation.preserves_last_known_state() {
                // Another process can temporarily own the PC/SC reader.
                // That is not evidence that the card changed or left.
                continue;
            }
            let aid_present = matches!(observation, FineidCardObservation::Present);
            if let Some(pos) = self
                .slots
                .iter()
                .position(|s| s.kind.local_reader() == Some(&reader.id))
            {
                let (id, was_present) = match self.slots.get(pos) {
                    Some(slot) => (slot.id, slot.card_present),
                    None => continue,
                };
                if aid_present && !was_present {
                    // Transition into presence: demand the
                    // cert-proven objects before the slot reports a
                    // token.
                    let Ok(objects) = prober.build_objects(&reader.id) else {
                        continue;
                    };
                    if let Some(slot) = self.slots.get_mut(pos) {
                        slot.card_present = true;
                    }
                    self.invalidate_slot(id);
                    self.cache_token(id, objects);
                } else if was_present && !aid_present {
                    if let Some(slot) = self.slots.get_mut(pos) {
                        slot.card_present = false;
                    }
                    self.invalidate_slot(id);
                }
            } else if aid_present {
                // New reader with a card: same cert-proven bar
                // before a slot exists at all.
                let Ok(objects) = prober.build_objects(&reader.id) else {
                    continue;
                };
                let id = self.next_slot_id;
                self.next_slot_id = self.next_slot_id.saturating_add(1);
                self.slots.push(SlotRecord {
                    id,
                    kind: SlotKind::Local {
                        reader: reader.id.clone(),
                    },
                    card_present: true,
                    reader_identity: prober.reader_identity(&reader.id),
                });
                self.cache_token(id, objects);
            }
        }
        Ok(())
    }

    /// Admit the paired phone the host's installed source offers.
    ///
    /// The source is the only trust origin that may admit a
    /// [`SlotKind::Remote`]: an offer read here is proof the host
    /// admitted the pairing, where a reader name reported by a USB
    /// device would only be a claim. With no source installed, no
    /// remote slot exists and no remote credential path is reachable.
    fn refresh_remote_slots(&mut self) {
        if let Some(source) = crate::remote::installed() {
            self.refresh_remote_slots_with(source);
        }
    }

    /// [`Self::refresh_remote_slots`] over an injected source, so the
    /// admission logic is testable without a host.
    ///
    /// At most one remote slot carries a token at a time, the one the
    /// offer names. A remote slot the offer no longer names keeps its
    /// id and loses its token. The token exists exactly while the
    /// offer carries a certificate that parses; a certificate that
    /// differs from the cached one withdraws the token and raises a
    /// new one, with new object handles, under the same slot id.
    fn refresh_remote_slots_with(&mut self, source: &dyn RemoteTokenSource) {
        let offer = source.offered();
        let unnamed: Vec<CkSlotId> = self
            .slots
            .iter()
            .filter(|slot| {
                slot.card_present
                    && slot.kind.is_remote()
                    && offer
                        .as_ref()
                        .is_none_or(|offer| slot.kind.remote_pair_id() != Some(offer.pair_id()))
            })
            .map(|slot| slot.id)
            .collect();
        for id in unnamed {
            self.withdraw_token(id);
        }
        let Some(offer) = offer else {
            return;
        };
        let id = self.remote_slot_for(&offer);
        let objects = offer
            .certificate()
            .and_then(|certificate| remote_token_objects(offer.pair_id(), certificate).ok());
        let Some(objects) = objects else {
            self.withdraw_token(id);
            return;
        };
        let cached_same_certificate = self
            .token_cache
            .get(&id)
            .is_some_and(|cached| cached.auth_cert_der() == objects.auth_cert_der());
        if cached_same_certificate {
            return;
        }
        self.withdraw_token(id);
        self.cache_token(id, objects);
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.id == id) {
            slot.card_present = true;
        }
        // A token the caller was last told was present was withdrawn
        // and raised again within this refresh; the caller is told of
        // the new token once.
        self.event_reported
            .entry(id)
            .and_modify(|reported| *reported = false);
    }

    /// The slot of the offered pairing, appended on first sight and
    /// renamed when the phone's label changed.
    fn remote_slot_for(&mut self, offer: &RemoteOffer) -> CkSlotId {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.kind.remote_pair_id() == Some(offer.pair_id()))
        {
            if let SlotKind::Remote { label, context, .. } = &mut slot.kind {
                if label != offer.label() {
                    offer.label().clone_into(label);
                }
                if context != offer.context() {
                    *context = offer.context().clone();
                }
            }
            return slot.id;
        }
        let id = self.next_slot_id;
        self.next_slot_id = self.next_slot_id.saturating_add(1);
        self.slots.push(SlotRecord {
            id,
            kind: SlotKind::Remote {
                pair_id: *offer.pair_id(),
                label: offer.label().to_owned(),
                context: offer.context().clone(),
            },
            card_present: false,
            reader_identity: ReaderIdentity {
                vendor_name: Some(REMOTE_READER_VENDOR.to_owned()),
                ifd_version: None,
            },
        });
        id
    }

    /// Mark a slot's token absent, end its login, and drop what was
    /// cached for it.
    fn withdraw_token(&mut self, slot_id: CkSlotId) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.id == slot_id) {
            slot.card_present = false;
        }
        self.remote_logged_in.remove(&slot_id);
        self.invalidate_slot(slot_id);
    }

    /// Drop cached objects and PIN1 login for a slot (on card
    /// removal). Zeroizes the PIN1 secret via `PinBytes`'s drop.
    fn invalidate_slot(&mut self, slot_id: CkSlotId) {
        self.token_cache.remove(&slot_id);
        if let Some(cache) = self.pin_caches.get(&slot_id)
            && let Ok(mut cache) = cache.lock()
        {
            cache.clear_positive();
        }
    }

    /// All slot ids in assignment order.
    #[must_use]
    pub(crate) fn slot_ids(&self) -> Vec<CkSlotId> {
        self.slots.iter().map(|s| s.id).collect()
    }

    /// Slot record for `id`, if it exists.
    #[must_use]
    pub(crate) fn slot(&self, id: CkSlotId) -> Option<&SlotRecord> {
        self.slots.iter().find(|s| s.id == id)
    }

    /// The device backing `slot_id`, if the slot exists.
    #[must_use]
    pub(crate) fn slot_kind(&self, slot_id: CkSlotId) -> Option<&SlotKind> {
        self.slot(slot_id).map(|s| s.kind())
    }

    /// Open a new session on `slot_id` and return its handle.
    pub(crate) fn open_session(&mut self, slot_id: CkSlotId, flags: CkFlags) -> CkSessionHandle {
        let handle = self.next_session_handle;
        self.next_session_handle = self.next_session_handle.saturating_add(1);
        self.sessions.insert(
            handle,
            Session {
                slot_id,
                flags,
                find: None,
                sign: None,
                verify: None,
            },
        );
        handle
    }

    /// Borrow a session by handle.
    #[must_use]
    pub(crate) fn session(&self, handle: CkSessionHandle) -> Option<&Session> {
        self.sessions.get(&handle)
    }

    /// Mutably borrow a session by handle.
    pub(crate) fn session_mut(&mut self, handle: CkSessionHandle) -> Option<&mut Session> {
        self.sessions.get_mut(&handle)
    }

    /// Close one session. Returns `false` if the handle was unknown.
    /// When a slot loses its last session, its PIN1 login is dropped.
    pub(crate) fn close_session(&mut self, handle: CkSessionHandle) -> bool {
        let Some(session) = self.sessions.remove(&handle) else {
            return false;
        };
        self.forget_login_if_no_sessions(session.slot_id);
        true
    }

    /// Close every session on `slot_id` and drop that slot's PIN1
    /// login.
    pub(crate) fn close_all_sessions(&mut self, slot_id: CkSlotId) {
        self.sessions
            .retain(|_handle, session| session.slot_id != slot_id);
        self.logout(slot_id);
    }

    /// Drop a slot's PIN1 login once no sessions remain on it (per
    /// PKCS#11 the token login state ends when the last session
    /// closes).
    fn forget_login_if_no_sessions(&mut self, slot_id: CkSlotId) {
        let still_open = self
            .sessions
            .values()
            .any(|session| session.slot_id == slot_id);
        if !still_open {
            self.logout(slot_id);
        }
    }

    /// Return the process-lifetime safety cache for a slot, creating it
    /// before card I/O when needed.
    pub(crate) fn pin_cache(
        &mut self,
        slot_id: CkSlotId,
    ) -> Result<Arc<Mutex<PinSafetyCache>>, CkRv> {
        if let Some(cache) = self.pin_caches.get(&slot_id) {
            return Ok(Arc::clone(cache));
        }
        let cache_key = self
            .slot_kind(slot_id)
            .map(SlotKind::cache_key)
            .ok_or(CKR_DEVICE_ERROR)?;
        let mut process_caches = PROCESS_PIN_CACHES.lock().map_err(|_| CKR_DEVICE_ERROR)?;
        let cache = if let Some(cache) = process_caches.get(&cache_key) {
            Arc::clone(cache)
        } else {
            let cache = Arc::new(Mutex::new(
                PinSafetyCache::new().map_err(|_| CKR_DEVICE_ERROR)?,
            ));
            process_caches.insert(cache_key, Arc::clone(&cache));
            cache
        };
        drop(process_caches);
        self.pin_caches.insert(slot_id, Arc::clone(&cache));
        Ok(cache)
    }

    /// Drop a slot's PIN1 login state (`C_Logout`).
    pub(crate) fn logout(&mut self, slot_id: CkSlotId) {
        self.remote_logged_in.remove(&slot_id);
        if let Some(cache) = self.pin_caches.get(&slot_id)
            && let Ok(mut cache) = cache.lock()
        {
            cache.clear_positive();
        }
    }

    /// Mark a remote RAPP reader slot as logged in (authenticated on-device).
    pub(crate) fn set_remote_logged_in(&mut self, slot_id: CkSlotId, logged_in: bool) {
        if logged_in {
            self.remote_logged_in.insert(slot_id);
        } else {
            self.remote_logged_in.remove(&slot_id);
        }
    }

    /// Whether a user is logged in on `slot_id`.
    #[must_use]
    pub(crate) fn is_logged_in(&self, slot_id: CkSlotId) -> bool {
        // A remote slot's PIN1 is verified on the device, so this
        // computer holds no secret to check: the slot is logged in
        // from `C_Login` until `C_Logout`, the last session's close,
        // or the token's withdrawal.
        if let Some(slot) = self.slot(slot_id)
            && slot.kind().is_remote()
        {
            return slot.card_present() && self.remote_logged_in.contains(&slot_id);
        }
        self.pin_caches.get(&slot_id).is_some_and(|cache| {
            cache
                .lock()
                .is_ok_and(|mut cache| cache.has_positive_pin1())
        })
    }

    /// Report the next pending slot event: the first slot whose
    /// card presence differs from what `C_WaitForSlotEvent` last
    /// reported. Consumes the event (the snapshot is updated), so
    /// each change is reported exactly once. A slot never reported
    /// before counts as an event on first sighting.
    ///
    /// The caller refreshes the slot table first; this method is
    /// pure bookkeeping so it stays testable without hardware.
    pub(crate) fn take_slot_event(&mut self) -> Option<CkSlotId> {
        for slot in &self.slots {
            let last = self.event_reported.get(&slot.id).copied();
            if last != Some(slot.card_present) {
                self.event_reported.insert(slot.id, slot.card_present);
                return Some(slot.id);
            }
        }
        None
    }

    pub(crate) fn clear_all_positive_pins(&self) {
        for cache in self.pin_caches.values() {
            if let Ok(mut cache) = cache.lock() {
                cache.clear_positive();
            }
        }
    }

    /// Return the cached token objects for `slot_id`, building and
    /// caching them from the card on first need.
    ///
    /// A remote slot's objects come from its offer alone, so an
    /// uncached remote slot has no token.
    ///
    /// # Errors
    /// [`CKR_TOKEN_NOT_PRESENT`] for a remote slot with no cached
    /// objects; [`CKR_DEVICE_ERROR`] if the slot is unknown or the
    /// card read / parse fails.
    pub(crate) fn ensure_token(&mut self, slot_id: CkSlotId) -> Result<TokenObjects, CkRv> {
        if let Some(cached) = self.token_cache.get(&slot_id) {
            return Ok(cached.clone());
        }
        let kind = self.slot_kind(slot_id).ok_or(CKR_DEVICE_ERROR)?;
        if kind.is_remote() {
            return Err(CKR_TOKEN_NOT_PRESENT);
        }
        let reader = kind.local_reader().ok_or(CKR_DEVICE_ERROR)?.clone();
        let objects = build_token_objects(&reader)?;
        Ok(self.cache_token(slot_id, objects))
    }

    /// The number of open sessions (used by tests / diagnostics).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Test-only constructor that injects a fixed slot table so the
    /// session / slot bookkeeping can be exercised without hardware.
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(slots: Vec<SlotRecord>, next_slot_id: CkSlotId) -> Self {
        Self {
            slots,
            next_slot_id,
            sessions: BTreeMap::new(),
            next_session_handle: SESSION_HANDLE_BASE,
            pin_caches: BTreeMap::new(),
            token_cache: BTreeMap::new(),
            event_reported: BTreeMap::new(),
            remote_logged_in: BTreeSet::new(),
            next_token_generation: FIRST_TOKEN_GENERATION,
        }
    }
}

/// Probe a card-present reader for the FINEID PKCS#15 application.
///
/// The module owns only FINEID tokens. A card-present reader can host an
/// unrelated token such as a `YubiKey`, which must never appear under the
/// `RefineID` NSS module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FineidCardObservation {
    Present,
    Absent,
    TemporarilyUnavailable,
}

impl FineidCardObservation {
    const fn preserves_last_known_state(self) -> bool {
        matches!(self, Self::TemporarilyUnavailable)
    }
}

fn probe_fineid_card(reader: &ReaderId) -> FineidCardObservation {
    let backend = PcscBackend;
    let Ok(mut card) = backend.open_session(reader, ReaderAccessCap::Read) else {
        return FineidCardObservation::TemporarilyUnavailable;
    };
    match card.select_pkcs15_application() {
        Ok(()) => FineidCardObservation::Present,
        Err(Pkcs15Error::Transport(_)) => FineidCardObservation::TemporarilyUnavailable,
        Err(
            Pkcs15Error::Status(_)
            | Pkcs15Error::Outcome(_)
            | Pkcs15Error::Aid(_)
            | Pkcs15Error::Command(_)
            | Pkcs15Error::Empty
            | Pkcs15Error::TooLarge
            | Pkcs15Error::InvalidData(_),
        ) => FineidCardObservation::Absent,
    }
}

/// Seam over the hardware probes [`ModuleState::refresh_slots`]
/// drives, so the slot-admission logic (AID probe + cert-proven
/// transition) is testable without a PC/SC stack. Production is
/// [`PcscProber`]; tests script the answers.
trait SlotProber {
    /// Enumerate readers with their raw card-present flags.
    fn enumerate(&self) -> Result<Vec<ReaderInfo>, CkRv>;
    /// Cheap FINEID probe: does the inserted card answer the
    /// PKCS#15 AID SELECT?
    fn probe(&self, reader: &ReaderId) -> FineidCardObservation;
    /// Strong FINEID proof: read and parse the token objects
    /// (EF.TokenInfo + authentication certificate).
    fn build_objects(&self, reader: &ReaderId) -> Result<TokenObjects, CkRv>;
    /// The reader's own driver-reported identity attributes.
    fn reader_identity(&self, reader: &ReaderId) -> ReaderIdentity;
}

/// Production [`SlotProber`] over the live PC/SC stack.
struct PcscProber;

impl SlotProber for PcscProber {
    fn enumerate(&self) -> Result<Vec<ReaderInfo>, CkRv> {
        PcscBackend
            .enumerate()
            .map_err(|_enum_err| CKR_DEVICE_ERROR)
    }

    fn probe(&self, reader: &ReaderId) -> FineidCardObservation {
        probe_fineid_card(reader)
    }

    fn build_objects(&self, reader: &ReaderId) -> Result<TokenObjects, CkRv> {
        build_token_objects(reader)
    }

    fn reader_identity(&self, reader: &ReaderId) -> ReaderIdentity {
        read_reader_identity(reader)
    }
}

/// Derive the PKCS#11 session state ([`CkState`]) from the session's
/// read/write flag and the token's login state.
#[must_use]
pub fn session_state(flags: CkFlags, logged_in: bool) -> CkState {
    let read_write = flags & CKF_RW_SESSION != 0;
    match (read_write, logged_in) {
        (false, false) => CKS_RO_PUBLIC_SESSION,
        (false, true) => CKS_RO_USER_FUNCTIONS,
        (true, false) => CKS_RW_PUBLIC_SESSION,
        (true, true) => CKS_RW_USER_FUNCTIONS,
    }
}

#[cfg(test)]
mod tests {
    use super::{FineidCardObservation, ModuleState, ReaderIdentity, SlotRecord, session_state};
    use crate::ck::{
        CKF_RW_SESSION, CKF_SERIAL_SESSION, CKS_RO_PUBLIC_SESSION, CKS_RO_USER_FUNCTIONS,
        CKS_RW_USER_FUNCTIONS, CkSlotId,
    };
    use crate::pin::PinBytes;
    use crate::slot_kind::{PAIR_ID_SIZE, RemoteSlotId, SlotKind};
    use refineid_pcsc::ReaderId;
    use refineid_remote::DisplayText;
    use std::sync::Arc;

    /// Build module state without touching hardware by injecting a
    /// fixed slot table. Every slot is a local PC/SC reader, which is
    /// the only kind the PC/SC enumeration border can admit.
    fn state_with_slots(names: &[&str]) -> ModuleState {
        let mut slots = Vec::new();
        let mut next: CkSlotId = 1;
        for name in names {
            slots.push(SlotRecord {
                id: next,
                kind: SlotKind::Local {
                    reader: ReaderId::new((*name).to_owned()),
                },
                card_present: true,
                reader_identity: ReaderIdentity::default(),
            });
            next = next.saturating_add(1);
        }
        ModuleState::from_parts_for_test(slots, next)
    }

    /// A pairing admitted by the host's source, for the remote-slot
    /// assertions.
    fn remote_slot(pair_hex: &str) -> SlotRecord {
        SlotRecord {
            id: 1,
            kind: SlotKind::Remote {
                pair_id: RemoteSlotId::parse(pair_hex).expect("valid pair id"),
                label: "Alpha Phone".to_owned(),
                context: DisplayText::new("alpha-desk".to_owned()).expect("bounded text"),
            },
            card_present: true,
            reader_identity: ReaderIdentity::default(),
        }
    }

    #[test]
    fn slot_ids_are_stable_and_ordered() {
        let state = state_with_slots(&["Reader A", "Reader B"]);
        assert_eq!(state.slot_ids(), vec![1, 2]);
        assert_eq!(
            state.slot(1).map(SlotRecord::display_name).as_deref(),
            Some("Reader A")
        );
        assert_eq!(
            state.slot(2).map(SlotRecord::display_name).as_deref(),
            Some("Reader B")
        );
    }

    /// A reader name is a claim, not a proof: the USB device's driver
    /// chose the string. Naming a reader after a pairing must not buy
    /// the credential answers that only a host-admitted pairing may
    /// give.
    #[test]
    fn a_local_reader_naming_itself_a_pairing_is_still_local() {
        let state = state_with_slots(&["rapp:0123456789abcdef"]);
        let kind = state.slot_kind(1).expect("slot 1 exists");
        assert!(!kind.is_remote());
        assert!(kind.local_reader().is_some());
        // Not logged in until a real C_Login VERIFYs PIN1 on the card.
        assert!(!state.is_logged_in(1));
    }

    /// A remote slot is logged in from `C_Login` until `C_Logout` or
    /// the token's withdrawal, and only while its token is present.
    #[test]
    fn a_remote_slot_is_logged_in_only_between_login_and_logout() {
        let mut state =
            ModuleState::from_parts_for_test(vec![remote_slot(&"a5".repeat(PAIR_ID_SIZE))], 2);
        assert!(state.slot_kind(1).is_some_and(SlotKind::is_remote));
        assert!(!state.is_logged_in(1));
        state.set_remote_logged_in(1, true);
        assert!(state.is_logged_in(1));
        state.logout(1);
        assert!(!state.is_logged_in(1));
        state.set_remote_logged_in(1, true);
        state.withdraw_token(1);
        assert!(!state.is_logged_in(1));
    }

    /// A remote slot's objects come from its offer alone; with none
    /// cached there is no token, and no local reader path is tried.
    #[test]
    fn an_uncached_remote_slot_has_no_token() {
        let mut state =
            ModuleState::from_parts_for_test(vec![remote_slot(&"a5".repeat(PAIR_ID_SIZE))], 2);
        assert!(matches!(
            state.ensure_token(1),
            Err(crate::ck::CKR_TOKEN_NOT_PRESENT)
        ));
    }

    /// A source whose offer the test scripts, counting every call.
    struct ScriptedSource {
        offer: std::sync::Mutex<Option<crate::remote::RemoteOffer>>,
        offered_calls: std::sync::atomic::AtomicUsize,
        sign_calls: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedSource {
        fn offering(offer: Option<crate::remote::RemoteOffer>) -> Self {
            Self {
                offer: std::sync::Mutex::new(offer),
                offered_calls: std::sync::atomic::AtomicUsize::new(0),
                sign_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn set(&self, offer: Option<crate::remote::RemoteOffer>) {
            *self.offer.lock().expect("offer lock") = offer;
        }

        fn offered_calls(&self) -> usize {
            self.offered_calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn sign_calls(&self) -> usize {
            self.sign_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::remote::RemoteTokenSource for ScriptedSource {
        fn offered(&self) -> Option<crate::remote::RemoteOffer> {
            self.offered_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.offer.lock().expect("offer lock").clone()
        }

        fn sign(
            &self,
            _pair_id: &RemoteSlotId,
            _request: &refineid_remote::SignatureRequest,
            _context: &DisplayText,
            _deadline: core::time::Duration,
        ) -> Result<Vec<u8>, crate::remote::RemoteSignError> {
            self.sign_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(crate::remote::RemoteSignError::Unreachable)
        }

        fn stop(&self) {}
    }

    /// A P-384 certificate as the source would offer it after checking
    /// it on its session.
    const OFFERED_CERT_DER: &[u8] =
        include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");

    /// Another P-384 certificate, for the offer that replaces the
    /// first.
    const REPLACEMENT_CERT_DER: &[u8] = include_bytes!("../ca-certs/dvv-gov-root-ca-g3-ecc.der");

    fn offer(pair_hex: &str, certificate: Option<&[u8]>) -> crate::remote::RemoteOffer {
        crate::remote::RemoteOffer::new(
            RemoteSlotId::parse(pair_hex).expect("valid pair id"),
            "Alpha Phone".to_owned(),
            DisplayText::new("alpha-desk".to_owned()).expect("bounded text"),
            certificate.map(|der| crate::remote::SessionCertificate::new(der.to_vec())),
        )
    }

    #[test]
    fn the_remote_slot_appears_with_the_offer_and_keeps_its_id_without_it() {
        let pair_hex = "a5".repeat(PAIR_ID_SIZE);
        let source = ScriptedSource::offering(Some(offer(&pair_hex, Some(OFFERED_CERT_DER))));
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state.refresh_remote_slots_with(&source);
        assert_eq!(state.slot_ids(), vec![1]);
        assert!(state.slot(1).is_some_and(SlotRecord::card_present));
        assert_eq!(
            state.slot(1).map(SlotRecord::display_name).as_deref(),
            Some("RefineID Remote Alpha Phone")
        );
        assert_eq!(state.take_slot_event(), Some(1));

        source.set(None);
        state.refresh_remote_slots_with(&source);
        assert_eq!(state.slot_ids(), vec![1]);
        assert!(!state.slot(1).is_some_and(SlotRecord::card_present));
        assert_eq!(state.take_slot_event(), Some(1));
        assert!(matches!(
            state.ensure_token(1),
            Err(crate::ck::CKR_TOKEN_NOT_PRESENT)
        ));

        source.set(Some(offer(&pair_hex, Some(OFFERED_CERT_DER))));
        state.refresh_remote_slots_with(&source);
        assert_eq!(state.slot_ids(), vec![1]);
        assert!(state.slot(1).is_some_and(SlotRecord::card_present));
    }

    #[test]
    fn the_token_follows_the_certificate_the_offer_carries() {
        let pair_hex = "a5".repeat(PAIR_ID_SIZE);
        let source = ScriptedSource::offering(Some(offer(&pair_hex, None)));
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state.refresh_remote_slots_with(&source);
        assert_eq!(state.slot_ids(), vec![1]);
        assert!(!state.slot(1).is_some_and(SlotRecord::card_present));

        source.set(Some(offer(&pair_hex, Some(OFFERED_CERT_DER))));
        state.refresh_remote_slots_with(&source);
        assert!(state.slot(1).is_some_and(SlotRecord::card_present));
        let objects = state.ensure_token(1).expect("token objects");
        assert_eq!(objects.auth_cert_der(), OFFERED_CERT_DER);
        assert_eq!(objects.token_serial(), "REMOTE-a5a5a5a5");

        let first_handle = objects.handle(crate::token::ObjectKind::Certificate);
        assert_eq!(
            objects.kind_of(first_handle),
            Some(crate::token::ObjectKind::Certificate)
        );
        assert_eq!(state.take_slot_event(), Some(1));
        assert_eq!(state.take_slot_event(), None);
        state.set_remote_logged_in(1, true);

        source.set(Some(offer(&pair_hex, Some(REPLACEMENT_CERT_DER))));
        state.refresh_remote_slots_with(&source);
        assert_eq!(state.slot_ids(), vec![1]);
        // The replacement is a withdrawal and a new token: the caller
        // is told once, and the login of the old token is over.
        assert_eq!(state.take_slot_event(), Some(1));
        assert_eq!(state.take_slot_event(), None);
        assert!(!state.is_logged_in(1));
        let objects = state.ensure_token(1).expect("token objects");
        assert_eq!(objects.auth_cert_der(), REPLACEMENT_CERT_DER);
        assert_eq!(objects.token_serial(), "REMOTE-a5a5a5a5");
        // The replaced token's handles name nothing on the new one.
        assert_eq!(objects.kind_of(first_handle), None);
        assert_ne!(
            objects.handle(crate::token::ObjectKind::Certificate),
            first_handle
        );

        source.set(Some(offer(&pair_hex, None)));
        state.refresh_remote_slots_with(&source);
        assert!(!state.slot(1).is_some_and(SlotRecord::card_present));
    }

    /// A token raised again after it was withdrawn is a new token:
    /// its objects take new handles and the old handles name nothing.
    #[test]
    fn a_token_raised_again_takes_new_handles() {
        let pair_hex = "a5".repeat(PAIR_ID_SIZE);
        let source = ScriptedSource::offering(Some(offer(&pair_hex, Some(OFFERED_CERT_DER))));
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state.refresh_remote_slots_with(&source);
        let first = state.ensure_token(1).expect("token objects");
        let old_handle = first.handle(crate::token::ObjectKind::PrivateKey);

        source.set(None);
        state.refresh_remote_slots_with(&source);
        source.set(Some(offer(&pair_hex, Some(OFFERED_CERT_DER))));
        state.refresh_remote_slots_with(&source);
        let second = state.ensure_token(1).expect("token objects");
        assert_eq!(second.kind_of(old_handle), None);
        assert_ne!(
            second.handle(crate::token::ObjectKind::PrivateKey),
            old_handle
        );
        assert_eq!(
            second.kind_of(second.handle(crate::token::ObjectKind::PrivateKey)),
            Some(crate::token::ObjectKind::PrivateKey)
        );
    }

    #[test]
    fn a_second_pairing_gets_its_own_slot_and_the_first_loses_its_token() {
        let first = "a5".repeat(PAIR_ID_SIZE);
        let second = "5a".repeat(PAIR_ID_SIZE);
        let source = ScriptedSource::offering(Some(offer(&first, Some(OFFERED_CERT_DER))));
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state.refresh_remote_slots_with(&source);
        source.set(Some(offer(&second, Some(OFFERED_CERT_DER))));
        state.refresh_remote_slots_with(&source);
        assert_eq!(state.slot_ids(), vec![1, 2]);
        assert!(!state.slot(1).is_some_and(SlotRecord::card_present));
        assert!(state.slot(2).is_some_and(SlotRecord::card_present));
    }

    /// Reading the token's objects and attributes is served from the
    /// cache the refresh filled; the source is not consulted again
    /// and never asked to sign.
    #[test]
    fn attribute_reads_never_call_the_source() {
        let pair_hex = "a5".repeat(PAIR_ID_SIZE);
        let source = ScriptedSource::offering(Some(offer(&pair_hex, Some(OFFERED_CERT_DER))));
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state.refresh_remote_slots_with(&source);
        assert_eq!(source.offered_calls(), 1);
        let objects = state.ensure_token(1).expect("token objects");
        for kind in [
            crate::token::ObjectKind::Certificate,
            crate::token::ObjectKind::PublicKey,
            crate::token::ObjectKind::PrivateKey,
        ] {
            assert!(objects.attribute(kind, crate::ck::CKA_ID).is_some());
            assert!(objects.attribute(kind, crate::ck::CKA_LABEL).is_some());
        }
        assert!(
            objects
                .attribute(crate::token::ObjectKind::Certificate, crate::ck::CKA_VALUE)
                .is_some()
        );
        let _ = state.ensure_token(1).expect("token objects again");
        state.set_remote_logged_in(1, true);
        assert!(state.is_logged_in(1));
        assert_eq!(source.offered_calls(), 1);
        assert_eq!(source.sign_calls(), 0);
    }

    /// A local reader and a paired phone must never share
    /// process-lifetime PIN-rejection memory, or a rejected PIN on one
    /// device would throttle the other.
    #[test]
    fn local_and_remote_slots_get_separate_pin_caches() {
        let mut local = state_with_slots(&["rapp:0123456789abcdef"]);
        let local_cache = local.pin_cache(1).expect("local cache");
        let mut remote = ModuleState::from_parts_for_test(
            vec![remote_slot("0123456789abcdef0123456789abcdef")],
            2,
        );
        let remote_cache = remote.pin_cache(1).expect("remote cache");
        assert!(!Arc::ptr_eq(&local_cache, &remote_cache));
    }

    #[test]
    fn sessions_open_and_close() {
        let mut state = state_with_slots(&["Reader A"]);
        let handle = state.open_session(1, CKF_SERIAL_SESSION);
        assert_eq!(state.session_count(), 1);
        assert!(state.session(handle).is_some());
        assert!(state.close_session(handle));
        assert_eq!(state.session_count(), 0);
        assert!(!state.close_session(handle));
    }

    #[test]
    fn session_state_mapping() {
        assert_eq!(
            session_state(CKF_SERIAL_SESSION, false),
            CKS_RO_PUBLIC_SESSION
        );
        assert_eq!(
            session_state(CKF_SERIAL_SESSION, true),
            CKS_RO_USER_FUNCTIONS
        );
        assert_eq!(
            session_state(CKF_SERIAL_SESSION | CKF_RW_SESSION, true),
            CKS_RW_USER_FUNCTIONS
        );
    }

    #[test]
    fn temporary_reader_contention_is_not_a_card_state_change() {
        assert!(FineidCardObservation::TemporarilyUnavailable.preserves_last_known_state());
        assert!(!FineidCardObservation::Absent.preserves_last_known_state());
        assert!(!FineidCardObservation::Present.preserves_last_known_state());
    }

    /// Scripted [`SlotProber`]: one card-present reader whose
    /// probe / object-build answers are fixed by the test.
    struct ScriptedProber {
        observation: FineidCardObservation,
        objects_ok: bool,
    }

    impl super::SlotProber for ScriptedProber {
        fn enumerate(&self) -> Result<Vec<refineid_pcsc::ReaderInfo>, super::CkRv> {
            Ok(vec![refineid_pcsc::ReaderInfo {
                id: refineid_pcsc::ReaderId::new("Scripted Reader".to_owned()),
                card_present: true,
            }])
        }

        fn probe(&self, _reader: &refineid_pcsc::ReaderId) -> FineidCardObservation {
            self.observation
        }

        fn reader_identity(&self, _reader: &refineid_pcsc::ReaderId) -> ReaderIdentity {
            ReaderIdentity::default()
        }

        fn build_objects(
            &self,
            _reader: &refineid_pcsc::ReaderId,
        ) -> Result<crate::token::TokenObjects, super::CkRv> {
            // A scripted prober cannot mint real TokenObjects (they
            // parse a certificate); the tests below only exercise
            // REFUSAL paths, so `objects_ok` must stay false.
            assert!(
                !self.objects_ok,
                "scripted prober cannot produce TokenObjects"
            );
            Err(crate::ck::CKR_DEVICE_ERROR)
        }
    }

    /// A card that refuses the PKCS#15 AID SELECT (a `YubiKey` in
    /// CCID mode, any non-FINEID smartcard) must never surface as
    /// a slot to NSS.
    #[test]
    fn select_refusing_card_yields_no_slot() {
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state
            .refresh_slots_with(&ScriptedProber {
                observation: FineidCardObservation::Absent,
                objects_ok: false,
            })
            .expect("refresh succeeds");
        assert!(state.slot_ids().is_empty());
    }

    /// A card that answers the AID SELECT but cannot yield a
    /// parseable FINEID authentication certificate must not
    /// surface as a slot either -- answering the SELECT is not
    /// proof of FINEID.
    #[test]
    fn aid_answering_cert_failing_card_yields_no_slot() {
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state
            .refresh_slots_with(&ScriptedProber {
                observation: FineidCardObservation::Present,
                objects_ok: false,
            })
            .expect("refresh succeeds");
        assert!(state.slot_ids().is_empty());
    }

    /// Slot events are reported exactly once per presence change:
    /// first sighting counts, a steady state does not, a removal
    /// (card stops answering the AID probe) does.
    #[test]
    fn slot_events_report_each_presence_change_once() {
        let mut state = state_with_slots(&["Scripted Reader"]);
        // First sighting of the pre-existing present slot.
        assert_eq!(state.take_slot_event(), Some(1));
        // Steady state: no further event.
        assert_eq!(state.take_slot_event(), None);
        // The card stops answering the AID probe -> removal event.
        state
            .refresh_slots_with(&ScriptedProber {
                observation: FineidCardObservation::Absent,
                objects_ok: false,
            })
            .expect("refresh succeeds");
        assert_eq!(state.take_slot_event(), Some(1));
        assert_eq!(state.take_slot_event(), None);
    }

    /// Reader contention while a slot's card was present must
    /// preserve the slot's last known state, not evict it.
    #[test]
    fn contention_preserves_existing_slot_presence() {
        let mut state = state_with_slots(&["Scripted Reader"]);
        state
            .refresh_slots_with(&ScriptedProber {
                observation: FineidCardObservation::TemporarilyUnavailable,
                objects_ok: false,
            })
            .expect("refresh succeeds");
        assert!(state.slot(1).is_some_and(SlotRecord::card_present));
    }

    #[test]
    fn rejected_pin_survives_logout_and_session_close() {
        let mut state = state_with_slots(&["Reader A"]);
        let handle = state.open_session(1, CKF_SERIAL_SESSION);
        let pin = PinBytes::try_from(*b"1234").expect("valid PIN1");
        let serial = refineid_pkcs15::TokenSerial::new("CARD-A".to_owned());
        let cache = state.pin_cache(1).expect("cache created");
        {
            let mut cache = cache.lock().expect("cache lock");
            cache
                .store_pin1(serial.clone(), pin.clone())
                .expect("a fresh PIN1 is not a rejected one");
            cache.record_rejected(&serial, &pin);
        }
        state.logout(1);
        assert!(state.close_session(handle));
        assert!(cache.lock().expect("cache lock").is_rejected(&serial, &pin));
    }

    /// A logout reaches a PIN1 that is out on an in-flight signature:
    /// the card's answer to that signature cannot bring it back.
    #[test]
    fn logout_destroys_a_pin1_out_on_a_checkout() {
        /// Retry count of a pristine FINEID PIN.
        const RETRIES_PRISTINE: u8 = 5;
        const DECIMAL_DIGIT_RADIX: u8 = 10;
        let mut digits = vec![0_u8; PinBytes::MAX_LENGTH];
        getrandom::fill(&mut digits).expect("operating system random source is available");
        for digit in &mut digits {
            *digit = b'0' + (*digit % DECIMAL_DIGIT_RADIX);
        }
        let pin = PinBytes::new(digits).expect("random digits satisfy the PIN policy");
        let pristine = refineid_auth::PinStatus::Remaining(
            refineid_apdu::PinRetries::from_nibble(RETRIES_PRISTINE)
                .expect("test retry count fits the status-word nibble"),
        );
        let serial = refineid_pkcs15::TokenSerial::new("CARD-LOGOUT".to_owned());
        let mut state = state_with_slots(&["Logout During Checkout Reader"]);
        let cache = state.pin_cache(1).expect("cache created");
        let checkout = {
            let mut cache = cache.lock().expect("cache lock");
            cache
                .store_pin1(serial.clone(), pin)
                .expect("a fresh PIN1 is not a rejected one");
            cache
                .checkout_pin1(&serial, pristine)
                .expect("the held value is checked out")
        };
        state.logout(1);
        let accepted: Result<
            refineid_auth::VerifyOutcome,
            refineid_auth::AuthError<core::convert::Infallible>,
        > = Ok(refineid_auth::VerifyOutcome::Ok);
        checkout.settle_verify(&mut cache.lock().expect("cache lock"), &accepted);
        assert!(!state.is_logged_in(1));
    }

    #[test]
    fn rejected_pin_survives_module_state_recreation() {
        let reader = "Process Lifetime Negative Cache Reader";
        let pin = PinBytes::try_from(*b"2468").expect("valid PIN1");
        let serial = refineid_pkcs15::TokenSerial::new("CARD-PROCESS".to_owned());
        {
            let mut state = state_with_slots(&[reader]);
            let cache = state.pin_cache(1).expect("cache created");
            cache
                .lock()
                .expect("cache lock")
                .record_rejected(&serial, &pin);
            state.clear_all_positive_pins();
        }
        let mut recreated = state_with_slots(&[reader]);
        let cache = recreated.pin_cache(1).expect("process cache reused");
        assert!(cache.lock().expect("cache lock").is_rejected(&serial, &pin));
    }
}
