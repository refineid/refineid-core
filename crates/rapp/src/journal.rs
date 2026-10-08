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

use super::{OperationId, OperationResultMessage, OperationState, PairId, RequestHash, SessionId};

/// Durable, non-secret operation record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalRecord {
    /// Stored pairing that authorized the operation.
    pub pair_id: PairId,
    /// Session the request arrived on; advisory provenance.
    pub session_id: SessionId,
    /// Semantic operation identifier.
    pub operation_id: OperationId,
    /// Hash of the exact authorized request.
    pub request_hash: RequestHash,
    /// Current permanent state.
    pub state: OperationState,
    /// Physical credential-command transmissions, always zero or one.
    pub transmission_count: u8,
    /// Whether any automatic retry remains legal.
    pub automatic_retry_permitted: bool,
}

/// Adapter boundary for durable write-ahead operation records.
pub trait JournalStore {
    /// Platform persistence error.
    type Error;

    /// Atomically persist the supplied complete record.
    ///
    /// # Errors
    /// The platform persistence failure.
    fn persist(&mut self, record: &JournalRecord) -> Result<(), Self::Error>;
}

/// Durable encrypted result-delivery extension to [`JournalStore`].
///
/// Every method is one atomic platform-storage transaction. Implementations
/// must keep the result device-local and excluded from backup or migration.
pub trait ResultJournalStore: JournalStore {
    /// Atomically persist the `result_pending` record and its complete result
    /// before the result message is released to the transport.
    ///
    /// # Errors
    /// The platform persistence failure.
    fn persist_result(
        &mut self,
        record: &JournalRecord,
        result: &OperationResultMessage,
    ) -> Result<(), Self::Error>;

    /// Atomically mark delivery uncertain while retaining the encrypted result.
    ///
    /// # Errors
    /// The platform persistence failure.
    fn retain_uncertain_result(&mut self, record: &JournalRecord) -> Result<(), Self::Error>;

    /// Atomically mark completion and erase the retained result body.
    ///
    /// # Errors
    /// The platform persistence failure.
    fn acknowledge_result(&mut self, record: &JournalRecord) -> Result<(), Self::Error>;
}

/// One proxy journal entry loaded after process restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredProxyRecord {
    /// Durable journal record as persisted before the restart.
    pub record: JournalRecord,
    /// Present only when a completed result is awaiting acknowledgment or was
    /// retained after delivery became uncertain.
    pub retained_result: Option<OperationResultMessage>,
}

/// Restart-recovery extension for proxy journals.
pub trait JournalRecoveryStore: ResultJournalStore {
    /// Load every retained record for the pairing.
    ///
    /// # Errors
    /// The platform persistence failure.
    fn load_all(&mut self) -> Result<Vec<RecoveredProxyRecord>, Self::Error>;
}

/// Failure from the at-most-once journal boundary.
#[derive(Debug, PartialEq, Eq)]
pub enum JournalError<E> {
    /// Durable persistence failed; no credential command may be sent.
    Persistence(E),
    /// The requested operation is illegal from the current state.
    InvalidState {
        /// State observed by the journal.
        state: OperationState,
    },
    /// Commit refers to a different authorized request.
    RequestHashMismatch,
    /// A credential command was already handed to the transport.
    AlreadyTransmitted,
}

/// Durable at-most-once operation coordinator.
#[allow(
    missing_copy_implementations,
    reason = "an at-most-once coordinator must move, never fork"
)]
#[derive(Debug)]
pub struct OperationJournal {
    record: JournalRecord,
}

impl OperationJournal {
    /// Create an operation with zero transmissions and nothing persisted.
    #[must_use]
    pub const fn prepared(
        pair_id: PairId,
        session_id: SessionId,
        operation_id: OperationId,
        request_hash: RequestHash,
    ) -> Self {
        Self {
            record: JournalRecord {
                pair_id,
                session_id,
                operation_id,
                request_hash,
                state: OperationState::Prepared,
                transmission_count: 0,
                automatic_retry_permitted: false,
            },
        }
    }

    /// Resume the coordinator of a record loaded after a restart.
    #[must_use]
    pub const fn recovered(record: JournalRecord) -> Self {
        Self { record }
    }

    /// Current durable record view.
    #[must_use]
    pub const fn record(&self) -> &JournalRecord {
        &self.record
    }

    /// Persist the write-ahead in-flight entry, counting the one
    /// transmission, and consume a non-clonable command (section 8.1).
    ///
    /// The returned wrapper is the only value an APDU/card adapter may accept.
    /// A persistence failure returns the command to the caller and performs no
    /// transmission.
    ///
    /// # Errors
    /// [`JournalError`] beside the returned command on an illegal state, a
    /// request-hash mismatch, an already-counted transmission, or a
    /// persistence failure.
    pub fn begin_card_command<S: JournalStore, C>(
        &mut self,
        store: &mut S,
        request_hash: RequestHash,
        command: C,
    ) -> Result<PendingCardCommand<C>, (JournalError<S::Error>, C)> {
        if self.record.state != OperationState::Prepared {
            return Err((
                JournalError::InvalidState {
                    state: self.record.state,
                },
                command,
            ));
        }
        if self.record.request_hash != request_hash {
            return Err((JournalError::RequestHashMismatch, command));
        }
        if self.record.transmission_count != 0 {
            return Err((JournalError::AlreadyTransmitted, command));
        }
        if let Err(error) = self.persist_update(store, OperationState::Executing, 1) {
            return Err((error, command));
        }
        Ok(PendingCardCommand { command })
    }

    /// Persist an unsuccessful terminal state with the result that reports
    /// it.
    ///
    /// Legal before any transmission and after the one card exchange; the
    /// retained result answers an identical retransmission later.
    ///
    /// # Errors
    /// [`JournalError`] on an illegal state or a persistence failure.
    pub fn finish_failure<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        state: OperationState,
        result: &OperationResultMessage,
    ) -> Result<(), JournalError<S::Error>> {
        if !matches!(
            self.record.state,
            OperationState::Prepared | OperationState::Executing
        ) || !is_unacknowledged_terminal(state)
        {
            return Err(JournalError::InvalidState {
                state: self.record.state,
            });
        }
        let mut next = self.record;
        next.state = state;
        next.automatic_retry_permitted = false;
        store
            .persist_result(&next, result)
            .map_err(JournalError::Persistence)?;
        self.record = next;
        Ok(())
    }

    /// Atomically retain a successful consequential result before sending it.
    ///
    /// # Errors
    /// [`JournalError`] on an illegal state or a persistence failure.
    pub fn finish_completed<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        result: &OperationResultMessage,
    ) -> Result<(), JournalError<S::Error>> {
        self.persist_completed_from(store, result, OperationState::Executing)
    }

    /// Atomically retain a successful registered safe-read result. Safe reads
    /// have no credential-command transmission and no in-flight entry.
    ///
    /// # Errors
    /// [`JournalError`] on an illegal state or a persistence failure.
    pub fn finish_safe_read_completed<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        result: &OperationResultMessage,
    ) -> Result<(), JournalError<S::Error>> {
        self.persist_completed_from(store, result, OperationState::Prepared)
    }

    /// Persist exact result acknowledgment and erase the retained body,
    /// leaving the durable tombstone (section 8.2.5).
    ///
    /// A result whose delivery became uncertain is still acknowledgeable once
    /// it is delivered again.
    ///
    /// # Errors
    /// [`JournalError`] on an illegal state or a persistence failure.
    pub fn acknowledge_result<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<(), JournalError<S::Error>> {
        if !matches!(
            self.record.state,
            OperationState::ResultPending | OperationState::DeliveryUncertain
        ) {
            return Err(JournalError::InvalidState {
                state: self.record.state,
            });
        }
        let mut next = self.record;
        next.state = OperationState::Completed;
        next.automatic_retry_permitted = false;
        store
            .acknowledge_result(&next)
            .map_err(JournalError::Persistence)?;
        self.record = next;
        Ok(())
    }

    /// Retain the result but make automatic redelivery or card retry illegal.
    ///
    /// # Errors
    /// [`JournalError`] on an illegal state or a persistence failure.
    pub fn mark_delivery_uncertain<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<(), JournalError<S::Error>> {
        if self.record.state != OperationState::ResultPending {
            return Err(JournalError::InvalidState {
                state: self.record.state,
            });
        }
        let mut next = self.record;
        next.state = OperationState::DeliveryUncertain;
        next.automatic_retry_permitted = false;
        store
            .retain_uncertain_result(&next)
            .map_err(JournalError::Persistence)?;
        self.record = next;
        Ok(())
    }

    /// Recover an in-flight non-terminal record without retrying it.
    ///
    /// # Errors
    /// [`JournalError`] on an illegal state or a persistence failure.
    pub fn recover_after_crash<S: JournalStore>(
        &mut self,
        store: &mut S,
    ) -> Result<(), JournalError<S::Error>> {
        if !matches!(
            self.record.state,
            OperationState::Committed | OperationState::Executing
        ) {
            return Err(JournalError::InvalidState {
                state: self.record.state,
            });
        }
        self.persist_update(
            store,
            OperationState::Ambiguous,
            self.record.transmission_count,
        )
    }

    fn persist_update<S: JournalStore>(
        &mut self,
        store: &mut S,
        state: OperationState,
        transmission_count: u8,
    ) -> Result<(), JournalError<S::Error>> {
        let mut next = self.record;
        next.state = state;
        next.transmission_count = transmission_count;
        next.automatic_retry_permitted = false;
        store.persist(&next).map_err(JournalError::Persistence)?;
        self.record = next;
        Ok(())
    }

    fn persist_completed_from<S: ResultJournalStore>(
        &mut self,
        store: &mut S,
        result: &OperationResultMessage,
        expected_state: OperationState,
    ) -> Result<(), JournalError<S::Error>> {
        if self.record.state != expected_state {
            return Err(JournalError::InvalidState {
                state: self.record.state,
            });
        }
        let mut next = self.record;
        next.state = OperationState::ResultPending;
        next.automatic_retry_permitted = false;
        store
            .persist_result(&next, result)
            .map_err(JournalError::Persistence)?;
        self.record = next;
        Ok(())
    }
}

const fn is_unacknowledged_terminal(state: OperationState) -> bool {
    matches!(
        state,
        OperationState::Cancelled
            | OperationState::Rejected
            | OperationState::CredentialRejected
            | OperationState::Ambiguous
    )
}

/// One credential command already accounted for in durable state.
///
/// It is deliberately non-clonable. Executing it consumes the wrapper.
#[derive(Debug)]
pub struct PendingCardCommand<C> {
    command: C,
}

impl<C> PendingCardCommand<C> {
    /// Consume the one-shot command into the physical credential adapter.
    pub fn execute<R>(self, transmit_once: impl FnOnce(C) -> R) -> R {
        transmit_once(self.command)
    }
}

#[cfg(test)]
mod tests {
    use super::{JournalRecord, JournalStore, OperationJournal};
    use crate::{OperationId, OperationState, PairId, RequestHash, SessionId};

    #[derive(Default)]
    struct MemoryStore(Vec<JournalRecord>);

    impl JournalStore for MemoryStore {
        type Error = core::convert::Infallible;

        fn persist(&mut self, record: &JournalRecord) -> Result<(), Self::Error> {
            self.0.push(*record);
            Ok(())
        }
    }

    fn journal() -> OperationJournal {
        OperationJournal::prepared(
            PairId::from_array([1; 16]),
            SessionId::from_array([2; 16]),
            OperationId::from_array([3; 16]),
            RequestHash::from_array([4; 32]),
        )
    }

    #[test]
    fn command_is_persisted_before_it_is_exposed_to_transport() {
        let mut journal = journal();
        let mut store = MemoryStore::default();

        let command = journal
            .begin_card_command(&mut store, RequestHash::from_array([4; 32]), "one-shot")
            .expect("the in-flight entry is written once");

        assert_eq!(
            store
                .0
                .last()
                .map(|record| (record.state, record.transmission_count)),
            Some((OperationState::Executing, 1))
        );
        assert_eq!(store.0.len(), 1);
        assert_eq!(command.execute(|value| value), "one-shot");
    }

    #[test]
    fn a_second_command_is_refused() {
        let mut journal = journal();
        let mut store = MemoryStore::default();
        journal
            .begin_card_command(&mut store, RequestHash::from_array([4; 32]), "one-shot")
            .expect("the in-flight entry is written once");
        assert!(
            journal
                .begin_card_command(&mut store, RequestHash::from_array([4; 32]), "again")
                .is_err()
        );
        assert_eq!(store.0.len(), 1);
    }

    #[test]
    fn crash_recovery_is_ambiguous_and_never_retryable() {
        let mut journal = journal();
        let mut store = MemoryStore::default();
        journal
            .begin_card_command(&mut store, RequestHash::from_array([4; 32]), "one-shot")
            .expect("the in-flight entry is written once");
        journal
            .recover_after_crash(&mut store)
            .expect("in-flight record becomes ambiguous");

        assert_eq!(journal.record().state, OperationState::Ambiguous);
        assert!(!journal.record().automatic_retry_permitted);
    }
}
