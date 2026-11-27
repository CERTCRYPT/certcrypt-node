// Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Operation journal — the node's record of what it submitted and the outcome.
//!
//! The node serves several issuers (each through its own issuer application).
//! The journal is therefore **partitioned by `contract_id`** (the issuer
//! scope): every read is scoped, and an issuer can only ever see operations it
//! initiated. Whoever operates the node, it does NOT expose a consultable
//! cross-issuer aggregate graph. Scope lives in the trait, so the
//! isolation is identical across backends (memory, SQLite, …).
//!
//! Roles are distinct and must not be conflated: the *issuer* (through its
//! issuer application) is a CLIENT of the node; the *operator* runs the node. The
//! journal records the operator's node activity, scoped per issuer.
//!
//! Persistence rationale: idempotency/retry around upstream submission and
//! survivable operation status across restarts. The node is NOT an archive or
//! custodian (node boundary) — it stores its own operational state, never the
//! certified material.
//!
//! # Retention
//!
//! Because it is not an archive, the journal forgets. A record is kept for the
//! retention period (see [`crate::retention`]) counted from the moment it became
//! TERMINAL, never from when it was written: an `accepted` member is still
//! settling, and purging it on age alone would answer 404 to an issuer that is
//! polling it right now. Once a record is gone the issuer still has the lookup
//! that outlives every node — `GET /v1/emissions/by-commitment/{digest}`.

use std::collections::HashMap;
use std::sync::RwLock;

/// The node-local lifecycle of one submission-set MEMBER. Under
/// `submission-set/1` each member is an autonomous fixation unit with its
/// own outcome, so the journal records one entry PER MEMBER, not one per submit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OperationState {
    /// Member accepted upstream; the issuance service finalizes it
    /// asynchronously. The `upstream_operation_id` is the member's own
    /// operation id.
    Accepted { upstream_operation_id: String },
    /// Member rejected per-member by the issuance service with an actionable reason.
    Rejected {
        reason_code: String,
        message: String,
    },
    /// Member's commitment was already consumed or already claimed (a replay).
    ReplayDetected { message: String },
    /// The set could not be admitted for lack of applicable capacity: one
    /// verdict for the whole set, recorded once for the submit. `capacity`
    /// carries the service's figures (`required`, `available`, `missing`), the
    /// only capacity answer an issuer gets; absent on records written without
    /// them.
    InsufficientCapacity {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capacity: Option<CapacityShortfall>,
    },
    /// The whole request was rejected upstream BEFORE per-member evaluation
    /// (idempotency conflict, operator-recognition failure, unparseable submission set).
    /// Recorded once for the submit, not per member (no member was reached).
    PreEvaluationRejected {
        reason_code: String,
        message: String,
    },
    /// The signed submission set is durably held in the node's outbox and the
    /// background relay will submit it again (same `request_id`, idempotent).
    /// Two causes:
    /// - the synchronous submit got no answer (a transport failure or a
    ///   transient status): the relay resubmits until the issuance service
    ///   answers;
    /// - the issuance service answered `insufficient_capacity` while the set's
    ///   commitments are still valid: a refused set consumes nothing, so the
    ///   relay submits it again until capacity covers it or the wait window
    ///   closes (see [`crate::capacity_wait`]). `capacity` then carries the
    ///   figures of the latest refusal.
    ///
    /// Non-terminal — the issuer polls `GET /v1/operations/{id}` for the
    /// eventual outcome, or `GET /v1/outbox/dead` if delivery is ever set aside.
    AcceptedForRetry {
        error: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capacity: Option<CapacityShortfall>,
    },
    /// The submission did not get through and the node is NOT holding it for
    /// retry. Terminal for this request.
    ///
    /// Two causes, told apart by `upstream_status`:
    /// - `Some(status)`: the issuance service REFUSED the request with a
    ///   definitive HTTP status (a 4xx other than 408, 425 or 429). Sending the
    ///   same bytes again cannot change that answer, so nothing is queued; the
    ///   issuer must fix the cause before submitting anew.
    /// - `None`: the service answered in a way the node could not use (an
    ///   unrecognized status), or the node could not record the outcome.
    SubmissionFailed {
        error: String,
        /// The HTTP status of a definitive upstream refusal. Absent otherwise,
        /// and on records that do not carry it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        upstream_status: Option<u16>,
    },
}

/// The figures of an `insufficient_capacity` verdict, as decimal strings. The
/// node only relays them, so it does no decimal arithmetic on them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapacityShortfall {
    pub required: String,
    pub available: String,
    pub missing: String,
}

impl OperationState {
    /// A `submission_failed` that is not an upstream refusal.
    pub fn submission_failed(error: impl Into<String>) -> Self {
        OperationState::SubmissionFailed {
            error: error.into(),
            upstream_status: None,
        }
    }
}

impl OperationState {
    /// Whether this state is final the moment it is recorded — nothing the node
    /// or the issuance service does later can change it.
    ///
    /// The two exceptions are the states that wait on something else:
    /// `Accepted` (the issuance service is still settling it; it turns terminal when
    /// a reconciliation sees `independent_ready`, `rejected` or
    /// `insufficient_capacity`) and `AcceptedForRetry` (the outbox still holds
    /// the set; it turns terminal when the issuance service answers for that `request_id`).
    pub fn is_terminal_when_recorded(&self) -> bool {
        !matches!(
            self,
            OperationState::Accepted { .. } | OperationState::AcceptedForRetry { .. }
        )
    }

    /// The serde tag of this state, as stored in `state_json`.
    #[cfg(test)]
    pub(crate) fn tag(&self) -> &'static str {
        match self {
            OperationState::Accepted { .. } => "accepted",
            OperationState::Rejected { .. } => "rejected",
            OperationState::ReplayDetected { .. } => "replay_detected",
            OperationState::InsufficientCapacity { .. } => "insufficient_capacity",
            OperationState::PreEvaluationRejected { .. } => "pre_evaluation_rejected",
            OperationState::AcceptedForRetry { .. } => "accepted_for_retry",
            OperationState::SubmissionFailed { .. } => "submission_failed",
        }
    }
}

/// Upstream operation statuses after which an `Accepted` member can no longer
/// change. Anything else (`processing`, or a status this node does not know)
/// keeps the record open: inventing a terminal state would start the retention
/// clock on an operation that is still moving.
///
/// `expired` (submission-set/1 §11.1): the accepted member can no longer reach
/// Independent and nothing was consumed. Terminal like the others; without it an
/// expired member would never start its retention clock.
pub const UPSTREAM_TERMINAL_STATUSES: [&str; 4] = [
    "independent_ready",
    "rejected",
    "insufficient_capacity",
    "expired",
];

/// Outcome of one bounded purge pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeOutcome {
    /// Records that had no write or terminal timestamp and were stamped with
    /// "now", so their retention starts then instead of never.
    pub stamped: usize,
    /// Records deleted.
    pub purged: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OperationRecord {
    pub operation_id: String,
    /// Issuer scope this operation belongs to. Reads are partitioned on this:
    /// an issuer never sees another issuer's operations.
    pub contract_id: String,
    /// The idempotency key used upstream (ULID); reused on retry.
    pub request_id: String,
    /// The submission set this member belonged to (the issuance service's `submission_set_id`).
    /// Groups the per-member records that came from the same submit. `None` for a
    /// pre-evaluation rejection or a transport failure (no set identity returned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_set_id: Option<String>,
    /// The member's position in the submitted set — what the issuer maps this
    /// record back to. `None` for a whole-request outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_index: Option<usize>,
    pub state: OperationState,
    /// Signed operator receipt for this operation — the node's own record,
    /// signed with its operator identity, that THIS operator processed the
    /// submission set (bound by submission_set_id, not by linkable content). `None` if the node
    /// was started without an operator key. Detachable / opt-in: it does not
    /// affect the verifier verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_receipt: Option<certcrypt_node_core::operator_receipt::OperatorReceipt>,
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal backend error: {0}")]
    Backend(String),
}

/// A scoped operation journal. Every accessor takes a `contract_id` so the
/// partitioning is enforced at the trait boundary, not per backend.
pub trait JournalStore: Send + Sync {
    /// Insert or replace a record (carries its own `contract_id`).
    fn put(&self, record: OperationRecord) -> Result<(), JournalError>;

    /// Fetch a record by id, but ONLY if it belongs to `contract_id`. Returns
    /// `None` both for "not found" and for "exists under another scope" — a
    /// cross-scope lookup is indistinguishable from absence (no leakage).
    fn get_scoped(
        &self,
        contract_id: &str,
        operation_id: &str,
    ) -> Result<Option<OperationRecord>, JournalError>;

    /// List operations for one issuer scope. Never returns other scopes'
    /// records. (Operator-side maintenance access is a separate concern, not
    /// this method.)
    fn list_scoped(&self, contract_id: &str) -> Result<Vec<OperationRecord>, JournalError>;

    /// The records of one submit (`request_id`) within one issuer scope. Used
    /// to keep the ids the issuer already holds: when a delayed submit is
    /// finally answered, each member's outcome is written over the record the
    /// issuer got at submit time, never under a new id it has no way to learn.
    fn list_by_request(
        &self,
        contract_id: &str,
        request_id: &str,
    ) -> Result<Vec<OperationRecord>, JournalError>;

    /// Record that an `Accepted` member reached a terminal upstream status at
    /// `at_ms`. Scoped like every read. Idempotent: the FIRST observation wins,
    /// so polling a settled operation again never pushes its purge further out.
    fn mark_terminal(
        &self,
        contract_id: &str,
        operation_id: &str,
        at_ms: i64,
    ) -> Result<(), JournalError>;

    /// Record that the issuance service answered for `request_id` at `at_ms`: every
    /// `AcceptedForRetry` record of that request is now settled from the node's
    /// side (the relay or a resubmit delivered it). Idempotent like
    /// [`Self::mark_terminal`].
    /// Scoped like every other write: another issuer's records under the same
    /// `request_id` are never touched.
    fn mark_request_resolved(
        &self,
        contract_id: &str,
        request_id: &str,
        at_ms: i64,
    ) -> Result<(), JournalError>;

    /// One bounded purge pass at `now_ms`: stamp at most `limit` records that
    /// lack timestamps, then delete at most `limit` records that are
    /// - terminal for at least `retention_ms`, or
    /// - `Accepted`, never observed terminal, and written at least
    ///   `2 × retention_ms` ago (the node cannot ask the issuance service on its own — a read
    ///   needs the issuer's half of the proof — so an issuer that stopped polling
    ///   would otherwise pin the record forever).
    ///
    /// An `AcceptedForRetry` that was never resolved is NEVER purged: its set is
    /// still in the outbox, possibly dead-lettered, and the record is how the
    /// issuer finds out.
    ///
    /// Bounded on purpose: the caller loops, so no single transaction holds the
    /// write lock long enough to stall `/v1/issue`.
    fn purge_expired(
        &self,
        now_ms: i64,
        retention_ms: i64,
        limit: usize,
    ) -> Result<PurgeOutcome, JournalError>;
}

/// One stored record plus the two timestamps retention runs on.
#[derive(Debug, Clone)]
struct MemoryEntry {
    record: OperationRecord,
    recorded_at_ms: i64,
    terminal_at_ms: Option<i64>,
}

/// In-memory journal, safe for concurrent handlers. For tests and ephemeral
/// dev; SQLite is the default durable backend.
#[derive(Debug, Default)]
pub struct MemoryJournal {
    inner: RwLock<HashMap<String, MemoryEntry>>,
}

impl MemoryJournal {
    pub fn new() -> Self {
        Self::default()
    }
}

impl JournalStore for MemoryJournal {
    fn put(&self, record: OperationRecord) -> Result<(), JournalError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut guard = self.inner.write().expect("journal lock poisoned");
        let previous = guard.get(&record.operation_id);
        // Same rules as the SQLite upsert: the write time is the first write,
        // and an already-observed terminal time is never moved.
        let recorded_at_ms = previous.map_or(now_ms, |p| p.recorded_at_ms);
        let terminal_at_ms = if record.state.is_terminal_when_recorded() {
            Some(previous.and_then(|p| p.terminal_at_ms).unwrap_or(now_ms))
        } else {
            None
        };
        guard.insert(
            record.operation_id.clone(),
            MemoryEntry {
                record,
                recorded_at_ms,
                terminal_at_ms,
            },
        );
        Ok(())
    }

    fn get_scoped(
        &self,
        contract_id: &str,
        operation_id: &str,
    ) -> Result<Option<OperationRecord>, JournalError> {
        let guard = self.inner.read().expect("journal lock poisoned");
        Ok(guard
            .get(operation_id)
            .filter(|e| e.record.contract_id == contract_id)
            .map(|e| e.record.clone()))
    }

    fn list_scoped(&self, contract_id: &str) -> Result<Vec<OperationRecord>, JournalError> {
        let guard = self.inner.read().expect("journal lock poisoned");
        Ok(guard
            .values()
            .filter(|e| e.record.contract_id == contract_id)
            .map(|e| e.record.clone())
            .collect())
    }

    fn list_by_request(
        &self,
        contract_id: &str,
        request_id: &str,
    ) -> Result<Vec<OperationRecord>, JournalError> {
        let guard = self.inner.read().expect("journal lock poisoned");
        Ok(guard
            .values()
            .filter(|e| e.record.contract_id == contract_id && e.record.request_id == request_id)
            .map(|e| e.record.clone())
            .collect())
    }

    fn mark_terminal(
        &self,
        contract_id: &str,
        operation_id: &str,
        at_ms: i64,
    ) -> Result<(), JournalError> {
        let mut guard = self.inner.write().expect("journal lock poisoned");
        if let Some(e) = guard
            .get_mut(operation_id)
            .filter(|e| e.record.contract_id == contract_id)
        {
            if matches!(e.record.state, OperationState::Accepted { .. }) {
                e.terminal_at_ms.get_or_insert(at_ms);
            }
        }
        Ok(())
    }

    fn mark_request_resolved(
        &self,
        contract_id: &str,
        request_id: &str,
        at_ms: i64,
    ) -> Result<(), JournalError> {
        let mut guard = self.inner.write().expect("journal lock poisoned");
        for e in guard.values_mut() {
            if e.record.request_id == request_id
                && e.record.contract_id == contract_id
                && matches!(e.record.state, OperationState::AcceptedForRetry { .. })
            {
                e.terminal_at_ms.get_or_insert(at_ms);
            }
        }
        Ok(())
    }

    fn purge_expired(
        &self,
        now_ms: i64,
        retention_ms: i64,
        limit: usize,
    ) -> Result<PurgeOutcome, JournalError> {
        // Nothing to stamp: every MemoryEntry is born with its timestamps.
        let mut guard = self.inner.write().expect("journal lock poisoned");
        let expired: Vec<String> = guard
            .iter()
            .filter(|(_, e)| is_expired(e, now_ms, retention_ms))
            .map(|(id, _)| id.clone())
            .take(limit)
            .collect();
        for id in &expired {
            guard.remove(id);
        }
        Ok(PurgeOutcome {
            stamped: 0,
            purged: expired.len(),
        })
    }
}

fn is_expired(e: &MemoryEntry, now_ms: i64, retention_ms: i64) -> bool {
    match e.terminal_at_ms {
        Some(t) => t <= now_ms.saturating_sub(retention_ms),
        None => {
            matches!(e.record.state, OperationState::Accepted { .. })
                && e.recorded_at_ms <= now_ms.saturating_sub(retention_ms.saturating_mul(2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(op: &str, contract: &str) -> OperationRecord {
        OperationRecord {
            operation_id: op.into(),
            contract_id: contract.into(),
            request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            submission_set_id: Some("set-1".into()),
            commitment_index: Some(0),
            state: OperationState::Accepted {
                upstream_operation_id: "OP-UP-1".into(),
            },
            operator_receipt: None,
        }
    }

    #[test]
    fn put_then_get_scoped_roundtrips() {
        let store = MemoryJournal::new();
        store.put(rec("op-1", "contract:A")).unwrap();
        let got = store.get_scoped("contract:A", "op-1").unwrap().unwrap();
        assert_eq!(got.request_id, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert!(store.get_scoped("contract:A", "missing").unwrap().is_none());
    }

    #[test]
    fn cross_scope_lookup_returns_none_not_leak() {
        let store = MemoryJournal::new();
        store.put(rec("op-1", "contract:A")).unwrap();
        // Another issuer scope must NOT see op-1, and it's indistinguishable
        // from "not found" (no presence leak).
        assert!(store.get_scoped("contract:B", "op-1").unwrap().is_none());
    }

    #[test]
    fn list_is_scoped() {
        let store = MemoryJournal::new();
        store.put(rec("op-1", "contract:A")).unwrap();
        store.put(rec("op-2", "contract:A")).unwrap();
        store.put(rec("op-3", "contract:B")).unwrap();
        assert_eq!(store.list_scoped("contract:A").unwrap().len(), 2);
        assert_eq!(store.list_scoped("contract:B").unwrap().len(), 1);
        assert_eq!(store.list_scoped("contract:C").unwrap().len(), 0);
    }
}
