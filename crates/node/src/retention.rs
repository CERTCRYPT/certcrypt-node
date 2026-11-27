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

//! Retention — how long the node remembers, and the sweep that makes it forget.
//!
//! The node is not an archive. Its two stores would otherwise grow for as long
//! as it runs, and every future schema change would take longer than the last.
//!
//! What is kept, and for how long:
//!
//! | Row | Leaves when |
//! |---|---|
//! | outbox, confirmed | at once ([`crate::outbox::OutboxStore::mark_submitted`] deletes it) |
//! | outbox, dead-lettered | never automatically — it is the only copy of the signed set |
//! | journal, terminal | `retention` after it became terminal |
//! | journal, `accepted`, never seen terminal | `2 × retention` after it was written |
//! | journal, `accepted_for_retry`, never delivered | never — its set may be dead-lettered |
//!
//! `retention` has a floor, [`MIN_RETENTION`]. An issuer polls
//! `GET /v1/operations/{id}` on its own schedule, and a node that forgets
//! sooner than the issuer looks turns a settled emission into a 404. Below the
//! floor is a configuration error, not something to round up silently: an
//! operator who typed `7` meant something, and finding out that it was ignored
//! is worse than the node refusing to start. After the period, the issuer still
//! has the lookup that outlives any node, `GET /v1/emissions/by-commitment/{digest}`.
//!
//! The sweep works in bounded batches with a pause between them, so the store's
//! single writer is never held long enough to stall `/v1/issue`.

use std::sync::Arc;
use std::time::Duration;

use crate::outbox::OutboxStore;
use crate::store::JournalStore;

/// The shortest retention a node accepts: 30 days.
pub const MIN_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Rejected retention configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RetentionError {
    #[error("journal retention of {requested_days} days is below the minimum of {min_days} days")]
    BelowMinimum { requested_days: u64, min_days: u64 },
    #[error("{var} must be a whole number of days, got {value:?}")]
    Unparseable { var: String, value: String },
}

/// How long terminal journal records are kept, and how the sweep paces itself.
///
/// The period can only be set through [`RetentionPolicy::with_retention_days`],
/// which enforces [`MIN_RETENTION`]: the field is private so that no embedder
/// can build a policy under the floor by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    retention: Duration,
    /// Pause between sweeps.
    pub sweep_interval: Duration,
    /// Rows touched per batch.
    pub batch: usize,
    /// Pause between batches within one sweep — the gap `/v1/issue` writes
    /// through.
    pub batch_pause: Duration,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retention: MIN_RETENTION,
            sweep_interval: Duration::from_secs(10 * 60),
            batch: 500,
            batch_pause: Duration::from_millis(50),
        }
    }
}

impl RetentionPolicy {
    /// Set the retention period in days. Fails below [`MIN_RETENTION`].
    pub fn with_retention_days(mut self, days: u64) -> Result<Self, RetentionError> {
        let min_days = MIN_RETENTION.as_secs() / 86_400;
        if days < min_days {
            return Err(RetentionError::BelowMinimum {
                requested_days: days,
                min_days,
            });
        }
        self.retention = Duration::from_secs(days.saturating_mul(86_400));
        Ok(self)
    }

    /// The retention period in force.
    pub fn retention(&self) -> Duration {
        self.retention
    }

    /// Read `{prefix}JOURNAL_RETENTION_DAYS`; unset means the default (the
    /// minimum). Unlike [`crate::HttpLimits::from_env_prefixed`], a bad value is
    /// an error rather than a fallback: backpressure must never stop a node
    /// from booting, but a retention the operator did not get is a promise to
    /// issuers that the node silently breaks.
    pub fn from_env_prefixed(prefix: &str) -> Result<Self, RetentionError> {
        let var = format!("{prefix}JOURNAL_RETENTION_DAYS");
        match std::env::var(&var) {
            Err(_) => Ok(Self::default()),
            Ok(value) => {
                let days =
                    value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| RetentionError::Unparseable {
                            var: var.clone(),
                            value: value.clone(),
                        })?;
                Self::default().with_retention_days(days)
            }
        }
    }
}

/// The background sweep. Spawn [`RetentionSweeper::run`] once per node.
pub struct RetentionSweeper {
    journal: Arc<dyn JournalStore>,
    outbox: Arc<dyn OutboxStore>,
    policy: RetentionPolicy,
}

impl RetentionSweeper {
    pub fn new(
        journal: Arc<dyn JournalStore>,
        outbox: Arc<dyn OutboxStore>,
        policy: RetentionPolicy,
    ) -> Self {
        Self {
            journal,
            outbox,
            policy,
        }
    }

    /// Sweep forever, one pass every `sweep_interval`.
    pub async fn run(self) {
        loop {
            self.sweep_once(chrono::Utc::now().timestamp_millis()).await;
            tokio::time::sleep(self.policy.sweep_interval).await;
        }
    }

    /// One full pass at `now_ms`: batches until a batch comes back short.
    /// Errors are logged and end the pass; the next pass retries. Returns the
    /// rows purged, for tests and logs.
    pub async fn sweep_once(&self, now_ms: i64) -> usize {
        let retention_ms = i64::try_from(self.policy.retention.as_millis()).unwrap_or(i64::MAX);
        let batch = self.policy.batch.max(1);
        let mut purged = 0usize;

        loop {
            let journal = self.journal.clone();
            let r = crate::blocking::store_call(move || {
                journal.purge_expired(now_ms, retention_ms, batch)
            })
            .await;
            match r {
                Ok(Ok(out)) => {
                    purged += out.purged;
                    if out.purged < batch && out.stamped < batch {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "retention: journal purge failed");
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "retention: journal purge did not complete");
                    break;
                }
            }
            tokio::time::sleep(self.policy.batch_pause).await;
        }

        loop {
            let outbox = self.outbox.clone();
            match crate::blocking::store_call(move || outbox.purge_submitted(batch)).await {
                Ok(Ok(n)) => {
                    purged += n;
                    if n < batch {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "retention: outbox purge failed");
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "retention: outbox purge did not complete");
                    break;
                }
            }
            tokio::time::sleep(self.policy.batch_pause).await;
        }

        if purged > 0 {
            tracing::info!(purged, "retention sweep");
        }
        purged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::{MemoryOutbox, SqliteOutbox};
    use crate::sqlite_journal::SqliteJournal;
    use crate::store::{MemoryJournal, OperationRecord, OperationState};

    const DAY_MS: i64 = 86_400_000;
    const R_MS: i64 = 30 * DAY_MS;

    fn rec(op: &str, request: &str, state: OperationState) -> OperationRecord {
        OperationRecord {
            operation_id: op.into(),
            contract_id: "contract:A".into(),
            request_id: request.into(),
            submission_set_id: None,
            commitment_index: None,
            state,
            operator_receipt: None,
        }
    }

    fn accepted() -> OperationState {
        OperationState::Accepted {
            upstream_operation_id: "UP".into(),
        }
    }

    fn rejected() -> OperationState {
        OperationState::Rejected {
            reason_code: "x".into(),
            message: "x".into(),
        }
    }

    fn for_retry() -> OperationState {
        OperationState::AcceptedForRetry {
            error: "down".into(),
            capacity: None,
        }
    }

    fn backends() -> Vec<(&'static str, Arc<dyn JournalStore>)> {
        vec![
            ("memory", Arc::new(MemoryJournal::new())),
            ("sqlite", Arc::new(SqliteJournal::open(":memory:").unwrap())),
        ]
    }

    fn exists(j: &Arc<dyn JournalStore>, op: &str) -> bool {
        j.get_scoped("contract:A", op).unwrap().is_some()
    }

    #[test]
    fn retention_below_thirty_days_is_refused() {
        assert_eq!(
            RetentionPolicy::default().with_retention_days(29),
            Err(RetentionError::BelowMinimum {
                requested_days: 29,
                min_days: 30
            })
        );
        assert!(RetentionPolicy::default().with_retention_days(0).is_err());
        let p = RetentionPolicy::default().with_retention_days(30).unwrap();
        assert_eq!(p.retention(), MIN_RETENTION);
        let p = RetentionPolicy::default().with_retention_days(90).unwrap();
        assert_eq!(p.retention().as_secs(), 90 * 86_400);
        assert_eq!(RetentionPolicy::default().retention(), MIN_RETENTION);
    }

    #[test]
    fn env_value_below_minimum_or_garbage_is_an_error_not_a_fallback() {
        // A per-test prefix: tests run in parallel and share the environment.
        let prefix = "RETENTION_TEST_A_";
        std::env::set_var(format!("{prefix}JOURNAL_RETENTION_DAYS"), "7");
        assert!(matches!(
            RetentionPolicy::from_env_prefixed(prefix),
            Err(RetentionError::BelowMinimum { .. })
        ));
        std::env::set_var(format!("{prefix}JOURNAL_RETENTION_DAYS"), "thirty");
        assert!(matches!(
            RetentionPolicy::from_env_prefixed(prefix),
            Err(RetentionError::Unparseable { .. })
        ));
        std::env::set_var(format!("{prefix}JOURNAL_RETENTION_DAYS"), "45");
        assert_eq!(
            RetentionPolicy::from_env_prefixed(prefix)
                .unwrap()
                .retention()
                .as_secs(),
            45 * 86_400
        );
        std::env::remove_var(format!("{prefix}JOURNAL_RETENTION_DAYS"));
        assert_eq!(
            RetentionPolicy::from_env_prefixed(prefix)
                .unwrap()
                .retention(),
            MIN_RETENTION
        );
    }

    #[test]
    fn terminal_record_is_kept_for_the_period_then_purged() {
        for (name, j) in backends() {
            let t0 = chrono::Utc::now().timestamp_millis();
            j.put(rec("op-r", "req-1", rejected())).unwrap();
            let out = j.purge_expired(t0 + R_MS - DAY_MS, R_MS, 100).unwrap();
            assert_eq!(out.purged, 0, "{name}: one day short of the period");
            assert!(exists(&j, "op-r"), "{name}");
            let out = j.purge_expired(t0 + R_MS + DAY_MS, R_MS, 100).unwrap();
            assert_eq!(out.purged, 1, "{name}: past the period");
            assert!(!exists(&j, "op-r"), "{name}");
        }
    }

    #[test]
    fn accepted_counts_from_terminal_not_from_creation() {
        for (name, j) in backends() {
            let t0 = chrono::Utc::now().timestamp_millis();
            j.put(rec("op-a", "req-1", accepted())).unwrap();
            // Settled late: observed terminal 20 days after it was written.
            j.mark_terminal("contract:A", "op-a", t0 + 20 * DAY_MS)
                .unwrap();
            // 40 days after creation, but only 20 after terminal: kept.
            j.purge_expired(t0 + 40 * DAY_MS, R_MS, 100).unwrap();
            assert!(exists(&j, "op-a"), "{name}: retention counts from terminal");
            // A later poll must not push the clock out (first observation wins).
            j.mark_terminal("contract:A", "op-a", t0 + 45 * DAY_MS)
                .unwrap();
            let out = j.purge_expired(t0 + 51 * DAY_MS, R_MS, 100).unwrap();
            assert_eq!(out.purged, 1, "{name}: 31 days after the first terminal");
        }
    }

    #[test]
    fn mark_terminal_is_scoped() {
        for (name, j) in backends() {
            let t0 = chrono::Utc::now().timestamp_millis();
            j.put(rec("op-a", "req-1", accepted())).unwrap();
            // Another contract cannot start this record's clock.
            j.mark_terminal("contract:B", "op-a", t0).unwrap();
            j.purge_expired(t0 + R_MS + DAY_MS, R_MS, 100).unwrap();
            assert!(exists(&j, "op-a"), "{name}");
        }
    }

    #[test]
    fn accepted_never_seen_terminal_waits_twice_the_period() {
        for (name, j) in backends() {
            let t0 = chrono::Utc::now().timestamp_millis();
            j.put(rec("op-a", "req-1", accepted())).unwrap();
            j.purge_expired(t0 + 2 * R_MS - DAY_MS, R_MS, 100).unwrap();
            assert!(exists(&j, "op-a"), "{name}: under 2R");
            let out = j.purge_expired(t0 + 2 * R_MS + DAY_MS, R_MS, 100).unwrap();
            assert_eq!(out.purged, 1, "{name}: past 2R");
        }
    }

    #[test]
    fn unresolved_retry_is_never_purged_and_resolution_starts_its_clock() {
        for (name, j) in backends() {
            let t0 = chrono::Utc::now().timestamp_millis();
            j.put(rec("op-f", "req-9", for_retry())).unwrap();
            j.purge_expired(t0 + 10 * R_MS, R_MS, 100).unwrap();
            assert!(exists(&j, "op-f"), "{name}: its set may be dead-lettered");
            // Another issuer resolving the same request_id starts nothing here.
            j.mark_request_resolved("contract:B", "req-9", t0 + 10 * R_MS)
                .unwrap();
            j.purge_expired(t0 + 12 * R_MS + DAY_MS, R_MS, 100).unwrap();
            assert!(exists(&j, "op-f"), "{name}: another scope's resolution");
            j.mark_request_resolved("contract:A", "req-9", t0 + 10 * R_MS)
                .unwrap();
            j.purge_expired(t0 + 10 * R_MS + DAY_MS, R_MS, 100).unwrap();
            assert!(exists(&j, "op-f"), "{name}: resolved, clock just started");
            let out = j.purge_expired(t0 + 11 * R_MS + DAY_MS, R_MS, 100).unwrap();
            assert_eq!(out.purged, 1, "{name}");
        }
    }

    #[test]
    fn rewriting_a_record_does_not_restart_its_clock() {
        for (name, j) in backends() {
            let t0 = chrono::Utc::now().timestamp_millis();
            j.put(rec("op-r", "req-1", rejected())).unwrap();
            j.put(rec("op-r", "req-1", rejected())).unwrap();
            let out = j.purge_expired(t0 + R_MS + DAY_MS, R_MS, 100).unwrap();
            assert_eq!(out.purged, 1, "{name}");
        }
    }

    #[test]
    fn purge_is_bounded_by_the_batch() {
        for (name, j) in backends() {
            let t0 = chrono::Utc::now().timestamp_millis();
            for i in 0..5 {
                j.put(rec(&format!("op-{i}"), "req", rejected())).unwrap();
            }
            let later = t0 + R_MS + DAY_MS;
            assert_eq!(j.purge_expired(later, R_MS, 2).unwrap().purged, 2, "{name}");
            assert_eq!(j.purge_expired(later, R_MS, 2).unwrap().purged, 2, "{name}");
            assert_eq!(j.purge_expired(later, R_MS, 2).unwrap().purged, 1, "{name}");
        }
    }

    #[test]
    fn rows_from_before_the_timestamps_start_their_clock_at_the_sweep() {
        let j = SqliteJournal::open(":memory:").unwrap();
        j.put(rec("op-old", "req-1", rejected())).unwrap();
        j.put(rec("op-old-acc", "req-2", accepted())).unwrap();
        // What an earlier node left: no timestamps at all.
        j.with_conn_for_test(|c| {
            c.execute(
                "UPDATE operations SET recorded_at_ms = NULL, terminal_at_ms = NULL",
                [],
            )
            .unwrap();
        });
        let sweep_at = chrono::Utc::now().timestamp_millis() + 400 * DAY_MS;
        let out = j.purge_expired(sweep_at, R_MS, 100).unwrap();
        assert_eq!(out.purged, 0, "never purged on the pass that stamps them");
        assert_eq!(out.stamped, 3, "two write stamps plus one terminal stamp");
        let j: Arc<dyn JournalStore> = Arc::new(j);
        assert!(exists(&j, "op-old"));
        let out = j
            .purge_expired(sweep_at + R_MS + DAY_MS, R_MS, 100)
            .unwrap();
        assert_eq!(out.purged, 1, "the terminal one goes R after the stamp");
        assert!(exists(&j, "op-old-acc"), "the open one waits 2R");
    }

    #[tokio::test]
    async fn sweep_drains_every_batch_and_the_legacy_outbox() {
        let journal: Arc<dyn JournalStore> = Arc::new(SqliteJournal::open(":memory:").unwrap());
        let outbox: Arc<dyn OutboxStore> = Arc::new(SqliteOutbox::open(":memory:").unwrap());
        let t0 = chrono::Utc::now().timestamp_millis();
        for i in 0..7 {
            journal
                .put(rec(&format!("op-{i}"), "req", rejected()))
                .unwrap();
        }
        let policy = RetentionPolicy {
            batch: 3,
            batch_pause: Duration::ZERO,
            ..RetentionPolicy::default()
        };
        let sweeper = RetentionSweeper::new(journal.clone(), outbox, policy);
        assert_eq!(sweeper.sweep_once(t0 + R_MS + DAY_MS).await, 7);
        assert_eq!(sweeper.sweep_once(t0 + R_MS + DAY_MS).await, 0);

        // Memory backends take the same path.
        let sweeper = RetentionSweeper::new(
            Arc::new(MemoryJournal::new()),
            Arc::new(MemoryOutbox::new()),
            policy,
        );
        assert_eq!(sweeper.sweep_once(t0).await, 0);
    }
}
