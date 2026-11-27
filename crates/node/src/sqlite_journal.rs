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

//! SQLite-backed operation journal — the node's default durable store.
//!
//! Embedded (bundled) SQLite: a single file per node instance, no server, no
//! central infra. This fits the node as a portable operator-side component
//! (single binary) and keeps the operational state local to the operator. The
//! issuer-scope partitioning (`contract_id`) lives in the [`JournalStore`]
//! trait, so every query here is filtered by scope — the isolation is identical
//! to the memory backend.

use std::sync::Mutex;

use rusqlite::Connection;

use crate::store::{JournalError, JournalStore, OperationRecord, OperationState, PurgeOutcome};

/// `state_json` tags whose records are terminal the moment they are written.
/// Used only to stamp rows that carry no `terminal_at_ms`; new rows
/// get their stamp from [`OperationState::is_terminal_when_recorded`] in `put`.
/// Kept as SQL text so the stamping UPDATE needs no row-by-row decode.
const TERMINAL_WHEN_RECORDED_SQL: &str = "('rejected', 'replay_detected', \
     'insufficient_capacity', 'pre_evaluation_rejected', 'submission_failed')";

impl From<rusqlite::Error> for JournalError {
    fn from(e: rusqlite::Error) -> Self {
        JournalError::Backend(e.to_string())
    }
}

/// SQLite operation journal. One connection behind a `std::sync::Mutex`.
///
/// The mutex stays SYNCHRONOUS on purpose: SQLite is blocking I/O and belongs
/// off the executor entirely, so `async` callers wrap these methods in
/// `tokio::task::spawn_blocking` (see [`crate::blocking`]) rather than trading
/// the lock for an async one. Write volume is low and a pool is still
/// unnecessary — WAL (applied on open) lifts one connection well past what the
/// node asks of it.
pub struct SqliteJournal {
    conn: Mutex<Connection>,
}

impl SqliteJournal {
    /// Open (or create) the journal at `path` with default [`StoreOptions`]
    /// (durable: fsync per commit). Use `":memory:"` for an ephemeral DB in
    /// tests.
    pub fn open(path: &str) -> Result<Self, JournalError> {
        Self::open_with_options(path, crate::blocking::StoreOptions::default())
    }

    /// Open (or create) the journal with explicit store options — durability
    /// level and lock patience. See [`crate::blocking::StoreOptions`].
    ///
    /// The journal records resolved outcomes rather than in-flight delivery
    /// state, so relaxing durability here is a smaller loss than on the outbox:
    /// a lost journal row costs an operator's record of what happened, not a
    /// submission the caller believes was accepted.
    pub fn open_with_options(
        path: &str,
        options: crate::blocking::StoreOptions,
    ) -> Result<Self, JournalError> {
        let conn = Connection::open(path)?;
        crate::blocking::apply_store_pragmas(&conn, options)
            .map_err(|e| JournalError::Backend(format!("journal pragmas: {e}")))?;
        crate::blocking::ensure_incremental_vacuum(&conn)
            .map_err(|e| JournalError::Backend(format!("journal auto_vacuum: {e}")))?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn init(conn: &Connection) -> Result<(), JournalError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS operations (
                 operation_id TEXT PRIMARY KEY,
                 contract_id  TEXT NOT NULL,
                 request_id   TEXT NOT NULL,
                 state_json   TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_operations_contract
                 ON operations (contract_id);",
        )?;
        // Additive migrations for nullable columns (rows predating them just have
        // NULL). ADD COLUMN errors if the column already exists, so swallow that
        // one case. The submission-set columns group the per-member records that
        // came from the same submit (NULL for whole-request outcomes).
        //
        // ADD COLUMN is O(1) in SQLite, which is why it may run here, before the
        // node serves. Anything that rewrites rows does NOT belong in `init`: it
        // would hold the write lock for the whole copy while `/v1/issue` waits.
        // The retention timestamps follow that rule — rows that predate them are
        // stamped later, in bounded batches, by `purge_expired`.
        for col in [
            "operator_receipt_json TEXT",
            "submission_set_id TEXT",
            "commitment_index INTEGER",
            "recorded_at_ms INTEGER",
            "terminal_at_ms INTEGER",
        ] {
            match conn.execute(&format!("ALTER TABLE operations ADD COLUMN {col}"), []) {
                Ok(_) => {}
                Err(e) if e.to_string().contains("duplicate column name") => {}
                Err(e) => return Err(JournalError::Backend(format!("add column: {e}"))),
            }
        }
        // The retention sweep's two predicates. Partial indexes keep them small:
        // the open-record one only ever covers `accepted` rows still settling.
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_operations_terminal_at
                 ON operations (terminal_at_ms) WHERE terminal_at_ms IS NOT NULL;
             CREATE INDEX IF NOT EXISTS idx_operations_open_recorded_at
                 ON operations (recorded_at_ms) WHERE terminal_at_ms IS NULL;
             CREATE INDEX IF NOT EXISTS idx_operations_request
                 ON operations (request_id);",
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn row_to_record(
        operation_id: String,
        contract_id: String,
        request_id: String,
        state_json: String,
        operator_receipt_json: Option<String>,
        submission_set_id: Option<String>,
        commitment_index: Option<i64>,
    ) -> Result<OperationRecord, JournalError> {
        let state: OperationState = serde_json::from_str(&state_json)
            .map_err(|e| JournalError::Backend(format!("state_json decode: {e}")))?;
        let operator_receipt = match operator_receipt_json {
            Some(j) => Some(
                serde_json::from_str(&j)
                    .map_err(|e| JournalError::Backend(format!("receipt decode: {e}")))?,
            ),
            None => None,
        };
        Ok(OperationRecord {
            operation_id,
            contract_id,
            request_id,
            submission_set_id,
            commitment_index: commitment_index.map(|i| i as usize),
            state,
            operator_receipt,
        })
    }
}

impl JournalStore for SqliteJournal {
    fn put(&self, record: OperationRecord) -> Result<(), JournalError> {
        let state_json = serde_json::to_string(&record.state)
            .map_err(|e| JournalError::Backend(format!("state_json encode: {e}")))?;
        let receipt_json = match &record.operator_receipt {
            Some(a) => Some(
                serde_json::to_string(a)
                    .map_err(|e| JournalError::Backend(format!("receipt encode: {e}")))?,
            ),
            None => None,
        };
        let now_ms = chrono::Utc::now().timestamp_millis();
        let terminal_at_ms = record.state.is_terminal_when_recorded().then_some(now_ms);
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        // On conflict the write time stays the FIRST write, and an
        // already-observed terminal time is kept rather than moved: a record
        // rewritten later must not buy itself a fresh retention period.
        conn.execute(
            "INSERT INTO operations
                 (operation_id, contract_id, request_id, state_json, operator_receipt_json,
                  submission_set_id, commitment_index, recorded_at_ms, terminal_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(operation_id) DO UPDATE SET
                 contract_id = excluded.contract_id,
                 request_id  = excluded.request_id,
                 state_json  = excluded.state_json,
                 operator_receipt_json = excluded.operator_receipt_json,
                 submission_set_id = excluded.submission_set_id,
                 commitment_index = excluded.commitment_index,
                 recorded_at_ms = COALESCE(operations.recorded_at_ms, excluded.recorded_at_ms),
                 terminal_at_ms = CASE
                     WHEN excluded.terminal_at_ms IS NULL THEN NULL
                     ELSE COALESCE(operations.terminal_at_ms, excluded.terminal_at_ms)
                 END",
            rusqlite::params![
                record.operation_id,
                record.contract_id,
                record.request_id,
                state_json,
                receipt_json,
                record.submission_set_id,
                record.commitment_index.map(|i| i as i64),
                now_ms,
                terminal_at_ms,
            ],
        )?;
        Ok(())
    }

    fn get_scoped(
        &self,
        contract_id: &str,
        operation_id: &str,
    ) -> Result<Option<OperationRecord>, JournalError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        // The contract_id is part of the WHERE clause: a cross-scope lookup
        // returns no row, indistinguishable from "not found".
        let mut stmt = conn.prepare(
            "SELECT operation_id, contract_id, request_id, state_json, operator_receipt_json,
                    submission_set_id, commitment_index
             FROM operations WHERE operation_id = ?1 AND contract_id = ?2",
        )?;
        let mut rows = stmt.query(rusqlite::params![operation_id, contract_id])?;
        match rows.next()? {
            Some(row) => Ok(Some(Self::row_to_record(
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            )?)),
            None => Ok(None),
        }
    }

    fn list_scoped(&self, contract_id: &str) -> Result<Vec<OperationRecord>, JournalError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT operation_id, contract_id, request_id, state_json, operator_receipt_json,
                    submission_set_id, commitment_index
             FROM operations WHERE contract_id = ?1 ORDER BY operation_id",
        )?;
        let rows = stmt.query_map(rusqlite::params![contract_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (op, c, req, st, att, set_id, idx) = r?;
            out.push(Self::row_to_record(op, c, req, st, att, set_id, idx)?);
        }
        Ok(out)
    }

    fn list_by_request(
        &self,
        contract_id: &str,
        request_id: &str,
    ) -> Result<Vec<OperationRecord>, JournalError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT operation_id, contract_id, request_id, state_json, operator_receipt_json,
                    submission_set_id, commitment_index
             FROM operations WHERE request_id = ?1 AND contract_id = ?2 ORDER BY operation_id",
        )?;
        let rows = stmt.query_map(rusqlite::params![request_id, contract_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (op, c, req, st, att, set_id, idx) = r?;
            out.push(Self::row_to_record(op, c, req, st, att, set_id, idx)?);
        }
        Ok(out)
    }

    fn mark_terminal(
        &self,
        contract_id: &str,
        operation_id: &str,
        at_ms: i64,
    ) -> Result<(), JournalError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "UPDATE operations SET terminal_at_ms = ?3
             WHERE operation_id = ?1 AND contract_id = ?2
               AND terminal_at_ms IS NULL
               AND json_extract(state_json, '$.state') = 'accepted'",
            rusqlite::params![operation_id, contract_id, at_ms],
        )?;
        Ok(())
    }

    fn mark_request_resolved(
        &self,
        contract_id: &str,
        request_id: &str,
        at_ms: i64,
    ) -> Result<(), JournalError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "UPDATE operations SET terminal_at_ms = ?3
             WHERE contract_id = ?1 AND request_id = ?2
               AND terminal_at_ms IS NULL
               AND json_extract(state_json, '$.state') = 'accepted_for_retry'",
            rusqlite::params![contract_id, request_id, at_ms],
        )?;
        Ok(())
    }

    fn purge_expired(
        &self,
        now_ms: i64,
        retention_ms: i64,
        limit: usize,
    ) -> Result<PurgeOutcome, JournalError> {
        let limit = limit as i64;
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        // 1. Rows written before the timestamps existed. Their retention starts
        //    now — the conservative choice: the node never learned their real
        //    age, and guessing low would purge records an issuer may still read.
        let mut stamped = conn.execute(
            "UPDATE operations SET recorded_at_ms = ?1
             WHERE rowid IN (SELECT rowid FROM operations
                             WHERE recorded_at_ms IS NULL LIMIT ?2)",
            rusqlite::params![now_ms, limit],
        )?;
        stamped += conn.execute(
            &format!(
                "UPDATE operations SET terminal_at_ms = ?1
                 WHERE rowid IN (SELECT rowid FROM operations
                                 WHERE terminal_at_ms IS NULL
                                   AND json_extract(state_json, '$.state')
                                       IN {TERMINAL_WHEN_RECORDED_SQL}
                                 LIMIT ?2)"
            ),
            rusqlite::params![now_ms, limit],
        )?;
        // 2. The purge itself. See `JournalStore::purge_expired` for the rules.
        let purged = conn.execute(
            "DELETE FROM operations
             WHERE rowid IN (
                 SELECT rowid FROM operations
                 WHERE terminal_at_ms IS NOT NULL AND terminal_at_ms <= ?1 - ?2
                 UNION ALL
                 SELECT rowid FROM operations
                 WHERE terminal_at_ms IS NULL
                   AND recorded_at_ms <= ?1 - 2 * ?2
                   AND json_extract(state_json, '$.state') = 'accepted'
                 LIMIT ?3)",
            rusqlite::params![now_ms, retention_ms, limit],
        )?;
        // 3. Deleting only marks pages free; hand a bounded number back to the
        //    filesystem so the file actually shrinks, without one long pass.
        if purged > 0 {
            crate::blocking::incremental_vacuum(&conn, crate::blocking::VACUUM_PAGES_PER_PASS)?;
        }
        Ok(PurgeOutcome { stamped, purged })
    }
}

#[cfg(test)]
impl SqliteJournal {
    /// Raw connection access for tests that must recreate an older on-disk
    /// layout.
    pub(crate) fn with_conn_for_test<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        f(&self.conn.lock().expect("sqlite mutex poisoned"))
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
                upstream_operation_id: "OP-UP".into(),
            },
            operator_receipt: None,
        }
    }

    #[test]
    fn roundtrip_and_scope_isolation() {
        let j = SqliteJournal::open(":memory:").unwrap();
        j.put(rec("op-1", "contract:A")).unwrap();
        j.put(rec("op-2", "contract:A")).unwrap();
        j.put(rec("op-3", "contract:B")).unwrap();

        // Scoped get.
        assert!(j.get_scoped("contract:A", "op-1").unwrap().is_some());
        // Cross-scope get returns None (no leak).
        assert!(j.get_scoped("contract:B", "op-1").unwrap().is_none());
        // Scoped list.
        assert_eq!(j.list_scoped("contract:A").unwrap().len(), 2);
        assert_eq!(j.list_scoped("contract:B").unwrap().len(), 1);

        // State survives the JSON round-trip.
        let got = j.get_scoped("contract:A", "op-1").unwrap().unwrap();
        assert!(matches!(got.state, OperationState::Accepted { .. }));
        // The submission-set grouping columns survive too.
        assert_eq!(got.submission_set_id.as_deref(), Some("set-1"));
        assert_eq!(got.commitment_index, Some(0));
    }

    #[test]
    fn terminal_sql_list_matches_the_enum() {
        // The stamping UPDATE filters on a hand-written tag list. A new
        // terminal state added to the enum but not to that list would never be
        // stamped on unstamped rows, so it would never be purged — silently.
        let all = [
            OperationState::Accepted {
                upstream_operation_id: "u".into(),
            },
            OperationState::Rejected {
                reason_code: "r".into(),
                message: "m".into(),
            },
            OperationState::ReplayDetected {
                message: "m".into(),
            },
            OperationState::InsufficientCapacity {
                capacity: Some(crate::store::CapacityShortfall {
                    required: "5.00".into(),
                    available: "2.00".into(),
                    missing: "3.00".into(),
                }),
            },
            OperationState::PreEvaluationRejected {
                reason_code: "r".into(),
                message: "m".into(),
            },
            OperationState::AcceptedForRetry {
                error: "e".into(),
                capacity: None,
            },
            OperationState::submission_failed("e"),
        ];
        for st in &all {
            let json: serde_json::Value = serde_json::to_value(st).unwrap();
            assert_eq!(json["state"], st.tag(), "tag() must match serde");
            let quoted = format!("'{}'", st.tag());
            assert_eq!(
                TERMINAL_WHEN_RECORDED_SQL.contains(&quoted),
                st.is_terminal_when_recorded(),
                "{} is misclassified in TERMINAL_WHEN_RECORDED_SQL",
                st.tag()
            );
        }
    }

    #[test]
    fn put_is_upsert() {
        let j = SqliteJournal::open(":memory:").unwrap();
        j.put(rec("op-1", "contract:A")).unwrap();
        let mut updated = rec("op-1", "contract:A");
        updated.state = OperationState::Rejected {
            reason_code: "submission_set_invalid".into(),
            message: "x".into(),
        };
        j.put(updated).unwrap();
        let got = j.get_scoped("contract:A", "op-1").unwrap().unwrap();
        assert!(matches!(got.state, OperationState::Rejected { .. }));
        assert_eq!(
            j.list_scoped("contract:A").unwrap().len(),
            1,
            "upsert, not insert"
        );
    }
}
