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

//! Transactional outbox — durable resilience for the submit to the issuance
//! service.
//!
//! When `/v1/issue` builds a submission-set, the node writes it here as
//! `Pending` BEFORE the upstream POST. A background relay reclaims due entries
//! and resubmits with the SAME `request_id` until the issuance service
//! confirms — surviving a service outage, a node restart, and even the client
//! dying. The service deduplicates on (contract, `request_id`) and replays its
//! answer, which makes the retry safe: at-least-once delivery + idempotent
//! consumer = exactly-once effective.
//!
//! A set the service answers with `insufficient_capacity` stays here while its
//! commitments are valid: the refusal consumed nothing, and the relay submits
//! it again on the schedule of [`crate::capacity_wait`].
//!
//! A submission the service REFUSES (a definitive 4xx) does not stay here:
//! sending the same bytes again cannot change the answer. On the synchronous
//! path the entry is removed and the issuer is told at once; during background
//! delivery it is dead-lettered on the spot.
//!
//! Two delivery invariants the entry MUST respect:
//! - **No re-signing:** we store the holder-signed `SubmissionSetV1` VERBATIM and
//!   resend the SAME bytes. A retry NEVER re-signs the evidence (re-signing with
//!   another key-set leaf would create two evidences for one emission →
//!   correlatable). (The operator-recognition proof IS re-signed per attempt —
//!   it is the operator's, not the holder's, and binds request_id+set_id which
//!   are stable.)
//! - **Zero-data, precisely:** the stored `SubmissionSetV1` never contains the
//!   certified payload — that is the custody claim, and it holds. But only its
//!   `capacity_evidence` half is the pseudonymous projection; the `operative`
//!   half carries `holder_id` and `pool_id` IN CLEAR (see `OperativeContext` in
//!   capacity-artifacts/src/submission_set.rs, whose own doc says so). So a
//!   pending row is a client→artifact link on disk, and stays one until the
//!   submission is confirmed. That is why `mark_submitted` DELETEs the row
//!   rather than flagging it: once the issuance service has answered, the node
//!   will never resend it, and keeping the link would be custody with no
//!   purpose. A re-admit of the same `request_id` afterward is safe — the
//!   issuance service, not this table, is what deduplicates: it deduplicates on
//!   (contract, `request_id`).
//!   `mark_dead` still only flags: a dead row is the one place the signed set
//!   survives, and it stays until an operator acts on it.
//!
//! Scope: like the journal, the outbox is partitioned by `contract_id`, so one
//! issuer never sees another's entries.

/// Lifecycle of one outbox entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    /// Awaiting (re)delivery to the issuance service. The relay picks these up when due.
    Pending,
    /// Confirmed upstream (per-member outcome received). Terminal. The node
    /// deletes a confirmed row instead of storing this state; a row that
    /// carries it still parses, and [`OutboxStore::purge_submitted`] removes
    /// it.
    Submitted,
    /// Set aside: refused by the issuance service during background delivery,
    /// unparseable, or out of `max_attempts`. Dead-letter — visible, never
    /// silently dropped.
    Dead,
}

/// One submission-set awaiting durable delivery to the issuance service. Keyed by
/// `request_id` (the idempotency key), so re-admitting the same id is a no-op
/// upsert — never a duplicate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OutboxEntry {
    /// Idempotency key (the issuance service dedupes on it). Stable across every
    /// retry. Unique WITHIN its scope only: the key is (`contract_id`,
    /// `request_id`), so two issuers that pick the same id hold two entries and
    /// neither can touch the other's.
    pub request_id: String,
    /// Issuer scope (the partition key, first half of the key).
    pub contract_id: String,
    /// The holder-signed `SubmissionSetV1`, serialized VERBATIM. Resent
    /// byte-identical on every retry; it is never re-signed. Zero-data.
    pub submission_set_json: String,
    pub state: OutboxState,
    /// How many delivery attempts have been made.
    pub attempts: u32,
    /// Epoch milliseconds; the relay only claims entries with `next_attempt_at <= now`.
    pub next_attempt_at_ms: i64,
    /// Epoch milliseconds the entry was first admitted.
    pub created_at_ms: i64,
    /// Last delivery error (for diagnostics / dead-letter inspection).
    pub last_error: Option<String>,
    /// Issuer-elected settlement-window preference, serialized as
    /// `{"window_profile":..,"fallback_policy":..}`, so a retried submit resolves
    /// the SAME window the issuer chose rather than the default. `None` = no
    /// preference was supplied: the retry then falls back to the issuance
    /// service's default. Node→issuance service only; never part of the signed
    /// submission_set.
    pub settlement_preferences: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("outbox backend error: {0}")]
    Backend(String),
}

/// A durable outbox. The relay drives delivery through this trait, so it is
/// backend-agnostic (memory for tests, SQLite for production) exactly like
/// [`crate::store::JournalStore`].
pub trait OutboxStore: Send + Sync {
    /// Insert a Pending entry, or no-op if (`contract_id`, `request_id`) is
    /// already present — re-admitting the same request is idempotent, never
    /// duplicates. The caller reads the existing entry with [`Self::get`] first
    /// and resends ITS set; admit never overwrites one.
    fn admit(&self, entry: OutboxEntry) -> Result<(), OutboxError>;

    /// The entry of `request_id` in `contract_id`'s scope, in any state. `None`
    /// both for absent and for another issuer's entry under the same id.
    fn get(&self, contract_id: &str, request_id: &str) -> Result<Option<OutboxEntry>, OutboxError>;

    /// Claim up to `limit` Pending entries whose `next_attempt_at_ms <= now_ms`,
    /// oldest first. (The relay then attempts delivery and reports back via
    /// `mark_*`.)
    fn claim_due(&self, now_ms: i64, limit: usize) -> Result<Vec<OutboxEntry>, OutboxError>;

    /// The issuance service answered for this entry: remove it. Terminal — the node never
    /// resends a confirmed set, so the row has nothing left to do.
    /// Every transition below is keyed by (`contract_id`, `request_id`): one
    /// issuer's outcome can never settle another issuer's entry.
    fn mark_submitted(&self, contract_id: &str, request_id: &str) -> Result<(), OutboxError>;

    /// Reschedule a failed delivery: `attempts += 1`, set the next backoff time,
    /// record the error. Stays Pending.
    fn mark_retry(
        &self,
        contract_id: &str,
        request_id: &str,
        next_attempt_at_ms: i64,
        error: &str,
    ) -> Result<(), OutboxError>;

    /// Postpone a Pending entry to `next_attempt_at_ms` WITHOUT counting an
    /// attempt, recording why. For a service that asked to be left alone
    /// (`Retry-After`): honoring that request must not bring the entry any
    /// closer to the dead-letter.
    fn defer(
        &self,
        contract_id: &str,
        request_id: &str,
        next_attempt_at_ms: i64,
        reason: &str,
    ) -> Result<(), OutboxError>;

    /// Mark an entry Dead (refused, unparseable, or out of attempts).
    /// Dead-letter; never dropped.
    fn mark_dead(
        &self,
        contract_id: &str,
        request_id: &str,
        error: &str,
    ) -> Result<(), OutboxError>;

    /// Put a Dead entry of `contract_id` back to Pending with a fresh attempt
    /// budget, due at `now_ms`. Returns `false` when there is no such Dead
    /// entry in that scope — another issuer's entry is indistinguishable from
    /// a missing one. The stored set is resent verbatim, as on every retry.
    fn redrive(
        &self,
        contract_id: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, OutboxError>;

    /// List Dead entries for one issuer scope (dead-letter inspection). Scoped
    /// exactly like the journal: never returns another issuer's entries.
    fn list_dead(&self, contract_id: &str) -> Result<Vec<OutboxEntry>, OutboxError>;

    /// Cross-scope health counts `(pending, dead)` for operability (`/health`).
    /// Aggregate only — no ids, no payloads, no per-issuer breakdown — so it
    /// leaks no cross-issuer presence. A non-zero `dead` is the signal
    /// that work is stuck and an operator must look.
    fn counts(&self) -> Result<OutboxCounts, OutboxError>;

    /// Delete up to `limit` rows in the `submitted` state (confirmed entries
    /// that were flagged rather than deleted). Returns how many went. Bounded so the retention sweep can loop without holding the write
    /// lock against `/v1/issue`.
    fn purge_submitted(&self, limit: usize) -> Result<usize, OutboxError>;
}

/// Delivery attempts after which a pending entry counts as stalled. The same
/// number at which a non-transient failure dead-letters
/// (`crate::relay::RelayConfig::max_attempts` by default).
pub const STALLED_AFTER_ATTEMPTS: u32 = 12;

/// Aggregate outbox health, surfaced on `/health`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct OutboxCounts {
    pub pending: u64,
    pub dead: u64,
    /// Pending entries with at least [`STALLED_AFTER_ATTEMPTS`] failed
    /// attempts. Unavailability never dead-letters, so an entry the service
    /// keeps answering 503 for would otherwise be visible only as a `pending`
    /// that never goes down. Non-zero means look at the relay's log.
    pub stalled: u64,
}

/// In-memory outbox for tests / ephemeral dev. SQLite is the durable backend.
/// Keyed by (`contract_id`, `request_id`), like the SQLite primary key.
#[derive(Debug, Default)]
pub struct MemoryOutbox {
    inner: std::sync::RwLock<std::collections::HashMap<(String, String), OutboxEntry>>,
}

fn key(contract_id: &str, request_id: &str) -> (String, String) {
    (contract_id.to_string(), request_id.to_string())
}

impl MemoryOutbox {
    pub fn new() -> Self {
        Self::default()
    }
}

impl OutboxStore for MemoryOutbox {
    fn admit(&self, entry: OutboxEntry) -> Result<(), OutboxError> {
        let mut g = self.inner.write().expect("outbox lock poisoned");
        // Idempotent: re-admitting an existing request_id does NOT overwrite
        // (the in-flight entry's attempts/state are authoritative).
        g.entry(key(&entry.contract_id, &entry.request_id))
            .or_insert(entry);
        Ok(())
    }

    fn get(&self, contract_id: &str, request_id: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        let g = self.inner.read().expect("outbox lock poisoned");
        Ok(g.get(&key(contract_id, request_id)).cloned())
    }

    fn claim_due(&self, now_ms: i64, limit: usize) -> Result<Vec<OutboxEntry>, OutboxError> {
        let g = self.inner.read().expect("outbox lock poisoned");
        let mut due: Vec<OutboxEntry> = g
            .values()
            .filter(|e| e.state == OutboxState::Pending && e.next_attempt_at_ms <= now_ms)
            .cloned()
            .collect();
        due.sort_by_key(|e| e.created_at_ms);
        due.truncate(limit);
        Ok(due)
    }

    fn mark_submitted(&self, contract_id: &str, request_id: &str) -> Result<(), OutboxError> {
        let mut g = self.inner.write().expect("outbox lock poisoned");
        g.remove(&key(contract_id, request_id));
        Ok(())
    }

    fn mark_retry(
        &self,
        contract_id: &str,
        request_id: &str,
        next_attempt_at_ms: i64,
        error: &str,
    ) -> Result<(), OutboxError> {
        let mut g = self.inner.write().expect("outbox lock poisoned");
        if let Some(e) = g.get_mut(&key(contract_id, request_id)) {
            e.attempts += 1;
            e.next_attempt_at_ms = next_attempt_at_ms;
            e.last_error = Some(error.to_string());
        }
        Ok(())
    }

    fn defer(
        &self,
        contract_id: &str,
        request_id: &str,
        next_attempt_at_ms: i64,
        reason: &str,
    ) -> Result<(), OutboxError> {
        let mut g = self.inner.write().expect("outbox lock poisoned");
        if let Some(e) = g.get_mut(&key(contract_id, request_id)) {
            e.next_attempt_at_ms = next_attempt_at_ms;
            e.last_error = Some(reason.to_string());
        }
        Ok(())
    }

    fn mark_dead(
        &self,
        contract_id: &str,
        request_id: &str,
        error: &str,
    ) -> Result<(), OutboxError> {
        let mut g = self.inner.write().expect("outbox lock poisoned");
        if let Some(e) = g.get_mut(&key(contract_id, request_id)) {
            e.attempts += 1;
            e.state = OutboxState::Dead;
            e.last_error = Some(error.to_string());
        }
        Ok(())
    }

    fn redrive(
        &self,
        contract_id: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, OutboxError> {
        let mut g = self.inner.write().expect("outbox lock poisoned");
        match g.get_mut(&key(contract_id, request_id)) {
            Some(e) if e.state == OutboxState::Dead => {
                e.state = OutboxState::Pending;
                e.attempts = 0;
                e.next_attempt_at_ms = now_ms;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn list_dead(&self, contract_id: &str) -> Result<Vec<OutboxEntry>, OutboxError> {
        let g = self.inner.read().expect("outbox lock poisoned");
        Ok(g.values()
            .filter(|e| e.state == OutboxState::Dead && e.contract_id == contract_id)
            .cloned()
            .collect())
    }

    fn counts(&self) -> Result<OutboxCounts, OutboxError> {
        let g = self.inner.read().expect("outbox lock poisoned");
        let mut c = OutboxCounts {
            pending: 0,
            dead: 0,
            stalled: 0,
        };
        for e in g.values() {
            match e.state {
                OutboxState::Pending => {
                    c.pending += 1;
                    if e.attempts >= STALLED_AFTER_ATTEMPTS {
                        c.stalled += 1;
                    }
                }
                OutboxState::Dead => c.dead += 1,
                OutboxState::Submitted => {}
            }
        }
        Ok(c)
    }

    fn purge_submitted(&self, limit: usize) -> Result<usize, OutboxError> {
        let mut g = self.inner.write().expect("outbox lock poisoned");
        let gone: Vec<(String, String)> = g
            .iter()
            .filter(|(_, e)| e.state == OutboxState::Submitted)
            .map(|(k, _)| k.clone())
            .take(limit)
            .collect();
        for k in &gone {
            g.remove(k);
        }
        Ok(gone.len())
    }
}

// ── SQLite-backed durable outbox (the production backend) ───────────────────
//
// Separate file from the journal (`node-outbox.sqlite` by default): the outbox
// holds in-flight delivery state (deleted on confirmation), the journal holds
// resolved outcomes (kept for the retention period, see `crate::retention`). Same embedded-SQLite, single-file, no-server model.

impl From<rusqlite::Error> for OutboxError {
    fn from(e: rusqlite::Error) -> Self {
        OutboxError::Backend(e.to_string())
    }
}

/// SQLite outbox. One connection behind a `std::sync::Mutex`.
///
/// **The mutex is deliberate and stays synchronous.** SQLite work is blocking
/// I/O, so it does not belong on an executor thread at all; the fix for the
/// async server is to run these calls under `tokio::task::spawn_blocking` (see
/// [`crate::blocking`]), NOT to make the lock async. An async mutex would only
/// move the wait off the thread while leaving the write itself on it.
///
/// A pool is still unnecessary, and the measurement says so: with WAL enabled
/// (below) one connection sustains ~10k writes/s under 10-way contention, while
/// `/v1/issue` costs a handful of writes. The node's scaling answer is
/// horizontal — more instances, each with its own SQLite — not a bigger pool
/// against one file.
///
/// The key is (`contract_id`, `request_id`) — see [`OutboxEntry::request_id`].
const OUTBOX_COLUMNS: &str = "
                 request_id          TEXT NOT NULL,
                 contract_id         TEXT NOT NULL,
                 submission_set_json TEXT NOT NULL,
                 state               TEXT NOT NULL,
                 attempts            INTEGER NOT NULL,
                 next_attempt_at_ms  INTEGER NOT NULL,
                 created_at_ms       INTEGER NOT NULL,
                 last_error          TEXT,
                 settlement_preferences TEXT,
                 PRIMARY KEY (contract_id, request_id)";

/// Forward-migrate an outbox created with `request_id` alone as its key to the
/// scoped key, in one transaction: copy into a new table,
/// drop the old one, rename. Runs on open, so a deploy migrates the file the
/// node already has; a file already on the scoped key is left alone. The rows
/// are copied as they are — every pending set still goes out byte-identical.
fn migrate_scoped_key(conn: &rusqlite::Connection) -> Result<(), OutboxError> {
    // pk > 0 marks a primary-key column; the old schema has exactly one.
    let pk_columns: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('outbox') WHERE pk > 0",
        [],
        |r| r.get(0),
    )?;
    if pk_columns != 1 {
        return Ok(());
    }
    conn.execute_batch(&format!(
        "BEGIN IMMEDIATE;
         CREATE TABLE outbox_scoped ({OUTBOX_COLUMNS});
         INSERT INTO outbox_scoped
             (request_id, contract_id, submission_set_json, state, attempts,
              next_attempt_at_ms, created_at_ms, last_error, settlement_preferences)
         SELECT request_id, contract_id, submission_set_json, state, attempts,
                next_attempt_at_ms, created_at_ms, last_error, settlement_preferences
         FROM outbox;
         DROP TABLE outbox;
         ALTER TABLE outbox_scoped RENAME TO outbox;
         CREATE INDEX IF NOT EXISTS ix_outbox_due ON outbox (state, next_attempt_at_ms);
         COMMIT;"
    ))?;
    Ok(())
}

pub struct SqliteOutbox {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl SqliteOutbox {
    /// Open (or create) the outbox at `path` with default [`StoreOptions`]
    /// (durable: fsync per commit). Use `":memory:"` in tests.
    pub fn open(path: &str) -> Result<Self, OutboxError> {
        Self::open_with_options(path, crate::blocking::StoreOptions::default())
    }

    /// Open (or create) the outbox with explicit store options — durability
    /// level and lock patience. See [`crate::blocking::StoreOptions`].
    pub fn open_with_options(
        path: &str,
        options: crate::blocking::StoreOptions,
    ) -> Result<Self, OutboxError> {
        let conn = rusqlite::Connection::open(path)?;
        crate::blocking::apply_store_pragmas(&conn, options)
            .map_err(|e| OutboxError::Backend(format!("outbox pragmas: {e}")))?;
        crate::blocking::ensure_incremental_vacuum(&conn)
            .map_err(|e| OutboxError::Backend(format!("outbox auto_vacuum: {e}")))?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS outbox ({OUTBOX_COLUMNS});
             -- the relay's hot query: Pending entries due now, oldest first.
             CREATE INDEX IF NOT EXISTS ix_outbox_due
                 ON outbox (state, next_attempt_at_ms);"
        ))?;
        // Idempotent forward-migration for a DB created before the column
        // existed: add it if absent. A duplicate-column error means an already
        // migrated DB → ignore it; any other error propagates.
        match conn.execute(
            "ALTER TABLE outbox ADD COLUMN settlement_preferences TEXT",
            [],
        ) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.contains("duplicate column name") => {}
            Err(e) => return Err(e.into()),
        }
        migrate_scoped_key(&conn)?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    fn state_str(s: OutboxState) -> &'static str {
        match s {
            OutboxState::Pending => "pending",
            OutboxState::Submitted => "submitted",
            OutboxState::Dead => "dead",
        }
    }

    fn parse_state(s: &str) -> Result<OutboxState, OutboxError> {
        match s {
            "pending" => Ok(OutboxState::Pending),
            "submitted" => Ok(OutboxState::Submitted),
            "dead" => Ok(OutboxState::Dead),
            other => Err(OutboxError::Backend(format!(
                "unknown outbox state: {other}"
            ))),
        }
    }

    fn row_to_entry(row: &rusqlite::Row) -> Result<OutboxEntry, OutboxError> {
        let state_s: String = row.get(3)?;
        Ok(OutboxEntry {
            request_id: row.get(0)?,
            contract_id: row.get(1)?,
            submission_set_json: row.get(2)?,
            state: Self::parse_state(&state_s)?,
            attempts: row.get::<_, i64>(4)? as u32,
            next_attempt_at_ms: row.get(5)?,
            created_at_ms: row.get(6)?,
            last_error: row.get(7)?,
            settlement_preferences: row.get(8)?,
        })
    }
}

impl OutboxStore for SqliteOutbox {
    fn admit(&self, entry: OutboxEntry) -> Result<(), OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        // ON CONFLICT DO NOTHING: re-admitting an existing (scope, request_id) is a no-op
        // (the in-flight row is authoritative) — idempotent, never duplicates.
        conn.execute(
            "INSERT INTO outbox
                 (request_id, contract_id, submission_set_json, state, attempts,
                  next_attempt_at_ms, created_at_ms, last_error, settlement_preferences)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(contract_id, request_id) DO NOTHING",
            rusqlite::params![
                entry.request_id,
                entry.contract_id,
                entry.submission_set_json,
                Self::state_str(entry.state),
                entry.attempts as i64,
                entry.next_attempt_at_ms,
                entry.created_at_ms,
                entry.last_error,
                entry.settlement_preferences,
            ],
        )?;
        Ok(())
    }

    fn get(&self, contract_id: &str, request_id: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT request_id, contract_id, submission_set_json, state, attempts,
                    next_attempt_at_ms, created_at_ms, last_error, settlement_preferences
             FROM outbox WHERE contract_id = ?1 AND request_id = ?2",
        )?;
        let mut rows = stmt.query_map(rusqlite::params![contract_id, request_id], |row| {
            Ok(Self::row_to_entry(row))
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r??)),
            None => Ok(None),
        }
    }

    fn claim_due(&self, now_ms: i64, limit: usize) -> Result<Vec<OutboxEntry>, OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT request_id, contract_id, submission_set_json, state, attempts,
                    next_attempt_at_ms, created_at_ms, last_error, settlement_preferences
             FROM outbox
             WHERE state = 'pending' AND next_attempt_at_ms <= ?1
             ORDER BY created_at_ms ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![now_ms, limit as i64], |row| {
            // map_err inside: rusqlite closure must return rusqlite::Result.
            Ok(Self::row_to_entry(row))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    fn mark_submitted(&self, contract_id: &str, request_id: &str) -> Result<(), OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        conn.execute(
            "DELETE FROM outbox WHERE contract_id = ?1 AND request_id = ?2",
            rusqlite::params![contract_id, request_id],
        )?;
        Ok(())
    }

    fn mark_retry(
        &self,
        contract_id: &str,
        request_id: &str,
        next_attempt_at_ms: i64,
        error: &str,
    ) -> Result<(), OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        conn.execute(
            "UPDATE outbox
             SET attempts = attempts + 1, next_attempt_at_ms = ?3, last_error = ?4
             WHERE contract_id = ?1 AND request_id = ?2",
            rusqlite::params![contract_id, request_id, next_attempt_at_ms, error],
        )?;
        Ok(())
    }

    fn defer(
        &self,
        contract_id: &str,
        request_id: &str,
        next_attempt_at_ms: i64,
        reason: &str,
    ) -> Result<(), OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        conn.execute(
            "UPDATE outbox SET next_attempt_at_ms = ?3, last_error = ?4
             WHERE contract_id = ?1 AND request_id = ?2 AND state = 'pending'",
            rusqlite::params![contract_id, request_id, next_attempt_at_ms, reason],
        )?;
        Ok(())
    }

    fn mark_dead(
        &self,
        contract_id: &str,
        request_id: &str,
        error: &str,
    ) -> Result<(), OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        conn.execute(
            "UPDATE outbox
             SET attempts = attempts + 1, state = 'dead', last_error = ?3
             WHERE contract_id = ?1 AND request_id = ?2",
            rusqlite::params![contract_id, request_id, error],
        )?;
        Ok(())
    }

    fn redrive(
        &self,
        contract_id: &str,
        request_id: &str,
        now_ms: i64,
    ) -> Result<bool, OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        let n = conn.execute(
            "UPDATE outbox SET state = 'pending', attempts = 0, next_attempt_at_ms = ?3
             WHERE request_id = ?1 AND contract_id = ?2 AND state = 'dead'",
            rusqlite::params![request_id, contract_id, now_ms],
        )?;
        Ok(n == 1)
    }

    fn list_dead(&self, contract_id: &str) -> Result<Vec<OutboxEntry>, OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT request_id, contract_id, submission_set_json, state, attempts,
                    next_attempt_at_ms, created_at_ms, last_error, settlement_preferences
             FROM outbox WHERE state = 'dead' AND contract_id = ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![contract_id], |row| {
            Ok(Self::row_to_entry(row))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    fn counts(&self) -> Result<OutboxCounts, OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        let pending: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE state = 'pending'",
            [],
            |r| r.get(0),
        )?;
        let dead: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE state = 'dead'",
            [],
            |r| r.get(0),
        )?;
        let stalled: i64 = conn.query_row(
            "SELECT COUNT(*) FROM outbox WHERE state = 'pending' AND attempts >= ?1",
            rusqlite::params![STALLED_AFTER_ATTEMPTS as i64],
            |r| r.get(0),
        )?;
        Ok(OutboxCounts {
            pending: pending.max(0) as u64,
            dead: dead.max(0) as u64,
            stalled: stalled.max(0) as u64,
        })
    }

    fn purge_submitted(&self, limit: usize) -> Result<usize, OutboxError> {
        let conn = self.conn.lock().expect("outbox mutex poisoned");
        let gone = conn.execute(
            "DELETE FROM outbox WHERE rowid IN
                 (SELECT rowid FROM outbox WHERE state = 'submitted' LIMIT ?1)",
            rusqlite::params![limit as i64],
        )?;
        // Every confirmed entry is a DELETE now, so free pages accumulate on
        // every submit, not only here: reclaim a bounded batch on each pass.
        crate::blocking::incremental_vacuum(&conn, crate::blocking::VACUUM_PAGES_PER_PASS)?;
        Ok(gone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(request_id: &str, contract: &str, next_ms: i64) -> OutboxEntry {
        OutboxEntry {
            request_id: request_id.into(),
            contract_id: contract.into(),
            submission_set_json: "{\"schema\":\"submission-set/1\"}".into(),
            state: OutboxState::Pending,
            attempts: 0,
            next_attempt_at_ms: next_ms,
            created_at_ms: next_ms,
            last_error: None,
            settlement_preferences: None,
        }
    }

    #[test]
    fn admit_is_idempotent_by_request_id() {
        let o = MemoryOutbox::new();
        o.admit(entry("r1", "c:A", 0)).unwrap();
        // Re-admitting the same request_id must NOT create a second entry nor reset it.
        o.admit(entry("r1", "c:A", 999)).unwrap();
        let due = o.claim_due(1000, 10).unwrap();
        assert_eq!(due.len(), 1, "one entry per request_id");
        assert_eq!(
            due[0].next_attempt_at_ms, 0,
            "original entry kept, not overwritten"
        );
    }

    #[test]
    fn claim_due_respects_time_and_state() {
        let o = MemoryOutbox::new();
        o.admit(entry("ready", "c:A", 100)).unwrap();
        o.admit(entry("future", "c:A", 5000)).unwrap();
        // Only the one whose next_attempt_at <= now is claimable.
        let due = o.claim_due(1000, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].request_id, "ready");
        // After submitting, it is no longer claimable.
        o.mark_submitted("c:A", "ready").unwrap();
        assert!(o.claim_due(1000, 10).unwrap().is_empty());
    }

    #[test]
    fn mark_retry_bumps_attempts_and_reschedules() {
        let o = MemoryOutbox::new();
        o.admit(entry("r1", "c:A", 0)).unwrap();
        o.mark_retry("c:A", "r1", 5000, "upstream down").unwrap();
        // Not due at now=1000 anymore (rescheduled to 5000).
        assert!(o.claim_due(1000, 10).unwrap().is_empty());
        let due = o.claim_due(6000, 10).unwrap();
        assert_eq!(due[0].attempts, 1);
        assert_eq!(due[0].last_error.as_deref(), Some("upstream down"));
    }

    #[test]
    fn dead_is_listed_scoped_and_not_claimable() {
        let o = MemoryOutbox::new();
        o.admit(entry("r1", "c:A", 0)).unwrap();
        o.admit(entry("r2", "c:B", 0)).unwrap();
        o.mark_dead("c:A", "r1", "exhausted").unwrap();
        // Dead is not claimable.
        let due = o.claim_due(1000, 10).unwrap();
        assert!(due.iter().all(|e| e.request_id != "r1"));
        // Dead-letter listing is scoped: c:A sees its dead, c:B does not.
        assert_eq!(o.list_dead("c:A").unwrap().len(), 1);
        assert_eq!(o.list_dead("c:B").unwrap().len(), 0);
    }

    // ── SQLite backend parity: the same contract must hold for SqliteOutbox ──

    #[test]
    fn sqlite_admit_idempotent_and_claim_due() {
        let o = SqliteOutbox::open(":memory:").unwrap();
        o.admit(entry("r1", "c:A", 0)).unwrap();
        o.admit(entry("r1", "c:A", 999)).unwrap(); // idempotent no-op
        o.admit(entry("future", "c:A", 5000)).unwrap();
        let due = o.claim_due(1000, 10).unwrap();
        assert_eq!(
            due.len(),
            1,
            "only r1 is due; the dup did not create a second row"
        );
        assert_eq!(due[0].request_id, "r1");
        assert_eq!(due[0].next_attempt_at_ms, 0, "original kept (DO NOTHING)");
    }

    #[test]
    fn sqlite_settlement_preferences_survive_admit_claim_roundtrip() {
        // The elected window must survive admit: a relay retry that lost it would
        // resolve the default window instead. It must round-trip verbatim.
        let o = SqliteOutbox::open(":memory:").unwrap();
        let mut chosen = entry("with-pref", "c:A", 0);
        chosen.settlement_preferences =
            Some(r#"{"window_profile":"close_30s","fallback_policy":"reject"}"#.into());
        o.admit(chosen).unwrap();
        // A legacy-style entry (no preference) must stay None, not error.
        o.admit(entry("no-pref", "c:A", 0)).unwrap();

        let due = o.claim_due(1000, 10).unwrap();
        let with = due.iter().find(|e| e.request_id == "with-pref").unwrap();
        let without = due.iter().find(|e| e.request_id == "no-pref").unwrap();
        assert_eq!(
            with.settlement_preferences.as_deref(),
            Some(r#"{"window_profile":"close_30s","fallback_policy":"reject"}"#),
            "elected window must survive the admit→claim round-trip"
        );
        assert_eq!(
            without.settlement_preferences, None,
            "absent preference stays None"
        );
    }

    #[test]
    fn sqlite_retry_submitted_dead_lifecycle() {
        let o = SqliteOutbox::open(":memory:").unwrap();
        o.admit(entry("r1", "c:A", 0)).unwrap();
        o.mark_retry("c:A", "r1", 5000, "down").unwrap();
        assert!(
            o.claim_due(1000, 10).unwrap().is_empty(),
            "rescheduled past now"
        );
        let due = o.claim_due(6000, 10).unwrap();
        assert_eq!(due[0].attempts, 1);
        assert_eq!(due[0].last_error.as_deref(), Some("down"));

        o.admit(entry("r2", "c:A", 0)).unwrap();
        o.mark_submitted("c:A", "r2").unwrap();
        assert!(o
            .claim_due(6000, 10)
            .unwrap()
            .iter()
            .all(|e| e.request_id != "r2"));

        o.admit(entry("r3", "c:B", 0)).unwrap();
        o.mark_dead("c:B", "r3", "exhausted").unwrap();
        assert_eq!(o.list_dead("c:B").unwrap().len(), 1);
        assert_eq!(
            o.list_dead("c:A").unwrap().len(),
            0,
            "dead-letter is scoped"
        );
    }

    #[test]
    fn confirmed_entry_is_deleted_and_can_be_readmitted() {
        // The confirmed row carried holder_id/pool_id in clear; it must be gone,
        // not flagged. And a later re-admit of the same request_id (an SDK retry
        // after a success it never heard about) must work again.
        for sqlite in [false, true] {
            let o: Box<dyn OutboxStore> = if sqlite {
                Box::new(SqliteOutbox::open(":memory:").unwrap())
            } else {
                Box::new(MemoryOutbox::new())
            };
            o.admit(entry("r1", "c:A", 0)).unwrap();
            o.mark_submitted("c:A", "r1").unwrap();
            assert_eq!(
                o.purge_submitted(10).unwrap(),
                0,
                "sqlite={sqlite}: nothing left to purge — the row was deleted"
            );
            o.admit(entry("r1", "c:A", 0)).unwrap();
            assert_eq!(
                o.claim_due(1000, 10).unwrap().len(),
                1,
                "sqlite={sqlite}: re-admit after confirmation must create a fresh entry"
            );
        }
    }

    #[test]
    fn sqlite_purges_rows_left_submitted_by_earlier_versions() {
        let o = SqliteOutbox::open(":memory:").unwrap();
        for id in ["old-1", "old-2", "old-3"] {
            o.admit(entry(id, "c:A", 0)).unwrap();
        }
        o.admit(entry("dead", "c:A", 0)).unwrap();
        o.mark_dead("c:A", "dead", "exhausted").unwrap();
        {
            // A confirmed entry flagged rather than deleted.
            let conn = o.conn.lock().unwrap();
            conn.execute(
                "UPDATE outbox SET state = 'submitted' WHERE request_id LIKE 'old-%'",
                [],
            )
            .unwrap();
        }
        assert_eq!(o.purge_submitted(2).unwrap(), 2, "bounded by the limit");
        assert_eq!(o.purge_submitted(10).unwrap(), 1);
        assert_eq!(o.purge_submitted(10).unwrap(), 0);
        assert_eq!(
            o.list_dead("c:A").unwrap().len(),
            1,
            "a dead entry is never purged"
        );
    }

    #[test]
    fn defer_postpones_without_spending_an_attempt() {
        for sqlite in [false, true] {
            let o: Box<dyn OutboxStore> = if sqlite {
                Box::new(SqliteOutbox::open(":memory:").unwrap())
            } else {
                Box::new(MemoryOutbox::new())
            };
            o.admit(entry("r1", "c:A", 0)).unwrap();
            o.defer("c:A", "r1", 5000, "maintenance").unwrap();
            assert!(o.claim_due(1000, 10).unwrap().is_empty(), "sqlite={sqlite}");
            let due = o.claim_due(6000, 10).unwrap();
            assert_eq!(due[0].attempts, 0, "sqlite={sqlite}: no attempt counted");
            assert_eq!(due[0].last_error.as_deref(), Some("maintenance"));
        }
    }

    #[test]
    fn redrive_revives_a_dead_entry_in_scope_only() {
        for sqlite in [false, true] {
            let o: Box<dyn OutboxStore> = if sqlite {
                Box::new(SqliteOutbox::open(":memory:").unwrap())
            } else {
                Box::new(MemoryOutbox::new())
            };
            o.admit(entry("r1", "c:A", 0)).unwrap();
            for _ in 0..3 {
                o.mark_retry("c:A", "r1", 0, "x").unwrap();
            }
            o.mark_dead("c:A", "r1", "exhausted").unwrap();
            assert!(
                !o.redrive("c:B", "r1", 100).unwrap(),
                "sqlite={sqlite}: other scope"
            );
            assert!(
                !o.redrive("c:A", "missing", 100).unwrap(),
                "sqlite={sqlite}"
            );
            assert!(o.redrive("c:A", "r1", 100).unwrap(), "sqlite={sqlite}");
            let due = o.claim_due(100, 10).unwrap();
            assert_eq!(due.len(), 1, "sqlite={sqlite}: pending again");
            assert_eq!(due[0].attempts, 0, "sqlite={sqlite}: fresh budget");
            assert!(o.list_dead("c:A").unwrap().is_empty(), "sqlite={sqlite}");
            assert!(
                !o.redrive("c:A", "r1", 100).unwrap(),
                "sqlite={sqlite}: only a Dead entry can be redriven"
            );
        }
    }

    #[test]
    fn an_entry_failing_past_the_threshold_counts_as_stalled() {
        for sqlite in [false, true] {
            let o: Box<dyn OutboxStore> = if sqlite {
                Box::new(SqliteOutbox::open(":memory:").unwrap())
            } else {
                Box::new(MemoryOutbox::new())
            };
            o.admit(entry("r1", "c:A", 0)).unwrap();
            o.admit(entry("r2", "c:A", 0)).unwrap();
            for _ in 0..STALLED_AFTER_ATTEMPTS {
                o.mark_retry("c:A", "r1", 0, "HTTP 503").unwrap();
            }
            let c = o.counts().unwrap();
            assert_eq!((c.pending, c.stalled), (2, 1), "sqlite={sqlite}");
        }
    }

    #[test]
    fn counts_aggregate_pending_and_dead_cross_scope() {
        // Memory and SQLite must agree: counts() is cross-scope (operability),
        // pending excludes submitted, dead is its own bucket.
        for sqlite in [false, true] {
            let o: Box<dyn OutboxStore> = if sqlite {
                Box::new(SqliteOutbox::open(":memory:").unwrap())
            } else {
                Box::new(MemoryOutbox::new())
            };
            o.admit(entry("p1", "c:A", 0)).unwrap();
            o.admit(entry("p2", "c:B", 0)).unwrap(); // different scope, still counted
            o.admit(entry("s1", "c:A", 0)).unwrap();
            o.mark_submitted("c:A", "s1").unwrap();
            o.admit(entry("d1", "c:A", 0)).unwrap();
            o.mark_dead("c:A", "d1", "exhausted").unwrap();
            let c = o.counts().unwrap();
            assert_eq!(c.pending, 2, "sqlite={sqlite}: two pending across scopes");
            assert_eq!(c.stalled, 0, "sqlite={sqlite}: nothing has failed yet");
            assert_eq!(
                c.dead, 1,
                "sqlite={sqlite}: one dead, submitted not counted"
            );
        }
    }

    // Two issuers that choose the same request_id hold two entries,
    // and no transition on one reaches the other.
    #[test]
    fn same_request_id_in_two_scopes_is_two_entries() {
        for sqlite in [false, true] {
            let o: Box<dyn OutboxStore> = if sqlite {
                Box::new(SqliteOutbox::open(":memory:").unwrap())
            } else {
                Box::new(MemoryOutbox::new())
            };
            let mut a = entry("same", "c:A", 0);
            a.submission_set_json = "{\"set\":\"A\"}".into();
            let mut b = entry("same", "c:B", 0);
            b.submission_set_json = "{\"set\":\"B\"}".into();
            o.admit(a).unwrap();
            o.admit(b).unwrap();
            assert_eq!(o.claim_due(10, 10).unwrap().len(), 2, "sqlite={sqlite}");
            // B's confirmation removes B's entry only.
            o.mark_submitted("c:B", "same").unwrap();
            let left = o.claim_due(10, 10).unwrap();
            assert_eq!(left.len(), 1, "sqlite={sqlite}");
            assert_eq!(left[0].contract_id, "c:A");
            assert_eq!(left[0].submission_set_json, "{\"set\":\"A\"}");
            // And B cannot dead-letter A's.
            o.mark_dead("c:B", "same", "x").unwrap();
            assert_eq!(o.claim_due(10, 10).unwrap().len(), 1, "sqlite={sqlite}");
            assert!(o.get("c:B", "same").unwrap().is_none());
            assert!(o.get("c:A", "same").unwrap().is_some());
        }
    }

    // A file created with request_id alone as the key is migrated on
    // open, its pending rows intact.
    #[test]
    fn sqlite_migrates_the_unscoped_key() {
        let dir = std::env::temp_dir().join(format!("outbox-mig-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("o.sqlite");
        let path = path.to_str().unwrap();
        {
            let c = rusqlite::Connection::open(path).unwrap();
            c.execute_batch(
                "CREATE TABLE outbox (
                     request_id TEXT PRIMARY KEY, contract_id TEXT NOT NULL,
                     submission_set_json TEXT NOT NULL, state TEXT NOT NULL,
                     attempts INTEGER NOT NULL, next_attempt_at_ms INTEGER NOT NULL,
                     created_at_ms INTEGER NOT NULL, last_error TEXT,
                     settlement_preferences TEXT);
                 INSERT INTO outbox VALUES ('r1','c:A','{}','pending',2,0,1,NULL,NULL);",
            )
            .unwrap();
        }
        let o = SqliteOutbox::open(path).unwrap();
        let e = o
            .get("c:A", "r1")
            .unwrap()
            .expect("row survives the migration");
        assert_eq!(e.attempts, 2);
        // The new key is in force: the same id in another scope is a second row.
        o.admit(entry("r1", "c:B", 0)).unwrap();
        assert_eq!(o.claim_due(10, 10).unwrap().len(), 2);
        drop(o);
        // Reopening an already-migrated file is a no-op.
        let o = SqliteOutbox::open(path).unwrap();
        assert_eq!(o.claim_due(10, 10).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
