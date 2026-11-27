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

//! Keeping the blocking store off the executor's threads.
//!
//! The node's journal and outbox are embedded SQLite behind a synchronous
//! mutex, and their trait methods are synchronous by design. Called directly
//! from an `async` handler, each one blocks an **executor thread** — not merely
//! the task — so with as many concurrent requests as the runtime has threads the
//! whole server stops answering, `/health` included, and a status monitor
//! records a node that is merely saturated as *down*.
//!
//! Two independent fixes, both needed, and neither sufficient alone:
//!
//! 1. **[`apply_store_pragmas`] — raise the store's own ceiling.** WAL plus
//!    a `busy_timeout`. Measured on one connection under 10-way contention:
//!    3.2k → 10.4k writes/s, worst caller wait 140 ms → 45 ms.
//! 2. **[`store_call`] — get the blocking work off the executor.** Even at
//!    10.4k writes/s, a caller that waits 45 ms while *holding an executor
//!    thread* still starves the server. `spawn_blocking` moves the wait to
//!    tokio's blocking pool, where waiting is what the threads are for. Measured
//!    overhead ~6 µs per call, against 20-400 µs of actual store work.
//!
//! Why not an async mutex: it would move the *wait* off the executor thread but
//! leave the SQLite call itself on it, and it would force `JournalStore` and
//! `OutboxStore` to become async traits — 14 call sites and a poisoning story
//! traded for half a fix.

use rusqlite::Connection;

/// How a SQLite-backed store is opened: durability level and lock patience.
///
/// Public and settable because these are deployment decisions, not protocol
/// ones. The defaults sit at the safe end of each trade-off; an operator with a
/// different risk profile changes them deliberately, in code, rather than
/// discovering them baked in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreOptions {
    /// `PRAGMA synchronous`. See [`Durability`].
    pub durability: Durability,
    /// How long a caller waits for another connection's write lock before
    /// `SQLITE_BUSY`.
    ///
    /// Load-bearing once WAL is on: WAL admits concurrent readers alongside one
    /// writer, and with no timeout a contended write fails *immediately* rather
    /// than waiting its turn. Generous by default — a blocked store call waits on
    /// the blocking pool, where a slow call costs a pool thread, not the server.
    /// Raise it on slow or networked storage; lower it if you would rather fail
    /// fast than queue.
    pub busy_timeout: std::time::Duration,
}

/// `PRAGMA synchronous` — what a commit guarantees, and what it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Durability {
    /// `synchronous = FULL`: fsync on every commit. A committed write survives an
    /// operating-system crash or power loss.
    ///
    /// The default, and the right one for an outbox: a lost commit there is a
    /// submission the caller was told had been accepted and that the relay will
    /// never resend. Durability is the property an outbox exists to provide.
    Full,
    /// `synchronous = NORMAL`: the WAL is synced at checkpoints, not per commit.
    ///
    /// Measured ~3.7× faster than [`Durability::Full`], at a real cost: an
    /// OS-level crash or power loss can lose the most recent committed
    /// transactions. A process crash alone is still safe.
    ///
    /// Reasonable when the store is reconstructible or the submissions are
    /// replayable from elsewhere. Do NOT choose it merely because the benchmark
    /// number is larger — it is larger precisely because less is promised.
    Normal,
}

impl Durability {
    fn pragma_value(self) -> &'static str {
        match self {
            Durability::Full => "FULL",
            Durability::Normal => "NORMAL",
        }
    }
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            durability: Durability::Full,
            busy_timeout: std::time::Duration::from_secs(5),
        }
    }
}

impl StoreOptions {
    /// Choose the durability level. See [`Durability`] for the trade-off.
    pub fn with_durability(mut self, d: Durability) -> Self {
        self.durability = d;
        self
    }

    /// Set how long a contended write waits before `SQLITE_BUSY`.
    pub fn with_busy_timeout(mut self, d: std::time::Duration) -> Self {
        self.busy_timeout = d;
        self
    }
}

/// Put a freshly opened connection into the mode a node store needs.
///
/// - `journal_mode = WAL` — readers stop blocking the writer, and a commit no
///   longer pays the rollback journal's double fsync. The single largest win
///   available here (measured 3.3× throughput), and deliberately NOT
///   configurable: the rollback journal has no advantage worth exposing.
/// - `synchronous` — from [`StoreOptions::durability`].
/// - `busy_timeout` — from [`StoreOptions::busy_timeout`].
/// - `foreign_keys = ON` — cheap, and keeps a future schema honest.
///
/// A `:memory:` database accepts all of these; WAL is silently a no-op there
/// (nothing to write ahead of), so tests take the same path as production
/// without a branch.
pub fn apply_store_pragmas(
    conn: &Connection,
    options: StoreOptions,
) -> Result<(), rusqlite::Error> {
    // pragma_update is the typed setter; journal_mode answers with the mode it
    // actually adopted, so it needs the query form to consume that row.
    conn.pragma_update_and_check(None, "journal_mode", "WAL", |_row| Ok(()))?;
    conn.pragma_update(None, "synchronous", options.durability.pragma_value())?;
    conn.busy_timeout(options.busy_timeout)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

/// Free pages handed back to the filesystem per retention pass (4 MiB at the
/// default 4 KiB page). Bounded for the same reason the purge is: one pass must
/// never hold the write lock long enough to stall `/v1/issue`.
pub const VACUUM_PAGES_PER_PASS: u32 = 1024;

/// Put the store in `auto_vacuum = INCREMENTAL`, so pages freed by the
/// retention purge can be returned to the filesystem a few at a time.
///
/// SQLite only accepts this mode before the first table exists. A file whose
/// tables were created without it is converted with one full `VACUUM`, which
/// rewrites the whole file: it runs here, at open, before the node serves, and
/// it runs exactly once per file. It is logged with its duration so an
/// operator with a large file sees where the startup time went.
pub fn ensure_incremental_vacuum(conn: &Connection) -> Result<(), rusqlite::Error> {
    const INCREMENTAL: i64 = 2;
    let mode = |c: &Connection| c.query_row("PRAGMA auto_vacuum", [], |r| r.get::<_, i64>(0));
    if mode(conn)? == INCREMENTAL {
        return Ok(());
    }
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    if mode(conn)? != INCREMENTAL {
        let started = std::time::Instant::now();
        conn.execute_batch("VACUUM")?;
        tracing::warn!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "store converted to incremental auto-vacuum (one-time full VACUUM)"
        );
    }
    Ok(())
}

/// Return up to `pages` free pages to the filesystem. A no-op on a store that
/// is not in incremental auto-vacuum mode.
pub fn incremental_vacuum(conn: &Connection, pages: u32) -> Result<(), rusqlite::Error> {
    // The pragma answers with a row per step; drain it so every step runs.
    let mut stmt = conn.prepare(&format!("PRAGMA incremental_vacuum({pages})"))?;
    let mut rows = stmt.query([])?;
    while rows.next()?.is_some() {}
    Ok(())
}

/// Run one blocking store call on tokio's blocking pool.
///
/// Use this at **every** `await`-reachable store touch. The closure gets an
/// `Arc` clone of the store, so it owns what it needs for the duration and
/// nothing borrows across the `.await`.
///
/// # Panics and poisoning
///
/// The store keeps its `expect("… mutex poisoned")` calls: a poisoned mutex
/// means a previous caller panicked mid-transaction, and continuing against a
/// connection in an unknown state would be worse than failing. What this
/// function decides is *where* that panic lands — inside a blocking-pool
/// task, which `spawn_blocking` surfaces as a `JoinError` rather than tearing
/// down the worker thread. Callers map that to a 5xx, so one poisoned store answers
/// honestly instead of taking the process with it.
pub async fn store_call<T, F>(f: F) -> Result<T, StoreCallError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| StoreCallError(e.to_string()))
}

/// A blocking store call that did not complete: the store's mutex was poisoned
/// by an earlier panic, or the runtime is shutting down. Distinct from a store
/// error (which the store itself reports) — this is the call never finishing.
#[derive(Debug, thiserror::Error)]
#[error("store call failed to complete: {0}")]
pub struct StoreCallError(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pragmas_apply_and_wal_is_adopted_on_a_file_db() {
        // WAL is a no-op on :memory:, so this must be a real file to prove the
        // mode was actually adopted rather than silently ignored.
        let dir =
            std::env::temp_dir().join(format!("certcrypt-node-pragma-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pragma.sqlite");
        let conn = Connection::open(&path).unwrap();
        apply_store_pragmas(&conn, StoreOptions::default()).unwrap();

        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal", "WAL must actually be adopted");

        // FULL is synchronous level 2. Anything less loses committed emissions on
        // an OS crash, which is the one thing the outbox exists to prevent.
        let sync: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2, "synchronous must be FULL (2), not NORMAL (1)");

        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_file_is_converted_to_incremental_auto_vacuum() {
        // A file whose tables exist with auto_vacuum NONE.
        // Setting the pragma alone is silently ignored there, so this must be a
        // real file with a real table to prove the VACUUM conversion happened.
        let dir =
            std::env::temp_dir().join(format!("certcrypt-node-vacuum-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.sqlite");
        let _ = std::fs::remove_file(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);")
                .unwrap();
        }
        let conn = Connection::open(&path).unwrap();
        apply_store_pragmas(&conn, StoreOptions::default()).unwrap();
        ensure_incremental_vacuum(&conn).unwrap();
        let mode: i64 = conn
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            mode, 2,
            "auto_vacuum must be INCREMENTAL (2) after conversion"
        );
        let x: i64 = conn.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(x, 1, "the conversion must keep the data");
        incremental_vacuum(&conn, VACUUM_PAGES_PER_PASS).unwrap();

        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pragmas_do_not_fail_on_an_in_memory_db() {
        // Tests and ephemeral dev open `:memory:`; the same code path must work
        // there without a branch, even though WAL cannot apply.
        let conn = Connection::open_in_memory().unwrap();
        apply_store_pragmas(&conn, StoreOptions::default())
            .expect("pragmas must be harmless on :memory:");
    }

    #[tokio::test]
    async fn store_call_returns_the_closure_value() {
        let got = store_call(|| 6 * 7).await.unwrap();
        assert_eq!(got, 42);
    }

    #[tokio::test]
    async fn store_call_reports_a_panicking_closure_instead_of_unwinding() {
        // A poisoned-mutex `expect` inside the store must surface as an error the
        // handler can turn into a 5xx — not take down the runtime.
        let err = store_call(|| panic!("sqlite mutex poisoned")).await;
        assert!(
            err.is_err(),
            "a panicking store call must be reported, not swallowed"
        );
    }
}
