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

//! Throughput and latency of the node's durable store under concurrency.
//!
//! Measures the two properties that set the store's ceiling, on the real
//! `SqliteOutbox` against a real file (never `:memory:`, which has no journal
//! and would flatter every number):
//!
//! - **Durability mode.** WAL + `busy_timeout` versus SQLite's default
//!   rollback journal.
//! - **Concurrency shape.** Whether callers block the async executor or hand the
//!   work to `spawn_blocking`.
//!
//! It needs nothing but a writable temp directory: no issuance service, no network.
//! That is the point — it isolates the node's own ceiling, so the number is not
//! contaminated by an upstream round-trip.
//!
//! Usage:
//!   cargo run --release -p certcrypt-node --example bench_store_concurrency
//!
//! Tuning (env):
//!   BENCH_CONCURRENCY=32   in-flight callers
//!   BENCH_OPS=2000         total operations per scenario
//!
//! Always build with `--release`: a debug build measures rustc's bookkeeping
//! rather than SQLite's.

use std::sync::Arc;
use std::time::{Duration, Instant};

use certcrypt_node::outbox::{OutboxEntry, OutboxError, OutboxState, OutboxStore, SqliteOutbox};

/// One scenario's measured result.
struct Report {
    label: &'static str,
    ops: usize,
    elapsed: Duration,
    /// Per-operation latencies, sorted, for percentile extraction.
    latencies_us: Vec<u128>,
}

impl Report {
    fn percentile(&self, p: f64) -> u128 {
        if self.latencies_us.is_empty() {
            return 0;
        }
        let idx = ((self.latencies_us.len() as f64 - 1.0) * p).round() as usize;
        self.latencies_us[idx]
    }

    fn print(&self) {
        let throughput = self.ops as f64 / self.elapsed.as_secs_f64();
        println!(
            "{:<34} {:>9.0} ops/s   p50 {:>7} µs   p95 {:>8} µs   p99 {:>8} µs   max {:>8} µs",
            self.label,
            throughput,
            self.percentile(0.50),
            self.percentile(0.95),
            self.percentile(0.99),
            self.latencies_us.last().copied().unwrap_or(0),
        );
    }
}

fn entry(request_id: String) -> OutboxEntry {
    OutboxEntry {
        request_id,
        contract_id: "bench:contract".into(),
        // Roughly the size of a small signed submission set, so the row is
        // representative rather than a toy.
        submission_set_json: format!(
            r#"{{"schema":"submission-set/1","filler":"{}"}}"#,
            "x".repeat(2048)
        ),
        state: OutboxState::Pending,
        attempts: 0,
        next_attempt_at_ms: 0,
        created_at_ms: 0,
        last_error: None,
        settlement_preferences: None,
    }
}

/// A minimal baseline outbox WITHOUT the pragmas: the same
/// schema and the same `ON CONFLICT DO NOTHING` admit, on a bare connection
/// behind a `std::sync::Mutex`, in SQLite's default rollback-journal mode.
///
/// Deliberately a local copy rather than a `SqliteOutbox` with the pragmas
/// skipped: the production type has no such door, and a benchmark is not a
/// reason to add one to a public API.
struct BaselineOutbox {
    conn: std::sync::Mutex<rusqlite::Connection>,
}

impl BaselineOutbox {
    fn open(path: &std::path::Path) -> Self {
        let conn = rusqlite::Connection::open(path).expect("open baseline");
        // No WAL, no busy_timeout, no synchronous override — SQLite's defaults.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox (
                 request_id          TEXT PRIMARY KEY,
                 contract_id         TEXT NOT NULL,
                 submission_set_json TEXT NOT NULL,
                 state               TEXT NOT NULL,
                 attempts            INTEGER NOT NULL,
                 next_attempt_at_ms  INTEGER NOT NULL,
                 created_at_ms       INTEGER NOT NULL,
                 last_error          TEXT,
                 settlement_preferences TEXT
             );",
        )
        .expect("baseline schema");
        Self {
            conn: std::sync::Mutex::new(conn),
        }
    }
}

impl OutboxStore for BaselineOutbox {
    fn admit(&self, entry: OutboxEntry) -> Result<(), OutboxError> {
        let conn = self.conn.lock().expect("baseline mutex poisoned");
        conn.execute(
            "INSERT INTO outbox
                 (request_id, contract_id, submission_set_json, state, attempts,
                  next_attempt_at_ms, created_at_ms, last_error, settlement_preferences)
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(request_id) DO NOTHING",
            rusqlite::params![
                entry.request_id,
                entry.contract_id,
                entry.submission_set_json,
                entry.attempts as i64,
                entry.next_attempt_at_ms,
                entry.created_at_ms,
                entry.last_error,
                entry.settlement_preferences,
            ],
        )
        .map_err(|e| OutboxError::Backend(e.to_string()))?;
        Ok(())
    }

    // The bench only drives `admit`; the rest exist to satisfy the trait.
    fn claim_due(&self, _now_ms: i64, _limit: usize) -> Result<Vec<OutboxEntry>, OutboxError> {
        Ok(Vec::new())
    }
    fn get(&self, _c: &str, _r: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        Ok(None)
    }
    fn mark_submitted(&self, _c: &str, _request_id: &str) -> Result<(), OutboxError> {
        Ok(())
    }
    fn mark_retry(&self, _c: &str, _r: &str, _n: i64, _e: &str) -> Result<(), OutboxError> {
        Ok(())
    }
    fn mark_dead(&self, _c: &str, _request_id: &str, _error: &str) -> Result<(), OutboxError> {
        Ok(())
    }
    fn defer(&self, _c: &str, _r: &str, _n: i64, _e: &str) -> Result<(), OutboxError> {
        Ok(())
    }
    fn redrive(&self, _c: &str, _r: &str, _now: i64) -> Result<bool, OutboxError> {
        Ok(false)
    }
    fn list_dead(&self, _contract_id: &str) -> Result<Vec<OutboxEntry>, OutboxError> {
        Ok(Vec::new())
    }
    fn counts(&self) -> Result<certcrypt_node::outbox::OutboxCounts, OutboxError> {
        Ok(certcrypt_node::outbox::OutboxCounts {
            pending: 0,
            dead: 0,
            stalled: 0,
        })
    }
    fn purge_submitted(&self, _limit: usize) -> Result<usize, OutboxError> {
        Ok(0)
    }
}

/// Drive `ops` admits through `concurrency` in-flight callers.
///
/// `on_executor = true` calls the store directly from the async task: the
/// blocking call pins an executor thread. `false` routes it through
/// `spawn_blocking`, as the node's handlers do.
async fn run_scenario(
    label: &'static str,
    store: Arc<dyn OutboxStore>,
    ops: usize,
    concurrency: usize,
    on_executor: bool,
) -> Report {
    let latencies = Arc::new(std::sync::Mutex::new(Vec::with_capacity(ops)));
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let started = Instant::now();

    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let store = store.clone();
        let latencies = latencies.clone();
        let next = next.clone();
        workers.push(tokio::spawn(async move {
            loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= ops {
                    break;
                }
                let e = entry(format!("bench-{i:08}"));
                let t = Instant::now();
                if on_executor {
                    let _ = store.admit(e);
                } else {
                    let s = store.clone();
                    let _ = tokio::task::spawn_blocking(move || s.admit(e)).await;
                }
                latencies.lock().unwrap().push(t.elapsed().as_micros());
            }
        }));
    }
    for w in workers {
        let _ = w.await;
    }

    let elapsed = started.elapsed();
    let mut latencies_us = Arc::try_unwrap(latencies)
        .expect("sole owner")
        .into_inner()
        .unwrap();
    latencies_us.sort_unstable();
    Report {
        label,
        ops,
        elapsed,
        latencies_us,
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let concurrency: usize = std::env::var("BENCH_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(32);
    let ops: usize = std::env::var("BENCH_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);

    let dir = std::env::temp_dir().join(format!("certcrypt-node-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create bench dir");

    println!(
        "node store bench — {concurrency} concurrent callers, {ops} admits per scenario, \
         {} executor threads",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );
    println!("(SqliteOutbox::admit against a real file; --release strongly recommended)\n");

    // Baseline: rollback journal, store called straight from the async task.
    let before = Arc::new(BaselineOutbox::open(&dir.join("before.sqlite")));
    run_scenario(
        "baseline journal + on-executor",
        before,
        ops,
        concurrency,
        true,
    )
    .await
    .print();

    // Each property alone, so the contribution of each is visible.
    let wal_only =
        Arc::new(SqliteOutbox::open(dir.join("wal-only.sqlite").to_str().unwrap()).unwrap());
    run_scenario(
        "        WAL + on-executor",
        wal_only,
        ops,
        concurrency,
        true,
    )
    .await
    .print();

    let blocking_only = Arc::new(BaselineOutbox::open(&dir.join("blocking-only.sqlite")));
    run_scenario(
        "        journal + spawn_blocking",
        blocking_only,
        ops,
        concurrency,
        false,
    )
    .await
    .print();

    // Both, which is what the node ships.
    let after = Arc::new(SqliteOutbox::open(dir.join("after.sqlite").to_str().unwrap()).unwrap());
    run_scenario(
        "node     WAL + spawn_blocking",
        after,
        ops,
        concurrency,
        false,
    )
    .await
    .print();

    let _ = std::fs::remove_dir_all(&dir);
}
