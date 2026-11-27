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

//! A node upgraded over a large store must be admitting again within seconds.
//!
//! The rule this guards: opening a store may only make cheap schema changes
//! (`ADD COLUMN`, an index). Anything that rewrites rows belongs in a bounded
//! background pass, because while it runs it holds the store's only writer and
//! `/v1/issue` cannot admit. What this test measures is the consequence that
//! matters — time from open to the first admit on a large store — so a change
//! that makes startup slow fails here rather than in an operator's restart.
//! It is a budget, not a detector: a single cheap rewrite can hide inside it.
//!
//! The stores are built in the oldest layout the node still opens: the original
//! columns only, no retention timestamps, `auto_vacuum = NONE`, and confirmed
//! outbox rows flagged `submitted` instead of deleted. The one-time `VACUUM`
//! that converts them to incremental auto-vacuum is part of what is timed.

use std::time::{Duration, Instant};

use certcrypt_node::outbox::{OutboxEntry, OutboxState, OutboxStore, SqliteOutbox};
use certcrypt_node::sqlite_journal::SqliteJournal;
use certcrypt_node::store::JournalStore;

const JOURNAL_ROWS: usize = 100_000;
const OUTBOX_ROWS: usize = 20_000;

/// Opening takes well under a second in a debug build, conversion included.
/// The margin is for a slow CI disk, not for new work in `open`.
const BUDGET: Duration = Duration::from_secs(5);

fn legacy_journal(path: &std::path::Path) {
    let mut conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE operations (
             operation_id TEXT PRIMARY KEY,
             contract_id  TEXT NOT NULL,
             request_id   TEXT NOT NULL,
             state_json   TEXT NOT NULL,
             operator_receipt_json TEXT,
             submission_set_id TEXT,
             commitment_index INTEGER
         );
         CREATE INDEX idx_operations_contract ON operations (contract_id);",
    )
    .unwrap();
    let tx = conn.transaction().unwrap();
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO operations (operation_id, contract_id, request_id, state_json,
                     submission_set_id, commitment_index)
                 VALUES (?1, ?2, ?3, ?4, 'set', 0)",
            )
            .unwrap();
        for i in 0..JOURNAL_ROWS {
            let state = if i % 3 == 0 {
                r#"{"state":"rejected","reason_code":"x","message":"x"}"#
            } else {
                r#"{"state":"accepted","upstream_operation_id":"UP"}"#
            };
            stmt.execute(rusqlite::params![
                format!("op_{i:026}"),
                format!("contract:{}", i % 50),
                format!("req_{i:026}"),
                state,
            ])
            .unwrap();
        }
    }
    tx.commit().unwrap();
}

fn legacy_outbox(path: &std::path::Path) {
    let mut conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE outbox (
             request_id          TEXT PRIMARY KEY,
             contract_id         TEXT NOT NULL,
             submission_set_json TEXT NOT NULL,
             state               TEXT NOT NULL,
             attempts            INTEGER NOT NULL,
             next_attempt_at_ms  INTEGER NOT NULL,
             created_at_ms       INTEGER NOT NULL,
             last_error          TEXT
         );
         CREATE INDEX ix_outbox_due ON outbox (state, next_attempt_at_ms);",
    )
    .unwrap();
    let payload = format!(
        "{{\"schema\":\"submission-set/1\",\"pad\":\"{}\"}}",
        "x".repeat(1500)
    );
    let tx = conn.transaction().unwrap();
    {
        let mut stmt = tx
            .prepare("INSERT INTO outbox VALUES (?1, ?2, ?3, ?4, 0, 0, 0, NULL)")
            .unwrap();
        for i in 0..OUTBOX_ROWS {
            let state = if i % 100 == 0 { "pending" } else { "submitted" };
            stmt.execute(rusqlite::params![
                format!("req_{i:026}"),
                format!("contract:{}", i % 50),
                payload,
                state,
            ])
            .unwrap();
        }
    }
    tx.commit().unwrap();
}

#[test]
fn an_upgraded_node_admits_within_budget_over_a_large_legacy_store() {
    let dir = std::env::temp_dir().join(format!("cc-node-startup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let journal_path = dir.join("journal.sqlite");
    let outbox_path = dir.join("outbox.sqlite");
    legacy_journal(&journal_path);
    legacy_outbox(&outbox_path);

    // Exactly what main.rs does before it binds its port, then the first admit.
    let started = Instant::now();
    let journal = SqliteJournal::open(journal_path.to_str().unwrap()).unwrap();
    let outbox = SqliteOutbox::open(outbox_path.to_str().unwrap()).unwrap();
    outbox
        .admit(OutboxEntry {
            request_id: "first-after-upgrade".into(),
            contract_id: "contract:1".into(),
            submission_set_json: "{}".into(),
            state: OutboxState::Pending,
            attempts: 0,
            next_attempt_at_ms: 0,
            created_at_ms: 0,
            last_error: None,
            settlement_preferences: None,
        })
        .unwrap();
    let elapsed = started.elapsed();
    eprintln!(
        "open + first admit over {JOURNAL_ROWS} journal / {OUTBOX_ROWS} outbox legacy rows: {elapsed:?}"
    );
    assert!(
        elapsed < BUDGET,
        "the node took {elapsed:?} to admit after an upgrade (budget {BUDGET:?}): \
         look for row rewrites added to `open`"
    );

    // Nothing was lost on the way.
    assert_eq!(
        journal.list_scoped("contract:0").unwrap().len(),
        JOURNAL_ROWS / 50
    );
    assert_eq!(
        outbox.counts().unwrap().pending as usize,
        OUTBOX_ROWS / 100 + 1,
        "legacy pending rows survive; the new one is admitted"
    );

    // The cleanup that open() deliberately does NOT do happens in
    // bounded passes, each short enough not to stall an admit.
    let mut worst = Duration::ZERO;
    loop {
        let t = Instant::now();
        let n = outbox.purge_submitted(500).unwrap();
        worst = worst.max(t.elapsed());
        if n == 0 {
            break;
        }
    }
    eprintln!("worst legacy-outbox purge pass: {worst:?}");
    assert!(
        worst < Duration::from_secs(1),
        "one purge pass held the writer for {worst:?}"
    );

    drop((journal, outbox));
    let _ = std::fs::remove_dir_all(&dir);
}
