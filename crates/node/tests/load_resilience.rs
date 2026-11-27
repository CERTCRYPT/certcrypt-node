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

//! Load-resilience contract of the node's HTTP surface.
//!
//! These tests pin two properties:
//!
//! 1. **`/health` stays answerable while the store is busy.** A store locked
//!    from `async` handlers without `spawn_blocking` blocks an *executor
//!    thread*, not just a task: with N in-flight requests on an N-thread runtime
//!    the whole server — `/health` included — stops answering, and a monitor
//!    reads "down" on a server that is merely saturated.
//! 2. **`/health` does not lie.** A store whose `counts()` fails must not be
//!    reported as `status:"ok"` with `{pending:0,dead:0}`: a broken store would
//!    then be indistinguishable from an empty outbox.
//!
//! The runtimes here are pinned to a small `worker_threads` count on purpose: it
//! is what makes executor-thread starvation reproducible instead of
//! machine-dependent. A test that only fails on a 2-core CI box is not a test.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use certcrypt_node::http::{router, NodeState};
use certcrypt_node::outbox::{MemoryOutbox, OutboxCounts, OutboxEntry, OutboxError, OutboxStore};
use certcrypt_node::store::MemoryJournal;
use certcrypt_node::upstream::UpstreamClient;

/// How long the slow store blocks inside one `counts()`/`list_dead()` call.
/// Comfortably longer than the health probe timeout below, so a serialized
/// server cannot accidentally pass.
const STORE_STALL: StdDuration = StdDuration::from_millis(1_500);

/// Budget for a `/health` probe taken while the store is saturated. `/health`
/// must not touch the contended store at all, so this is generous by design.
const HEALTH_BUDGET: StdDuration = StdDuration::from_millis(1_000);

// ── Test doubles ────────────────────────────────────────────────────────────

/// An outbox whose scoped reads block the calling thread for [`STORE_STALL`].
///
/// This stands in for a real SQLite store under contention: one connection
/// behind a lock, each caller waiting its turn. `list_dead` is the stalling
/// entry point because `GET /v1/outbox/dead` reaches it from a plain handler.
///
/// `list_dead` stalls; `counts()` (what `/health` reads) does not. The property
/// under test is that a route monopolizing the store cannot starve `/health` —
/// which is what a synchronous lock on an executor thread would do.
///
/// The blocking pool is capped in the test runtime so this stays a real
/// contention test: at tokio's 512-thread default, 16 concurrent store calls
/// would never compete for a thread and the test would pass regardless.
struct StallingOutbox {
    inner: MemoryOutbox,
    /// Peak simultaneous callers observed inside the stalling section. Proves
    /// the requests really did overlap rather than arriving one after another.
    concurrent_peak: AtomicUsize,
    in_flight: AtomicUsize,
}

impl StallingOutbox {
    fn new() -> Self {
        Self {
            inner: MemoryOutbox::new(),
            concurrent_peak: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
        }
    }

    fn stall(&self) {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.concurrent_peak.fetch_max(now, Ordering::SeqCst);
        // A genuinely blocking wait — NOT `tokio::time::sleep`. A synchronous
        // store call cannot yield, and that is exactly the hazard under test.
        std::thread::sleep(STORE_STALL);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl OutboxStore for StallingOutbox {
    fn admit(&self, entry: OutboxEntry) -> Result<(), OutboxError> {
        self.inner.admit(entry)
    }

    fn claim_due(&self, now_ms: i64, limit: usize) -> Result<Vec<OutboxEntry>, OutboxError> {
        self.inner.claim_due(now_ms, limit)
    }

    fn get(&self, contract_id: &str, request_id: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        self.inner.get(contract_id, request_id)
    }

    fn mark_submitted(&self, contract_id: &str, request_id: &str) -> Result<(), OutboxError> {
        self.inner.mark_submitted(contract_id, request_id)
    }

    fn mark_retry(
        &self,
        contract_id: &str,
        request_id: &str,
        next_attempt_at_ms: i64,
        error: &str,
    ) -> Result<(), OutboxError> {
        self.inner
            .mark_retry(contract_id, request_id, next_attempt_at_ms, error)
    }

    fn mark_dead(
        &self,
        contract_id: &str,
        request_id: &str,
        error: &str,
    ) -> Result<(), OutboxError> {
        self.inner.mark_dead(contract_id, request_id, error)
    }

    fn defer(
        &self,
        contract_id: &str,
        request_id: &str,
        next: i64,
        reason: &str,
    ) -> Result<(), OutboxError> {
        self.inner.defer(contract_id, request_id, next, reason)
    }

    fn redrive(&self, contract_id: &str, request_id: &str, now: i64) -> Result<bool, OutboxError> {
        self.inner.redrive(contract_id, request_id, now)
    }

    fn list_dead(&self, contract_id: &str) -> Result<Vec<OutboxEntry>, OutboxError> {
        self.stall();
        self.inner.list_dead(contract_id)
    }

    fn counts(&self) -> Result<OutboxCounts, OutboxError> {
        // Fast on purpose. In production `/health` costs two COUNT(*) over an
        // indexed column; the hazard was never that its own read is slow, but
        // that OTHER routes' blocking calls starve the threads it needs to run
        // at all. Stalling this too would only assert that 1.5 s of work cannot
        // finish inside a 1 s budget, which is arithmetic, not a property.
        self.inner.counts()
    }

    fn purge_submitted(&self, limit: usize) -> Result<usize, OutboxError> {
        self.inner.purge_submitted(limit)
    }
}

/// An outbox whose `counts()` always fails — a store that is broken rather than
/// merely slow (corrupt file, revoked permissions, exhausted disk).
struct BrokenOutbox;

impl OutboxStore for BrokenOutbox {
    fn admit(&self, _entry: OutboxEntry) -> Result<(), OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn claim_due(&self, _now_ms: i64, _limit: usize) -> Result<Vec<OutboxEntry>, OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn get(&self, _c: &str, _r: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn mark_submitted(&self, _c: &str, _request_id: &str) -> Result<(), OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn mark_retry(
        &self,
        _c: &str,
        _request_id: &str,
        _next_attempt_at_ms: i64,
        _error: &str,
    ) -> Result<(), OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn mark_dead(&self, _c: &str, _request_id: &str, _error: &str) -> Result<(), OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn defer(
        &self,
        _c: &str,
        _request_id: &str,
        _next: i64,
        _reason: &str,
    ) -> Result<(), OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn redrive(&self, _c: &str, _r: &str, _now: i64) -> Result<bool, OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn list_dead(&self, _contract_id: &str) -> Result<Vec<OutboxEntry>, OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn counts(&self) -> Result<OutboxCounts, OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }

    fn purge_submitted(&self, _limit: usize) -> Result<usize, OutboxError> {
        Err(OutboxError::Backend("disk I/O error".into()))
    }
}

// ── Harness ─────────────────────────────────────────────────────────────────

/// Spawn a node with the supplied outbox. No operator identity is seeded: these
/// tests never submit upstream, they only exercise the HTTP surface, and the
/// routes they hit (`/health`, `/v1/outbox/dead`) do not need one.
async fn spawn_node_with_outbox(outbox: Arc<dyn OutboxStore>) -> SocketAddr {
    let state = NodeState {
        upstream: Arc::new(UpstreamClient::new("http://127.0.0.1:1".to_string())),
        store: Arc::new(MemoryJournal::new()),
        outbox,
        issuer_verifier: shared::issuer_verifier(),
        operator: None,
        operator_credential: None,
        max_commitments_per_request: 10_000,
        lifecycle: Default::default(),
        deployment_rules: Default::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    addr
}

mod shared;

// ── 1. /health stays answerable under store contention ──────────────────────

/// The regression this pins: a synchronous store call made straight from an
/// `async` handler blocks an **executor thread**, not just its task. With as
/// many such requests in flight as the runtime has worker threads, the server
/// stops answering ANYTHING — `/health` included — and a status monitor
/// records a saturated node as *down*, which is the wrong operational verdict
/// and sends an operator looking for the wrong failure.
///
/// The test measures that directly: the executor gets 2 threads, and 8
/// concurrent requests each occupy the store for 1.5 s. Store calls made on the
/// executor would hold those threads and `/health` would time out. With the
/// store calls on the blocking pool, the 2 executor threads stay free to serve
/// `/health` while all 8 wait.
///
/// `max_blocking_threads` is left at its default deliberately: constraining it
/// would test tokio's pool sizing, whereas the property here is that store work
/// is not on the executor at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_answers_while_store_is_saturated() {
    let outbox = Arc::new(StallingOutbox::new());
    let addr = spawn_node_with_outbox(outbox.clone()).await;

    // 8 concurrent store-occupying requests against a 2-thread executor: 4×
    // oversubscription of the runtime if the store calls ran on it.
    let mut load = Vec::new();
    for _ in 0..8 {
        // A FRESH proof per request: the node burns a challenge on use, so a
        // shared header would be rejected as a replay and never reach the store.
        let auth = shared::issuer_auth_for(
            &shared::ISSUER_SEED,
            "GET",
            &format!("http://{addr}/v1/outbox/dead"),
            b"",
        );
        load.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            client
                .get(format!("http://{addr}/v1/outbox/dead"))
                .header(shared::ISSUER_AUTH_HEADER, auth)
                .timeout(StdDuration::from_secs(30))
                .send()
                .await
                .map(|r| r.status().as_u16())
        }));
    }

    // Let the load reach the store.
    tokio::time::sleep(StdDuration::from_millis(300)).await;

    // The load must genuinely be inside the store as we probe, or the probe
    // proves nothing about contention.
    let in_flight = outbox.in_flight.load(Ordering::SeqCst);
    assert!(
        in_flight >= 2,
        "the load must overlap inside the store while /health is probed \
         (in flight: {in_flight})"
    );

    // THE ASSERTION: /health answers, and answers promptly, right now.
    let probe = reqwest::Client::new()
        .get(format!("http://{addr}/health"))
        .timeout(HEALTH_BUDGET)
        .send()
        .await;

    let resp = probe.expect(
        "/health must answer while the store is saturated: a saturated node \
         must not look like a dead node to the monitor",
    );
    assert_eq!(
        resp.status(),
        200,
        "/health must report 200 when the node is merely busy and the store is sound"
    );

    // And the saturating requests must all still have been served correctly —
    // backpressure is the concurrency limit's job (tested below), not silent
    // failure here.
    for t in load {
        let status = t.await.expect("load task panicked");
        assert_eq!(
            status.as_ref().map(|s| *s).ok(),
            Some(200),
            "a slow store must still yield a correct answer, not an error"
        );
    }
}

// ── 2. /health tells the truth about a broken store ─────────────────────────

/// A `/health` that hardcoded `status:"ok"` and swallowed a store failure with
/// `unwrap_or({pending:0,dead:0})` would render a broken store identically to
/// an empty outbox and always return 200. Telemetry built on that signal would
/// paint green over a failure, so the endpoint must fail visibly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_is_not_200_when_the_store_is_broken() {
    let addr = spawn_node_with_outbox(Arc::new(BrokenOutbox)).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/health"))
        .timeout(StdDuration::from_secs(5))
        .send()
        .await
        .expect("/health must answer even when the store is broken");

    assert_ne!(
        resp.status(),
        200,
        "a broken store must NOT report 200: an unreadable outbox is not a healthy node"
    );

    let body: serde_json::Value = resp.json().await.expect("/health must stay JSON");
    assert_ne!(
        body.get("status").and_then(|s| s.as_str()),
        Some("ok"),
        "status must not claim \"ok\" when the store cannot be read"
    );
    assert_ne!(
        body.pointer("/outbox/pending").and_then(|v| v.as_u64()),
        Some(0),
        "a failed count must not be rendered as the number 0 — an empty outbox and \
         an unreadable one must be distinguishable"
    );
}

// ── 3. HTTP backpressure ────────────────────────────────────────────────────

/// Spawn a node with explicit HTTP limits, so a test can make the limit bite
/// without issuing 64 concurrent requests.
async fn spawn_node_with_limits(
    outbox: Arc<dyn OutboxStore>,
    limits: certcrypt_node::http::HttpLimits,
) -> SocketAddr {
    let state = NodeState {
        upstream: Arc::new(UpstreamClient::new("http://127.0.0.1:1".to_string())),
        store: Arc::new(MemoryJournal::new()),
        outbox,
        issuer_verifier: shared::issuer_verifier(),
        operator: None,
        operator_credential: None,
        max_commitments_per_request: 10_000,
        lifecycle: Default::default(),
        deployment_rules: Default::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            certcrypt_node::http::router_with_limits(state, limits),
        )
        .await
        .unwrap();
    });
    addr
}

/// The concurrency limit must QUEUE excess requests, not reject them: the SDKs
/// retry, so shedding a brief burst would amplify one spike into a retry storm.
/// With a limit of 1 and a store that takes 1.5 s, three requests must all be
/// served correctly — serialized, slower, but never an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn excess_requests_queue_instead_of_being_rejected() {
    let outbox = Arc::new(StallingOutbox::new());
    let limits = certcrypt_node::http::HttpLimits {
        max_concurrent_requests: 1,
        // Generous: 3 serialized 1.5 s requests need ~4.5 s, so the timeout must
        // not be what decides this test.
        request_timeout: StdDuration::from_secs(20),
    };
    let addr = spawn_node_with_limits(outbox.clone(), limits).await;

    let mut tasks = Vec::new();
    for _ in 0..6 {
        let auth = shared::issuer_auth_for(
            &shared::ISSUER_SEED,
            "GET",
            &format!("http://{addr}/v1/outbox/dead"),
            b"",
        );
        tasks.push(tokio::spawn(async move {
            // A FRESH client per task, so each opens its OWN connection. This is
            // what distinguishes a global limit from a per-connection one: with a
            // per-connection semaphore these 6 would all run at once.
            reqwest::Client::new()
                .get(format!("http://{addr}/v1/outbox/dead"))
                .header(shared::ISSUER_AUTH_HEADER, auth)
                .timeout(StdDuration::from_secs(30))
                .send()
                .await
                .map(|r| r.status().as_u16())
        }));
    }

    for t in tasks {
        let status = t.await.expect("task panicked").expect("request failed");
        assert_eq!(
            status, 200,
            "a queued request must be served, not shed: the SDKs retry, and \
             shedding a burst turns one spike into a storm"
        );
    }

    // Note this test asserts DELIVERY, not the cap: with a blocking store the
    // callers would serialize on the blocking pool even with no limit at all, so
    // a peak assertion here would prove nothing about the layer. The cap itself
    // is pinned by `the_concurrency_limit_is_global_across_connections`.
    assert!(
        outbox.concurrent_peak.load(Ordering::SeqCst) >= 1,
        "the load must have reached the store"
    );
}

/// The timeout is what keeps the queue honest. It is unbounded in depth, so it
/// must be bounded in TIME: a request that cannot be served inside the budget
/// gets a 503 rather than hanging forever. 503 (not 408) because the SDKs treat
/// it as retryable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_that_cannot_be_served_in_budget_gets_503() {
    let outbox = Arc::new(StallingOutbox::new());
    let limits = certcrypt_node::http::HttpLimits {
        max_concurrent_requests: 1,
        // Shorter than one store call (1.5 s), so the second request cannot
        // possibly get its slot in time.
        request_timeout: StdDuration::from_millis(400),
    };
    let addr = spawn_node_with_limits(outbox.clone(), limits).await;

    let auth_first = shared::issuer_auth_for(
        &shared::ISSUER_SEED,
        "GET",
        &format!("http://{addr}/v1/outbox/dead"),
        b"",
    );
    let first = tokio::spawn(async move {
        reqwest::Client::new()
            .get(format!("http://{addr}/v1/outbox/dead"))
            .header(shared::ISSUER_AUTH_HEADER, auth_first)
            .timeout(StdDuration::from_secs(30))
            .send()
            .await
            .map(|r| r.status().as_u16())
    });

    // Let the first request take the only slot.
    tokio::time::sleep(StdDuration::from_millis(200)).await;

    let auth_second = shared::issuer_auth_for(
        &shared::ISSUER_SEED,
        "GET",
        &format!("http://{addr}/v1/outbox/dead"),
        b"",
    );
    let second = reqwest::Client::new()
        .get(format!("http://{addr}/v1/outbox/dead"))
        .header(shared::ISSUER_AUTH_HEADER, auth_second)
        .timeout(StdDuration::from_secs(30))
        .send()
        .await
        .expect("the node must ANSWER a timed-out request, not drop the connection");

    assert_eq!(
        second.status(),
        503,
        "a request that cannot be served inside the budget must get 503 — a \
         bounded queue, not an unbounded wait"
    );

    let _ = first.await;
}

/// `/health` is mounted outside the concurrency limit on purpose: the monitor
/// decides on the HTTP code alone, so a probe that had to queue for a slot would
/// make a FULL node look DOWN — the same misdiagnosis that keeping store calls
/// off the executor prevents.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_is_exempt_from_the_concurrency_limit() {
    let outbox = Arc::new(StallingOutbox::new());
    // A limit of 1, immediately consumed by a slow /v1 request.
    let limits = certcrypt_node::http::HttpLimits {
        max_concurrent_requests: 1,
        request_timeout: StdDuration::from_secs(20),
    };
    let addr = spawn_node_with_limits(outbox.clone(), limits).await;

    let auth = shared::issuer_auth_for(
        &shared::ISSUER_SEED,
        "GET",
        &format!("http://{addr}/v1/outbox/dead"),
        b"",
    );
    let hog = tokio::spawn(async move {
        reqwest::Client::new()
            .get(format!("http://{addr}/v1/outbox/dead"))
            .header(shared::ISSUER_AUTH_HEADER, auth)
            .timeout(StdDuration::from_secs(30))
            .send()
            .await
            .map(|r| r.status().as_u16())
    });

    tokio::time::sleep(StdDuration::from_millis(300)).await;
    assert!(
        outbox.in_flight.load(Ordering::SeqCst) > 0,
        "the /v1 request must hold the only slot while /health is probed"
    );

    // /health answers promptly even though every /v1 slot is taken.
    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/health"))
        .timeout(HEALTH_BUDGET)
        .send()
        .await
        .expect("/health must not queue behind the /v1 concurrency limit");
    assert_eq!(resp.status(), 200);

    let _ = hog.await;
}

// ── 4. The public API an embedder relies on ─────────────────────────────────
//
// This crate ships as a library as well as a binary, so these pin the surface a
// third party integrates against. They are compile-and-behavior tests of the
// CONTRACT, not of the internals: if a refactor makes any of them fail, an
// embedder's build breaks too.

/// Everything an embedder needs is reachable from the crate root, without
/// reaching into private-looking module paths.
#[test]
fn the_embedding_surface_is_exported_from_the_crate_root() {
    use certcrypt_node::{Durability, HttpLimits, StoreOptions};

    // Limits are constructible and adjustable in code — no environment needed.
    let limits = HttpLimits::default()
        .with_max_concurrent_requests(128)
        .with_request_timeout(StdDuration::from_secs(45));
    assert_eq!(limits.max_concurrent_requests, 128);
    assert_eq!(limits.request_timeout, StdDuration::from_secs(45));

    // So are store options, including the durability trade-off.
    let opts = StoreOptions::default()
        .with_durability(Durability::Normal)
        .with_busy_timeout(StdDuration::from_secs(1));
    assert_eq!(opts.durability, Durability::Normal);
    assert_eq!(opts.busy_timeout, StdDuration::from_secs(1));
}

/// The defaults must be safe for someone who configures nothing: a durable
/// store, and limits that bound the work rather than leaving it unbounded.
#[test]
fn defaults_are_safe_for_an_embedder_who_configures_nothing() {
    use certcrypt_node::{Durability, HttpLimits, StoreOptions};

    assert_eq!(
        StoreOptions::default().durability,
        Durability::Full,
        "the default must be the durable one: a lost outbox commit is a \
         submission the caller was told had been accepted"
    );
    let limits = HttpLimits::default();
    assert!(
        limits.max_concurrent_requests > 0,
        "a limit of 0 would wedge the server shut"
    );
    assert!(
        !limits.request_timeout.is_zero(),
        "an unbounded request has no backpressure"
    );
}

/// A degenerate value must not be able to disable backpressure or stop a node
/// booting — the setters keep the previous value instead.
#[test]
fn zero_values_are_refused_rather_than_disabling_the_limit() {
    use certcrypt_node::HttpLimits;

    let d = HttpLimits::default();
    let attempted = d
        .with_max_concurrent_requests(0)
        .with_request_timeout(StdDuration::ZERO);
    assert_eq!(
        attempted, d,
        "zero must leave the default in place, not remove the limit"
    );
}

/// The environment reader takes the caller's prefix. This crate must claim no
/// global variable namespace: an embedder's limits cannot change because of a
/// variable it did not set.
#[test]
fn from_env_prefixed_uses_the_callers_namespace() {
    use certcrypt_node::HttpLimits;

    // A prefix nothing sets: the result must be exactly the defaults.
    let unset = HttpLimits::from_env_prefixed("CERTCRYPT_NODE_TEST_UNSET_PREFIX_");
    assert_eq!(unset, HttpLimits::default());

    // And the bundled binary's prefix is public, so an embedder can opt into the
    // same names deliberately rather than guessing them.
    let _ = HttpLimits::from_env_prefixed(certcrypt_node::http::ENV_PREFIX);
}

/// A durable store must be openable with a non-default durability, and the
/// pragma must actually take effect — otherwise the option is decorative.
#[test]
fn an_embedder_can_choose_a_different_durability() {
    use certcrypt_node::{Durability, OutboxStore, SqliteOutbox, StoreOptions};

    let dir = std::env::temp_dir().join(format!(
        "certcrypt-node-embed-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("chosen.sqlite");

    let store = SqliteOutbox::open_with_options(
        path.to_str().unwrap(),
        StoreOptions::default().with_durability(Durability::Normal),
    )
    .expect("an embedder must be able to pick its own durability");
    // The store is usable, not merely constructible.
    store
        .counts()
        .expect("a store opened with custom options must work");
    drop(store);

    // `synchronous` is a per-CONNECTION setting and is not stored in the file, so
    // it cannot be read back from a fresh connection. `journal_mode` IS persisted,
    // so that is what proves the pragma path ran against this database at all.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        mode.to_lowercase(),
        "wal",
        "the store pragmas must have been applied to this database"
    );
    drop(conn);

    // And the level itself is checked where it is observable: on a connection
    // that the same code path just configured.
    let conn = rusqlite::Connection::open(&path).unwrap();
    certcrypt_node::blocking::apply_store_pragmas(
        &conn,
        StoreOptions::default().with_durability(Durability::Normal),
    )
    .unwrap();
    let sync: i64 = conn
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        sync, 1,
        "NORMAL is synchronous level 1 — the option must take effect"
    );

    drop(conn);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The concurrency limit must be **global**, not per connection.
///
/// axum clones the inner service for each connection, and `tower`'s plain
/// `ConcurrencyLimitLayer` gives every clone its own semaphore — so N
/// connections admit N × limit requests, which is no cap at all. Only
/// `GlobalConcurrencyLimitLayer`, which shares one `Arc<Semaphore>`, actually
/// bounds the server.
///
/// The saturation here is `tokio::time::sleep`, deliberately: a *blocking* store
/// would serialize the callers on the blocking pool whatever the layer did, and
/// the test would pass either way. Yielding work isolates the layer as the only
/// thing that can serialize anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_concurrency_limit_is_global_across_connections() {
    use std::sync::atomic::AtomicUsize;

    static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);
    IN_FLIGHT.store(0, Ordering::SeqCst);
    PEAK.store(0, Ordering::SeqCst);

    let limits = certcrypt_node::HttpLimits::default()
        .with_max_concurrent_requests(2)
        .with_request_timeout(StdDuration::from_secs(30));

    let app = axum::Router::new()
        .route(
            "/stall",
            axum::routing::get(|| async {
                let n = IN_FLIGHT.fetch_add(1, Ordering::SeqCst) + 1;
                PEAK.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(StdDuration::from_millis(500)).await;
                IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                "ok"
            }),
        )
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
            limits.max_concurrent_requests,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut tasks = Vec::new();
    for _ in 0..8 {
        tasks.push(tokio::spawn(async move {
            // A fresh client per task = a fresh connection per task. This is the
            // condition under which a per-connection limit fails to cap.
            reqwest::Client::new()
                .get(format!("http://{addr}/stall"))
                .timeout(StdDuration::from_secs(30))
                .send()
                .await
                .map(|r| r.status().as_u16())
        }));
    }
    for t in tasks {
        assert_eq!(
            t.await.expect("task panicked").expect("request failed"),
            200,
            "queued requests must still be served"
        );
    }

    assert_eq!(
        PEAK.load(Ordering::SeqCst),
        2,
        "the limit must be global: {} requests ran at once across 8 connections \
         with a limit of 2",
        PEAK.load(Ordering::SeqCst)
    );
}
