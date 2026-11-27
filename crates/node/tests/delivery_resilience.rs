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

//! What the node does while the issuance service is unavailable, and while the
//! node itself is restarting.
//!
//! Each test drives a real node router against a stub service whose answer is
//! switched per test: accept, planned maintenance (`503` + `Retry-After`), an
//! outage (`503`), a fault (`500`), or any chosen status — a definitive
//! refusal about the request itself (`400`, `409`, …) or a transient one
//! (`408`, `429`, …). The relay is driven one tick at a time, so the timing is
//! the test's, not the clock's.

mod shared;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
use certcrypt_node::http::{router, Lifecycle, NodeState};
use certcrypt_node::outbox::{MemoryOutbox, OutboxEntry, OutboxError, OutboxStore};
use certcrypt_node::relay::{Relay, RelayConfig};
use certcrypt_node::store::{JournalError, JournalStore, MemoryJournal, OperationRecord};
use certcrypt_node::upstream::UpstreamClient;
use chrono::{Duration, SubsecRound, Utc};
use serde_json::json;

const ACCEPT: u8 = 0;
const MAINTENANCE: u8 = 1;
const OUTAGE: u8 = 2;
const FAULT: u8 = 4;
/// Answer with `Stub::status` (and `Retry-After: Stub::retry_after` when
/// non-zero).
const STATUS: u8 = 3;
/// The set does not fit the issuer's capacity (`insufficient_capacity`).
const NO_CAPACITY: u8 = 5;
/// A verdict on the whole set other than capacity (`rejected`).
const SET_REJECTED: u8 = 6;

#[derive(Clone, Default)]
struct Stub {
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
    /// The `submission_set_id` of every set received, in order.
    sets: Arc<std::sync::Mutex<Vec<String>>>,
    status: Arc<AtomicU16>,
    retry_after: Arc<AtomicU16>,
}

impl Stub {
    /// Switch the stub to answering `status` (no `Retry-After`).
    fn answer(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
        self.retry_after.store(0, Ordering::SeqCst);
        self.mode.store(STATUS, Ordering::SeqCst);
    }
}

async fn stub_submit(
    State(st): State<Stub>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    st.calls.fetch_add(1, Ordering::SeqCst);
    st.sets.lock().unwrap().push(
        body["submission_set"]["payload"]["submission_set_id"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    );
    match st.mode.load(Ordering::SeqCst) {
        MAINTENANCE => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            [(axum::http::header::RETRY_AFTER, "600")],
            Json(json!({ "error": "maintenance", "message": "planned" })),
        )
            .into_response(),
        // Unavailable, with no idea when it will be back: no Retry-After.
        OUTAGE => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down").into_response(),
        // The service failed on THIS request — a fault, not an outage.
        FAULT => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response(),
        NO_CAPACITY => Json(json!({
            "status": "insufficient_capacity",
            "operation_id": "00000000000000000000000000",
            "capacity": { "required": "5.00", "available": "2.00", "missing": "3.00" },
        }))
        .into_response(),
        SET_REJECTED => Json(json!({
            "status": "rejected",
            "operation_id": null,
            "reason_code": "submission_set_invalid",
            "message": "as configured",
        }))
        .into_response(),
        STATUS => {
            let code = axum::http::StatusCode::from_u16(st.status.load(Ordering::SeqCst))
                .expect("a valid status");
            let mut resp = (
                code,
                Json(json!({ "error": "stub_status", "message": "as configured" })),
            )
                .into_response();
            let wait = st.retry_after.load(Ordering::SeqCst);
            if wait > 0 {
                resp.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from(wait),
                );
            }
            resp
        }
        _ => {
            let n = body["submission_set"]["payload"]["certificates"]
                .as_array()
                .map_or(0, |a| a.len());
            let results: Vec<_> = (0..n)
                .map(|i| {
                    json!({
                        "commitment_index": i,
                        "status": "accepted",
                        "operation_id": format!("OP-UP-{i}"),
                    })
                })
                .collect();
            Json(json!({ "submission_set_id": "stub-set", "results": results })).into_response()
        }
    }
}

async fn spawn_stub(mode: u8) -> (String, Stub) {
    let stub = Stub::default();
    stub.mode.store(mode, Ordering::SeqCst);
    let app = Router::new()
        .route("/v1/submit", post(stub_submit))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), stub)
}

struct Node {
    addr: SocketAddr,
    outbox: Arc<dyn OutboxStore>,
    relay: Relay,
    lifecycle: Lifecycle,
}

async fn spawn_node(api_url: &str, outbox: Arc<dyn OutboxStore>) -> Node {
    spawn_node_with_cap(api_url, outbox, 10_000).await
}

async fn spawn_node_with_cap(
    api_url: &str,
    outbox: Arc<dyn OutboxStore>,
    max_commitments_per_request: usize,
) -> Node {
    spawn_node_full(
        api_url,
        outbox,
        Arc::new(MemoryJournal::new()),
        max_commitments_per_request,
    )
    .await
}

async fn spawn_node_full(
    api_url: &str,
    outbox: Arc<dyn OutboxStore>,
    store: Arc<dyn JournalStore>,
    max_commitments_per_request: usize,
) -> Node {
    let (operator, credential) = shared::operator_material();
    let (operator, credential) = (Arc::new(operator), Arc::new(credential));
    let upstream = Arc::new(UpstreamClient::new(api_url.to_string()));
    let lifecycle = Lifecycle::default();
    let state = NodeState {
        upstream: upstream.clone(),
        store: store.clone(),
        outbox: outbox.clone(),
        issuer_verifier: shared::issuer_verifier(),
        operator: Some(operator.clone()),
        operator_credential: Some(credential.clone()),
        max_commitments_per_request,
        lifecycle: lifecycle.clone(),
        deployment_rules: Default::default(),
    };
    let relay = Relay::new(outbox.clone(), upstream, store, operator, credential).with_config(
        RelayConfig {
            max_attempts: 3,
            ..RelayConfig::default()
        },
    );
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Node {
        addr,
        outbox,
        relay,
        lifecycle,
    }
}

fn issue_body(n: usize) -> serde_json::Value {
    issue_body_expiring(n, Duration::minutes(30))
}

/// An issue body whose commitments expire `expires_in` from now.
fn issue_body_expiring(n: usize, expires_in: Duration) -> serde_json::Value {
    let now = Utc::now().trunc_subsecs(0);
    let fixture = shared::submission_set_fixture::make_dev_submission_set_n(
        now - Duration::minutes(1),
        now + expires_in,
        n,
    );
    let commitments: Vec<_> = fixture
        .submission_set
        .certificates
        .iter()
        .map(|c| json!({ "capacity_evidence": c.capacity_evidence, "operative": c.operative }))
        .map(|mut c| {
            // The node only carries an issuer's OWN evidence: bind the fixture's
            // members to the root this file's issuer authenticates with. The
            // node does not verify the evidence signature (the service does),
            // so rewriting the root leaves the request otherwise intact.
            c["capacity_evidence"]["projected_authorization"]["holder_key_set_root"] =
                json!(shared::holder_key_set_root(&shared::ISSUER_SEED));
            c
        })
        .collect();
    json!({ "commitments": commitments })
}

async fn issue(node: &Node, seed: &[u8; 32], n: usize) -> reqwest::Response {
    issue_with(node, seed, &issue_body(n)).await
}

async fn issue_with(node: &Node, seed: &[u8; 32], body: &serde_json::Value) -> reqwest::Response {
    shared::signed(
        reqwest::Client::new()
            .post(format!("http://{}/v1/issue", node.addr))
            .json(body),
        seed,
    )
    .send()
    .await
    .unwrap()
}

/// Every entry in the outbox, due or not.
fn all_entries(outbox: &Arc<dyn OutboxStore>) -> Vec<OutboxEntry> {
    outbox.claim_due(i64::MAX, 1000).unwrap()
}

/// Far enough ahead that any backoff or deferral has elapsed.
fn later() -> i64 {
    Utc::now().timestamp_millis() + 3_600_000
}

#[tokio::test]
async fn an_unanswered_submit_hands_out_member_ids_that_the_delivery_fills_in() {
    let (api, stub) = spawn_stub(MAINTENANCE).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;

    let resp = issue(&node, &shared::ISSUER_SEED, 2).await;
    assert_eq!(resp.status(), 202, "durably held, not yet delivered");
    let body: serde_json::Value = resp.json().await.unwrap();
    let results = body["results"].as_array().expect("one result per member");
    assert_eq!(results.len(), 2);
    let ids: Vec<String> = results
        .iter()
        .map(|r| {
            assert_eq!(r["state"]["state"], "accepted_for_retry");
            r["operation_id"].as_str().unwrap().to_string()
        })
        .collect();

    // Maintenance was honored: postponed, no attempt spent.
    let entries = all_entries(&node.outbox);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].attempts, 0,
        "a Retry-After is not a failed attempt"
    );
    assert!(entries[0].next_attempt_at_ms > Utc::now().timestamp_millis() + 500_000);

    // Maintenance over; the relay delivers.
    stub.mode.store(ACCEPT, Ordering::SeqCst);
    node.relay.tick(later()).await;
    assert!(
        all_entries(&node.outbox).is_empty(),
        "delivered entries leave the outbox"
    );

    // The ids the issuer got at submit now carry the real outcome.
    for (i, id) in ids.iter().enumerate() {
        let rec: serde_json::Value = shared::signed(
            reqwest::Client::new().get(format!("http://{}/v1/operations/{id}", node.addr)),
            &shared::ISSUER_SEED,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(rec["state"]["state"], "accepted", "member {i}");
        assert_eq!(rec["state"]["upstream_operation_id"], format!("OP-UP-{i}"));
    }
}

#[tokio::test]
async fn maintenance_pauses_the_whole_batch_without_spending_attempts() {
    let (api, stub) = spawn_stub(MAINTENANCE).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    for _ in 0..3 {
        assert_eq!(issue(&node, &shared::ISSUER_SEED, 1).await.status(), 202);
    }
    let inline_calls = stub.calls.load(Ordering::SeqCst);

    node.relay.tick(later()).await;
    assert_eq!(
        stub.calls.load(Ordering::SeqCst) - inline_calls,
        1,
        "the first Retry-After stops the batch; the others are not hammered"
    );
    assert!(all_entries(&node.outbox).iter().all(|e| e.attempts == 0));
}

#[tokio::test]
async fn an_outage_never_dead_letters() {
    let (api, _stub) = spawn_stub(OUTAGE).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    assert_eq!(issue(&node, &shared::ISSUER_SEED, 1).await.status(), 202);
    // max_attempts is 3; go well past it.
    for _ in 0..8 {
        node.relay.tick(later()).await;
    }
    let entries = all_entries(&node.outbox);
    assert_eq!(entries.len(), 1, "still pending");
    assert!(entries[0].attempts >= 8);
    let root = shared::holder_key_set_root(&shared::ISSUER_SEED);
    assert!(node.outbox.list_dead(&root).unwrap().is_empty());
}

#[tokio::test]
async fn a_fault_on_the_request_dead_letters_instead_of_retrying_forever() {
    // A 500 says the service failed on this request, and a deterministic
    // fault answers the same way every time, so retrying it
    // forever would hide it behind a `pending` that never moves.
    let (api, _stub) = spawn_stub(FAULT).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    assert_eq!(issue(&node, &shared::ISSUER_SEED, 1).await.status(), 202);
    for _ in 0..4 {
        node.relay.tick(later()).await;
    }
    let root = shared::holder_key_set_root(&shared::ISSUER_SEED);
    assert_eq!(
        node.outbox.list_dead(&root).unwrap().len(),
        1,
        "visible, redrivable"
    );
}

#[tokio::test]
async fn an_outage_past_the_threshold_shows_as_stalled_on_health() {
    let (api, _stub) = spawn_stub(OUTAGE).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    assert_eq!(issue(&node, &shared::ISSUER_SEED, 1).await.status(), 202);
    for _ in 0..certcrypt_node::outbox::STALLED_AFTER_ATTEMPTS {
        node.relay.tick(later()).await;
    }
    let h: serde_json::Value = reqwest::get(format!("http://{}/health", node.addr))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(h["outbox"]["pending"], 1);
    assert_eq!(
        h["outbox"]["stalled"], 1,
        "still retried, but no longer invisible"
    );
    assert_eq!(h["outbox"]["dead"], 0);
}

#[tokio::test]
async fn a_refusal_during_delivery_dead_letters_at_once_and_its_issuer_can_redrive_it() {
    // The inline submit meets an outage, so the set is held for the relay.
    let (api, stub) = spawn_stub(OUTAGE).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let resp = issue(&node, &shared::ISSUER_SEED, 1).await;
    assert_eq!(resp.status(), 202);
    let issued: serde_json::Value = resp.json().await.unwrap();
    let request_id = issued["request_id"].as_str().unwrap().to_string();

    // By the time the relay delivers it, the service refuses it outright. One
    // attempt is enough: the same bytes would get the same answer, so the
    // relay does not spend the rest of its budget (max_attempts is 3 here).
    stub.answer(409);
    node.relay.tick(later()).await;
    let root = shared::holder_key_set_root(&shared::ISSUER_SEED);
    let dead = node.outbox.list_dead(&root).unwrap();
    assert_eq!(dead.len(), 1, "dead-lettered on the first refusal");
    assert!(
        dead[0].last_error.as_deref().unwrap_or("").contains("409"),
        "the refusal is what the operator sees: {:?}",
        dead[0].last_error
    );

    let redrive = |seed: [u8; 32]| {
        let url = format!("http://{}/v1/outbox/dead/{request_id}/redrive", node.addr);
        async move {
            shared::signed(reqwest::Client::new().post(url), &seed)
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        redrive([99u8; 32]).await,
        404,
        "another issuer cannot see it"
    );
    assert_eq!(redrive(shared::ISSUER_SEED).await, 202);
    assert!(node.outbox.list_dead(&root).unwrap().is_empty());

    // The operator fixed whatever was wrong; the redriven entry now goes through.
    stub.mode.store(ACCEPT, Ordering::SeqCst);
    node.relay.tick(later()).await;
    assert!(all_entries(&node.outbox).is_empty(), "delivered");
}

#[tokio::test]
async fn a_definitive_refusal_is_answered_not_accepted_for_retry() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let root = shared::holder_key_set_root(&shared::ISSUER_SEED);

    for status in [400u16, 401, 403, 404, 409, 413, 422] {
        stub.answer(status);
        let resp = issue(&node, &shared::ISSUER_SEED, 2).await;
        assert_eq!(
            resp.status(),
            422,
            "upstream {status}: a refusal is not a gateway error, nor accepted for retry"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["state"]["state"], "submission_failed",
            "upstream {status}"
        );
        assert_eq!(
            body["state"]["upstream_status"], status,
            "upstream {status}"
        );
        assert_eq!(
            body["results"].as_array().map(Vec::len),
            Some(0),
            "no member was evaluated, so none is handed out as waiting"
        );
        assert!(
            all_entries(&node.outbox).is_empty(),
            "upstream {status}: nothing is kept for retry"
        );
        assert!(node.outbox.list_dead(&root).unwrap().is_empty());
    }

    // And the relay has nothing to resend.
    let calls = stub.calls.load(Ordering::SeqCst);
    node.relay.tick(later()).await;
    assert_eq!(stub.calls.load(Ordering::SeqCst), calls);
}

#[tokio::test]
async fn a_refusal_on_resubmit_settles_the_ids_handed_out_earlier() {
    // First attempt: unavailable, so the issuer gets waiting ids.
    let (api, stub) = spawn_stub(OUTAGE).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let mut body = issue_body(1);
    body["request_id"] = json!(ulid::Ulid::new().to_string());
    let first: serde_json::Value = issue_with(&node, &shared::ISSUER_SEED, &body)
        .await
        .json()
        .await
        .unwrap();
    let op_id = first["results"][0]["operation_id"]
        .as_str()
        .unwrap()
        .to_string();

    // The issuer resends the same request; this time the service refuses it.
    stub.answer(403);
    let resp = issue_with(&node, &shared::ISSUER_SEED, &body).await;
    assert_eq!(resp.status(), 422);
    assert!(
        all_entries(&node.outbox).is_empty(),
        "nothing left to deliver"
    );

    // The id it already holds now carries the refusal instead of waiting forever.
    let rec: serde_json::Value = shared::signed(
        reqwest::Client::new().get(format!("http://{}/v1/operations/{op_id}", node.addr)),
        &shared::ISSUER_SEED,
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(rec["state"]["state"], "submission_failed");
    assert_eq!(rec["state"]["upstream_status"], 403);
}

#[tokio::test]
async fn transient_statuses_are_still_accepted_for_retry() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;

    for status in [408u16, 425, 429, 500, 502, 503, 504] {
        stub.answer(status);
        let resp = issue(&node, &shared::ISSUER_SEED, 1).await;
        assert_eq!(resp.status(), 202, "upstream {status} is retried");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["results"][0]["state"]["state"], "accepted_for_retry",
            "upstream {status}"
        );
    }
    assert_eq!(all_entries(&node.outbox).len(), 7, "every one is held");
}

#[tokio::test]
async fn a_rate_limit_is_waited_out_without_spending_an_attempt() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    stub.answer(429);
    stub.retry_after.store(120, Ordering::SeqCst);
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;

    assert_eq!(issue(&node, &shared::ISSUER_SEED, 1).await.status(), 202);
    let entries = all_entries(&node.outbox);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].attempts, 0,
        "a Retry-After is not a failed attempt"
    );
    assert!(entries[0].next_attempt_at_ms > Utc::now().timestamp_millis() + 100_000);
}

/// The request problems the node sees before sending anything. Each must be
/// answered 422 — never 502, which an SDK would retry — with nothing sent
/// upstream and nothing queued.
#[tokio::test]
async fn request_problems_are_422_and_nothing_is_sent() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    let node = spawn_node_with_cap(&api, Arc::new(MemoryOutbox::new()), 2).await;

    let with_member = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut body = issue_body(1);
        edit(&mut body["commitments"][0]["capacity_evidence"]["projected_commitment"]);
        body
    };
    // Two members under two authorizations (another issuer kid), which cannot
    // share one set.
    let mixed = {
        let mut a = issue_body(1);
        let mut b = issue_body(1);
        b["commitments"][0]["capacity_evidence"]["projected_authorization"]
            ["authorization_issuer_kid"] = json!("another-kid");
        a["commitments"]
            .as_array_mut()
            .unwrap()
            .push(b["commitments"][0].clone());
        a
    };

    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("no_commitments", json!({ "commitments": [] })),
        ("too_many_commitments", issue_body(3)),
        (
            "unknown_commitment_ttl",
            with_member(&|pc| pc["rules_version"] = json!("rules/no-such-domain")),
        ),
        (
            "commitment_ttl_mismatch",
            with_member(&|pc| pc["expires_at"] = pc["issued_at"].clone()),
        ),
        (
            "invalid_timestamp",
            with_member(&|pc| pc["issued_at"] = json!("yesterday")),
        ),
        ("submission_set_invalid", mixed),
    ];
    for (code, body) in cases {
        let resp = issue_with(&node, &shared::ISSUER_SEED, &body).await;
        assert_eq!(resp.status(), 422, "{code}");
        let err: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(err["error"], code);
        assert!(
            err["message"].as_str().is_some_and(|m| !m.is_empty()),
            "{code}"
        );
        assert!(err["request_id"].as_str().is_some(), "{code}");
    }
    assert_eq!(stub.calls.load(Ordering::SeqCst), 0, "nothing was sent");
    assert!(all_entries(&node.outbox).is_empty(), "nothing was queued");
}

#[tokio::test]
async fn a_node_without_operator_recognition_answers_503_not_502() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    let state = NodeState {
        upstream: Arc::new(UpstreamClient::new(api)),
        store: Arc::new(MemoryJournal::new()),
        outbox: Arc::new(MemoryOutbox::new()),
        issuer_verifier: shared::issuer_verifier(),
        operator: None,
        operator_credential: None,
        max_commitments_per_request: 10,
        lifecycle: Lifecycle::default(),
        deployment_rules: Default::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let resp = shared::signed(
        reqwest::Client::new()
            .post(format!("http://{addr}/v1/issue"))
            .json(&issue_body(1)),
        &shared::ISSUER_SEED,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 503);
    let err: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(err["error"], "operator_not_configured");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 0, "nothing was sent");
}

#[tokio::test]
async fn while_draining_writes_get_retry_after_and_reads_still_work() {
    let (api, _stub) = spawn_stub(ACCEPT).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    node.lifecycle.begin_drain();

    let resp = issue(&node, &shared::ISSUER_SEED, 1).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers()["retry-after"], "10");

    let health = reqwest::get(format!("http://{}/health", node.addr))
        .await
        .unwrap();
    assert_eq!(health.status(), 503);
    let h: serde_json::Value = health.json().await.unwrap();
    assert_eq!(h["status"], "draining");

    let read = shared::signed(
        reqwest::Client::new().get(format!("http://{}/v1/outbox/dead", node.addr)),
        &shared::ISSUER_SEED,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(read.status(), 200, "reads are not refused while draining");
}

/// An outbox that accepts nothing — a full disk, a locked file.
struct RefusingOutbox(MemoryOutbox);

impl OutboxStore for RefusingOutbox {
    fn admit(&self, _e: OutboxEntry) -> Result<(), OutboxError> {
        Err(OutboxError::Backend("database is locked".into()))
    }
    fn claim_due(&self, n: i64, l: usize) -> Result<Vec<OutboxEntry>, OutboxError> {
        self.0.claim_due(n, l)
    }
    fn get(&self, c: &str, r: &str) -> Result<Option<OutboxEntry>, OutboxError> {
        self.0.get(c, r)
    }
    fn mark_submitted(&self, c: &str, r: &str) -> Result<(), OutboxError> {
        self.0.mark_submitted(c, r)
    }
    fn mark_retry(&self, c: &str, r: &str, n: i64, e: &str) -> Result<(), OutboxError> {
        self.0.mark_retry(c, r, n, e)
    }
    fn defer(&self, c: &str, r: &str, n: i64, e: &str) -> Result<(), OutboxError> {
        self.0.defer(c, r, n, e)
    }
    fn mark_dead(&self, c: &str, r: &str, e: &str) -> Result<(), OutboxError> {
        self.0.mark_dead(c, r, e)
    }
    fn redrive(&self, c: &str, r: &str, n: i64) -> Result<bool, OutboxError> {
        self.0.redrive(c, r, n)
    }
    fn list_dead(&self, c: &str) -> Result<Vec<OutboxEntry>, OutboxError> {
        self.0.list_dead(c)
    }
    fn counts(&self) -> Result<certcrypt_node::outbox::OutboxCounts, OutboxError> {
        self.0.counts()
    }
    fn purge_submitted(&self, l: usize) -> Result<usize, OutboxError> {
        self.0.purge_submitted(l)
    }
}

#[tokio::test]
async fn a_set_the_node_cannot_hold_is_refused_not_sent_unprotected() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    let node = spawn_node(&api, Arc::new(RefusingOutbox(MemoryOutbox::new()))).await;
    let resp = issue(&node, &shared::ISSUER_SEED, 1).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers()["retry-after"], "5");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["state"]["state"], "submission_failed",
        "retryable for an SDK"
    );
    assert_eq!(stub.calls.load(Ordering::SeqCst), 0, "nothing was sent");
}

// ---- A request_id already used: answered from what the node holds ----

fn with_request_id(mut body: serde_json::Value, request_id: &str) -> serde_json::Value {
    body["request_id"] = json!(request_id);
    body
}

/// The answer was lost and the client resends the same request: the node
/// replays the outcome it journaled and sends nothing. Building the set again
/// would stamp a new closure_time — a different set under the same
/// request_id, which the service refuses.
#[tokio::test]
async fn a_retry_after_a_lost_answer_replays_it_and_sends_nothing() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let body = with_request_id(issue_body(2), &ulid::Ulid::new().to_string());

    let first = issue_with(&node, &shared::ISSUER_SEED, &body).await;
    assert_eq!(first.status(), 200);
    let first: serde_json::Value = first.json().await.unwrap();
    // Past the second boundary, so a rebuilt set would differ.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let again = issue_with(&node, &shared::ISSUER_SEED, &body).await;
    assert_eq!(again.status(), 200);
    let again: serde_json::Value = again.json().await.unwrap();

    assert_eq!(
        again["results"], first["results"],
        "same ids, same outcomes"
    );
    assert_eq!(again["submission_set_id"], first["submission_set_id"]);
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1, "nothing resent");
}

/// Still queued (the service was down): the retry resends the STORED set,
/// byte for byte, not a new one.
#[tokio::test]
async fn a_retry_while_queued_resends_the_stored_set() {
    let (api, stub) = spawn_stub(OUTAGE).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let body = with_request_id(issue_body(1), &ulid::Ulid::new().to_string());

    assert_eq!(
        issue_with(&node, &shared::ISSUER_SEED, &body)
            .await
            .status(),
        202
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        issue_with(&node, &shared::ISSUER_SEED, &body)
            .await
            .status(),
        202
    );

    let sets = stub.sets.lock().unwrap().clone();
    assert_eq!(sets.len(), 2);
    assert!(!sets[0].is_empty());
    assert_eq!(sets[0], sets[1], "the same set both times");
    assert_eq!(all_entries(&node.outbox).len(), 1, "still one entry");
}

/// The same request_id with other content is a conflict, answered by the node
/// without sending anything — queued or already answered.
#[tokio::test]
async fn a_request_id_reused_with_other_content_is_a_conflict() {
    // Queued: the stored set is compared member by member.
    let (api, stub) = spawn_stub(OUTAGE).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let rid = ulid::Ulid::new().to_string();
    let first = with_request_id(issue_body(1), &rid);
    assert_eq!(
        issue_with(&node, &shared::ISSUER_SEED, &first)
            .await
            .status(),
        202
    );
    let other = with_request_id(issue_body(1), &rid); // a fresh fixture: other evidence
    let resp = issue_with(&node, &shared::ISSUER_SEED, &other).await;
    assert_eq!(resp.status(), 409);
    let err: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(err["error"], "idempotency_conflict");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);

    // Answered: the journal keeps outcomes, not sets, so the member count is
    // what tells a different request apart.
    let (api, stub) = spawn_stub(ACCEPT).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let rid = ulid::Ulid::new().to_string();
    let one = with_request_id(issue_body(1), &rid);
    assert_eq!(
        issue_with(&node, &shared::ISSUER_SEED, &one).await.status(),
        200
    );
    let two = with_request_id(issue_body(2), &rid);
    assert_eq!(
        issue_with(&node, &shared::ISSUER_SEED, &two).await.status(),
        409
    );
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
}

/// An issuer carries only its own evidence: a member bound to another
/// holder_key_set_root is refused before anything is sent or queued.
#[tokio::test]
async fn evidence_of_another_issuer_is_refused() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let mut body = issue_body(1);
    body["commitments"][0]["capacity_evidence"]["projected_authorization"]["holder_key_set_root"] =
        json!(shared::holder_key_set_root(&[99u8; 32]));
    let resp = issue_with(&node, &shared::ISSUER_SEED, &body).await;
    assert_eq!(resp.status(), 422);
    let err: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(err["error"], "evidence_not_of_issuer");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
    assert!(all_entries(&node.outbox).is_empty());
}

/// A journal that refuses writes while `failing` is set.
struct FlakyJournal {
    inner: MemoryJournal,
    failing: std::sync::atomic::AtomicBool,
}

impl FlakyJournal {
    fn check(&self) -> Result<(), JournalError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(JournalError::Backend("disk full".into()));
        }
        Ok(())
    }
}

impl JournalStore for FlakyJournal {
    fn put(&self, r: OperationRecord) -> Result<(), JournalError> {
        self.check()?;
        self.inner.put(r)
    }
    fn get_scoped(&self, c: &str, o: &str) -> Result<Option<OperationRecord>, JournalError> {
        self.inner.get_scoped(c, o)
    }
    fn list_scoped(&self, c: &str) -> Result<Vec<OperationRecord>, JournalError> {
        self.inner.list_scoped(c)
    }
    fn list_by_request(&self, c: &str, r: &str) -> Result<Vec<OperationRecord>, JournalError> {
        self.inner.list_by_request(c, r)
    }
    fn mark_terminal(&self, c: &str, o: &str, at: i64) -> Result<(), JournalError> {
        self.inner.mark_terminal(c, o, at)
    }
    fn mark_request_resolved(&self, c: &str, r: &str, at: i64) -> Result<(), JournalError> {
        self.inner.mark_request_resolved(c, r, at)
    }
    fn purge_expired(
        &self,
        now: i64,
        retention: i64,
        limit: usize,
    ) -> Result<certcrypt_node::store::PurgeOutcome, JournalError> {
        self.inner.purge_expired(now, retention, limit)
    }
}

/// The service accepted the set but the node could not journal the outcome:
/// it answers 503 ("resend") and KEEPS the outbox entry, so the resend carries
/// the same set instead of a new one the service would refuse.
#[tokio::test]
async fn a_journal_failure_keeps_the_set_for_the_resend() {
    let (api, stub) = spawn_stub(ACCEPT).await;
    let journal = Arc::new(FlakyJournal {
        inner: MemoryJournal::new(),
        failing: std::sync::atomic::AtomicBool::new(true),
    });
    let node = spawn_node_full(&api, Arc::new(MemoryOutbox::new()), journal.clone(), 10_000).await;
    let body = with_request_id(issue_body(1), &ulid::Ulid::new().to_string());

    assert_eq!(
        issue_with(&node, &shared::ISSUER_SEED, &body)
            .await
            .status(),
        503
    );
    assert_eq!(all_entries(&node.outbox).len(), 1, "the set is kept");

    journal.failing.store(false, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_eq!(
        issue_with(&node, &shared::ISSUER_SEED, &body)
            .await
            .status(),
        200
    );

    let sets = stub.sets.lock().unwrap().clone();
    assert_eq!(sets.len(), 2);
    assert_eq!(sets[0], sets[1], "the resend carried the same set");
    assert!(all_entries(&node.outbox).is_empty(), "done once journaled");
}

// ---- insufficient_capacity: waited out while the commitments are valid ----

/// The state of one operation, as its issuer reads it.
async fn operation_state(node: &Node, id: &str) -> serde_json::Value {
    let rec: serde_json::Value = shared::signed(
        reqwest::Client::new().get(format!("http://{}/v1/operations/{id}", node.addr)),
        &shared::ISSUER_SEED,
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    rec["state"].clone()
}

/// Submits `n` members against a service with no capacity for them and
/// returns the member ids the node handed out while it waits.
async fn issue_while_short(node: &Node, n: usize) -> Vec<String> {
    let resp = issue(node, &shared::ISSUER_SEED, n).await;
    assert_eq!(resp.status(), 202, "held while the commitments are valid");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["state"].is_null(), "answered per member");
    let results = body["results"].as_array().expect("one result per member");
    assert_eq!(results.len(), n);
    results
        .iter()
        .map(|r| {
            assert_eq!(r["state"]["state"], "accepted_for_retry");
            assert_eq!(r["state"]["capacity"]["missing"], "3.00");
            r["operation_id"].as_str().unwrap().to_string()
        })
        .collect()
}

const MINUTE_MS: i64 = 60_000;

#[tokio::test]
async fn a_capacity_refusal_is_held_and_submitted_again_on_schedule() {
    let (api, stub) = spawn_stub(NO_CAPACITY).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let t0 = Utc::now().timestamp_millis();

    let ids = issue_while_short(&node, 2).await;
    let entries = all_entries(&node.outbox);
    assert_eq!(entries.len(), 1, "the set stays in the outbox");
    assert_eq!(entries[0].attempts, 0, "waiting is not a failed attempt");
    let first_due = entries[0].next_attempt_at_ms;
    assert!(
        (t0 + 50_000..=t0 + 70_000).contains(&first_due),
        "first new attempt about a minute later"
    );
    assert!(
        node.outbox.claim_due(t0 + 30_000, 10).unwrap().is_empty(),
        "nothing is due before then"
    );

    // Still short two minutes in: held again, two minutes later.
    node.relay.tick(t0 + 2 * MINUTE_MS).await;
    assert_eq!(stub.calls.load(Ordering::SeqCst), 2);
    let entries = all_entries(&node.outbox);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].attempts, 0);
    assert!(entries[0].next_attempt_at_ms >= t0 + 3 * MINUTE_MS);
    for id in &ids {
        let st = operation_state(&node, id).await;
        assert_eq!(st["state"], "accepted_for_retry");
        assert_eq!(st["capacity"]["required"], "5.00");
    }

    // Capacity arrived: the next attempt is admitted, on the same ids.
    stub.mode.store(ACCEPT, Ordering::SeqCst);
    node.relay.tick(t0 + 5 * MINUTE_MS).await;
    assert!(all_entries(&node.outbox).is_empty(), "delivered");
    for (i, id) in ids.iter().enumerate() {
        let st = operation_state(&node, id).await;
        assert_eq!(st["state"], "accepted", "member {i}");
        assert_eq!(st["upstream_operation_id"], format!("OP-UP-{i}"));
    }
    let sets = stub.sets.lock().unwrap().clone();
    assert!(
        sets.windows(2).all(|w| w[0] == w[1]),
        "the same set each time"
    );
}

#[tokio::test]
async fn a_capacity_refusal_past_the_window_is_final() {
    let (api, _stub) = spawn_stub(NO_CAPACITY).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;

    let ids = issue_while_short(&node, 2).await;
    // An hour later the 30-minute commitments have expired: the refusal stands.
    node.relay.tick(later()).await;
    assert!(
        all_entries(&node.outbox).is_empty(),
        "nothing left to retry"
    );
    for id in &ids {
        let st = operation_state(&node, id).await;
        assert_eq!(st["state"], "insufficient_capacity");
        assert_eq!(st["capacity"]["missing"], "3.00", "the last figures");
    }
}

#[tokio::test]
async fn a_capacity_refusal_with_no_window_left_is_final_at_once() {
    let (api, stub) = spawn_stub(NO_CAPACITY).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;

    // Expiring sooner than the safety margin: there is nothing to wait for.
    let resp = issue_with(
        &node,
        &shared::ISSUER_SEED,
        &issue_body_expiring(1, Duration::minutes(3)),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["state"]["state"], "insufficient_capacity");
    assert_eq!(body["state"]["capacity"]["available"], "2.00");
    assert!(all_entries(&node.outbox).is_empty());
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn another_verdict_on_a_later_attempt_is_recorded_as_on_a_first_submission() {
    let (api, stub) = spawn_stub(NO_CAPACITY).await;
    let node = spawn_node(&api, Arc::new(MemoryOutbox::new())).await;
    let t0 = Utc::now().timestamp_millis();

    let ids = issue_while_short(&node, 1).await;
    stub.mode.store(SET_REJECTED, Ordering::SeqCst);
    node.relay.tick(t0 + 2 * MINUTE_MS).await;
    assert!(all_entries(&node.outbox).is_empty());
    let st = operation_state(&node, &ids[0]).await;
    assert_eq!(st["state"], "pre_evaluation_rejected");
    assert_eq!(st["reason_code"], "submission_set_invalid");
}
