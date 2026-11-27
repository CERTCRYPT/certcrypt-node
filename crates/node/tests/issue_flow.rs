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

//! End-to-end issue flow: issuer client -> node -> (stub issuance service).
//!
//! Stands up a minimal stub of the issuance service's `POST /v1/submit` and a
//! real `certcrypt-node` HTTP server, then drives the path an issuer client would:
//! `POST /v1/issue` with a real signed `submission-set/1`, and asserts the
//! node submits upstream (with the right envelope and recognition proof, and no
//! shared bearer) and journals the
//! outcome, retrievable via `GET /v1/operations/{id}`.
//!
//! The stub lets us exercise node's upstream client + http + store without
//! booting the issuance service. The submission set is a real fixture from
//! this repo's own fixture builder, so the wire payload is the genuine shape.

mod shared;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use certcrypt_node::http::{router, NodeState};
use certcrypt_node::store::MemoryJournal;
use certcrypt_node::upstream::UpstreamClient;
use chrono::{Duration, SubsecRound, Utc};
use serde_json::json;

/// Stub issuance-service state: records the last seen Authorization header + body.
#[derive(Clone, Default)]
struct StubState {
    seen: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
}

/// Per-member stub of the issuance service's submission-set response. It echoes one outcome
/// per certificate it received, so the node's per-member plumbing is exercised
/// against the genuine wire shape (`submission-set/1` §11). To exercise PARTIAL
/// acceptance, when more than one member is present it marks the LAST one as a
/// replay (the "bad" member that must NOT tumble the valid ones).
async fn stub_submit_submission_set(
    State(st): State<StubState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    st.seen.lock().unwrap().push((auth, body.clone()));

    let certs = body["submission_set"]["payload"]["certificates"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let n = certs.len();
    let results: Vec<serde_json::Value> = certs
        .iter()
        .enumerate()
        .map(|(i, _c)| {
            // Partial acceptance: with N>1 the last member is a replay; all
            // others accepted. With N==1 the single member is accepted.
            if n > 1 && i == n - 1 {
                json!({
                    "commitment_index": i,
                    "status": "replay_detected",
                    "message": "already consumed"
                })
            } else {
                json!({
                    "commitment_index": i,
                    "status": "accepted",
                    "operation_id": format!("OP-UPSTREAM-{}", i + 1)
                })
            }
        })
        .collect();

    Json(json!({
        "submission_set_id": "stub-set-id-abc",
        "results": results
    }))
}

/// Stub of the issuance service's `GET /v1/operations/{id}`. Models the ASYNCHRONOUS terminal
/// transition the real issuance service performs: an accepted operation is finalized to
/// `independent_ready` with its PoI + settlement material out-of-band. This lets
/// the node's reconciliation path (a non-terminal local record → fresh upstream view)
/// be exercised without a real issuance service or chain. Any id starting with
/// `OP-UPSTREAM-` is reported as terminal.
async fn stub_get_operation(
    axum::extract::Path(operation_id): axum::extract::Path<String>,
) -> Response {
    if operation_id.starts_with("OP-UPSTREAM-") {
        return Json(json!({
            "operation_id": operation_id,
            "status": "independent_ready",
            "independence_proof": "eyJzdHViIjoicG9pIn0=",
            "settlement_material": "eyJzdHViIjoic2V0dGxlbWVudCJ9"
        }))
        .into_response();
    }
    (axum::http::StatusCode::NOT_FOUND, "operation not found").into_response()
}

async fn spawn_stub_api() -> (SocketAddr, StubState) {
    // The default stub has NO `/v1/operations/{id}` route: an operations GET
    // returns 404, so the node's reconciliation falls back to the local record.
    // This isolates the journaling tests from reconciliation. The reconciliation
    // path itself is exercised by `spawn_stub_api_with_operations` below.
    let state = StubState::default();
    let app = Router::new()
        .route("/v1/submit", post(stub_submit_submission_set))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, state)
}

/// Stub that ALSO serves `GET /v1/operations/{id}` with a terminal view, to
/// exercise the node's reconciliation path.
async fn spawn_stub_api_with_operations() -> (SocketAddr, StubState) {
    let state = StubState::default();
    let app = Router::new()
        .route("/v1/submit", post(stub_submit_submission_set))
        .route("/v1/operations/:operation_id", get(stub_get_operation))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, state)
}

/// Two distinct test issuers, identified by their key-set seed. The node keeps
/// no list of issuer tokens: an issuer PRESENTS a system-domain-signed Level-1
/// binding plus a fresh possession signature, and the node verifies it offline.
/// So a test "issuer" is just a seed — its `holder_key_set_root` (the authenticated
/// scope) is derived from it, exactly as in production.
const SEED_ISSUER_A: [u8; 32] = [42u8; 32];
const SEED_OTHER: [u8; 32] = [43u8; 32];

/// The system-domain Level-1 seed the stub trust anchor is built from, and the
/// fingerprint the node pins. Fixed values: these are test vectors, not secrets.
const L1_SEED: [u8; 32] = [7u8; 32];
const FP: &str = "abababababababababababababababababababababababababababababababab";
const KID: &str = "test-l1-kid";

/// Build the trust anchor the node verifies issuer proofs against: a resolver
/// seeded with the system-domain L1 public key under the pinned fingerprint.
/// Stands in for the foundation-backed resolver main.rs builds: once a key
/// resolves, the verification path is the same.
fn issuer_verifier() -> certcrypt_node::auth::IssuerVerifier {
    use capacity_artifacts::composite_sig::PROFILE_P256_MLDSA65;
    use capacity_verify::manifest::{ResolvedManifestEntry, StaticManifestResolver};

    let (l1_mldsa_pub, _) = capacity_verify::mldsa::keypair_from_seed(&L1_SEED).unwrap();
    let ecdsa_sk = capacity_verify::ecdsa_p256::signing_key_from_seed(&L1_SEED);
    let l1_p256_pub = capacity_verify::ecdsa_p256::public_key_sec1(&ecdsa_sk, false);

    let mut resolver = StaticManifestResolver::new();
    resolver.insert(
        FP,
        ResolvedManifestEntry {
            kid: KID.into(),
            algorithm: PROFILE_P256_MLDSA65.into(),
            public_key: l1_mldsa_pub,
            classical_public_key: l1_p256_pub,
            valid_from: Some(
                chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2020, 1, 1, 0, 0, 0).unwrap(),
            ),
            valid_until: Some(
                chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2099, 1, 1, 0, 0, 0).unwrap(),
            ),
        },
    );
    certcrypt_node::auth::IssuerVerifier {
        resolver: Arc::new(resolver),
        system_root_fingerprint: Arc::new(FP.to_string()),
        challenges: Arc::new(Default::default()),
    }
}

/// The `x-certcrypt-issuer-auth` header value for `seed`: base64(JSON) of a
/// complete, valid proof.
///
/// A FRESH one per call, deliberately. The node accepts a challenge exactly once
/// (freshness + single use), so a helper that returned a cached header would make
/// every test after the first fail as a replay — and would quietly stop testing
/// what it claims to test.
/// One `/v1/issue` member from a fixture certificate, bound to the root `seed`
/// authenticates with: the node only carries an issuer's OWN evidence. It does
/// not verify the evidence signature (the service does), so rewriting the root
/// leaves the request otherwise intact.
fn issue_member(
    c: &capacity_artifacts::SubmissionSetCertificateV1,
    seed: &[u8; 32],
) -> serde_json::Value {
    let (leaf_pub, _) = capacity_verify::mldsa::keypair_from_seed(seed).unwrap();
    let mut member = json!({
        "capacity_evidence": c.capacity_evidence,
        "operative": c.operative,
    });
    member["capacity_evidence"]["projected_authorization"]["holder_key_set_root"] =
        json!(capacity_artifacts::capacity_evidence::operation_key_leaf_hash(&leaf_pub));
    member
}

fn issuer_auth_header(seed: &[u8; 32], request: &shared::RequestBinding) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use sha3::{Digest, Sha3_256};

    let ecdsa_sk = capacity_verify::ecdsa_p256::signing_key_from_seed(&L1_SEED);
    let (leaf_pub, _) = capacity_verify::mldsa::keypair_from_seed(seed).unwrap();
    let root = capacity_artifacts::capacity_evidence::operation_key_leaf_hash(&leaf_pub);

    let binding = capacity_artifacts::capacity_holder_authorization::Level1AuthorizationBinding {
        system_id: "certcrypt".into(),
        rules_version: "rules/conformance".into(),
        system_root_fingerprint: FP.into(),
        authorized_role: "capacity_commitment_holder".into(),
        authorization_issuer_kid: KID.into(),
        valid_from: "2026-01-01T00:00:00Z".into(),
        valid_until: "2099-01-01T00:00:00Z".into(),
        holder_key_set_root: root,
    };
    let digest = hex::encode(Sha3_256::digest(binding.signing_bytes().unwrap()));
    let level1_signature =
        capacity_verify::composite::composite_sign_p256(&digest, &ecdsa_sk, &L1_SEED).unwrap();

    // `<unix_millis>.<nonce>` — the shape the SDK mints and the node's freshness
    // check parses. The counter keeps concurrent tests from colliding.
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let challenge = format!(
        "{}.it-{}",
        chrono::Utc::now().timestamp_millis(),
        NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let possession =
        capacity_verify::mldsa::sign_detached(seed, request.message(&challenge).as_bytes())
            .unwrap();

    let proof = json!({
        "signed_level1": {
            "level1_binding": binding,
            "level1_signature": level1_signature,
        },
        "disclosure": {
            "leaf_index": 0,
            "public_key_b64": B64.encode(&leaf_pub),
            "inclusion_proof": [],
            "tree_size": 1,
        },
        "challenge": challenge,
        "possession_b64": B64.encode(&possession),
    });
    B64.encode(serde_json::to_vec(&proof).unwrap())
}

/// Header name the node reads the issuer proof from.
const ISSUER_AUTH_HEADER: &str = "x-certcrypt-issuer-auth";

/// `builder` with a fresh proof for `seed` (this file's L1 material), bound to
/// that very request. Call it last, once the body is set.
fn signed(builder: reqwest::RequestBuilder, seed: &[u8; 32]) -> reqwest::RequestBuilder {
    let request = shared::request_binding(&builder);
    builder.header(ISSUER_AUTH_HEADER, issuer_auth_header(seed, &request))
}

/// Build an operator identity + a recognition credential for the node. The
/// stub issuance service does not verify the credential signature, so a
/// self-signed credential over the operator's real public key is enough to let
/// the node assemble the recognition proof (operator recognition is mandatory).
fn operator_material() -> (
    certcrypt_node_core::operator_receipt::OperatorIdentity,
    capacity_artifacts::operator_recognition::OperatorRecognitionCredentialV1,
) {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use capacity_artifacts::operator_recognition::{
        OperatorRecognitionCredentialV1, RecognitionInputs, RecognitionIssuer,
        RecognitionSignature, OPERATOR_KEY_ALG_ACTIVE, RECOGNITION_ARTIFACT_TYPE,
        SIGNATURE_ALG_ACTIVE,
    };
    use capacity_verify::mldsa;
    use chrono::TimeZone;

    let operator = certcrypt_node_core::operator_receipt::OperatorIdentity::generate();
    let operator_pk_b64 = B64.encode(&operator.public_key);

    let (_cred_pk, cred_sk) = mldsa::keypair();
    let cred_kid = "dev:test-credential-subkey".to_string();
    let valid_from = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let valid_until = chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
    let recognition_issuer = RecognitionIssuer {
        kid: cred_kid,
        manifest_sequence: 1,
    };
    let inputs = RecognitionInputs {
        system_root_fingerprint: "ab".repeat(32),
        rules_version: "rules/conformance".to_string(),
        operator_public_key: operator_pk_b64.clone(),
        operator_key_alg: OPERATOR_KEY_ALG_ACTIVE.to_string(),
        valid_from,
        valid_until,
        recognition_issuer: recognition_issuer.clone(),
    };
    let recognition_id =
        OperatorRecognitionCredentialV1::compute_recognition_id(&inputs, &operator.operator_id)
            .unwrap();
    let mut credential = OperatorRecognitionCredentialV1 {
        artifact_type: RECOGNITION_ARTIFACT_TYPE.to_string(),
        system_id: capacity_artifacts::capacity_commitment::SYSTEM_ID_ACTIVE.to_string(),
        rules_version: "rules/conformance".to_string(),
        system_root_fingerprint: "ab".repeat(32),
        recognition_id,
        operator_id: operator.operator_id.clone(),
        operator_public_key: operator_pk_b64,
        operator_key_alg: OPERATOR_KEY_ALG_ACTIVE.to_string(),
        valid_from,
        valid_until,
        recognition_issuer,
        signature: RecognitionSignature {
            signature_alg: SIGNATURE_ALG_ACTIVE.to_string(),
            signature_b64: String::new(),
        },
    };
    let signing_bytes = credential.signing_bytes().unwrap();
    let sig = mldsa::sign_detached(&cred_sk, &signing_bytes).unwrap();
    credential.signature.signature_b64 = B64.encode(&sig);
    (operator, credential)
}

async fn spawn_node(api_url: String) -> SocketAddr {
    let (operator, credential) = operator_material();
    let state = NodeState {
        upstream: Arc::new(UpstreamClient::new(api_url)),
        store: Arc::new(MemoryJournal::new()),
        outbox: Arc::new(certcrypt_node::outbox::MemoryOutbox::new()),
        issuer_verifier: issuer_verifier(),
        // Operator recognition is mandatory at submit; the node must hold
        // an operator identity + credential to assemble the proof.
        operator: Some(Arc::new(operator)),
        operator_credential: Some(Arc::new(credential)),
        max_commitments_per_request: 10_000,
        lifecycle: Default::default(),
        deployment_rules: Default::default(),
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn issuer_issues_set_node_submits_upstream_and_journals() {
    // Real signed submission set (the wire payload an issuer client would hand the node).
    let now = Utc::now().trunc_subsecs(0);
    let closure = now - Duration::minutes(1);
    let expires = now + Duration::minutes(30);
    let fixture = shared::submission_set_fixture::make_dev_submission_set(closure, expires);

    let (api_addr, stub) = spawn_stub_api().await;
    let node_addr = spawn_node(format!("http://{api_addr}")).await;

    let client = reqwest::Client::new();

    // 1) The issuer client POSTs /v1/issue with the LOOSE commitments (the SDK ships signed
    // CapacityEvidence; the node is the builder that wraps them into the set). The
    // scope (contract_id) is DERIVED from the issuer proof, never declared in the body.
    let commitments: Vec<serde_json::Value> = fixture
        .submission_set
        .certificates
        .iter()
        .map(|c| issue_member(c, &SEED_ISSUER_A))
        .collect();
    let issue_body = json!({ "commitments": commitments });
    let resp = signed(
        client
            .post(format!("http://{node_addr}/v1/issue"))
            .json(&issue_body),
        &SEED_ISSUER_A,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200, "issue should succeed");
    let issued: serde_json::Value = resp.json().await.unwrap();

    // Per-member response shape (submission-set/1 §11): a single-member set is
    // the degenerate case — one entry in `results`, no whole-request `state`.
    assert_eq!(issued["submission_set_id"], "stub-set-id-abc");
    let results = issued["results"].as_array().expect("results array");
    assert_eq!(results.len(), 1, "single-member set has one result");
    let member = &results[0];
    let operation_id = member["operation_id"].as_str().unwrap().to_string();
    assert!(operation_id.starts_with("op_"), "node-local member op id");
    assert_eq!(member["commitment_index"], 0);
    assert_eq!(member["state"]["state"], "accepted");
    assert_eq!(
        member["state"]["upstream_operation_id"], "OP-UPSTREAM-1",
        "node surfaces the member's upstream operation id"
    );

    // 2) The node actually called the stub issuance service with the proof-bearing envelope
    // and no shared bearer credential.
    // Copy out of the lock immediately so no guard is held across later awaits.
    let calls: Vec<(String, serde_json::Value)> = stub.seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "node made exactly one upstream call");
    let (auth, body) = &calls[0];
    assert!(
        auth.is_empty(),
        "node must not send a shared bearer credential"
    );
    assert_eq!(
        body["submission_set"]["schema"], "submission-set/1",
        "canonical artifact family label, per the API contract's `schema` property"
    );
    assert_eq!(
        body["submission_set"]["payload"]["schema"], "submission-set/1",
        "inner artifact schema"
    );
    assert!(
        body["request_id"].as_str().unwrap().len() >= 26,
        "ULID idempotency key"
    );
    // The node attached the operator-recognition proof (mandatory):
    // the credential plus a possession signature bound to this submit.
    assert_eq!(
        body["operator_recognition"]["credential"]["artifact_type"], "operator.recognition/1",
        "node attaches its recognition credential"
    );
    assert!(
        body["operator_recognition"]["possession_b64"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "node attaches a possession proof"
    );

    // 3) Status is retrievable by the SAME issuer (scope derived from its proof).
    let status = signed(
        client.get(format!("http://{node_addr}/v1/operations/{operation_id}")),
        &SEED_ISSUER_A,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(status.status(), 200);
    let rec: serde_json::Value = status.json().await.unwrap();
    assert_eq!(rec["operation_id"], operation_id);
    assert_eq!(rec["state"]["state"], "accepted");
    // The per-member record carries its submission-set grouping.
    assert_eq!(rec["submission_set_id"], "stub-set-id-abc");
    assert_eq!(rec["commitment_index"], 0);

    // 4) A DIFFERENT issuer (different proof -> different scope) must NOT see
    // the operation: 404, indistinguishable from "not found". The
    // scope cannot be spoofed because it comes from the proof, not the request.
    let cross = signed(
        client.get(format!("http://{node_addr}/v1/operations/{operation_id}")),
        &SEED_OTHER,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        cross.status(),
        404,
        "another issuer must not see this operation"
    );
}

#[tokio::test]
async fn partial_acceptance_journals_one_record_per_member() {
    // A submission set of THREE members of the same issuer (one settlement
    // leaf). The stub marks the last as a replay; the first two are accepted.
    // The node must surface a per-member result for each AND journal each member
    // as its own operation — the bad member does NOT tumble the valid ones.
    let now = Utc::now().trunc_subsecs(0);
    let closure = now - Duration::minutes(1);
    let expires = now + Duration::minutes(30);
    let fixture = shared::submission_set_fixture::make_dev_submission_set_n(closure, expires, 3);

    let (api_addr, stub) = spawn_stub_api().await;
    let node_addr = spawn_node(format!("http://{api_addr}")).await;
    let client = reqwest::Client::new();

    let commitments: Vec<serde_json::Value> = fixture
        .submission_set
        .certificates
        .iter()
        .map(|c| issue_member(c, &SEED_ISSUER_A))
        .collect();
    let resp = signed(
        client
            .post(format!("http://{node_addr}/v1/issue"))
            .json(&json!({ "commitments": commitments })),
        &SEED_ISSUER_A,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let issued: serde_json::Value = resp.json().await.unwrap();

    // One result per submitted member, in order.
    let results = issued["results"].as_array().expect("results array");
    assert_eq!(results.len(), 3, "three members in, three results out");
    assert_eq!(results[0]["state"]["state"], "accepted");
    assert_eq!(results[1]["state"]["state"], "accepted");
    assert_eq!(
        results[2]["state"]["state"], "replay_detected",
        "the bad member is rejected individually"
    );
    // The whole-request `state` is absent on the per-member path.
    assert!(
        issued["state"].is_null(),
        "no whole-request state when per-member"
    );

    // The node made exactly one upstream call carrying all three certs.
    let calls: Vec<(String, serde_json::Value)> = stub.seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    let certs = calls[0].1["submission_set"]["payload"]["certificates"]
        .as_array()
        .unwrap();
    assert_eq!(
        certs.len(),
        3,
        "all three members sent in one submission set"
    );

    // Each member was journaled as its OWN operation, retrievable by its id, and
    // carries the shared submission_set_id.
    for (i, member) in results.iter().enumerate() {
        let op_id = member["operation_id"].as_str().unwrap();
        let rec: serde_json::Value = signed(
            client.get(format!("http://{node_addr}/v1/operations/{op_id}")),
            &SEED_ISSUER_A,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
        assert_eq!(rec["operation_id"], *op_id);
        assert_eq!(rec["commitment_index"], i);
        assert_eq!(rec["submission_set_id"], "stub-set-id-abc");
        let expected = if i == 2 {
            "replay_detected"
        } else {
            "accepted"
        };
        assert_eq!(rec["state"]["state"], expected);
    }
}

#[tokio::test]
async fn issue_without_credential_is_401() {
    let (api_addr, _stub) = spawn_stub_api().await;
    let node_addr = spawn_node(format!("http://{api_addr}")).await;
    let client = reqwest::Client::new();
    // No Authorization header.
    let resp = client
        .post(format!("http://{node_addr}/v1/issue"))
        .json(&json!({ "commitments": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "no credential -> unauthorized");

    // Unverifiable issuer proof.
    let resp2 = client
        .post(format!("http://{node_addr}/v1/issue"))
        .bearer_auth("tok-bogus")
        .json(&json!({ "commitments": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 401, "unknown credential -> unauthorized");
}

#[tokio::test]
async fn unknown_operation_is_404() {
    let (api_addr, _stub) = spawn_stub_api().await;
    let node_addr = spawn_node(format!("http://{api_addr}")).await;
    let client = reqwest::Client::new();
    // Authenticated, but the operation does not exist in this scope -> 404.
    let resp = signed(
        client.get(format!("http://{node_addr}/v1/operations/op_missing")),
        &SEED_ISSUER_A,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn health_ok() {
    let (api_addr, _stub) = spawn_stub_api().await;
    let node_addr = spawn_node(format!("http://{api_addr}")).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{node_addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// The node RECONCILES a non-terminal local record with the issuance service: after a member
/// is accepted (local state `accepted`), a `GET /v1/operations/{id}` on the node
/// proxies to the issuance service by the `upstream_operation_id` and returns the issuance service's fresh
/// terminal view (`independent_ready` + PoI + settlement material) — closing the
/// loop the issuer's SDK polls. Without this the node would report `accepted`
/// forever and the SDK would never observe `independent_ready`.
#[tokio::test]
async fn node_reconciles_accepted_to_independent_ready_from_api() {
    let now = Utc::now().trunc_subsecs(0);
    let closure = now - Duration::minutes(1);
    let expires = now + Duration::minutes(30);
    let fixture = shared::submission_set_fixture::make_dev_submission_set(closure, expires);

    let (api_addr, _stub) = spawn_stub_api_with_operations().await;
    let node_addr = spawn_node(format!("http://{api_addr}")).await;
    let client = reqwest::Client::new();

    // 1) Issue one commitment → the stub issuance service accepts it (operation_id OP-UPSTREAM-1),
    //    so the node journals a non-terminal `accepted` record.
    let commitments: Vec<serde_json::Value> = fixture
        .submission_set
        .certificates
        .iter()
        .map(|c| issue_member(c, &SEED_ISSUER_A))
        .collect();
    let issue_resp = signed(
        client
            .post(format!("http://{node_addr}/v1/issue"))
            .json(&json!({ "commitments": commitments })),
        &SEED_ISSUER_A,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(issue_resp.status(), 200, "issue accepted");
    let issue_body: serde_json::Value = issue_resp.json().await.unwrap();
    let operation_id = issue_body["results"][0]["operation_id"]
        .as_str()
        .expect("node-local operation_id")
        .to_string();

    // 2) GET the operation on the NODE. The local record is `accepted`, so the
    //    node MUST reconcile with the issuance service and return the terminal view.
    let get_resp = signed(
        client.get(format!("http://{node_addr}/v1/operations/{operation_id}")),
        &SEED_ISSUER_A,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(get_resp.status(), 200);
    let body: serde_json::Value = get_resp.json().await.unwrap();

    // The node forwarded the issuance service's terminal state — NOT the local `accepted`.
    assert_eq!(
        body["status"], "independent_ready",
        "node must reconcile to the upstream terminal state, got: {body}"
    );
    assert!(
        body["independence_proof"].is_string(),
        "reconciled body must carry the PoI from upstream: {body}"
    );
    assert!(
        body["settlement_material"].is_string(),
        "reconciled body must carry the settlement material from upstream: {body}"
    );
}
