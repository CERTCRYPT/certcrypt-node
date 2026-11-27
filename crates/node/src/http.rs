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

//! Node HTTP surface — what the issuer application consumes.
//!
//! The core of the contract:
//! - `GET  /health` — liveness
//! - `POST /v1/issue` — accept loose commitments, close them into one
//!   submission set, submit it upstream to the issuance service, journal the
//!   outcome
//! - `GET  /v1/operations/{id}` — read a node-local operation's state
//!
//! The issuer application is a CLIENT of the node. The node owns the upstream
//! submission; the issuer client never talks to the issuance service
//! directly. The evidence is built and signed elsewhere (by the issuer) and
//! handed here loose; the node closes it into a `submission-set/1` artifact.

use std::sync::Arc;

use base64::Engine as _;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use capacity_artifacts::operator_recognition::OperatorRecognitionCredentialV1;
use capacity_artifacts::{SubmissionSetCertificateV1, SubmissionSetV1};
use certcrypt_node_core::operator_receipt::{OperatorIdentity, OperatorReceipt};
use certcrypt_node_core::{
    assemble_submission_set, CapacityEvidence, OperativeContext, SubmissionMember,
};
use serde::{Deserialize, Serialize};

use crate::auth::{AuthedIssuer, IssuerVerifier};
use crate::outbox::{OutboxEntry, OutboxState, OutboxStore};
use crate::store::{JournalStore, OperationRecord, OperationState};
use crate::upstream::{FlatOutcome, SubmitResponse, UpstreamClient};

/// Margin on top of the upstream request budget before an admitted outbox entry
/// becomes visible to the relay (see the admit in the issue handler).
const OUTBOX_INLINE_GRACE_MARGIN_MS: i64 = 5_000;

/// Shared node state.
#[derive(Clone)]
pub struct NodeState {
    pub upstream: Arc<UpstreamClient>,
    pub store: Arc<dyn JournalStore>,
    /// The trust anchor the node verifies issuer proofs against, OFFLINE: the
    /// system-domain Level-1 public key (resolved via the manifest by fingerprint +
    /// kid) plus the pinned `system_root_fingerprint`. No static token map, no DB,
    /// no call to the issuance service — the issuer PRESENTS a
    /// `SignedLevel1Binding` + a fresh possession signature and the node
    /// VERIFIES it (verify, don't trust).
    pub issuer_verifier: IssuerVerifier,
    /// The node's operator identity. When present, the node signs an operator
    /// receipt for each submission_set it transports (bound by submission_set_id, opt-in,
    /// detachable — it does NOT affect the verifier verdict and is NOT a
    /// linkable per-certificate stamp). `None` if started without an operator
    /// key (receipt simply omitted).
    pub operator: Option<Arc<OperatorIdentity>>,
    /// The node's system-domain-signed recognition credential (operator.recognition/1),
    /// obtained once from the issuance service and configured here. The node
    /// presents it with every submission set it transports (and with every
    /// domain-binding registration); the issuance service is the only party
    /// that checks it. `None` if not configured (the node then cannot prove
    /// recognition, and operator recognition is mandatory: it cannot submit).
    pub operator_credential: Option<Arc<OperatorRecognitionCredentialV1>>,
    /// Defensive cap on members per `/v1/issue` (anti-DoS/OOM on the managed
    /// node). NOT protocol semantics — the spec sets no max members per set; this
    /// is operational robustness, configurable (a self-hosted issuer with a large
    /// nightly batch may raise it; the managed node keeps it conservative).
    pub max_commitments_per_request: usize,
    /// Durable transactional outbox: the signed submission-set is admitted here
    /// BEFORE the upstream POST, so a background relay can resubmit it (same
    /// request_id, idempotent) if the issuance service is down, the node
    /// restarts, or the client dies. See `outbox.rs`.
    pub outbox: Arc<dyn OutboxStore>,
    /// Whether the process is shutting down (see [`Lifecycle`]).
    pub lifecycle: Lifecycle,
    /// Rules domains this deployment runs under beyond the published ones (see
    /// [`DeploymentRules`]). Empty by default.
    pub deployment_rules: DeploymentRules,
}

/// The node's own lifecycle, as the HTTP surface sees it.
///
/// On shutdown the node first DRAINS: for a short window it keeps its port
/// open and answers every write with `503` + `Retry-After` — the time the
/// operator expects the restart to take — while reads keep working and the
/// requests already in flight finish. An SDK that arrives then learns when to
/// come back. Without the window it would find the port closed, which says
/// nothing about when the node returns.
#[derive(Debug, Clone)]
pub struct Lifecycle {
    draining: Arc<std::sync::atomic::AtomicBool>,
    restart_retry_after: std::time::Duration,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            restart_retry_after: std::time::Duration::from_secs(10),
        }
    }
}

impl Lifecycle {
    /// Set the `Retry-After` announced while draining (at least one second).
    pub fn with_restart_retry_after(mut self, d: std::time::Duration) -> Self {
        self.restart_retry_after = d.max(std::time::Duration::from_secs(1));
        self
    }

    /// Read `{prefix}RESTART_RETRY_AFTER_SECS`, falling back to the default
    /// (10 s) when unset, unparseable or zero.
    pub fn from_env_prefixed(prefix: &str) -> Self {
        let d = Self::default();
        match std::env::var(format!("{prefix}RESTART_RETRY_AFTER_SECS"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|&n| n > 0)
        {
            Some(secs) => d.with_restart_retry_after(std::time::Duration::from_secs(secs)),
            None => d,
        }
    }

    /// Start draining. Irreversible for the life of the process.
    pub fn begin_drain(&self) {
        self.draining
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn restart_retry_after(&self) -> std::time::Duration {
        self.restart_retry_after
    }
}

/// While draining, refuse every write with `503` + `Retry-After`; let reads
/// through. A read changes nothing, and an issuer polling an operation should
/// not see it vanish because the node is restarting.
async fn drain_gate(
    State(state): State<NodeState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !state.lifecycle.is_draining() || req.method() == axum::http::Method::GET {
        return next.run(req).await;
    }
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "node_restarting",
            "message": "the node is restarting; retry after the indicated time",
        })),
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(state.lifecycle.restart_retry_after().as_secs()),
    );
    resp
}

impl axum::extract::FromRef<NodeState> for IssuerVerifier {
    fn from_ref(state: &NodeState) -> IssuerVerifier {
        state.issuer_verifier.clone()
    }
}

/// HTTP backpressure limits for [`router_with_limits`].
///
/// Every knob is public and settable in code; nothing here reads the
/// environment unless you ask it to via [`HttpLimits::from_env_prefixed`]. An
/// operator embedding this crate keeps whatever configuration system it already
/// has, and gets no surprises from variables it did not set.
///
/// ```no_run
/// use certcrypt_node::HttpLimits;
/// use std::time::Duration;
///
/// // Explicit, the default style for an embedder.
/// let limits = HttpLimits::default()
///     .with_max_concurrent_requests(256)
///     .with_request_timeout(Duration::from_secs(60));
///
/// // Or from your own environment namespace.
/// let limits = HttpLimits::from_env_prefixed("ACME_NODE_");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    /// Requests served concurrently across the `/v1/*` surface. Excess requests
    /// QUEUE (they are not rejected on arrival) until `request_timeout` runs out.
    pub max_concurrent_requests: usize,
    /// Wall-clock budget for one request, queue wait included.
    pub request_timeout: std::time::Duration,
}

impl Default for HttpLimits {
    /// Conservative defaults, sized for the SMALLEST plausible deployment — a
    /// single modest instance, which is what someone who just added this crate
    /// is most likely running.
    ///
    /// They are deliberately not tuned for any particular operator: a default
    /// that assumes a large host would let a small one accept far more work than
    /// it can finish, turning a burst into a queue nobody drains. Both values are
    /// meant to be RAISED with evidence — see each field for what the evidence
    /// should be.
    fn default() -> Self {
        Self {
            // Sized against what is behind the routes, not against CPU count.
            // Every `/v1/*` request ends in blocking store calls, and the store is
            // ONE SQLite connection behind a mutex: past a few dozen in-flight
            // requests the extra ones only lengthen the queue at that same mutex,
            // so a higher number buys latency, not throughput.
            //
            // Raise it when measurement shows the store is NOT the constraint —
            // e.g. a workload dominated by the upstream round-trip rather than by
            // local writes. `examples/bench_store_concurrency.rs` measures where
            // your store saturates on your hardware.
            max_concurrent_requests: 64,
            // Must exceed the issuance service's own budget: `/v1/issue` waits on that
            // POST, so a shorter timeout here would abandon submissions the issuance service
            // was about to accept — and the outbox would then retry work that had
            // in fact succeeded. Raise it if your upstream is slower (a distant
            // region, a constrained link); lower it only if you know your upstream
            // is closer than this allows for.
            request_timeout: std::time::Duration::from_secs(30),
        }
    }
}

impl HttpLimits {
    /// Set the concurrency limit. Zero is rejected (it would wedge the server
    /// shut) and leaves the current value.
    pub fn with_max_concurrent_requests(mut self, n: usize) -> Self {
        if n > 0 {
            self.max_concurrent_requests = n;
        }
        self
    }

    /// Set the per-request budget. Zero is rejected and leaves the current value.
    pub fn with_request_timeout(mut self, d: std::time::Duration) -> Self {
        if !d.is_zero() {
            self.request_timeout = d;
        }
        self
    }

    /// Read the limits from environment variables under `prefix`, falling back
    /// to [`Self::default`] for anything unset, unparseable, or zero.
    ///
    /// Reads `{prefix}MAX_CONCURRENT_REQUESTS` and
    /// `{prefix}REQUEST_TIMEOUT_SECONDS`. The prefix is a parameter rather than a
    /// constant because the variable namespace belongs to whoever deploys this,
    /// not to this crate: an embedder passes its own (`"ACME_NODE_"`), and the
    /// bundled binary passes [`ENV_PREFIX`].
    ///
    /// A zero or unparseable value takes the default rather than disabling the
    /// limit: a concurrency limit of 0 would wedge the server shut, and that is
    /// never what an operator meant to type. It is silently ignored rather than
    /// fatal because backpressure settings must not be able to stop a node from
    /// booting.
    pub fn from_env_prefixed(prefix: &str) -> Self {
        let d = Self::default();
        let read = |suffix: &str| std::env::var(format!("{prefix}{suffix}")).ok();
        Self {
            max_concurrent_requests: read("MAX_CONCURRENT_REQUESTS")
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(d.max_concurrent_requests),
            request_timeout: read("REQUEST_TIMEOUT_SECONDS")
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|&n| n > 0)
                .map(std::time::Duration::from_secs)
                .unwrap_or(d.request_timeout),
        }
    }
}

/// Rules domains a deployment runs under that are not published, each with the
/// capacity-commitment TTL it fixes.
///
/// The node checks `expires_at == issued_at + ttl` before submitting, and it can
/// only do so for a domain whose TTL it knows. The published domains carry theirs
/// in the protocol core. A deployment that runs under a domain of its own — a
/// staging environment, a self-hosted system domain — declares it here, because
/// a domain that is not published cannot be compiled into a public binary.
///
/// The published table always answers first, and a published domain cannot be
/// declared here: configuration must never be able to change a TTL a verifier
/// enforces.
///
/// ```no_run
/// use certcrypt_node::DeploymentRules;
///
/// let rules = DeploymentRules::default()
///     .with_domain("rules/my-staging", 86_400)
///     .expect("a non-published domain with a non-zero TTL");
///
/// // Or from your own environment namespace.
/// let rules = DeploymentRules::from_env_prefixed("ACME_NODE_").expect("well-formed");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentRules {
    ttl_seconds: std::collections::BTreeMap<String, u32>,
}

impl DeploymentRules {
    /// Declare one domain and its TTL. Refuses a name that is not a rules domain,
    /// a zero TTL, and any domain the published table already knows.
    pub fn with_domain(mut self, rules_version: &str, ttl_seconds: u32) -> Result<Self, String> {
        if !rules_version.starts_with("rules/") || rules_version.len() == "rules/".len() {
            return Err(format!(
                "rules_version must be \"rules/<name>\", got {rules_version:?}"
            ));
        }
        if ttl_seconds == 0 {
            return Err(format!(
                "{rules_version}: the commitment TTL must be non-zero"
            ));
        }
        if capacity_artifacts::settlement::commitment_ttl_seconds_for(rules_version).is_some() {
            return Err(format!(
                "{rules_version} is a published rules domain; its TTL is not configurable"
            ));
        }
        self.ttl_seconds
            .insert(rules_version.to_string(), ttl_seconds);
        Ok(self)
    }

    /// Read `{prefix}DEPLOYMENT_RULES`: comma-separated `rules/<name>=<ttl_seconds>`
    /// entries. Unset or empty declares nothing, which is the correct default.
    ///
    /// Unlike [`HttpLimits::from_env_prefixed`], a malformed value is an error and
    /// not a fallback: ignoring it would start a node that refuses, at the first
    /// issue, every commitment the operator meant it to accept.
    pub fn from_env_prefixed(prefix: &str) -> Result<Self, String> {
        let var = format!("{prefix}DEPLOYMENT_RULES");
        let raw = std::env::var(&var).unwrap_or_default();
        let mut rules = Self::default();
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (domain, ttl) = entry
                .split_once('=')
                .ok_or_else(|| format!("{var}: {entry:?} is not rules/<name>=<ttl_seconds>"))?;
            let ttl: u32 = ttl
                .trim()
                .parse()
                .map_err(|_| format!("{var}: {entry:?} has a non-numeric TTL"))?;
            rules = rules
                .with_domain(domain.trim(), ttl)
                .map_err(|e| format!("{var}: {e}"))?;
        }
        Ok(rules)
    }

    /// The TTL for `rules_version`: the published table first, then this
    /// deployment's own domains. `None` MUST be treated as a refusal.
    pub fn commitment_ttl_seconds_for(&self, rules_version: &str) -> Option<u32> {
        capacity_artifacts::settlement::commitment_ttl_seconds_for(rules_version)
            .or_else(|| self.ttl_seconds.get(rules_version).copied())
    }
}

/// Environment-variable prefix used by the bundled `certcrypt-node` binary.
///
/// Exposed so an embedder can deliberately opt INTO the same variable names the
/// shipped binary uses (`HttpLimits::from_env_prefixed(ENV_PREFIX)`) rather than
/// having to guess them — and so that the binary has no configuration path that
/// is unavailable to anyone else.
pub const ENV_PREFIX: &str = "NODE_";

/// Build the node's HTTP surface with default limits. See [`router_with_limits`].
pub fn router(state: NodeState) -> Router {
    router_with_limits(state, HttpLimits::default())
}

/// Build the node's HTTP surface.
///
/// # Why `/health` sits outside the concurrency limit
///
/// The `/v1/*` routes carry the backpressure; `/health` is mounted on its own
/// router with only tracing. That asymmetry is the point: `/health` is what a
/// status monitor probes, and the monitor decides purely on the HTTP code. If a
/// probe had to queue for a slot — or got shed — a node that is merely FULL
/// would report as DOWN, the misdiagnosis that keeping store calls off the
/// executor exists to prevent. A liveness probe must never compete with
/// the traffic it is reporting on.
///
/// # Why queueing rather than load-shedding
///
/// `ConcurrencyLimitLayer` alone makes request n+1 WAIT for a slot;
/// `tower::load_shed` would reject it instantly instead. Queueing is the right
/// default here because the SDKs retry: shedding a brief burst would turn one
/// spike into a retry storm that amplifies it. `TimeoutLayer` is what keeps the
/// queue honest — a request that cannot get served inside the budget is cut
/// rather than left to hang, so the queue is bounded in TIME even though it is
/// unbounded in depth.
///
/// # Layer order
///
/// Layers apply bottom-up, so the effective order for an incoming request is:
/// trace → timeout → concurrency limit → handler. The timeout sits OUTSIDE the
/// limit deliberately: its budget must cover the queue wait, not just the
/// handler. Inside the limit it would only time out work already being served
/// and a request could still wait forever for a slot.
pub fn router_with_limits(state: NodeState, limits: HttpLimits) -> Router {
    let versioned = Router::new()
        .route("/v1/issue", post(issue))
        .route("/v1/activate", post(activate))
        .route("/v1/operations/:operation_id", get(get_operation))
        // By the capacity-evidence digest. Unlike the route above, this one does
        // NOT consult the local journal: the digest identifies the emission at the
        // issuance service, so a restarted node (or a different one) can still answer.
        .route(
            "/v1/emissions/by-commitment/:independence_ref",
            get(get_emission_by_commitment),
        )
        // Literal segment, so it can never be captured as an id by a
        // `/v1/emissions/:id`-shaped route added later.
        .route("/v1/emissions/unresolved", get(get_unresolved_emissions))
        .route("/v1/outbox/dead", get(get_dead_letters))
        .route(
            "/v1/outbox/dead/:request_id/redrive",
            post(redrive_dead_letter),
        )
        // Innermost: reads the body to hash it for the issuer proof, so it runs
        // only once a concurrency slot is held (a queued request holds no body
        // in memory).
        .layer(axum::middleware::from_fn(bind_request))
        // GLOBAL, not `ConcurrencyLimitLayer`. axum clones the inner service per
        // connection, and a plain `ConcurrencyLimitLayer` gives every clone its
        // OWN semaphore — so the cap becomes per-connection and N connections
        // admit N × limit requests, which is no cap at all. The global layer
        // shares one `Arc<Semaphore>` across every clone. Verified: with the
        // per-connection layer, 6 concurrent callers all ran at limit=1.
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
            limits.max_concurrent_requests,
        ))
        // tower-http's TimeoutLayer, not tower's: this one answers with an HTTP
        // status instead of a transport error, so a timed-out request reaches the
        // integrator's SDK as a retryable 503 rather than a dropped connection.
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            limits.request_timeout,
        ))
        // Outermost: a write refused for draining must not first queue for a
        // concurrency slot it will never use.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            drain_gate,
        ));

    Router::new()
        .route("/health", get(health))
        .merge(versioned)
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
}

/// Largest body the node reads: axum's own default for the JSON extractors,
/// which would refuse anything larger anyway.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Record the request an issuer proof must have been made for — host, method,
/// path and query, SHA3-256 of the body — as a [`crate::auth::RequestBinding`]
/// extension, and hand the handler the body it read. See the type for why the
/// proof is bound to the request.
async fn bind_request(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };
    let binding = crate::auth::RequestBinding {
        host: parts
            .headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        method: parts.method.as_str().to_string(),
        path_and_query: parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string()),
        body_sha3_hex: hex::encode(<sha3::Sha3_256 as sha3::Digest>::digest(&bytes)),
    };
    parts.extensions.insert(binding);
    next.run(axum::extract::Request::from_parts(
        parts,
        axum::body::Body::from(bytes),
    ))
    .await
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    /// `"ok"` when the store answered, `"down"` when it could not be read,
    /// `"draining"` while the node is shutting down. Never a hardcoded
    /// constant: it reports what was actually observed.
    status: &'static str,
    /// Aggregate outbox counts (operability). A non-zero `dead` means work is
    /// stuck and an operator must inspect `GET /v1/outbox/dead`.
    ///
    /// `None` — the field is OMITTED from the JSON — when the store could not be
    /// read. It must never be rendered as `{pending:0,dead:0}`: an empty outbox
    /// and an unreadable one are different facts, and conflating them would
    /// let a broken store look healthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    outbox: Option<crate::outbox::OutboxCounts>,
}

/// `GET /health` — liveness plus outbox operability counts. Public, aggregate
/// only (no ids/payloads, no per-issuer breakdown).
///
/// Returns **503 with `status:"down"`** when the store cannot be read, matching
/// the issuance service's own `/health`: a status monitor decides purely on the
/// HTTP code and never parses the body, so a `200` carrying `status:"down"`
/// would be recorded as `ok` and a monitor would paint green over a failure.
/// The distinction is load-bearing, not cosmetic.
///
/// The error detail is logged, never returned: this endpoint is public and
/// unauthenticated, so the body must not leak store paths or backend topology.
async fn health(State(state): State<NodeState>) -> Response {
    // Draining is neither up nor down: say which, so a monitor shows a restart
    // rather than an outage.
    if state.lifecycle.is_draining() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "draining",
                outbox: None,
            }),
        )
            .into_response();
    }
    // Off the executor: a store call from an async handler blocks a runtime
    // thread, and `/health` blocking is how a saturated node comes to look dead
    // to the monitor.
    let outbox = state.outbox.clone();
    let counts = match crate::blocking::store_call(move || outbox.counts()).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "health: outbox call did not complete");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "down",
                    outbox: None,
                }),
            )
                .into_response();
        }
    };
    match counts {
        Ok(counts) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok",
                outbox: Some(counts),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "health: outbox counts failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "down",
                    outbox: None,
                }),
            )
                .into_response()
        }
    }
}

/// One loose commitment the SDK emits. The SDK is thin: it signs only the
/// holder's `CapacityEvidence` (the one thing only the holder can do) and ships it
/// loose. The NODE is the builder. `operative` carries the integration's fixed
/// `(holder_id, pool_id)` — assigned by CERTCRYPT at onboarding, already in the SDK
/// config (`NodeClientOptions.pool_id`); the SDK relays it, it does not freely
/// declare it (a commitment for another pool is refused on submit).
#[derive(Debug, Deserialize, Serialize)]
struct LooseCommitment {
    /// The holder-signed zero-data commitment (the emission, projected).
    capacity_evidence: CapacityEvidence,
    /// Node→issuance-service-only cleartext context for capacity attribution (never reaches the
    /// offline verifier).
    operative: OperativeContext,
}

/// `issue([commitments])`: the SDK ships 1..N loose commitments it has on hand
/// (a batch import, a nightly job). The NODE wraps them into ONE `submission-set/1`
/// (envelope metadata + `submission_set_id` + transport — no key involved) and
/// submits it. All members MUST share issuer + authorization (the leaf grouping
/// constraint of `submission-set/1`): mono-issuer is given (one authenticated
/// issuer proof); mono-authorization is enforced by `assemble_submission_set`. This
/// is N-in-one-request (synchronous, no state) — NOT a time-window
/// accumulation, which the node does not do.
#[derive(Debug, Deserialize, Serialize)]
struct IssueRequest {
    /// Optional idempotency key (26-char ULID). If absent, the node generates
    /// one. Reusing it makes the upstream submission idempotent.
    #[serde(default)]
    request_id: Option<String>,
    /// The loose commitments to wrap into one submission-set (1..N, same issuer +
    /// authorization).
    commitments: Vec<LooseCommitment>,
    /// Issuer-elected settlement-window preference (close-tier). The node forwards
    /// it verbatim to the issuance service as `operation.settlement_preferences`; it is a
    /// CERTCRYPT-domain operational preference, NOT part of the submission-set or
    /// the proof. Absent → the issuance service resolves the catalog default.
    #[serde(default)]
    settlement_preferences: Option<SettlementPreferences>,
}

/// Issuer-elected settlement window profile + fallback (mirror of the issuance service's
/// `SettlementPreferences`). Node→issuance-service transport only.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct SettlementPreferences {
    window_profile: String,
    fallback_policy: String,
}

/// One node-local member result returned to the issuer. Each accepted member is
/// an autonomous fixation unit with its own node-local `operation_id`
/// (the key for `GET /v1/operations/{id}`).
#[derive(Debug, Serialize)]
struct MemberResult {
    /// Node-local operation id for this member (distinct from the upstream one).
    operation_id: String,
    /// The member's position in the submitted set — what the issuer maps the
    /// result back to.
    commitment_index: usize,
    state: OperationState,
}

impl From<crate::journaling::RecordedMember> for MemberResult {
    fn from(m: crate::journaling::RecordedMember) -> Self {
        Self {
            operation_id: m.operation_id,
            commitment_index: m.commitment_index,
            state: m.state,
        }
    }
}

#[derive(Debug, Serialize)]
struct IssueResponse {
    request_id: String,
    /// The issuance service's submission-set identity, when member evaluation was reached.
    /// Absent for a pre-evaluation rejection or a transport failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    submission_set_id: Option<String>,
    /// One result per submitted member (the per-member path). Empty when the
    /// whole request was rejected before member evaluation — see `state`.
    results: Vec<MemberResult>,
    /// A whole-request outcome, set ONLY when no per-member evaluation happened
    /// (pre-evaluation rejection or transport failure). Mutually exclusive with
    /// a non-empty `results`.
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<OperationState>,
    /// Signed operator receipt, if the node has an operator identity. The
    /// caller MAY keep it as proof that this operator processed the set, or
    /// discard it (it does not affect the verdict). One receipt per submit,
    /// bound by submission_set_id (not per member, not a linkable per-certificate stamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    operator_receipt: Option<OperatorReceipt>,
}

async fn issue(
    State(state): State<NodeState>,
    issuer: AuthedIssuer,
    Json(mut req): Json<IssueRequest>,
) -> Response {
    let request_id = req
        .request_id
        .unwrap_or_else(|| ulid::Ulid::new().to_string());

    // Everything checked before the upstream call is about the request itself:
    // it is answered 422 (nothing was sent, nothing journaled, nothing queued),
    // never 502 — a gateway error would tell the SDK to retry a request that
    // can only fail the same way.
    if req.commitments.is_empty() {
        return invalid_issue_response(
            request_id,
            "no_commitments",
            "issue requires at least one commitment".to_string(),
        );
    }
    // Defensive cap (anti-DoS, not protocol semantics).
    if req.commitments.len() > state.max_commitments_per_request {
        return invalid_issue_response(
            request_id,
            "too_many_commitments",
            format!(
                "too many commitments in one request: {} > cap {}",
                req.commitments.len(),
                state.max_commitments_per_request
            ),
        );
    }

    // COMMITMENT TTL — refuse a self-inflated window at the edge.
    //
    // `expires_at` must equal `issued_at + ttl(rules_version)`, the public rule of
    // the rules-domain the verifier enforces as COMMITMENT_TTL_VALID. Checked here
    // so an SDK that got it wrong learns at issuance, locally, instead of having
    // the issuance service accept and settle a certificate that no verifier will ever accept.
    //
    // AGAINST THE ARTIFACT'S OWN rules_version, not against one the node is pinned
    // to — the node has no rules-domain of its own and must not acquire one. It
    // carries traffic for every version in flight; tying it to one would force an
    // operator to run a node per live version, which with a six-month support
    // window is up to seven. This is a coherence check, not an authority one.
    //
    // Which is why it is NOT sufficient on its own: an issuer declaring a version
    // whose TTL is longer passes here and is caught by the issuance service, which does know its
    // domain. Same division as `operator.recognition` — the node presents, the issuance service
    // verifies. This one only spares the honest caller a round trip.
    for (index, c) in req.commitments.iter().enumerate() {
        let pc = &c.capacity_evidence.projected_commitment;
        let Some(ttl) = state
            .deployment_rules
            .commitment_ttl_seconds_for(&pc.rules_version)
        else {
            return invalid_issue_response(
                request_id,
                "unknown_commitment_ttl",
                format!(
                    "member at index {}: rules_version {} declares no commitment TTL",
                    index, pc.rules_version
                ),
            );
        };
        let issued = chrono::DateTime::parse_from_rfc3339(&pc.issued_at);
        let expires = chrono::DateTime::parse_from_rfc3339(&pc.expires_at);
        match (issued, expires) {
            (Ok(i), Ok(e)) => {
                let expected = i + chrono::Duration::seconds(i64::from(ttl));
                if e != expected {
                    return invalid_issue_response(
                        request_id,
                        "commitment_ttl_mismatch",
                        format!(
                            "member at index {}: expires_at must be issued_at + {ttl}s for {}, \
                             got {} (expected {})",
                            index,
                            pc.rules_version,
                            pc.expires_at,
                            expected.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                        ),
                    );
                }
            }
            _ => {
                return invalid_issue_response(
                    request_id,
                    "invalid_timestamp",
                    format!(
                        "member at index {}: issued_at/expires_at are not RFC 3339",
                        index
                    ),
                );
            }
        }
    }

    let scope = issuer.holder_key_set_root.clone();

    // The evidence must be the authenticated issuer's own. The
    // builder only checks that the members agree with EACH OTHER; without this
    // an issuer holding another issuer's signed evidence could carry it under
    // its own scope. Delegated transport, if it is ever needed, has to be
    // represented and authorized explicitly — not inferred from a valid proof.
    if let Some(index) = req.commitments.iter().position(|c| {
        c.capacity_evidence
            .projected_authorization
            .holder_key_set_root
            != scope
    }) {
        return invalid_issue_response(
            request_id,
            "evidence_not_of_issuer",
            format!(
                "member at index {index}: its capacity evidence is bound to another \
                 holder_key_set_root than the one this request authenticated with"
            ),
        );
    }

    // A request_id this issuer already used is answered from what the node
    // already holds for it, never by building a new set. Building
    // again stamps a new closure_time, so the same request_id would carry a
    // different submission_set_id: the service refuses that as a conflict, and
    // the client's retry after a lost response would turn an accepted submit
    // into a refusal. Still queued → resend the stored set, byte for byte. Already
    // answered → replay the journaled outcome.
    let settlement_json = req
        .settlement_preferences
        .as_ref()
        .and_then(|p| serde_json::to_string(p).ok());
    match prior_submit(&state, &scope, &request_id).await {
        Err(()) => return outbox_unavailable_response(request_id),
        Ok(Prior::None) => {}
        Ok(Prior::Queued(entry)) => {
            let Ok(stored) = serde_json::from_str::<SubmissionSetV1>(&entry.submission_set_json)
            else {
                return node_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    request_id,
                    "internal_error",
                    "the node could not read the set it holds for this request_id".to_string(),
                );
            };
            let asked: Vec<SubmissionSetCertificateV1> = req
                .commitments
                .into_iter()
                .map(|c| SubmissionSetCertificateV1 {
                    capacity_evidence: c.capacity_evidence,
                    operative: c.operative,
                })
                .collect();
            if stored.certificates != asked || settlement_json != entry.settlement_preferences {
                return idempotency_conflict_response(request_id);
            }
            let preferences = entry
                .settlement_preferences
                .as_deref()
                .and_then(|j| serde_json::from_str::<SettlementPreferences>(j).ok());
            return submit_and_journal(&state, &issuer, request_id, &stored, preferences).await;
        }
        Ok(Prior::Recorded(records)) => {
            return replay_recorded(request_id, records, req.commitments.len());
        }
    }

    // The node is the builder: wrap the loose commitments into ONE submission-set.
    // rules_version + system_root_fingerprint come from the evidence the holder
    // signed (the node does not re-declare them); closure_time is the node's
    // set-close clock. assemble_submission_set runs the construction hygiene
    // (all members share issuer + authorization, else it rejects) and computes the
    // transport submission_set_id — no key involved. This is N-in-one-request, not
    // a time-window accumulation.
    // Take the settlement preference out BEFORE moving `req.commitments` (a
    // partial move of `req` would make a later field access fail to compile).
    let settlement_preferences = req.settlement_preferences.take();
    let pa = &req.commitments[0].capacity_evidence.projected_authorization;
    let rules_version = pa.rules_version.clone();
    let system_root_fingerprint = pa.system_root_fingerprint.clone();
    let members: Vec<SubmissionMember> = req
        .commitments
        .into_iter()
        .map(|c| SubmissionMember {
            capacity_evidence: c.capacity_evidence,
            operative: c.operative,
        })
        .collect();
    // closure_time MUST be RFC 3339 second-precision (the issuance service rejects fractional
    // seconds; submission_set_id is computed over it, so it must match what the
    // verifier recomputes).
    use chrono::SubsecRound as _;
    let closure_time = chrono::Utc::now().trunc_subsecs(0);
    let submission_set = match assemble_submission_set(
        members,
        &rules_version,
        &system_root_fingerprint,
        closure_time,
    ) {
        Ok(s) => s,
        Err(e) => {
            return invalid_issue_response(
                request_id,
                "submission_set_invalid",
                format!("submission-set assembly failed: {e}"),
            );
        }
    };

    submit_and_journal(
        &state,
        &issuer,
        request_id,
        &submission_set,
        settlement_preferences,
    )
    .await
}

/// `POST /v1/activate` — issuer activation (OTP). Pure pass-through: the node
/// forwards the body verbatim to the issuance service's `/v1/activate` and relays the response.
///
/// NO issuer-auth proof is required here (and none can exist yet): activation is
/// precisely how the issuer OBTAINS its Level-1 binding — the credential every
/// OTHER request authenticates with. The authorization to activate is the one-time
/// activation CODE itself (high-entropy, single-use), which the issuance service validates and
/// TOFU-binds. Bootstrapping the credential cannot require presenting it. The node
/// neither parses nor persists the binding (non-custodian); it only transports.
async fn activate(State(state): State<NodeState>, Json(body): Json<serde_json::Value>) -> Response {
    match state.upstream.activate(&body).await {
        Ok(json) => (StatusCode::OK, Json(json)).into_response(),
        Err(crate::upstream::UpstreamError::Status {
            status,
            body,
            retry_after,
        }) => {
            let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            // Relay the issuance service's problem body verbatim (it is already an ApiProblem JSON),
            // and its Retry-After: activation has no outbox behind it, so the
            // issuer's SDK is the one that has to wait out a maintenance.
            let mut resp = match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(v) => (code, Json(v)).into_response(),
                Err(_) => (code, body).into_response(),
            };
            if let Some(d) = retry_after {
                if let Ok(v) = axum::http::HeaderValue::from_str(&d.as_secs().to_string()) {
                    resp.headers_mut()
                        .insert(axum::http::header::RETRY_AFTER, v);
                }
            }
            resp
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "upstream_error", "message": e.to_string() })),
        )
            .into_response(),
    }
}

/// Submit a submission_set upstream and journal the outcome under the issuer's scope.
/// Used by `/v1/issue` (the issuer builds+signs the submission_set in its SDK and posts
/// it; the node only transports).
async fn submit_and_journal(
    state: &NodeState,
    issuer: &AuthedIssuer,
    request_id: String,
    submission_set: &SubmissionSetV1,
    settlement_preferences: Option<SettlementPreferences>,
) -> Response {
    // A whole-request node-local operation id, used ONLY for outcomes that are
    // not per-member (a recognition failure before submit, a pre-evaluation
    // rejection, a transport/journal failure). Accepted members each get their
    // OWN node-local id below.
    let request_operation_id = format!("op_{}", ulid::Ulid::new());

    // Operator recognition is mandatory: the node MUST attach its
    // system-domain-signed credential plus a possession proof — the operator
    // key signs `request_id.submission_set_id`, binding possession to THIS
    // submit. The issuance service fails closed without it. A node started
    // without an operator key and/or credential cannot submit; that is the
    // node's own configuration, not the issuer's request, so it is answered 503
    // rather than sending a request the service will reject.
    let recognition = match (state.operator.as_ref(), state.operator_credential.as_ref()) {
        (Some(op), Some(cred)) => {
            let possession_msg = format!("{request_id}.{}", submission_set.submission_set_id);
            match op.sign_challenge(possession_msg.as_bytes()) {
                Ok(possession_b64) => crate::upstream::OperatorRecognitionProof {
                    credential: (**cred).clone(),
                    possession_b64,
                },
                Err(e) => {
                    tracing::error!(error = %e, "possession proof signing failed");
                    return node_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        request_id,
                        "internal_error",
                        "the node could not sign its operator possession proof".to_string(),
                    );
                }
            }
        }
        _ => {
            return node_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                "operator_not_configured",
                "node has no operator identity and/or recognition credential; \
                 operator recognition is mandatory, so it cannot submit"
                    .to_string(),
            );
        }
    };

    // OUTBOX: admit the signed set as Pending BEFORE the POST (durability). If
    // the node dies after this, the relay resubmits it (same request_id,
    // idempotent). We store the set VERBATIM — a retry never re-signs it.
    //
    // A set the node cannot make durable is REFUSED with 503 + Retry-After, not
    // sent on without a safety net: the node only takes custody of what it can
    // keep. The SDK still holds the signed set and resends it with the same
    // request_id, so the refusal costs a short wait, never an emission.
    let admitted = match serde_json::to_string(submission_set) {
        Ok(set_json) => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let entry = OutboxEntry {
                request_id: request_id.clone(),
                contract_id: issuer.holder_key_set_root.clone(),
                submission_set_json: set_json,
                state: OutboxState::Pending,
                attempts: 0,
                // NOT due yet. The POST below is still to happen, and an entry due
                // now would let the relay pick it up while that POST is in flight:
                // two concurrent submits of the same request_id, the loser refused
                // upstream on its idempotency key. The relay exists for the case where this handler
                // never records an outcome, so the entry only becomes due once the
                // inline POST cannot still be running: its whole budget plus a margin.
                // Both outcomes below overwrite this anyway.
                next_attempt_at_ms: now_ms
                    + i64::try_from(state.upstream.request_timeout().as_millis())
                        .unwrap_or(i64::MAX / 2)
                    + OUTBOX_INLINE_GRACE_MARGIN_MS,
                created_at_ms: now_ms,
                last_error: None,
                // Persist the issuer-elected window so a relay retry resolves the
                // SAME profile the issuer chose, not the catalog default. Serialized
                // to the issuance service's on-wire shape; a serialize failure just leaves it
                // None (retry falls back to default) rather than dropping the entry.
                settlement_preferences: settlement_preferences
                    .as_ref()
                    .and_then(|p| serde_json::to_string(p).ok()),
            };
            // Off the executor, like every other store touch. Idempotency rests
            // on `ON CONFLICT(contract_id, request_id) DO NOTHING`.
            let outbox = state.outbox.clone();
            match crate::blocking::store_call(move || outbox.admit(entry)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        Err(e) => Err(format!("submission set did not serialize: {e}")),
    };
    if let Err(e) = admitted {
        tracing::warn!(error = %e, "outbox admit failed; refusing the submit (503) rather than holding it without durability");
        return outbox_unavailable_response(request_id);
    }

    let response = state
        .upstream
        .submit_submission_set(
            &request_id,
            submission_set,
            recognition,
            settlement_preferences
                .as_ref()
                .map(|p| (p.window_profile.clone(), p.fallback_policy.clone())),
        )
        .await;

    // A definitive refusal (a 4xx other than 408/425/429): the service read the
    // request and said no, and the same bytes will get the same answer.
    let refusal = response.as_ref().err().and_then(|e| e.refusal_status());

    // `insufficient_capacity` consumes nothing, so while the set's commitments
    // are valid the node keeps it and submits it again (see
    // `crate::capacity_wait`): `Some((next attempt, waiting state))`.
    let capacity_wait = match &response {
        Ok(SubmitResponse::Flat(FlatOutcome::InsufficientCapacity { capacity })) => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let outbox = state.outbox.clone();
            let (s, r) = (issuer.holder_key_set_root.clone(), request_id.clone());
            // Waiting is counted from when the node first took the set.
            let since_ms = match crate::blocking::store_call(move || outbox.get(&s, &r)).await {
                Ok(Ok(Some(entry))) => entry.created_at_ms,
                _ => now_ms,
            };
            crate::capacity_wait::plan(submission_set, capacity, now_ms, since_ms)
        }
        _ => None,
    };

    // OUTBOX outcome: the service RESPONDED (PerMember, Flat, or a definitive
    // refusal) → the entry is done (per-member rejections are terminal, not
    // transport failures), but it is removed only once the journal holds the
    // outcome (see `confirmed` below). A capacity refusal inside its wait
    // window, and any other Err, leave it Pending for the relay. Best-effort
    // (`let _ =`): a failure to record the transition must not fail an
    // emission the service already accepted — the relay reconciles from the
    // row.
    let confirmed = !(response.is_err() && refusal.is_none()) && capacity_wait.is_none();
    if let Some((next, _)) = &capacity_wait {
        // Postponed, not failed: waiting for capacity spends no delivery attempt.
        let outbox = state.outbox.clone();
        let (scope, rid, next) = (
            issuer.holder_key_set_root.clone(),
            request_id.clone(),
            *next,
        );
        let _ = crate::blocking::store_call(move || {
            outbox.defer(&scope, &rid, next, "insufficient_capacity")
        })
        .await;
    }
    {
        let outbox = state.outbox.clone();
        let request_id = request_id.clone();
        let scope = issuer.holder_key_set_root.clone();
        match &response {
            Err(e) if refusal.is_none() => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                let err = e.to_string();
                match e.retry_after() {
                    // The service asked to be left alone (maintenance, rate
                    // limit): wait as long as it said, without counting an
                    // attempt.
                    Some(wait) => {
                        let next = now_ms + crate::relay::honoured_wait_ms(wait);
                        let _ = crate::blocking::store_call(move || {
                            outbox.defer(&scope, &request_id, next, &err)
                        })
                        .await;
                    }
                    // First relay retry soon; the relay applies backoff thereafter.
                    None => {
                        let next = now_ms + 1000;
                        let _ = crate::blocking::store_call(move || {
                            outbox.mark_retry(&scope, &request_id, next, &err)
                        })
                        .await;
                    }
                }
            }
            _ => {}
        }
    }

    // Operator receipt: if the node has an operator identity, sign that THIS
    // operator processed this submit (bound by submission_set_id, ONE per submit — not
    // per member, never a linkable per-certificate stamp). Opt-in / detachable;
    // a signing failure must not fail the operation (it's auxiliary), so we log
    // and proceed without it.
    let operator_receipt: Option<OperatorReceipt> = state.operator.as_ref().and_then(|op| {
        let issued_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        match op.issue_receipt(
            &submission_set.submission_set_id,
            &submission_set.system_id,
            &submission_set.rules_version,
            &issued_at,
        ) {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(error = %e, "operator receipt failed; proceeding without it");
                None
            }
        }
    });

    let settled_request_id = request_id.clone();
    let reply = match (response, refusal, capacity_wait) {
        // ---- Per-member path: one journal record + one result PER MEMBER ----
        (Ok(SubmitResponse::PerMember(set)), _, _) => {
            // Each member is an autonomous unit with its OWN node-local id — the
            // one this request already handed the issuer, if it handed one.
            let members = set
                .results
                .into_iter()
                .map(|m| crate::journaling::MemberOutcome {
                    commitment_index: m.commitment_index,
                    state: crate::journaling::member_state(m.status),
                })
                .collect();
            let recorded = crate::journaling::record_members(
                &state.store,
                // Scope comes from the authenticated credential, NEVER the body.
                &issuer.holder_key_set_root,
                &request_id,
                &set.submission_set_id,
                members,
                operator_receipt.clone(),
            )
            .await;
            match recorded {
                Ok(recorded) => (
                    StatusCode::OK,
                    Json(IssueResponse {
                        request_id,
                        submission_set_id: Some(set.submission_set_id),
                        results: recorded.into_iter().map(MemberResult::from).collect(),
                        state: None,
                        operator_receipt,
                    }),
                )
                    .into_response(),
                // A member was accepted upstream but we cannot record it. Surface
                // as a retryable 503 so the caller resends (idempotent via
                // request_id); the service deduplicates the resubmit.
                Err(e) => journal_unavailable_response(
                    request_id,
                    Some(set.submission_set_id),
                    format!("journal write failed: {e}"),
                ),
            }
        }

        // ---- Waiting for capacity: held, submitted again later ----
        // (Only ever set for an `insufficient_capacity` answer.)
        (_, _, Some((_, waiting))) => {
            // Members an earlier attempt left waiting carry the latest figures.
            let _ = crate::journaling::settle_waiting_records(
                &state.store,
                &issuer.holder_key_set_root,
                &request_id,
                waiting.clone(),
            )
            .await;
            accepted_for_retry_response(
                state,
                issuer,
                request_id,
                submission_set,
                &waiting,
                operator_receipt,
            )
            .await
        }

        // ---- Whole-request outcomes: one record, no per-member results ----
        (Ok(SubmitResponse::Flat(flat)), _, None) => {
            let state_val = match flat {
                FlatOutcome::Rejected {
                    reason_code,
                    message,
                    ..
                } => OperationState::PreEvaluationRejected {
                    reason_code,
                    message,
                },
                FlatOutcome::InsufficientCapacity { capacity } => {
                    OperationState::InsufficientCapacity { capacity }
                }
                FlatOutcome::Unknown => {
                    OperationState::submission_failed("upstream returned an unrecognized status")
                }
            };
            // Members an earlier attempt left waiting get the same answer.
            let _ = crate::journaling::settle_waiting_records(
                &state.store,
                &issuer.holder_key_set_root,
                &request_id,
                state_val.clone(),
            )
            .await;
            journal_whole_request(
                state,
                issuer,
                request_operation_id,
                request_id,
                state_val,
                operator_receipt,
            )
            .await
        }
        // ---- Definitive refusal: terminal, nothing queued ----
        (Err(e), Some(upstream_status), _) => {
            // The service refused the request itself. It was NOT accepted for
            // retry — the outbox entry is already gone — so the issuer must
            // learn now, with the service's status, rather than poll a record
            // that would never move. Members an earlier attempt left waiting
            // get the same answer.
            let state_val = OperationState::SubmissionFailed {
                error: e.to_string(),
                upstream_status: Some(upstream_status),
            };
            let _ = crate::journaling::settle_waiting_records(
                &state.store,
                &issuer.holder_key_set_root,
                &request_id,
                state_val.clone(),
            )
            .await;
            journal_whole_request(
                state,
                issuer,
                request_operation_id,
                request_id,
                state_val,
                operator_receipt,
            )
            .await
        }
        (Err(e), None, _) => {
            // The synchronous POST did not get an answer, but the set is durably
            // in the outbox and the relay WILL deliver it.
            let waiting = OperationState::AcceptedForRetry {
                error: e.to_string(),
                capacity: None,
            };
            accepted_for_retry_response(
                state,
                issuer,
                request_id,
                submission_set,
                &waiting,
                operator_receipt,
            )
            .await
        }
    };

    // The service answered and the journal holds the outcome: only now is the
    // outbox entry done. Removing it before the journal write would mean a
    // journal failure (answered 503, "resend") leaves nothing to resend but a
    // NEW set under the same request_id, which the service refuses as a conflict. Kept,
    // the entry is resent byte-identical — by the issuer's retry, which finds
    // it (see `prior_submit`), or by the relay once its grace has passed.
    if confirmed && reply.extensions().get::<JournalUnavailable>().is_none() {
        let outbox = state.outbox.clone();
        let scope = issuer.holder_key_set_root.clone();
        let (s2, r2) = (scope.clone(), settled_request_id.clone());
        let _ = crate::blocking::store_call(move || outbox.mark_submitted(&s2, &r2)).await;
        // Settles any whole-request `accepted_for_retry` record of this
        // request (one not recorded per member).
        let store = state.store.clone();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let _ = crate::blocking::store_call(move || {
            store.mark_request_resolved(&scope, &settled_request_id, now_ms)
        })
        .await;
    }
    reply
}

/// `202` for a set the outbox holds for a later attempt. Every member gets its
/// own `waiting` record NOW, so the issuer holds the ids the real outcomes will
/// be written to.
async fn accepted_for_retry_response(
    state: &NodeState,
    issuer: &AuthedIssuer,
    request_id: String,
    submission_set: &SubmissionSetV1,
    waiting: &OperationState,
    operator_receipt: Option<OperatorReceipt>,
) -> Response {
    let recorded = crate::journaling::record_waiting(
        &state.store,
        &issuer.holder_key_set_root,
        &request_id,
        &submission_set.submission_set_id,
        submission_set.certificates.len(),
        waiting,
        operator_receipt.clone(),
    )
    .await;
    match recorded {
        Ok(recorded) => (
            StatusCode::ACCEPTED,
            Json(IssueResponse {
                request_id,
                submission_set_id: Some(submission_set.submission_set_id.clone()),
                results: recorded.into_iter().map(MemberResult::from).collect(),
                state: None,
                operator_receipt,
            }),
        )
            .into_response(),
        Err(je) => {
            journal_unavailable_response(request_id, None, format!("journal write failed: {je}"))
        }
    }
}

/// How long an issuer is asked to wait when the outbox cannot take a set.
const OUTBOX_UNAVAILABLE_RETRY_AFTER_SECS: u64 = 5;

/// `503` + `Retry-After` for a submit the node could not make durable. Nothing
/// was sent upstream and nothing journaled; the body keeps the `IssueResponse`
/// shape so an SDK classifies it as the retryable `submission_failed`.
fn outbox_unavailable_response(request_id: String) -> Response {
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(IssueResponse {
            request_id,
            submission_set_id: None,
            results: Vec::new(),
            state: Some(OperationState::submission_failed(
                "node outbox unavailable; nothing was sent",
            )),
            operator_receipt: None,
        }),
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(OUTBOX_UNAVAILABLE_RETRY_AFTER_SECS),
    );
    resp
}

/// Journal a single whole-request outcome (no per-member evaluation happened)
/// and build the matching `IssueResponse`. Used for pre-evaluation rejections
/// and transport failures.
async fn journal_whole_request(
    state: &NodeState,
    issuer: &AuthedIssuer,
    operation_id: String,
    request_id: String,
    op_state: OperationState,
    operator_receipt: Option<OperatorReceipt>,
) -> Response {
    let record = OperationRecord {
        operation_id: operation_id.clone(),
        contract_id: issuer.holder_key_set_root.clone(),
        request_id: request_id.clone(),
        submission_set_id: None,
        commitment_index: None,
        state: op_state.clone(),
        operator_receipt: operator_receipt.clone(),
    };
    let store = state.store.clone();
    let put = crate::blocking::store_call(move || store.put(record))
        .await
        .unwrap_or_else(|e| {
            Err(crate::store::JournalError::Backend(format!(
                "journal call did not complete: {e}"
            )))
        });
    if let Err(e) = put {
        return journal_unavailable_response(
            request_id,
            None,
            format!("journal write failed: {e}"),
        );
    }
    (
        whole_request_status(&op_state),
        Json(IssueResponse {
            request_id,
            submission_set_id: None,
            results: Vec::new(),
            state: Some(op_state),
            operator_receipt,
        }),
    )
        .into_response()
}

/// The status a whole-request outcome is answered with — the first time and
/// when a retry of the same request_id replays it.
fn whole_request_status(op_state: &OperationState) -> StatusCode {
    match op_state {
        // The service refused the request: a client-class answer, so the SDK
        // stops instead of resending bytes that will be refused again.
        OperationState::SubmissionFailed {
            upstream_status: Some(_),
            ..
        } => StatusCode::UNPROCESSABLE_ENTITY,
        // The service answered with something the node could not use.
        OperationState::SubmissionFailed { .. } => StatusCode::BAD_GATEWAY,
        // Durably accepted, not yet delivered: 202 is the honest code (the issuer
        // polls for the eventual outcome) — distinct from a settled 200.
        OperationState::AcceptedForRetry { .. } => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    }
}

/// What the node already holds for a (scope, request_id) — see `issue`.
enum Prior {
    None,
    /// The set is still in the outbox (pending or dead-lettered).
    Queued(OutboxEntry),
    /// The service answered and the journal holds the outcome.
    Recorded(Vec<OperationRecord>),
}

/// Look the request up, outbox first: an entry there is the set to resend,
/// whatever the journal says. `Err` when either store cannot be read — the
/// caller refuses with 503 rather than guess and risk a second set.
async fn prior_submit(state: &NodeState, scope: &str, request_id: &str) -> Result<Prior, ()> {
    let outbox = state.outbox.clone();
    let (s, r) = (scope.to_string(), request_id.to_string());
    match crate::blocking::store_call(move || outbox.get(&s, &r)).await {
        Ok(Ok(Some(entry))) => return Ok(Prior::Queued(entry)),
        Ok(Ok(None)) => {}
        _ => return Err(()),
    }
    let store = state.store.clone();
    let (s, r) = (scope.to_string(), request_id.to_string());
    match crate::blocking::store_call(move || store.list_by_request(&s, &r)).await {
        Ok(Ok(records)) if records.is_empty() => Ok(Prior::None),
        Ok(Ok(records)) => Ok(Prior::Recorded(records)),
        _ => Err(()),
    }
}

/// Answer a retried request_id from its journaled outcome, as the first answer
/// was. The journal keeps outcomes, not sets, so the only check against reuse
/// with different content is the member count; a different count is a conflict.
fn replay_recorded(request_id: String, records: Vec<OperationRecord>, asked: usize) -> Response {
    let operator_receipt = records.iter().find_map(|r| r.operator_receipt.clone());
    let (mut members, whole): (Vec<_>, Vec<_>) = records
        .into_iter()
        .partition(|r| r.commitment_index.is_some());
    if members.is_empty() {
        // Whole-request outcome. Should there be several records (one per
        // attempt), any of them carries the same answer.
        let Some(record) = whole.into_iter().next() else {
            return idempotency_conflict_response(request_id);
        };
        return (
            whole_request_status(&record.state),
            Json(IssueResponse {
                request_id,
                submission_set_id: None,
                results: Vec::new(),
                state: Some(record.state),
                operator_receipt,
            }),
        )
            .into_response();
    }
    if members.len() != asked {
        return idempotency_conflict_response(request_id);
    }
    members.sort_by_key(|r| r.commitment_index);
    let waiting = members
        .iter()
        .any(|r| matches!(r.state, OperationState::AcceptedForRetry { .. }));
    let submission_set_id = members[0].submission_set_id.clone();
    (
        if waiting {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        Json(IssueResponse {
            request_id,
            submission_set_id,
            results: members
                .into_iter()
                .map(|r| MemberResult {
                    operation_id: r.operation_id,
                    commitment_index: r.commitment_index.unwrap_or_default(),
                    state: r.state,
                })
                .collect(),
            state: None,
            operator_receipt,
        }),
    )
        .into_response()
}

/// `409` for a request_id this issuer already used with different content.
/// Never sent upstream: the node answers from what it holds.
fn idempotency_conflict_response(request_id: String) -> Response {
    node_error_response(
        StatusCode::CONFLICT,
        request_id,
        "idempotency_conflict",
        "this request_id was already used with a different set of commitments or \
         settlement preferences; use a new request_id for a new request"
            .to_string(),
    )
}

/// Marks a `journal_unavailable_response`: the outbox entry is kept for it.
#[derive(Clone, Copy)]
struct JournalUnavailable;

/// How long an issuer is asked to wait when the journal cannot record an outcome.
const JOURNAL_UNAVAILABLE_RETRY_AFTER_SECS: u64 = 5;

/// `503` + `Retry-After` for a submit whose outcome the node could not record.
/// A node-local failure, not an upstream one: resending with the same
/// `request_id` is safe (the service deduplicates it) and gets the outcome
/// recorded. The body keeps the `IssueResponse` shape.
fn journal_unavailable_response(
    request_id: String,
    submission_set_id: Option<String>,
    error: String,
) -> Response {
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(IssueResponse {
            request_id,
            submission_set_id,
            results: Vec::new(),
            state: Some(OperationState::submission_failed(error)),
            operator_receipt: None,
        }),
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from(JOURNAL_UNAVAILABLE_RETRY_AFTER_SECS),
    );
    resp.extensions_mut().insert(JournalUnavailable);
    resp
}

/// `422` for an issue request the node refuses before submitting it: the
/// request itself is wrong (no members, too many, a TTL that does not match
/// its `rules_version`, timestamps that are not RFC 3339, members that cannot
/// form one set). Nothing was sent, journaled or queued, and resending the
/// same request gets the same answer. Same `{error, message}` body as the
/// node's other JSON errors, plus the `request_id` the caller can correlate.
fn invalid_issue_response(request_id: String, code: &'static str, message: String) -> Response {
    node_error_response(StatusCode::UNPROCESSABLE_ENTITY, request_id, code, message)
}

/// A JSON `{error, message, request_id}` answer for `/v1/issue`.
fn node_error_response(
    status: StatusCode,
    request_id: String,
    code: &'static str,
    message: String,
) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": code,
            "message": message,
            "request_id": request_id,
        })),
    )
        .into_response()
}

/// PRIVATE signing-domain separator for the issuer↔node↔issuance-service read
/// channel — NOT a public protocol identifier: no verifier evaluates it and no
/// conforming implementation has to reproduce it. The issuance service verifies
/// the exact same string, so the two MUST stay in step.
const READ_DOMAIN: &str = "certcrypt:read:2";

/// The message both halves of a read sign: the issuer's per-read challenge and the
/// resource. The challenge is what makes a read single-use at the issuance service:
/// a node that relays the issuer's half cannot keep it and read again on its own.
fn read_message(challenge: &str, resource: &str) -> String {
    format!("{READ_DOMAIN}|{challenge}|{resource}")
}

/// The challenge the issuer minted for this read, taken from its half as relayed.
/// The node reads it only to sign the same message; it never checks it — the
/// issuance service does, and spends it.
fn issuer_read_challenge(issuer_read: &str) -> Option<String> {
    let json = base64::engine::general_purpose::STANDARD
        .decode(issuer_read.trim().as_bytes())
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&json).ok()?;
    v.get("challenge")?.as_str().map(str::to_owned)
}

/// Build the node's half of a read chain over `resource`, under the challenge in
/// the issuer's half.
///
/// ONE function for every read route, deliberately: the two halves must cover the
/// byte-identical message, and the way that breaks is someone building the string
/// slightly differently at a second call site. Getting it wrong is SILENT — the
/// issuance service rejects one half, reconciliation falls back to the local
/// record, and the issuer polls a stale state forever while the operation is
/// already settled upstream.
///
/// `resource` is passed through verbatim; this never normalizes it. The issuer
/// signed some exact string, and reformatting it here would produce two signatures
/// over different messages.
///
/// Returns `None` when the node has no operator identity or credential, or the
/// issuer sent no half with a challenge — it then relays what it has, and the
/// issuance service refuses, which is the correct fail-closed answer.
fn build_operator_read_proof(
    state: &NodeState,
    issuer_read: Option<&str>,
    resource: &str,
) -> Option<String> {
    let op = state.operator.as_ref()?;
    let credential = state.operator_credential.as_ref()?;
    let msg = read_message(&issuer_read_challenge(issuer_read?)?, resource);
    let sig = op.sign_challenge(msg.as_bytes()).ok()?;
    let proof = serde_json::json!({
        "credential": credential.as_ref(),
        "possession_b64": sig,
    });
    Some(base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&proof).ok()?))
}

/// Read one emission by the digest of the capacity evidence that produced it.
///
/// PURE RELAY, and deliberately so. The node holds nothing this lookup needs: the
/// digest is the ISSUER's identifier — recomputed from evidence it signed — and
/// the record lives at the issuance service. So there is no journal read, no local id to
/// translate, and nothing for a restarted node to have lost.
///
/// That is the point of the route. A node's operation id lives only in that
/// node's journal, so an issuer that restarts its node with an in-memory journal,
/// or moves to another node, loses the ability to ask about emissions still in
/// flight. The digest does not have that problem.
///
/// The read chain is untouched: the issuer's proof is relayed verbatim and the
/// node adds its own over the SAME resource. A node cannot act on an emission its
/// issuer did not ask about, which is what both halves together enforce.
async fn get_emission_by_commitment(
    State(state): State<NodeState>,
    _issuer: AuthedIssuer,
    headers: axum::http::HeaderMap,
    Path(independence_ref): Path<String>,
) -> Response {
    let issuer_read = headers
        .get("x-certcrypt-issuer-read")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let operator_read =
        build_operator_read_proof(&state, issuer_read.as_deref(), &independence_ref);

    match state
        .upstream
        .get_emission_by_commitment(
            &independence_ref,
            issuer_read.as_deref(),
            operator_read.as_deref(),
        )
        .await
    {
        Ok(Some(body)) => (StatusCode::OK, Json(body)).into_response(),
        // No local fallback HERE, unlike the operation route: this lookup has no
        // local record to fall back TO, so a miss is a miss and says so.
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "not_found",
                "message": "no emission for this capacity-evidence digest",
            })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(independence_ref, error = %e, "by-commitment read failed upstream");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "upstream_unavailable",
                    "message": "the issuance service did not answer",
                })),
            )
                .into_response()
        }
    }
}

async fn get_operation(
    State(state): State<NodeState>,
    issuer: AuthedIssuer,
    headers: axum::http::HeaderMap,
    Path(operation_id): Path<String>,
) -> Response {
    // Scope comes from the authenticated credential. A cross-scope id resolves
    // to None (404), indistinguishable from "not found" — one issuer never
    // learns whether another issuer's operation exists.
    let store = state.store.clone();
    let scope = issuer.holder_key_set_root.clone();
    let op_id = operation_id.clone();
    let fetched = match crate::blocking::store_call(move || store.get_scoped(&scope, &op_id)).await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "get_operation: journal call did not complete");
            return (StatusCode::SERVICE_UNAVAILABLE, "journal unavailable").into_response();
        }
    };
    let record = match fetched {
        Ok(Some(record)) => record,
        Ok(None) => return (StatusCode::NOT_FOUND, "operation not found").into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("journal read failed: {e}"),
            )
                .into_response()
        }
    };

    // Reconcile a NON-TERMINAL local record with the issuance service. The node's journal only
    // records the submit-time outcome (`Accepted`); the terminal
    // `independent_ready` transition + the PoI/settlement material are finalized
    // ASYNCHRONOUSLY by the issuance service. Without this, an accepted member would
    // sit at `accepted` in the node forever and the issuer's SDK (which only talks
    // to the node) would never observe `independent_ready` — the loop the issuer
    // polls would never close.
    //
    // This is a live pass-through, NOT custody: the issuance service's fresh body is forwarded
    // to the issuer verbatim and never persisted here (the node stays a
    // non-custodian). The scope was already enforced by `get_scoped` above; we
    // only proxy an id that belongs to the authenticated contract.
    if let OperationState::Accepted {
        upstream_operation_id,
    } = &record.state
    {
        // Assemble the read chain for the issuance service. The ISSUER's half is whatever the
        // SDK presented, relayed untouched: the node cannot produce it and must
        // not rewrite it — it is the issuance service's evidence of whose data this is. The
        // node adds its OWN half, proving a recognized operator carried the
        // request.
        //
        // BOTH HALVES COVER THE UPSTREAM ID — the one the issuance service routes on. The
        // issuer can sign it because the node reported it at submit
        // (`upstream_operation_id` in the member's state), so there is exactly one
        // identifier in play and no local-to-upstream mapping for anyone to
        // declare or to trust.
        //
        // Getting this wrong is silent: the two halves end up over different
        // messages, the issuance service rejects one, and a failed reconciliation
        // falls back to the local record — so the issuer polls `accepted` forever
        // while its operation sits settled upstream.
        let issuer_read = headers
            .get("x-certcrypt-issuer-read")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let operator_read =
            build_operator_read_proof(&state, issuer_read.as_deref(), upstream_operation_id);

        // `if let` rather than `match`: the other arm — the service has no view yet (404)
        // or a transport error — is a deliberate no-op. Falling through to the
        // local record is what keeps the issuer polling with its last-known
        // state; a reconciliation failure MUST NOT hide the accepted state.
        // The no-op arm is deliberate, but it must not be INVISIBLE: a silent
        // fallback is indistinguishable from "the issuance service says accepted", and that is
        // what would make this failure slow to notice.
        let reconciled = state
            .upstream
            .get_operation(
                upstream_operation_id,
                issuer_read.as_deref(),
                operator_read.as_deref(),
            )
            .await;
        match &reconciled {
            Ok(Some(_)) => {}
            Ok(None) => tracing::debug!(
                upstream_operation_id,
                "reconcile: the issuance service has no view of this attempt yet; serving the local record"
            ),
            Err(e) => tracing::warn!(
                upstream_operation_id,
                error = %e,
                "reconcile FAILED; serving the local record — the issuer will keep \
                 polling its last-known state even if the attempt is already settled \
                 upstream"
            ),
        }
        if let Ok(Some(api_body)) = reconciled {
            // Terminal upstream: start this record's retention clock. Only the
            // first observation counts (the store keeps it), so polling a
            // settled operation again never extends its life. Best-effort: a
            // missed stamp keeps the record longer, never shorter.
            let upstream_terminal = api_body
                .get("status")
                .and_then(|s| s.as_str())
                .is_some_and(|s| crate::store::UPSTREAM_TERMINAL_STATUSES.contains(&s));
            if upstream_terminal {
                let store = state.store.clone();
                let scope = issuer.holder_key_set_root.clone();
                let op_id = operation_id.clone();
                let now_ms = chrono::Utc::now().timestamp_millis();
                let _ = crate::blocking::store_call(move || {
                    store.mark_terminal(&scope, &op_id, now_ms)
                })
                .await;
            }
            {
                // Forward the issuance service's authoritative view (status, and when terminal
                // the `independence_proof` + `settlement_material`) to the issuer.
                return (StatusCode::OK, Json(api_body)).into_response();
            }
        }
    }

    (StatusCode::OK, Json(record)).into_response()
}

#[derive(Debug, Deserialize)]
struct UnresolvedQuery {
    /// RFC3339, relayed VERBATIM. Never parsed or reformatted here: the issuer
    /// signed this exact string, and normalizing it would leave the two halves of
    /// the chain covering different messages.
    since: String,
    limit: Option<u32>,
}

/// `GET /v1/emissions/unresolved` — pure proxy of the issuance service's issuer-facing
/// enumeration.
///
/// WHY THE NODE CARRIES THIS. The SDK only ever talks to the node, so a reconciler
/// that lost its handles reaches the issuance service through here or not at all. And it cannot
/// use `/v1/operations/{id}`: that route needs an id, and the id died with the
/// handle.
///
/// PROXY, NOT PARTICIPANT. The node relays the issuer's half untouched, adds its
/// own over the SAME resource, and forwards the answer. It never inspects the
/// scope: which integration this resolves to is decided upstream from the PROVEN
/// key-set root, and `holder_id`/`pool_id` never cross THIS wire in either
/// direction. (Scoped to this proxy route only — on the submit path they do:
/// see `OperativeContext` in the `/v1/issue` handler above.)
///
/// The node's half authorizes nothing on its own. The issuance service verifies the ISSUER
/// first and refuses before doing any work on the node's behalf, so signing a
/// resource the caller supplied grants no power the caller did not already have.
///
/// Live pass-through, NOT custody: nothing here is persisted.
async fn get_unresolved_emissions(
    State(state): State<NodeState>,
    _issuer: AuthedIssuer,
    headers: axum::http::HeaderMap,
    Query(q): Query<UnresolvedQuery>,
) -> Response {
    // The issuer's half, relayed as presented. The node cannot mint it (it holds
    // no leaf of that key set) and must not rewrite it: it is the issuance service's evidence
    // of WHOSE data this is.
    let issuer_read = headers
        .get("x-certcrypt-issuer-read")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // BOTH halves cover the byte-identical resource. `q.since` goes in exactly as
    // the issuer wrote it — see build_operator_read_proof for why normalizing is
    // the silent way to break this.
    let resource = format!("emissions:unresolved:{}", q.since);
    let operator_read = build_operator_read_proof(&state, issuer_read.as_deref(), &resource);

    match state
        .upstream
        .list_unresolved_emissions(
            &q.since,
            q.limit,
            issuer_read.as_deref(),
            operator_read.as_deref(),
        )
        .await
    {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        // No local fallback, unlike the operation read: there is no local answer to
        // "what do I have open?" that could stand in for the issuance service's. Surfacing the
        // failure beats an empty list, which a reconciler would read as "nothing
        // pending" and act on by re-emitting.
        Err(e) => {
            let (status, detail) = match &e {
                crate::upstream::UpstreamError::Status { status, .. } => (
                    StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY),
                    "upstream refused the read",
                ),
                _ => (StatusCode::BAD_GATEWAY, "upstream unreachable"),
            };
            (status, Json(serde_json::json!({ "error": detail }))).into_response()
        }
    }
}

/// One dead-lettered submission, as exposed to the issuer. Zero-data: NEVER the
/// stored `submission_set_json` (the projected commitments) — only the delivery
/// metadata needed to diagnose and decide on a manual replay.
#[derive(Debug, Serialize)]
struct DeadLetter {
    request_id: String,
    attempts: u32,
    created_at_ms: i64,
    last_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeadLetterList {
    /// Dead entries for THIS issuer's scope. Empty list, not 404, when none —
    /// "no stuck work" is a first-class healthy answer the issuer can poll for.
    dead: Vec<DeadLetter>,
}

/// `GET /v1/outbox/dead` — the issuer's window onto submissions the node set
/// aside: refused by the issuance service during background delivery, or out
/// of retries. Stuck work must be visible, never silently dropped. Scoped by
/// the authenticated credential; one issuer never sees another's dead-letters.
async fn get_dead_letters(State(state): State<NodeState>, issuer: AuthedIssuer) -> Response {
    let outbox = state.outbox.clone();
    let scope = issuer.holder_key_set_root.clone();
    let listed = match crate::blocking::store_call(move || outbox.list_dead(&scope)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "dead-letters: outbox call did not complete");
            return (StatusCode::SERVICE_UNAVAILABLE, "outbox unavailable").into_response();
        }
    };
    match listed {
        Ok(entries) => {
            let dead = entries
                .into_iter()
                .map(|e| DeadLetter {
                    request_id: e.request_id,
                    attempts: e.attempts,
                    created_at_ms: e.created_at_ms,
                    last_error: e.last_error,
                })
                .collect();
            (StatusCode::OK, Json(DeadLetterList { dead })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("outbox read failed: {e}"),
        )
            .into_response(),
    }
}

/// `POST /v1/outbox/dead/{request_id}/redrive` — put one of THIS issuer's
/// dead-lettered submissions back in the delivery queue with a fresh attempt
/// budget. For the failures that do dead-letter (a refusal that was not about
/// reachability — a credential the operator has since fixed, say). Scoped like
/// the listing: another issuer's entry answers 404, exactly like a missing one.
/// The stored set is resent verbatim; nothing is re-signed.
async fn redrive_dead_letter(
    State(state): State<NodeState>,
    issuer: AuthedIssuer,
    Path(request_id): Path<String>,
) -> Response {
    let outbox = state.outbox.clone();
    let scope = issuer.holder_key_set_root.clone();
    let rid = request_id.clone();
    let now_ms = chrono::Utc::now().timestamp_millis();
    match crate::blocking::store_call(move || outbox.redrive(&scope, &rid, now_ms)).await {
        Ok(Ok(true)) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "request_id": request_id, "state": "pending" })),
        )
            .into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            "no dead-lettered submission with that id",
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("outbox write failed: {e}"),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "redrive: outbox call did not complete");
            (StatusCode::SERVICE_UNAVAILABLE, "outbox unavailable").into_response()
        }
    }
}

#[cfg(test)]
mod deployment_rules_tests {
    use super::DeploymentRules;

    #[test]
    fn published_domains_resolve_without_configuration() {
        let rules = DeploymentRules::default();
        assert_eq!(
            rules.commitment_ttl_seconds_for("rules/2026-01"),
            Some(86_400)
        );
        assert_eq!(rules.commitment_ttl_seconds_for("rules/my-staging"), None);
    }

    #[test]
    fn a_declared_domain_resolves_after_the_published_table() {
        let rules = DeploymentRules::default()
            .with_domain("rules/my-staging", 3_600)
            .unwrap();
        assert_eq!(
            rules.commitment_ttl_seconds_for("rules/my-staging"),
            Some(3_600)
        );
        assert_eq!(
            rules.commitment_ttl_seconds_for("rules/2026-01"),
            Some(86_400)
        );
    }

    #[test]
    fn a_published_domain_cannot_be_redeclared() {
        // Otherwise configuration could widen a window a verifier enforces.
        assert!(DeploymentRules::default()
            .with_domain("rules/2026-01", 2_592_000)
            .is_err());
    }

    #[test]
    fn malformed_declarations_are_refused() {
        assert!(DeploymentRules::default()
            .with_domain("staging", 60)
            .is_err());
        assert!(DeploymentRules::default()
            .with_domain("rules/", 60)
            .is_err());
        assert!(DeploymentRules::default()
            .with_domain("rules/x", 0)
            .is_err());
    }

    #[test]
    fn environment_parsing_is_strict() {
        // A unique prefix per case: tests share one process environment.
        std::env::set_var("DRT_OK_DEPLOYMENT_RULES", " rules/a=60 , rules/b=120 ");
        let rules = DeploymentRules::from_env_prefixed("DRT_OK_").unwrap();
        assert_eq!(rules.commitment_ttl_seconds_for("rules/a"), Some(60));
        assert_eq!(rules.commitment_ttl_seconds_for("rules/b"), Some(120));

        assert_eq!(
            DeploymentRules::from_env_prefixed("DRT_UNSET_").unwrap(),
            DeploymentRules::default()
        );

        std::env::set_var("DRT_BAD_DEPLOYMENT_RULES", "rules/a");
        assert!(DeploymentRules::from_env_prefixed("DRT_BAD_").is_err());
        std::env::set_var("DRT_NAN_DEPLOYMENT_RULES", "rules/a=soon");
        assert!(DeploymentRules::from_env_prefixed("DRT_NAN_").is_err());
    }
}

#[cfg(test)]
mod read_chain_tests {
    //! The service builds `certcrypt:read:2|<challenge>|emissions:unresolved:<since>`
    //! and the node must produce the byte-identical string. Two halves of one
    //! contract, and when it breaks it breaks SILENTLY: one half is rejected and
    //! the issuer polls a stale state forever.
    use super::{issuer_read_challenge, read_message};
    use base64::Engine as _;

    fn resource_for(since: &str) -> String {
        format!("emissions:unresolved:{since}")
    }

    #[test]
    fn resource_matches_the_service_prefix() {
        // Mirrors the resource prefix the issuance service verifies.
        assert_eq!(
            resource_for("2026-08-24T09:00:00Z"),
            "emissions:unresolved:2026-08-24T09:00:00Z"
        );
    }

    #[test]
    fn since_is_relayed_verbatim_offsets_included() {
        // The issuer may legitimately sign a non-UTC offset. Normalizing it to Z
        // here would sign a DIFFERENT message than the issuer did.
        let raw = "2026-08-24T11:00:00+02:00";
        assert!(resource_for(raw).ends_with(raw));
    }

    #[test]
    fn signed_message_is_domain_pipe_challenge_pipe_resource() {
        let msg = read_message("1761552000000.abc", &resource_for("2026-08-24T09:00:00Z"));
        assert_eq!(
            msg,
            "certcrypt:read:2|1761552000000.abc|emissions:unresolved:2026-08-24T09:00:00Z"
        );
    }

    #[test]
    fn the_challenge_is_taken_from_the_issuer_half_as_relayed() {
        let half = base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({
                "possession_b64": "x",
                "challenge": "1761552000000.abc",
            }))
            .unwrap(),
        );
        assert_eq!(
            issuer_read_challenge(&half).as_deref(),
            Some("1761552000000.abc")
        );
        // A half without a challenge: the node signs nothing, the service refuses.
        let bare = base64::engine::general_purpose::STANDARD.encode(br#"{"possession_b64":"x"}"#);
        assert_eq!(issuer_read_challenge(&bare), None);
        assert_eq!(issuer_read_challenge("not base64!"), None);
    }

    #[test]
    fn enumeration_resource_cannot_collide_with_an_operation_id() {
        // An operation read signs a bare ULID. The prefix keeps a signature
        // captured for one shape from ever being valid for the other.
        let enumeration = resource_for("2026-08-24T09:00:00Z");
        assert!(enumeration.contains(':'));
        assert!(!enumeration.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
