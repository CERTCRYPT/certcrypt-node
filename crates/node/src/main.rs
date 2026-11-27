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

//! `certcrypt-node` binary entrypoint.
//!
//! Configuration via environment (there is no config file), among others:
//! - `CERTCRYPT_API_URL` — the explicit issuance service for this environment
//! - `NODE_BIND_ADDR` — where this node listens (default `127.0.0.1:8080`)
//! - `NODE_JOURNAL` (default `node-journal.sqlite`; `:memory:` for an ephemeral
//!   in-SQLite DB, `memory` for the pure in-process journal)
//! - `NODE_JOURNAL_RETENTION_DAYS` — how long terminal operation records are
//!   kept (default and minimum 30; a lower or unparseable value refuses to boot)
//! - `NODE_RESTART_RETRY_AFTER_SECS` — the `Retry-After` announced to SDKs
//!   while the node drains for a restart (default 10)
//! - `NODE_SHUTDOWN_DRAIN_SECS` — how long it drains before closing its port
//!   (default 3)
//! - `CERTCRYPT_NODE_OPERATOR_DOMAIN` — optional host name to associate with
//!   the operator key (operator.domain-binding/1); see `domain_binding`
//! - `NODE_DOMAIN_BINDING_STATE` (default `node-domain-binding.json`) and
//!   `NODE_WELL_KNOWN_FILE` (default `certcrypt-node.json`, the file to serve at
//!   `https://<host>/.well-known/certcrypt-node.json`)
//! - `NODE_SERVE_WELL_KNOWN` — `1` to have the node answer that path itself,
//!   when its own HTTPS front end is the declared host (off by default)
//! - `RUST_LOG` (default `info`)
//!
//! Commands, with the same environment (only `CERTCRYPT_API_URL`, the operator
//! key and, for `rebind`, the credential and the domain are needed):
//! - `certcrypt-node unbind <host>` — withdraw the association with a host
//! - `certcrypt-node rebind` — sign a new `bind` for the configured host now
//!
//! There is deliberately no upstream default: silently crossing from a dev or
//! private deployment into the public service would be a configuration error.

use std::{path::Path, sync::Arc, time::Duration};

use certcrypt_node::auth::IssuerVerifier;
use certcrypt_node::http::{DeploymentRules, HttpLimits, Lifecycle, NodeState};
use certcrypt_node::outbox::{MemoryOutbox, OutboxStore, SqliteOutbox};
use certcrypt_node::relay::Relay;
use certcrypt_node::retention::{RetentionPolicy, RetentionSweeper};
use certcrypt_node::sqlite_journal::SqliteJournal;
use certcrypt_node::store::{JournalStore, MemoryJournal};
use certcrypt_node::upstream::UpstreamClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The fmt output on stdout, plus the ring GET /ops?logs=N reads.
    let log_ring = certcrypt_node::ops::init_tracing("info");

    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        return run_domain_command(&args).await;
    }

    // Read first, before any store is opened: a retention the operator asked
    // for and did not get is a broken promise to issuers, so a bad value stops
    // the boot instead of falling back.
    let retention = RetentionPolicy::from_env_prefixed(certcrypt_node::http::ENV_PREFIX)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Same reason: a domain the operator declared and the node silently dropped
    // would refuse, at the first issue, every commitment meant to pass.
    let deployment_rules = DeploymentRules::from_env_prefixed(certcrypt_node::http::ENV_PREFIX)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let domain_binding = certcrypt_node::domain_binding::DomainBindingConfig::from_env()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let bind_addr =
        std::env::var("NODE_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let api_url = std::env::var("CERTCRYPT_API_URL")
        .map_err(|_| anyhow::anyhow!("CERTCRYPT_API_URL must be set explicitly"))?;

    // Journal backend: SQLite (default, durable, single file) or the pure
    // in-memory journal. Scope partitioning lives in the trait, so behavior is
    // identical either way.
    let journal_cfg =
        std::env::var("NODE_JOURNAL").unwrap_or_else(|_| "node-journal.sqlite".to_string());
    let store: Arc<dyn JournalStore> = if journal_cfg == "memory" {
        Arc::new(MemoryJournal::new())
    } else {
        Arc::new(SqliteJournal::open(&journal_cfg)?)
    };

    // Outbox backend (durable submit-retry): own SQLite file by default, separate
    // from the journal (outbox = in-flight delivery state, purged on confirm;
    // journal = resolved outcomes, kept). `memory` for ephemeral dev/tests.
    let outbox_cfg =
        std::env::var("NODE_OUTBOX").unwrap_or_else(|_| "node-outbox.sqlite".to_string());
    let outbox: Arc<dyn OutboxStore> = if outbox_cfg == "memory" {
        Arc::new(MemoryOutbox::new())
    } else {
        Arc::new(SqliteOutbox::open(&outbox_cfg)?)
    };

    // Issuer authentication trust anchor (zero-trust, offline). NO static token
    // map: the node holds the material to VERIFY an issuer's self-verifying proof
    // — the system-domain Level-1 public key and the pinned
    // `system_root_fingerprint`. The issuer PRESENTS a SignedLevel1Binding + a
    // fresh possession signature; the node verifies it locally, exactly as the
    // offline verifier checks a PoI.
    let issuer_verifier = {
        let fingerprint = std::env::var("CERTCRYPT_SYSTEM_ROOT_FINGERPRINT").map_err(|_| {
            anyhow::anyhow!("CERTCRYPT_SYSTEM_ROOT_FINGERPRINT must be set (64 lowercase hex)")
        })?;
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            anyhow::bail!("CERTCRYPT_SYSTEM_ROOT_FINGERPRINT must be 64 lowercase hex chars");
        }

        // The Level-1 key comes from the system domain's signed foundation
        // statement (system-foundation/1), never from a key of the node's own.
        // The statement is verified in full before anything is trusted: its
        // bootstrap manifest must recompute to the pinned fingerprint and a
        // quorum of the bootstrap members must have signed it, the Level-1 key
        // included. Any failure stops the node here.
        //
        // For a local test deployment, produce a statement from your own
        // development material with
        //   `cargo run -p certcrypt-node --example gen_dev_foundation > <path>`
        let foundation_path = std::env::var("CERTCRYPT_SYSTEM_FOUNDATION_PATH").map_err(|_| {
            anyhow::anyhow!(
                "CERTCRYPT_SYSTEM_FOUNDATION_PATH must be set (path to the system domain's \
                 signed system-foundation/1 statement)"
            )
        })?;
        let (resolver, foundation_source) =
            load_or_fetch_system_foundation(&api_url, Path::new(&foundation_path), &fingerprint)
                .await?;
        tracing::info!(
            %fingerprint,
            foundation = %foundation_source,
            statement_id = %resolver.foundation().foundation_statement_id,
            quorum = %format!("{}-of-{}", resolver.foundation().quorum_k, resolver.foundation().quorum_n),
            level1_kid = %resolver.level1_kid(),
            "issuer-auth trust anchor verified from the signed system foundation (offline)"
        );

        IssuerVerifier {
            resolver: Arc::new(resolver),
            system_root_fingerprint: Arc::new(fingerprint),
            // One cache for the whole process: a challenge spent on /v1/issue must
            // not be reusable on /v1/operations or /v1/outbox/dead.
            challenges: Arc::new(Default::default()),
        }
    };

    let operator = Some(load_operator_identity()?);
    let operator_credential = Some(load_operator_credential()?.ok_or_else(|| {
        anyhow::anyhow!(
            "CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64 is required; obtain an \
             operator.recognition/1 credential from the system domain for this operator key"
        )
    })?);

    // Defensive cap on members per /v1/issue (anti-DoS; not protocol semantics).
    // Conservative default for the managed node; a self-hosted issuer with a large
    // batch may raise it.
    let max_commitments_per_request = std::env::var("NODE_MAX_COMMITMENTS_PER_REQUEST")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(10_000);

    let upstream = Arc::new(UpstreamClient::new(api_url.clone()));

    // Shutdown behavior: how long the restart is expected to take (announced
    // as Retry-After while draining) and how long the drain window lasts.
    let lifecycle = Lifecycle::from_env_prefixed(certcrypt_node::http::ENV_PREFIX);
    let drain_window = std::time::Duration::from_secs(
        std::env::var("NODE_SHUTDOWN_DRAIN_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(3),
    );

    let state = NodeState {
        upstream: upstream.clone(),
        store: store.clone(),
        issuer_verifier,
        operator: operator.clone(),
        operator_credential: operator_credential.clone(),
        max_commitments_per_request,
        outbox: outbox.clone(),
        lifecycle: lifecycle.clone(),
        deployment_rules,
    };

    // The pages this node serves itself, read before the binder takes the config.
    let well_known = domain_binding
        .serve
        .then(|| domain_binding.published_path.clone());

    // BACKGROUND TASKS, in one process per state (see `background_lock`): the
    // relay, the operator domain binding and the retention sweep start once
    // this process holds the lock on its journal. During an upgrade the new
    // process serves requests at once and takes the tasks over when the old
    // one exits. Skipped only if the node has no operator identity (it could
    // not submit anyway).
    let relay = if let (Some(op), Some(cred)) = (operator.clone(), operator_credential.clone()) {
        // Background relay: drains the outbox (Pending entries due now) and
        // resubmits with the SAME request_id (idempotent) until the issuance
        // service confirms — the durable half of resilience that survives a
        // node restart or a dead client.
        let relay = Relay::new(
            outbox.clone(),
            upstream.clone(),
            store.clone(),
            op.clone(),
            cred,
        );
        let stop = relay.shutdown_flag();
        // Operator domain binding (optional): signs, publishes to a local
        // file, registers and renews; with no domain and no earlier statements
        // it does nothing.
        let binder = certcrypt_node::domain_binding::DomainBinder::new(
            domain_binding,
            op,
            operator_credential.clone(),
            (*upstream).clone(),
        );
        // Retention sweep: forgets terminal journal records after the period
        // and clears outbox rows left in the `submitted` state. Bounded
        // batches, so it never holds the store's writer against /v1/issue.
        let sweeper = RetentionSweeper::new(store.clone(), outbox.clone(), retention);
        let lock_path = certcrypt_node::background_lock::lock_path(&journal_cfg);
        let waiting = stop.clone();
        let handle = tokio::spawn(async move {
            if let Some(path) = lock_path {
                match certcrypt_node::background_lock::acquire_unless(path, waiting).await {
                    // Held until the process exits; the OS releases it then.
                    Ok(Some(lock)) => std::mem::forget(lock),
                    Ok(None) => return,
                    Err(e) => {
                        tracing::error!(error = %e, "background lock unusable — relay, domain binding and retention NOT started");
                        return;
                    }
                }
            }
            tokio::spawn(binder.run());
            tokio::spawn(async move { sweeper.run().await });
            tracing::info!(
                retention_days = retention.retention().as_secs() / 86_400,
                "outbox relay, domain binding and retention sweep started"
            );
            relay.run().await
        });
        Some((stop, handle))
    } else {
        tracing::warn!(
            "no operator identity/credential — outbox relay NOT started (node cannot submit)"
        );
        None
    };

    // HTTP backpressure: a bounded number of concurrent /v1 requests plus a
    // wall-clock budget per request, so a burst of integrator traffic meets a
    // queue and a limit.
    // /health stays outside the limit (see http::router_with_limits).
    // Exactly the API a third-party embedder uses — this binary gets no private
    // configuration path. `ENV_PREFIX` is public, so anyone can opt into these
    // same variable names, or pass their own prefix, or skip the environment
    // entirely and build `HttpLimits` in code.
    let limits = HttpLimits::from_env_prefixed(certcrypt_node::http::ENV_PREFIX);
    tracing::info!(
        max_concurrent_requests = limits.max_concurrent_requests,
        request_timeout_seconds = limits.request_timeout.as_secs(),
        "http backpressure configured"
    );
    // GET /ops (NODE_OPS_TOKEN): outside the limits, like /health.
    let mut app = certcrypt_node::http::router_with_limits(state, limits).merge(
        certcrypt_node::ops::router(certcrypt_node::ops::OpsState::from_env_prefixed(
            certcrypt_node::http::ENV_PREFIX,
            "node",
            log_ring,
        )),
    );
    // GET /.well-known/certcrypt-node.json (NODE_SERVE_WELL_KNOWN): outside
    // the limits too; a static file the issuance service reads a few times a day.
    if let Some(path) = well_known {
        tracing::info!(file = %path.display(), "serving /.well-known/certcrypt-node.json");
        app = app.merge(certcrypt_node::domain_binding::well_known_router(path));
    }
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!(%bind_addr, %api_url, "certcrypt-node listening");

    // Ordered shutdown on SIGTERM/ctrl-c:
    //   1. drain — writes answer 503 + Retry-After, reads still work, and the
    //      relay stops claiming new entries;
    //   2. after the drain window, stop accepting; in-flight requests finish;
    //   3. wait for the relay to record the delivery it has in hand;
    //   4. return — the stores close, which checkpoints their WAL.
    let relay_stop = relay.as_ref().map(|(stop, _)| stop.clone());
    let draining = lifecycle.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            // Drain first, log second: nothing that happens to the log output
            // may stand between the signal and the drain.
            draining.begin_drain();
            if let Some(stop) = relay_stop {
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            tracing::info!(
                drain_secs = drain_window.as_secs(),
                retry_after_secs = draining.restart_retry_after().as_secs(),
                "shutdown requested; draining"
            );
            tokio::time::sleep(drain_window).await;
        })
        .await?;
    if let Some((_, handle)) = relay {
        // Bounded: one upstream call plus margin. A relay that cannot finish in
        // that time is abandoned; its entry stays Pending and is resent on start.
        let budget = upstream.request_timeout() + std::time::Duration::from_secs(5);
        if tokio::time::timeout(budget, handle).await.is_err() {
            tracing::warn!("relay did not stop in time; its entry stays pending");
        }
    }
    tracing::info!("certcrypt-node stopped");
    Ok(())
}

/// The node's OWN signing key (NOT the issuer's emission key, NOT the
/// system-domain key). Used to sign an operator receipt per transported
/// submission set (opt-in, detachable, unlinkable per-certificate) and the
/// operator's domain-binding statements. In production it is provisioned once
/// and persisted. Both halves are required: an ephemeral identity could not
/// prove the administrative binding again after a restart and cannot be a
/// recognized transport operator.
fn load_operator_identity(
) -> anyhow::Result<Arc<certcrypt_node_core::operator_receipt::OperatorIdentity>> {
    use base64::Engine as _;
    let b = base64::engine::general_purpose::STANDARD;
    let sk = std::env::var("CERTCRYPT_NODE_OPERATOR_SK_B64")
        .ok()
        .filter(|s| !s.is_empty());
    let pk = std::env::var("CERTCRYPT_NODE_OPERATOR_PK_B64")
        .ok()
        .filter(|s| !s.is_empty());
    let id = match (sk, pk) {
        (Some(sk), Some(pk)) => {
            let sk = b
                .decode(sk.trim())
                .map_err(|e| anyhow::anyhow!("CERTCRYPT_NODE_OPERATOR_SK_B64 base64: {e}"))?;
            let pk = b
                .decode(pk.trim())
                .map_err(|e| anyhow::anyhow!("CERTCRYPT_NODE_OPERATOR_PK_B64 base64: {e}"))?;
            certcrypt_node_core::operator_receipt::OperatorIdentity::from_keypair(pk, sk)
        }
        (None, None) => anyhow::bail!(
            "CERTCRYPT_NODE_OPERATOR_SK_B64 and CERTCRYPT_NODE_OPERATOR_PK_B64 are required; \
             generate them locally with: cargo run -p certcrypt-node --example gen_operator_key"
        ),
        _ => anyhow::bail!(
            "set BOTH CERTCRYPT_NODE_OPERATOR_SK_B64 and CERTCRYPT_NODE_OPERATOR_PK_B64"
        ),
    };
    tracing::info!(operator_id = %id.operator_id, "operator identity loaded");
    Ok(Arc::new(id))
}

/// The system-domain-signed recognition credential (operator.recognition/1),
/// obtained once from the issuance service and configured as base64 of its
/// JSON. The node presents it with every submission and with every
/// domain-binding `bind`; the issuance service is the party that checks it. `None` when not configured;
/// the server requires it, the `unbind` command does not.
fn load_operator_credential() -> anyhow::Result<
    Option<Arc<capacity_artifacts::operator_recognition::OperatorRecognitionCredentialV1>>,
> {
    let Some(b64) = std::env::var("CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    use base64::Engine as _;
    let json = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| anyhow::anyhow!("CERTCRYPT_NODE_OPERATOR_CREDENTIAL_B64 base64: {e}"))?;
    let cred: capacity_artifacts::operator_recognition::OperatorRecognitionCredentialV1 =
        serde_json::from_slice(&json)
            .map_err(|e| anyhow::anyhow!("operator credential parse: {e}"))?;
    tracing::info!(operator_id = %cred.operator_id, "operator recognition credential loaded");
    Ok(Some(Arc::new(cred)))
}

/// `unbind <host>` and `rebind`: one pass against the issuance service, then
/// exit. They share the state file with a running node (under its lock).
async fn run_domain_command(args: &[String]) -> anyhow::Result<()> {
    use certcrypt_node::domain_binding::{DomainBinder, DomainBindingConfig};
    let api_url = std::env::var("CERTCRYPT_API_URL")
        .map_err(|_| anyhow::anyhow!("CERTCRYPT_API_URL must be set explicitly"))?;
    let cfg = DomainBindingConfig::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
    let binder = DomainBinder::new(
        cfg,
        load_operator_identity()?,
        load_operator_credential()?,
        UpstreamClient::new(api_url),
    );
    let now = chrono::Utc::now();
    let report = match args {
        [cmd, host] if cmd == "unbind" => binder.unbind(host, now).await?,
        [cmd] if cmd == "rebind" => binder.rebind(now).await?,
        _ => anyhow::bail!("usage: certcrypt-node unbind <host> | certcrypt-node rebind"),
    };
    println!("signed: {:?}", report.signed);
    println!("held by the issuance service: {:?}", report.held);
    for p in &report.problems {
        println!("problem: {p}");
    }
    if report.problems.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("not every statement was registered; see the problems above")
    }
}

const MAX_FOUNDATION_BYTES: u64 = 2 * 1024 * 1024;

/// Use a verified local copy when available. On first boot (or after local
/// corruption), retrieve the signed statement from the API as an untrusted
/// transport, verify it against the independently pinned fingerprint, and only
/// then persist it atomically. A valid cache keeps restarts independent from a
/// live API.
async fn load_or_fetch_system_foundation(
    api_url: &str,
    cache_path: &Path,
    pinned_fingerprint: &str,
) -> anyhow::Result<(
    capacity_verify::foundation::FoundationManifestResolver,
    String,
)> {
    if let Ok(bytes) = std::fs::read(cache_path) {
        match capacity_verify::foundation::FoundationManifestResolver::from_statement_bytes(
            &bytes,
            pinned_fingerprint,
            capacity_verify::foundation::registered_statement_id(pinned_fingerprint),
        ) {
            Ok(resolver) => return Ok((resolver, cache_path.display().to_string())),
            Err(error) => tracing::warn!(
                path = %cache_path.display(),
                %error,
                "cached system foundation rejected; attempting verified recovery from API"
            ),
        }
    }

    let configured_url = std::env::var("CERTCRYPT_SYSTEM_FOUNDATION_URL").ok();
    let url = system_foundation_url(api_url, configured_url.as_deref());
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("download system foundation from {url}: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("download system foundation from {url}: {e}"))?;
    if response.content_length().unwrap_or(0) > MAX_FOUNDATION_BYTES {
        anyhow::bail!("system foundation from {url} exceeds {MAX_FOUNDATION_BYTES} bytes");
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("read system foundation response from {url}: {e}"))?;
    if bytes.len() as u64 > MAX_FOUNDATION_BYTES {
        anyhow::bail!("system foundation from {url} exceeds {MAX_FOUNDATION_BYTES} bytes");
    }
    let resolver = capacity_verify::foundation::FoundationManifestResolver::from_statement_bytes(
        &bytes,
        pinned_fingerprint,
        capacity_verify::foundation::registered_statement_id(pinned_fingerprint),
    )
    .map_err(|e| anyhow::anyhow!("downloaded system foundation from {url} rejected: {e}"))?;

    let parent = cache_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        anyhow::bail!(
            "system foundation cache directory does not exist: {}",
            parent.display()
        );
    }
    let file_name = cache_path.file_name().ok_or_else(|| {
        anyhow::anyhow!(
            "invalid system foundation cache path: {}",
            cache_path.display()
        )
    })?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    std::fs::write(&temporary, &bytes).map_err(|e| {
        anyhow::anyhow!(
            "write verified system foundation {}: {e}",
            temporary.display()
        )
    })?;
    std::fs::rename(&temporary, cache_path).map_err(|e| {
        let _ = std::fs::remove_file(&temporary);
        anyhow::anyhow!(
            "install verified system foundation {}: {e}",
            cache_path.display()
        )
    })?;

    Ok((
        resolver,
        format!("{url} (cached at {})", cache_path.display()),
    ))
}

fn system_foundation_url(api_url: &str, configured_url: Option<&str>) -> String {
    configured_url
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "{}/v1/system-foundation",
                api_url.trim().trim_end_matches('/')
            )
        })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod system_foundation_url_tests {
    use super::system_foundation_url;

    #[test]
    fn absent_or_empty_override_derives_the_api_endpoint() {
        for configured in [None, Some(""), Some("   ")] {
            assert_eq!(
                system_foundation_url("http://127.0.0.1:9000/", configured),
                "http://127.0.0.1:9000/v1/system-foundation"
            );
        }
    }

    #[test]
    fn explicit_override_is_trimmed_and_preserved() {
        assert_eq!(
            system_foundation_url(
                "https://issuance.example",
                Some(" https://mirror.example/system-foundation.json ")
            ),
            "https://mirror.example/system-foundation.json"
        );
    }
}
