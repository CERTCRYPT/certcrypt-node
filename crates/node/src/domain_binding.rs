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

//! Operator domain binding (operator.domain-binding/1), the node's side.
//!
//! An operator may associate its operator key with an HTTPS origin it
//! controls, so that a displaying service can show that host name next to the
//! operator. It is optional: a node without `CERTCRYPT_NODE_OPERATOR_DOMAIN`
//! carries submissions exactly the same way. The association says who operates
//! the node; it is not an endorsement and is not part of any proof.
//!
//! What the node does:
//!   - signs a `bind` statement for the configured host with the operator key,
//!     valid for [`BIND_MAX_VALIDITY_DAYS`] days;
//!   - writes the resource to serve at
//!     `https://<host>/.well-known/certcrypt-node.json` into a local file. The
//!     operator's web server publishes that file. With `NODE_SERVE_WELL_KNOWN`
//!     the node also answers that one path itself, for a host whose requests
//!     already reach the node; it serves nothing else on the origin;
//!   - registers the statement with the issuance service, after writing the
//!     file. The service fetches the origin itself before it shows anything;
//!   - signs a new statement [`RENEW_AFTER_DAYS`] days after the current one
//!     and keeps the previous one published until it expires, so the new one
//!     can be checked before the old one lapses;
//!   - presents the newest statement again at every start, which carries a
//!     renewed recognition credential to the service.
//!
//! The sequence is the statement's identity for the operator. It is reserved
//! and persisted BEFORE a signed statement leaves the process, so a crash can
//! waste a number but never reuse one; and it never decreases: when the
//! service answers with a higher accepted sequence, the node continues above
//! it. Sequences are kept per operator key, so a key rotation starts a new
//! series and the statements of the previous key stay published until they
//! expire.
//!
//! The state file and the published file are written atomically under an
//! exclusive lock, so the `unbind` and `rebind` commands can run while the
//! node is serving.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use capacity_artifacts::operator_domain_binding::{
    normalize_domain, parse_instant, parse_sequence, DomainBindingInputs, OperatorDomainBindingV1,
    WellKnownBindings, BIND_MAX_VALIDITY_DAYS, INTENT_BIND, INTENT_UNBIND, SEQUENCE_MAX,
    WELL_KNOWN_MAX_BYTES, WELL_KNOWN_MAX_ENTRIES,
};
use capacity_artifacts::operator_recognition::OperatorRecognitionCredentialV1;
use certcrypt_node_core::operator_receipt::OperatorIdentity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::upstream::{UpstreamClient, UpstreamError};

/// A new `bind` is signed this many days after the current one.
pub const RENEW_AFTER_DAYS: i64 = 60;
/// How long an `unbind` may be accepted for the first time. Its effect is
/// permanent; this only bounds when it can be registered or discovered.
pub const UNBIND_VALIDITY_DAYS: i64 = 30;
/// How often the node checks whether something is due.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// Where the node keeps its domain-binding state and writes the published file.
#[derive(Debug, Clone)]
pub struct DomainBindingConfig {
    /// `CERTCRYPT_NODE_OPERATOR_DOMAIN`, normalised to its A-label form.
    pub domain: Option<String>,
    /// `NODE_DOMAIN_BINDING_STATE` (default `node-domain-binding.json`).
    pub state_path: PathBuf,
    /// `NODE_WELL_KNOWN_FILE` (default `certcrypt-node.json`): the file the
    /// operator's web server serves at `/.well-known/certcrypt-node.json`.
    pub published_path: PathBuf,
    /// `NODE_SERVE_WELL_KNOWN` (off by default): the node itself answers
    /// `GET /.well-known/certcrypt-node.json` with that file, for a node that
    /// is reached through the configured host (see [`well_known_router`]).
    pub serve: bool,
}

impl DomainBindingConfig {
    /// Read the configuration. A host name that cannot be bound stops the
    /// boot: silently ignoring a domain the operator asked for would leave it
    /// waiting for an association that never comes.
    pub fn from_env() -> Result<Self, String> {
        let domain = match std::env::var("CERTCRYPT_NODE_OPERATOR_DOMAIN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(d) => Some(
                normalize_domain(&d).map_err(|e| format!("CERTCRYPT_NODE_OPERATOR_DOMAIN: {e}"))?,
            ),
            None => None,
        };
        let path = |var: &str, default: &str| {
            PathBuf::from(
                std::env::var(var)
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| default.to_string()),
            )
        };
        Ok(Self {
            domain,
            state_path: path("NODE_DOMAIN_BINDING_STATE", "node-domain-binding.json"),
            published_path: path("NODE_WELL_KNOWN_FILE", "certcrypt-node.json"),
            serve: matches!(
                std::env::var("NODE_SERVE_WELL_KNOWN")
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "yes" | "on"
            ),
        })
    }
}

/// `GET /.well-known/certcrypt-node.json`, answered from the published file.
///
/// For a node reached through the host it declares (its own HTTPS front end
/// passes every path to the node), so no separate web server has to publish
/// the file. Read on every request — the node rewrites it on renewal — and
/// never cached. No file (or one over the size limit) is a 404, which the
/// issuance service reads as "not published".
///
/// One node, one file: several nodes behind one host would each publish a
/// different file, so only one of them may declare the host and serve it.
pub fn well_known_router(published_path: PathBuf) -> axum::Router {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    let path = Arc::new(published_path);
    axum::Router::new().route(
        capacity_artifacts::operator_domain_binding::WELL_KNOWN_PATH,
        axum::routing::get(move || {
            let path = path.clone();
            async move {
                let read = tokio::task::spawn_blocking(move || std::fs::read(&*path)).await;
                match read.ok().and_then(Result::ok) {
                    Some(b) if b.len() <= WELL_KNOWN_MAX_BYTES => (
                        [
                            (header::CONTENT_TYPE, "application/json"),
                            (header::CACHE_CONTROL, "no-store"),
                        ],
                        b,
                    )
                        .into_response(),
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }
        }),
    )
}

/// The service's answer to one registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// `accepted` or `idempotent`: the service holds the statement.
    Held,
    /// Any other `status`, with the highest accepted sequence when given.
    Status {
        status: String,
        maximum_accepted_sequence: Option<u64>,
    },
    /// The service could not be reached, is overloaded, or does not offer
    /// registration on this deployment. Tried again at the next check.
    Unavailable(String),
    /// The service read the request and refused it (a 4xx).
    Refused(String),
}

/// Sends a registration to the issuance service.
pub trait Registrar {
    fn register(&self, body: serde_json::Value) -> impl Future<Output = Registration> + Send;

    /// Fetch `https://<domain>/.well-known/certcrypt-node.json` the way the
    /// service will, and say whether it already carries `statement`.
    fn check_published(
        &self,
        domain: &str,
        statement: &OperatorDomainBindingV1,
    ) -> impl Future<Output = Publication> + Send;
}

/// What the node saw at its own published URL before registering a `bind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publication {
    /// The host serves the statement: register it now.
    Served,
    /// The host answered, without the statement (another file, an older one,
    /// an error status, a redirect). Registering now would make the service
    /// find nothing and give the statement up, so the node waits.
    NotServed(String),
    /// The node could not reach its own host (no route out, name not
    /// resolvable from inside its network). It cannot check; it registers and
    /// the service decides.
    Unreachable(String),
}

/// Read the published resource like the service does: HTTPS only, no
/// redirect, no proxy, bounded time and size.
pub async fn fetch_published(domain: &str, statement: &OperatorDomainBindingV1) -> Publication {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Publication::Unreachable(e.to_string()),
    };
    let url = format!(
        "https://{domain}{}",
        capacity_artifacts::operator_domain_binding::WELL_KNOWN_PATH
    );
    let mut resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) if e.is_connect() || e.is_timeout() => {
            return Publication::Unreachable(format!("{url}: {e}"))
        }
        // TLS and protocol failures are the host's answer, not a missing route.
        Err(e) => return Publication::NotServed(format!("{url}: {e}")),
    };
    if !resp.status().is_success() {
        return Publication::NotServed(format!("{url}: HTTP {}", resp.status().as_u16()));
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(c)) => {
                if body.len() + c.len() > WELL_KNOWN_MAX_BYTES {
                    return Publication::NotServed(format!(
                        "{url}: larger than {WELL_KNOWN_MAX_BYTES} bytes"
                    ));
                }
                body.extend_from_slice(&c);
            }
            Ok(None) => break,
            Err(e) => return Publication::NotServed(format!("{url}: {e}")),
        }
    }
    match serde_json::from_slice::<WellKnownBindings>(&body) {
        Ok(doc) if doc.bindings.iter().any(|b| b == statement) => Publication::Served,
        Ok(_) => Publication::NotServed(format!(
            "{url} does not carry sequence {} yet",
            statement.sequence
        )),
        Err(e) => {
            Publication::NotServed(format!("{url}: not a certcrypt-node.json document ({e})"))
        }
    }
}

impl Registrar for UpstreamClient {
    async fn register(&self, body: serde_json::Value) -> Registration {
        match self.register_domain_binding(&body).await {
            Ok(v) => {
                let status = v
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default()
                    .to_string();
                if status == "accepted" || status == "idempotent" {
                    return Registration::Held;
                }
                Registration::Status {
                    status,
                    maximum_accepted_sequence: v
                        .get("maximumAcceptedSequence")
                        .and_then(|m| m.as_str())
                        .and_then(|m| parse_sequence(m).ok()),
                }
            }
            Err(e @ UpstreamError::Status { .. }) if e.refusal_status().is_some() => {
                Registration::Refused(e.to_string())
            }
            Err(e) => Registration::Unavailable(e.to_string()),
        }
    }

    async fn check_published(
        &self,
        domain: &str,
        statement: &OperatorDomainBindingV1,
    ) -> Publication {
        fetch_published(domain, statement).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    statement: OperatorDomainBindingV1,
    registered: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    /// Highest sequence reserved per operator id. Never decreases.
    #[serde(default)]
    sequences: BTreeMap<String, u64>,
    /// Statements written to the published file, of every operator key this
    /// node has used, until they expire.
    #[serde(default)]
    published: Vec<Entry>,
    /// `(operator_id, domain_ascii)` pairs withdrawn with `unbind`: never bound
    /// again automatically, only by `rebind`.
    #[serde(default)]
    withdrawn: BTreeSet<(String, String)>,
}

fn instant(s: &str) -> DateTime<Utc> {
    // Statements in the state were built by this node; an unreadable instant
    // reads as already past, so the statement is replaced, never kept forever.
    parse_instant("instant", s).unwrap_or(DateTime::<Utc>::MIN_UTC)
}

fn sequence_of(e: &Entry) -> u64 {
    parse_sequence(&e.statement.sequence).unwrap_or(0)
}

impl State {
    fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("domain-binding state {}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!(
                "domain-binding state {}: {e}",
                path.display()
            )),
        }
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        self.published
            .retain(|e| instant(&e.statement.valid_until) > now);
    }

    fn newest_bind(&self, operator_id: &str, domain: &str) -> Option<&Entry> {
        self.published
            .iter()
            .filter(|e| {
                e.statement.operator_id == operator_id
                    && e.statement.intent == INTENT_BIND
                    && e.statement.domain_ascii == domain
            })
            .max_by_key(|e| sequence_of(e))
    }

    fn reserve(&mut self, operator_id: &str) -> anyhow::Result<u64> {
        let next = self
            .sequences
            .get(operator_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .filter(|n| *n <= SEQUENCE_MAX)
            .ok_or_else(|| anyhow::anyhow!("operator domain-binding sequence exhausted"))?;
        self.sequences.insert(operator_id.to_string(), next);
        Ok(next)
    }

    fn raise_to(&mut self, operator_id: &str, floor: u64) {
        let cur = self.sequences.entry(operator_id.to_string()).or_insert(0);
        if *cur < floor {
            *cur = floor;
        }
    }

    /// The published resource: newest first, at most the entry limit, and
    /// within the size limit (the oldest go first).
    fn published_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut entries: Vec<&Entry> = self.published.iter().collect();
        entries.sort_by_key(|e| std::cmp::Reverse(instant(&e.statement.issued_at)));
        entries.truncate(WELL_KNOWN_MAX_ENTRIES);
        loop {
            let doc = WellKnownBindings {
                bindings: entries.iter().map(|e| e.statement.clone()).collect(),
            };
            let bytes = serde_json::to_vec(&doc)?;
            if bytes.len() <= WELL_KNOWN_MAX_BYTES || entries.is_empty() {
                return Ok(bytes);
            }
            entries.pop();
        }
    }
}

/// Write `bytes` to `path` atomically: a temporary file in the same directory,
/// flushed to disk, then renamed over the target.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("invalid path {}", path.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> std::io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::anyhow!("write {}: {e}", path.display()));
    }
    Ok(())
}

/// What one pass did, for logs and for the commands' output.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PassReport {
    /// Sequences of the statements signed in this pass.
    pub signed: Vec<u64>,
    /// Sequences the service now holds.
    pub held: Vec<u64>,
    /// Problems the operator should see.
    pub problems: Vec<String>,
}

/// The node's domain-binding worker and commands.
pub struct DomainBinder<R> {
    cfg: DomainBindingConfig,
    operator: Arc<OperatorIdentity>,
    credential: Option<Arc<OperatorRecognitionCredentialV1>>,
    registrar: R,
}

enum Action<'a> {
    /// The periodic check. `present` re-registers the newest bind even when
    /// the service already holds it (at start, to carry a renewed credential).
    Check {
        present: bool,
    },
    Unbind(&'a str),
    Rebind,
}

impl<R: Registrar> DomainBinder<R> {
    pub fn new(
        cfg: DomainBindingConfig,
        operator: Arc<OperatorIdentity>,
        credential: Option<Arc<OperatorRecognitionCredentialV1>>,
        registrar: R,
    ) -> Self {
        Self {
            cfg,
            operator,
            credential,
            registrar,
        }
    }

    /// Check at start (presenting the newest statement again), then every
    /// [`CHECK_INTERVAL`].
    pub async fn run(self) {
        let mut present = true;
        loop {
            match self.check(Utc::now(), present).await {
                Ok(r) => {
                    for p in &r.problems {
                        tracing::warn!(problem = %p, "operator domain binding");
                    }
                    if !r.signed.is_empty() || !r.held.is_empty() {
                        tracing::info!(signed = ?r.signed, held = ?r.held, "operator domain binding");
                    }
                }
                Err(e) => tracing::error!(error = %e, "operator domain binding check failed"),
            }
            present = false;
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    }

    /// Sign what is due and register what the service does not hold yet.
    pub async fn check(&self, now: DateTime<Utc>, present: bool) -> anyhow::Result<PassReport> {
        self.pass(now, Action::Check { present }).await
    }

    /// Withdraw the association with `domain` (any spelling; normalised). The
    /// `unbind` replaces the domain's `bind` statements in the published file
    /// and the node will not bind that domain again on its own.
    pub async fn unbind(&self, domain: &str, now: DateTime<Utc>) -> anyhow::Result<PassReport> {
        let domain = normalize_domain(domain).map_err(|e| anyhow::anyhow!("{e}"))?;
        self.pass(now, Action::Unbind(&domain)).await
    }

    /// Sign a new `bind` for the configured domain now, whatever the current
    /// one's age; also lifts an earlier `unbind` of that domain. Not needed when
    /// the host starts serving a registered statement late: the service keeps
    /// checking the newest statement while it is valid.
    pub async fn rebind(&self, now: DateTime<Utc>) -> anyhow::Result<PassReport> {
        if self.cfg.domain.is_none() {
            anyhow::bail!("CERTCRYPT_NODE_OPERATOR_DOMAIN is not set");
        }
        self.pass(now, Action::Rebind).await
    }

    fn sign(
        &self,
        intent: &str,
        domain: &str,
        sequence: u64,
        now: DateTime<Utc>,
        validity_days: i64,
    ) -> anyhow::Result<OperatorDomainBindingV1> {
        let mut s = OperatorDomainBindingV1::unsigned(&DomainBindingInputs {
            intent: intent.into(),
            operator_public_key_b64: base64::engine::general_purpose::STANDARD
                .encode(&self.operator.public_key),
            domain: domain.into(),
            sequence,
            issued_at: now,
            valid_until: now + chrono::Duration::days(validity_days),
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let msg = s.signing_message().map_err(|e| anyhow::anyhow!("{e}"))?;
        let sig = capacity_verify::mldsa::sign_detached(self.operator.secret_key(), &msg)
            .map_err(|e| anyhow::anyhow!("sign domain binding: {e}"))?;
        s.signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        Ok(s)
    }

    fn sign_and_record(
        &self,
        st: &mut State,
        intent: &str,
        domain: &str,
        now: DateTime<Utc>,
        report: &mut PassReport,
    ) -> anyhow::Result<()> {
        let op = &self.operator.operator_id;
        let seq = st.reserve(op)?;
        let validity = if intent == INTENT_BIND {
            BIND_MAX_VALIDITY_DAYS
        } else {
            UNBIND_VALIDITY_DAYS
        };
        let statement = self.sign(intent, domain, seq, now, validity)?;
        if intent == INTENT_UNBIND {
            st.published.retain(|e| {
                !(e.statement.operator_id == *op && e.statement.domain_ascii == domain)
            });
        }
        st.published.push(Entry {
            statement,
            registered: false,
        });
        report.signed.push(seq);
        Ok(())
    }

    fn lock(&self) -> anyhow::Result<File> {
        let mut name = self.cfg.state_path.as_os_str().to_owned();
        name.push(".lock");
        let f = File::create(PathBuf::from(name))?;
        f.lock()?;
        Ok(f)
    }

    fn save(&self, st: &State) -> anyhow::Result<()> {
        write_atomic(&self.cfg.state_path, &serde_json::to_vec_pretty(st)?)
    }

    async fn pass(&self, now: DateTime<Utc>, action: Action<'_>) -> anyhow::Result<PassReport> {
        // A node that never used the feature keeps no files for it.
        if matches!(action, Action::Check { .. })
            && self.cfg.domain.is_none()
            && !self.cfg.state_path.exists()
        {
            return Ok(PassReport::default());
        }
        // Held only by this node and its own commands, for one pass; waiting
        // for it on the runtime is acceptable.
        let _lock = self
            .lock()
            .map_err(|e| anyhow::anyhow!("lock {}: {e}", self.cfg.state_path.display()))?;
        let op = self.operator.operator_id.clone();
        let mut st = State::load(&self.cfg.state_path)?;
        let before = st.published.clone();
        st.prune(now);
        let mut report = PassReport::default();

        let mut present = false;
        match action {
            Action::Check { present: p } => {
                present = p;
                if let Some(domain) = self.cfg.domain.clone() {
                    if st.withdrawn.contains(&(op.clone(), domain.clone())) {
                        report.problems.push(format!(
                            "{domain} was withdrawn with unbind; run rebind to associate it again"
                        ));
                    } else {
                        let due = st.newest_bind(&op, &domain).is_none_or(|e| {
                            instant(&e.statement.issued_at)
                                + chrono::Duration::days(RENEW_AFTER_DAYS)
                                <= now
                        });
                        if due {
                            self.sign_and_record(&mut st, INTENT_BIND, &domain, now, &mut report)?;
                        }
                    }
                }
            }
            Action::Unbind(domain) => {
                st.withdrawn.insert((op.clone(), domain.to_string()));
                self.sign_and_record(&mut st, INTENT_UNBIND, domain, now, &mut report)?;
            }
            Action::Rebind => {
                let domain = self.cfg.domain.clone().unwrap_or_default();
                st.withdrawn.remove(&(op.clone(), domain.clone()));
                self.sign_and_record(&mut st, INTENT_BIND, &domain, now, &mut report)?;
            }
        }

        // The sequences are on disk before any statement leaves the process.
        self.save(&st)?;
        if st.published != before || present {
            if st.published.is_empty() && !self.cfg.published_path.exists() {
                // Nothing to publish and nothing published: leave no file.
            } else {
                write_atomic(&self.cfg.published_path, &st.published_bytes()?)?;
            }
        }

        self.register_pending(&mut st, now, present, &mut report)
            .await?;
        self.save(&st)?;
        Ok(report)
    }

    async fn register_pending(
        &self,
        st: &mut State,
        now: DateTime<Utc>,
        present: bool,
        report: &mut PassReport,
    ) -> anyhow::Result<()> {
        let op = self.operator.operator_id.clone();
        // A conflict re-signs the statement above the service's maximum; two
        // rounds are enough unless something else signs with this key.
        for _round in 0..3 {
            let newest_bind_seq = st
                .published
                .iter()
                .filter(|e| e.statement.operator_id == op && e.statement.intent == INTENT_BIND)
                .map(sequence_of)
                .max();
            let todo: Vec<usize> = st
                .published
                .iter()
                .enumerate()
                .filter(|(_, e)| {
                    e.statement.operator_id == op
                        && (!e.registered || (present && Some(sequence_of(e)) == newest_bind_seq))
                })
                .map(|(i, _)| i)
                .collect();
            if todo.is_empty() {
                return Ok(());
            }
            let mut re_sign: Vec<(String, String)> = Vec::new();
            let mut drop_seq: Vec<u64> = Vec::new();
            for i in todo {
                let e = &st.published[i];
                let seq = sequence_of(e);
                let intent = e.statement.intent.clone();
                let domain = e.statement.domain_ascii.clone();
                if intent == INTENT_BIND && self.credential.is_none() {
                    report.problems.push(format!(
                        "bind {seq} for {domain} needs the operator recognition credential"
                    ));
                    continue;
                }
                // A bind the service has not seen yet is registered only once
                // its host serves it: registered earlier, the service would
                // find nothing and give it up, and would show the host name
                // only at a later check once served. Not checked when
                // re-presenting a held statement.
                if intent == INTENT_BIND && !e.registered {
                    match self.registrar.check_published(&domain, &e.statement).await {
                        Publication::Served => {}
                        Publication::NotServed(why) => {
                            report.problems.push(format!(
                                "bind {seq} for {domain} is not served yet ({why}); serve the file \
                                 at /.well-known/certcrypt-node.json — it is registered at the next \
                                 check once it is"
                            ));
                            continue;
                        }
                        Publication::Unreachable(why) => {
                            report.problems.push(format!(
                                "could not check {domain} from this node ({why}); registering \
                                 bind {seq} anyway"
                            ));
                        }
                    }
                }
                let e = &st.published[i];
                let mut body = serde_json::json!({ "binding": e.statement });
                if let Some(c) = &self.credential {
                    body["credential"] = serde_json::to_value(c.as_ref())?;
                }
                match self.registrar.register(body).await {
                    Registration::Held => {
                        st.published[i].registered = true;
                        report.held.push(seq);
                    }
                    Registration::Status {
                        status,
                        maximum_accepted_sequence,
                    } if status == "sequence_conflict" || status == "stale_sequence" => {
                        // The service knows a higher sequence than this node
                        // (its state was lost or restored from a backup).
                        st.raise_to(&op, maximum_accepted_sequence.unwrap_or(seq));
                        drop_seq.push(seq);
                        re_sign.push((intent, domain));
                    }
                    Registration::Status { status, .. } if status == "unknown_domain" => {
                        // An unbind of a domain this key was never associated
                        // with: there is nothing to withdraw.
                        st.published[i].registered = true;
                        report
                            .problems
                            .push(format!("{domain} was not associated with this operator"));
                    }
                    Registration::Status { status, .. } if status == "integration_inactive" => {
                        report.problems.push(format!(
                            "{intent} {seq} for {domain}: the node's integration is not active; \
                             it is presented again at the next check"
                        ));
                    }
                    Registration::Status { status, .. } => {
                        report
                            .problems
                            .push(format!("{intent} {seq} for {domain}: {status}"));
                    }
                    Registration::Unavailable(e) => {
                        report.problems.push(format!(
                            "registration unavailable ({e}); tried again at the next check"
                        ));
                        return Ok(());
                    }
                    Registration::Refused(e) => {
                        report
                            .problems
                            .push(format!("{intent} {seq} for {domain} refused: {e}"));
                    }
                }
            }
            if re_sign.is_empty() {
                return Ok(());
            }
            st.published
                .retain(|e| !(e.statement.operator_id == op && drop_seq.contains(&sequence_of(e))));
            for (intent, domain) in re_sign {
                self.sign_and_record(st, &intent, &domain, now, report)?;
            }
            self.save(st)?;
            write_atomic(&self.cfg.published_path, &st.published_bytes()?)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        publication: Mutex<Publication>,
        answers: Mutex<Vec<Registration>>,
        bodies: Mutex<Vec<serde_json::Value>>,
    }

    impl Fake {
        fn new(answers: Vec<Registration>) -> Self {
            Self {
                publication: Mutex::new(Publication::Served),
                answers: Mutex::new(answers),
                bodies: Mutex::new(Vec::new()),
            }
        }
        fn sent(&self) -> Vec<serde_json::Value> {
            self.bodies.lock().unwrap().clone()
        }
    }

    impl Registrar for &Fake {
        async fn check_published(&self, _d: &str, _s: &OperatorDomainBindingV1) -> Publication {
            self.publication.lock().unwrap().clone()
        }

        async fn register(&self, body: serde_json::Value) -> Registration {
            self.bodies.lock().unwrap().push(body);
            let mut a = self.answers.lock().unwrap();
            if a.is_empty() {
                Registration::Held
            } else {
                a.remove(0)
            }
        }
    }

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("cc-node-domain-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg(d: &Path, domain: Option<&str>) -> DomainBindingConfig {
        DomainBindingConfig {
            domain: domain.map(|s| normalize_domain(s).unwrap()),
            state_path: d.join("state.json"),
            published_path: d.join("certcrypt-node.json"),
            serve: false,
        }
    }

    fn published(d: &Path) -> Vec<OperatorDomainBindingV1> {
        let doc: WellKnownBindings =
            serde_json::from_slice(&std::fs::read(d.join("certcrypt-node.json")).unwrap()).unwrap();
        doc.bindings
    }

    fn t0() -> DateTime<Utc> {
        "2026-01-10T00:00:00Z".parse().unwrap()
    }

    #[tokio::test]
    async fn signs_publishes_and_registers_a_bind() {
        let d = dir();
        let op = Arc::new(OperatorIdentity::generate());
        let fake = Fake::new(vec![]);
        let b = DomainBinder::new(cfg(&d, Some("Nodes.Example.ORG")), op.clone(), None, &fake);
        let r = b.check(t0(), true).await.unwrap();
        assert_eq!(r.signed, vec![1]);
        // No credential: the bind is written but not registered.
        assert!(r.held.is_empty());
        assert_eq!(r.problems.len(), 1);

        let p = published(&d);
        assert_eq!(p.len(), 1);
        let s = &p[0];
        assert_eq!(s.domain_ascii, "nodes.example.org");
        assert_eq!(s.operator_id, op.operator_id);
        assert_eq!(s.sequence, "1");
        s.validate_structure(t0()).unwrap();
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&s.signature_b64)
            .unwrap();
        capacity_verify::mldsa::verify_detached(
            &op.public_key,
            &sig,
            &s.signing_message().unwrap(),
        )
        .unwrap();
        assert!(fake.sent().is_empty());
    }

    #[tokio::test]
    async fn renews_after_sixty_days_and_keeps_the_previous_until_it_expires() {
        let d = dir();
        let op = Arc::new(OperatorIdentity::generate());
        let fake = Fake::new(vec![]);
        let b = DomainBinder::new(cfg(&d, Some("nodes.example.org")), op, None, &fake);
        b.check(t0(), false).await.unwrap();
        let r = b
            .check(t0() + chrono::Duration::days(59), false)
            .await
            .unwrap();
        assert!(r.signed.is_empty(), "nothing is due before 60 days");
        let r = b
            .check(t0() + chrono::Duration::days(60), false)
            .await
            .unwrap();
        assert_eq!(r.signed, vec![2]);
        let seqs: Vec<String> = published(&d).into_iter().map(|s| s.sequence).collect();
        assert_eq!(
            seqs,
            vec!["2", "1"],
            "newest first, previous still published"
        );
        b.check(t0() + chrono::Duration::days(91), false)
            .await
            .unwrap();
        let seqs: Vec<String> = published(&d).into_iter().map(|s| s.sequence).collect();
        assert_eq!(seqs, vec!["2"], "the expired one is gone");
    }

    #[tokio::test]
    async fn a_conflict_continues_above_the_services_maximum() {
        let d = dir();
        let op = Arc::new(OperatorIdentity::generate());
        let fake = Fake::new(vec![Registration::Status {
            status: "stale_sequence".into(),
            maximum_accepted_sequence: Some(12),
        }]);
        let cred = credential_for(&op);
        let b = DomainBinder::new(cfg(&d, Some("nodes.example.org")), op, Some(cred), &fake);
        let r = b.check(t0(), true).await.unwrap();
        assert_eq!(r.signed, vec![1, 13]);
        assert_eq!(r.held, vec![13]);
        let seqs: Vec<String> = published(&d).into_iter().map(|s| s.sequence).collect();
        assert_eq!(seqs, vec!["13"], "the refused statement is not published");
        let sent = fake.sent();
        assert_eq!(sent.len(), 2);
        assert!(sent[0]["credential"].is_object());
    }

    #[tokio::test]
    async fn presents_the_newest_bind_again_at_start_and_retries_when_unavailable() {
        let d = dir();
        let op = Arc::new(OperatorIdentity::generate());
        let cred = credential_for(&op);
        let fake = Fake::new(vec![Registration::Unavailable("503".into())]);
        let b = DomainBinder::new(cfg(&d, Some("nodes.example.org")), op, Some(cred), &fake);
        let r = b.check(t0(), true).await.unwrap();
        assert!(r.held.is_empty());
        // The next check registers it; a restart presents it again.
        let r = b
            .check(t0() + chrono::Duration::hours(1), false)
            .await
            .unwrap();
        assert_eq!(r.held, vec![1]);
        let r = b
            .check(t0() + chrono::Duration::hours(2), false)
            .await
            .unwrap();
        assert!(r.held.is_empty(), "held: not sent again without a restart");
        let r = b
            .check(t0() + chrono::Duration::hours(3), true)
            .await
            .unwrap();
        assert_eq!(r.held, vec![1]);
        assert_eq!(fake.sent().len(), 3);
    }

    #[tokio::test]
    async fn unbind_replaces_the_bind_and_blocks_automatic_rebinding() {
        let d = dir();
        let op = Arc::new(OperatorIdentity::generate());
        let cred = credential_for(&op);
        let fake = Fake::new(vec![]);
        let b = DomainBinder::new(cfg(&d, Some("nodes.example.org")), op, Some(cred), &fake);
        b.check(t0(), true).await.unwrap();
        let r = b
            .unbind("NODES.example.org", t0() + chrono::Duration::days(1))
            .await
            .unwrap();
        assert_eq!(r.signed, vec![2]);
        assert_eq!(r.held, vec![2]);
        let p = published(&d);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].intent, "unbind");

        let r = b
            .check(t0() + chrono::Duration::days(70), false)
            .await
            .unwrap();
        assert!(
            r.signed.is_empty(),
            "a withdrawn domain is not bound again on its own"
        );
        assert_eq!(r.problems.len(), 1);

        let r = b.rebind(t0() + chrono::Duration::days(71)).await.unwrap();
        assert_eq!(r.signed, vec![3]);
        assert_eq!(r.held, vec![3]);
    }

    #[tokio::test]
    async fn a_new_key_starts_its_own_series_and_the_old_statements_stay_published() {
        let d = dir();
        let fake = Fake::new(vec![]);
        let old = Arc::new(OperatorIdentity::generate());
        DomainBinder::new(cfg(&d, Some("nodes.example.org")), old.clone(), None, &fake)
            .check(t0(), false)
            .await
            .unwrap();
        let new = Arc::new(OperatorIdentity::generate());
        let r = DomainBinder::new(cfg(&d, Some("nodes.example.org")), new.clone(), None, &fake)
            .check(t0() + chrono::Duration::days(1), false)
            .await
            .unwrap();
        assert_eq!(r.signed, vec![1]);
        let ops: BTreeSet<String> = published(&d).into_iter().map(|s| s.operator_id).collect();
        assert_eq!(
            ops,
            BTreeSet::from([old.operator_id.clone(), new.operator_id.clone()])
        );
    }

    #[tokio::test]
    async fn no_domain_and_no_history_leaves_no_files() {
        let d = dir();
        let fake = Fake::new(vec![]);
        let op = Arc::new(OperatorIdentity::generate());
        DomainBinder::new(cfg(&d, None), op, None, &fake)
            .check(t0(), true)
            .await
            .unwrap();
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "no file at all");
        assert!(fake.sent().is_empty());
    }

    #[tokio::test]
    async fn a_bind_is_registered_only_once_its_host_serves_it() {
        let d = dir();
        let op = Arc::new(OperatorIdentity::generate());
        let cred = credential_for(&op);
        let fake = Fake::new(vec![]);
        *fake.publication.lock().unwrap() = Publication::NotServed("HTTP 404".into());
        let b = DomainBinder::new(cfg(&d, Some("nodes.example.org")), op, Some(cred), &fake);
        let r = b.check(t0(), true).await.unwrap();
        assert_eq!(r.signed, vec![1]);
        assert!(r.held.is_empty());
        assert!(
            fake.sent().is_empty(),
            "nothing registered while the host does not serve it"
        );

        *fake.publication.lock().unwrap() = Publication::Served;
        let r = b
            .check(t0() + chrono::Duration::hours(1), false)
            .await
            .unwrap();
        assert!(r.signed.is_empty(), "the same statement, not a new one");
        assert_eq!(r.held, vec![1]);

        // A node that cannot reach its own host registers anyway.
        let d2 = dir();
        let op2 = Arc::new(OperatorIdentity::generate());
        let fake2 = Fake::new(vec![]);
        *fake2.publication.lock().unwrap() = Publication::Unreachable("no route".into());
        let r = DomainBinder::new(
            cfg(&d2, Some("nodes.example.org")),
            op2.clone(),
            Some(credential_for(&op2)),
            &fake2,
        )
        .check(t0(), true)
        .await
        .unwrap();
        assert_eq!(r.held, vec![1]);
        assert_eq!(r.problems.len(), 1);
    }

    #[tokio::test]
    async fn the_node_serves_its_published_file_when_asked() {
        use tower::ServiceExt as _;
        let d = dir();
        let op = Arc::new(OperatorIdentity::generate());
        let fake = Fake::new(vec![]);
        let get = || {
            axum::http::Request::get("/.well-known/certcrypt-node.json")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let app = well_known_router(d.join("certcrypt-node.json"));
        let r = app.clone().oneshot(get()).await.unwrap();
        assert_eq!(r.status(), 404, "nothing published yet");

        DomainBinder::new(cfg(&d, Some("nodes.example.org")), op, None, &fake)
            .check(t0(), true)
            .await
            .unwrap();
        let r = app.oneshot(get()).await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "application/json");
        let body = axum::body::to_bytes(r.into_body(), WELL_KNOWN_MAX_BYTES)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            std::fs::read(d.join("certcrypt-node.json")).unwrap()
        );
    }

    /// A credential naming this operator key. The node does not check its
    /// signatures (the service does), so they are left empty here.
    fn credential_for(op: &OperatorIdentity) -> Arc<OperatorRecognitionCredentialV1> {
        use capacity_artifacts::operator_recognition::{RecognitionIssuer, RecognitionSignature};
        Arc::new(OperatorRecognitionCredentialV1 {
            artifact_type: "operator.recognition/1".into(),
            system_id: "test".into(),
            rules_version: "test".into(),
            system_root_fingerprint: "0".repeat(64),
            recognition_id: "rec-test".into(),
            operator_id: op.operator_id.clone(),
            operator_public_key: base64::engine::general_purpose::STANDARD.encode(&op.public_key),
            operator_key_alg: "ml-dsa-65-fips204-v1".into(),
            valid_from: t0() - chrono::Duration::days(1),
            valid_until: t0() + chrono::Duration::days(365),
            recognition_issuer: RecognitionIssuer {
                kid: "test".into(),
                manifest_sequence: 1,
            },
            signature: RecognitionSignature {
                signature_alg: "ml-dsa-65-fips204-v1".into(),
                signature_b64: String::new(),
            },
        })
    }
}
