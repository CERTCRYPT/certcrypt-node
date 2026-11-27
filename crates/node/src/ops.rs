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

//! `GET /ops` — the node's operational state for its operator, beside
//! `/health`. Contract `ops/1`: the commit the binary was built from, when the
//! process started, its memory and, with `?logs=N`, the last log lines.
//!
//! `/health` answers "is it up" for a monitor; this answers "what is running
//! and what has it been saying" for whoever operates the node, without access
//! to the host's journal. The logs come from an in-process ring the tracing
//! subscriber writes to alongside stdout ([`init_tracing`]); it starts empty at
//! every restart.
//!
//! Auth: Bearer `NODE_OPS_TOKEN` ([`OpsState::from_env_prefixed`] with
//! [`crate::http::ENV_PREFIX`]), compared in constant time. Unset, the endpoint
//! does not exist (404). It is served on the node's listener, outside the
//! `/v1` concurrency limit and drain gate like `/health`, so keep the token
//! secret and keep the listener off the public internet.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing_subscriber::{fmt::MakeWriter, EnvFilter};

/// Lines kept. A line is capped at `MAX_LINE_CHARS`, so the ring stays bounded.
pub const MAX_LINES: usize = 1000;
const MAX_LINE_CHARS: usize = 2000;

/// The commit this build came from, when the build exported
/// `CERTCRYPT_BUILD_COMMIT` before `cargo build`. Otherwise null.
pub const BUILD_COMMIT: Option<&str> = option_env!("CERTCRYPT_BUILD_COMMIT");

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub ts: String,
    pub level: &'static str,
    pub line: String,
}

#[derive(Default)]
struct RingInner {
    lines: VecDeque<LogLine>,
    dropped: u64,
}

/// The shared ring: the tracing writer pushes, `GET /ops` reads.
#[derive(Clone)]
pub struct LogRing {
    inner: Arc<Mutex<RingInner>>,
    started: Instant,
    started_at: chrono::DateTime<chrono::Utc>,
}

impl Default for LogRing {
    fn default() -> Self {
        Self::new()
    }
}

impl LogRing {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RingInner::default())),
            started: Instant::now(),
            started_at: chrono::Utc::now(),
        }
    }

    pub fn push(&self, raw: &str) {
        let line = strip_ansi(raw.trim_end());
        if line.is_empty() {
            return;
        }
        let level = level_of(&line);
        let line: String = line.chars().take(MAX_LINE_CHARS).collect();
        let entry = LogLine {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level,
            line,
        };
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if inner.lines.len() == MAX_LINES {
            inner.lines.pop_front();
            inner.dropped += 1;
        }
        inner.lines.push_back(entry);
    }

    /// The last `n` lines, oldest first, and how many were evicted since start.
    pub fn tail(&self, n: usize) -> (Vec<LogLine>, u64) {
        let Ok(inner) = self.inner.lock() else {
            return (Vec::new(), 0);
        };
        let skip = inner.lines.len().saturating_sub(n);
        (
            inner.lines.iter().skip(skip).cloned().collect(),
            inner.dropped,
        )
    }
}

/// The fmt layer's level word after the timestamp.
fn level_of(line: &str) -> &'static str {
    let head: String = line.chars().take(48).collect();
    if head.contains("ERROR") {
        "error"
    } else if head.contains("WARN") {
        "warn"
    } else {
        "info"
    }
}

/// Removes ANSI escape sequences (colors) the fmt layer may add.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A `MakeWriter` that writes every event to stdout
/// and also into the ring.
#[derive(Clone)]
pub struct RingMakeWriter {
    ring: LogRing,
}

impl RingMakeWriter {
    pub fn new(ring: LogRing) -> Self {
        Self { ring }
    }
}

pub struct RingWriter {
    ring: LogRing,
    buf: Vec<u8>,
}

impl Write for RingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        // Into the ring first: a stdout that can no longer be written (the
        // reader of a pipe has exited) must not cost the ring the line as well.
        self.buf.extend_from_slice(bytes);
        std::io::stdout().write_all(bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

/// One event is written whole, then the writer is dropped: that is when its
/// text goes into the ring, one entry per line.
impl Drop for RingWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.buf);
        for line in text.lines() {
            self.ring.push(line);
        }
    }
}

impl<'a> MakeWriter<'a> for RingMakeWriter {
    type Writer = RingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RingWriter {
            ring: self.ring.clone(),
            buf: Vec::new(),
        }
    }
}

/// The binary's tracing setup (fmt + `RUST_LOG`, else `default_filter`), also
/// feeding the ring it returns.
pub fn init_tracing(default_filter: &str) -> LogRing {
    let ring = LogRing::new();
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    // No internal-error reports: when stdout fails, tracing-subscriber reports
    // it with eprintln!, which panics when stderr is the same broken pipe
    // (`run 2>&1 | tee log` after tee exits), killing whatever task logged.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(RingMakeWriter::new(ring.clone()))
        .log_internal_errors(false)
        .init();
    ring
}

/// What one process reports about itself.
#[derive(Clone)]
pub struct OpsState {
    pub service: &'static str,
    pub token: Option<Arc<String>>,
    pub ring: LogRing,
}

impl OpsState {
    /// `<prefix>OPS_TOKEN` from the environment (`NODE_OPS_TOKEN` for the
    /// bundled binary); empty or unset = no `/ops`.
    pub fn from_env_prefixed(prefix: &str, service: &'static str, ring: LogRing) -> Self {
        let token = std::env::var(format!("{prefix}OPS_TOKEN"))
            .ok()
            .filter(|t| !t.trim().is_empty())
            .map(Arc::new);
        Self {
            service,
            token,
            ring,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OpsQuery {
    #[serde(default)]
    pub logs: Option<usize>,
}

#[derive(Debug, Serialize)]
struct OpsMemory {
    #[serde(rename = "rssBytes")]
    rss_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct OpsResponse {
    contract: &'static str,
    service: &'static str,
    commit: Option<&'static str>,
    #[serde(rename = "startedAt")]
    started_at: String,
    #[serde(rename = "uptimeSec")]
    uptime_sec: u64,
    pid: u32,
    runtime: String,
    memory: OpsMemory,
    #[serde(skip_serializing_if = "Option::is_none")]
    logs: Option<Vec<LogLine>>,
    #[serde(rename = "logsDropped", skip_serializing_if = "Option::is_none")]
    logs_dropped: Option<u64>,
}

/// Resident memory from /proc (Linux); None elsewhere.
fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?;
    Some(kb * 1024)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn handler(
    State(state): State<OpsState>,
    headers: HeaderMap,
    Query(q): Query<OpsQuery>,
) -> Response {
    let Some(expected) = state.token.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (logs, logs_dropped) = match q.logs {
        Some(n) if n > 0 => {
            let (lines, dropped) = state.ring.tail(n.min(MAX_LINES));
            (Some(lines), Some(dropped))
        }
        _ => (None, None),
    };
    let body = OpsResponse {
        contract: "ops/1",
        service: state.service,
        commit: BUILD_COMMIT,
        started_at: state
            .ring
            .started_at
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        uptime_sec: state.ring.started.elapsed().as_secs(),
        pid: std::process::id(),
        runtime: format!("rust ({} {})", state.service, env!("CARGO_PKG_VERSION")),
        memory: OpsMemory {
            rss_bytes: rss_bytes(),
        },
        logs,
        logs_dropped,
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

/// `GET /ops` as a router of its own, to merge into a binary's router or to
/// serve alone.
pub fn router(state: OpsState) -> Router {
    Router::new().route("/ops", get(handler)).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(token: Option<&str>) -> OpsState {
        OpsState {
            service: "node",
            token: token.map(|t| Arc::new(t.to_string())),
            ring: LogRing::new(),
        }
    }

    async fn call(state: OpsState, bearer: Option<&str>, logs: Option<usize>) -> Response {
        let mut headers = HeaderMap::new();
        if let Some(b) = bearer {
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {b}").parse().unwrap(),
            );
        }
        handler(State(state), headers, Query(OpsQuery { logs })).await
    }

    #[tokio::test]
    async fn without_a_token_ops_does_not_exist() {
        assert_eq!(
            call(state(None), Some("x"), None).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn a_wrong_or_missing_token_is_refused() {
        assert_eq!(
            call(state(Some("t")), Some("u"), None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(state(Some("t")), None, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn state_always_logs_only_when_asked() {
        let st = state(Some("t"));
        st.ring.push("2026-10-08T10:00:00Z  WARN hello");
        let res = call(st.clone(), Some("t"), None).await;
        assert_eq!(res.status(), StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(v["contract"], "ops/1");
        assert_eq!(v["service"], "node");
        assert!(v.get("logs").is_none());
        let res = call(st, Some("t"), Some(5)).await;
        let v: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(v["logs"][0]["level"], "warn");
    }

    #[test]
    fn the_ring_is_bounded_and_strips_colours() {
        let ring = LogRing::new();
        ring.push("\u{1b}[31mERROR\u{1b}[0m boom");
        assert_eq!(ring.tail(1).0[0].line, "ERROR boom");
        for i in 0..(MAX_LINES + 3) {
            ring.push(&format!("l{i}"));
        }
        let (lines, dropped) = ring.tail(MAX_LINES * 2);
        assert_eq!(lines.len(), MAX_LINES);
        assert_eq!(dropped, 4);
    }

    #[test]
    fn a_written_event_lands_line_by_line() {
        let ring = LogRing::new();
        let mk = RingMakeWriter::new(ring.clone());
        {
            let mut w = mk.make_writer();
            w.write_all(b"first\nsecond\n").unwrap();
        }
        assert_eq!(ring.tail(10).0.len(), 2);
    }
}
