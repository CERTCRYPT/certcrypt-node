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

//! Outbox relay — the durable half of submit resilience.
//!
//! A background loop that drains the outbox: claims Pending entries due now,
//! resubmits each to the issuance service with the SAME `request_id`
//! (idempotent), and:
//! - on confirmation → removes the entry + journals each member's outcome
//!   over the record the issuer already holds;
//! - on `insufficient_capacity` while the set's commitments are still valid →
//!   keeps the entry and postpones it without counting an attempt, on the
//!   schedule of [`crate::capacity_wait`]; once that window closes the refusal
//!   is recorded as final like any other whole-set verdict;
//! - when the service asks to be left alone (`Retry-After`: planned
//!   maintenance, rate limiting) → pauses the WHOLE loop for that long and
//!   postpones the entry without counting an attempt;
//! - on a transient failure (unreachable, timeout, 408/425/429, 502/503/504) →
//!   reschedules with exponential backoff + full jitter, for as long as the
//!   failure lasts: the set is fine, only the path to the service is not, so it
//!   never dead-letters;
//! - on a definitive refusal (a 4xx other than 408/425/429) → dead-letters it
//!   AT ONCE: the service read the request and said no, and resending the same
//!   bytes cannot change that, exactly like an entry that no longer parses;
//! - on any other failure (a `500`, a node-side signing error) → retries up to
//!   `max_attempts`, then dead-letters it.
//!
//! A dead-lettered entry waits for an operator: `POST
//! /v1/outbox/dead/{request_id}/redrive` revives it once the cause is fixed.
//!
//! Delivery invariants:
//! - The stored `SubmissionSetV1` is resent VERBATIM (never re-signed).
//!   The operator-recognition proof IS re-signed each attempt — it is the
//!   operator's, binds the stable `request_id.submission_set_id`, not the holder.
//! - At-least-once delivery (the relay) + idempotent consumer (the issuance service) =
//!   exactly-once effective.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use capacity_artifacts::SubmissionSetV1;

use crate::outbox::OutboxStore;
use crate::store::{JournalStore, OperationState};
use crate::upstream::{FlatOutcome, OperatorRecognitionProof, SubmitResponse, UpstreamClient};

// ── the transport-retry policy ─────────────────────────────────────────────
//
// One decision function for every failed call to the issuance service, written
// to the rules the conformance contract pins for all clients — issuer SDKs
// apply the same rules to a node. The relay feeds it the node's own policy (no
// time budget, no attempt limit for transport failures: the outbox is durable,
// so it waits out an outage of any length); the conformance test feeds it the
// contract's default policy and checks every case.

/// The longest `Retry-After` honored. A hint, not a promise: past this the
/// client probes again, so a wrong value cannot park it for a day.
pub const MAX_HONOURED_RETRY_AFTER: Duration = Duration::from_secs(900);
/// The shortest. `Retry-After: 0` would otherwise be a free, uncounted busy loop.
pub const MIN_HONOURED_RETRY_AFTER: Duration = Duration::from_secs(1);

/// `wait` clamped to the honored range, in milliseconds.
pub fn honoured_wait_ms(wait: Duration) -> i64 {
    let w = wait.clamp(MIN_HONOURED_RETRY_AFTER, MAX_HONOURED_RETRY_AFTER);
    i64::try_from(w.as_millis()).unwrap_or(i64::MAX / 2)
}

/// Reads `Retry-After` only as a whole number of seconds, trimmed. An HTTP
/// date, a sign, a fraction or text is treated as absent.
pub fn parse_retry_after(raw: &str) -> Option<Duration> {
    let t = raw.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // All digits but too large for u64: as long as anyone could mean — the
    // clamp brings it down to the ceiling.
    Some(Duration::from_secs(t.parse::<u64>().unwrap_or(u64::MAX)))
}

/// One failed call, as the policy sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportOutcome {
    /// No HTTP answer: refused, reset, timed out.
    Transport,
    /// An HTTP answer that was not a success. `retry_after` is the header
    /// already parsed under the whole-seconds rule.
    Http {
        status: u16,
        retry_after: Option<Duration>,
    },
}

/// The client's budgets and backoff. `None` = no limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_elapsed: Option<Duration>,
    pub max_attempts: Option<u32>,
    pub backoff_base: Duration,
    pub backoff_cap: Duration,
}

/// What to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Not a transport failure: the caller decides.
    Return,
    /// The configured attempt or time budget is spent.
    GiveUp,
    /// The server asked for this exact wait; it does not count as an attempt.
    WaitAsked { wait_ms: i64 },
    /// A counted attempt: wait a uniform draw in `[0, ceiling_ms]`.
    Backoff { ceiling_ms: i64 },
}

/// The transport-retry decision.
/// `counted_before` is the number of counted attempts before this failure;
/// `elapsed_ms` is the time since the first attempt.
pub fn decide(
    policy: &RetryPolicy,
    outcome: TransportOutcome,
    counted_before: u32,
    elapsed_ms: i64,
) -> Decision {
    let ms = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX / 4);
    if let TransportOutcome::Http { status, .. } = outcome {
        let transient = matches!(status, 408 | 425 | 429 | 503) || (500..=599).contains(&status);
        if !transient {
            return Decision::Return;
        }
    }
    if let Some(max) = policy.max_elapsed {
        if elapsed_ms >= ms(max) {
            return Decision::GiveUp;
        }
    }
    if let TransportOutcome::Http {
        status: 503 | 429,
        retry_after: Some(asked),
    } = outcome
    {
        let wait_ms = honoured_wait_ms(asked);
        if let Some(max) = policy.max_elapsed {
            if elapsed_ms + wait_ms > ms(max) {
                return Decision::GiveUp; // Waiting less cannot work.
            }
        }
        return Decision::WaitAsked { wait_ms };
    }
    let n = counted_before.saturating_add(1);
    if policy.max_attempts.is_some_and(|max| n >= max) {
        return Decision::GiveUp;
    }
    let mut ceiling_ms = ms(policy
        .backoff_base
        .saturating_mul(2u32.saturating_pow(n - 1))
        .min(policy.backoff_cap));
    if let Some(max) = policy.max_elapsed {
        ceiling_ms = ceiling_ms.min(ms(max) - elapsed_ms); // Never sleep past the time budget.
    }
    Decision::Backoff { ceiling_ms }
}

/// Tunables (env-overridable in `Relay::from_env_or_default`).
#[derive(Debug, Clone, Copy)]
pub struct RelayConfig {
    /// Loop tick interval.
    pub tick: std::time::Duration,
    /// Entries claimed per tick.
    pub batch: usize,
    /// Backoff base (attempt n waits ~base*2^(n-1) + jitter).
    pub backoff_base: std::time::Duration,
    /// Cap on a single backoff wait.
    pub backoff_cap: std::time::Duration,
    /// Attempts before an entry that failed for a NON-transient reason (a
    /// `500`, a node-side signing error) is moved to Dead. Transient failures
    /// never reach Dead; definitive refusals (4xx) reach it on the first one.
    pub max_attempts: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            tick: std::time::Duration::from_millis(1000),
            batch: 32,
            backoff_base: std::time::Duration::from_millis(200),
            backoff_cap: std::time::Duration::from_secs(300), // 5 min (durable plane)
            max_attempts: 12,
        }
    }
}

/// What one delivery attempt tells the loop.
enum Next {
    /// Carry on with the batch.
    Continue,
    /// The issuance service asked for quiet until this instant (epoch ms): stop the batch.
    PauseUntil(i64),
}

/// The relay needs the same operator material the synchronous path uses, to
/// re-sign the recognition proof per attempt.
pub struct Relay {
    outbox: Arc<dyn OutboxStore>,
    upstream: Arc<UpstreamClient>,
    store: Arc<dyn JournalStore>,
    operator: Arc<certcrypt_node_core::operator_receipt::OperatorIdentity>,
    credential: Arc<capacity_artifacts::operator_recognition::OperatorRecognitionCredentialV1>,
    cfg: RelayConfig,
    /// Epoch ms before which the loop claims nothing (a `Retry-After`).
    paused_until_ms: AtomicI64,
    /// Set by the process on shutdown; the loop exits after the entry in hand.
    shutdown: Arc<AtomicBool>,
}

impl Relay {
    pub fn new(
        outbox: Arc<dyn OutboxStore>,
        upstream: Arc<UpstreamClient>,
        store: Arc<dyn JournalStore>,
        operator: Arc<certcrypt_node_core::operator_receipt::OperatorIdentity>,
        credential: Arc<capacity_artifacts::operator_recognition::OperatorRecognitionCredentialV1>,
    ) -> Self {
        Self {
            outbox,
            upstream,
            store,
            operator,
            credential,
            cfg: RelayConfig::from_env(),
            paused_until_ms: AtomicI64::new(0),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Replace the tunables (tests, embedders).
    pub fn with_config(mut self, cfg: RelayConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// The flag that stops the loop. Set it on shutdown: the entry being
    /// delivered finishes and its outcome is recorded, then `run` returns.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Run until the shutdown flag is set (spawned with `tokio::spawn`). Each
    /// tick processes one batch of due entries, then sleeps.
    pub async fn run(self) {
        while !self.shutdown.load(Ordering::Relaxed) {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let paused_until = self.paused_until_ms.load(Ordering::Relaxed);
            if now_ms < paused_until {
                // Sleep in ticks, not in one go, so a shutdown is not held
                // hostage by a 15-minute maintenance window.
                tokio::time::sleep(self.cfg.tick.min(Duration::from_millis(
                    u64::try_from(paused_until - now_ms).unwrap_or(0),
                )))
                .await;
                continue;
            }
            self.tick(now_ms).await;
            tokio::time::sleep(self.cfg.tick).await;
        }
        tracing::info!("outbox relay stopped");
    }

    /// One batch at `now_ms`. Public for tests.
    pub async fn tick(&self, now_ms: i64) {
        // Off the executor like every other store touch. The relay owns its
        // task, but a blocking call here still pins a runtime thread and so
        // competes with the request handlers it shares the executor with.
        let outbox = self.outbox.clone();
        let batch = self.cfg.batch;
        let claimed = crate::blocking::store_call(move || outbox.claim_due(now_ms, batch)).await;
        match claimed.unwrap_or_else(|e| {
            Err(crate::outbox::OutboxError::Backend(format!(
                "claim_due did not complete: {e}"
            )))
        }) {
            Ok(due) => {
                for entry in due {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Next::PauseUntil(t) = self.process(entry, now_ms).await {
                        self.paused_until_ms.store(t, Ordering::Relaxed);
                        tracing::warn!(
                            resume_in_ms = t - chrono::Utc::now().timestamp_millis(),
                            "relay paused: the issuance service asked to retry later"
                        );
                        break;
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "relay claim_due failed"),
        }
    }

    /// One delivery attempt for one entry, in the batch claimed at `now_ms`.
    async fn process(&self, entry: crate::outbox::OutboxEntry, now_ms: i64) -> Next {
        let set: SubmissionSetV1 = match serde_json::from_str(&entry.submission_set_json) {
            Ok(s) => s,
            Err(e) => {
                // Corrupt entry: cannot ever succeed → dead-letter (fail-closed,
                // visible — never silently dropped).
                self.dead_letter(&entry, &format!("unparseable submission_set: {e}"))
                    .await;
                return Next::Continue;
            }
        };

        // Re-sign the recognition proof for THIS attempt (operator's, not holder's
        // — binds the stable request_id.submission_set_id, so it does not re-sign the set).
        let possession_msg = format!("{}.{}", entry.request_id, set.submission_set_id);
        let recognition = match self.operator.sign_challenge(possession_msg.as_bytes()) {
            Ok(possession_b64) => OperatorRecognitionProof {
                credential: (*self.credential).clone(),
                possession_b64,
            },
            Err(e) => {
                self.reschedule_or_dead(&entry, &format!("possession sign failed: {e}"), false)
                    .await;
                return Next::Continue;
            }
        };

        // Replay the issuer-elected window persisted at admit time, so a retry
        // resolves the SAME window the issuer chose rather than the default. An
        // absent or unparseable value degrades to the default; the idempotency
        // key keeps any retry from being applied twice regardless.
        let settlement_pref = entry
            .settlement_preferences
            .as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .and_then(|v| {
                let profile = v.get("window_profile")?.as_str()?.to_string();
                let fallback = v.get("fallback_policy")?.as_str()?.to_string();
                Some((profile, fallback))
            });

        match self
            .upstream
            .submit_submission_set(&entry.request_id, &set, recognition, settlement_pref)
            .await
        {
            Ok(SubmitResponse::PerMember(resp)) => {
                // Confirmed. Each member's outcome goes over the record the
                // issuer already holds for it (see `crate::journaling`).
                let members = resp
                    .results
                    .into_iter()
                    .map(|m| crate::journaling::MemberOutcome {
                        commitment_index: m.commitment_index,
                        state: crate::journaling::member_state(m.status),
                    })
                    .collect();
                if let Err(e) = crate::journaling::record_members(
                    &self.store,
                    &entry.contract_id,
                    &entry.request_id,
                    &resp.submission_set_id,
                    members,
                    None,
                )
                .await
                {
                    // Not fatal for delivery: the issuance service holds the outcome and the
                    // issuer can still read it by commitment digest.
                    tracing::warn!(request_id = %entry.request_id, error = %e, "relay: journal write failed");
                }
                self.finish(&entry.contract_id, &entry.request_id).await;
                tracing::info!(request_id = %entry.request_id, "relay delivered");
            }
            Ok(SubmitResponse::Flat(flat)) => {
                // `insufficient_capacity` inside its wait window (see
                // `crate::capacity_wait`): the refusal consumed nothing, so keep
                // the set and try again later. The members carry the latest
                // figures meanwhile; no delivery attempt is spent.
                let wait = match &flat {
                    FlatOutcome::InsufficientCapacity { capacity } => {
                        crate::capacity_wait::plan(&set, capacity, now_ms, entry.created_at_ms)
                    }
                    _ => None,
                };
                if let Some((next, waiting)) = wait {
                    let _ = crate::journaling::settle_waiting_records(
                        &self.store,
                        &entry.contract_id,
                        &entry.request_id,
                        waiting,
                    )
                    .await;
                    let outbox = self.outbox.clone();
                    let (scope, rid) = (entry.contract_id.clone(), entry.request_id.clone());
                    let _ = crate::blocking::store_call(move || {
                        outbox.defer(&scope, &rid, next, "insufficient_capacity")
                    })
                    .await;
                    tracing::info!(
                        request_id = %entry.request_id,
                        "relay: insufficient capacity; the set is submitted again later"
                    );
                    return Next::Continue;
                }
                // Any other verdict on the whole set is terminal — no point
                // retrying (an `insufficient_capacity` reaches here once its wait
                // window has closed). Members still waiting get that answer.
                let state = match flat {
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
                    FlatOutcome::Unknown => OperationState::submission_failed(
                        "upstream returned an unrecognized status",
                    ),
                };
                let _ = crate::journaling::settle_waiting_records(
                    &self.store,
                    &entry.contract_id,
                    &entry.request_id,
                    state,
                )
                .await;
                self.finish(&entry.contract_id, &entry.request_id).await;
            }
            Err(e) => {
                // The node's policy: no time budget and no attempt limit for
                // transport failures — the outbox is durable, so an outage of
                // any length is waited out rather than dead-lettered.
                let policy = RetryPolicy {
                    max_elapsed: None,
                    max_attempts: None,
                    backoff_base: self.cfg.backoff_base,
                    backoff_cap: self.cfg.backoff_cap,
                };
                match decide(&policy, e.as_outcome(), entry.attempts, 0) {
                    Decision::WaitAsked { wait_ms } => {
                        let until = chrono::Utc::now().timestamp_millis() + wait_ms;
                        let outbox = self.outbox.clone();
                        let scope = entry.contract_id.clone();
                        let rid = entry.request_id.clone();
                        let reason = e.to_string();
                        let _ = crate::blocking::store_call(move || {
                            outbox.defer(&scope, &rid, until, &reason)
                        })
                        .await;
                        return Next::PauseUntil(until);
                    }
                    // The contract says when to wait and for how long; whether a
                    // failure may wait FOREVER is the relay's own budget, and it
                    // grants that only to unavailability (see is_transient).
                    Decision::Backoff { .. } | Decision::GiveUp => {
                        self.reschedule_or_dead(&entry, &e.to_string(), e.is_transient())
                            .await;
                    }
                    // A definitive refusal: the same bytes get the same answer,
                    // so spending more attempts on it would only delay the
                    // dead-letter that makes it visible.
                    Decision::Return => {
                        self.dead_letter(&entry, &e.to_string()).await;
                    }
                }
            }
        }
        Next::Continue
    }

    /// The issuance service answered for this request: drop the outbox entry, and start the
    /// retention clock of any whole-request `accepted_for_retry` record of this
    /// request. Best-effort like the other journal writes
    /// here — a missed stamp only keeps a record longer, never shorter.
    async fn finish(&self, contract_id: &str, request_id: &str) {
        let outbox = self.outbox.clone();
        let (scope, rid) = (contract_id.to_string(), request_id.to_string());
        let _ = crate::blocking::store_call(move || outbox.mark_submitted(&scope, &rid)).await;
        let store = self.store.clone();
        let (scope, rid) = (contract_id.to_string(), request_id.to_string());
        let now_ms = chrono::Utc::now().timestamp_millis();
        let _ =
            crate::blocking::store_call(move || store.mark_request_resolved(&scope, &rid, now_ms))
                .await;
    }

    /// Move an entry to Dead now: a failure that no retry can fix.
    async fn dead_letter(&self, entry: &crate::outbox::OutboxEntry, err: &str) {
        let outbox = self.outbox.clone();
        let scope = entry.contract_id.clone();
        let rid = entry.request_id.clone();
        let err_owned = err.to_string();
        let _ =
            crate::blocking::store_call(move || outbox.mark_dead(&scope, &rid, &err_owned)).await;
        tracing::warn!(request_id = %entry.request_id, error = %err, "relay dead-lettered a definitive failure");
    }

    /// Backoff-reschedule (stays Pending), or move to Dead once a NON-transient
    /// failure has used up its attempts. A transient one keeps retrying at the
    /// backoff cap for as long as it lasts.
    async fn reschedule_or_dead(
        &self,
        entry: &crate::outbox::OutboxEntry,
        err: &str,
        transient: bool,
    ) {
        let next_attempt = entry.attempts + 1;
        let outbox = self.outbox.clone();
        let scope = entry.contract_id.clone();
        let rid = entry.request_id.clone();
        let err_owned = err.to_string();
        if next_attempt >= self.cfg.max_attempts {
            if !transient {
                let _ =
                    crate::blocking::store_call(move || outbox.mark_dead(&scope, &rid, &err_owned))
                        .await;
                tracing::warn!(request_id = %entry.request_id, attempts = next_attempt, "relay dead-lettered");
                return;
            }
            if next_attempt == self.cfg.max_attempts {
                tracing::warn!(
                    request_id = %entry.request_id,
                    error = %err,
                    "relay: still undelivered after {next_attempt} attempts; the failure is \
                     transient, so it keeps retrying at the backoff cap"
                );
            }
        }
        let wait = backoff_ms(next_attempt, self.cfg.backoff_base, self.cfg.backoff_cap);
        let next_ms = chrono::Utc::now().timestamp_millis() + wait;
        let _ = crate::blocking::store_call(move || {
            outbox.mark_retry(&scope, &rid, next_ms, &err_owned)
        })
        .await;
    }
}

impl RelayConfig {
    fn from_env() -> Self {
        let d = RelayConfig::default();
        let secs = |k: &str, def: std::time::Duration| {
            std::env::var(k)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .map(std::time::Duration::from_secs)
                .unwrap_or(def)
        };
        RelayConfig {
            tick: std::env::var("NODE_RELAY_TICK_MS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .map(std::time::Duration::from_millis)
                .unwrap_or(d.tick),
            batch: std::env::var("NODE_RELAY_BATCH")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(d.batch),
            backoff_base: d.backoff_base,
            backoff_cap: secs("NODE_RELAY_BACKOFF_CAP_SECS", d.backoff_cap),
            max_attempts: std::env::var("NODE_RELAY_MAX_ATTEMPTS")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(d.max_attempts),
        }
    }
}

/// Exponential backoff with full jitter for attempt `n` (1-based), in ms.
/// Deterministic-free jitter uses the system clock nanos as a cheap entropy
/// source (no need for a crypto RNG — this is a scheduling jitter, not a secret).
fn backoff_ms(n: u32, base: std::time::Duration, cap: std::time::Duration) -> i64 {
    let exp = base
        .saturating_mul(2u32.saturating_pow(n.saturating_sub(1)))
        .min(cap)
        .as_millis() as i64;
    if exp <= 0 {
        return 0;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as i64)
        .unwrap_or(0);
    nanos % (exp + 1) // full jitter in [0, exp]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> std::time::Duration {
        std::time::Duration::from_millis(200)
    }
    fn cap() -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }

    #[test]
    fn backoff_stays_within_full_jitter_bounds_and_caps() {
        // For each attempt, the deterministic ceiling is base*2^(n-1) capped, and
        // the returned wait must land in [0, ceiling] (full jitter).
        for n in 1..=20u32 {
            let ceiling = base()
                .saturating_mul(2u32.saturating_pow(n.saturating_sub(1)))
                .min(cap())
                .as_millis() as i64;
            let w = backoff_ms(n, base(), cap());
            assert!(w >= 0, "attempt {n}: negative wait {w}");
            assert!(
                w <= ceiling,
                "attempt {n}: wait {w} exceeds ceiling {ceiling}"
            );
        }
    }

    #[test]
    fn backoff_ceiling_is_monotonic_until_cap_then_flat() {
        // The ceiling (not the jittered value) grows then pins to the cap.
        let ceil = |n: u32| {
            base()
                .saturating_mul(2u32.saturating_pow(n.saturating_sub(1)))
                .min(cap())
                .as_millis() as i64
        };
        let cap_ms = cap().as_millis() as i64;
        let mut prev = 0;
        for n in 1..=30u32 {
            let c = ceil(n);
            assert!(c >= prev, "ceiling regressed at attempt {n}");
            assert!(c <= cap_ms, "ceiling {c} above cap {cap_ms} at {n}");
            prev = c;
        }
        // Late attempts are pinned exactly at the cap.
        assert_eq!(ceil(30), cap_ms);
    }
}
